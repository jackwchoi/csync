use crate::{fs_util::*, util::*};
use rayon::prelude::*;
use std::{
    collections::HashSet,
    fs::{copy, create_dir_all, metadata},
    io::Read,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};
use tempfile::NamedTempFile;
use walkdir::WalkDir;

pub fn drng_range(num_bytes: usize, min: u8, max: u8) -> Vec<u8> {
    assert!(min < max);
    let seed: [u8; 32] = [0; 32];

    let min = min as f64;
    let max = max as f64;
    let width = max - min;

    rng_seed!(&seed, num_bytes)
        .into_iter()
        .map(|byte| byte as f64 / std::u8::MAX as f64)   // [0, 255] -> [0, 1]
        .map(|ratio| width * ratio)                      // [0, 1] -> [0, width]
        .map(|adjusted| (adjusted + min).round() as u8) // [0, width] -> [min, max]
        .collect()
}

#[inline]
fn parent(path: &Path) -> &Path {
    match path.parent() {
        Some(par) => par,
        None => Path::new(""),
    }
}

fn cp_r(src: &Path, out_dir: &Path) {
    let src_par = parent(src);

    WalkDir::new(src)
        .follow_links(false)
        .into_iter()
        .map(Result::unwrap)
        .for_each(|entry| {
            let pbuf = entry.path();
            let rel_src_path = subpath(&pbuf, &src_par).unwrap();
            let dest = out_dir.join(rel_src_path);

            create_dir_all(parent(&dest)).unwrap();

            match entry.metadata().unwrap().is_dir() {
                true => create_dir_all(&pbuf).unwrap(),
                false => {
                    assert!(parent(&dest).exists());
                    copy(&pbuf, &dest).unwrap();
                }
            }
        });
}

#[inline]
pub fn basename(path: &Path) -> &str {
    path.file_name().unwrap().to_str().unwrap()
}

#[inline]
fn perm_bits(path: &Path) -> u32 {
    metadata(path).unwrap().permissions().mode()
}

fn rand_file(seed: &[u8], size: usize) -> NamedTempFile {
    let tmpf = tmpfile!().unwrap();
    let seed_hash = hash1!(seed);

    let rand_bytes = rng_seed!(&seed_hash[..], size);
    tmpf
}

/// inefficient, only use for testing
fn assert_file_eq(path_a: &Path, path_b: &Path) {
    // basename ==
    assert_eq!(basename(path_a), basename(path_b));
    // permission bits ==
    assert_eq!(perm_bits(path_a), perm_bits(path_b));

    match path_a.is_dir() {
        // if dir, just check that the two dirs are in fact dirs
        true => assert!(path_b.exists() && path_b.is_dir()),
        // if file,
        false => {
            let bytes = |path| fopen_r(&path).unwrap().bytes().map(Result::unwrap);
            let bytes_a = bytes(path_a);
            let bytes_b = bytes(path_b);

            assert!(iter_eq(bytes_a, bytes_b), "files {:?} != {:?}", path_a, path_b,);
        }
    };
}

/// inefficient, only use for testing
pub fn assert_tree_eq(a: &Path, b: &Path) {
    // basename ==
    assert_eq!(basename(a), basename(b));
    // permission bits ==
    assert_eq!(perm_bits(a), perm_bits(b));

    match (a.is_dir(), b.is_dir()) {
        (false, false) => assert_file_eq(a, b),
        (true, true) => {
            let (a_paths, b_paths) = {
                let paths = |root| {
                    find(root)
                        .map(Result::unwrap)
                        .map(|p| subpath(&p, root).unwrap())
                        .collect::<HashSet<_>>()
                };
                (paths(a), paths(b))
            };
            assert_eq!(&a_paths.len(), &b_paths.len());

            {
                let dirs = |ps: &HashSet<PathBuf>| ps.par_iter().cloned().filter(|p| p.is_dir()).collect::<HashSet<_>>();
                let a_dirs = dirs(&a_paths);
                let b_dirs = dirs(&b_paths);
                assert_eq!(a_dirs, b_dirs);
            }
            let rel_paths = {
                let files = |ps: &HashSet<PathBuf>| ps.par_iter().cloned().filter(|p| p.is_file()).collect::<HashSet<_>>();
                let a_files = files(&a_paths);
                let b_files = files(&b_paths);
                assert_eq!(a_files, b_files);
                a_files // ok because these 2 sets are eq
            };

            rel_paths.into_par_iter().for_each(|rel_path| {
                let a_path = a.join(&rel_path);
                let b_path = b.join(&rel_path);

                assert_file_eq(&a_path, &b_path);
            });
        }
        _ => panic!("one is dir and another is file"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use colmac::*;
    use std::fs::File;

    #[inline]
    fn rel_paths(path: &Path, root: &Path) -> HashSet<PathBuf> {
        find(path).map(Result::unwrap).map(|p| subpath(&p, root).unwrap()).collect()
    }

    mod cp_r {
        use super::*;
        use std::io::Write;

        macro_rules! f_with {
            ( $path:expr, $( $line:expr ),* ) => {{
                {
                    let mut f = fopen_w($path).unwrap();
                    $(
                        f.write($line).unwrap();
                    )*
                }

                PathBuf::from($path)
            }};
        }

        #[test]
        fn individual_files() {
            find("src").par_bridge().map(Result::unwrap).for_each(|src_path| {
                let out_dir = tmpdir!().unwrap();
                let dst_path = out_dir.path().join(basename(&src_path));

                cp_r(&src_path, out_dir.path());
                assert_file_eq(&src_path, &dst_path);
            });
        }

        #[test]
        fn empty_dirs() {
            let tmpd = tmpdir!().unwrap();
            let tmpd = tmpd.path();

            let d1 = tmpd.join("d1");
            let d2 = tmpd.join("d2");
            assert!(!d1.exists());
            assert!(!d2.exists());

            create_dir_all(&d1).unwrap();
            cp_r(&d1, &d2);
            assert!(d1.exists());
            assert!(d2.exists());

            assert_eq!(ls(d1).unwrap().count(), 0);
            assert_eq!(ls(d2).unwrap().count(), 0);
        }

        #[test]
        fn flat_dir_with_files() {
            let src = Path::new("src/encoder");

            let out_dir = tmpdir!().unwrap();
            let out_dir = out_dir.path();

            cp_r(src, out_dir);

            let src_paths = rel_paths(src, Path::new("src"));
            let dst_paths = rel_paths(&out_dir.join("encoder"), out_dir);
            assert_eq!(src_paths, dst_paths);

            src_paths.into_par_iter().for_each(|rel_path| {
                assert!(rel_path.starts_with("encoder"));
                let src_path = Path::new("src").join(&rel_path);
                let dst_path = out_dir.join(&rel_path);
                assert_file_eq(&src_path, &dst_path);
            });
        }

        #[test]
        fn nested_dir() {
            let src = tmpdir!().unwrap();
            let src = src.path();

            let out_dir = tmpdir!().unwrap();
            let out_dir = out_dir.path();

            let d1 = Path::new("d1"); // d1
            let d2 = &d1.join("d2"); // d1/d2
            create_dir_all(src.join(&d2)).unwrap(); // $src/d1/d2

            let f1 = &d1.join("f1"); // d1/f1
            let f2 = &d1.join("f2"); // d1/f2
            let f3 = &d2.join("f3"); // d1/d2/f3
            let f4 = &d2.join("f4"); // d1/d2/f4

            vec![
                f_with!(&src.join(f1), b"6Rw3Sb4l\nGMYRjGD4HDYqVpx5TL7fUAYM"),
                f_with!(&src.join(f2), b"eIlduL4Slrqkk4derv8\nnLFV6LU8oxIpo"),
                f_with!(&src.join(f3), b"RPqI116slEIJqu\nAoOG6CN6TddYtRqlc1"),
                f_with!(&src.join(f4), b"8q74QSRNs9kFeGsoa7BL\nKADi1biocvXy"),
            ];

            cp_r(&src.join(d1), &out_dir);

            // count dirs and match files by hardcoding
            let src_rel_paths = rel_paths(&src.join(d1), src);
            let out_rel_paths = rel_paths(&out_dir.join(d1), out_dir);
            assert_eq!(src_rel_paths, out_rel_paths);

            src_rel_paths.into_par_iter().for_each(|rel_path| {
                let src_path = src.join(&rel_path);
                let out_path = out_dir.join(&rel_path);
                assert_file_eq(&src_path, &out_path);
            });
        }
    }

    mod assert_tree_eq {
        use super::*;
        macro_rules! sugar_assert {
            ( $root_a:expr, $root_b:expr ) => {
                assert_tree_eq(Path::new(&$root_a), Path::new(&$root_b))
            };
        }

        #[test]
        fn reflexivity() {
            find("src").par_bridge().map(Result::unwrap).for_each(|p| sugar_assert!(p, p));
        }

        #[test]
        fn two_empty_dirs_with_same_name() {
            let tmpd1 = tmpdir!().unwrap();
            let d1 = tmpd1.path().join("d");

            let tmpd2 = tmpdir!().unwrap();
            let d2 = tmpd2.path().join("d");
            {
                create_dir_all(&d1).unwrap();
                create_dir_all(&d2).unwrap();
            }
            sugar_assert!(d1, d2);
        }

        #[test]
        fn two_empty_files_with_same_name() {
            let tmpd1 = tmpdir!().unwrap();
            let f1 = tmpd1.path().join("f");

            let tmpd2 = tmpdir!().unwrap();
            let f2 = tmpd2.path().join("f");
            {
                fopen_w(&f1).unwrap();
                fopen_w(&f2).unwrap();
            }
            sugar_assert!(f1, f2);
        }

        #[test]
        fn flat_dir_with_files() {
            let tmpd = tmpdir!().unwrap();

            let src_dir = Path::new("src/encoder");
            let out_dir = tmpd.path();

            create_dir_all(&out_dir).unwrap();
            cp_r(&src_dir, &out_dir);

            sugar_assert!(src_dir, out_dir.join("encoder"));
        }

        mod should_panic {
            use super::*;

            #[should_panic]
            fn one_dir_is_empty() {
                sugar_assert!("src", tmpdir!().unwrap().path());
            }

            #[test]
            #[should_panic]
            fn two_empty_dirs_with_diff_name() {
                let d1 = tmpdir!().unwrap();
                let d2 = tmpdir!().unwrap();
                sugar_assert!(d1.path(), d2.path());
            }

            #[test]
            #[should_panic]
            fn two_empty_files_with_diff_name() {
                let f1 = tmpfile!().unwrap();
                let f2 = tmpfile!().unwrap();
                sugar_assert!(f1.path(), f2.path());
            }

            macro_rules! gen {
                ( $fname:ident, $root_a:literal, $root_b:literal ) => {
                    #[test]
                    #[should_panic]
                    fn $fname() {
                        sugar_assert!($root_a, $root_b);
                    }
                };
            }

            gen!(dir_and_file_1, "src/", "Cargo.toml");

            gen!(dir_and_file_2, "src/main.rs", "target/");

            gen!(different_dirs, "src/", "target/");

            gen!(one_is_subdir, "src/", "src/encoder");

            gen!(different_files, "src/main.rs", "src/crypt/crypt_syncer.rs");
        }
    }
}
