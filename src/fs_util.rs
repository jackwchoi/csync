use crate::prelude::*;
use std::{
    fs::File,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};
use tempfile::{self, NamedTempFile, TempDir};
use walkdir::WalkDir;

///
pub fn remove<P>(path: P) -> std::io::Result<()>
where
    P: AsRef<Path>,
{
    match path.as_ref().exists() {
        true => match path.as_ref().is_dir() {
            true => std::fs::remove_dir_all(path),
            false => std::fs::remove_file(path),
        },
        false => Ok(()),
    }
}

///
macro_rules! tmpfile {
    () => {
        crate::fs_util::mktemp_file(None, "", "")
    };
    ( $out_dir:expr ) => {
        tmpfile!($out_dir, "", "")
    };
    ( $out_dir:expr, $prefix:expr ) => {
        tmpfile!($out_dir, $prefix, "")
    };
    ( $out_dir:expr, $prefix:expr, $suffix:expr ) => {
        crate::fs_util::mktemp_file(Some($out_dir), $prefix, $suffix)
    };
}

///
macro_rules! tmpdir {
    () => {
        crate::fs_util::mktemp_dir(None, "", "")
    };
    ( $out_dir:expr ) => {
        tmpfile!($out_dir, "", "")
    };
    ( $out_dir:expr, $prefix:expr ) => {
        tmpfile!($out_dir, $prefix, "")
    };
    ( $out_dir:expr, $prefix:expr, $suffix:expr ) => {
        crate::fs_util::mktemp_dir(Some($out_dir), $prefix, $suffix)
    };
}

///
#[inline]
pub fn perm_bits<P>(path: &P) -> std::io::Result<u32>
where
    P: AsRef<Path>,
{
    Ok(std::fs::metadata(path)?.permissions().mode())
}

///
#[inline]
pub fn is_canonical<P>(path: P) -> std::io::Result<bool>
where
    P: AsRef<Path>,
{
    Ok(&path.as_ref().canonicalize()? == path.as_ref())
}

///
#[inline]
pub fn mktemp_file(out_dir: Option<&Path>, prefix: &str, suffix: &str) -> std::io::Result<NamedTempFile> {
    tempfile::Builder::new()
        .prefix(prefix)
        .suffix(suffix)
        .tempfile_in(out_dir.unwrap_or(std::env::temp_dir().as_path()))
}

///
#[inline]
pub fn mktemp_dir(out_dir: Option<&Path>, prefix: &str, suffix: &str) -> std::io::Result<TempDir> {
    tempfile::Builder::new()
        .prefix(prefix)
        .suffix(suffix)
        .tempdir_in(out_dir.unwrap_or(std::env::temp_dir().as_path()))
}

///
#[inline]
pub fn modified<P>(source: P) -> std::io::Result<std::time::SystemTime>
where
    P: AsRef<Path>,
{
    std::fs::metadata(source)?.modified()
}

///
#[inline]
pub fn find<P>(root: P) -> impl Iterator<Item = CsyncResult<PathBuf>>
where
    P: AsRef<Path>,
{
    WalkDir::new(root).follow_links(true).into_iter().map(|entry| {
        entry
            .map(walkdir::DirEntry::into_path)
            .map_err(|err| CsyncErr::Other(format!("{}", err)))
    })
}

///
#[inline]
pub fn ls<P>(root: P) -> std::io::Result<impl Iterator<Item = std::io::Result<PathBuf>>>
where
    P: AsRef<Path>,
{
    Ok(std::fs::read_dir(root)?.map(|entry_res| entry_res.map(|entry| entry.path())))
}

/// Open a file with a write permission, creating the file if it does not already exist.
///
/// 1. if the file already exists, the existing content will be truncated
/// 2. if the file does not exist, the created file will have its Unix permission bits ste to
///    `0o600 = 0b0110000000`
#[inline]
pub fn fopen_w<P>(path: P) -> std::io::Result<File>
where
    P: AsRef<Path>,
{
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(DEFAULT_PERM_BITS)
        .open(path)
}

/// Open a file with a read permission.
#[inline]
pub fn fopen_r<P>(path: P) -> std::io::Result<File>
where
    P: AsRef<Path>,
{
    std::fs::OpenOptions::new().read(true).open(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::*;
    use colmac::*;
    use rayon::iter::ParallelBridge;
    use rayon::prelude::*;
    use std::collections::HashSet;
    use std::{fs::Permissions, os::unix::fs::PermissionsExt};
    use walkdir::DirEntry;

    ///
    mod fopen_r {
        use super::*;

        ///
        #[test]
        fn fails_if_it_does_not_exist() {
            let tmpd = tmpdir!().unwrap();
            let tmpf = tmpd.path().join("fopX");
            assert!(match fopen_r(&tmpf) {
                Err(_) => true,
                _ => false,
            });
        }

        ///
        #[test]
        fn does_not_overwrite_permission_bits() {
            let tmpd = tmpdir!().unwrap();
            vec![0o600, 0o644, 0o744]
                .into_iter()
                .enumerate()
                .par_bridge()
                .for_each(|(uid, bits)| {
                    let path = tmpd.path().join(uid.to_string());
                    {
                        let file = fopen_w(&path).unwrap();
                        let perm = Permissions::from_mode(bits);
                        file.set_permissions(perm).unwrap();
                    }

                    {
                        fopen_r(&path).unwrap();
                    }

                    let result_bits = perm_bits(&path).unwrap();
                    let bottom_9bits = result_bits & 0o777;
                    assert_eq!(bottom_9bits, bits as u32);
                });
        }
    }

    ///
    mod fopen_w {
        use super::*;

        ///
        #[test]
        fn creates_if_it_does_not_exist() {
            let tmpd = tmpdir!().unwrap();
            let tmpf = tmpd.path().join("06uN");
            assert!(!tmpf.exists());
            {
                fopen_w(&tmpf).unwrap();
            }
            assert!(tmpf.exists() && tmpf.is_file());
        }

        ///
        #[test]
        fn file_does_not_exist_so_sets_permissions_bits_to_default_bits() {
            let tmpd = tmpdir!().unwrap();
            let tmpf = tmpd.path().join("06uN");
            assert!(!tmpf.exists());
            {
                fopen_w(&tmpf).unwrap();
            }
            assert!(tmpf.exists() && tmpf.is_file());
            let bottom_9bits = perm_bits(&tmpf).unwrap() & DEFAULT_PERM_BITS;
            assert_eq!(bottom_9bits, DEFAULT_PERM_BITS);
        }

        ///
        #[test]
        fn file_exists_so_does_not_change_permission_bits() {
            let tmpd = tmpdir!().unwrap();
            let tmpf = tmpd.path().join("0nLS");

            let old_bits = 0o644;

            assert!(!tmpf.exists());
            {
                let f = fopen_w(&tmpf).unwrap();
                let perm = Permissions::from_mode(old_bits);
                f.set_permissions(perm).unwrap();
            }
            assert!(tmpf.exists() && tmpf.is_file());

            // open again
            {
                fopen_w(&tmpf).unwrap();
            }
            let bottom_9bits = perm_bits(&tmpf).unwrap() & old_bits;
            assert_eq!(bottom_9bits, old_bits);
        }
    }

    ///
    mod walkdir_assumptions {
        use super::*;

        ///
        fn walk(root: &Path) -> HashSet<PathBuf> {
            WalkDir::new(root)
                .into_iter()
                .map(Result::unwrap)
                .map(DirEntry::into_path)
                .collect()
        }

        ///
        #[test]
        fn walkdir_includes_empty_root() {
            let tmpd = tmpdir!().unwrap();
            let tmpd_path = tmpd.path();

            let result: HashSet<_> = walk(tmpd_path);
            let expected: HashSet<_> = hashset![tmpd_path.to_path_buf()];
            assert_eq!(expected.len(), 1);
            assert_eq!(result, expected);
        }

        ///
        #[test]
        fn walkdir_includes_nonempty_root() {
            let tmpd = tmpdir!().unwrap();
            let tmpd_path = tmpd.path();

            let tmpf_path = tmpd_path.join("f");
            let tmpf = fopen_w(&tmpf_path).unwrap();

            let result: HashSet<_> = walk(tmpd_path);
            let expected: HashSet<_> = vec![tmpd_path, &tmpf_path].into_iter().map(|p| p.to_path_buf()).collect();
            assert_eq!(expected.len(), 2);
            assert_eq!(result, expected);
        }
    }
}
