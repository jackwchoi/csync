use crate::{prelude::*, test_util::*, tests_e2e::success::util::*, util::*};
use itertools::{Either, Itertools};
use maplit::*;
use std::{
    collections::HashSet,
    io::Write,
    path::{Path, PathBuf},
    time::SystemTime,
};
use walkdir::{DirEntry, WalkDir};

#[derive(PartialEq, Eq, Hash, Debug)]
enum Change {
    CreateDir(PathBuf),
    Append(PathBuf),
    Delete(PathBuf),
}

// TODO https://doc.rust-lang.org/std/macro.is_x86_feature_detected.html

//
fn create_files<P>(root: P, rel_paths: &Vec<&str>)
where
    P: AsRef<Path>,
{
    rel_paths
        .iter()
        .map(|rel_path| (rel_path.ends_with('/'), root.as_ref().join(rel_path)))
        .for_each(|(is_dir, full_path)| match is_dir {
            true => std::fs::create_dir_all(full_path).unwrap(),
            false => {
                std::fs::create_dir_all(full_path.parent().unwrap()).unwrap();
                std::fs::File::create(full_path).unwrap();
            }
        });
}

fn csync_files<P>(root: P) -> impl Iterator<Item = walkdir::DirEntry>
where
    P: AsRef<Path>,
{
    WalkDir::new(&root)
        .into_iter()
        .map(Result::unwrap)
        .filter(|de| de.file_type().is_file())
        .filter_map(|de| match de.path().extension() == Some(std::ffi::OsStr::new(FILE_SUFFIX)) {
            true => Some(de),
            false => None,
        })
}

fn subpaths<P1, P2>(paths: &HashSet<P2>, root: P1) -> HashSet<PathBuf>
where
    P1: AsRef<Path>,
    P2: AsRef<Path>,
{
    paths.iter().map(|p| subpath(p, &root).unwrap()).collect()
}

fn pop_front<P>(path: P) -> PathBuf
where
    P: AsRef<Path>,
{
    subpath(
        &path,
        path.as_ref().ancestors().filter(|a| a != &Path::new("")).last().unwrap(),
    )
    .unwrap()
}

// 1. encrypt source -> out_dir
// 1. decrypt out_dir -> dec_dir
// 1. make changes based on change_set, to source
// 1. incremental encrypt to out_dir
// 1. detect created/changed files in out_dir
// 1. create out_dir_new with just the created-changed files
// 1. decrypt out_dir_new to dec_dir_new and verify change
// 1. verify deleted files
macro_rules! generate_incremental_build_success_test_func {
    ( $fn_name:ident, $root_tmpdir:expr, $files_to_create:expr, $rel_change_set:expr, $key:literal ) => {
        #[test]
        fn $fn_name() {
            let _root_tmpdir = $root_tmpdir;
            let files_to_create = $files_to_create;

            // same keys, so it shouldn't fail from mismatch
            let key_1 = $key;
            let key_2 = key_1;

            //
            let exit_code = 0;

            //
            let source = tmpdir!().unwrap();
            let source = source.path();
            create_files(&source, &files_to_create);
            let source_basename = basename(&source).unwrap();

            //
            let out_dir = tmpdir!().unwrap();
            let out_dir = out_dir.path();
            let out_dir_basename = basename(&out_dir).unwrap();
            //
            let dec_dir_1 = tmpdir!().unwrap();
            let dec_dir_1 = dec_dir_1.path();

            macro_rules! encrypt {
                ( $source_pbuf_iter:block ) => {
                    check_encrypt!(
                        exit_code,
                        &source,
                        &out_dir,
                        key_1,
                        key_2,
                        $source_pbuf_iter,
                        path_as_str!(source),
                        &format!("-o {}", path_as_str!(&out_dir))
                    )
                };
            }
            macro_rules! decrypt {
                ( $original:expr, $out_dir:expr, $dec_dir:expr ) => {
                    let original = $original;
                    let out_dir = $out_dir;
                    let dec_dir = $dec_dir;
                    assert!(original.exists());
                    assert!(out_dir.exists());
                    assert!(dec_dir.exists());
                    check_decrypt!(
                        exit_code,
                        &out_dir,
                        &dec_dir,
                        &original,
                        key_1,
                        key_2,
                        path_as_str!(&out_dir),
                        &format!("-o {}", path_as_str!(&dec_dir))
                    )
                };
            }

            // initial encryption from `source` -> `out_dir`
            encrypt!({ |_| true });

            decrypt!(source, out_dir, dec_dir_1);
            let dec_dir_1_snapshot = snapshot(&dec_dir_1);

            let time_after_initial_enc = SystemTime::now();

            // change set with relative paths
            let rel_change_set = $rel_change_set;
            // change set with absolute paths
            let change_set: HashSet<_> = rel_change_set
                .iter()
                .map(|c| match c {
                    Change::Append(path) => Change::Append(source.join(path)),
                    Change::CreateDir(path) => Change::CreateDir(source.join(path)),
                    Change::Delete(path) => Change::Delete(source.join(path)),
                })
                .collect();
            let source_snapshot_3 = snapshot(&source);
            // actually perform the changes
            change_set.iter().for_each(|c| match c {
                // write some random data to the file
                Change::Append(path) => {
                    write!(
                        std::fs::OpenOptions::new().append(true).open(path).unwrap(),
                        "c9Z7fHoHRrhFYbbVitnaUoPJjC7siehUXIv6CZEWYaEwAOlJdHODR2a6Mjz8LZdT"
                    )
                    .unwrap();
                }
                // just create the dir
                Change::CreateDir(path) => std::fs::create_dir_all(path).unwrap(),
                // delete
                Change::Delete(path) => match path.exists() {
                    true => match path.is_file() {
                        true => std::fs::remove_file(path).unwrap(),
                        false => std::fs::remove_dir_all(path).unwrap(),
                    },
                    false => (),
                },
            });
            let source_snapshot_4 = snapshot(&source);
            let source_diff_4_minus_3 = source_snapshot_4.since(&source_snapshot_3);
            let source_diff_4_minus_3_mod_created: HashSet<_> = source_diff_4_minus_3
                .added
                .union(&source_diff_4_minus_3.modified)
                .cloned()
                .collect();

            // incremental encryption from `source` -> `out_dir`
            encrypt!({ |path| { source_diff_4_minus_3_mod_created.contains(path) } });

            // decrypt the incrementally encrypted result to a different directory
            // to check that deleted files are correctly reflected
            {
                //
                let dec_dir_2 = tmpdir!().unwrap();
                let dec_dir_2 = dec_dir_2.path();

                //
                decrypt!(source, out_dir, dec_dir_2);

                // check to see if the deletions are reflected
                let dec_dir_1_rel_paths = subpaths(&dec_dir_1_snapshot.files(), &dec_dir_1);
                let dec_dir_2_rel_paths = subpaths(&snapshot(&dec_dir_2).files(), &dec_dir_2);
                let deleted_files_actual: HashSet<_> = dec_dir_1_rel_paths
                    .difference(&dec_dir_2_rel_paths)
                    .map(|p| subpath(p, p.ancestors().filter(|a| a != &Path::new("")).last().unwrap()).unwrap())
                    .collect();
                //
                let deleted_files_expect: HashSet<_> = rel_change_set
                    .iter()
                    .filter_map(|c| match c {
                        Change::Delete(path) => Some(path),
                        _ => None,
                    })
                    .cloned()
                    .collect();

                assert_eq!(
                    &deleted_files_actual, &deleted_files_expect,
                    "deleted files don't match"
                );
            }
            // now `source` and `out_dir` only contain newly created and modified files

            // look through `out_dir` and separate files into two sets:
            // 1. those that were modified after `time_after_initial_enc`
            // 2. those that were modified before
            let (_, changed): (HashSet<_>, HashSet<_>) = csync_files(&out_dir)
                .map(|de| {
                    let metadata = de.metadata().unwrap();
                    (metadata.modified().unwrap(), subpath(de.path(), &out_dir).unwrap())
                })
                .partition_map(|(modified, pbuf)| match time_after_initial_enc < modified {
                    true => Either::Right(pbuf),
                    false => Either::Left(pbuf),
                });

            // create a dir that contains all files from `source` that have been modified
            // during the incremental encryption
            //
            // `cp -r "$source" "$original_w_modified_files"`
            let original_w_modified_files_tmpd = tmpdir!().unwrap();
            let original_w_modified_files_tmpd = original_w_modified_files_tmpd
                .path()
                .join("316mqlHdMwUmCNXgGcm4t9uVzeL9AxzU");
            cp_r(&source, &original_w_modified_files_tmpd);
            let original_w_modified_files = (&original_w_modified_files_tmpd).join(&source_basename);
            assert!(original_w_modified_files.exists());
            // collect only the created and modified files
            let modified_files: HashSet<_> = rel_change_set
                .iter()
                .filter_map(|c| match c {
                    Change::CreateDir(rel_path) | Change::Append(rel_path) => {
                        // workaround the type system
                        Some(
                            original_w_modified_files
                                .join(rel_path)
                                .ancestors()
                                .map(Path::to_path_buf)
                                .collect::<Vec<_>>(),
                        )
                    }
                    _ => None,
                })
                .flat_map(|vec| vec.into_iter())
                .collect();

            if modified_files.len() == 0 {
                return;
            }
            // delete all deleted files, so that `original_w_modified_files` only contains
            // created and modified files
            WalkDir::new(&original_w_modified_files)
                .contents_first(true)
                .into_iter()
                .map(Result::unwrap)
                .map(DirEntry::into_path)
                .for_each(|pbuf| {
                    let is_modified = modified_files.contains(pbuf.as_path());
                    match (is_modified, pbuf.is_file()) {
                        (false, is_file) if pbuf != original_w_modified_files => match is_file {
                            true => std::fs::remove_file(&pbuf).unwrap(),
                            false => std::fs::remove_dir(&pbuf).unwrap(),
                        },
                        _ => (),
                    }
                });

            //
            let out_dir_w_modified_files_tmpd = tmpdir!().unwrap();
            let out_dir_w_modified_files_tmpd = out_dir_w_modified_files_tmpd.path();
            cp_r(&out_dir, &out_dir_w_modified_files_tmpd);
            let out_dir_w_modified_files = (&out_dir_w_modified_files_tmpd).join(&out_dir_basename);

            assert!(out_dir_w_modified_files.exists());
            csync_files(&out_dir_w_modified_files).for_each(|de| {
                let pbuf = de.into_path();
                // need to delete one more after outdirwmodifiedfiles
                let rel_path = pop_front(subpath(&pbuf, &out_dir_w_modified_files).unwrap());
                if !changed.contains(&rel_path) {
                    match std::fs::remove_file(&pbuf) {
                        Ok(_) => (),
                        Err(err) if err.kind() == std::io::ErrorKind::NotFound => (),
                        Err(_) => panic!(),
                    };
                }
            });
            let tmpout = tmpdir!().unwrap();
            let tmpout = tmpout.path();
            // decrypt this, and it should only contain newly created / modified files
            decrypt!(&original_w_modified_files, &out_dir_w_modified_files, &tmpout);
        }
    };
}

macro_rules! append {
    ( $path:literal ) => {
        Change::Append(PathBuf::from($path))
    };
}
macro_rules! create {
    ( $path:literal ) => {
        Change::CreateDir(PathBuf::from($path))
    };
}
macro_rules! delete {
    ( $path:literal ) => {
        Change::Delete(PathBuf::from($path))
    };
}

// TODO use hash based modification detection

mod deletions {
    use super::*;

    // ./
    // ├── d0/
    // │  ├── d1/
    // │  │  ├── d2/
    // │  │  └── f1
    // │  ├── d4/
    // │  │  ├── f3
    // │  │  └── f4
    // │  ├── d5/
    // │  │  ├── d6/
    // │  │  └── d7/
    // │  └── f2
    // ├── d3/
    // └── f0
    //
    // ./d0/
    // ./d0/d1/
    // ./d0/d1/d2/
    // ./d0/d1/f1
    // ./d0/d4/
    // ./d0/d4/f3
    // ./d0/d4/f4
    // ./d0/d5/"
    // ./d0/d5/d6
    // ./d0/d5/d7
    // ./d0/d5/d8
    // ./d0/f2
    // ./d3/
    // ./f0
    macro_rules! paths {
        () => {
            vec![
                "d0/",
                "d0/d1/",
                "d0/d1/d2/",
                "d0/d1/f1",
                "d0/d4/",
                "d0/d4/f3",
                "d0/d4/f4",
                "d0/d5/",
                "d0/d5/d6/",
                "d0/d5/d7/",
                "d0/d5/d8/",
                "d0/f2",
                "d3/",
                "f0",
            ]
        };
    }

    //
    generate_incremental_build_success_test_func!(
        delete_nothing,
        tmpdir!().unwrap(),
        paths!(),
        hashset! {},
        "dcq100mDxK2f1slccaE5u6r49GrH5X3KjTgBXQJGEhaKJZk8EWqNVVTw5t9g7qqL"
    );
    //
    generate_incremental_build_success_test_func!(
        delete_toplevel_file,
        tmpdir!().unwrap(),
        paths!(),
        hashset! {delete!("f0")},
        "80G3L0ybIYpzgdHbFS3YXGCvCi1e8Tc0stuQ26T8T7mKvttF0wxvoMcYNRiFSpKJ"
    );
    //
    generate_incremental_build_success_test_func!(
        delete_toplevel_empty_dir,
        tmpdir!().unwrap(),
        paths!(),
        hashset! {delete!("d3/")},
        "aQYr0DxQbYsGxA5eQPlbdwd78lXYn8uyixSd7ci59KBMRFAjAi3HCtt0z1KvYT1u"
    );
    //
    generate_incremental_build_success_test_func!(
        nested_empty_dir,
        tmpdir!().unwrap(),
        paths!(),
        hashset! {delete!("d0/d1/d2/")},
        "B9WlmZZbRThjGwUyypFz33jUcvxRKdH827X3PKzdFxODpaaTFvFRh3HvgW418fTU"
    );
    //
    generate_incremental_build_success_test_func!(
        nested_file,
        tmpdir!().unwrap(),
        paths!(),
        hashset! {delete!("d0/d1/f1")},
        "Jgc99KQ2CifNNeFpTxzMfiAxMNw6aHNvNYq7hGRfMW4wU3fuPPa4XUF1NdU3LQ5s"
    );
    //
    generate_incremental_build_success_test_func!(
        nested_dir_of_files,
        tmpdir!().unwrap(),
        paths!(),
        hashset! {delete!("d0/d4/"), delete!("d0/d4/f3"), delete!("d0/d4/f4")},
        "FpNquL7nH1ycnsWeMvvyUUH1gwRmdUzp5KIYWc45z9mDmlHrgir2LYir18BoNesI"
    );
    //
    generate_incremental_build_success_test_func!(
        nested_dir_of_empty_dirs,
        tmpdir!().unwrap(),
        paths!(),
        hashset! {
            delete!("d0/d5/"),
            delete!("d0/d5/d6/"),
            delete!("d0/d5/d7/"),
            delete!("d0/d5/d8/")
        },
        "FpNquL7nH1ycnsWeMvvyUUH1gwRmdUzp5KIYWc45z9mDmlHrgir2LYir18BoNesI"
    );
    //
    generate_incremental_build_success_test_func!(
        nested_dir_of_all,
        tmpdir!().unwrap(),
        paths!(),
        hashset! {
            delete!("d0/"),
            delete!("d0/d1/"),
            delete!("d0/d1/d2/"),
            delete!("d0/d1/f1"),
            delete!("d0/d4/"),
            delete!("d0/d4/f3"),
            delete!("d0/d4/f4"),
            delete!("d0/d5/"),
            delete!("d0/d5/d6/"),
            delete!("d0/d5/d7/"),
            delete!("d0/d5/d8/"),
            delete!("d0/f2")
        },
        "b1VV1nNCmwPKS2cIu8CFEHgg8HsSa1AOtfhjfzCNr2gEfmPaSrmOc33N1slcb5Im"
    );
}

/*
"FLyPjJfFfRqjZsiEudkbJDcxtWntvVPtcgyYzF9Gz7OcvKWSU34XQEePvwyJXuKX"
"xOsHKomPrPsdIuf7lynKZaZKQrv60vHQ9WkYDvPWSgfJrDEm7T2A4izPvHSwwdOH"
"wHxZS6khMOgo80J3JfepWPIG1ENuvQsfoMezDCQhBvVHy1MicBG16cnpBMJZn9sS"
"wLT9WcAmEg4ma3hOpz72Fj0TkIi1h2jQGWBOg7zdxuIz6nRhd1uwGpCpljoCECtO"
"QN6nXe7B3KkQUHZZAKEvnncGfbYcoYZR1jXlEzO3CN4GXEJSTmYRzy1eFM6kJHZ4"
"xzcI2Y9tG2NBQj7E7vlZzmADW4B4XSlyR2fIID0ySZRBD5nNZoiLAbd5ryFiiiGK"
"WmgqBkDGyRqZ9gYFYrs3QQ3fPCyY6R7uX10Lz5hx40trINllm3BqtbaqamH8asvk"
"jwFxuYFpBPK0aaX8uwuGJ26ypgaKMne8BceRgLCUeHnuSkKm49bkeJJbqJ84yaN9"
"cfeCqNwQrFkXoB22vrSGLQbIMmX1Qwwj0pCQNEKgAPyCVr7kI7xjWHvsOxqC897y"
"kkYntCY2VyCXSCX4un3jTQpRJA93LahKGf4kQSnYkYmKMbokYgVfqJ8xMzbJhx78"
"KrTlIqkiEjqGMbKOylmnPA9IUnsD5GeWz9XBVBShY6q2cabclhDYzSoiApeLP64B"
*/

/*
#[test]
fn created_files_are_detected() {
    todo!();
}
#[test]
fn changed_files_are_detected() {
    todo!();
}
*/
