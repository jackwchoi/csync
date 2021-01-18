use crate::{prelude::*, test_util::*, tests_e2e::success::util::*, util::*};
use colmac::*;
use itertools::{Either, Itertools};
use std::{
    collections::HashSet,
    io::Write,
    path::PathBuf,
    time::{Duration, Instant, SystemTime},
};
use walkdir::{DirEntry, WalkDir};

#[derive(PartialEq, Eq, Hash)]
enum Change {
    CreateDir(PathBuf),
    Append(PathBuf),
    Delete(PathBuf),
}

// REQUIREMENTS: incremental build
//
// 1. detect deleted files
// 1. detect created files
// 1. detect changed files based on mod time
//     1. changed in content
//     1. changed in permission bits TODO later

// 1. take as an arg HashMap<PathBuf, Change>, specifying the changes to take place after initial
//    encryption but before incremental encryption
// 1. after initial encryption, decrypt to a dir

// check that change_set correctly takes dec_dir_1 to dec_dir_2
fn assert_change_set<P1, P2>(
    change_set: HashSet<Change>,
    dec_dir_1: P1,
    dec_dir_1_snapshot: (Instant, HashSet<PathBuf>),
    dec_dir_2: P2,
    dec_dir_2_snapshot: (Instant, HashSet<PathBuf>),
) where
    P1: AsRef<std::path::Path>,
    P2: AsRef<std::path::Path>,
{
    /*
    //
    let dir_1_files: HashSet<_> = dec_dir_1_snapshot.1.iter().map(|pbuf| subpath(&pbuf, &dec_dir_1).unwrap()).collect();
    let dir_2_files: HashSet<_> = dec_dir_2_snapshot.1.iter().map(|pbuf| subpath(&pbuf, &dec_dir_2).unwrap()).collect();

    //
    let deleted_files: HashSet<_> = dir_1_files.difference(&dir_2_files).cloned().collect();
    let created_files: HashSet<_> = dir_2_files.difference(&dir_1_files).cloned().collect();

    //
    let changed_files: HashSet<_> = dir_1_files
        .intersection(&dir_2_files)
        .filter(|relpath| {
            let content_before = std::fs::read_to_string(dec_dir_1.as_ref().join(relpath)).unwrap();
            let content_after = std::fs::read_to_string(dec_dir_1.as_ref().join(relpath)).unwrap();
            content_before != content_after
        })
        .cloned()
        .collect();

    //
    let change_set_deleted_files: HashSet<_> = change_set
        .iter()
        .filter_map(|c| match c {
            Change::Append(path) | Change::CreateDir(path) => None,
            Change::Delete(path) => Some(path.clone()),
        })
        .collect();
    let change_set_written_files: HashSet<_> = change_set
        .iter()
        .filter_map(|c| match c {
            Change::Append(path) | Change::CreateDir(path) => Some(path.clone()),
            Change::Delete(path) => None,
        })
        .collect();

    //
    assert_eq!(deleted_files, change_set_deleted_files);
    assert_eq!(
        created_files.union(&changed_files).cloned().collect::<HashSet<_>>(),
        change_set_deleted_files
    );
    */
}

//
fn create_files<P>(root: P, rel_paths: &Vec<&str>)
where
    P: AsRef<std::path::Path>,
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

#[derive(Debug)]
struct Snapshot {
    pub time: Instant,
    pub files: HashSet<PathBuf>,
}

fn snapshot<P>(root: P) -> Snapshot
where
    P: AsRef<std::path::Path>,
{
    Snapshot {
        time: Instant::now(),
        files: WalkDir::new(root)
            .into_iter()
            .map(Result::unwrap)
            .map(DirEntry::into_path)
            .collect(),
    }
}

fn csync_files<P>(root: P) -> impl Iterator<Item = walkdir::DirEntry>
where
    P: AsRef<std::path::Path>,
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

fn subpaths<P1, P2>(paths: &HashSet<P2>, root: P1) -> HashSet<std::path::PathBuf>
where
    P1: AsRef<std::path::Path>,
    P2: AsRef<std::path::Path>,
{
    paths.iter().map(|p| subpath(p, &root).unwrap()).collect()
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
            let root_tmpdir = $root_tmpdir;
            let files_to_create = $files_to_create;

            //
            let exit_code = 0;

            //
            let source = tmpdir!().unwrap();
            let source = source.path();
            create_files(&source, &files_to_create);

            //
            let out_dir = tmpdir!().unwrap();
            let out_dir = out_dir.path();
            //
            let dec_dir_1 = tmpdir!().unwrap();
            let dec_dir_1 = dec_dir_1.path();

            // same keys, so it shouldn't fail from mismatch
            let key_1 = $key;
            let key_2 = key_1;

            macro_rules! encrypt {
                ( $source_pbuf_iter:block, $outdir_pbuf_iter:block ) => {
                    check_encrypt!(
                        exit_code,
                        &source,
                        &out_dir,
                        key_1,
                        key_2,
                        $source_pbuf_iter,
                        $outdir_pbuf_iter,
                        path_as_str!(source),
                        &format!("-o {}", path_as_str!(&out_dir))
                    )
                };
            }
            macro_rules! decrypt {
                ( $original:expr, $out_dir:expr, $dec_dir:expr ) => {
                    check_decrypt!(
                        exit_code,
                        &$out_dir,
                        &$dec_dir,
                        &$original,
                        key_1,
                        key_2,
                        path_as_str!(&$out_dir),
                        &format!("-o {}", path_as_str!(&$dec_dir))
                    )
                };
            }

            let original_source_snapshot = snapshot(&source);

            // initial encryption from `source` -> `out_dir`
            encrypt!({ |_| true }, { |_| true });
            let source_snapshot_after_init_enc = snapshot(&source);
            let out_dir_snapshot = snapshot(&out_dir);

            decrypt!(source, out_dir, dec_dir_1);
            let dec_dir_1_snapshot = snapshot(&dec_dir_1);

            let time_after_initial_enc = SystemTime::now();

            // change set with relative paths
            let rel_change_set = $rel_change_set;
            // change set with absolute paths
            let change_set: HashSet<_> = rel_change_set
                .iter()
                .map(|c| match c {
                    Change::Append(path) => Change::Append(root_tmpdir.path().join(path)),
                    Change::CreateDir(path) => Change::CreateDir(root_tmpdir.path().join(path)),
                    Change::Delete(path) => Change::Delete(root_tmpdir.path().join(path)),
                })
                .collect();
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

            let time_after_change = SystemTime::now();

            // incremental encryption from `source` -> `out_dir`
            encrypt!(
                {
                    |path| {
                        find(&path).any(|p| time_after_initial_enc < std::fs::metadata(p.unwrap()).unwrap().modified().unwrap())
                    }
                },
                { |path| find(&path).any(|p| time_after_change < std::fs::metadata(p.unwrap()).unwrap().modified().unwrap()) }
            );

            // decrypt the incrementally encrypted result to a different directory
            // to check that deleted files are correctly reflected
            {
                //
                let dec_dir_2 = tmpdir!().unwrap();
                let dec_dir_2 = dec_dir_2.path();

                //
                decrypt!(source, out_dir, dec_dir_2);

                // check to see if the deletions are reflected
                let dec_dir_1_rel_paths = subpaths(&dec_dir_1_snapshot.files, &dec_dir_1);
                let dec_dir_2_rel_paths = subpaths(&snapshot(&dec_dir_2).files, &dec_dir_2);
                let deleted_files_actual: HashSet<_> = dec_dir_1_rel_paths.difference(&dec_dir_2_rel_paths).collect();
                let deleted_files_expect: HashSet<_> = change_set
                    .iter()
                    .filter_map(|c| match c {
                        Change::Delete(path) => Some(path),
                        _ => None,
                    })
                    .collect();
                assert_eq!(deleted_files_actual, deleted_files_expect, "deleted files don't match");
            }
            // now `source` and `out_dir` only contain newly created and modified files

            // look through `out_dir` and separate files into two sets:
            // 1. those that were modified after `time_after_initial_enc`
            // 2. those that were modified before
            let (unchanged, changed): (HashSet<_>, HashSet<_>) = csync_files(&out_dir)
                .map(|de| {
                    let metadata = de.metadata().unwrap();
                    let pbuf = de.into_path();
                    (metadata.modified().unwrap(), pbuf)
                })
                .partition_map(|(modified, pbuf)| match time_after_initial_enc < modified {
                    true => Either::Right(subpath(pbuf, &out_dir).unwrap()),
                    false => Either::Left(subpath(pbuf, &out_dir).unwrap()),
                });

            // create a dir that contains all files from `source` that have been modified
            // during the incremental encryption
            //
            // `cp -r "$source" "$original_w_modified_files"`
            let original_w_modified_files = tmpdir!().unwrap();
            let original_w_modified_files = original_w_modified_files
                .path()
                .join("316mqlHdMwUmCNXgGcm4t9uVzeL9AxzU");
            cp_r(&source, &original_w_modified_files);
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
                                .map(std::path::Path::to_path_buf)
                                .collect::<Vec<_>>(),
                        )
                    }
                    _ => None,
                })
                .flat_map(|vec| vec.into_iter())
                .collect();
            // delete all deleted files, so that `original_w_modified_files` only contains
            // created and modified files
            WalkDir::new(&original_w_modified_files)
                .contents_first(true)
                .into_iter()
                .map(Result::unwrap)
                .map(DirEntry::into_path)
                .for_each(|pbuf| match (modified_files.contains(pbuf.as_path()), pbuf.is_file()) {
                    (true, _) => (),
                    (false, true) => std::fs::remove_file(&pbuf).unwrap(),
                    (false, false) => std::fs::remove_dir(&pbuf).unwrap(),
                });

            //
            let out_dir_w_modified_files = tmpdir!().unwrap();
            let out_dir_w_modified_files = out_dir_w_modified_files.path().join("VQk7fteKLaXXX66sFjTUwip4Oj2AjIUl");
            cp_r(&out_dir, &out_dir_w_modified_files);
            csync_files(&out_dir_w_modified_files).for_each(|de| {
                let pbuf = de.into_path();
                let rel_path = subpath(pbuf, &out_dir_w_modified_files).unwrap();
                if !changed.contains(&rel_path) {
                    std::fs::remove_file(&rel_path).unwrap();
                }
            });

            let x = tmpdir!().unwrap();
            let x = x.path();
            // decrypt this, and it should only contain newly created / modified files
            decrypt!(original_w_modified_files, out_dir_w_modified_files, x);
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

mod deletions {
    use super::*;

    //
    generate_incremental_build_success_test_func!(
        delete_file,
        tmpdir!().unwrap(),
        vec!["d1/", "d1/d2/", "d1/d2/f1", "d1/d2/f2", "d1/d3", "d1/f3"],
        hashset![delete!("d1/f3")],
        "80G3L0ybIYpzgdHbFS3YXGCvCi1e8Tc0stuQ26T8T7mKvttF0wxvoMcYNRiFSpKJ"
    );

    //
    generate_incremental_build_success_test_func!(
        delete_empty_dir,
        tmpdir!().unwrap(),
        vec!["d1/", "d1/d2/", "d1/d2/f1", "d1/d2/f2", "d1/d3", "d1/f3"],
        hashset![delete!("d1/d3")],
        "DZsrSWWxIkLMBl8RjijVhlNsQk1tsVv0fN3bi5qvH0wbRxnEKLQHKQfHS9v99mHu"
    );
}

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
