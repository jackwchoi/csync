use crate::{fs_util::*, prelude::*, test_util::*, tests_e2e::success::util::*, util::*};
use itertools::Itertools;
use std::{
    collections::{HashMap, HashSet},
    io::Write,
    path::PathBuf,
};
use tempfile::TempDir;
use walkdir::{DirEntry, WalkDir};

enum Change {
    Write(PathBuf),
    Delete(PathBuf),
}

fn find<P>(root: P) -> impl Iterator<Item = PathBuf>
where
    P: AsRef<std::path::Path>,
{
    WalkDir::new(root).into_iter().map(Result::unwrap).map(DirEntry::into_path)
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
// 1. after changes and incremental encryption, decrypt to a different dir
// 1. check that the initial change spec matches the diff between the 2 decryption dirs

// check that change_set correctly takes dec_dir_1 to dec_dir_2
fn assert_change_set<P1, P2>(change_set: HashSet<Change>, dec_dir_1: P1, dec_dir_2: P2)
where
    P1: AsRef<std::path::Path>,
    P2: AsRef<std::path::Path>,
{
    //
    let dir_1_files: HashSet<_> = find(&dec_dir_1).map(|pbuf| subpath(&pbuf, &dec_dir_1).unwrap()).collect();
    let dir_2_files: HashSet<_> = find(&dec_dir_2).map(|pbuf| subpath(&pbuf, &dec_dir_2).unwrap()).collect();

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
            Change::Write(path) => None,
            Change::Delete(path) => Some(path.clone()),
        })
        .collect();
    let change_set_written_files: HashSet<_> = change_set
        .iter()
        .filter_map(|c| match c {
            Change::Write(path) => Some(path.clone()),
            Change::Delete(path) => None,
        })
        .collect();

    //
    assert_eq!(deleted_files, change_set_deleted_files);
    assert_eq!(
        created_files.union(&changed_files).cloned().collect::<HashSet<_>>(),
        change_set_deleted_files
    );
}

//
macro_rules! generate_incremental_build_success_test_func {
    //
    ( $fn_name:ident, $root_tmpd:expr, $change_set:expr, $key:literal,  ) => {

    };
    ( $fn_name:ident, $pbuf_and_tmpd:expr, $key:literal $(, $arg:literal )* ) => {
        //
        #[test]
        fn $fn_name() {
            let (source, _tmpd): (PathBuf, Option<TempDir>) = $pbuf_and_tmpd;
            let source = &source;

            // pass
            let exit_code = 0;

            // shadow because we don't want move or drop
            let out_dir = tmpdir!().unwrap();
            let out_dir = out_dir.path();

            // shadow because we don't want move or drop
            let out_out_dir = tmpdir!().unwrap();
            let out_out_dir = out_out_dir.path();

            // same keys, so it shouldn't fail from mismatch
            let key_1 = $key;
            let key_2 = key_1;

            // encryption checks
            check_encrypt!(
                exit_code,
                source,
                out_dir,
                key_1,
                key_2,
                path_as_str!(source),
                &format!("-o {}", path_as_str!(out_dir))
                $(, $arg )*
            );

            let hashes_after_first_enc = false;

            // encryption checks
            check_encrypt!(
                exit_code,
                source,
                out_dir,
                key_1,
                key_2,
                path_as_str!(source),
                &format!("-o {}", path_as_str!(out_dir))
                $(, $arg )*
            );

            let hashes_after_second_enc = false;

            // TODO assert_eq(hashes_after_second_enc);

            // decryption checks
            check_decrypt!(
                exit_code,
                out_dir,
                out_out_dir,
                source,
                key_1,
                key_2,
                path_as_str!(out_dir),
                &format!("-o {}", path_as_str!(out_out_dir))
            );
        }
    };
}
