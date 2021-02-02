pub use crate::{prelude::*, test_util::*, tests_e2e::success::util::*, util::*};
pub use itertools::Itertools;
pub use std::{
    collections::HashSet,
    io::Write,
    path::{Path, PathBuf},
};
pub use walkdir::WalkDir;

#[derive(PartialEq, Eq, Hash, Debug)]
pub enum Change {
    // create a dir
    CreateDir(PathBuf),
    // add some random data to this file
    Append(PathBuf),
    // delete this file/dir
    Delete(PathBuf),
}

impl Change {
    //
    pub fn prepend<P>(&self, root: P) -> Self
    where
        P: AsRef<Path>,
    {
        macro_rules! prepend {
            ( $path:expr ) => {
                root.as_ref().join($path)
            };
        }
        match &self {
            Change::Append(path) => Change::Append(prepend!(path)),
            Change::CreateDir(path) => Change::CreateDir(prepend!(path)),
            Change::Delete(path) => Change::Delete(prepend!(path)),
        }
    }

    //
    pub fn manifest(&self) {
        match self {
            // write some random data to the file
            Change::Append(path) => {
                assert!(path.is_file());
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
        }
    }
}

// TODO https://doc.rust-lang.org/std/macro.is_x86_feature_detected.html

//
pub fn create_files<P>(root: P, rel_paths: &Vec<&str>)
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

pub fn subpaths<P1, P2>(paths: &HashSet<P2>, root: P1) -> HashSet<PathBuf>
where
    P1: AsRef<Path>,
    P2: AsRef<Path>,
{
    paths.iter().map(|p| subpath(p, &root).unwrap()).collect()
}

pub fn pop_front<P>(path: P) -> PathBuf
where
    P: AsRef<Path>,
{
    subpath(
        &path,
        path.as_ref().ancestors().filter(|a| a != &Path::new("")).last().unwrap(),
    )
    .unwrap()
}

pub fn cp_r_src_with_mod_created<P>(source: P, rel_change_set: &HashSet<Change>) -> (tempfile::TempDir, HashSet<PathBuf>)
where
    P: AsRef<Path>,
{
    let source_basename = basename(&source).unwrap();
    // create a dir that contains all files from `source` that have been modified
    // during the incremental encryption
    //
    // `cp -r "$source" "$original_w_modified_files"`
    let tmpd = tmpdir!().unwrap();
    let tmpd_path = tmpd.path();
    cp_r(&source, &tmpd_path);

    //
    let original_w_modified_files = (&tmpd_path).join(&source_basename);
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
                          //  .ancestors()
                          //  .map(Path::to_path_buf)
                          //  .collect::<Vec<_>>(),
                    )
                }
                _ => None,
            })
           // .flat_map(|vec| vec.into_iter())
            .collect();

    /*
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
    */

    (tmpd, modified_files)
}

pub fn cp_r_outdir_with_mod_created<P>(outdir: P, changed: &HashSet<PathBuf>) -> (tempfile::TempDir, PathBuf)
where
    P: AsRef<Path>,
{
    let outdir_basename = basename(&outdir).unwrap();

    let out_dir_w_modified_files_tmpd = tmpdir!().unwrap();
    let out_dir_w_modified_files_tmpd_path = out_dir_w_modified_files_tmpd.path();
    cp_r(&outdir, &out_dir_w_modified_files_tmpd_path);
    let out_dir_w_modified_files = (&out_dir_w_modified_files_tmpd_path).join(&outdir_basename);

    assert!(out_dir_w_modified_files.exists());
    WalkDir::new(&out_dir_w_modified_files)
        .into_iter()
        .map(Result::unwrap)
        .filter(|de| de.file_type().is_file())
        .filter_map(|de| match de.path().extension() == Some(std::ffi::OsStr::new(FILE_SUFFIX)) {
            true => Some(de),
            false => None,
        })
        .for_each(|de| {
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
    (out_dir_w_modified_files_tmpd, out_dir_w_modified_files)
}

pub fn check_deletions<P1, P2>(
    dec_dir_1: P1,
    dec_dir_2: P2,
    dec_dir_1_snapshot: &Snapshot,
    dec_dir_2_snapshot: &Snapshot,
    rel_change_set: &HashSet<Change>,
) where
    P1: AsRef<Path>,
    P2: AsRef<Path>,
{
    // check to see if the deletions are reflected
    let dec_dir_1_rel_paths = subpaths(&dec_dir_1_snapshot.files(), dec_dir_1);
    let dec_dir_2_rel_paths = subpaths(&dec_dir_2_snapshot.files(), dec_dir_2);
    let deleted_files_actual: HashSet<_> = dec_dir_1_rel_paths.difference(&dec_dir_2_rel_paths).map(pop_front).collect();
    //
    let deleted_files_expect: HashSet<_> = rel_change_set
        .iter()
        .filter_map(|c| match c {
            Change::Delete(path) => Some(path),
            _ => None,
        })
        .cloned()
        .collect();

    assert_eq!(&deleted_files_actual, &deleted_files_expect, "deleted files don't match");
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
        //
        #[test]
        fn $fn_name() {
            //
            let _root_tmpdir = $root_tmpdir;
            //
            let files_to_create = $files_to_create;
            //
            let key_1 = $key;
            let key_2 = key_1;
            //
            let exit_code = 0;
            //
            let source = tmpdir!().unwrap();
            let source = source.path();
            //
            let out_dir = tmpdir!().unwrap();
            let out_dir = out_dir.path();
            //
            let rel_change_set = $rel_change_set;

            // set up `source` as specified in `$files_to_create`
            create_files(&source, &files_to_create);

            // syntactic sugar
            macro_rules! encrypt {
                ( $source_predicate:block ) => {
                    check_encrypt!(
                        exit_code,
                        &source,
                        &out_dir,
                        key_1,
                        key_2,
                        $source_predicate,
                        path_as_str!(source),
                        &format!("-o {}", path_as_str!(&out_dir))
                    )
                };
            }
            // syntactic sugar
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

            //
            let dec_dir_1 = tmpdir!().unwrap();
            let dec_dir_1 = dec_dir_1.path();

            // initial encryption from `source` -> `out_dir`
            encrypt!({ |_| true });

            decrypt!(source, out_dir, dec_dir_1);

            let dec_dir_1_snapshot = snapshot(&dec_dir_1);

            // change set with absolute paths
            let change_set: HashSet<_> = rel_change_set
                .iter()
                .map(|c: &Change| -> Change { c.prepend(&source) })
                .collect();

            //
            let modified_and_created_in_source: HashSet<_> = {
                //
                let source_snapshot_before_changes = snapshot(&source);
                change_set.iter().for_each(Change::manifest);
                let source_snapshot_after_changes = snapshot(&source);
                //
                let source_changes = source_snapshot_after_changes.since(&source_snapshot_before_changes);
                //
                source_changes.added.union(&source_changes.modified).cloned().collect()
            };

            // TODO the outdir snapshot before/after moved around and caused no failures
            // TODO make sure this is used and checkd properly
            let out_dir_snapshot_before_initial_enc = snapshot(&out_dir);
            // incremental encryption from `source` -> `out_dir`
            encrypt!({ |path| { modified_and_created_in_source.contains(path) } });
            let out_dir_snapshot_after_initial_enc = snapshot(&out_dir);

            // decrypt the incrementally encrypted result to a different directory
            // to check that deleted files are correctly reflected
            {
                //
                let dec_dir_2 = tmpdir!().unwrap();
                let dec_dir_2 = dec_dir_2.path();

                //
                decrypt!(source, out_dir, dec_dir_2);

                //
                let dec_dir_2_snapshot = snapshot(&dec_dir_2);
                check_deletions(
                    &dec_dir_1,
                    &dec_dir_2,
                    &dec_dir_1_snapshot,
                    &dec_dir_2_snapshot,
                    &rel_change_set,
                );
            }
            // now `source` and `out_dir` only contain newly created and modified files

            let out_dir_diff = out_dir_snapshot_after_initial_enc.since(&out_dir_snapshot_before_initial_enc);
            let out_dir_diff_mod_created: HashSet<_> = out_dir_diff.added.union(&out_dir_diff.modified).cloned().collect();
            let changed: HashSet<_> = out_dir_diff_mod_created
                .into_iter()
                .map(|p| subpath(&p, &out_dir).unwrap())
                .collect();

            let (original_w_modified_files, modified_files) = cp_r_src_with_mod_created(&source, &rel_change_set);
            let original_w_modified_files = original_w_modified_files.path();

            if modified_files.len() == 0 {
                return;
            }

            let (_out_dir_w_modified_files_tmpd, out_dir_w_modified_files) = cp_r_outdir_with_mod_created(&out_dir, &changed);

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
