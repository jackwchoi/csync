use crate::{prelude::*, test_util::*, tests_e2e::util::*, util::*};

#[test]
fn incremental_dir_with_diff_key_is_auth_fail() {
    let source = tmpdir!().unwrap();
    let source = source.path();

    cp_r("src/", &source);

    let outdir = tmpdir!().unwrap();
    let outdir = outdir.path();

    // same keys, so it shouldn't fail from mismatch
    let key_1 = "9SrrPb1UNNqlauatXShO6u0bO5GdYQJmUUmpHdRki6u2FHqUFn6nuPX2SUIwNp17";
    let key_2 = key_1;

    //
    let exit_code = 0;
    check_encrypt!(
        exit_code,
        &source,
        &outdir,
        key_1,
        key_2,
        path_as_str!(source),
        &format!("-o {}", path_as_str!(&outdir))
    );

    /*

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
    */
    todo!()
}
