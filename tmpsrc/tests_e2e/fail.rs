use crate::tests_e2e::util::*;
use crate::{fs_util::*, prelude::*, test_util::*, util::*};
use itertools::Itertools;
use std::{io::Write, path::PathBuf};

#[test]
fn password_confirmation_fail_during_encryption() {
    //
    let exit_code = CsyncErr::PasswordConfirmationFail.exit_code();

    // two different keys
    let key_1 = "oKorQhgZY3MFLRzc236NPWyghxzSf2EW";
    let key_2 = "lWAI3d36N4g4GXtjYB8cjgNwcfkbzmYc";

    //
    let source = tmpdir!().unwrap();
    let out_dir = tmpdir!().unwrap();

    // encryption checks
    check_core!(
        exit_code,
        key_1,
        key_2,
        "encrypt",
        path_as_str!(&source.path()),
        &format!("-o {}", path_as_str!(out_dir.path()))
    );

    //
    assert!(dir_is_empty(out_dir.path()));
}

#[test]
fn metadata_load_failed() {
    //
    let decryption_exit_code = CsyncErr::MetadataLoadFailed(String::new()).exit_code();

    //
    let source = tmpdir!().unwrap();
    let source = source.path();

    // shadow because we don't want move or drop
    let out_dir = tmpdir!().unwrap();
    let out_dir = out_dir.path();

    // shadow because we don't want move or drop
    let out_out_dir = tmpdir!().unwrap();
    let out_out_dir = out_out_dir.path();

    // same keys, so it shouldn't fail from mismatch
    let key_1 = "JPSIXf4R4tQcOWe9U3paJTcKoUiEQmHm";
    let key_2 = key_1;

    // decryption checks
    check_decrypt!(
        decryption_exit_code,
        &out_dir,
        &out_out_dir,
        source,
        key_1,
        key_2,
        path_as_str!(&out_dir),
        &format!("-o {}", path_as_str!(out_out_dir))
    );

    //
    assert!(dir_is_empty(&source));
    assert!(dir_is_empty(&out_dir));
    assert!(dir_is_empty(&out_out_dir));
}

#[test]
fn authentication_fail() {
    //
    let encryption_exit_code = 0;
    let decryption_exit_code = CsyncErr::AuthenticationFail.exit_code();

    //
    let source = tmpdir!().unwrap();
    let source = source.path();

    // shadow because we don't want move or drop
    let out_dir = tmpdir!().unwrap();
    let out_dir = out_dir.path();

    // shadow because we don't want move or drop
    let out_out_dir = tmpdir!().unwrap();
    let out_out_dir = out_out_dir.path();

    // same keys, so it shouldn't fail from mismatch
    let key_1 = "JPSIXf4R4tQcOWe9U3paJTcKoUiEQmHm";
    let key_2 = key_1;

    // encryption checks
    check_encrypt!(
        encryption_exit_code,
        &source,
        &out_dir,
        key_1,
        key_2,
        path_as_str!(source),
        &format!("-o {}", path_as_str!(out_dir))
    );

    // different key from encryption
    let key_1 = "G4hsElnQWIY7sUPNkmkI6pT0vosQVQPv";
    let key_2 = key_1;

    // decryption checks
    check_decrypt!(
        decryption_exit_code,
        &out_dir,
        &out_out_dir,
        source,
        key_1,
        key_2,
        path_as_str!(&out_dir),
        &format!("-o {}", path_as_str!(out_out_dir))
    );

    //
    assert!(dir_is_empty(&out_out_dir));
}

mod source_does_not_exist {
    use super::*;

    #[test]
    fn encryption_source_does_not_exist() {
        //
        let exit_code = CsyncErr::SourceDoesNotExist(PathBuf::from("")).exit_code();

        // same keys
        let key_1 = "wy2SuiVU1JadEM0H4G2vGHpVg1ePJFf6";
        let key_2 = key_1;

        //
        let tmpd = tmpdir!().unwrap();
        let source = tmpd.path().join("aW7aK7lBgW4gZWoH3Y4LCcIn2xAgEm2d");
        assert!(!source.exists());

        //
        let out_dir = tmpdir!().unwrap();

        // encryption checks
        check_core!(
            exit_code,
            key_1,
            key_2,
            "encrypt",
            path_as_str!(&source),
            &format!("-o {}", path_as_str!(out_dir.path()))
        );

        //
        assert!(dir_is_empty(out_dir.path()));
    }

    #[test]
    fn decryption_source_does_not_exist() {
        //
        let encryption_exit_code = 0;
        let decryption_exit_code = CsyncErr::SourceDoesNotExist(PathBuf::from("")).exit_code();

        let source = tmpdir!().unwrap();
        let source = source.path();

        // shadow because we don't want move or drop
        let out_dir = tmpdir!().unwrap();
        let out_dir = out_dir.path();

        // shadow because we don't want move or drop
        let out_out_dir = tmpdir!().unwrap();
        let out_out_dir = out_out_dir.path();

        // same keys, so it shouldn't fail from mismatch
        let key_1 = "lh7DsqnJtEllR407yN2Qp9MaWaTpkTO2";
        let key_2 = key_1;

        // encryption checks
        check_encrypt!(
            encryption_exit_code,
            source,
            out_dir,
            key_1,
            key_2,
            path_as_str!(source),
            &format!("-o {}", path_as_str!(out_dir))
        );

        let dne_out_dir = tmpdir!().unwrap();
        let dne_out_dir = dne_out_dir.path().join("grEx4pLK5p6OnrAST9GaHfCTwsc3jHQ3");

        //
        assert!(!dne_out_dir.exists());

        // decryption checks
        check_decrypt!(
            decryption_exit_code,
            &dne_out_dir,
            out_out_dir,
            source,
            key_1,
            key_2,
            path_as_str!(&dne_out_dir),
            &format!("-o {}", path_as_str!(out_out_dir))
        );

        //
        assert!(dir_is_empty(&out_out_dir));
    }
}

#[test]
fn decryption_outdir_is_nonempty() {
    //
    let encryption_exit_code = 0;
    let decryption_exit_code = CsyncErr::DecryptionOutdirIsNonempty(PathBuf::from("")).exit_code();

    //
    let key_1 = "Ig0BOcmwiUMHUv7W5kcLFvxK3iYMEF5i";
    let key_2 = key_1;

    //
    let source = tmpdir!().unwrap();
    let out_dir = tmpdir!().unwrap();
    let out_out_dir = tmpdir!().unwrap();

    // encryption checks
    check_encrypt!(
        encryption_exit_code,
        &source,
        out_dir.path(),
        key_1,
        key_2,
        path_as_str!(&source),
        &format!("-o {}", path_as_str!(out_dir.path()))
    );

    //
    let rand_file_pbuf = out_out_dir.path().join("HH4aOlvbxe0IX6wlokdyWfnsZULhrasj");
    {
        fopen_w(&rand_file_pbuf).unwrap();
    }
    assert!(rand_file_pbuf.exists());

    //
    check_core!(
        decryption_exit_code,
        key_1,
        key_2,
        "decrypt",
        path_as_str!(out_dir.path()),
        &format!("-o {}", path_as_str!(out_out_dir.path()))
    );
}

/*
AuthenticationFail,                    // checksum verification failed for this file
DecryptionOutdirIsNonempty(PathBuf),   // when decrypting, outdir must be empty
HashSpecConflict,                      //
MetadataLoadFailed(String),            // couldn't load this metadata file
NonFatalReportFailed,                  //
Other(String),                         // anything else
OutdirIsNotDir(PathBuf),               // ...  decrypting ...
PasswordConfirmationFail,              //
PathContainsInvalidUtf8Bytes(PathBuf), //
SerdeFailed,                           //
SourceDoesNotExist(PathBuf),           //
SourceDoesNotHaveFilename(PathBuf),    //
SourceEqOutdir(PathBuf),               //

non_fatal_report_failed
other
path_contains_invalid_utf8_bytes
serde_failed
*/

// TODO test to see what happens if outdir a symlink

#[test]
fn outdir_is_not_dir() {
    //
    let exit_code = CsyncErr::OutdirIsNotDir(PathBuf::from("")).exit_code();

    // same keys
    let key_1 = "LeVkTH1hGLyYQM4MrGabWbh1STb4IS2P";
    let key_2 = key_1;

    //
    let source = tmpdir!().unwrap();

    //
    let tmpd = tmpdir!().unwrap();
    let out_dir = tmpd.path().join("emnzmttCuAiVsrsSTerxHeTcU2ebOWqE");
    {
        fopen_w(&out_dir).unwrap();
    }
    assert!(out_dir.exists());
    assert!(out_dir.is_file());

    // encryption checks
    check_core!(
        exit_code,
        key_1,
        key_2,
        "encrypt",
        path_as_str!(&source),
        &format!("-o {}", path_as_str!(&out_dir))
    );
}

#[test]
fn source_eq_outdir() {
    //
    let exit_code = CsyncErr::SourceEqOutdir(PathBuf::from("")).exit_code();

    // same keys
    let key_1 = "f4NKSepEHuDJ5Ja8Nm9D1MatBOn97YgB";
    let key_2 = key_1;

    //
    let source = tmpdir!().unwrap();

    // encryption checks
    check_core!(
        exit_code,
        key_1,
        key_2,
        "encrypt",
        path_as_str!(&source.path()),
        &format!("-o {}", path_as_str!(&source.path()))
    );
}

#[test]
fn source_does_not_have_filename() {
    //
    let exit_code = CsyncErr::SourceDoesNotHaveFilename(PathBuf::from("")).exit_code();

    // same keys
    let key_1 = "TOCX1X58BkZDezq2GSN0hVK0jB4kxj04";
    let key_2 = key_1;

    //
    let source = PathBuf::from("/");

    //
    let out_dir = tmpdir!().unwrap();

    // encryption checks
    check_core!(
        exit_code,
        key_1,
        key_2,
        "encrypt",
        path_as_str!(&source),
        &format!("-o {}", path_as_str!(&out_dir.path()))
    );
}

#[test]
fn todo_1() {
    panic!("incremental encryption to a csync dir with different password is auth fail");
}
