use crate::tests_e2e::util::*;
use crate::{prelude::*, test_util::*, util::*};
use itertools::Itertools;
use std::io::Write;

#[test]
pub fn encrypted_dir_basename_changed() {
    let source = tmpdir!().unwrap();
    let source = source.path();

    // pass
    let exit_code = 0;

    //
    let tmpd = tmpdir!().unwrap();

    //
    let out_dir = tmpd.path().join("auVj2ZazQDC0ZNvgAp7WyhIfR0PSTyJS");
    std::fs::create_dir(&out_dir).unwrap();
    //
    let renamed_out_dir = tmpd.path().join("jhlqRjoF7Iy3xA8TKtCpxiCr6YdH2cMC");

    //
    let out_out_dir = tmpdir!().unwrap();
    let out_out_dir = out_out_dir.path();

    // same keys, so it shouldn't fail from mismatch
    let key_1 = "NbhfRifWQdHyUHPTrK0joRJ7u1NvsGL1";
    let key_2 = key_1;

    // encryption checks
    check_encrypt!(
        exit_code,
        &source,
        &out_dir,
        key_1,
        key_2,
        path_as_str!(&source),
        &format!("-o {}", path_as_str!(&out_dir))
    );

    std::fs::rename(&out_dir, &renamed_out_dir).unwrap();

    // decryption checks
    check_decrypt!(
        exit_code,
        &renamed_out_dir,
        &out_out_dir,
        &source,
        key_1,
        key_2,
        path_as_str!(&renamed_out_dir),
        &format!("-o {}", path_as_str!(&out_out_dir))
    );
}
