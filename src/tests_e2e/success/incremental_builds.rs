use crate::{fs_util::*, prelude::*, test_util::*, tests_e2e::success::util::*, util::*};
use itertools::Itertools;
use std::{io::Write, path::PathBuf};
use tempfile::TempDir;

//
macro_rules! generate_success_body {
    //
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
            let key_1 = "0LJov4GYGMPUvzQSuxcap3guApyhB3KM";
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
    }
}

// 1. default configs
// 1. random password
generate_mod!(default, "08h4eMP5jWCtm09PWFMEK8ND6nAxfv1NrztA4S1t0wFhi3NmRlbFis4ERFyCcKmL");
