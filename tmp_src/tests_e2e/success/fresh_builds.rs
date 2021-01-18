use crate::{fs_util::*, prelude::*, test_util::*, tests_e2e::success::util::*, util::*};
use itertools::Itertools;
use std::{io::Write, path::PathBuf};
use tempfile::TempDir;

//
macro_rules! generate_fresh_build_success_test_func {
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
generate_mod!(
    default,
    generate_fresh_build_success_test_func,
    "08h4eMP5jWCtm09PWFMEK8ND6nAxfv1NrztA4S1t0wFhi3NmRlbFis4ERFyCcKmL"
);

// 1. default configs
// 1. empty password
generate_mod!(default_empty_password, generate_fresh_build_success_test_func, "");

// 1. `aes256cbc` as the cipher
// 1. hash strength specified by number of iteration
generate_mod!(
    aes256cbc_pbkdf2_params,
    generate_fresh_build_success_test_func,
    "CL9OhnSRp5uOeb1sZWjMulidwLmbFmL89TDo6FQ5vIq325tPiCEDQxzcK9aFC8B9",
    "--cipher aes256cbc",
    "--spread-depth 4",
    "--key-deriv-alg pbkdf2",
    "--pbkdf2-num-iter 89432"
);

// 1. `aes256cbc` as the cipher
// 1. hash strength specified by time
generate_mod!(
    aes256cbc_pbkdf2_time,
    generate_fresh_build_success_test_func,
    "zVzfYb4RlAdS8zng8gX7Dq1zADhOEnBxoqk4iwsmKW6oNs7A2dVPOBu9QZeXLU4c",
    "--cipher aes256cbc",
    "--spread-depth 5",
    "--key-deriv-alg pbkdf2",
    "--pbkdf2-alg hmac-sha512",
    "--key-deriv-time 4"
);

generate_mod!(
    chacha20_scrypt_params_custom_len,
    generate_fresh_build_success_test_func,
    "AMrSoKIyDByT1kn398swxJOPUYu58b5M98BISjqcvlzpDeKtnFPOD3wULCgDZVHE",
    "--cipher chacha20",
    "--spread-depth 6",
    "--key-deriv-time 3",
    "--scrypt-output-len 1483"
);

generate_mod!(
    chacha20_scrypt_time,
    generate_fresh_build_success_test_func,
    "nTn3RoJEVvX8IH5zQZ5LKTJTSBU3ZqsTG9d2TSL2GB1DbTlNzBBaXwPxEu9DRsby",
    "--cipher chacha20",
    "--spread-depth 7",
    "--scrypt-log-n 13",
    "--scrypt-r 9",
    "--scrypt-p 2"
);
