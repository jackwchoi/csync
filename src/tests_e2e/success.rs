use crate::tests_e2e::util::*;
use crate::{fs_util::*, prelude::*, test_util::*, util::*};
use itertools::Itertools;
use std::{io::Write, path::PathBuf};
use tempfile::TempDir;

#[test]
fn encrypted_dir_basename_changed() {
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

// # Parameters
//
// 1. `$mod_name`
// 1. `$key`
// 1. `$( , $arg )*`: string args to pass to the csync prorcess
macro_rules! generate_mod {
        //
        ( $mod_name:ident, $key:literal $( , $arg:literal )* ) => {
            //
            mod $mod_name {
                use super::*;

                //
                macro_rules! generate_test {
                    ( $fn_name:ident, $pbuf_and_tmpd:expr ) => {
                        generate_success_body!(
                            $fn_name,
                            $pbuf_and_tmpd,
                            $key
                            $( , $arg )*
                        );
                    };
                }

                //
                generate_suite!(generate_test);
            }
        }
    }

// 1. default configs
// 1. random password
generate_mod!(default, "08h4eMP5jWCtm09PWFMEK8ND6nAxfv1NrztA4S1t0wFhi3NmRlbFis4ERFyCcKmL");

// 1. default configs
// 1. empty password
generate_mod!(default_empty_password, "");

// 1. `aes256cbc` as the cipher
// 1. hash strength specified by number of iteration
generate_mod!(
    aes256cbc_pbkdf2_params,
    "H7u1ZPOHnzMVXyVT6vBSnkIe6TMTj5otNQGi2wmIW4lJw36sBccg8PCm5AKX8iMX",
    "--cipher aes256cbc",
    "--spread-depth 4",
    "--key-deriv-alg pbkdf2",
    "--pbkdf2-num-iter 89432"
);

// 1. `aes256cbc` as the cipher
// 1. hash strength specified by time
generate_mod!(
    aes256cbc_pbkdf2_time,
    "H7u1ZPOHnzMVXyVT6vBSnkIe6TMTj5otNQGi2wmIW4lJw36sBccg8PCm5AKX8iMX",
    "--cipher aes256cbc",
    "--spread-depth 5",
    "--key-deriv-alg pbkdf2",
    "--pbkdf2-alg hmac-sha512",
    "--key-deriv-time 4"
);

generate_mod!(
    chacha20_scrypt_params_custom_len,
    "H7u1ZPOHnzMVXyVT6vBSnkIe6TMTj5otNQGi2wmIW4lJw36sBccg8PCm5AKX8iMX",
    "--cipher chacha20",
    "--spread-depth 6",
    "--key-deriv-time 3",
    "--scrypt-output-len 1483"
);

generate_mod!(
    chacha20_scrypt_time,
    "H7u1ZPOHnzMVXyVT6vBSnkIe6TMTj5otNQGi2wmIW4lJw36sBccg8PCm5AKX8iMX",
    "--cipher chacha20",
    "--spread-depth 7",
    "--scrypt-log-n 13",
    "--scrypt-r 9",
    "--scrypt-p 2"
);
