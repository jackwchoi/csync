use super::*;
use crate::{fs_util::*, prelude::*, test_util::*, util::*};
use itertools::Itertools;
use std::path::Path;
use std::{
    io::{self, Write},
    path::PathBuf,
};
use tempfile::TempDir;

// `&Path -> &str`
macro_rules! path_as_str {
    ( $path:expr ) => {
        &path_as_string($path).unwrap()
    };
}

// # Returns
//
// `bytes` forcefully converted to `&str`, assuming it's utf8-encoded.
#[inline]
fn bytes_to_str(bytes: &[u8]) -> &str {
    std::str::from_utf8(bytes).unwrap()
}

// # Returns
//
// Non-overlapping matches of the regex pattern, `pattern`, within `text`.
fn matches(pattern: &str, text: &str) -> Vec<String> {
    regex::Regex::new(pattern)
        .unwrap()
        .find_iter(text)
        .map(|mat| mat.as_str().to_string())
        .collect()
}

// Equivalent to running the following in Bash: `bash -c "$command"`.
//
// `&0`, `&1` and `&2` can all be piped.
#[inline]
fn bash(command: &str) -> io::Result<std::process::Child> {
    std::process::Command::new("bash")
        .arg("-c")
        .arg(command)
        .stdin(std::process::Stdio::piped() /*  &0 */)
        .stdout(std::process::Stdio::piped() /* &1 */)
        .stderr(std::process::Stdio::piped() /* &2 */)
        .spawn()
}

//
fn grep_report_line_with_header(header: &str, output: &std::process::Output) -> String {
    //
    let match_lines = {
        let stderr_str = bytes_to_str(&output.stderr);
        // the entire line that starts with `REPORT_HEADER_NUM_FILES` except the newline
        let pattern = format!(r"{}[^\n]+", header);
        //
        matches(&pattern, stderr_str)
    };

    //
    assert_eq!(match_lines.len(), 1);
    match_lines.get(0).unwrap().to_string()
}

//
fn check_report_line(line: &str, value: f64, unit: &str) {
    let (adjusted_value, adj_unit) = adjust_value(value, unit);
    assert!(line.ends_with(&adj_unit));
    assert!(line.contains(&adjusted_value));
}

// # Returns
//
// An iterator of files in `source` that csync cares about.
fn get_all_source<P>(source: P) -> impl Iterator<Item = PathBuf>
where
    P: AsRef<Path>,
{
    find(source).map(CsyncResult::unwrap)
}

// # Returns
//
// An iterator of files in `outdir` that csync cares about.
fn get_all_outdir<P>(outdir: P) -> impl Iterator<Item = PathBuf>
where
    P: AsRef<Path>,
{
    find(outdir)
        .map(CsyncResult::unwrap)
        .filter(|pb| pb.is_file())
        .filter(|pb| pb.extension().unwrap().to_str() == Some("csync"))
}

/// Let `$args` be `$( $arg ),+` concatted with ` `; runs the following bash command:
/// `printf "$key_1\n$key_2\n" | cargo run -- $args` and checks that the exit code of that
/// process matches the provided `$exit_code_expected`.
///
/// Blocks until the above `cargo` process terminates.
///
/// # Parameters
///
/// 1. `$exit_code_expected`: the expected exit code of the `csync` process
/// 1. `$key_1`: the first key to provide csync
/// 1. `$key_2`: the second key to provide csync
/// 1. `$( $arg ),+`: arguments to pass to the cargo process
///
/// # Returns
///
/// The output of the `cargo` process as `std::process::Output`.
macro_rules! check_core {
    (
        $exit_code_expected:expr,
        $key_1:expr,
        $key_2:expr,
        $( $arg:expr ),+
    ) => {{
        // `std::process::Output` resulting from the child proc
        let output = {
            // concat args  to spawn a child process
            let mut proc = {
                let command: String = vec!["cargo run --", $( $arg ),+]
                    .into_iter()
                    .intersperse(" ")
                    .collect();
                bash(&command).unwrap()
            };

            // write passwords to the stdin of the child proc
            {
                let stdin = proc.stdin.as_mut().unwrap();
                write!(stdin, "{}\n{}\n", $key_1, $key_2).unwrap();
            }

            proc.wait_with_output().unwrap()
        };

        // check exit code
        {
            let exit_code = output.status.code().unwrap();
            assert_eq!(exit_code, $exit_code_expected, "{:?}", output);
        }
        //
        output
    }}
}

/// Functionally a strict superset of `check_core`; does some encryption-specific checks.
///
/// 1. `$exit_code_expected`: the expected exit code of the `csync` process
/// 1. `$source`: the directory being encrypted
/// 1. `$out_dir`: the directory in which the result of the encryption will go
/// 1. `$key_1`: the first key to provide csync
/// 1. `$key_2`: the second key to provide csync
/// 1. `$( $arg ),+`: arguments to pass to the cargo process
macro_rules! check_encrypt {
    (
        $exit_code_expected:expr,
        $source:expr,
        $out_dir:expr,
        $key_1:expr,
        $key_2:expr,
        $( $arg:expr ),+
    ) => {{
        //
        let out_dir = $out_dir;
        // hash of the directory structure, te see if anything changes
        let out_dir_hash_before = hash_tree(&out_dir);

        //
        let output = check_core!($exit_code_expected, $key_1, $key_2, $( $arg ),+);

        // exit code of the process
        match output.status.code().unwrap() {
            // if no error, do more correctness checks
            0 => {
                // check the number of files synced
                {
                    // count all files and dirs in `$source`; these are the ones that `csync` encrypts
                    let source_file_count = get_all_source($source).count();
                    // count only the files in `$out_dir`; everything else in there doesn't really care
                    let cipher_file_count = get_all_outdir(&out_dir).count();
                    // check that the 2 are equal, meaning that the correct number have been synced
                    assert_eq!(source_file_count, cipher_file_count, "check_encrypt! count match fail");

                    // check that `csync` reports the correct number, for number of files synced
                    let file_count_line = grep_report_line_with_header(REPORT_HEADER_NUM_FILES, &output);
                    check_report_line(&file_count_line, source_file_count as f64, "files");
                }

                // check the amount of data read from `$source`
                {
                    // sum up the number of bytes in each file/dir in `$source`
                    let data_read: u64 = get_all_source($source)
                        .map(|pb| std::fs::metadata(&pb).unwrap().len())
                        .sum();
                    // check that it was reported correctly
                    let data_read_line = grep_report_line_with_header(REPORT_HEADER_DATA_READ, &output);
                    check_report_line(&data_read_line, data_read as f64, "B");
                }

                // check the amount of data written to `$out_dir`
                {
                    // sum up the number of bytes in each file in `$out_dir`
                    let data_written: u64 = get_all_outdir(&out_dir)
                        .map(|pb| std::fs::metadata(&pb).unwrap().len())
                        .sum();
                    // check that it was reported correctly
                    let data_written_line = grep_report_line_with_header(REPORT_HEADER_DATA_WRITTEN, &output);
                    check_report_line(&data_written_line, data_written as f64, "B");
                }
            }
            // TODO do things like chekcing to make sure that the files didn't change and etc
            _ => {
                // hash of the directory structure, te see if anything changes
                let out_dir_hash_before = hash_tree(&out_dir);

                match out_dir.exists() {
                    true => panic!("failed encryption should not create outdir"),
                    false => (),
                }
            },
        };
        output
    }}
}

/// Functionally a strict superset of `check_core`; does some decryption-specific checks.
///
/// 1. `$exit_code_expected`: the expected exit code of the `csync` process
/// 1. `$source`: the directory being decrypted
/// 1. `$out_dir`: the directory in which the result of the decryption will go
/// 1. `$original`: the orginal directory, such that encrypting `$original` results in `$source`
/// 1. `$key_1`: the first key to provide csync
/// 1. `$key_2`: the second key to provide csync
/// 1. `$( $arg ),+`: arguments to pass to the cargo process
macro_rules! check_decrypt {
    (
        $exit_code_expected:expr,
        $source:expr,
        $out_dir:expr,
        $original:expr,
        $key_1:expr,
        $key_2:expr,
        $( $arg:expr ),+
    ) => {{
        //
        let out_dir = $out_dir;
        // hash of the directory structure, te see if anything changes
        let out_dir_hash_before = hash_tree(&out_dir);

        //
        let output = check_core!($exit_code_expected, $key_1, $key_2, $( $arg ),+);

        //
        match output.status.code().unwrap() {
            0 => {
                // this is to account for the fact that when csync is run like
                // `csync src/ -d -o out/`, it creates `out/src/`
                //
                // so `final_dest = $out/$(basename $src)` is the root of the decryption's result
                let final_dest = out_dir.join($original.file_name().unwrap());

                {
                    // check that correct number of files have been decrypted
                    let encrypted_file_count = find($source).filter(|x| x.as_ref().unwrap().is_file()).count();
                    let decrypted_file_count = find(&final_dest).map(|x| x.unwrap()).count();
                    assert_eq!(encrypted_file_count, decrypted_file_count, "check_decrypt");
                }

                // everything must be identical
                assert_tree_eq(&final_dest, $original);
            }
            // TODO do things like chekcing to make sure that the files didn't change and etc
            _ => {
                let out_dir_hash_after = hash_tree(&out_dir);
                assert_eq!(out_dir_hash_before, out_dir_hash_after);
            }
        };
        output
    }}
}

/// Generate a set of tests that do the same checks.
///
/// This set is generated by applying `$fn_gen` to `PathBuf`s to various files and directories.
///
/// # Parameters
///
/// 1. `$fn_gen`: `ident` of a macro with `( $fn_name:ident, $pbuf_and_tmpd:expr )` as its
///    parameters. `$pbuf_and_tmpd` has the type `(PathBuf, Option<TempDir>)`. An invocation of
///    `$fn_gen!(_, _)` should create a test whose name should match `$fn_name` and does whatever checks
///    are necessary.
///
///    the first element of the tuple is used as the source dir
macro_rules! generate_suite {
    //
    ( $fn_gen:ident ) => {
        // nested directories of files with printable content
        $fn_gen!(nested_dir_printable_bytes, (PathBuf::from("src"), None));

        // nested directories of files with printable content, path appended with slash
        $fn_gen!(nested_dir_printable_bytes_with_fslash, (PathBuf::from("src/"), None));

        // nested directories of files with nonprintable content
        $fn_gen!(
            nested_dir_nonprintable_bytes_0,
            (PathBuf::from(".git/objects/00/"), None)
        );
        // nested directories of files with nonprintable content
        $fn_gen!(
            nested_dir_nonprintable_bytes_1,
            (PathBuf::from(".git/objects/pack/"), None)
        );

        // nested directories of files with nonprintable content; more complex
        //
        // uses output directory of `csync` to create pseudo-random bytes
        $fn_gen!(nested_dir_nonprintable_bytes_using_csync_outdir, {
            // pass
            let exit_code = 0;

            let source = PathBuf::from("src/");

            // shadow because we don't want move or drop
            let out_dir = tmpdir!().unwrap();
            let out_dir_path = out_dir.path();

            // same keys, so it shouldn't fail from mismatch
            let key_1 = "cFIRaukCSubxsArp1CzD5A3r3sctoWxj";
            let key_2 = key_1;

            // encryption checks
            check_encrypt!(
                exit_code,
                &source,
                out_dir_path,
                key_1,
                key_2,
                path_as_str!(&source),
                &format!("-o {}", path_as_str!(out_dir_path)),
                "-v"
            );

            (out_dir_path.to_path_buf(), Some(out_dir))
        });

        //
        $fn_gen!(single_file_printable_bytes, (PathBuf::from("src/main.rs"), None));

        //
        $fn_gen!(single_dir_empty, {
            let tmpd = tmpdir!().unwrap();
            let tmpd_pbuf = tmpd.path().to_path_buf();
            (tmpd_pbuf, Some(tmpd))
        });

        //
        $fn_gen!(single_file_empty, {
            let tmpd = tmpdir!().unwrap();
            let tmpf_pbuf = tmpd.path().join("FsNJNQ3TcFNxvv6jqZbesHkCHD9hn574");
            fopen_w(&tmpf_pbuf).unwrap();
            (tmpf_pbuf, Some(tmpd))
        });
    };
}

mod success {
    use super::*;

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
            &format!("-o {}", path_as_str!(&out_dir)),
            "-v"
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
            &format!("-o {} -d", path_as_str!(&out_out_dir)),
            "-v"
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
                    &format!("-o {}", path_as_str!(out_dir)),
                    "-v"
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
                    &format!("-o {} -d", path_as_str!(out_out_dir)),
                    "-v"
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
        "--pbkdf2-num-iter 89432"
    );

    // 1. `aes256cbc` as the cipher
    // 1. hash strength specified by time
    generate_mod!(
        aes256cbc_pbkdf2_time,
        "H7u1ZPOHnzMVXyVT6vBSnkIe6TMTj5otNQGi2wmIW4lJw36sBccg8PCm5AKX8iMX",
        "--cipher aes256cbc",
        "--spread-depth 5",
        "--pbkdf2-algorithm hmac-sha512",
        "--pbkdf2-time 4"
    );

    generate_mod!(
        chacha20_scrypt_params_custom_len,
        "H7u1ZPOHnzMVXyVT6vBSnkIe6TMTj5otNQGi2wmIW4lJw36sBccg8PCm5AKX8iMX",
        "--cipher chacha20",
        "--spread-depth 6",
        "--scrypt-time 3",
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
}

////////////////////////////////////////////////////////////////

macro_rules! generate_fail_body {
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
            let key_1 = "aoeu";
            let key_2 = "aoeu";

            // encryption checks
            check_encrypt!(
                exit_code,
                source,
                out_dir,
                key_1,
                key_2,
                path_as_str!(source),
                &format!("-o {}", path_as_str!(out_dir)),
                "-v"
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
                &format!("-o {} -d", path_as_str!(out_out_dir)),
                "-v"
            );
        }
    }
}

mod fail {
    use super::*;

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
            path_as_str!(&source.path()),
            &format!("-o {}", path_as_str!(out_dir.path())),
            "-v"
        );

        //
        assert!(dir_is_empty(out_dir.path()));
    }

    #[test]
    fn authentication_fail() {
        //
        let encryption_exit_code = 0;
        let decryption_exit_code = CsyncErr::AuthenticationFail.exit_code();

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
            source,
            out_dir,
            key_1,
            key_2,
            path_as_str!(source),
            &format!("-o {}", path_as_str!(out_dir)),
            "-v"
        );
        
        // different key from encryption
        let key_1 = "G4hsElnQWIY7sUPNkmkI6pT0vosQVQPv";
        let key_2 = key_1;

        // decryption checks
        check_decrypt!(
            decryption_exit_code,
            &out_dir,
            out_out_dir,
            source,
            key_1,
            key_2,
            path_as_str!(&out_dir),
            &format!("-o {} -d", path_as_str!(out_out_dir)),
            "-v"
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
                path_as_str!(&source),
                &format!("-o {}", path_as_str!(out_dir.path())),
                "-v"
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
                &format!("-o {}", path_as_str!(out_dir)),
                "-v"
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
                &format!("-o {} -d", path_as_str!(out_out_dir)),
                "-v"
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
            &format!("-o {}", path_as_str!(out_dir.path())),
            "-v"
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
            path_as_str!(out_dir.path()),
            &format!("-o {}", path_as_str!(out_out_dir.path())),
            "-v -d"
        );
    }

    /*
    AuthenticationFail,                    // checksum verification failed for this file
    DecryptionOutdirIsNonempty(PathBuf),   // when decrypting, outdir must be empty
    HashSpecConflict,                      //
    IncrementalEncryptionDisabledForNow => 100,
    InvalidSpreadDepth(SpreadDepth),       // spread depth is outside of the allowed range
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

    metadata_load_failed
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
            path_as_str!(&source),
            &format!("-o {}", path_as_str!(&out_dir)),
            "-v"
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
            path_as_str!(&source.path()),
            &format!("-o {}", path_as_str!(&source.path())),
            "-v"
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
            path_as_str!(&source),
            &format!("-o {}", path_as_str!(&out_dir.path())),
            "-v"
        );
    }

    mod hash_spec_conflict {
        use super::*;

        //
        macro_rules! testgen {
            //
            ( $fn_name:ident, $( $arg:expr ),+ ) => {
                //
                #[test]
                fn $fn_name() {
                    //
                    let exit_code = CsyncErr::HashSpecConflict.exit_code();

                    // same keys
                    let key_1 = "LeVkTH1hGLyYQM4MrGabWbh1STb4IS2P";
                    let key_2 = key_1;

                    //
                    let source = tmpdir!().unwrap();
                    let out_dir = tmpdir!().unwrap();

                    // encryption checks
                    check_core!(
                        exit_code,
                        key_1,
                        key_2,
                        path_as_str!(&source),
                        &format!("-o {}", path_as_str!(&out_dir)),
                        "-v"
                        $( , $arg )+
                    );
                }
            };
        }

        //
        testgen!(pbkdf2_conflict, "--pbkdf2-num-iter 142390", "--pbkdf2-time 2");

        // conflicts within scrypt
        mod scrypt {
            use super::*;

            testgen!(time_logn, "--scrypt-time 3", "--scrypt-log-n 9");
            testgen!(time_r, "--scrypt-time 4", "--scrypt-r 4");
            testgen!(time_p, "--scrypt-time 5", "--scrypt-p 2");
            testgen!(time_r_p, "--scrypt-time 6", "--scrypt-r 3", "--scrypt-p 2");
            testgen!(time_logn_r, "--scrypt-time 6", "--scrypt-log-n 9", "--scrypt-r 3");
            testgen!(time_logn_p, "--scrypt-time 6", "--scrypt-log-n 9", "--scrypt-p 2");
            testgen!(
                time_r_p_logn,
                "--scrypt-time 7",
                "--scrypt-log-n 10",
                "--scrypt-r 3",
                "--scrypt-p 2"
            );
        }

        // conflicts between pbkdf2 and scrypt
        mod pbkdf2_scrypt {
            use super::*;

            testgen!(pbkdf2_time_scrypt_time, "--pbkdf2-time 2", "--scrypt-time 1");
            testgen!(pbkdf2_time_scrypt_logn, "--pbkdf2-time 2", "--scrypt-log-n 9");
            testgen!(pbkdf2_time_scrypt_r, "--pbkdf2-time 2", "--scrypt-r 4");
            testgen!(pbkdf2_time_scrypt_p, "--pbkdf2-time 2", "--scrypt-p 2");

            testgen!(pbkdf2_numiter_scrypt_time, "--pbkdf2-num-iter 141414", "--scrypt-time 2");
            testgen!(pbkdf2_numiter_scrypt_logn, "--pbkdf2-num-iter 123123", "--scrypt-log-n 9");
            testgen!(pbkdf2_numiter_scrypt_r, "--pbkdf2-num-iter 1423122", "--scrypt-r 4");
            testgen!(pbkdf2_numiter_scrypt_p, "--pbkdf2-num-iter 1978239", "--scrypt-p 2");
        }
    }

    mod invalid_spread_depth {
        use super::*;
        use crate::primitives::spread_depth::*;

        //
        macro_rules! testgen {
            //
            ( $fn_name:ident, $( $arg:expr ),+ ) => {
                //
                #[test]
                fn $fn_name() {
                    //
                    let exit_code = CsyncErr::InvalidSpreadDepth(43).exit_code();

                    // same keys
                    let key_1 = "wsJlckEFNdxH5v7Z10pulyOzbglPOfAH";
                    let key_2 = key_1;

                    //
                    let source = tmpdir!().unwrap();
                    let out_dir = tmpdir!().unwrap();

                    // encryption checks
                    check_core!(
                        exit_code,
                        key_1,
                        key_2,
                        path_as_str!(&source),
                        &format!("-o {}", path_as_str!(&out_dir)),
                        "-v"
                        $( , $arg )+
                    );
                }
            };
        }

        testgen!(invalid_0, "--spread-depth 0");

        testgen!(invalid_256, "--spread-depth 256");

        testgen!(invalid_257, "--spread-depth 257");

        testgen!(invalid_12345, "--spread-depth 12345");
    }

    mod incremental_encryption_disabled_for_now {
        use super::*;

        //
        macro_rules! testgen {
            //
            ( $fn_name:ident, $outdir_and_tmpd:expr ) => {
                //
                #[test]
                fn $fn_name() {
                    //
                    let exit_code = CsyncErr::IncrementalEncryptionDisabledForNow.exit_code();

                    // same keys
                    let key_1 = "s5cZP4BNq0LlcWzlPG8vxho569u7d120";
                    let key_2 = key_1;

                    //
                    let source = tmpdir!().unwrap();
                    let (out_dir, tmpd) = $outdir_and_tmpd;

                    // encryption checks
                    check_core!(
                        exit_code,
                        key_1,
                        key_2,
                        path_as_str!(&source),
                        &format!("-o {}", path_as_str!(&out_dir)),
                        "-v"
                    );
                }
            };
        }

        testgen!(contains_file, {
            let tmpd = tmpdir!().unwrap();

            let filepath = tmpd.path().join("4Lhfo56kkktP95PYfXFWc5JNmRT8iCVj");
            {
                std::fs::File::create(&filepath).unwrap();
            }

            (tmpd.path().to_path_buf(), tmpd)
        });

        testgen!(contains_empty_dir, {
            let tmpd = tmpdir!().unwrap();

            let dirpath = tmpd.path().join("4Lhfo56kkktP95PYfXFWc5JNmRT8iCVj");
            std::fs::create_dir(&dirpath).unwrap();

            (tmpd.path().to_path_buf(), tmpd)
        });
    }
}
