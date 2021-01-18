use crate::{prelude::*, test_util::*, util::*};
use std::path::Path;
use std::{io, path::PathBuf};

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
pub fn bytes_to_str(bytes: &[u8]) -> &str {
    std::str::from_utf8(bytes).unwrap()
}

// # Returns
//
// Non-overlapping matches of the regex pattern, `pattern`, within `text`.
pub fn matches(pattern: &str, text: &str) -> Vec<String> {
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
pub fn bash(command: &str) -> io::Result<std::process::Child> {
    std::process::Command::new("bash")
        .arg("-c")
        .arg(command)
        .stdin(std::process::Stdio::piped() /*  &0 */)
        .stdout(std::process::Stdio::piped() /* &1 */)
        .stderr(std::process::Stdio::piped() /* &2 */)
        .spawn()
}

//
pub fn grep_report_line_with_header(header: &str, output: &std::process::Output) -> String {
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
pub fn check_report_line(line: &str, value: f64, unit: &str) {
    let (adjusted_value, adj_unit) = adjust_value(value, unit);
    assert!(line.ends_with(&adj_unit));
    assert!(line.contains(&adjusted_value));
}

// # Returns
//
// An iterator of files in `source` that csync cares about.
pub fn get_all_source<P>(source: P) -> impl Iterator<Item = PathBuf>
where
    P: AsRef<Path>,
{
    find(source).map(CsyncResult::unwrap)
}

// # Returns
//
// An iterator of files in `outdir` that csync cares about.
pub fn get_all_outdir<P>(outdir: P) -> impl Iterator<Item = PathBuf>
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
        $subcommand:literal,
        $( $arg:expr ),+
    ) => {{
        // `std::process::Output` resulting from the child proc
        let output = {
            // concat args  to spawn a child process
            let mut proc = {
                let command: String = vec!["cargo run --", $subcommand, $( $arg ),+]
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
        $source_filter:block,
        $outdir_filter:block,
        $( $arg:expr ),+
    ) => {{
        //
        let source = $source;
        //
        let out_dir = $out_dir;
        // hash of the directory structure, te see if anything changes
        let out_dir_hash_before = hash_tree(&out_dir);

        //
        let output = check_core!($exit_code_expected, $key_1, $key_2, "encrypt", $( $arg ),+);

        // exit code of the process
        match output.status.code().unwrap() {
            // if no error, do more correctness checks
            0 => {
                // check the number of files synced
                {
                    // count all files and dirs in `$source`; these are the ones that `csync` encrypts
                    let source_file_count = get_all_source(&source).filter($source_filter).count();
                    // count only the files in `$out_dir`; everything else in there doesn't really care
                    let cipher_file_count = get_all_outdir(&out_dir).filter($outdir_filter).count();
                    // check that the 2 are equal, meaning that the correct number have been synced
                    assert_eq!(source_file_count, cipher_file_count, "check_encrypt! count match fail");

                    // check that `csync` reports the correct number, for number of files synced
                    let file_count_line = grep_report_line_with_header(REPORT_HEADER_NUM_FILES, &output);
                    check_report_line(&file_count_line, source_file_count as f64, "files");
                }

                // check the amount of data read from `$source`
                {
                    // sum up the number of bytes in each file/dir in `$source`
                    let data_read: u64 = get_all_source(&source)
                        .filter($source_filter)
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
                        .filter($outdir_filter)
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
                let out_dir_hash_after = hash_tree(&out_dir);
                assert_eq!(out_dir_hash_before, out_dir_hash_after);
            },
        };
        output
    }};
    (
        $exit_code_expected:expr,
        $source:expr,
        $out_dir:expr,
        $key_1:expr,
        $key_2:expr,
        $( $arg:expr ),+
    ) => {
        check_encrypt!(
            $exit_code_expected,
            $source,
            $out_dir,
            $key_1,
            $key_2,
            { |_| true },
            { |_| true },
            $( $arg ),+
        );
    }
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
        let output = check_core!($exit_code_expected, $key_1, $key_2, "decrypt", $( $arg ),+);

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
                &format!("-o {}", path_as_str!(out_dir_path))
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
