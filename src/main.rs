#[macro_use]
extern crate static_assertions;

// dependency free
mod primitives;
mod secure_vec;

#[macro_use]
mod prelude;

#[macro_use]
mod fs_util;
#[macro_use]
mod hasher;
#[macro_use]
mod rand_util;

#[macro_use]
mod util;

mod specs;

#[macro_use]
mod encoder;
mod test_util;

mod clargs;
mod crypt;

// TODO use prelude::* pattern for each mod

#[cfg(test)]
mod tests_e2e;

use crate::{clargs::*, crypt::syncer::*, prelude::*, secure_vec::*, specs::prelude::*, util::*};
use ansi_term::Colour::Green;
use rayon::prelude::*;
use std::{
    convert::TryFrom,
    fmt, process,
    sync::mpsc::Receiver,
    time::{Duration, Instant},
};
use structopt::StructOpt;

#[derive(Clone, Debug)]
struct RunResult {
    syncer_spec: SyncerSpec,
    sync_stats: SyncStats,
}

///
fn exit(verbose: bool, code: i32) {
    if verbose {
        eprintln!("csync: ERROR! exiting with code {}...", code);
    }
    process::exit(code)
}

assert_cfg!(unix, "Only Unix systems are supported for now");

///
fn main() {
    let opts = clargs::Opts::from_args();

    match run(&opts) {
        Ok(RunResult { sync_stats, .. }) => {
            eprintln!("\n{}", sync_stats);
        }
        Err(err) => {
            eprintln!("csync: ERROR {}", err);
            exit(true, err.exit_code());
        }
    }
}

///
fn get_password() -> CsyncResult<CryptoSecureBytes> {
    let get = |disp| match rpassword::prompt_password_stderr(disp) {
        Ok(pw) => Ok(sha512!(&pw.into())),
        Err(err) => csync_err!(Other, format!("Problem reading the password: {}", err)),
    };
    let initial = get("Enter your password: ")?;
    let confirm = get("Confirm your password: ")?;

    match initial == confirm {
        true => Ok(initial),

        false => csync_err!(PasswordConfirmationFail),
    }
}

fn reporting_thread(start: Instant, receiver: Receiver<Option<(usize, usize)>>) -> std::thread::JoinHandle<()> {
    //
    std::thread::spawn(move || {
        //
        let mut file_count = 0;
        let mut bytes_read = 0;
        let mut bytes_writ = 0;
        //
        loop {
            // TODO change from unwrap to ignoring behavior
            match receiver.recv().unwrap() {
                Some((src_bytes, dst_bytes)) => {
                    let elapsed = end_timer(&start);

                    file_count += 1;
                    bytes_read += src_bytes;
                    bytes_writ += dst_bytes;

                    let format_v = |value: f64, unit| {
                        let (adj_value, adj_unit) = adjust_value(value, unit);
                        Green.paint(format!("{:>7} {}", adj_value, adj_unit))
                    };

                    // TODO format time, report compression ratios
                    eprint!(
                        "\r{} | {} -> {} in {:>7} = {}...",
                        format_v(file_count as f64, "files"),
                        format_v(bytes_read as f64, "B"),
                        format_v(bytes_writ as f64, "B"),
                        Green.paint(format!("{:.3?}", elapsed)),
                        format_v(bytes_read as f64 / (elapsed.as_nanos() as f64) * 1e9, "B/s")
                    );
                }
                None => break,
            }
        }
    })
}

#[derive(Clone, Debug)]
struct SyncStats {
    dest_bytes: f64,
    num_files: usize,
    src_bytes: f64,
    total_dur: Duration,
    total_thru: f64,
}

impl fmt::Display for SyncStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        macro_rules! pretty {
            ( $header:expr, $value:expr ) => {
                write!(f, "{:>32} {:>7}\n", format!("{}:", $header), format!("{:.3?}", $value))
            };
            ( $header:expr, $value:expr, $base_unit:literal ) => {
                match adjust_value($value, $base_unit) {
                    (adj_value, unit) => write!(f, "{:>32} {:>7} {}\n", format!("{}:", $header), adj_value, unit),
                }
            };
        }
        pretty!(REPORT_HEADER_NUM_FILES, self.num_files as f64, "files")?;
        pretty!(REPORT_HEADER_DATA_READ, self.src_bytes, "B")?;
        pretty!(REPORT_HEADER_DATA_WRITTEN, self.dest_bytes, "B")?;
        pretty!(REPORT_HEADER_THROUGHPUT, self.total_thru, "B/sec")?;
        pretty!(REPORT_HEADER_DURATION, &self.total_dur)
    }
}

impl SyncStats {
    fn new(num_files: usize, src_bytes: f64, dest_bytes: f64, total_thru: f64, total_dur: Duration) -> Self {
        Self {
            dest_bytes,
            num_files,
            src_bytes,
            total_dur,
            total_thru,
        }
    }
}

// TODO use macro to circomvent this again
///
fn run(opts: &Opts) -> CsyncResult<RunResult> {
    let external_spec = SyncerSpecExt::try_from(opts)?;

    let init_key = get_password()?;

    // TODO do an initial scan to get file count and size count to get an approxdmate duration?

    //
    macro_rules! handle {
        //
        ( $syncer:expr, $action:ident, $verbose:expr ) => {{
            //
            let syncer = $syncer;
            let syncer_spec = syncer.get_spec();
            let actions = syncer.$action()?;

            //
            if $verbose {
                eprintln!("\nUsing {} threads...", rayon::current_num_threads());
            }

            //
            let (sender, receiver) = std::sync::mpsc::channel();
            let sender_for_termination = sender.clone();
            let sender = std::sync::Mutex::new(sender);

            let report_thread = reporting_thread(start_timer(), receiver);

            if $verbose {
                eprintln!("");
            }

            // TODO just report error using filtermap instead of stopping the whole thing
            let (result, t) = time!(actions
                .map(move |action_res| match action_res {
                    // action and how long that action took
                    Ok(action) => match (std::fs::metadata(action.src), std::fs::metadata(action.dest)) {
                        // sizes oif the src and dest files in bytes
                        // TODO reduce meta calls by including this in meta map and propagating it
                        (Ok(meta_src), Ok(meta_dst)) => {
                            let src_bytes = meta_src.len();
                            let dst_bytes = meta_dst.len();
                            if $verbose {
                                sender
                                    .lock()
                                    .unwrap()
                                    .send(Some((src_bytes as usize, dst_bytes as usize)))
                                    .unwrap();
                            }
                            Ok((src_bytes as f64, dst_bytes as f64))
                        }
                        _ => csync_err!(NonFatalReportFailed),
                    },
                    Err(err) => Err(err),
                })
                .fold(
                    || Ok((0usize, 0f64, 0f64)),
                    |acc_res, res| {
                        match (acc_res, res) {
                            (Ok((count, src_size_acc, dst_size_acc)), Ok((src_size, dst_size))) => Ok((
                                count + 1,               // counting one more
                                src_size_acc + src_size, // sum up the size of src files in bytes
                                dst_size_acc + dst_size, // sum up the size of src files in bytes
                            )),
                            (Err(err), _) | (_, Err(err)) => Err(err),
                        }
                    },
                )
                .reduce(
                    || Ok((0usize, 0f64, 0f64)),
                    |acc_res_a, acc_res_b| match (acc_res_a, acc_res_b) {
                        (Ok((count_a, src_size_a, dst_size_a)), Ok((count_b, src_size_b, dst_size_b))) =>
                            Ok((count_a + count_b, src_size_a + src_size_b, dst_size_a + dst_size_b,)),
                        (Err(err), _) | (_, Err(err)) => Err(err),
                    },
                ));

            if $verbose {
                eprintln!("");
            }

            sender_for_termination.send(None).unwrap();
            report_thread.join().unwrap();

            let (count, bytes_src, bytes_dst) = match result {
                Ok(x) => x,
                Err(err) => Err(err)?,
            };

            let throughput = (bytes_src as f64) / (t.as_nanos() as f64) * 1e9;
            RunResult {
                sync_stats: SyncStats::new(count, bytes_src, bytes_dst, throughput, t),
                syncer_spec,
            }
        }};
    }

    let syncer = Syncer::new(&external_spec, InitialKey(init_key))?;

    // use macro here because `actions = syncer.$action()?` results in an opaque type, which makes
    // match arms have incompatible type
    Ok(match external_spec {
        SyncerSpecExt::Encrypt { verbose, .. } => handle!(syncer, sync_enc, verbose),
        SyncerSpecExt::Decrypt { verbose, .. } => handle!(syncer, sync_dec, verbose),
        SyncerSpecExt::Clean { .. } => todo!(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{fs_util::*, test_util::*, util::*};
    use std::path::Path;

    ///
    #[test]
    fn os_is_unix() {
        assert!(cfg!(unix));
    }

    /*
    mod pseudo {
        use super::*;
        use std::fs::create_dir_all;

        macro_rules! testgen {
            ( $test_name:ident, $block:block ) => {
                #[test]
                fn $test_name() {
                    todo!();
                    /*
                    let (tmpd, src_root) = $block;
                    let out_dir = tmpd.path().join("out");
                    let out_out_dir = tmpd.path().join("out_out");

                    {
                        let key_hash = pbkdf2_1!(
                            &b"llkbuHvCeAQRQjKbPDwS3m8nKyX2HxFHXQMMb0XpDiT5uSJV9wa0ITDWywhB1u1g"
                                .to_vec()
                                .into()
                        );
                        let pbkdf2_num_iter = 256;
                        let spread_depth = 5;
                        /*
                        pub enum SyncerSpecExt {
                            Encrypt {
                                auth_opt: Option<AuthenticatorSpec>,
                                cipher_opt: Option<CipherSpec>,
                                compressor_opt: Option<CompressorSpec>,
                                kd_spec_ext_opt: Option<KeyDerivSpecExt>,
                                out_dir: PathBuf,
                                source: PathBuf,
                                spread_depth_opt: Option<u8>,
                                verbose: bool,
                            },
                            Decrypt {
                                out_dir: PathBuf,
                                source: PathBuf,
                                verbose: bool,
                            },
                            Clean {
                                source: PathBuf,
                                verbose: bool,
                            },
                        }
                        */
                        let enc_res: Vec<_> = Syncer::new(
                            SyncerSpecExt::Encrypt{
                                auth_opt: None,
                                cipher_opt: None,
                                compressor_opt: None,
                                kd_spec_ext_opt: None,

                            }
                            false,
                            Mode::Encrypt,
                            &src_root,
                            &out_dir,
                            Some(KeyDerivSpecExt::Pbkdf2 {
                                num_iter_opt: Some(256),
                                time_opt: None,
                            }),
                            Some(spread_depth),
                            key_hash.clone(),
                        )
                        .unwrap()
                        .sync_enc(false)
                        .unwrap()
                        .map(Result::unwrap)
                        .collect();

                        let dec_res: Vec<_> = Syncer::new(
                            false,
                            Mode::Decrypt,
                            &out_dir,
                            &out_out_dir,
                            None,
                            Some(4),
                            key_hash,
                        )
                        .unwrap()
                        .sync_dec(false)
                        .unwrap()
                        .map(Result::unwrap)
                        .collect();
                    }

                    let src_basename = basename(&src_root).unwrap();
                    let dest = out_out_dir.join(src_basename);

                    assert_tree_eq(&src_root, &dest);
                    */
                }
            };
        }

        testgen!(empty_dir, {
            let tmpd = tmpdir!().unwrap();
            let empty_dir = tmpd.path().join("dhxg");
            create_dir_all(&empty_dir).unwrap();
            (tmpd, empty_dir)
        });

        testgen!(empty_file, {
            let tmpd = tmpdir!().unwrap();
            let empty_dir = tmpd.path().join("bwn0");
            {
                fopen_w(&empty_dir).unwrap();
            }
            (tmpd, empty_dir)
        });

        testgen!(text_file, { (tmpdir!().unwrap(), PathBuf::from("src/main.rs")) });

        testgen!(text_files, { (tmpdir!().unwrap(), PathBuf::from("src")) });

        testgen!(bin_files, { (tmpdir!().unwrap(), PathBuf::from(".git")) });
    }
    */
}
