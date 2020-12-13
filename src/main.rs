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
#[allow(dead_code)] // because most functions in this mod are only used in tests
mod test_util;

mod clargs;
mod crypt;

#[cfg(test)]
mod tests_e2e;

use crate::{clargs::*, crypt::syncer::*, prelude::*, secure_vec::*, specs::prelude::*, util::*};
use rayon::prelude::*;
use std::{
    convert::TryFrom,
    fmt,
    sync::mpsc::Receiver,
    time::{Duration, Instant},
};
use structopt::StructOpt;

macro_rules! color {
    ( $color:ident, $fmt_str:literal $( , $arg:expr )* ) => {
        ansi_term::Colour::$color.paint(format!($fmt_str $( , $arg )*))
    }
}

#[derive(Clone, Debug)]
struct RunResult {
    syncer_spec: SyncerSpec,
    sync_stats: SyncStats,
}

#[derive(Clone, Debug)]
struct SyncStats {
    dest_bytes: f64,
    num_files: usize,
    src_bytes: f64,
    total_dur: Duration,
    total_thru: f64,
}

assert_cfg!(unix, "Only Unix systems are supported for now");

///
fn main() {
    // parse the cli args
    let opts = clargs::Opts::from_args();

    //
    match run(&opts) {
        Ok(RunResult { sync_stats, .. }) => {
            eprintln!("\n{}", sync_stats);
        }
        Err(err) => {
            //
            eprintln!("{}", color!(Red, "csync: ERROR {}", err));

            // this is used to uniquely identify the types of errors, for testing purposes
            std::process::exit(err.exit_code());
        }
    }
}

///
fn get_password(confirm: bool) -> CsyncResult<CryptoSecureBytes> {
    //
    let get = |disp| match rpassword::prompt_password_stderr(disp) {
        Ok(pw) => Ok(sha512!(&pw.into())),
        Err(err) => csync_err!(Other, format!("Problem reading the password: {}", err)),
    };
    let initial = get("Enter your password: ")?;

    match confirm {
        true => {
            let confirm = get("Confirm your password: ")?;

            // constant time comparison
            match initial == confirm {
                true => Ok(initial),
                false => csync_err!(PasswordConfirmationFail),
            }
        }
        false => Ok(initial),
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
            //
            // \r and print the err file \n if error
            // the ncontinue with the updating line
            match receiver.recv().unwrap() {
                Some((src_bytes, dst_bytes)) => {
                    let elapsed = end_timer(&start);

                    file_count += 1;
                    bytes_read += src_bytes;
                    bytes_writ += dst_bytes;

                    let format_v = |value: f64, unit| {
                        let (adj_value, adj_unit) = adjust_value(value, unit);
                        color!(Green, "{:>7} {}", adj_value, adj_unit)
                    };

                    // TODO format time, report compression ratios
                    eprint!(
                        "\r{} | {} -> {} in {:>7} = {}...",
                        format_v(file_count as f64, "files"),
                        format_v(bytes_read as f64, "B"),
                        format_v(bytes_writ as f64, "B"),
                        color!(Green, "{:.3?}", elapsed),
                        format_v(bytes_read as f64 / (elapsed.as_nanos() as f64) * 1e9, "B/s")
                    );
                }
                None => break,
            }
        }
    })
}

impl fmt::Display for SyncStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        macro_rules! pretty {
            ( $header:expr, $value:expr ) => {
                write!(f, "{:>32} {:>7}\n", format!("{}:", $header), format!("{:.3?}", $value))
            };
            ( $header:expr, $value:expr, $base_unit:literal ) => {{
                let (adj_value, unit) = adjust_value($value, $base_unit);
                write!(f, "{:>32} {:>7} {}\n", format!("{}:", $header), adj_value, unit)
            }};
        }
        pretty!(REPORT_HEADER_NUM_FILES, self.num_files as f64, "files")?;
        pretty!(REPORT_HEADER_DATA_READ, self.src_bytes, "B")?;
        pretty!(REPORT_HEADER_DATA_WRITTEN, self.dest_bytes, "B")?;
        pretty!(REPORT_HEADER_THROUGHPUT, self.total_thru, "B/sec")?;
        pretty!(REPORT_HEADER_DURATION, &self.total_dur)
    }
}

//
impl SyncStats {
    //
    #[inline]
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
    //
    let external_spec = SyncerSpecExt::try_from(opts)?;

    // TODO configure num threads
    // https://docs.rs/rayon/1.5.0/rayon/struct.ThreadPoolBuilder.html
    // rayon::ThreadPoolBuilder::new().num_threads(22).build_global().unwrap();

    // the key that the user entered
    // TODO also, don't confirm if incremental build
    let confirm_password = !opts.decrypt && !opts.clean;
    let init_key = get_password(confirm_password)?;

    // TODO do an initial scan to get file count and size count to get an approxdmate duration?

    //
    macro_rules! handle {
        //
        ( $syncer:expr, $action:ident, $verbose:expr ) => {{
            // syncer-related
            let syncer = $syncer;
            let syncer_spec = syncer.get_spec();
            let actions = syncer.$action()?;

            //
            if $verbose {
                eprintln!("\nUsing {} threads...", rayon::current_num_threads());
            }

            // channel for the thread that updates progress real time
            let (sender, receiver) = std::sync::mpsc::channel();
            let sender_for_termination = sender.clone();
            let sender = std::sync::Mutex::new(sender);

            let report_thread = reporting_thread(start_timer(), receiver);

            // TODO just report error using filtermap instead of stopping the whole thing
            let (result, time_taken) = time!(actions
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

            sender_for_termination.send(None).unwrap();
            report_thread.join().unwrap();

            let (count, bytes_src, bytes_dst) = result?;

            let throughput = (bytes_src as f64) / (time_taken.as_nanos() as f64) * 1e9;
            RunResult {
                sync_stats: SyncStats::new(count, bytes_src, bytes_dst, throughput, time_taken),
                syncer_spec,
            }
        }};
    }

    //
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
    // this is mostly due to the fact that we use perm bits
    // maybe
    #[test]
    fn os_is_unix() {
        assert!(cfg!(unix));
    }
}
