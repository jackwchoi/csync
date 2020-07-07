use std::path::PathBuf;
use structopt::StructOpt;

/// oeusnth
#[derive(StructOpt, Debug)]
#[structopt(name = "csync")]
pub struct Opts {
    #[structopt(short = "o", long = "out", parse(from_os_str))]
    pub out_dir: PathBuf,

    /*
    /// watch for changes in `source`, and sync when changes are detected
    #[structopt(short = "w", long = "watch")]
    pub watch: bool,
    */
    #[structopt(parse(from_os_str))]
    pub source: PathBuf,
}
