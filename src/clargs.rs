use std::path::PathBuf;
use structopt::StructOpt;

/// CryptSync (`csync`) efficiently compresses and encrypts a set of files and directories.
///
/// See the help-page for each subcommand like `csync <SUBCOMMAND> --help`, for example
/// `csync encrypt --help`.
///
/// Project home page: `https://github.com/jackwchoi/csync`
#[derive(Clone, Debug, StructOpt)]
#[structopt(name = "csync")]
pub enum Opts {
    /// Encrypt a directory to a `csync` directory.
    ///
    /// You can configure the following aspects of the encryption process:
    /// AUTHENTICATION ALGORITHM (`--auth`), COMPRESSION ALGORITHM (`--compressor`), ENCRYPTION
    /// ALGORITHM (`--cipher`), KEY DERIVATION ALGORITHM (`--pbkdf2-*` and `--scrypt-*`),
    /// LENGTHS OF RANDOM SALTS (`--salt-len`), NUMBER OF THREADS (`--num-threads`), SPREAD
    /// DEPTH (`--spread_depth`)
    Encrypt {
        /// Use this authentication algorithm; supported algorithms are: `hmac-sha512`.
        #[structopt(long, default_value = "hmac-sha512")]
        auth: String,

        /// Use this encryption algorithm; supported algorithms are: `aes256cbc` and `chacha20`.
        #[structopt(long, default_value = "chacha20")]
        cipher: String,

        /// Use this compression algorithm to use; supported algorithms are: `zstd`.
        #[structopt(long, default_value = "zstd")]
        compressor: String,

        /// Use this many threads; defaults to the number of cores available on the machine.
        #[structopt(short, long = "num-threads")]
        num_threads_opt: Option<usize>,

        /// The csync directory to be created. If a directory exists under this path, a csync directory
        /// will be created with a basename identical name as the source directory. If a directory does
        /// not exist under this path, one will be created.
        /// TODO make this default for --clean
        #[structopt(short, long, parse(from_os_str))]
        out_dir: PathBuf,

        /// Use this algorithm within `pbkdf2`; supported options are `hmac-sha512`.
        /// Defaults to `hmac-sha512`.
        #[structopt(long = "pbkdf2-algorithm")]
        pbkdf2_alg_opt: Option<String>,
        ///
        #[structopt(long = "pbkdf2-num-iter")]
        pbkdf2_num_iter_opt: Option<u32>,
        ///
        #[structopt(long = "pbkdf2-time")]
        pbkdf2_time_to_hash_opt: Option<u16>,

        ///
        #[structopt(long = "scrypt-time")]
        scrypt_time_to_hash_opt: Option<u16>,
        /// Use this as the `log_2(n)` parameter for `scrypt`.
        #[structopt(long = "scrypt-log-n")]
        scrypt_log_n_opt: Option<u8>,
        /// Use this as the `r` parameter for `scrypt`.
        #[structopt(long = "scrypt-r")]
        scrypt_r_opt: Option<u32>,
        /// Use this as the `p` parameter for `scrypt`.
        #[structopt(long = "scrypt-p")]
        scrypt_p_opt: Option<u32>,
        ///
        #[structopt(long = "scrypt-output-len")]
        scrypt_output_len_opt: Option<usize>,

        /// Use salts that are this many bytes long.
        #[structopt(long, default_value = "512")]
        salt_len: u16,

        /// The source directory to csync.
        #[structopt(parse(from_os_str))]
        source: PathBuf,

        /// TODO
        #[structopt(short = "s", long = "spread-depth")]
        spread_depth_opt: Option<usize>,

        /// Print information like step-by-step reporting and timing informations.
        #[structopt(short, long)]
        verbose: bool,
    },

    /// Decrypt a `csync` directory back to its plaintext form.
    Decrypt {
        /// Use this many threads; defaults to the number of cores available on the machine.
        #[structopt(short, long = "num-threads")]
        num_threads_opt: Option<usize>,

        /// The csync directory to be created. If a directory exists under this path, a csync directory
        /// will be created with a basename identical name as the source directory. If a directory does
        /// not exist under this path, one will be created.
        #[structopt(short, long, parse(from_os_str))]
        out_dir: PathBuf,

        /// The source directory to csync.
        #[structopt(parse(from_os_str))]
        source: PathBuf,

        /// Print information like step-by-step reporting and timing informations.
        #[structopt(short, long)]
        verbose: bool,
    },

    /// Clean a `csync` directory by making it as compact as possible.
    Clean {
        /// Use this many threads; defaults to the number of cores available on the machine.
        #[structopt(short, long = "num-threads")]
        num_threads_opt: Option<usize>,

        /// The source directory to csync.
        #[structopt(parse(from_os_str))]
        source: PathBuf,

        /// Print information like step-by-step reporting and timing informations.
        #[structopt(short, long)]
        verbose: bool,
    },
}
