use crate::prelude::DEFAULT_ZSTD_LEVEL_STR;
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
    /// Encrypt a file/directory to a compressed/encrypted `csync` directory.
    Encrypt {
        /// Authentication algorithm to use; supported algorithms are [`hmac-sha512`].
        #[structopt(long, default_value = "hmac-sha512")]
        auth: String,

        /// Encryption algorithm to use; supported algorithms are [`aes256cbc`, `chacha20`].
        #[structopt(long, default_value = "chacha20")]
        cipher: String,

        /// Compression algorithm to use; supported algorithms are [`zstd`].
        #[structopt(long, default_value = "zstd")]
        compressor: String,

        /// Number of threads to use; defaults to the number of cores available on the machine.
        #[structopt(long = "num-threads")]
        num_threads_opt: Option<usize>,

        /// `csync` directory in which compressed/encrypted files will be stored. This directory
        /// must be empty or be another `csync` directory that accepts the password from this
        /// session.
        #[structopt(short, long, parse(from_os_str))]
        out_dir: PathBuf,

        /// supported options are `scrypt`, `pbkdf2`.
        #[structopt(long, default_value = "scrypt")]
        key_deriv_alg: String,

        /// Number of seconds the key derivation process should take on this machine. `csync` will
        /// figure out the approximate parameters
        #[structopt(long, default_value = "4")]
        key_deriv_time: u16,

        /// Indicates that key derivation algorithms should use their explicit parameters rather
        /// than approximating them based on `--key-deriv-time`.
        ///
        /// For example, `csync encrypt src -o out` uses `scrypt` with parameters that obey the
        /// default value of `--key-deriv-time`. Running `csync encrypt src -o out
        /// --key-deriv-by-params` runs `scrypt` using `--scrypt-log-n`, `--scrypt-r, `--scrypt-p`.
        #[structopt(long)]
        key_deriv_by_params: bool,

        /// Use this algorithm within `pbkdf2`; supported options are `hmac-sha512`.
        #[structopt(long = "pbkdf2-alg", default_value = "hmac-sha512")]
        pbkdf2_alg: String,

        /// Number of iterations for `pbkdf2`; ignored unless `--key-deriv-by-params` is specified.
        #[structopt(long = "pbkdf2-num-iter", default_value = "131072")]
        pbkdf2_num_iter: u32,

        /// `log_2(n)` parameter for `scrypt`; ignored unless `--key-deriv-by-params` is specified.
        #[structopt(long, default_value = "15")]
        scrypt_log_n: u8,

        /// `r` parameter for `scrypt`; ignored unless `--key-deriv-by-params` is specified.
        #[structopt(long, default_value = "8")]
        scrypt_r: u32,

        /// `p` parameter for `scrypt`; ignored unless `--key-deriv-by-params` is specified.
        #[structopt(long, default_value = "1")]
        scrypt_p: u32,

        /// Length of the output of `scrypt`, in bytes.
        #[structopt(long, default_value = "512")]
        scrypt_output_len: usize,

        /// Use salts that are this many bytes long.
        #[structopt(long, default_value = "512")]
        salt_len: u16,

        /// The source directory to csync.
        #[structopt(parse(from_os_str))]
        source: PathBuf,

        /// Evenly distribute the compressed/encrypted files into `64^(spread_depth)` different
        /// directories.
        #[structopt(long, default_value="3")]
        spread_depth: u8,

        /// Print information like step-by-step reporting and timing informations.
        #[structopt(short, long)]
        verbose: bool,

        /// Compression level for `zstd`, allowed range is 1-19.
        #[structopt(long, default_value = DEFAULT_ZSTD_LEVEL_STR)]
        zstd_level: u8,
    },

    /// Decrypt a `csync` directory back to its plaintext form.
    Decrypt {
        /// Use this many threads; defaults to the number of cores available on the machine.
        #[structopt(long = "num-threads")]
        num_threads_opt: Option<usize>,

        /// `csync` directory in which compressed/encrypted files will be stored. This directory
        /// must be empty or be another `csync` directory that accepts the password from this
        /// session.
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
        #[structopt(long = "num-threads")]
        num_threads_opt: Option<usize>,

        /// The source directory to csync.
        #[structopt(parse(from_os_str))]
        source: PathBuf,

        /// Print information like step-by-step reporting and timing informations.
        #[structopt(short, long)]
        verbose: bool,
    },
}
