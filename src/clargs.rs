use std::path::PathBuf;
use structopt::StructOpt;

/// Crypt-Sync (`csync`) creates a compressed and encrypted archive which can be incrementally
/// updated, meaning that on successive runs `csync` will only sync the files that have changed
/// since the last sync.
///
/// `csync` uses the following default configurations which can be customized
///
///                     Random salt:                  (4096-bit)
///                    Spread depth:                  (3)
///        Authentication algorithm:      HMAC-SHA512 (_)
///           Compression algorithm:        Zstandard (level-3)
///            Encryption algorithm:         ChaCha20 (4096-bit salt)
///        Key-derivation algorithm:           Scrypt (log_n: 20, r: 8, p: 1, 4096-bit output, 4096-bit salt)
///
/// Project home page: `https://github.com/jackwchoi/csync`
#[derive(Clone, Debug, StructOpt)]
#[structopt(name = "csync")]
pub struct Opts {
    /// Use this authentication algorithm; supported algorithms are: `hmac-sha512`.
    /// Defaults to `hmac-sha512`.
    #[structopt(long = "auth")]
    pub auth_opt: Option<String>,

    /// Use this encryption algorithm; supported algorithms are: `aes256cbc` and `chacha20`.
    /// Defaults to `chacha20`.
    #[structopt(long = "cipher")]
    pub cipher_opt: Option<String>,

    /// Clean the provided `csync` directory, making it as compact as possible.
    #[structopt(long = "clean")]
    pub clean: bool,

    /// Use salts that are this many bytes long.
    #[structopt(long = "salt-len")]
    pub salt_len_opt: Option<u16>,

    /// Use this many threads; defaults to the number of cores available on the machine.
    #[structopt(short = "t", long = "num-threads")]
    pub num_threads: Option<usize>,

    /*
    /// Clean the csync directory, making it as compact as possible.
    #[structopt(short="C",long = "no-color")]
    pub no_color: bool,
    */
    /// Use this compression algorithm to use; supported algorithms are: `zstd`.
    /// Defaults to `zstd`.
    #[structopt(long = "compressor")]
    pub compressor_opt: Option<String>,

    /// Decrypt the provided `csync` directory.
    #[structopt(short = "d", long = "decrypt")]
    pub decrypt: bool,

    /*
    /// Run diagnostics and see which options make the most sense for your machine.
    #[structopt(long = "dignostics")]
    pub diagnostics: bool,
    */
    /// The csync directory to be created. If a directory exists under this path, a csync directory
    /// will be created with a basename identical name as the source directory. If a directory does
    /// not exist under this path, one will be created.
    /// TODO make this default for --clean
    #[structopt(short = "o", long = "outdir", parse(from_os_str))]
    pub out_dir: PathBuf,

    /// Use this algorithm within `pbkdf2`; supported options are `hmac-sha512`.
    /// Defaults to `hmac-sha512`.
    #[structopt(long = "pbkdf2-algorithm")]
    pub pbkdf2_alg_opt: Option<String>,
    ///
    #[structopt(long = "pbkdf2-num-iter")]
    pub pbkdf2_num_iter_opt: Option<u32>,
    ///
    #[structopt(long = "pbkdf2-time")]
    pub pbkdf2_time_to_hash_opt: Option<u16>,

    ///
    #[structopt(long = "scrypt-time")]
    pub scrypt_time_to_hash_opt: Option<u16>,
    /// Use this as the `log_2(n)` parameter for `scrypt`.
    #[structopt(long = "scrypt-log-n")]
    pub scrypt_log_n_opt: Option<u8>,
    /// Use this as the `r` parameter for `scrypt`.
    #[structopt(long = "scrypt-r")]
    pub scrypt_r_opt: Option<u32>,
    /// Use this as the `p` parameter for `scrypt`.
    #[structopt(long = "scrypt-p")]
    pub scrypt_p_opt: Option<u32>,
    ///
    #[structopt(long = "scrypt-output-len")]
    pub scrypt_output_len_opt: Option<usize>,

    /// The source directory to csync.
    #[structopt(parse(from_os_str))]
    pub source: PathBuf,

    /// TODO
    #[structopt(short = "s", long = "spread-depth")]
    pub spread_depth_opt: Option<usize>,

    /// Print information like step-by-step reporting and timing informations.
    #[structopt(short = "v", long = "verbose")]
    pub verbose: bool,
}
