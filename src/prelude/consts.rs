use data_encoding::Encoding;
use data_encoding_macro::*;

pub const BASE32PATH: Encoding = new_encoding! {
    symbols: "abcdefghijklmnopqrstuvwxyz012345",
    padding: '_',
};

// TODO units for the ones below

pub const REPORT_HEADER_NUM_FILES: &str = "Files synced";
pub const REPORT_HEADER_DATA_READ: &str = "Data read";
pub const REPORT_HEADER_DATA_WRITTEN: &str = "Data stored";
pub const REPORT_HEADER_THROUGHPUT: &str = "Throughput";
pub const REPORT_HEADER_DURATION: &str = "Duration";

pub const DEFAULT_BUFFER_SIZE: usize = 1 << 14; // buffer size in bytes
pub const DEFAULT_PERM_BITS: u32 = 0o600; // permission bits of files created by `csync`
pub const DEFAULT_SALT: [u8; 512] = [0u8; 512]; //
pub const DEFAULT_REHASH_OUTPUT_LEN: usize = 512;

pub const DEFAULT_ZSTD_LEVEL: u8 = 3; // same as the `zstd` executable
pub const DEFAULT_ZSTD_LEVEL_STR: &str = "3"; // same as the `zstd` executable

pub const FILE_SUFFIX: &str = "csync"; // extension for encrypted files

const_assert!(0 < DEFAULT_ZSTD_LEVEL && DEFAULT_ZSTD_LEVEL <= 23);
const_assert!(DEFAULT_BUFFER_SIZE == 16384);

#[cfg(test)]
mod tests {
    use super::*;

    ///
    #[test]
    fn default_zstd_level() {
        let from_num = DEFAULT_ZSTD_LEVEL.to_string();
        let from_str = DEFAULT_ZSTD_LEVEL.to_string();
        assert_eq!(from_num, from_str);
    }
}
