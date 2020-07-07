pub use crate::encoder::text::*;
use crate::util::*;
use ring::{digest, pbkdf2};
use std::{
    io::{self, Read},
    num::NonZeroU32,
};

pub const PBKDF2_NUM_ITER_DEFAULT: u32 = 1 << 17; // default number of iterations for pbkdf2, 2^17 = 131,072
pub const PBKDF2_SALT_DEFAULT: [u8; 16] = [0; 16]; // default salt to use for pbkdf2
pub static PBKDF2_ALGORITHM: pbkdf2::Algorithm = pbkdf2::PBKDF2_HMAC_SHA512; // default hash algorithm to use for pbkdf2
const PBKDF2_OUTPUT_LEN: usize = digest::SHA512_OUTPUT_LEN; // number of bytes that pbkdf2 should output

// static assertions about the consts above
const_assert!(PBKDF2_NUM_ITER_DEFAULT == 131072);
const_assert!(PBKDF2_OUTPUT_LEN == 64);
const_assert!(PBKDF2_SALT_DEFAULT.len() == 16);

/// Hash key with default configs using `pbkdf2`.
///
/// Configs used are:
///
/// 1. `PBKDF2_NUM_ITER_DEFAULT` number of iterations
/// 1. `PBKDF2_SALT_DEFAULT` as the salt
///
/// # Parameters
///
/// 1. `key`: the input bytes to hash
///
/// # Returns
///
/// 64-byte hash of the input key as `Vec<u8>`
macro_rules! hash {
    ( $num_iter:expr, $key:expr ) => {
        crate::hasher::hash_custom($key, None, Some($num_iter))
    };
    ( $num_iter:expr, $key:expr, $salt:expr ) => {
        crate::hasher::hash_custom($key, Some($salt), Some($num_iter))
    };
}

/// Hash key with default configs using `pbkdf2`, except with 1 iteration.
///
/// Configs used are:
///
/// 1. 1 number of iteration
/// 1. `PBKDF2_SALT_DEFAULT` as the salt
///
/// # Parameters
///
/// 1. `key`: the input bytes to hash
///
/// # Returns
///
/// 64-byte hash of the input key as `Vec<u8>`
macro_rules! hash1 {
    ( $key:expr ) => {
        crate::hasher::hash_custom($key, None, Some(1))
    };
    ( $key:expr, $salt:expr ) => {
        crate::hasher::hash_custom($key, Some($salt), Some(1))
    };
}

/// Hash key with custom configs using `pbkdf2`.
///
/// Configs used are:
///
/// # Parameters
///
/// 1. `key`: the input bytes to hash
/// 1. `opt_salt`: if provided, it will be hashed with this function with 1 iteration and
///    PBKDF2_SALT_DEFAULT and the first 16 bytes are used. PBKDF2_SALT_DEFAULT is used otherwise.
/// 1. `opt_num_iter`: number of PBKDF2 iterations; `PBKDF2_NUM_ITER_DEFAULT` is used if `None`
///
/// # Returns
///
/// 64-byte hash of the input key.
pub fn hash_custom(key: &[u8], opt_salt: Option<&[u8]>, opt_num_iter: Option<u32>) -> Vec<u8> {
    // default to PBKDF2_NUM__ITER_DEFAULT
    let num_iter = opt_num_iter.unwrap_or(PBKDF2_NUM_ITER_DEFAULT);
    if num_iter == 0 {
        panic!("opt_num_iter cannot be 0");
    }

    // if salt is provided, hash it again asd use the first 16 bytes
    // else use the default hash
    let salt: Vec<u8> = match opt_salt {
        Some(s) if s.len() < 16 => hash_custom(s, None, Some(1)).into_iter().take(16).collect(),
        Some(s) => Vec::from(&s[..16]),
        None => Vec::from(&PBKDF2_SALT_DEFAULT[..]),
    };

    // required by pbkdf2
    debug_assert_eq!(16, salt.len());

    let mut buffer = [0u8; PBKDF2_OUTPUT_LEN];
    pbkdf2::derive(
        PBKDF2_ALGORITHM,
        NonZeroU32::new(num_iter).unwrap(),
        &salt[..],
        key,
        &mut buffer[..],
    );

    Vec::from(&buffer[..])
}

/// Calculate a SHA512 checksum of the input.
pub fn sha512_read<R>(file: &mut R) -> io::Result<Vec<u8>>
where
    R: Read,
{
    let mut buffer = [0u8; BUFFER_SIZE];
    let mut context = digest::Context::new(&digest::SHA512);

    loop {
        match file.read(&mut buffer)? {
            0 => {
                let digest = context.finish();
                break Ok(Vec::from(digest.as_ref()));
            }
            bytes_read => context.update(&buffer[..bytes_read]),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs_util::*;
    use rayon::prelude::*;
    use std::collections::HashSet;
    use std::fs::File;

    fn keys<'a>() -> Vec<&'a str> {
        vec!["", "a", "asf", "123", "asfoij123r98!@$%#@$Q%#$T"]
    }

    fn salt_lengths() -> Vec<u8> {
        vec![0, 1, 2, 4, 8, 16, 32, 64]
    }

    mod fix_algorithms {
        use super::*;

        #[test]
        fn fix_hash1() {
            let key_bytes = "4s5nRZ8dL0OLdBvYWFR48u9VfbGdLfC3".as_bytes();
            let result = hash1!(key_bytes);
            let expected = vec![
                242, 209, 3, 16, 92, 90, 71, 234, 5, 78, 222, 209, 254, 200, 76, 0, 197, 176, 129, 154, 5, 213, 178, 164, 255,
                103, 170, 92, 9, 97, 96, 188, 30, 152, 236, 186, 30, 80, 9, 63, 204, 51, 43, 61, 101, 22, 10, 253, 246, 34, 69,
                59, 63, 34, 0, 98, 132, 122, 184, 136, 173, 242, 20, 199,
            ];
            assert_eq!(result, expected);
            assert_eq!(hash_custom(key_bytes, None, Some(1)), expected);
        }

        #[test]
        fn fix_hash1_with_keys() {
            let key_bytes = "[200~l1cIATc3DL6UC37Qejf88K23eTXiVtTm".as_bytes();
            let salt = [3u8; 16];
            let result = hash1!(key_bytes, &salt);
            let expected = vec![
                141, 3, 202, 69, 42, 133, 247, 50, 207, 50, 79, 25, 217, 38, 93, 41, 150, 190, 37, 60, 186, 207, 85, 88, 4,
                118, 242, 238, 136, 224, 76, 138, 141, 3, 113, 151, 50, 4, 105, 228, 15, 135, 166, 113, 148, 236, 250, 117,
                177, 162, 33, 39, 71, 238, 41, 29, 82, 31, 178, 204, 219, 171, 15, 10,
            ];
            assert_eq!(result, expected);
            assert_eq!(hash_custom(key_bytes, Some(&salt), Some(1)), expected);
        }

        #[test]
        fn fix_hash() {
            let key_bytes = b"14ys8k0MQUEXjIq7oZd8pKFh11851yr5";
            vec![
                (
                    1 << 16,
                    vec![
                        55, 188, 78, 11, 109, 252, 230, 30, 162, 183, 97, 71, 105, 40, 182, 83, 131, 9, 42, 142, 224, 41, 176,
                        110, 188, 251, 202, 102, 101, 76, 59, 15, 122, 141, 162, 161, 171, 197, 73, 135, 0, 144, 215, 208, 91,
                        72, 6, 248, 220, 104, 219, 114, 215, 45, 92, 164, 246, 118, 135, 23, 157, 227, 82, 10,
                    ],
                ),
                (
                    1 << 17,
                    vec![
                        57, 40, 12, 174, 25, 7, 196, 243, 252, 220, 104, 37, 65, 10, 152, 231, 118, 25, 100, 42, 88, 186, 155,
                        190, 114, 89, 56, 189, 222, 158, 44, 189, 17, 83, 144, 213, 89, 122, 162, 251, 243, 140, 250, 138, 204,
                        107, 14, 93, 99, 127, 70, 0, 67, 24, 81, 86, 66, 53, 182, 161, 194, 74, 173, 45,
                    ],
                ),
            ]
            .into_par_iter()
            .for_each(|(num_iter, expected)| {
                let result = hash!(num_iter, key_bytes);
                assert_eq!(result, expected);
                assert_eq!(hash_custom(key_bytes, None, Some(num_iter)), expected);
            });
        }

        #[test]
        fn fix_hash_with_keys() {
            let key_bytes = b"9BGVrWW5FKl4qtvMXuI67ag8PpXqVV94";
            let salt = [3u8; 16];
            vec![
                (
                    1 << 16,
                    vec![
                        22, 5, 196, 164, 214, 45, 61, 231, 155, 63, 59, 19, 26, 181, 189, 194, 251, 149, 220, 0, 112, 147, 54,
                        218, 101, 237, 58, 51, 141, 238, 216, 71, 186, 213, 154, 87, 201, 55, 170, 52, 178, 20, 35, 41, 45, 89,
                        80, 141, 59, 90, 18, 207, 127, 192, 70, 170, 107, 165, 43, 179, 223, 87, 83, 53,
                    ],
                ),
                (
                    1 << 17,
                    vec![
                        87, 44, 214, 12, 172, 54, 121, 29, 103, 27, 147, 82, 110, 105, 190, 197, 173, 245, 136, 214, 50, 249,
                        121, 217, 244, 40, 38, 127, 202, 158, 58, 219, 21, 135, 118, 0, 147, 183, 96, 122, 75, 44, 53, 172,
                        206, 148, 57, 168, 105, 63, 251, 178, 81, 188, 219, 116, 132, 71, 216, 75, 127, 202, 125, 62,
                    ],
                ),
            ]
            .into_par_iter()
            .for_each(|(num_iter, expected)| {
                let result = hash!(num_iter, key_bytes, &salt);
                assert_eq!(result, expected);
                assert_eq!(hash_custom(key_bytes, Some(&salt), Some(num_iter)), expected);
            });
        }
    }

    #[test]
    fn hash_is_deterministic() {
        // for each key
        keys().into_par_iter().for_each(|key| {
            // for each salt length
            salt_lengths()
                .into_par_iter()
                .map(|len| (0..len).collect::<Vec<_>>())
                .for_each(|salt| {
                    // for each num iter
                    (1..4).for_each(|num_iter| {
                        let set: HashSet<_> = (0..4)
                            .map(|_| hash_custom(key.as_bytes(), Some(&salt), Some(num_iter)))
                            .collect();

                        // all hashes are identical
                        assert_eq!(1, set.len());
                        // the hashes are 64 bytes in length
                        assert_eq!(64, set.iter().nth(0).unwrap().len());
                    })
                });
        });
    }

    mod sha512_read {
        use super::*;
        use std::io::Write;

        macro_rules! file {
            ( $root:expr, $filename:expr ) => {{
                let path = $root.path().join($filename);
                {
                    fopen_w(&path).unwrap();
                }
                File::open(path).unwrap()
            }};
            ( $root:expr, $filename:expr, $content:expr ) => {{
                let path = $root.path().join($filename);
                {
                    let mut file = fopen_w(&path).unwrap();
                    file.write($content).unwrap();
                }
                File::open(path).unwrap()
            }};
        }

        /// 1. 2 of the 3 files are empty, so the se tof the checksums is size 2
        #[test]
        fn empty_files() {
            let dir = tmpdir!().unwrap();
            let checksums: HashSet<_> = vec![
                file!(dir, "tXryV7s9WWPM7ljK7OQ2YL5bBpe0zKD6"),
                file!(dir, "1FINZBhrkWruNGgiQwdCEXyhpZDxmQxl"),
                file!(dir, "CacAccgKVUvVQgvuwsJq5WwdDdRk2bDn", b"yWv0UUzc53KLoipjfSVvmAPf4fm2QebD"),
            ]
            .par_iter_mut()
            .map(sha512_read)
            .map(Result::unwrap)
            .collect();

            assert_eq!(checksums.len(), 2);
        }

        /// 1. 2 of the 3 files have the same content, so the set of the checksums is size 2
        #[test]
        fn content_collisions() {
            let dir = tmpdir!().unwrap();
            let checksums: HashSet<_> = vec![
                file!(dir, "iLPCceoxfqvFpNJ4CIMEeeoG8J9D0zxY", b"1XU5qM4XPJlt97T1QpA6OJRrw34EvKXY"),
                file!(dir, "CyirAhBFFAmbcTBSJf0weN6VisU9RaUX", b"bbUlD2vEWsN94JwgHVmCnmlYSdZ28dZc"),
                file!(dir, "hJrHYoXJSIHOXnqhAj5umrzcOTTnn0cI", b"bbUlD2vEWsN94JwgHVmCnmlYSdZ28dZc"),
            ]
            .par_iter_mut()
            .map(sha512_read)
            .map(Result::unwrap)
            .collect();

            assert_eq!(checksums.len(), 2);
        }

        /// 1. 3 of the 4 files have the same content, so the set of the checksums is size 2
        /// 2. make sure that after reading `n` bytes from a file, the checksum function discards
        ///    those bytes when computing the hash
        #[test]
        fn mutated_files() {
            let dir = tmpdir!().unwrap();

            // file3 will have `common` as its content, while file4 will have the bytes `abcd`
            // followed by `common`
            let common = "zEHseHP8Pelv8Rm78mi1OVp3bPAqxjve";
            let common_with_junk = format!("abcd{}", common);

            // read 4 bytes from the file, and return the mutated file
            let mutated = {
                let mut mutated = file!(dir, "mbkiLksWk7QvlogMykQGrEQOGe1rH3cN", common_with_junk.as_bytes());
                let mut buffer = [0u8; 4];
                mutated.read(&mut buffer).unwrap();
                assert_eq!(&buffer[..], b"abcd");
                mutated
            };

            let checksums: HashSet<_> = vec![
                file!(dir, "E9xQqcHyvGSRvbfPsSH6KbYAVkFgT3sX", b"zDK6ePdXfZ9kN8acogTYvVujh2aCPbM2"),
                file!(dir, "yyuV7ASsoMnNZnhLcfgDIeemDCZj3ggv", b"bK0XunltMMAeq9ViE33WtP4gwOnb0UIY"),
                file!(dir, "s53EX50oyakRf2lVGUdFdpFjzhe0Cniq", common.as_bytes()),
                mutated,
            ]
            .par_iter_mut()
            .map(sha512_read)
            .map(Result::unwrap)
            .collect();

            assert_eq!(checksums.len(), 3);
        }
    }
}
