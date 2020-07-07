pub use crate::encoder::text::*;
use crate::{prelude::*, secure_vec::*};
use ring::{digest, pbkdf2};
use scrypt::{scrypt, ScryptParams};
use std::num::NonZeroU32;

macro_rules! sha512 {
    ( $key:expr ) => {
        pbkdf2!(ring::pbkdf2::PBKDF2_HMAC_SHA512, 1, $key)
    };
    ( $key:expr, $salt:expr ) => {
        pbkdf2!(ring::pbkdf2::PBKDF2_HMAC_SHA512, 1, $key, $salt)
    };
}

macro_rules! pbkdf2 {
    ( $alg:expr, $num_iter:expr, $key:expr ) => {
        crate::hasher::pbkdf2_custom($alg, $num_iter, None, $key)
    };
    ( $alg:expr, $num_iter:expr, $key:expr, $salt:expr ) => {
        crate::hasher::pbkdf2_custom($alg, $num_iter, Some($salt), $key)
    };
}

macro_rules! scrypt {
    ( $key:expr ) => {
        scrypt!(impl $key, None, None, None)
    };
    ( $key:expr, $salt:expr ) => {
        scrypt!(impl $key, Some($salt), None, None)
    };
    ( $key:expr, $salt:expr, $params:expr ) => {
        scrypt!(impl $key, Some($salt), Some($params), None)
    };
    ( $key:expr, $salt:expr, $params:expr, $output_len:expr ) => {
        scrypt!(impl $key, Some($salt), Some($params), Some($output_len))
    };
    ( impl $key:expr, $salt_opt:expr, $params_opt:expr, $output_len_opt:expr ) => {
        crate::hasher::scrypt_custom($params_opt, $output_len_opt, $salt_opt, $key)
    };
}

/// output_len_opt must be less than
pub fn scrypt_custom(
    params_opt: Option<ScryptParams>,
    output_len_opt: Option<usize>,
    salt_opt: Option<&CryptoSecureBytes>,
    key: &SecureBytes,
) -> CsyncResult<CryptoSecureBytes> {
    //
    let salt = match salt_opt {
        Some(s) => s.clone(),
        None => CryptoSecureBytes(DEFAULT_SALT.to_vec().into()),
    };
    //
    let params = params_opt.unwrap_or({
        let log_n = 15;
        let r = 8;
        let p = 1;
        ScryptParams::new(log_n, r, p)?
    });

    let output_len = output_len_opt.unwrap_or(DEFAULT_SCRYPT_OUTPUT_LEN);

    let mut buffer = vec![0u8; output_len];
    scrypt(key.unsecure(), salt.0.unsecure(), &params, &mut buffer[..])?;

    Ok(buffer).map(SecureVec::from).map(CryptoSecureBytes)
}

pub fn pbkdf2_custom(
    alg: pbkdf2::Algorithm,
    num_iter: u32,
    opt_salt: Option<&CryptoSecureBytes>,
    key: &SecureBytes,
) -> CryptoSecureBytes {
    // default to PBKDF2_NUM__ITER_DEFAULT
    if num_iter == 0 {
        panic!("opt_num_iter cannot be 0");
    }

    let salt = match opt_salt {
        Some(s) => s.clone(),
        None => CryptoSecureBytes(DEFAULT_SALT.to_vec().into()),
    };

    match alg == pbkdf2::PBKDF2_HMAC_SHA512 {
        true => {
            let mut buffer = [0u8; digest::SHA512_OUTPUT_LEN];
            pbkdf2::derive(
                alg,
                NonZeroU32::new(num_iter).unwrap(),
                salt.0.unsecure(),
                key.unsecure(),
                &mut buffer[..],
            );

            CryptoSecureBytes(buffer.to_vec().into())
        }
        false => todo!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs_util::*;
    use rayon::prelude::*;
    use ring::pbkdf2::PBKDF2_HMAC_SHA512;
    use std::{collections::HashSet, fs::File};

    ///
    fn keys<'a>() -> Vec<&'a str> {
        vec!["", "a", "asf", "123", "asfoij123r98!@$%#@$Q%#$T"]
    }

    ///
    mod fix_algorithms {
        use super::*;

        ///
        #[test]
        fn fix_hash1() {
            let key_bytes = b"4s5nRZ8dL0OLdBvYWFR48u9VfbGdLfC3";
            let result = sha512!(&key_bytes.to_vec().into());
            let expected = vec![
                242, 72, 60, 218, 195, 187, 91, 79, 146, 228, 160, 73, 95, 113, 12, 96, 151, 29, 210, 204, 202, 126, 174, 93,
                252, 68, 60, 67, 54, 246, 20, 206, 84, 141, 104, 243, 71, 222, 86, 113, 196, 187, 56, 127, 233, 205, 200, 70,
                166, 20, 93, 103, 19, 180, 53, 82, 108, 139, 98, 187, 51, 13, 126, 211,
            ];
            assert_eq!(result.0.unsecure(), &expected[..]);
            assert_eq!(
                pbkdf2_custom(PBKDF2_HMAC_SHA512, 1, None, &key_bytes.to_vec().into(),)
                    .0
                    .unsecure(),
                &expected[..]
            );
        }

        ///
        #[test]
        fn fix_hash1_with_salt() {
            let key_bytes = b"[200~l1cIATc3DL6UC37Qejf88K23eTXiVtTm";
            let salt = [3u8; 16];
            let result = sha512!(&key_bytes.to_vec().into(), &CryptoSecureBytes(salt.to_vec().into()));
            let expected = vec![
                141, 3, 202, 69, 42, 133, 247, 50, 207, 50, 79, 25, 217, 38, 93, 41, 150, 190, 37, 60, 186, 207, 85, 88, 4,
                118, 242, 238, 136, 224, 76, 138, 141, 3, 113, 151, 50, 4, 105, 228, 15, 135, 166, 113, 148, 236, 250, 117,
                177, 162, 33, 39, 71, 238, 41, 29, 82, 31, 178, 204, 219, 171, 15, 10,
            ];
            assert_eq!(result.0.unsecure(), &expected[..]);
            assert_eq!(
                pbkdf2_custom(
                    PBKDF2_HMAC_SHA512,
                    1,
                    Some(&CryptoSecureBytes(salt.to_vec().into())),
                    &key_bytes.to_vec().into()
                )
                .0
                .unsecure(),
                &expected[..]
            );
        }

        ///
        #[test]
        fn fix_hash() {
            let key_bytes = b"14ys8k0MQUEXjIq7oZd8pKFh11851yr5";
            vec![
                (
                    1 << 16,
                    vec![
                        144, 167, 4, 157, 226, 39, 104, 174, 154, 94, 88, 66, 170, 97, 74, 3, 107, 127, 41, 100, 115, 62, 6,
                        11, 189, 132, 168, 197, 86, 48, 184, 215, 156, 63, 150, 163, 149, 180, 130, 206, 5, 26, 24, 215, 224,
                        189, 231, 168, 185, 96, 16, 54, 171, 113, 153, 227, 74, 196, 203, 108, 106, 66, 126, 133,
                    ],
                ),
                (
                    1 << 17,
                    vec![
                        181, 26, 5, 27, 48, 163, 110, 49, 49, 27, 124, 1, 124, 241, 165, 121, 53, 38, 147, 198, 180, 105, 71,
                        249, 55, 90, 82, 6, 154, 140, 247, 97, 15, 122, 136, 250, 54, 3, 232, 169, 79, 60, 231, 227, 161, 227,
                        55, 86, 67, 132, 184, 82, 149, 144, 195, 255, 146, 239, 7, 26, 139, 15, 108, 225,
                    ],
                ),
            ]
            .into_par_iter()
            .for_each(|(num_iter, expected)| {
                let result = pbkdf2!(PBKDF2_HMAC_SHA512, num_iter, &SecureVec::new(key_bytes.to_vec()));
                assert_eq!(result.0.unsecure(), &expected[..]);
                assert_eq!(
                    pbkdf2_custom(PBKDF2_HMAC_SHA512, num_iter, None, &key_bytes.to_vec().into())
                        .0
                        .unsecure(),
                    &expected[..]
                );
            });
        }

        ///
        #[test]
        fn fix_hash_with_salt() {
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
                let result = pbkdf2!(
                    PBKDF2_HMAC_SHA512,
                    num_iter,
                    &key_bytes.to_vec().into(),
                    &CryptoSecureBytes(salt.to_vec().into())
                );
                assert_eq!(result.0.unsecure(), &expected[..]);
                assert_eq!(
                    pbkdf2_custom(
                        PBKDF2_HMAC_SHA512,
                        num_iter,
                        Some(&CryptoSecureBytes(salt.to_vec().into())),
                        &key_bytes.to_vec().into()
                    )
                    .0
                    .unsecure(),
                    &expected[..]
                );
            });
        }
    }

    ///
    #[test]
    fn hash_is_deterministic() {
        let salt = sha512!(&b"SvMHNJuEsuH3Sx7F4lBOipHogxFdJHl2ySmw9lBzNhMSR6bM8VtyRwHzzQ6AyQVp"
            .to_vec()
            .into());
        // for each key
        keys().into_par_iter().for_each(|key| {
            // for each num iter
            let hashes: HashSet<_> = (0..4)
                .map(|_| pbkdf2_custom(PBKDF2_HMAC_SHA512, 3, Some(&salt), &key.to_string().into()))
                .collect();

            // all hashes are identical
            assert_eq!(1, hashes.len());
            // the hashes are 64 bytes in length
            assert_eq!(64, hashes.iter().nth(0).unwrap().0.unsecure().len());
        });
    }

    /*
    ///
    #[test]
    fn hash_is_deterministic() {
        // for each key
        keys().into_par_iter().for_each(|key| {
            // for each salt length
            vec![0, 1, 2, 4, 8, 16, 32, 64]
                .into_par_iter()
                .map(|len| (0..len).collect::<Vec<_>>())
                .for_each(|salt| {
                    // for each num iter
                    (1..4).for_each(|num_iter| {
                        let set: HashSet<_> = (0..4)
                            .map(|_| {
                                pbkdf2_custom(
                                    PBKDF2_HMAC_SHA512,
                                    num_iter,
                                    Some(&salt.to_vec().into()),
                                    &key.to_string().into(),
                                )
                            })
                            .collect();

                        // all hashes are identical
                        assert_eq!(1, set.len());
                        // the hashes are 64 bytes in length
                        assert_eq!(64, set.iter().nth(0).unwrap().unsecure().len());
                    })
                });
        });
    }
    */
}
