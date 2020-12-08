/// TODO  benchmark the different ciphers
use crate::{encoder::crypt_encoder::*, prelude::*, secure_vec::*};
use openssl::symm::{Cipher, Crypter, Mode};
use std::{
    cmp::min,
    io::{self, BufReader, Error, ErrorKind, Read},
};

const INITIALIZATION_VECTOR: [u8; 16] = [0; 16];

/// create `Aes256CbcEnc` and `Aes256CbcDec`
/// using macro because they differ only by the struct name and the openssl::symm::Mode that is used
macro_rules! cryptor {
    // `$struct_name` => Aes256CbcEnc | Aes256CbcDec | ..
    // `$crypter_mode` => MODE::Encrypt | MODE::Decrypt
    ( $struct_name:ident, $cipher:ident, $crypter_mode:expr ) => {
        ///
        pub struct $struct_name<R>
        where
            R: Read,
        {
            block_size: usize, // used by `openssl::symm::Crypter`
            encoder: Crypter,  // what does the actuali work
            source: BufReader<R>,
            finalized: bool,
        }

        ///
        impl<R> $struct_name<R>
        where
            R: Read,
        {
            /// `wrap` just calls this method
            ///
            /// # Parameters
            ///
            /// - `source`: some struct that impls `std::io::Read` that this struct wraps around
            pub fn new(source: R, key_hash_seed_opt: (&CryptoSecureBytes, Option<&CryptoSecureBytes>)) -> CsyncResult<Self> {
                let cipher = Cipher::$cipher();

                let (key_hash, seed_opt) = key_hash_seed_opt;
                assert!(cipher.key_len() <= key_hash.0.unsecure().len());

                let default = CryptoSecureBytes(SecureVec::new(INITIALIZATION_VECTOR.to_vec()));
                let init_seed = seed_opt.unwrap_or(&default);

                let seed_hash = sha512!(&init_seed.0);
                let seed = match cipher.iv_len() {
                    Some(len) => Some(&seed_hash.0.unsecure()[..len]),
                    None => None,
                };
                let mut encoder = Crypter::new(
                    cipher,
                    $crypter_mode, // one of openssl::symm::Mode
                    &key_hash.0.unsecure()[..cipher.key_len()],
                    seed,
                )?;
                encoder.pad(true);

                // assert_eq!(cipher.iv_len(), Some(12398));
                // https://github.com/PeculiarVentures/node-webcrypto-ossl/issues/112

                Ok(Self {
                    block_size: cipher.block_size(), // see `fn read` in `impl Read` for why this is needed
                    source: BufReader::new(source),
                    encoder,
                    finalized: false,
                })
            }
        }

        ///
        impl<R> Read for $struct_name<R>
        where
            R: Read,
        {
            ///
            fn read(&mut self, target: &mut [u8]) -> io::Result<usize> {
                // panics if `output.len() < input.len() + block_size`
                // meaning the following must hold:
                //   output.len()              >= input.len() + block_size
                //   output.len() - block_size >= input.len()
                debug_assert!(self.block_size <= target.len());
                debug_assert!(target.len() > 4096);
                let output_len = min(target.len(), DEFAULT_BUFFER_SIZE);
                let input_size = output_len - self.block_size;
                let mut buffer = [0u8; DEFAULT_BUFFER_SIZE];

                // 1. read from `source` and update `target` with this read
                // 2. until the read from `source` is 0, repeat step 1
                // 3. once read from `source` is 0, finalize
                match self.source.read(&mut buffer[..input_size])? {
                    // done reading from source, so there is nothing to update `target` with
                    0 => match self.finalized {
                        // self has already been finalized, so signal the end with `Ok(0)`
                        true => Ok(0),
                        // finalize seems to never return 0 when using aes256cbc, so we need to use
                        // the `finalized` flag to remember the fact that on the next call to this
                        // function, we must return `Ok(0)`
                        false => {
                            self.finalized = true;
                            self.encoder
                                .finalize(target)
                                .map_err(|err| Error::new(ErrorKind::Other, err))
                        }
                    },
                    // not done reading yet
                    bytes_read => {
                        // update target with the data we just read from `source`
                        match self
                            .encoder
                            .update(&buffer[..bytes_read], target)
                            .map_err(CsyncErr::from)?
                        {
                            // 0 because `bytes_read` was not large enough for `update`.
                            // recurse so that we read and update again
                            0 => self.read(target),
                            bytes_read => Ok(bytes_read),
                        }
                    }
                }
            }
        }

        ///
        impl<R> CryptEncoder<R> for $struct_name<R>
        where
            R: Read,
        {
            ///
            #[inline]
            fn get_inner(self) -> Option<R> {
                Some(self.source.into_inner())
            }

            ///
            #[inline]
            fn get_inner_ref(&self) -> Option<&R> {
                Some(self.source.get_ref())
            }
        }
    };
}

cryptor!(Aes256CbcEnc, aes_256_cbc, Mode::Encrypt);
cryptor!(Aes256CbcDec, aes_256_cbc, Mode::Decrypt);

cryptor!(ChaCha20Enc, chacha20, Mode::Encrypt);
cryptor!(ChaCha20Dec, chacha20, Mode::Decrypt);

/// TODO generate tests from macros to test for chacha
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{fs_util::*, hasher::*};
    use rayon::prelude::*;
    use std::collections::HashSet;

    /*
        ///
        macro_rules! is_block_cipher {
            ( $cipher:ident ) => {
                1 < Cipher::$cipher().block_size()
            };
        }

        /// Generate test suites for different `openssl::symm::Cipher`s.
        ///
        /// # Parameters
        ///
        /// 1. `$mod_name`: name of the `mod` to contain the generated test suite, for example `aes`,
        ///    `chacha20`
        /// 1. `expecteds`: TODO
        /// 1. `$encryptor`: name of the struct that serves as the encryptor, for example
        ///    `EncryptorAes256Cbc`
        /// 1. `$encryptor`: name of the struct that serves as the decryptor, for example
        ///    `DecryptorAes256Cbc`
        macro_rules! gen_tests {
            ( $mod_name:ident, $expecteds:ident, $encryptor:ident, $decryptor:ident ) => {
    ///
                mod $mod_name {
                    use super::*;

    ///
                    fn test_data() -> Vec<(CryptoSecureBytes, Vec<u8>, Option<CryptoSecureBytes>, Vec<u8>)> {
                        let expecteds = $expecteds();
                        let test_data = key_data_ivopt();
                        assert_eq!(expecteds.len(), test_data.len());
                            test_data
                                .into_iter()
                                .zip(expecteds.into_iter())
                                .map(|((unhashed_key, data, unhashed_iv_opt), expected_ciphertext)| {
                                    (
                                        sha512!(&unhashed_key.into()),
                                        data,
                                        unhashed_iv_opt.map(|x| sha512!(&x)),
                                        expected_ciphertext,
                                    )
                                })
                                .collect()
                    }

    ///
                    #[test]
                    fn verify_test_data() {
                        let expecteds: Vec<_> = $expecteds()
                            .into_iter()
                            .filter(|x| match is_block_cipher!($mod_name) {
                                true => true,
                                false => 0 < x.len()
                            })
                            .collect();
                        let as_set: HashSet<_> = expecteds
                            .iter()
                            .filter(|x| match is_block_cipher!($mod_name) {
                                true => true,
                                false => 0 < x.len()
                            })
                            .cloned()
                            .collect();

                        assert_eq!(expecteds.len(), as_set.len());
                    }

    ///
                    #[test]
                    fn iv_works() {
                        let test_data: HashSet<_> = key_data_ivopt()
                            .into_iter()
                            .map(|(key, data, _)| (key, data))
                            .collect();
                        let ivs: Vec<_> = vec![
                            vec![],
                            vec![124, 171, 142, 15, 175, 18, 99, 185, 108, 132, 207, 73, 186, 239, 174, 152, 42],
                            vec![159, 139, 66, 137, 64, 146, 145, 249, 178, 134, 165, 186, 68, 169, 37, 121, 180],
                            vec![216, 65, 51, 139, 228, 96, 15, 36, 134, 105, 118, 134, 30, 209, 161, 24, 184, 53],
                            vec![229, 85, 49, 186, 109, 225, 198, 174, 47, 64, 170, 253, 90, 58, 233, 66, 160, 28],
                            vec![233, 167, 91, 129, 166, 30, 81, 241, 51, 123, 209, 242, 35, 206, 251, 247, 243],
                            vec![70, 216, 238, 16, 227, 166, 102, 103, 145, 159, 220, 161, 94, 26, 68, 15, 10, 42]
                        ]
                        .into_iter()
                        .map(SecureVec::from)
                        .collect();

                        let all_ciphertexts: HashSet<_> = test_data
                            .par_iter()
                            .cloned()
                            .flat_map(|(key, data)| {
                                let hashed_key = sha512!(&key.into());
                                let ciphertexts: Vec<_> = ivs
                                    .par_iter()
                                    .cloned()
                                    .map(|iv| compose_encoders!(
                                            &data[..],
                                            $encryptor => (&hashed_key, Some(&CryptoSecureBytes(iv)))
                                        )
                                        .unwrap()
                                        .as_vec()
                                        .unwrap())
                                    .collect();

                                ciphertexts
                                    .iter()
                                    .for_each(|ciphertext| match is_block_cipher!($mod_name) {
                                        true => assert_ne!(ciphertext.len(), 0),
                                        false => (),
                                    });

                                match is_block_cipher!($mod_name) {
                                    true => assert_eq!(
                                        ciphertexts.iter().collect::<HashSet<_>>().len(),
                                        ivs.iter().collect::<HashSet<_>>().len()
                                    ),
                                    false => match data.len() {
                                        0 => (),
                                        _ => assert_eq!(
                                            // all ciphertexts with lengths greater than 0
                                            ciphertexts
                                                .iter()
                                                .collect::<HashSet<_>>()
                                                .len(),
                                            ivs
                                                .iter()
                                                .collect::<HashSet<_>>()
                                                .len(),
                                            "abcde"
                                        ),
                                    }
                                }
                                ciphertexts.into_par_iter()
                            })
                            .collect();

                        match is_block_cipher!($mod_name) {
                            true => assert_eq!(all_ciphertexts.len(), test_data.len() * ivs.len()),
                            false => assert_eq!(
                                all_ciphertexts.len(),
                                test_data.iter().filter(|(_, data)| 0 < data.len()).collect::<HashSet<_>>().len()
                                    * ivs.len()
                                    + std::cmp::min(
                                        test_data.iter().filter(|(_, data)| 0 == data.len()).collect::<HashSet<_>>().len(),
                                        1
                                    )
                            ),
                        }
                    }

    ///
                    #[test]
                    fn parametrized_encrypt() {
                        test_data()
                            .into_par_iter()
                            .for_each(|(hashed_key, data, iv_opt, expected_ciphertext)| {
                                let ciphertext = compose_encoders!(
                                    &data[..],
                                    $encryptor => (&hashed_key, iv_opt.as_ref())
                                )
                                .unwrap()
                                .as_vec()
                                .unwrap();
                                assert_eq!(ciphertext, expected_ciphertext);
                                if data.len() > 0 {
                                    assert_ne!(&data, &ciphertext);
                                }
                            });
                    }

    ///
                    #[test]
                    fn parametrized_decrypt() {
                        test_data()
                            .into_par_iter()
                            .for_each(|(hashed_key, data, iv_opt, expected_ciphertext)| {
                                if data.len() > 0 {
                                    assert_ne!(&data[..], &expected_ciphertext[..]);
                                }

                                let decrypted = compose_encoders!(
                                    &expected_ciphertext[..],
                                    $decryptor => (&hashed_key, iv_opt.as_ref())
                                )
                                .unwrap()
                                .as_vec()
                                .unwrap();
                                assert_eq!(&decrypted, &data);
                            });
                    }

    ///
                    mod compose_encoders {
                        use super::*;
                        use std::fs::read_to_string;
                        use std::fs::File;
                        use std::path::Path;

    ///
                        #[test]
                        fn parametrized_inverse() {
                            test_data()
                                .into_iter()
                                .for_each(|(hashed_key, data, iv_opt, expected_ciphertext)| {
                                    if data.len() > 0 {
                                        assert_ne!(data, &expected_ciphertext[..]);
                                    }

                                    let result = compose_encoders!(
                                        &data[..],
                                        $encryptor => (&hashed_key, iv_opt.as_ref()),
                                        $decryptor => (&hashed_key, iv_opt.as_ref())
                                    )
                                    .unwrap()
                                    .as_vec()
                                    .unwrap();
                                    assert_eq!(&result, &data);
                                });
                        }

    ///
                        #[test]
                        fn inverse_with_real_files() {
                            let key_hash = sha512!(&b"zdpVea3Rm0qEEetZpNAbCKisdhObuzal".to_vec().into());
                            let iv_opt = Some(sha512!(&b"Va78UT3Bpy51cTeuAvWSX3d9Gon88YJd".to_vec().into()));

                            ind("./src")
                                .par_bridge()
                                .map(Result::unwrap)
                                .filter(|path_buf| path_buf.as_path().is_file())
                                .map(|src| -> io::Result<()> {
                                    let f = |p| fopen_r(&p);

                                    let hashed_key = sha512!(&b"XmUiSf1v7kr0YdanfboSoOM7W0lLi7b4".to_vec().into());
                                    let result = compose_encoders!(
                                        f(&src)?,
                                        $encryptor => (&hashed_key, iv_opt.as_ref()),
                                        $decryptor => (&hashed_key, iv_opt.as_ref())
                                    )
                                    .unwrap()
                                    .as_vec()
                                    .unwrap();

                                    let mut expected = vec![];
                                    f(&src)?.read_to_end(&mut expected)?;

                                    assert_eq!(result, expected);
                                    Ok(())
                                })
                                .for_each(io::Result::unwrap);
                        }
                    }
                }
            }
        }

        ///
        fn key_data_ivopt() -> Vec<(Vec<u8>, Vec<u8>, Option<SecureBytes>)> {
            vec![
                //    empty key,    empty data, nonempty iv
                (vec![], vec![], None),
                //    empty key, nonempty data, nonempty iv
                (
                    vec![],
                    vec![114, 118, 61, 60, 187, 171, 189, 134, 43, 18, 113, 252, 35, 80, 128, 155, 165],
                    None,
                ),
                // nonempty key,    empty data, nonempty iv
                (
                    b"9yw9OoAKbLcIDOKBPGD8sTumoIdoaceR4VYmrEOtJjszbr2O0nkHUiW8gtoARL57".to_vec(),
                    vec![],
                    None,
                ),
                // nonempty key, nonempty data, nonempty iv
                (
                    b"GdqzqfeXV6xLLP3SIr909Ybj4rn3mFpPU0TAHkUupMwtq8kgKqSFz9lqnyPiu0Zb".to_vec(),
                    vec![66, 43, 106, 227, 20, 38, 228, 185, 11, 99, 68, 220, 121, 105, 207, 230, 218],
                    None,
                ),
                //    empty key,    empty data, nonempty iv
                (
                    vec![],
                    vec![],
                    Some(vec![201, 135, 144, 222, 228, 183, 101, 113, 2, 81, 255, 186, 217, 144].into()),
                ),
                //    empty key, nonempty data, nonempty iv
                (
                    vec![],
                    vec![114, 118, 61, 60, 187, 171, 189, 134, 43, 18, 113, 252, 35, 80, 128, 155, 165],
                    Some(vec![173, 126, 235, 118, 96, 8, 1, 210, 27, 108, 122, 57, 59, 218, 98, 253, 183, 64].into()),
                ), // nonempty key,    empty data, nonempty iv
                (
                    b"9yw9OoAKbLcIDOKBPGD8sTumoIdoaceR4VYmrEOtJjszbr2O0nkHUiW8gtoARL57".to_vec(),
                    vec![],
                    Some(vec![239, 135, 47, 70, 200, 10, 130, 66, 63, 79, 214, 76, 113, 24, 92, 83, 118, 95].into()),
                ),
                // nonempty key, nonempty data, nonempty iv
                (
                    b"GdqzqfeXV6xLLP3SIr909Ybj4rn3mFpPU0TAHkUupMwtq8kgKqSFz9lqnyPiu0Zb".to_vec(),
                    vec![66, 43, 106, 227, 20, 38, 228, 185, 11, 99, 68, 220, 121, 105, 207, 230, 218],
                    Some(vec![89, 29, 76, 67, 199, 83, 84, 68, 23, 171, 142, 216, 12, 83, 15, 159, 228, 226].into()),
                ),
            ]
        }

        // (unhashed_key, data, unhashed_iv, expected_data)
        ///
        #[inline]
        fn test_data_aes256cbc() -> Vec<Vec<u8>> {
            vec![
                vec![176, 235, 24, 113, 92, 121, 132, 167, 137, 189, 168, 219, 62, 208, 19, 198],
                vec![
                    73, 149, 23, 7, 51, 150, 41, 209, 169, 156, 187, 11, 72, 10, 112, 52, 55, 142, 161, 44, 236, 115, 155, 124,
                    201, 91, 14, 216, 91, 169, 147, 155,
                ],
                vec![81, 203, 52, 32, 23, 1, 253, 78, 167, 39, 75, 36, 131, 62, 201, 25],
                vec![
                    145, 83, 108, 85, 122, 37, 134, 149, 207, 13, 37, 194, 71, 193, 53, 222, 43, 178, 229, 214, 97, 164, 124, 140,
                    21, 246, 132, 184, 169, 156, 112, 12,
                ],
                vec![70, 129, 131, 104, 165, 124, 65, 245, 2, 122, 137, 156, 142, 81, 5, 93],
                vec![
                    174, 143, 48, 218, 240, 17, 162, 148, 91, 116, 206, 104, 64, 162, 252, 195, 8, 68, 138, 147, 108, 168, 52, 27,
                    23, 243, 156, 244, 245, 158, 130, 218,
                ],
                vec![22, 255, 99, 148, 228, 24, 224, 60, 159, 182, 22, 223, 13, 123, 11, 174],
                vec![
                    163, 107, 197, 80, 156, 132, 212, 144, 222, 126, 136, 105, 145, 127, 185, 86, 251, 2, 19, 36, 45, 207, 253, 61,
                    109, 193, 18, 248, 86, 32, 135, 28,
                ],
            ]
        }

        // (unhashed_key, data, unhashed_iv, expected_data)
        ///
        #[inline]
        fn test_data_chacha20() -> Vec<Vec<u8>> {
            vec![
                vec![],
                vec![13, 181, 88, 149, 114, 142, 146, 161, 25, 79, 233, 163, 206, 204, 54, 71, 29],
                vec![],
                vec![228, 31, 119, 209, 171, 192, 192, 38, 243, 176, 57, 113, 177, 32, 55, 109, 40],
                vec![],
                vec![
                    244, 130, 95, 237, 109, 247, 11, 173, 57, 129, 123, 125, 187, 186, 194, 99, 155,
                ],
                vec![],
                vec![61, 74, 114, 165, 150, 104, 87, 123, 4, 103, 100, 110, 173, 83, 123, 47, 35],
            ]
        }

        gen_tests!(aes_256_cbc, test_data_aes256cbc, Aes256CbcEnc, Aes256CbcDec);

        gen_tests!(chacha20, test_data_chacha20, ChaCha20Enc, ChaCha20Dec);
        */
}
