use crate::{encoder::crypt_encoder::*, util::*};
use openssl::symm::{Cipher, Crypter, Mode};
use std::io::{self, BufReader, Error, ErrorKind, Read};

const INITIALIZATION_VECTOR: [u8; 16] = [0; 16];

/// create `EncryptorAES` and `DecryptorAES`
/// using macro because they differ only by the struct name and the openssl::symm::Mode that is used
macro_rules! aes {
    // `$struct_name` => EncryptorAES | DecryptorAES | ..
    // `$crypter_mode` => MODE::Encrypt | MODE::Decrypt
    ( $struct_name:ident, $crypter_mode:expr ) => {
        pub struct $struct_name<R>
        where
            R: Read,
        {
            block_size: usize, // used by `openssl::symm::Crypter`
            encoder: Crypter,  // what does the actual work
            source: BufReader<R>,
        }

        impl<R> $struct_name<R>
        where
            R: Read,
        {
            /// `wrap` just calls this method
            ///
            /// # Parameters
            ///
            /// - `source`: some struct that impls `std::io::Read` that this struct wraps around
            pub fn new(source: R, hash_seed_opt: (&[u8], Option<&[u8]>)) -> io::Result<Self> {
                let (key_hash, seed_opt) = hash_seed_opt;
                assert!(32 <= key_hash.len());
                let seed = seed_opt.unwrap_or(&INITIALIZATION_VECTOR);
                assert!(16 <= seed.len());
                let cipher = Cipher::aes_256_cfb128();

                Ok(Self {
                    block_size: cipher.block_size(), // see `fn read` in `impl Read` for why this is needed
                    source: BufReader::with_capacity(BUFFER_SIZE, source),
                    encoder: Crypter::new(
                        cipher,
                        $crypter_mode, // one of openssl::symm::Mode
                        &key_hash[..32],
                        Some(&seed[..16]),
                    )
                    .map_err(|err| err!("{}", err))?,
                })
            }
        }

        impl<R> Read for $struct_name<R>
        where
            R: Read,
        {
            fn read(&mut self, target: &mut [u8]) -> io::Result<usize> {
                // panics if `output.len() < input.len() + block_size`
                // meaning the following must hold:
                //   output.len()              >= input.len() + block_size
                //   output.len() - block_size >= input.len()
                //
                // NOTE when target.len() - self.block_size == 0, input size is set to 1
                // still don't understand the implications of target.len() being 1
                debug_assert!(0 < target.len());
                let input_size = std::cmp::max(1, target.len() - self.block_size);
                if input_size == 1 {
                    assert_eq!(1, self.block_size);
                }

                // assume that 4096 bytes always produce > 0 number of ciphertext bytes
                assert!(input_size > 0);
                let mut buffer = [0u8; BUFFER_SIZE];
                match self.source.read(&mut buffer) {
                    Ok(bytes_read) => match self.encoder.update(&buffer[..bytes_read], target).map_err(io_err)? {
                        // if 0, assume that we are done so finalize the encoder
                        0 => self.encoder.finalize(&mut target[..]).map_err(io_err),
                        bytes_read => Ok(bytes_read),
                    },
                    Err(err) => panic!("{:?}", err),
                }
            }
        }

        impl<R> CryptEncoder<R> for $struct_name<R> where R: Read {}
    };
}

aes!(EncryptorAES, Mode::Encrypt);

aes!(DecryptorAES, Mode::Decrypt);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{fs_util::*, hasher::*};
    use rayon::prelude::*;

    // decided to explicitly include ciphertext to make sure that the encryption algorithm doesn't
    // change implicitly
    // TODO add checks for initialization vectors
    fn test_data<'a>() -> Vec<(&'a str, &'a str, Vec<u8>)> {
        vec![
            // empty key nonempty data
            (
                "",
                "1 !asd9-1!#$@",
                vec![217, 164, 7, 116, 146, 202, 233, 13, 243, 66, 195, 162, 171],
            ),
            // empty key empty data
            ("", "", vec![]),
            // nonempty key empty data
            ("12-39uaszASD!@ z", "", vec![]),
            // nonempty key nonempty data
            (
                "12-39uaszASD!@ z",
                "1 !asd9-1!#$@",
                vec![22, 63, 194, 45, 233, 28, 69, 41, 200, 87, 183, 82, 36],
            ),
            // nonempty key long data
            (
                "12-39uaszASD!@ z",
                "1 !asd9-1!#$@aoij!@#$ *((_Z!)  !@#$poaksfpokasopdkop12@#!@$@#&(Q%AWDSF(U",
                vec![
                    22, 63, 194, 45, 233, 28, 69, 41, 200, 87, 183, 82, 36, 118, 66, 212, 51, 135, 227, 148, 116, 124, 227,
                    133, 236, 218, 71, 177, 160, 31, 239, 147, 228, 69, 38, 191, 236, 173, 6, 64, 148, 242, 186, 247, 54, 240,
                    99, 188, 67, 55, 145, 165, 230, 81, 121, 223, 115, 171, 93, 119, 252, 123, 30, 243, 38, 239, 126, 137, 86,
                    176, 134, 201,
                ],
            ),
        ]
    }

    macro_rules! encoder_pure {
        ( $fn_name:ident, $( $crypt_encoder:ident ),* ) => {
            fn $fn_name<R: Read>(unhashed_key: &str, data: R) -> io::Result<Vec<u8>> {
                let key_hash = hash_custom(unhashed_key.as_bytes(), None, Some(256));

                compose_encoders!(
                    data,
                    $( $crypt_encoder => (&key_hash[..], None) ),*
                ).unwrap().as_vec()
            }
        };
    }

    encoder_pure!(encrypt_pure, EncryptorAES);

    encoder_pure!(decrypt_pure, DecryptorAES);

    encoder_pure!(identity_pure, EncryptorAES, DecryptorAES);

    mod encryptor_aes {
        use super::*;

        #[test]
        fn parametrized_encrypt() {
            test_data()
                .into_par_iter()
                .for_each(|(unhashed_key, data, expected_ciphertext)| {
                    let data_bytes = data.as_bytes();

                    let ciphertext = encrypt_pure(unhashed_key, data_bytes).unwrap();
                    assert_eq!(ciphertext, expected_ciphertext);
                    if data_bytes.len() > 0 {
                        assert_ne!(data_bytes, &ciphertext[..]);
                    }
                });
        }
    }

    mod decryptor_aes {
        use super::*;

        #[test]
        fn parametrized_decrypt() {
            test_data()
                .into_par_iter()
                .for_each(|(unhashed_key, data, expected_ciphertext)| {
                    let data_bytes = data.as_bytes();
                    if data_bytes.len() > 0 {
                        assert_ne!(data_bytes, &expected_ciphertext[..]);
                    }

                    let decrypted = decrypt_pure(unhashed_key, &expected_ciphertext[..]).unwrap();
                    assert_eq!(&decrypted[..], data_bytes);
                });
        }
    }

    mod compose_encoders {
        use super::*;
        use std::fs::read_to_string;
        use std::fs::File;
        use std::path::Path;

        #[test]
        fn prametrized_inverse() {
            test_data()
                .into_par_iter()
                .for_each(|(unhashed_key, data, expected_ciphertext)| {
                    let data_bytes = data.as_bytes();
                    if data_bytes.len() > 0 {
                        assert_ne!(data_bytes, &expected_ciphertext[..]);
                    }

                    let result = identity_pure(unhashed_key, data_bytes).unwrap();
                    assert_eq!(&result[..], data_bytes);
                });
        }

        #[test]
        fn inverse_with_real_files() {
            let key_hash = hash1!(b"zdpVea3Rm0qEEetZpNAbCKisdhObuzal");

            find("./src")
                .par_bridge()
                .map(Result::unwrap)
                .filter(|path_buf| path_buf.as_path().is_file())
                .map(|src| -> io::Result<()> {
                    let f = |p| File::open(&p);

                    let result = identity_pure("XmUiSf1v7kr0YdanfboSoOM7W0lLi7b4", f(&src)?)?;

                    let mut expected = vec![];
                    f(&src)?.read_to_end(&mut expected)?;

                    Ok(assert_eq!(result, expected))
                })
                .for_each(io::Result::unwrap);
        }

        #[test]
        fn wrong_password_does_not_panic() {
            let enc_pw = hash1!(b"BFYFyPAhRSwuj2TfpcZhmvsofrRKhrnD");
            let dec_pw = hash1!(b"Hy0nQuaNSpKxX5GOhBZxMHKV1aClMscy");
            let encoder = compose_encoders!(
                 File::open(file!()).unwrap(),
                 EncryptorAES => (&enc_pw[..], None),
                 DecryptorAES => (&dec_pw[..], None)
            )
            .unwrap()
            .as_vec()
            .unwrap();
        }
    }

    // check that new_custom with different seed actually works
}
