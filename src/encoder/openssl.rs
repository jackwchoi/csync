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
