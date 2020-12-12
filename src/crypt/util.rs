use crate::{
    encoder::{hmac::*, identity::*, openssl::*, zstd::*},
    fs_util::*,
    prelude::*,
    secure_vec::*,
    specs::prelude::*,
    util::*,
};
use ring::hmac;
use serde::{de::DeserializeOwned, Serialize};
use std::{
    fmt::Debug,
    fs::File,
    io::{Read, Write},
    path::Path,
};

// consts about random padding used in the encryption
const MIN_RANDPAD_LEN: u64 = 1;
const MAX_RANDPAD_LEN: u64 = 1 << 11;
const PAD_DELIMITER: u8 = 0;

pub const MIN_DIR_RAND_DATA_LEN: u64 = 1 << 4;
pub const MAX_DIR_RAND_DATA_LEN: u64 = 1 << 10;

const_assert!(MAX_RANDPAD_LEN == 2048);
const_assert!(MIN_DIR_RAND_DATA_LEN == 16);
const_assert!(MAX_DIR_RAND_DATA_LEN == 1024);

// # Parameters
//
// 1. `data`: some data to serialize
//
// # Returns
//
// `data` serialized into a compact format, which can be deserializsed using
// `crate::crypt::util::deser`
fn ser<T>(data: &T) -> CsyncResult<SecureBytes>
where
    T: Debug + Serialize,
{
    let data_ser: SecureBytes = serialize(data)?.into();
    let data_ser_len: SecureBytes = u32_to_u8s(data_ser.unsecure().len() as u32).into();
    debug_assert!(data_ser.unsecure().len() < std::u32::MAX as usize);
    debug_assert_eq!(u8s_to_u32(data_ser_len.unsecure()), data_ser.unsecure().len() as u32);

    macro_rules! bytes_iter {
        ( $secure_bytes:expr ) => {
            $secure_bytes.unsecure().iter()
        };
    }
    Ok(bytes_iter!(data_ser_len)
        .chain(bytes_iter!(data_ser))
        .copied()
        .collect::<Vec<_>>()
        .into())
}

// # Parameters
//
// 1. `source`: sequence of bytes, where the output of `crate::crypt::util::ser` to deserialize is
//    followed by some arbitrary data
//
// # Returns
//
// The deserialized data.
//
// # Side Effects
//
// Reads the first `n` bytes of `source` that corresponds to the serialized data. Leaves the
// rest of the source untouched.
fn deser<R, T>(source: &mut R) -> CsyncResult<T>
where
    R: Read,
    T: Clone + Debug + DeserializeOwned,
{
    let data_len = u8s_to_u32(&read_exact(4, source)?);
    let data_bytes = read_exact(data_len as usize, source)?;
    deserialize(&data_bytes[..])
}

// # Parameters
//
// 1. `min_padding_length`:
// 1. `max_padding_length`:
//
// # Returns
//
// `PAD_DELIMITER` occurs only once, which is at the end
fn random_padding(min_padding_len: u64, max_padding_len: u64) -> Vec<u8> {
    debug_assert!(0 < min_padding_len);
    debug_assert!(min_padding_len < max_padding_len);

    //let rand_u64 = crate::rand_util::rand_u64(None, min_padding_length, max_padding_length);

    // keep trying until the right amount has been collected
    loop {
        let double_pad: Vec<_> = rng!(2 * min_padding_len, 2 * max_padding_len)
            .0
            .unsecure()
            .into_iter()
            .copied()
            .filter(|byte| *byte != PAD_DELIMITER)
            .collect();

        match double_pad.len() as u64 / 2 {
            pad_len if min_padding_len <= pad_len && pad_len < max_padding_len => {
                break double_pad
                    .into_iter()
                    .take(pad_len as usize)
                    .chain(std::iter::once(PAD_DELIMITER))
                    .collect()
            }
            _ => (),
        }
    }
}

/// Encrypt data into a custom format, decryptable using `csync_decrypt`.
///
/// # Ciphertext Format
///
/// The final ciphertext written to `dest` has the following non-overlapping
/// components, in order:
/// 1. `4` bytes: length of the authentication specification
/// 1. `n_auth_spec` bytes: authenicated specification, serialized, unencrypted
/// 1. `4` bytes: length of the authenticated signature
/// 1. `n_auth_sig` bytes: authenicated signature
/// 1. `4` bytes: length of the syncer specification
/// 1. `n_syncer_spec` bytes: syncer specification, serialized, unencrypted
/// 1. `4` bytes: length of the action specification
/// 1. `n_action_spec` bytes: action specification, serialized, unencrypted
/// 1. `n_body` bytes: random padding and the plaintext, encrypted
///
/// # Parameters
///
/// 1. `syncer_spec`: syncer spec to use
/// 1. `action_spec`: action spec to use
/// 1. `arena`: some thread-safe directory; thread-safe-dir here is defined as a directory
///    in which only a single thread is able to create and remove files
/// 1. `source`: data source to encrypt
/// 1. `dest`: destination to which final output will be written
/// 1. `key_hash`: the derived key to use in encrypting data
///
/// # Returns
///
/// `Ok(())` if successful, `Err(_)` otherwise.
pub fn csync_encrypt<P, R, W>(
    syncer_spec: &SyncerSpec,
    action_spec: &ActionSpec,
    arena: P,
    source: R,
    mut dest: &mut W,
    key_hash: &DerivedKey,
) -> CsyncResult<()>
where
    P: AsRef<Path>,
    R: Read,
    W: Write,
{
    let tmpf_path = arena.as_ref().join("csync_encrypt");
    let rand_padding = random_padding(MIN_RANDPAD_LEN, MAX_RANDPAD_LEN);

    //
    let syncer_spec_ser = ser(syncer_spec)?;
    let action_spec_ser = ser(action_spec)?;

    // 1. create an encrypted content where
    //     1. the header contains the syncer and action specs
    //     2. the body is the random padding and the actual content
    // 2. encrypt `body` and write to `tmpf_path` which is everything but the signature
    // 3. compute the authenticated signature and return it
    macro_rules! auth {
        (
            $encryptor:ident => $encryptor_opts:expr,
            $compressor:ident => $compressor_opts:expr,
            $hmac_alg:expr
        ) => {{
            // the content to produce authenticated signatures for
            let mut auth_encoder = compose_encoders!(
                    syncer_spec_ser.unsecure()
                    .chain(action_spec_ser.unsecure())
                    .chain(compose_encoders!(
                        (&rand_padding[..]).chain(source),
                        $compressor => $compressor_opts,
                        $encryptor => $encryptor_opts
                    )?),
                HmacEncoder => (&key_hash.0, Some($hmac_alg))
            )?;
            // read the content to `tmpf_path` to avoid memory
            auth_encoder.read_all_to(&mut fopen_w(&tmpf_path)?)?;
            // get the computed hash
            auth_encoder.get_result().unwrap()
        }}
    }

    match syncer_spec {
        SyncerSpec::Encrypt {
            authenticator_spec,
            compressor_spec,
            cipher_spec,
            ..
        } => {
            // authenticated signatures
            let auth_sig = match (compressor_spec, cipher_spec) {
                (CompressorSpec::Zstd { level }, CipherSpec::Aes256Cbc { init_vec }) => auth!(
                    Aes256CbcEnc => (&key_hash.0, Some(&init_vec)),
                    ZstdEncoder => Some(*level),
                    hmac::HMAC_SHA512
                ),
                (CompressorSpec::Zstd { level }, CipherSpec::ChaCha20 { init_vec }) => auth!(
                    ChaCha20Enc => (&key_hash.0, Some(&init_vec)),
                    ZstdEncoder => Some(*level),
                    hmac::HMAC_SHA512
                ),
            };

            //
            let auth_spec_ser = ser(authenticator_spec)?;
            let auth_sig_ser = ser(&auth_sig.0)?;

            //
            compose_encoders!(
                auth_spec_ser.unsecure()
                    .chain(auth_sig_ser.unsecure())
                    .chain(fopen_r(&tmpf_path)?),
                IdentityEncoder => None
            )?
            .read_all_to(&mut dest)?; // 3

            std::fs::remove_file(&tmpf_path)?;
            Ok(())
        }
        _ => panic!("csync encrypt only takes encrypt "),
    }
}

// # Parameters
//
// 1. `src`:
// 1. `dest_opt`:
// 1. `key_hash`:
//
// # Returns
//
// A tuple of the following 3 objects, in order:
// 1. closure such that, when called, the decrypted content of `src` is written to the inner value
//    of `dest_opt`, if it exists
// 1. `dest_opt`: where to write the decrypted content; written to `std::io::sink()` if None
// 1.
fn csync_decrypt_core<'a, 'b, R, W>(
    mut src: R,
    dest_opt: Option<W>,
    key_hash: &'a DerivedKey,
) -> CsyncResult<(impl FnOnce() -> CsyncResult<()> + 'b, SyncerSpec, ActionSpec)>
where
    'a: 'b,
    R: Read + 'a,
    W: Write + 'a,
{
    // read the authentication spec and the precomputed signature
    let auth_spec: AuthenticatorSpec = deser(&mut src)?;
    let auth_sig = CryptoSecureBytes(deser::<_, SecureBytes>(&mut src)?);

    // create an authenticated encoder that reads from the rest of `src`
    //
    // the reason this gets created here is to read the data verbatim while computing the signature
    // at the same time, thereby reading from `src` once instead of twice
    let mut auth_encoder = match auth_spec {
        AuthenticatorSpec::HmacSha512 => compose_encoders!(
            src,
            HmacEncoder => (&key_hash.0, Some(hmac::HMAC_SHA512))
        )?,
    };

    //
    let syncer_spec: SyncerSpec = deser(&mut auth_encoder)?;
    let action_spec: ActionSpec = deser(&mut auth_encoder)?;

    macro_rules! decrypt {
        (
            $decryptor:ident => $decryptor_opts:expr,
            $decompressor:ident => $decompressor_opts:expr
        ) => {{
            //
            let mut plaintext = compose_encoders!(
                auth_encoder,
                $decryptor => $decryptor_opts,
                $decompressor => $decompressor_opts,
                IdentityEncoder => None
            )?;
            read_until(&mut plaintext, PAD_DELIMITER, &mut std::io::sink())?;
            match dest_opt {
                Some(mut dest) => plaintext.read_all_to(&mut dest)?,
                None => plaintext.read_all_to(&mut std::io::sink())?,
            };

            let computed_auth_sig = plaintext
                .get_inner().unwrap()
                .get_inner_ref().unwrap()
                .get_inner_ref().unwrap()
                .get_result().unwrap();
            match auth_sig == computed_auth_sig {
                true => Ok(()),
                false => csync_err!(AuthenticationFail),
            }
        }}
    }

    let syncer_spec_clone = syncer_spec.clone();
    Ok((
        move || match syncer_spec_clone {
            SyncerSpec::Encrypt {
                compressor_spec,
                cipher_spec,
                ..
            }
            | SyncerSpec::Decrypt {
                compressor_spec,
                cipher_spec,
                ..
            } => match (compressor_spec, cipher_spec) {
                (CompressorSpec::Zstd { level }, CipherSpec::Aes256Cbc { init_vec }) => decrypt!(
                    Aes256CbcDec => (&key_hash.0, Some(&init_vec)),
                    ZstdDecoder => Some(level)
                ),
                (CompressorSpec::Zstd { level }, CipherSpec::ChaCha20 { init_vec }) => decrypt!(
                    ChaCha20Dec => (&key_hash.0, Some(&init_vec)),
                    ZstdDecoder => Some(level)
                ),
            },
            SyncerSpec::Clean { .. } => todo!(),
        },
        syncer_spec,
        action_spec,
    ))
}

///
pub fn csync_decrypt<R, W>(src: R, dest_opt: Option<W>, key_hash: &DerivedKey) -> CsyncResult<(SyncerSpec, ActionSpec)>
where
    R: Read,
    W: Write,
{
    let (lambda, syncer_spec, action_spec) = csync_decrypt_core(src, dest_opt, key_hash)?;
    lambda()?;
    Ok((syncer_spec, action_spec))
}

/// # Parame
pub fn load_syncer_action_specs<P>(path: P) -> CsyncResult<(SyncerSpec, ActionSpec)>
where
    P: std::convert::AsRef<Path>,
{
    let garbage_key = DerivedKey(sha512!(&vec![].into()));
    let (_, syncer_spec, action_spec) = csync_decrypt_core(fopen_r(path)?, Option::<File>::None, &garbage_key)?;
    Ok((syncer_spec, action_spec))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::*;

    mod ser_deser {
        use super::*;

        //
        macro_rules! testgen {
            ( $test_name:ident, $type_name:ident, $data:expr ) => {
                //
                #[test]
                fn $test_name() {
                    // initialize and serialize `$data`
                    let auth_spec: $type_name = $data;
                    let auth_spec_ser = ser(&auth_spec).unwrap();

                    // create a tmp file in a tmp directory
                    let tmpd = tmpdir!().unwrap();
                    let tmpf_path = tmpd.path().join("6urC");

                    // write the serialized data to the tmp file
                    {
                        let mut tmpf = fopen_w(&tmpf_path).unwrap();
                        tmpf.write(auth_spec_ser.unsecure()).unwrap();
                    }

                    // read the serialized data from the tmp file
                    let mut tmpf = fopen_r(&tmpf_path).unwrap();
                    let auth_spec_deser: $type_name = deser(&mut tmpf).unwrap();

                    // the deserialized data must be eq to the original data
                    assert_eq!(auth_spec_deser, auth_spec);
                }
            };
        }

        //
        testgen!(deser_undoes_ser_auth_spec, AuthenticatorSpec, Default::default());
    }

    mod csync_encrypt_decrypt {
        use super::*;
        use crate::primitives::*;
        use rayon::iter::ParallelBridge;
        use rayon::prelude::*;

        //
        fn rand_action_spec() -> ActionSpec {
            let key = sha512!(&b"ZnwakvuS5pisQZAs3lXJZMHvrza2ZK7xnzaQnw39kokIhPcSpo94muiW1fwFnBbu"
                .to_vec()
                .into());
            let salt = sha512!(&b"GJi5WO5zVk8BXJCNn9HSdgXLsjwV2j1ndcgp5N8gADuB6gZMNZfBoAewxnR1aeKY"
                .to_vec()
                .into());
            let key_hash = sha512!(&key.0, &salt);
            ActionSpec::new(&Default::default(), Some(DEFAULT_PERM_BITS), &DerivedKey(key_hash)).unwrap()
        }

        //
        macro_rules! rand_syncer_spec {
            ( $variant:ident, $out_dir_path:expr, $source_path:expr ) => {{
                SyncerSpec::$variant {
                    authenticator_spec: Default::default(),
                    cipher_spec: Default::default(),
                    compressor_spec: Default::default(),
                    key_deriv_spec: Default::default(),
                    out_dir: $out_dir_path,
                    source: $source_path,
                    init_salt: sha512!(&b"JjLE5Pd8sMRB5pN32xNBC4WyIzN5MLSDRJ11D5kN2BWAoVhoGErKYFT2OwBN45jW"
                        .to_vec()
                        .into()),
                    spread_depth: SpreadDepth::new(4),
                    verbose: false,
                }
            }};
        }

        macro_rules! testgen {
            ( $test_name:ident, $files_iter_func:ident ) => {
                //
                #[test]
                fn $test_name() {
                    // create a random action spec and a syncer spec
                    let out_dir = tmpdir!().unwrap();
                    let out_dir_path = out_dir.path().to_path_buf();
                    let source_path = Path::new("src").to_path_buf();
                    let action_spec = rand_action_spec();
                    let syncer_spec = rand_syncer_spec!(Encrypt, out_dir_path, source_path);

                    $files_iter_func().take(32).par_bridge().for_each(|file_path| {
                        let arena = tmpdir!().unwrap();

                        let key_hash = {
                            let key_deriv_spec: KeyDerivSpec = Default::default();
                            key_deriv_spec
                                .derive(
                                    &b"bnd51yibKcrXj8XKgf3bmlYJzEhhM15E6RU7WnykUead1geM9CXYnGFEndx5vqiH"
                                        .to_vec()
                                        .into(),
                                )
                                .unwrap()
                        };

                        let mut enc_dest: Vec<u8> = vec![];
                        csync_encrypt(
                            &syncer_spec,
                            &action_spec,
                            arena.path(),
                            fopen_r(&file_path).unwrap(),
                            &mut enc_dest,
                            &key_hash,
                        )
                        .unwrap();

                        let mut dec_dest: Vec<u8> = vec![];
                        csync_decrypt(&enc_dest[..], Some(&mut dec_dest), &key_hash).unwrap();
                        assert_eq!(&dec_dest[..], &std::fs::read(&file_path).unwrap()[..]);
                    });
                }
            };
        }

        testgen!(ascii, ascii_files);

        testgen!(bin, bin_files);
    }

    /*

    ///
    mod csync_encrypt_decrypt {
        use super::*;
        use std::collections::HashSet;
        use std::fs::read_to_string;

        ///
        #[test]
        fn uses_random_salt() {
            let salt = rng!(DEFAULT_SALT_LEN);
            let derived_key = DerivedKey(sha512!(
                &b"k8B0nWuQ2WIpQbSl84UDM1esE9aIqXwdATS6B88GQzgBLeMfwPBsrmp31NT6iE3v"
                    .to_vec()
                    .into(),
                &salt
            ));

            let out_dir = tmpdir!().unwrap();
            ascii_files().par_bridge().filter(|pbuf| pbuf.is_file()).for_each(|src_pbuf| {
                // for each file = `src_pbuf`, enc it `n` times
                // each one should result in distinct ciphertexts because the salt is random
                let tmpd = tmpdir!().unwrap();
                let n = 4;
                let enc_bytes: HashSet<_> = (0..n)
                    .par_bridge()
                    .map(|_| {
                        let mut dest = vec![];
                        csync_encrypt(
                            &spec_ext_to_int(&SyncerSpecExt::Encrypt {
                                auth_opt: Some(Default::default()),
                                cipher_opt: Some(Default::default()),
                                compressor_opt: Some(Default::default()),
                                kd_spec_ext_opt: Some(KeyDerivSpecExt::Pbkdf2 {
                                    alg_opt: None,
                                    num_iter_opt: Some(100),
                                    time_opt: None,
                                }),
                                out_dir: out_dir.path().to_path_buf(),
                                source: Path::new("src").to_path_buf(),
                                spread_depth_opt: None,
                                verbose: false,
                            })
                            .unwrap(),
                            &rand_action_spec!().unwrap(),
                            tmpd.path(),
                            || fopen_r(&src_pbuf),
                            &mut dest,
                            &derived_key,
                        )
                        .unwrap();
                        dest
                    })
                    .collect();
                assert_eq!(enc_bytes.len(), n);
            });
        }

        ///
        #[test]
        fn inverse() {
            let salt = rng!(DEFAULT_SALT_LEN);
            let derived_key = DerivedKey(sha512!(
                &b"6QcsHuSripKWIxMcbVxUgFUwWJ8vY6B8rB90ERL3loZblicHzDF7Lo8jGgp89MAu"
                    .to_vec()
                    .into(),
                &salt
            ));

            let tmpd = tmpdir!().unwrap();
            let out_dir = tmpdir!().unwrap();
            ascii_files()
                .enumerate()
                .par_bridge()
                .filter(|(_, pbuf)| pbuf.is_file())
                .map(|(_, src_pbuf)| {
                    let mut encrypted = vec![];
                    csync_encrypt(
                        &spec_ext_to_int(&SyncerSpecExt::Encrypt {
                            auth_opt: Some(Default::default()),
                            cipher_opt: Some(Default::default()),
                            compressor_opt: Some(Default::default()),
                            kd_spec_ext_opt: Some(KeyDerivSpecExt::Pbkdf2 {
                                alg_opt: None,
                                num_iter_opt: Some(100),
                                time_opt: None,
                            }),
                            out_dir: out_dir.path().to_path_buf(),
                            source: Path::new("src").to_path_buf(),
                            spread_depth_opt: None,
                            verbose: false,
                        })
                        .unwrap(),
                        &rand_action_spec!().unwrap(),
                        tmpd.path(),
                        || fopen_r(&src_pbuf),
                        &mut encrypted,
                        &derived_key,
                    )
                    .unwrap();
                    (encrypted, read_to_string(&src_pbuf).unwrap())
                })
                .for_each(|(encrypted, expected_plaintext)| {
                    let tmpd = tmpdir!().unwrap();
                    let tmpf_path = tmpd.path().join("abc");
                    {
                        let mut f = fopen_w(&tmpf_path).unwrap();
                        f.write_all(&encrypted[..]).unwrap();
                    }

                    let mut decrypted = vec![];
                    csync_decrypt(fopen_r(&tmpf_path).unwrap(), Some(&mut decrypted), &derived_key).unwrap();
                    assert_eq!(&decrypted[..], expected_plaintext.as_bytes());
                });
        }
    }
    */
}
