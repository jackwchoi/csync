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
    sync::mpsc::channel,
};

// consts about random padding used in the encryption
const MIN_RANDPAD_LEN: u64 = 1;
const MAX_RANDPAD_LEN: u64 = 1 << 11;
const PAD_DELIMITER: u8 = 0;

pub const MIN_DIR_RAND_DATA_LEN: u64 = 1 << 4;
pub const MAX_DIR_RAND_DATA_LEN: u64 = 1 << 10;

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
    metadata: &SecureBytes,
) -> CsyncResult<()>
where
    P: AsRef<Path>,
    R: Read,
    W: Write,
{
    let tmpf_path = arena.as_ref().join("csync_encrypt");
    let rand_padding = random_padding(MIN_RANDPAD_LEN, MAX_RANDPAD_LEN);

    //
    let metadata_ser = ser(metadata)?;
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
                HmacEncoder => (&key_hash.0, Some((Some($hmac_alg), None)))
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

            // TODO include authenticated signature of the plaintext in the front
            //
            compose_encoders!(
                metadata_ser.unsecure().chain(
                auth_spec_ser.unsecure())
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
) -> CsyncResult<(impl FnOnce() -> CsyncResult<()> + 'b, SyncerSpec, ActionSpec, SecureBytes)>
where
    'a: 'b,
    R: Read + 'a,
    W: Write + 'a,
{
    let metadata: SecureBytes = deser(&mut src)?;
    // read the authentication spec and the precomputed signature
    let auth_spec: AuthenticatorSpec = deser(&mut src)?;
    let auth_sig = CryptoSecureBytes(deser::<_, SecureBytes>(&mut src)?);

    let (sender, receiver) = channel();
    // create an authenticated encoder that reads from the rest of `src`
    //
    // the reason this gets created here is to read the data verbatim while computing the signature
    // at the same time, thereby reading from `src` once instead of twice
    let mut auth_encoder = match auth_spec {
        AuthenticatorSpec::HmacSha512 => compose_encoders!(
            src,
            HmacEncoder => (&key_hash.0, Some((Some(hmac::HMAC_SHA512), Some(sender))))
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

            /*
            let computed_auth_sig = plaintext
                .get_inner().unwrap()
                .get_inner_ref().unwrap()
                .get_inner_ref().unwrap()
                .get_result().unwrap();
            */
            let computed_auth_sig = receiver.recv().unwrap();
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
        metadata,
    ))
}

///
pub fn csync_decrypt<R, W>(src: R, dest_opt: Option<W>, key_hash: &DerivedKey) -> CsyncResult<(SyncerSpec, ActionSpec)>
where
    R: Read,
    W: Write,
{
    let (lambda, syncer_spec, action_spec, _) = csync_decrypt_core(src, dest_opt, key_hash)?;
    lambda()?;
    Ok((syncer_spec, action_spec))
}

/// # Parame
pub fn load_syncer_action_specs<P>(path: P) -> CsyncResult<(SyncerSpec, ActionSpec)>
where
    P: std::convert::AsRef<Path>,
{
    let garbage_key = DerivedKey(sha512!(&vec![].into()));
    let (_, syncer_spec, action_spec, _) = csync_decrypt_core(fopen_r(path)?, Option::<File>::None, &garbage_key)?;
    Ok((syncer_spec, action_spec))
}

/// # Parame
pub fn load_meta<P>(path: P) -> CsyncResult<SecureBytes>
where
    P: std::convert::AsRef<Path>,
{
    let garbage_key = DerivedKey(sha512!(&vec![].into()));
    let (_, _, _, metadata) = csync_decrypt_core(fopen_r(path)?, Option::<File>::None, &garbage_key)?;
    Ok(metadata)
}
