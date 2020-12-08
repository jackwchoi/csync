use crate::{
    encoder::{hmac::*, identity::*, openssl::*, zstd::*},
    fs_util::*,
    prelude::*,
    primitives::*,
    secure_vec::*,
    specs::{authenticator_spec::*, cipher_spec::*, compressor_spec::*, key_deriv_spec::*, syncer_spec_ext::*},
    util::*,
};
use ring::{hmac, pbkdf2};
use scrypt::ScryptParams;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    fmt::Debug,
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
};

/// Parameters for `scrypt`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ScryptLogN(pub u8);
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ScryptR(pub u32);
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ScryptP(pub u32);

///
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum SyncerSpec {
    Encrypt {
        //
        authenticator_spec: AuthenticatorSpec,
        cipher_spec: CipherSpec,
        compressor_spec: CompressorSpec,
        key_deriv_spec: KeyDerivSpec,
        //
        out_dir: PathBuf,
        source: PathBuf,
        //
        init_salt: CryptoSecureBytes,
        spread_depth: SpreadDepth,
        verbose: bool,
    },
    Decrypt {
        //
        authenticator_spec: AuthenticatorSpec,
        cipher_spec: CipherSpec,
        compressor_spec: CompressorSpec,
        key_deriv_spec: KeyDerivSpec,
        //
        out_dir: PathBuf,
        source: PathBuf,
        //
        init_salt: CryptoSecureBytes,
        spread_depth: SpreadDepth,
        verbose: bool,
    },
    Clean {
        source: PathBuf,
        verbose: bool,
    },
}

impl std::convert::TryFrom<&SyncerSpecExt> for SyncerSpec {
    type Error = CsyncErr;

    //
    fn try_from(spec_ext: &SyncerSpecExt) -> Result<Self, Self::Error> {
        match spec_ext {
            SyncerSpecExt::Encrypt {
                auth_spec,
                cipher_spec,
                compressor_spec,
                kd_spec_ext,
                out_dir,
                source,
                spread_depth_opt,
                verbose,
            } => {
                if !source.exists() {
                    csync_err!(SourceDoesNotExist, source.clone())?;
                }
                match out_dir.exists() {
                    true => match out_dir.is_dir() {
                        true => match std::fs::read_dir(out_dir).map(Iterator::count) {
                            Ok(0) => (),
                            _ => csync_err!(IncrementalEncryptionDisabledForNow)?,
                        },
                        false => csync_err!(OutdirIsNotDir, out_dir.to_path_buf())?,
                    },
                    false => (),
                };
                debug_assert!(match out_dir.exists() {
                    true => match out_dir.is_dir() {
                        true => std::fs::read_dir(out_dir)?.count() == 0,
                        false => false,
                    },
                    false => true,
                });

                let key_deriv_spec = match kd_spec_ext.clone() {
                    KeyDerivSpecExt::Pbkdf2 {
                        alg_opt,
                        num_iter_opt,
                        time_opt,
                    } => {
                        macro_rules! pbkdf2_spec {
                            ( $num_iter:expr ) => {
                                KeyDerivSpec::Pbkdf2 {
                                    alg: unwrap_or_default(alg_opt.clone()),
                                    num_iter: $num_iter,
                                    salt: CryptoSecureBytes(rng!(DEFAULT_SALT_LEN).0),
                                }
                            };
                        }
                        match (num_iter_opt, time_opt) {
                            (Some(num_iter), None) => pbkdf2_spec!(num_iter),
                            (None, time_opt) => {
                                let time = time_opt.unwrap_or(DEFAULT_TIME_TO_HASH);
                                let alg = unwrap_or_default(alg_opt);
                                pbkdf2_spec!(determine_pbkdf2_num_iter(alg.ring(), time))
                            }
                            _ => csync_err!(HashSpecConflict)?,
                        }
                    }
                    KeyDerivSpecExt::Scrypt {
                        log_n_opt,
                        r_opt,
                        p_opt,
                        time_opt,
                        output_len_opt,
                    } => {
                        let (log_n, r, p) = match (log_n_opt, r_opt, p_opt, time_opt) {
                            (None, None, None, time_opt) => {
                                let time = time_opt.unwrap_or(DEFAULT_TIME_TO_HASH);
                                let (log_n, r, p) = determine_scrypt_params(time)?;
                                (log_n.0, r.0, p.0)
                            }
                            (log_n_opt, r_opt, p_opt, None) => (
                                log_n_opt.unwrap_or(DEFAULT_SCRYPT_LOG_N),
                                r_opt.unwrap_or(DEFAULT_SCRYPT_R),
                                p_opt.unwrap_or(DEFAULT_SCRYPT_P),
                            ),
                            _ => csync_err!(HashSpecConflict)?,
                        };
                        KeyDerivSpec::Scrypt {
                            log_n,
                            p,
                            r,
                            output_len: output_len_opt.unwrap_or(DEFAULT_SCRYPT_OUTPUT_LEN),
                            salt: CryptoSecureBytes(rng!(DEFAULT_SALT_LEN).0),
                        }
                    }
                };

                Ok(SyncerSpec::Encrypt {
                    authenticator_spec: auth_spec.clone(),
                    cipher_spec: cipher_spec.clone(),
                    compressor_spec: compressor_spec.clone(),
                    init_salt: CryptoSecureBytes(rng!(DEFAULT_SALT_LEN).0),
                    key_deriv_spec,
                    out_dir: out_dir.canonicalize()?,
                    source: source.canonicalize()?,
                    spread_depth: spread_depth_opt.clone(),
                    verbose: *verbose,
                })
            }
            SyncerSpecExt::Decrypt { .. } | SyncerSpecExt::Clean { .. } => {
                panic!("`SyncerSpecExt` -> `SyncerSpec` should only be used for encrypting")
            }
        }
    }
}

/// # Parameters
///
/// 1. `$time_to_hash`:
/// 1. `$hasher`: &SecureVec<u8> -> &CryptoSecureBytes -> _
/// 1. `$time_handles`:
macro_rules! determine_params {
    ( $time_to_hash:expr, $hasher:expr, $time_handler:expr ) => {{
        let random_key = rng!(DEFAULT_SALT_LEN);
        let random_salt = rng!(DEFAULT_SALT_LEN);

        let average_time_nanos = {
            const SAMPLE_SIZE: u128 = 8;
            // run 16 times and average the last 8 runs
            (0..16)
                .map(|_| time!($hasher(&random_key.0, &random_salt)).1.as_nanos())
                .rev()
                .skip(SAMPLE_SIZE as usize)
                .take(SAMPLE_SIZE as usize)
                .map(|sample| sample / SAMPLE_SIZE)
                .sum::<u128>() as f64
        };

        $time_handler(average_time_nanos)
    }};
}

/// # Parameters
///
/// 1. `time_to_hash`: number of seconds to target
///
/// # Returns
///
/// Parameters for `scrypt` such that running `scrypt` with them will take anywhere between
/// `time_to_hash` and `2 * time_to_hash` number of seconds on this machine, approximately.
pub fn determine_scrypt_params(time_to_hash: u16) -> CsyncResult<(ScryptLogN, ScryptR, ScryptP)> {
    //
    const LOG_N: u8 = DEFAULT_SCRYPT_LOG_N - 5;
    const R: u32 = DEFAULT_SCRYPT_R;
    const P: u32 = DEFAULT_SCRYPT_P;
    let scrypt_params = ScryptParams::new(LOG_N, R, P)?;

    determine_params!(
        time_to_hash,
        |random_key, random_salt| scrypt!(random_key, random_salt, scrypt_params, DEFAULT_SCRYPT_OUTPUT_LEN),
        |average_time_nanos: f64| {
            let target_as_nanos = time_to_hash as f64 * 1e9;
            let factor = match (target_as_nanos / average_time_nanos).log2().ceil() {
                f if f > std::u8::MAX as f64 => panic!(),
                f if LOG_N as f64 <= f => 1u8,
                f => f as u8,
            };

            //
            Ok((ScryptLogN(LOG_N + factor), ScryptR(R), ScryptP(P)))
        }
    )
}

/// # Parameters
///
///
pub fn determine_pbkdf2_num_iter(alg: pbkdf2::Algorithm, time_to_hash: u16) -> u32 {
    //
    const INITIAL_NUM_ITER: u32 = 1 << 14;

    determine_params!(
        time_to_hash,
        |random_key, random_salt| pbkdf2!(alg, INITIAL_NUM_ITER, random_key, random_salt),
        |average_time_nanos: f64| {
            //
            let target_as_nanos = time_to_hash as f64 * 1e9;
            let multiplier = target_as_nanos / average_time_nanos as f64;
            let scaled = INITIAL_NUM_ITER as f64 * multiplier; // TODO add rand padding later

            //
            scaled as u32
        }
    )
}
