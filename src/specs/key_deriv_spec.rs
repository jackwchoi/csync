use crate::{prelude::*, secure_vec::*, specs::key_deriv_spec_ext::*, util::*};
use ring::pbkdf2;
use scrypt::ScryptParams;
use serde::{Deserialize, Serialize};

/// Parameters for `scrypt`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ScryptLogN(pub u8);
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ScryptR(pub u32);
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ScryptP(pub u32);

// # Parameters
//
// 1. `$time_to_hash`:
// 1. `$hasher`: &SecureVec<u8> -> &CryptoSecureBytes -> _
// 1. `$time_handles`:
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

// # Parameters
//
// 1. `time_to_hash`: number of seconds to target
//
// # Returns
//
// Parameters for `scrypt` such that running `scrypt` with them will take anywhere between
// `time_to_hash` and `2 * time_to_hash` number of seconds on this machine, approximately.
fn determine_scrypt_params(time_to_hash: u16) -> CsyncResult<(ScryptLogN, ScryptR, ScryptP)> {
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

// # Parameters
//
//
fn determine_pbkdf2_num_iter(alg: pbkdf2::Algorithm, time_to_hash: u16) -> u32 {
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

///
impl KeyDerivSpec {
    pub fn derive(&self, init_key: &SecureBytes) -> CsyncResult<DerivedKey> {
        match &self {
            KeyDerivSpec::Pbkdf2 { alg, salt, num_iter } => {
                Ok(pbkdf2!(alg.ring(), *num_iter, init_key, salt)).map(|hash| DerivedKey(hash))
            }
            KeyDerivSpec::Scrypt {
                log_n,
                r,
                p,
                output_len,
                salt,
            } => scrypt!(&init_key, salt, ScryptParams::new(*log_n, *r, *p)?, *output_len).map(|hash| DerivedKey(hash)),
        }
    }
}

///
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum KeyDerivSpec {
    Pbkdf2 {
        alg: Pbkdf2Algorithm,
        num_iter: u32,
        salt: CryptoSecureBytes,
    },
    Scrypt {
        log_n: u8,
        p: u32,
        r: u32,
        output_len: usize,
        salt: CryptoSecureBytes,
    },
}

impl Default for KeyDerivSpec {
    // TODO change to scrypt
    #[inline]
    fn default() -> Self {
        KeyDerivSpec::Scrypt {
            log_n: DEFAULT_SCRYPT_LOG_N,
            r: DEFAULT_SCRYPT_R,
            p: DEFAULT_SCRYPT_P,
            salt: CryptoSecureBytes(rng!(DEFAULT_SALT_LEN).0),
            output_len: DEFAULT_SALT_LEN,
        }
    }
}

impl std::convert::TryFrom<&KeyDerivSpecExt> for KeyDerivSpec {
    type Error = CsyncErr;

    //
    fn try_from(spec_ext: &KeyDerivSpecExt) -> Result<Self, Self::Error> {
        Ok(match spec_ext {
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
                    (Some(num_iter), None) => pbkdf2_spec!(*num_iter),
                    (None, time_opt) => {
                        let time = time_opt.unwrap_or(DEFAULT_TIME_TO_HASH);
                        let alg = unwrap_or_default(*alg_opt);
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
        })
    }
}
