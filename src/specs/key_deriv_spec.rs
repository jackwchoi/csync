use crate::{prelude::*, secure_vec::*, specs::key_deriv_spec_ext::*};
use ring::pbkdf2;
use scrypt::ScryptParams;
use serde::{Deserialize, Serialize};

// # Parameters
//
// 1. `$time_to_hash`:
// 1. `$hasher`: &SecureVec<u8> -> &CryptoSecureBytes -> _
// 1. `$time_handles`:
macro_rules! determine_params {
    ( $time_to_hash:expr, $salt_len:expr, $hasher:expr, $time_handler:expr ) => {{
        let random_key = rng!($salt_len as usize);
        let random_salt = rng!($salt_len as usize);

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
fn determine_scrypt_params(time_to_hash: u16, salt_len: u16) -> CsyncResult<(ScryptLogN, ScryptR, ScryptP)> {
    //
    const LOG_N: u8 = DEFAULT_SCRYPT_LOG_N - 4;
    const R: u32 = DEFAULT_SCRYPT_R;
    const P: u32 = DEFAULT_SCRYPT_P;
    let scrypt_params = ScryptParams::new(LOG_N, R, P)?;

    determine_params!(
        time_to_hash,
        salt_len,
        |random_key, random_salt| scrypt!(random_key, random_salt, scrypt_params, DEFAULT_SCRYPT_OUTPUT_LEN),
        |average_time_nanos: f64| {
            let target_as_nanos = time_to_hash as f64 * 1e9;
            let factor = match (target_as_nanos / average_time_nanos).log2().ceil() {
                // shouldn't really happen
                f if f > std::u8::MAX as f64 => panic!(),
                //
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
fn determine_pbkdf2_num_iter(alg: pbkdf2::Algorithm, time_to_hash: u16, salt_len: u16) -> u32 {
    //
    const INITIAL_NUM_ITER: u32 = 1 << 14;

    determine_params!(
        time_to_hash,
        salt_len,
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

impl std::convert::TryFrom<&KeyDerivSpecExt> for KeyDerivSpec {
    type Error = CsyncErr;

    //
    fn try_from(spec_ext: &KeyDerivSpecExt) -> Result<Self, Self::Error> {
        Ok(match spec_ext {
            KeyDerivSpecExt::Pbkdf2ByTime { alg_opt, time, salt_len } => {
                let alg = alg_opt.unwrap_or(Default::default());
                let num_iter = determine_pbkdf2_num_iter(alg.ring(), *time, *salt_len);
                KeyDerivSpec::Pbkdf2 {
                    alg,
                    num_iter,
                    salt: CryptoSecureBytes(rng!(*salt_len as usize).0),
                }
            }
            KeyDerivSpecExt::Pbkdf2ByParams {
                alg_opt,
                num_iter,
                salt_len,
            } => KeyDerivSpec::Pbkdf2 {
                alg: alg_opt.clone().unwrap_or(Default::default()),
                num_iter: *num_iter,
                salt: CryptoSecureBytes(rng!(*salt_len as usize).0),
            },
            KeyDerivSpecExt::ScryptByTime {
                time,
                output_len,
                salt_len,
            } => {
                let (log_n, r, p) = determine_scrypt_params(*time, *salt_len)?;
                //
                KeyDerivSpec::Scrypt {
                    log_n: log_n.0,
                    p: p.0,
                    r: r.0,
                    output_len: *output_len,
                    salt: CryptoSecureBytes(rng!(*salt_len as usize).0),
                }
            }
            KeyDerivSpecExt::ScryptByParams {
                log_n,
                r,
                p,
                output_len,
                salt_len,
            } => KeyDerivSpec::Scrypt {
                log_n: *log_n,
                p: *p,
                r: *r,
                output_len: *output_len,
                salt: CryptoSecureBytes(rng!(*salt_len as usize).0),
            },
        })
    }
}
