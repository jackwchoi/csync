use crate::{prelude::*, secure_vec::*};
use ring::pbkdf2;
use scrypt::ScryptParams;
use serde::{Deserialize, Serialize};

///
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum KeyDerivSpecExt {
    Pbkdf2 {
        alg_opt: Option<Pbkdf2Algorithm>,
        num_iter_opt: Option<u32>,
        time_opt: Option<u16>,
    },
    Scrypt {
        log_n_opt: Option<u8>,
        r_opt: Option<u32>,
        p_opt: Option<u32>,
        time_opt: Option<u16>,
        output_len_opt: Option<usize>,
    },
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
impl Default for KeyDerivSpecExt {
    // TODO change to scrypt
    fn default() -> Self {
        KeyDerivSpecExt::Scrypt {
            log_n_opt: None,
            r_opt: None,
            p_opt: None,
            time_opt: None,
            output_len_opt: None,
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
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum Pbkdf2Algorithm {
    HmacSha512,
}

///
impl Pbkdf2Algorithm {
    ///
    pub fn ring(&self) -> pbkdf2::Algorithm {
        match self {
            Pbkdf2Algorithm::HmacSha512 => pbkdf2::PBKDF2_HMAC_SHA512,
        }
    }
}
/// TODO change to tryinto
impl From<pbkdf2::Algorithm> for Pbkdf2Algorithm {
    fn from(alg: pbkdf2::Algorithm) -> Self {
        match alg == pbkdf2::PBKDF2_HMAC_SHA512 {
            true => Pbkdf2Algorithm::HmacSha512,
            false => todo!(),
        }
    }
}
impl Default for Pbkdf2Algorithm {
    #[inline]
    fn default() -> Self {
        Self::HmacSha512
    }
}
