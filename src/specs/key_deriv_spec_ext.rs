use ring::pbkdf2;
use serde::{Deserialize, Serialize};

/// Parameters for `scrypt`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ScryptLogN(pub u8);
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ScryptR(pub u32);
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ScryptP(pub u32);

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
