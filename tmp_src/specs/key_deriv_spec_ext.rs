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
    Pbkdf2ByTime {
        alg_opt: Option<Pbkdf2Algorithm>,
        time: u16,
        salt_len: u16,
    },
    Pbkdf2ByParams {
        alg_opt: Option<Pbkdf2Algorithm>,
        num_iter: u32,
        salt_len: u16,
    },
    ScryptByTime {
        time: u16,
        output_len: usize,
        salt_len: u16,
    },
    ScryptByParams {
        log_n: u8,
        r: u32,
        p: u32,
        output_len: usize,
        salt_len: u16,
    },
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
