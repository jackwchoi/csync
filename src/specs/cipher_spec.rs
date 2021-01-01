use crate::{prelude::*, secure_vec::*};
use serde::{Deserialize, Serialize};

///
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum CipherSpec {
    Aes256Cbc { init_vec: CryptoSecureBytes },
    ChaCha20 { init_vec: CryptoSecureBytes },
}

macro_rules! rand_salt {
    () => {
        CryptoSecureBytes(rng!(DEFAULT_SALT_LEN).0)
    };
}

///
impl CipherSpec {
    ///
    pub fn resalt(&self) -> Self {
        match self {
            Self::Aes256Cbc { .. } => Self::Aes256Cbc { init_vec: rand_salt!() },
            Self::ChaCha20 { .. } => Self::ChaCha20 { init_vec: rand_salt!() },
        }
    }
}
