use crate::secure_vec::*;
use serde::{Deserialize, Serialize};

///
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum CipherSpec {
    Aes256Cbc { init_vec: CryptoSecureBytes },
    ChaCha20 { init_vec: CryptoSecureBytes },
}

macro_rules! rand_salt {
    ( $salt_len:expr ) => {
        CryptoSecureBytes(rng!($salt_len as usize).0)
    };
}

///
impl CipherSpec {
    ///
    pub fn resalt(&self, salt_len: u16) -> Self {
        match self {
            Self::Aes256Cbc { .. } => Self::Aes256Cbc {
                init_vec: rand_salt!(salt_len),
            },
            Self::ChaCha20 { .. } => Self::ChaCha20 {
                init_vec: rand_salt!(salt_len),
            },
        }
    }
}
