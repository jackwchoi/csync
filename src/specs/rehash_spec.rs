use crate::{prelude::*, secure_vec::*, specs::key_deriv_spec::*};
use serde::{Deserialize, Serialize};

/// Use `Default::default()` as the constructor if you are not sure what you are doing.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct RehashSpec(KeyDerivSpec);

impl RehashSpec {
    #[inline]
    pub fn rehash(&self, key_hash: &DerivedKey) -> CsyncResult<RehashedKey> {
        self.0.derive(&key_hash.0 .0).map(|derived_key| RehashedKey(derived_key.0))
    }

    #[inline]
    pub fn verify(&self, rehash: &RehashedKey, key_hash: &DerivedKey) -> CsyncResult<()> {
        // NOTE this is a constant time operation, given that `SecureVec`'s `Eq` is const
        match &self.rehash(key_hash)? == rehash {
            true => Ok(()),
            false => csync_err!(AuthenticationFail),
        }
    }
}

///
impl Default for RehashSpec {
    #[inline]
    fn default() -> Self {
        // this does not need to be costly
        Self(KeyDerivSpec::Scrypt {
            log_n: 12,
            r: 8,
            p: 1,
            salt: CryptoSecureBytes(rng!(DEFAULT_SALT_LEN).0),
            output_len: DEFAULT_SALT_LEN,
        })
    }
}
