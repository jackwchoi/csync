use crate::{prelude::*, secure_vec::*, specs::key_deriv_spec::*};
use serde::{Deserialize, Serialize};

///
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct RehashSpec(KeyDerivSpec);

impl RehashSpec {
    ///
    pub fn with_key_deriv_spec(kd_spec: KeyDerivSpec) -> Self {
        Self(kd_spec)
    }

    pub fn rehash(&self, key_hash: &DerivedKey) -> CsyncResult<RehashedKey> {
        self.0.derive(&key_hash.0 .0).map(|derived_key| RehashedKey(derived_key.0))
    }

    pub fn verify(&self, rehash: &RehashedKey, key_hash: &DerivedKey) -> CsyncResult<()> {
        // NOTE this is a constant time operation, given that `SecureVec`'s `Eq` is const
        match &self.rehash(key_hash)? == rehash {
            true => Ok(()),
            false => {
                eprintln!("rehash spec auth fail");
                csync_err!(AuthenticationFail)
            }
        }
    }
}
