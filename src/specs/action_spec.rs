use crate::{
    prelude::*,
    secure_vec::*,
    specs::{cipher_spec::*, rehash_spec::*},
};
use serde::{Deserialize, Serialize};

///
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct ActionSpec {
    cipher_spec: CipherSpec, // included because each action gets a random salt
    unix_mode: Option<u32>,
    rehash_spec: RehashSpec,
    rehash: RehashedKey,
}

/// Specifies how an action should manifest.
impl ActionSpec {
    /// # Parameters
    ///
    /// 1. `cipher_spec`:
    /// 1. `unix_mode`:
    /// 1. `key_hash`:
    pub fn new(cipher_spec: &CipherSpec, unix_mode: Option<u32>, key_hash: &DerivedKey) -> CsyncResult<Self> {
        // rehash the key hash
        let rehash_spec: RehashSpec = Default::default();
        let rehash = rehash_spec.rehash(key_hash)?;

        //
        Ok(Self {
            cipher_spec: cipher_spec.clone(),
            rehash,
            rehash_spec,
            unix_mode,
        })
    }

    #[inline]
    pub fn get_unix_mode(&self) -> Option<u32> {
        self.unix_mode.clone()
    }

    #[inline]
    pub fn verify_derived_key(&self, key_hash: &DerivedKey) -> CsyncResult<()> {
        self.rehash_spec.verify(&self.rehash, key_hash)
    }
}
