use crate::{
    prelude::*,
    secure_vec::*,
    specs::{authenticator_spec::*, cipher_spec::*, compressor_spec::*, key_deriv_spec::*, syncer_spec_ext::*},
};
use serde::{Deserialize, Serialize};
use std::{fmt::Debug, path::PathBuf};

///
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum SyncerSpec {
    Encrypt {
        //
        authenticator_spec: AuthenticatorSpec,
        cipher_spec: CipherSpec,
        compressor_spec: CompressorSpec,
        key_deriv_spec: KeyDerivSpec,
        //
        out_dir: PathBuf,
        source: PathBuf,
        //
        init_salt: CryptoSecureBytes,
        spread_depth: u8,
        verbose: bool,
        //
        salt_len: u16,
    },
    Decrypt {
        //
        authenticator_spec: AuthenticatorSpec,
        cipher_spec: CipherSpec,
        compressor_spec: CompressorSpec,
        key_deriv_spec: KeyDerivSpec,
        //
        out_dir: PathBuf,
        source: PathBuf,
        //
        init_salt: CryptoSecureBytes,
        spread_depth: u8,
        verbose: bool,
        //
        salt_len: u16,
    },
    Clean {
        source: PathBuf,
        verbose: bool,
    },
}

impl SyncerSpec {
    pub fn inverse(&self) -> Option<Self> {
        match self.clone() {
            //
            SyncerSpec::Encrypt {
                authenticator_spec,
                cipher_spec,
                compressor_spec,
                init_salt,
                key_deriv_spec,
                out_dir,
                salt_len,
                source,
                spread_depth,
                verbose,
            } => Some(SyncerSpec::Decrypt {
                //
                out_dir: source.parent().unwrap(),
                source: out_dir,
                //
                authenticator_spec,
                cipher_spec,
                compressor_spec,
                init_salt,
                key_deriv_spec,
                salt_len,
                spread_depth,
                verbose,
            }),
            //
            SyncerSpec::Decrypt {..} |
            SyncerSpec::Clean { .. } => None,
        }
    }
}

impl std::convert::TryFrom<&SyncerSpecExt> for SyncerSpec {
    type Error = CsyncErr;

    //
    fn try_from(spec_ext: &SyncerSpecExt) -> Result<Self, Self::Error> {
        match spec_ext {
            SyncerSpecExt::Encrypt {
                auth_spec,
                cipher_spec,
                compressor_spec,
                kd_spec_ext,
                out_dir,
                source,
                spread_depth,
                verbose,
                salt_len,
            } => {
                let key_deriv_spec = KeyDerivSpec::try_from(kd_spec_ext)?;

                Ok(SyncerSpec::Encrypt {
                    authenticator_spec: auth_spec.clone(),
                    cipher_spec: cipher_spec.clone(),
                    compressor_spec: compressor_spec.clone(),
                    init_salt: CryptoSecureBytes(rng!(*salt_len as usize).0),
                    key_deriv_spec,
                    out_dir: out_dir.canonicalize()?,
                    source: source.canonicalize()?,
                    spread_depth: *spread_depth,
                    verbose: *verbose,
                    salt_len: *salt_len,
                })
            }
            SyncerSpecExt::Decrypt { .. } | SyncerSpecExt::Clean { .. } => {
                panic!("`SyncerSpecExt` -> `SyncerSpec` conversion should only be used for encrypting")
            }
        }
    }
}