use crate::{
    encoder::{hmac::*, identity::*, openssl::*, zstd::*},
    fs_util::*,
    prelude::*,
    primitives::*,
    secure_vec::*,
    specs::{authenticator_spec::*, cipher_spec::*, compressor_spec::*, key_deriv_spec::*, syncer_spec_ext::*},
    util::*,
};
use ring::{hmac, pbkdf2};
use scrypt::ScryptParams;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    fmt::Debug,
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
};

///
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
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
        spread_depth: SpreadDepth,
        verbose: bool,
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
        spread_depth: SpreadDepth,
        verbose: bool,
    },
    Clean {
        source: PathBuf,
        verbose: bool,
    },
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
                spread_depth_opt,
                verbose,
            } => {
                let key_deriv_spec = KeyDerivSpec::try_from(kd_spec_ext)?;

                Ok(SyncerSpec::Encrypt {
                    authenticator_spec: auth_spec.clone(),
                    cipher_spec: cipher_spec.clone(),
                    compressor_spec: compressor_spec.clone(),
                    init_salt: CryptoSecureBytes(rng!(DEFAULT_SALT_LEN).0),
                    key_deriv_spec,
                    out_dir: out_dir.canonicalize()?,
                    source: source.canonicalize()?,
                    spread_depth: spread_depth_opt.clone(),
                    verbose: *verbose,
                })
            }
            SyncerSpecExt::Decrypt { .. } | SyncerSpecExt::Clean { .. } => {
                panic!("`SyncerSpecExt` -> `SyncerSpec` should only be used for encrypting")
            }
        }
    }
}