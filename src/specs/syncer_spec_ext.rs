use crate::{
    clargs::*,
    prelude::*,
    primitives::*,
    secure_vec::*,
    specs::{authenticator_spec::*, cipher_spec::*, compressor_spec::*, key_deriv_spec_ext::*},
};
use std::{fmt::Debug, path::PathBuf};

///
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum SyncerSpecExt {
    Encrypt {
        auth_spec: AuthenticatorSpec,
        cipher_spec: CipherSpec,
        compressor_spec: CompressorSpec,
        kd_spec_ext: KeyDerivSpecExt,
        //
        out_dir: PathBuf,
        source: PathBuf,
        //
        spread_depth_opt: SpreadDepth,
        verbose: bool,
        //
        salt_len: u16,
    },
    Decrypt {
        out_dir: PathBuf,
        source: PathBuf,
        verbose: bool,
    },
    Clean {
        source: PathBuf,
        verbose: bool,
    },
}

///
impl std::convert::TryFrom<&Opts> for SyncerSpecExt {
    type Error = CsyncErr;

    //
    fn try_from(opts: &Opts) -> Result<Self, Self::Error> {
        match opts {
            Opts::Encrypt { source, .. } | Opts::Decrypt { source, .. } | Opts::Clean { source, .. } => {
                //
                if !source.exists() {
                    csync_err!(SourceDoesNotExist, source.clone())?;
                }
            }
        };
        match opts {
            Opts::Encrypt { out_dir, .. } => {
                if out_dir.exists() {
                    match out_dir.is_dir() {
                        true => match std::fs::read_dir(out_dir).map(Iterator::count)? {
                            0 => (),
                            _ => csync_err!(IncrementalEncryptionDisabledForNow)?,
                        },
                        false => csync_err!(OutdirIsNotDir, out_dir.to_path_buf())?,
                    }
                }
            }
            Opts::Decrypt { out_dir, .. } => {
                if out_dir.exists() {
                    match out_dir.is_dir() {
                        true => match std::fs::read_dir(out_dir).map(Iterator::count)? {
                            0 => (),
                            _ => csync_err!(DecryptionOutdirIsNonempty, out_dir.to_path_buf())?,
                        },
                        false => csync_err!(OutdirIsNotDir, out_dir.to_path_buf())?,
                    }
                }
            }
            Opts::Clean { .. } => {}
        };

        Ok(match opts {
            Opts::Encrypt {
                auth,
                cipher,
                compressor,
                salt_len,
                out_dir,
                source,
                spread_depth_opt,
                verbose,
                ..
            } => {
                let spread_depth_opt = match spread_depth_opt {
                    None => SpreadDepth::new(3),
                    Some(n) => match 0 < *n && *n <= std::u8::MAX as usize {
                        true => SpreadDepth::new(*n as u8),
                        false => csync_err!(InvalidSpreadDepth, *n)?,
                    },
                };

                let kd_spec_ext = extract_kd_opt(&opts)?;

                let auth_spec = match auth.as_str() {
                    "hmac-sha512" => AuthenticatorSpec::HmacSha512,
                    _ => todo!(),
                };
                let cipher_spec = match cipher.as_str() {
                    "aes256cbc" => CipherSpec::Aes256Cbc {
                        init_vec: CryptoSecureBytes(rng!(*salt_len as usize).0),
                    },
                    "chacha20" => CipherSpec::ChaCha20 {
                        init_vec: CryptoSecureBytes(rng!(*salt_len as usize).0),
                    },
                    _ => todo!(),
                };
                let compressor_spec = match compressor.as_str() {
                    "zstd" => CompressorSpec::Zstd {
                        level: DEFAULT_ZSTD_LEVEL,
                    },
                    _ => todo!(),
                };

                SyncerSpecExt::Encrypt {
                    auth_spec,
                    cipher_spec,
                    compressor_spec,
                    kd_spec_ext,
                    spread_depth_opt,
                    out_dir: out_dir.to_path_buf(),
                    source: source.to_path_buf(),
                    verbose: *verbose,
                    salt_len: *salt_len,
                }
            }
            Opts::Decrypt {
                source,
                out_dir,
                verbose,
                ..
            } => SyncerSpecExt::Decrypt {
                out_dir: out_dir.to_path_buf(),
                source: source.to_path_buf(),
                verbose: *verbose,
            },
            Opts::Clean { source, verbose, .. } => {
                SyncerSpecExt::Clean {
                    source: source.to_path_buf(),
                    verbose: *verbose,
                };
                todo!()
            }
        })
    }
}

fn extract_kd_opt(opts: &Opts) -> CsyncResult<KeyDerivSpecExt> {
    match opts {
        Opts::Encrypt {
            key_deriv_alg,
            key_deriv_time,
            key_deriv_by_params,
            pbkdf2_alg,
            pbkdf2_num_iter,
            scrypt_log_n,
            scrypt_p,
            scrypt_r,
            scrypt_output_len,
            salt_len,
            ..
        } => {
            match key_deriv_alg.as_ref() {
                "scrypt" => {
                    macro_rules! t {
                        ( $log_n_opt:expr, $r_opt:expr, $p_opt:expr, $time_opt:expr, $output_len:expr ) => {
                            Ok(KeyDerivSpecExt::Scrypt {
                                log_n_opt: $log_n_opt,
                                r_opt: $r_opt,
                                p_opt: $p_opt,
                                time_opt: $time_opt,
                                output_len: $output_len,
                                salt_len: *salt_len,
                            })
                        };
                    }

                    match key_deriv_by_params {
                        true => t!(
                            Some(*scrypt_log_n),
                            Some(*scrypt_r),
                            Some(*scrypt_p),
                            None,
                            *scrypt_output_len
                        ),
                        false => t!(None, None, None, Some(*key_deriv_time), *scrypt_output_len),
                    }
                }
                "pbkdf2" => {
                    macro_rules! t {
                        ( $num_iter_opt:expr, $time_opt:expr ) => {
                            Ok(KeyDerivSpecExt::Pbkdf2 {
                                alg_opt: Some(match pbkdf2_alg.as_ref() {
                                    "hmac-sha512" => Pbkdf2Algorithm::HmacSha512,
                                    _ => todo!(),
                                }),
                                num_iter_opt: $num_iter_opt,
                                time_opt: $time_opt,
                                salt_len: *salt_len,
                            })
                        };
                    }

                    match key_deriv_by_params {
                        true => t!(Some(*pbkdf2_num_iter), None),
                        false => t!(None, Some(*key_deriv_time)),
                    }
                }
                _ => todo!(),
            }
        }
        Opts::Decrypt { .. } | Opts::Clean { .. } => panic!(),
    }
}
