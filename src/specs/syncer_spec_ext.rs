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
                let salt_len = *salt_len as usize;

                let kd_spec_ext = extract_kd_opt(&opts)?;

                let auth_spec = match auth.as_str() {
                    "hmac-sha512" => AuthenticatorSpec::HmacSha512,
                    _ => todo!(),
                };
                let cipher_spec = match cipher.as_str() {
                    "aes256cbc" => CipherSpec::Aes256Cbc {
                        init_vec: CryptoSecureBytes(rng!(salt_len).0),
                    },
                    "chacha20" => CipherSpec::ChaCha20 {
                        init_vec: CryptoSecureBytes(rng!(salt_len).0),
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
            pbkdf2_alg_opt,
            pbkdf2_num_iter_opt,
            pbkdf2_time_to_hash_opt,
            scrypt_log_n_opt,
            scrypt_p_opt,
            scrypt_r_opt,
            scrypt_time_to_hash_opt,
            scrypt_output_len_opt,
            ..
        } => {
            match (
                pbkdf2_alg_opt,
                pbkdf2_time_to_hash_opt,
                pbkdf2_num_iter_opt,
                scrypt_time_to_hash_opt,
                scrypt_log_n_opt,
                scrypt_p_opt,
                scrypt_r_opt,
                scrypt_output_len_opt,
            ) {
                //
                (None, None, None, None, None, None, None, None) => Ok(KeyDerivSpecExt::Scrypt {
                    log_n_opt: None,
                    r_opt: None,
                    p_opt: None,
                    time_opt: None,
                    output_len_opt: None,
                    // TODO salt len
                }),
                // pbkdf2
                (alg_opt, time_to_hash, num_iter_opt, None, None, None, None, None) => {
                    macro_rules! t {
                        ( $alg_opt:expr, $num_iter_opt:expr, $time_opt:expr ) => {
                            Ok(KeyDerivSpecExt::Pbkdf2 {
                                alg_opt: Some(match $alg_opt.as_ref().map(String::as_str) {
                                    Some("hmac-sha512") => Pbkdf2Algorithm::HmacSha512,
                                    Some(_) => todo!(),
                                    None => Default::default(),
                                }),
                                num_iter_opt: $num_iter_opt,
                                time_opt: $time_opt,
                            })
                        };
                    }
                    match (time_to_hash, num_iter_opt) {
                        (Some(_), Some(_)) => csync_err!(HashSpecConflict)?,
                        (Some(0), _) => t!(alg_opt, None, Some(DEFAULT_TIME_TO_HASH)),
                        (_, Some(0)) => t!(alg_opt, None, Some(DEFAULT_TIME_TO_HASH)),
                        (None, None) => t!(alg_opt, None, None),
                        (Some(time), None) => t!(alg_opt, None, Some(*time)),
                        (None, Some(num_iter)) => t!(alg_opt, Some(*num_iter), None),
                    }
                }
                (None, None, None, time_to_hash_opt, log_n_opt, p_opt, r_opt, output_len_opt) => {
                    macro_rules! t {
                        ( $log_n_opt:expr, $r_opt:expr, $p_opt:expr, $time_opt:expr, $output_len_opt:expr ) => {
                            Ok(KeyDerivSpecExt::Scrypt {
                                log_n_opt: $log_n_opt,
                                r_opt: $r_opt,
                                p_opt: $p_opt,
                                time_opt: $time_opt,
                                output_len_opt: $output_len_opt,
                            })
                        };
                    }
                    match (time_to_hash_opt, log_n_opt, p_opt, r_opt) {
                        (Some(0), None, None, None) => t!(None, None, None, Some(DEFAULT_TIME_TO_HASH), *output_len_opt),
                        (Some(time), None, None, None) => t!(None, None, None, Some(*time), *output_len_opt),
                        (None, None, None, None) => t!(None, None, None, None, *output_len_opt),
                        (None, _, _, _) => t!(*log_n_opt, *r_opt, *p_opt, None, *output_len_opt),
                        _ => csync_err!(HashSpecConflict)?,
                    }
                }
                _ => csync_err!(HashSpecConflict)?,
            }
        }
        Opts::Decrypt { .. } | Opts::Clean { .. } => panic!(),
    }
}
