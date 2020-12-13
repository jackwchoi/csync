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
        let Opts {
            auth_opt,
            cipher_opt,
            clean,
            compressor_opt,
            decrypt,
            salt_len_opt,
            out_dir,
            source,
            spread_depth_opt,
            verbose,
            ..
        } = opts;
        //
        if !source.exists() {
            csync_err!(SourceDoesNotExist, source.clone())?;
        }
        //
        match out_dir.exists() {
            true => match out_dir.is_dir() {
                true => match std::fs::read_dir(out_dir).map(Iterator::count) {
                    Ok(0) => (),
                    Ok(_) => match decrypt {
                        true => csync_err!(DecryptionOutdirIsNonempty, out_dir.to_path_buf())?,
                        false => csync_err!(IncrementalEncryptionDisabledForNow)?,
                    },
                    Err(err) => Err(err)?,
                },
                false => csync_err!(OutdirIsNotDir, out_dir.to_path_buf())?,
            },
            false => (),
        };

        Ok(match (clean, decrypt) {
            (true, true) => csync_err!(CommandLineArgumentConflict, String::new())?,
            (true, false) => {
                SyncerSpecExt::Clean {
                    source: source.to_path_buf(),
                    verbose: *verbose,
                };
                todo!()
            }
            (false, true) => SyncerSpecExt::Decrypt {
                out_dir: out_dir.to_path_buf(),
                source: source.to_path_buf(),
                verbose: *verbose,
            },
            (false, false) => {
                let spread_depth_opt = match spread_depth_opt {
                    None => SpreadDepth::new(3),
                    Some(n) => match 0 < *n && *n <= std::u8::MAX as usize {
                        true => SpreadDepth::new(*n as u8),
                        false => csync_err!(InvalidSpreadDepth, *n)?,
                    },
                };
                let salt_len = salt_len_opt.map(|x| x as usize).unwrap_or(DEFAULT_SALT_LEN);

                let kd_spec_ext = extract_kd_opt(&opts)?;

                let auth_spec = match auth_opt.as_ref().map(String::as_str) {
                    None => Default::default(),
                    Some("hmac-sha512") => AuthenticatorSpec::HmacSha512,
                    Some(_) => todo!(),
                };
                let cipher_spec = match cipher_opt.as_ref().map(String::as_str) {
                    None => Default::default(),
                    Some("aes256cbc") => CipherSpec::Aes256Cbc {
                        init_vec: CryptoSecureBytes(rng!(salt_len).0),
                    },
                    Some("chacha20") => CipherSpec::ChaCha20 {
                        init_vec: CryptoSecureBytes(rng!(salt_len).0),
                    },
                    Some(_) => todo!(),
                };
                let compressor_spec = match compressor_opt.as_ref().map(String::as_str) {
                    None => Default::default(),
                    Some("zstd") => CompressorSpec::Zstd {
                        level: DEFAULT_ZSTD_LEVEL,
                    },
                    Some(_) => todo!(),
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
        })
    }
}

fn extract_kd_opt(opts: &Opts) -> CsyncResult<KeyDerivSpecExt> {
    let Opts {
        pbkdf2_alg_opt,
        pbkdf2_num_iter_opt,
        pbkdf2_time_to_hash_opt,
        scrypt_log_n_opt,
        scrypt_p_opt,
        scrypt_r_opt,
        scrypt_time_to_hash_opt,
        scrypt_output_len_opt,
        ..
    } = opts;
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
        (None, None, None, None, None, None, None, None) => Ok(Default::default()),
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
