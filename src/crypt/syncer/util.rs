/// TODO
///
/// 1. syncing to a non-empty dir
///     1. if encrypting, collect to hashset and check for differences
///     1. if decrypting, force the dir to be non empty
/// 1. if using metadata that is recovered, make sure that passwords match
use crate::{
    encoder::{crypt_encoder::*, openssl::*, text::*},
    fs_util::*,
    prelude::*,
    primitives::*,
    secure_vec::*,
    specs::prelude::*,
    util::*,
};
use itertools::Itertools;
use rayon::prelude::*;
use std::{
    fs::{read_dir, Permissions},
    path::{Path, PathBuf},
    time::SystemTime,
};
use walkdir::WalkDir;

/// TODO maybe have a visitor for this later?
pub fn report_syncer_spec(spec: &SyncerSpec) -> String {
    let action = match spec {
        SyncerSpec::Encrypt { .. } => "Encrypt",
        SyncerSpec::Decrypt { .. } => "Decrypt",
        SyncerSpec::Clean { .. } => "Clean",
    };

    // align things for pretty print
    macro_rules! format_body {
        ( $name:literal, $body:expr ) => {{
            let (main, extra) = $body;
            format!("{:>32}: {:>16} ({})\n", $name, main, extra)
        }};
    }

    // length in bits
    macro_rules! bit_len {
        ( $vec:expr ) => {
            8 * $vec.0.unsecure().len()
        };
    }

    match spec {
        SyncerSpec::Encrypt {
            authenticator_spec,
            cipher_spec,
            compressor_spec,
            key_deriv_spec,
            out_dir,
            source,
            init_salt,
            spread_depth,
            verbose,
            ..
        }
        | SyncerSpec::Decrypt {
            authenticator_spec,
            cipher_spec,
            compressor_spec,
            key_deriv_spec,
            out_dir,
            source,
            init_salt,
            spread_depth,
            verbose,
            ..
        } if *verbose => {
            let action_desc = format!("\n{}ing: {:?} -> {:?}\n\n", action, source, out_dir);
            let salt_desc = format_body!("Random salt", ("", format!("{}-bit", bit_len!(init_salt))));
            let spread_depth_desc = format_body!("Spread depth", ("", format!("{}", *spread_depth)));
            let auth_desc = format_body!(
                "Authentication algorithm",
                match authenticator_spec {
                    AuthenticatorSpec::HmacSha512 => ("HMAC-SHA512", "_"),
                }
            );
            let comp_desc = format_body!(
                "Compression algorithm",
                match compressor_spec {
                    CompressorSpec::Zstd { level } => ("Zstandard", format!("level-{}", level)),
                }
            );
            let cipher_desc = format_body!(
                "Encryption algorithm",
                match cipher_spec {
                    CipherSpec::Aes256Cbc { init_vec } => ("AES-256-CBC", format!("{}-bit salt", bit_len!(init_vec))),
                    CipherSpec::ChaCha20 { init_vec } => ("ChaCha20", format!("{}-bit salt", bit_len!(init_vec))),
                }
            );
            let key_deriv_desc = format_body!(
                "Key-derivation algorithm",
                match key_deriv_spec {
                    KeyDerivSpec::Pbkdf2 { num_iter, alg, salt } => (
                        "PBKDF2",
                        format!(
                            "{}, {} iter's, {}-bit salt",
                            match alg {
                                Pbkdf2Algorithm::HmacSha512 => "HMAC-SHA512",
                            },
                            num_iter,
                            bit_len!(salt)
                        )
                    ),
                    KeyDerivSpec::Scrypt {
                        log_n,
                        r,
                        p,
                        output_len,
                        salt,
                    } => (
                        "Scrypt",
                        format!(
                            "log_n: {}, r: {}, p: {}, {}-bit output, {}-bit salt",
                            log_n,
                            r,
                            p,
                            8 * output_len,
                            bit_len!(salt)
                        )
                    ),
                }
            );
            action_desc + &salt_desc + &spread_depth_desc + &auth_desc + &comp_desc + &cipher_desc + &key_deriv_desc
        }
        SyncerSpec::Clean { verbose, .. } if *verbose => todo!(),
        _ => String::new(),
    }
}

/// # Parameters
///
/// 1. `root`:
///
/// # Returns
///
/// Various metadata for each file under `root`. The purpose of this function is to minimize the
/// number of IO calls.
pub fn meta_map(root: &Path) -> impl ParallelIterator<Item = CsyncResult<(usize, PathBuf, Permissions, SystemTime, FileType)>> {
    debug_assert!(is_canonical(&root).unwrap());
    WalkDir::new(root)
        .follow_links(true)
        .into_iter()
        .enumerate()
        .par_bridge()
        .map(|(uid, entry_res)| {
            let entry = entry_res?;
            // :: DirEntry -> (PathBuf, SystemTime)
            // only handle regular files and dirs
            let meta = entry.metadata()?;
            let ftype = entry.file_type();
            //
            macro_rules! ok {
                ( $modified:expr, $file_type:expr ) => {
                    Ok((
                        uid,
                        entry.into_path().canonicalize()?,
                        meta.permissions(),
                        $modified,
                        $file_type,
                    ))
                };
            }
            //
            match meta.modified()? {
                // everything good
                modified if ftype.is_file() => ok!(modified, FileType::File),
                modified if ftype.is_dir() => ok!(modified, FileType::Dir),
                // not a file or dir, maybe support later
                _ => csync_err!(Other, format!("filetype not supported")),
            }
        })
}

//
pub fn check_out_dir(out_dir: &Path, spec: &SyncerSpec) -> CsyncResult<()> {
    // `out_dir` doesn't have to exist, but requires case-by-case checks
    match out_dir.exists() {
        //
        true if out_dir.is_dir() => match spec {
            SyncerSpec::Encrypt { .. } => Ok(()),
            SyncerSpec::Decrypt { .. } => match read_dir(out_dir)?.count() {
                //
                0 => Ok(()),
                //
                _ => csync_err!(DecryptionOutdirIsNonempty, out_dir.to_path_buf()),
            },
            SyncerSpec::Clean { .. } => todo!(),
        },
        //
        true => csync_err!(OutdirIsNotDir, out_dir.to_path_buf()),
        //
        false => Ok(()),
    }
}

// # Parameters
//
// 1. `spread_depth`: number of layers used in spreading; a max of `64 ^ spread_depth` number of
//    distinct directories can be created
// 2. `path`: the path with which spread dirs will be created
pub fn path_to_spread(spread_depth: u8, init_salt: &CryptoSecureBytes, path: &Path) -> CsyncResult<PathBuf> {
    debug_assert!(is_canonical(&path).unwrap());

    // 'spread dirs are the depth-n dirs created with sha512 in order to spread out the files
    // into different dirs
    match path_as_string(path) {
        // compute a pathsafe-base64-encoded hash of the pathbuf
        Some(s) => {
            let hash = base32path(sha512!(&s.into(), init_salt).0.unsecure())?;
            let hash_str = &hash[..spread_depth as usize];
            let hash_string_interspersed: String = hash_str.chars().intersperse('/').collect();
            // get the first spreaod_depth chars of the hash, with '/' interopersed
            Ok(PathBuf::from(hash_string_interspersed))
        }
        None => csync_err!(Other, "".to_string()),
    }
}

/// # Parameters
///
/// 1.
#[inline]
pub fn spread_to_hash(spread: &Path) -> CsyncResult<CryptoSecureBytes> {
    // get a hash of the chars in the spread dir path, to use as the initialization
    // vector for the Aes256CbcEnc
    match path_as_string(&spread) {
        Some(string) => Ok(sha512!(&string.chars().filter(|c| c != &'/').collect::<String>().into())),
        None => csync_err!(PathContainsInvalidUtf8Bytes, spread.to_path_buf()),
    }
}

/// # Parameters
///
/// 1. `src_root`:
/// 1. `src_path`:
/// 1. `file_type`:
/// 1. `spread_hash`:
/// 1. `derived_key`:
///
/// # Returns
///
/// a
pub fn path_to_cipherpath(
    src_root: &Path,
    src_path: &Path,
    file_type: FileType,
    spread_hash: &CryptoSecureBytes,
    derived_key: &DerivedKey,
) -> CsyncResult<PathBuf> {
    debug_assert!(src_path.starts_with(src_root));
    debug_assert!(is_canonical(src_root).unwrap());
    debug_assert!(is_canonical(src_path).unwrap());
    let aug_src_rel_path = {
        let src_rel_path = csync_unwrap_opt!(subpath_par(src_path, src_root));

        let rand_bytes_string = {
            // deterministic seed given the rel path of the src file
            let src_seed = {
                let src_rel_path_str = csync_unwrap_opt!(path_as_string(&src_rel_path));
                let hash = sha512!(&src_rel_path_str.into());
                CryptoSecureBytes((&hash.0.unsecure()[..32]).into())
            };

            // generate somewhere between 40 to 200 random bytes
            let rand_bytes: Vec<_> = rng_seed!(&src_seed, 40, 200, std::u8::MIN, std::u8::MAX)
                .0
                .unsecure()
                .into_iter()
                .copied()
                .filter(|byte| &32 <= byte && byte <= &126)
                .collect();

            compose_encoders!(
                &rand_bytes[..],
                TextEncoder => &BASE32PATH
            )?
            .as_string()?
        };
        debug_assert!(0 < rand_bytes_string.len());

        let filetype_prefix = match file_type {
            FileType::File => "f",
            FileType::Dir => "d",
        };

        Path::new(&rand_bytes_string).join(filetype_prefix).join(src_rel_path)
    };

    // encrypt the entire path using the spread hash as the init vec
    let aug_src_rel_path_string = path_as_string(&aug_src_rel_path).unwrap();
    let aug_src_rel_path_bytes = aug_src_rel_path_string.as_bytes();
    let ciphertext = compose_encoders!(
        aug_src_rel_path_bytes,
        Aes256CbcEnc => (&CryptoSecureBytes(derived_key.0 .0.clone()), Some(&spread_hash)),
        TextEncoder => &BASE32PATH
    )?
    .as_string()?;

    // group into chunks of 64 chars, then join them with '/'
    let without_ext = ciphertext
        .chars()
        .chunks(64)
        .into_iter()
        .map(|chunk| chunk.into_iter().collect::<String>())
        .join("/");

    Ok(PathBuf::from(format!("{}.{}", without_ext, FILE_SUFFIX)))
}

//
pub fn cipherpath_to_path(
    spread_depth: u8,
    src_root: &Path,
    cipherpath: &Path,
    derived_key: &DerivedKey,
) -> CsyncResult<(PathBuf, FileType, CryptoSecureBytes)> {
    debug_assert!(is_canonical(&src_root).unwrap());
    debug_assert!(cipherpath.is_absolute());
    let rel_path = subpath(cipherpath, src_root).unwrap();
    let comps: Vec<_> = rel_path.components().collect();
    let spread_hash = spread_to_hash(Path::new(
        &comps
            .iter()
            .take(spread_depth as usize)
            .map(|comp| match comp.as_os_str().to_str() {
                Some(s) => s,
                None => panic!("dir has been tampered with"),
            })
            .join("/")
            .chars()
            .flat_map(char::to_lowercase)
            .collect::<String>(),
    ))?;

    let cipher_bytes: Vec<_> = {
        let ciphertext = comps
            .iter()
            .skip(spread_depth as usize)
            .map(|comp| match comp.as_os_str().to_str() {
                Some(s) => s,
                None => panic!("dir has been tampered with"),
            })
            .join("");
        debug_assert!(ciphertext.len() > FILE_SUFFIX.len() + 1);
        let cipher_len = &ciphertext.len() - (FILE_SUFFIX.len() + 1); // + 1 for the .
        (&ciphertext[..cipher_len]).bytes().collect()
    };

    let decrypted = compose_encoders!(
        &cipher_bytes[..],
        TextDecoder => &BASE32PATH,
        Aes256CbcDec => (&CryptoSecureBytes(derived_key.0 .0.clone()), Some(&spread_hash))
    )?
    .as_string()?;

    let mut decrypted_comps = Path::new(&decrypted).components();
    decrypted_comps.next().unwrap(); // random padding
    let ftype = match decrypted_comps.next().unwrap().as_os_str().to_str() {
        Some("f") => FileType::File,
        Some("d") => FileType::Dir,
        _ => panic!("wrong number of comps"),
    };
    let decrypted_pbuf = PathBuf::from(decrypted_comps.as_path());

    Ok((decrypted_pbuf, ftype, spread_hash))
}
