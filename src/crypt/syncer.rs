/// TODO
///
/// 1. syncing to a non-empty dir
///     1. if encrypting, collect to hashset and check for differences
///     1. if decrypting, force the dir to be non empty
/// 1. if using metadata that is recovered, make sure that passwords match
use crate::{
    crypt::{action::*, util::*},
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
use std::ffi::OsStr;
use std::{
    convert::TryFrom,
    fs::{create_dir_all, metadata, read_dir, Permissions},
    io,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    time::SystemTime,
    u8,
};
use tempfile::TempDir;
use walkdir::WalkDir;

/// `Syncer` is the only public interface that handles all functionalities related to `csync`.
///
/// # Constructor
///
/// There is only one way to construct a `Syncer` instance, and it is through `Syncer::new`. The
/// behavior of this instance will be solely dictated by the `SyncerSpecExt`, which acts as its
/// specification.
///
/// This constructor takes a non-trivial amount of computation to complete; see the docs for
/// `Syncer::new`.
///
/// # Performance / Runtime Complexity, Memory Usage
///
/// __TLDR__:
/// 1. `Syncer`'s memory usage is the same regardless of whether you are working on 100 files or
///    millions of files
/// 1. if your machine has `k` times more cores than your friend's, `csync` will run `k` times faster
///    on your machine
///
/// `Syncer` uses the following concepts/styles/paradigms to work on large sets of files
/// efficiently:
/// 1. Data-parallelism: each file is processed independently of one another, in parallel
/// 1. Lazy-evaluation: computations do not take place until they are absolutely necessary
/// 1. Streaming: memory usage is constant and does not change over time
///
/// All of the above allow for some enticing properties, detailed below.
///
/// ## Asymptotic Properties
///
/// Let:
/// 1. `n` be the number of files `csync` operates on
/// 1. `k` be the number of cores on your machine
///
/// Then the following properties of `csync` holds:
/// 1. Runtime complexity grows linearly with `n`, in other words `O(n)`
/// 1. Memory usage grows linearly with `k` but __CONSTANT with respect to `n`__, in other words `O(k)`.
///     
/// # Exapmle
///
/// TODO
#[derive(Debug)]
pub struct Syncer {
    // some temp location where the encrypted files will be stored before
    // being moved to their final locations
    arena: TempDir,
    // every field above is either user-supplied or derived from the metadata below
    derived_key: DerivedKey,
    init_key: InitialKey,
    //
    spec: SyncerSpec,
}

///
impl Syncer {
    #[inline]
    pub fn get_spec(&self) -> SyncerSpec {
        self.spec.clone()
    }

    /// The only public constructor.
    pub fn new(spec_ext: &SyncerSpecExt, init_key: InitialKey) -> CsyncResult<Self> {
        //
        match spec_ext {
            //
            SyncerSpecExt::Encrypt { .. } => Syncer::with_spec_ext(spec_ext, init_key),
            //
            SyncerSpecExt::Decrypt { .. } => Syncer::from_dir(spec_ext, &init_key),
            //
            SyncerSpecExt::Clean { .. } => todo!(), // probably should use from_dir
        }
    }

    /// init from an existing csync dir by loading the metadata
    fn from_dir(spec_ext: &SyncerSpecExt, init_key: &InitialKey) -> CsyncResult<Self> {
        //
        macro_rules! from_dir {
            ( $source:expr, $out_dir:expr, $metadata_par_dir:expr ) => {{
                //
                match $source == $out_dir {
                    //
                    true => csync_err!(SourceEqOutdir, $source.to_path_buf())?,
                    //
                    false => {
                        let (syncer_spec, action_spec) = Syncer::load_syncer_action_spec($metadata_par_dir)?;

                        let derived_key = match &syncer_spec {
                            SyncerSpec::Encrypt {
                                key_deriv_spec,
                                verbose,
                                ..
                            } => {
                                let (derived_key, _) = time!(
                                    *verbose,
                                    "Generating/authenticating the derived key",
                                    key_deriv_spec.derive(&init_key.0 .0)?
                                );
                                derived_key
                            }
                            _ => panic!("Loaded metadata should only be of the variant `SyncerSpec::Encrypt`"),
                        };

                        action_spec.verify_derived_key(&derived_key)?;

                        // let hashed_key = Syncer::verify_syncer_spec(&syncer_spec, &action_spec, &init_key)?;
                        match spec_ext {
                            //
                            SyncerSpecExt::Encrypt { .. } => Syncer::with_spec(syncer_spec, init_key.clone(), None),
                            //
                            SyncerSpecExt::Decrypt { .. } => match syncer_spec {
                                //
                                SyncerSpec::Encrypt {
                                    authenticator_spec,
                                    cipher_spec,
                                    compressor_spec,
                                    key_deriv_spec,
                                    init_salt,
                                    spread_depth,
                                    verbose,
                                    ..
                                } => {
                                    create_dir_all($out_dir)?;
                                    Syncer::with_spec(
                                        SyncerSpec::Decrypt {
                                            authenticator_spec,
                                            cipher_spec,
                                            compressor_spec,
                                            key_deriv_spec,
                                            out_dir: $out_dir.canonicalize()?,
                                            source: $source.canonicalize()?,
                                            init_salt,
                                            spread_depth,
                                            verbose,
                                        },
                                        init_key.clone(),
                                        None,
                                    )
                                }
                                _ => todo!(),
                            },
                            _ => todo!(),
                        }
                    }
                }
            }};
        };
        //
        match &spec_ext {
            //
            SyncerSpecExt::Encrypt { source, out_dir, .. } => from_dir!(source, out_dir, out_dir),
            //
            SyncerSpecExt::Decrypt { source, out_dir, .. } => from_dir!(source, out_dir, source),
            //
            SyncerSpecExt::Clean { .. } => todo!(),
        }
    }

    /// # Parameters
    fn with_spec_ext(spec_ext: &SyncerSpecExt, init_key: InitialKey) -> CsyncResult<Self> {
        // if from_dir works, use it
        // if not, start fresh from
        match Syncer::from_dir(spec_ext, &init_key) {
            Ok(syncer) => match spec_ext {
                SyncerSpecExt::Encrypt { verbose, .. } | SyncerSpecExt::Decrypt { verbose, .. } => {
                    if *verbose {
                        eprintln!("Metadata recovered: csync will use this instead of provided options.");
                        // TODO ask for confirmation?
                    }
                    Ok(syncer)
                }
                _ => todo!(),
            },
            Err(_) => match spec_ext {
                SyncerSpecExt::Encrypt {
                    out_dir,
                    ..
                } => {
                    // if from_dir failed, outdir must either be empty or non-existent
                    match (out_dir.exists(), out_dir.is_dir()) {
                        (false, _) => (),
                        (true, true) => match std::fs::read_dir(out_dir).map(Iterator::count) {
                            Ok(0) => (),
                            Ok(_) => csync_err!(IncrementalEncryptionDisabledForNow)?,
                            Err(_) => panic!("Failed to read `out_dir`"),
                        },
                        (true, false) => csync_err!(OutdirIsNotDir, out_dir.to_path_buf())?,
                    }

                    create_dir_all(out_dir)?;
                    let spec = SyncerSpec::try_from(spec_ext)?;
                    Syncer::with_spec(spec, init_key, None)
                }
                SyncerSpecExt::Decrypt { .. } | SyncerSpecExt::Clean { .. } => todo!(),
            },
        }
    }

    ///
    fn with_spec(spec: SyncerSpec, init_key: InitialKey, derived_key_opt: Option<DerivedKey>) -> CsyncResult<Self> {
        report_syncer_spec(&spec);
        match &spec {
            //
            SyncerSpec::Clean { .. } => todo!(),
            //
            SyncerSpec::Encrypt {
                source,
                out_dir,
                key_deriv_spec,
                verbose,
                ..
            }
            | SyncerSpec::Decrypt {
                source,
                out_dir,
                key_deriv_spec,
                verbose,
                ..
            } => {
                if !source.exists() {
                    csync_err!(SourceDoesNotExist, source.to_path_buf())?;
                }

                debug_assert!(is_canonical(source).unwrap());
                debug_assert!(is_canonical(out_dir).unwrap());

                // do this here because canonicalization requires the path to exist
                // create_dir_all(&out_dir)?;
                check_out_dir(&out_dir, &spec)?;

                let source = source.canonicalize()?.to_path_buf();
                let out_dir = out_dir.canonicalize()?.to_path_buf();

                match source.file_name() {
                    //
                    None => csync_err!(SourceDoesNotHaveFilename, source.to_path_buf()),
                    //
                    Some(_) if source == out_dir => csync_err!(SourceEqOutdir, source),
                    //
                    _ => {
                        let derived_key = match derived_key_opt {
                            Some(derived_key) => derived_key,
                            None => time!(*verbose, "Generating a derived key", key_deriv_spec.derive(&init_key.0 .0)?).0,
                        };

                        Ok(Self {
                            arena: tmpdir!()?,
                            init_key,
                            derived_key,
                            spec,
                        })
                    }
                }
            }
        }
    }

    /// Load metadata from an existing `csync` directory.
    fn load_syncer_action_spec(source: &Path) -> CsyncResult<(SyncerSpec, ActionSpec)> {
        match source.exists() {
            true => {
                let result_opt = WalkDir::new(source)
                    .follow_links(true)
                    .into_iter()
                    .filter_map(|entry| match entry.map(walkdir::DirEntry::into_path) {
                        Ok(pbuf) => match pbuf.extension().map(OsStr::to_str) {
                            Some(Some("csync")) => match crate::crypt::util::load_syncer_action_specs(&pbuf) {
                                Ok(specs) => Some(specs),
                                _ => None,
                            },
                            _ => None,
                        },
                        _ => None,
                    })
                    .nth(0);

                match result_opt {
                    Some(specs) => Ok(specs),
                    None => csync_err!(MetadataLoadFailed, "Could not open any of the csync files".to_string()),
                }
            }
            false => csync_err!(ControlFlow),
        }
    }

    // TODO maybe return the final dk here so that with_spec doesnt do the same work again
    fn verify_syncer_spec(
        syncer_spec: &SyncerSpec,
        action_spec: &ActionSpec,
        init_key: &InitialKey,
    ) -> CsyncResult<DerivedKey> {
        match syncer_spec {
            SyncerSpec::Encrypt { key_deriv_spec, .. } | SyncerSpec::Decrypt { key_deriv_spec, .. } => {
                let derived_key = key_deriv_spec.derive(&init_key.0 .0)?;
                action_spec.verify_derived_key(&derived_key)?;
                Ok(derived_key)
            }
            SyncerSpec::Clean { .. } => todo!(),
        }
    }

    // 1. for the root cfile,
    ///
    pub fn sync_enc<'a>(&'a self) -> CsyncResult<impl ParallelIterator<Item = CsyncResult<Action>> + 'a> {
        match &self.spec {
            SyncerSpec::Encrypt { .. } => {
                self.check_rep();

                let iter = self.sync_enc_dry()?;

                Ok(iter.map(move |action| action?.manifest(self.arena.path(), &self.derived_key)))
            }
            _ => todo!(),
        }
    }

    ///
    pub fn sync_enc_dry<'a>(&'a self) -> CsyncResult<impl ParallelIterator<Item = CsyncResult<Action>> + 'a> {
        match &self.spec {
            SyncerSpec::Encrypt {
                source,
                out_dir,
                spread_depth,
                init_salt,
                ..
            } => {
                self.check_rep();
                check_out_dir(out_dir, &self.spec)?;

                Ok(meta_map(source).filter_map(move |meta_res| match meta_res {
                    Ok((_, src_pbuf, perms, src_modtime, file_type)) => {
                        let spread = match path_to_spread(*spread_depth, &init_salt, &src_pbuf) {
                            Ok(x) => x,
                            Err(err) => return Some(csync_err!(Other, format!("{}", err))),
                        };
                        let spread_hash = match spread_to_hash(&spread) {
                            Ok(x) => x,
                            Err(err) => return Some(Err(err)),
                        };

                        let cipherpath = {
                            let cipher_basename =
                                match path_to_cipherpath(source, &src_pbuf, file_type, &spread_hash, &self.derived_key) {
                                    Ok(cipherpath) => cipherpath,
                                    Err(err) => return Some(Err(err)),
                                };
                            out_dir.join(spread).join(cipher_basename)
                        };

                        // sugar
                        macro_rules! action {
                            ( $dest:expr ) => {
                                Some(Action::new(
                                    &self.spec,
                                    &src_pbuf.to_path_buf(),
                                    $dest,
                                    file_type,
                                    Some(perms.mode()),
                                    &self.derived_key,
                                ))
                            };
                        };

                        match metadata(&cipherpath) {
                            Ok(meta) => match meta.modified() {
                                // both files exist, so compare their modified times
                                Ok(enc_mod) => match src_modtime.duration_since(enc_mod) {
                                    // src was modified after enc, so include it
                                    Ok(duration) if 0 < duration.as_nanos() => action!(&cipherpath),
                                    // enc was modified after src, so don't include it
                                    _ => None,
                                },
                                Err(err) => panic!("{:?}", err),
                            },
                            Err(err) if err.kind() == io::ErrorKind::NotFound => action!(&cipherpath),
                            Err(err) => panic!("{:?}", err),
                        }
                    }
                    Err(err) => Some(Err(err)),
                }))
            }
            _ => todo!(),
        }
    }

    ///
    pub fn sync_dec<'a>(&'a self) -> CsyncResult<impl ParallelIterator<Item = CsyncResult<Action>> + 'a> {
        match &self.spec {
            SyncerSpec::Decrypt { .. } => {
                self.check_rep();

                let iter = self.sync_dec_dry()?;
                Ok(iter.map(move |action| action?.manifest(self.arena.path(), &self.derived_key)))
            }
            _ => {
                dbg!(&self.spec);
                todo!()
            }
        }
    }

    ///
    pub fn sync_dec_dry<'a>(&'a self) -> CsyncResult<impl ParallelIterator<Item = CsyncResult<Action>> + 'a> {
        match &self.spec {
            SyncerSpec::Decrypt {
                source,
                out_dir,
                spread_depth,
                ..
            } => {
                self.check_rep();
                check_out_dir(out_dir, &self.spec)?;

                Ok(WalkDir::new(source)
                    .into_iter()
                    .enumerate()
                    .par_bridge()
                    .filter(|(_, entry_res)| match entry_res {
                        Ok(entry) => match entry.metadata() {
                            // only work with files that end with .syncr
                            Ok(meta) => meta.is_file() && entry.path().extension() == Some(OsStr::new(FILE_SUFFIX)),
                            Err(_) => true,
                        },
                        Err(_) => true,
                    })
                    .map(move |(uid, entry_res)| -> CsyncResult<Action> {
                        let cipherpath = entry_res?.path().canonicalize()?;
                        debug_assert!(is_canonical(&cipherpath).unwrap());
                        let (path, file_type, _) =
                            cipherpath_to_path(spread_depth.clone(), source, &cipherpath, &self.derived_key)?;
                        Action::new(
                            &self.spec,
                            &cipherpath,
                            &out_dir.join(path),
                            file_type,
                            None,
                            &self.derived_key,
                        )
                    }))
            }
            _ => todo!(),
        }
    }

    /// Miscellaneous checks.
    #[inline]
    fn check_rep(&self) {}
}

fn report_syncer_spec(spec: &SyncerSpec) {
    let action = match spec {
        SyncerSpec::Encrypt { .. } => "Encrypt",
        SyncerSpec::Decrypt { .. } => "Decrypt",
        SyncerSpec::Clean { .. } => "Clean",
    };

    macro_rules! eprintln_body {
        ( $name:literal, $body:expr ) => {{
            let (main, extra) = $body;
            eprintln!("{:>32}: {:>16} ({})", $name, main, extra)
        }};
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
        } if *verbose => {
            eprintln!("\n{}ing: {:?} -> {:?}", action, source, out_dir);
            eprintln!();
            eprintln_body!("Random salt", ("", format!("{}-bit", 8 * init_salt.0.unsecure().len())));
            eprintln_body!("Spread depth", ("", format!("{}", **spread_depth)));
            eprintln_body!(
                "Authentication algorithm",
                match authenticator_spec {
                    AuthenticatorSpec::HmacSha512 => ("HMAC-SHA512", "_"),
                }
            );
            eprintln_body!(
                "Compression algorithm",
                match compressor_spec {
                    CompressorSpec::Zstd { level } => ("Zstandard", format!("level-{}", level)),
                }
            );
            eprintln_body!(
                "Encryption algorithm",
                match cipher_spec {
                    CipherSpec::Aes256Cbc { init_vec } =>
                        ("AES-256-CBC", format!("{}-bit salt", 8 * init_vec.0.unsecure().len())),
                    CipherSpec::ChaCha20 { init_vec } => ("ChaCha20", format!("{}-bit salt", 8 * init_vec.0.unsecure().len())),
                }
            );
            eprintln_body!(
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
                            8 * salt.0.unsecure().len()
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
                            8 * salt.0.unsecure().len()
                        )
                    ),
                }
            );
        }
        SyncerSpec::Clean { source, verbose } if *verbose => todo!(),
        _ => (),
    }
}

/// Mapping from paths under `root` to some of its metadata.
///
///
fn meta_map(root: &Path) -> impl ParallelIterator<Item = CsyncResult<(usize, PathBuf, Permissions, SystemTime, FileType)>> {
    debug_assert!(is_canonical(&root).unwrap());
    WalkDir::new(root)
        .follow_links(true)
        .into_iter()
        .enumerate()
        .par_bridge()
        .map(|(uid, entry_res)| match entry_res {
            // :: DirEntry -> (PathBuf, SystemTime)
            // only handle regular files and dirs
            Ok(entry) => {
                match (entry.metadata(), entry.file_type()) {
                    (Ok(meta), ftype) => {
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
                        match meta.modified() {
                            // everything good
                            Ok(modified) if ftype.is_file() => ok!(modified, FileType::File),
                            Ok(modified) if ftype.is_dir() => ok!(modified, FileType::Dir),
                            // not a file or dir, maybe support later
                            Ok(_) => csync_err!(Other, format!("filetype not supported")),
                            Err(err) => csync_err!(Other, format!("cannon read modified time: {}", err)),
                        }
                    }
                    (Err(err), _) => csync_err!(Other, format!("cannot read metadata: {}", err)),
                }
            }
            Err(err) => csync_err!(Other, format!("failed reading {}", err)),
        })
}

///
fn check_out_dir(out_dir: &Path, spec: &SyncerSpec) -> CsyncResult<()> {
    // `out_dir` doesn't have to exist, but requires case-by-case checks
    match out_dir.exists() {
        //
        true if out_dir.is_dir() => match spec {
            SyncerSpec::Encrypt { .. } => {
                // TODO check for missing files
                if std::fs::read_dir(out_dir)?.count() > 0 {
                    todo!();
                }
                Ok(())
            }
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

/// # Parameters
///
/// 1. `spread_depth`: number of layers used in spreading; a max of `64 ^ spread_depth` number of
///    distinct directories can be created
/// 2. `path`: the path with which spread dirs will be created
fn path_to_spread(spread_depth: SpreadDepth, init_salt: &CryptoSecureBytes, path: &Path) -> CsyncResult<PathBuf> {
    debug_assert!(is_canonical(&path).unwrap());

    // 'spread dirs are the depth-n dirs created with sha512 in order to spread out the files
    // into different dirs
    match path_as_string(path) {
        // compute a pathsafe-base64-encoded hash of the pathbuf
        Some(s) => match base32path(sha512!(&s.into(), init_salt).0.unsecure()) {
            // get the first spreaod_depth chars of the hash, with '/' interopersed
            Ok(hash) => Ok(PathBuf::from(
                (&hash[..*spread_depth as usize]).chars().intersperse('/').collect::<String>(),
            )),
            Err(err) => panic!("base64 encoding failed: {}", err),
        },
        None => panic!("path has non unicode chars"),
    }
}

/// # Parameters
///
/// 1.
#[inline]
fn spread_to_hash(spread: &Path) -> CsyncResult<CryptoSecureBytes> {
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
fn path_to_cipherpath(
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
            let rand_bytes: Vec<_> = rng_seed!(&src_seed, 40, 200, u8::MIN, u8::MAX)
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

///
fn cipherpath_to_path(
    spread_depth: SpreadDepth,
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
            .take(*spread_depth as usize)
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
            .skip(*spread_depth as usize)
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
