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
            SyncerSpecExt::Clean { .. } => todo!(),
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
                        match Syncer::load_syncer_action_spec($metadata_par_dir) {
                            //
                            Ok((syncer_spec, action_spec)) => {
                                let hashed_key = Syncer::verify_syncer_spec(&syncer_spec, &action_spec, &init_key)?;
                                match spec_ext {
                                    //
                                    SyncerSpecExt::Encrypt { .. } => Syncer::with_spec(syncer_spec, init_key.clone()),
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
                                            )
                                        }
                                        _ => todo!(),
                                    },
                                    _ => todo!(),
                                }
                            }
                            Err(err) => csync_err!(MetadataLoadFailed, err.to_string()),
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
                SyncerSpecExt::Encrypt { out_dir, .. } if out_dir.is_file() => {
                    csync_err!(OutdirIsNotDir, out_dir.to_path_buf())
                }
                SyncerSpecExt::Encrypt {
                    source,
                    out_dir,
                    verbose,
                    ..
                } => {
                    create_dir_all(out_dir)?;
                    let spec = SyncerSpec::try_from(spec_ext)?;
                    Syncer::with_spec(spec, init_key)
                }
                SyncerSpecExt::Decrypt { .. } | SyncerSpecExt::Clean { .. } => todo!(),
            },
        }
    }

    ///
    fn with_spec_and_derived_key(spec: SyncerSpec, derived_key: DerivedKey) -> CsyncResult<Self> {
        todo!()
    }

    ///
    fn with_spec(spec: SyncerSpec, init_key: InitialKey) -> CsyncResult<Self> {
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
                        let (derived_key, _) =
                            time!(*verbose, "Generating a derived key", key_deriv_spec.derive(&init_key.0 .0)?);
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
        let result_opt = WalkDir::new(source)
            .follow_links(true)
            .into_iter()
            .filter_map(|entry| match entry.map(walkdir::DirEntry::into_path) {
                Ok(pbuf) => match pbuf.extension().map(OsStr::to_str) {
                    Some(Some("csync")) => match load_syncer_action_specs(&pbuf) {
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
                if read_dir(out_dir)?.count() > 0 {
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
        Aes256CbcEnc => (&CryptoSecureBytes(derived_key.0.0.clone()), Some(&spread_hash)),
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
        Aes256CbcDec => (&CryptoSecureBytes(derived_key.0.0.clone()), Some(&spread_hash))
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

/*
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{fs_util::*, test_util::*};
    use colmac::*;
    use std::fs::{remove_dir_all, File};

    // create an empty file
    macro_rules! file {
        ( $root:expr ) => {
            file_w!($root)
        };
        ( $root:expr, $( $path:expr ),* ) => {{
            let path = $root;
            $(
                let path = path.join($path);
            )*
            file_w!(path)
        }};
    }

    macro_rules! file_w {
    // create an empty file
        ( $path:expr ) => {{
            let path = $path;
            fopen_w(&path).unwrap();
            path
        }};
        ( $out_dir:expr, $file:expr, $( $content:expr ),* ) => {{
            let path = $out_dir.join($file);
            let file = fopen_w(&path).unwrap();
            $(
                file.write($content).unwrap();
            )*
            file.flush().unwrap();
            path
        }};
    }

    // create an empty directory
    macro_rules! dir {
        ( $root:expr ) => {{
            let path = $root;
            create_dir_all(&path).unwrap();
            path
        }};
        ( $root:expr, $( $path:expr ),* ) => {{
            let path = $root;
            $(
                let path = path.join($path);
            )*
            create_dir_all(&path).unwrap();
            path
        }};
    }

    ///
    fn realpaths() -> Vec<PathBuf> {
        ascii_files().chain(bin_files()).collect()
    }

    ///
    mod path_to_spread {
        use super::*;
        use std::collections::HashMap;
        use std::path::Component;

        /// 0 is an invalid spread depth, so it should panic
        #[test]
        fn spread_depth_invalid_0() {
            let paths = realpaths();
            paths.into_iter().for_each(|path| {
                match path_to_spread(SpreadDepth::new(0), &sha512!(&b"5e7UGBluD9Q8aQS".to_vec().into()), &path) {
                    Err(CsyncErr::InvalidSpreadDepth(_)) => (),
                    _ => panic!(),
                }
            });
        }

        /// try all spread depths in the range [1, 86] and make sure that
        /// 1. there are indeed that many layers
        /// 2. each layer contains only one char
        #[test]
        fn spread_depth_valid_range() {
            let paths = realpaths();

            (1..87).for_each(|count| {
                // the map
                let src_to_spread: Vec<(&Path, PathBuf)> = paths
                    .par_iter()
                    .map(|path| {
                        (
                            path.as_path(),
                            path_to_spread(SpreadDepth::new(count), &sha512!(&b"XDJ5rE3bNHUJD0IF".to_vec().into()), &path)
                                .unwrap(),
                        )
                    })
                    .collect();

                // check that all and only the original paths are included
                let srcs: HashSet<PathBuf> = src_to_spread.iter().map(|(p, _)| p.to_path_buf()).collect();
                assert_eq!(srcs, paths.iter().cloned().collect());

                // check to make sure that the spreads conform to the spec
                src_to_spread.into_par_iter().for_each(|(_, spread)| {
                    let spread_comps: Vec<_> = spread.as_path().components().collect();

                    // there should only be `count` number of comps
                    assert_eq!(spread_comps.len(), count as usize);

                    // no paths start from root
                    assert!(spread_comps.iter().all(|comp| match comp {
                        Component::Normal(os_str) => os_str.to_str().unwrap().chars().count() == 1,
                        _ => false,
                    }));
                });
            });
        }

        /// 87 is an invalid spread depth, so it should panic
        #[test]
        fn spread_depth_invalid_87() {
            let paths = realpaths();
            paths.into_iter().for_each(|path| {
                match path_to_spread(SpreadDepth::new(87), &sha512!(&b"ZhKcDMMlRsyK674z".to_vec().into()), &path) {
                    Err(CsyncErr::InvalidSpreadDepth(_)) => (),
                    _ => panic!(),
                }
            });
        }
    }

    ///
    mod spread_to_hash {
        use super::*;

        ///
        fn spreads_to_salts(spread_depth: u8, spreads: &Vec<PathBuf>) -> HashSet<SecureBytes> {
            spreads.par_iter().map(|spread| spread_to_hash(&spread).unwrap().0).collect()
        }

        ///
        fn _parametrized_by_spread_depth(spread_depth: u8) {
            let (spreads, spreads_without_slashes): (Vec<_>, Vec<_>) = realpaths()
                .into_par_iter()
                .map(|path| {
                    path_to_spread(SpreadDepth::new(spread_depth), &sha512!(&b"GRWvJY2E".to_vec().into()), &path).unwrap()
                })
                .map(|pb| {
                    (
                        pb.clone(),
                        PathBuf::from(path_as_string(&pb).unwrap().chars().filter(|c| c != &'/').collect::<String>()),
                    )
                })
                .unzip();

            // collect into set to check for collision
            let salts = spreads_to_salts(spread_depth, &spreads);
            let salts_without_slashes = spreads_to_salts(spread_depth, &spreads_without_slashes);

            // make sure that slashes are ignored when converting spreads to salts
            assert_eq!(salts_without_slashes, salts);
            // sanity check
            assert_eq!(salts.len(), salts_without_slashes.len());
        }

        ///
        #[test]
        fn parametrized_by_spread_depth() {
            vec![1, 5, 17, 23].into_par_iter().for_each(_parametrized_by_spread_depth);
        }
    }

    ///
    #[test]
    fn path_to_cipherpath_inverse_of_cipherpath_to_path() {
        let src_root = Path::new("src").canonicalize().unwrap();
        let init_salt = SecureVec::new([72u8; 16].to_vec());
        let derived_key = sha512!(&b"ZofHNXwplsOmmpcjbD2ABH9RA1fTVAZbot5qznnA3EwUFSQ2coY2PNyGFkWcqb16"
            .to_vec()
            .into());

        vec![1, 4, 8, 19, 62].into_iter().for_each(|spread_depth| {
            meta_map(&src_root)
                .map(Result::unwrap)
                .for_each(|(_, src_pbuf, _, _, file_type)| {
                    let src_rel_path = subpath(&src_pbuf, &src_root.parent().unwrap()).unwrap();
                    let spread = path_to_spread(SpreadDepth::new(spread_depth), &CryptoSecureBytes(init_salt), &src_pbuf).unwrap();
                    let spread_hash = spread_to_hash(&spread).unwrap();

                    let ciphertext = path_to_cipherpath(&src_root, &src_pbuf, file_type, &spread_hash, &derived_key).unwrap();
                    let cipherpath = src_root.join(spread).join(ciphertext);

                    let (decrypted, ret_file_type, ret_spread_hash) =
                        cipherpath_to_path(SpreadDepth::new(spread_depth), &src_root, &cipherpath, &derived_key).unwrap();

                    assert_eq!(ret_file_type, file_type);
                    assert_eq!(&decrypted, &src_rel_path);
                    assert_eq!(spread_hash, ret_spread_hash);
                });
        })
    }

    ///
    mod sync_enc_dry {
        use super::*;

        ///
        mod aes_zstd {
            use super::*;

            /// constructs a syncer, calls `sync_enc_dry` and returns the actions.
            ///
            /// checks the following about each sync actions:
            /// 1. the path `src` starts with `src_root_canon`
            /// 1. the path `dest` starts with `out_dir_canon`
            /// 1. `spread_hash` is 64-bytes long
            /// 1. `sync_mode` is `Encrypt`
            /// 1. `file_type` is `File` or `Dir`
            /// 1. `uid` is unique
            ///
            /// also checks that:
            /// 1. the returned set of actions is identical to `srcs_to_sync`
            fn tester(
                src_root: &Path,
                out_dir: &Path,
                srcs_to_sync: &Vec<PathBuf>,
                spread_depth: u8,
                key_bytes: &[u8],
            ) -> (Syncer, HashSet<Action>) {
                todo!()
                /*
                let (syncer, sync_actions): (_, HashSet<_>) = {
                    let init_key = sha512!(&key_bytes.to_vec().into());
                    let syncer = Syncer::new(
                        false,
                        Mode::Encrypt,
                        src_root,
                        out_dir,
                        Some(KeyDerivSpecExt::Pbkdf2 {
                            num_iter_opt: Some(1783),
                            time_opt: None,
                        }),
                        Some(spread_depth),
                        init_key,
                    )
                    .unwrap();
                    let actions = syncer.sync_enc_dry().unwrap().map(Result::unwrap).collect();

                    (syncer, actions)
                };
                let src_root_canon = src_root.canonicalize().unwrap();
                let out_dir_canon = out_dir.canonicalize().unwrap();
                let (srcs, uids): (HashSet<_>, HashSet<_>) = sync_actions
                    .par_iter()
                    .cloned()
                    .map(|action| {
                        assert!(action.src.starts_with(&src_root_canon));
                        assert!(action.dest.starts_with(&out_dir_canon));
                        assert_eq!(action.dest.extension(), Some(OsStr::new(FILE_SUFFIX)));
                        assert_eq!(action.sync_mode, Mode::Encrypt);
                        (action.src, action.uid)
                    })
                    .unzip();

                // make sure that all the source files are included
                assert_eq!(uids.len(), srcs.len());
                assert_eq!(&srcs_to_sync.iter().cloned().collect::<HashSet<_>>(), &srcs);
                (syncer, sync_actions)
                */
            }

            ///
            #[test]
            fn short_names_no_filename_conflict() {
                let src_root = tmpdir!().unwrap();
                let src_root_canon = src_root.path().canonicalize().unwrap();

                let out_dir = tmpdir!().unwrap();

                let key_bytes = b"ydrCw13cvrlqquEUt6cSjaCRiTOuXUqC755o50ajcGeKLma1cn40NqOvevWIem6Y";
                let spread_depth = 25;

                // source files to be synced
                let srcs_to_sync = vec![
                    src_root_canon.clone(),
                    dir!(&src_root_canon, "d1"),
                    dir!(&src_root_canon, "d2"),
                    dir!(&src_root_canon, "d3"),
                    file!(&src_root_canon, "f4"),
                    file!(&src_root_canon, "f5"),
                    file!(&src_root_canon, "f6"),
                ];

                let (_, actions) = tester(&src_root_canon, &out_dir.path(), &srcs_to_sync, spread_depth, key_bytes);
                assert_eq!(actions.len(), 7);
            }

            ///
            #[test]
            fn empty_dir() {
                let src_root = tmpdir!().unwrap();
                let src_root_canon = src_root.path().canonicalize().unwrap();

                let out_dir = tmpdir!().unwrap();

                let key_bytes = b"KfjqzG5RuLuB1nTE0yENKcDXjx1BNBPkLgsl48EsWyt0Qz5P9WQo4qV3WDw0P2Np";
                let spread_depth = 42;

                // source files to be synced
                let srcs_to_sync = vec![src_root_canon.clone(), dir!(&src_root_canon, "d1")];

                let (_, actions) = tester(&src_root_canon, &out_dir.path(), &srcs_to_sync, spread_depth, key_bytes);
                assert_eq!(actions.len(), 2);
            }

            ///
            #[test]
            fn long_names_filename_conflicts() {
                let src_root = tmpdir!().unwrap();
                let src_root_canon = src_root.path().canonicalize().unwrap();

                let out_dir = tmpdir!().unwrap();

                let key_bytes = b"KfjqzG5RuLuB1nTE0yENKcDXjx1BNBPkLgsl48EsWyt0Qz5P9WQo4qV3WDw0P2Np";
                let spread_depth = 42;

                // source files to be synced
                let srcs_to_sync = vec![
                    src_root_canon.clone(),
                    dir!(&src_root_canon, "d1"),
                    dir!(&src_root_canon, "d2"),
                    dir!(&src_root_canon, "d3"),
                    file!(
                        &src_root_canon,
                        "d1",
                        "muF9juYPv0eeiAGaVZboVE5SEk0XTVc5tkIVXjm0vKj7wMchQwbVc5DzHgFYuWO27xSEpJv9"
                    ),
                    file!(
                        &src_root_canon,
                        "d2",
                        "muF9juYPv0eeiAGaVZboVE5SEk0XTVc5tkIVXjm0vKj7wMchQwbVc5DzHgFYuWO27xSEpJv9"
                    ),
                    file!(
                        &src_root_canon,
                        "d3",
                        "muF9juYPv0eeiAGaVZboVE5SEk0XTVc5tkIVXjm0vKj7wMchQwbVc5DzHgFYuWO27xSEpJv9"
                    ),
                ];

                let (_, actions) = tester(&src_root_canon, &out_dir.path(), &srcs_to_sync, spread_depth, key_bytes);
                assert_eq!(actions.len(), 7);
            }

            ///
            #[test]
            fn short_names_no_filename_conflict_modified() {
                let src_root = tmpdir!().unwrap();
                let src_root_canon = src_root.path().canonicalize().unwrap();

                let out_dir = tmpdir!().unwrap();

                let key_bytes = b"Q6ocC0SuMlRtRcm8e2IfulI5ZCcLezune6md9yjTFLBnjUDNTTt9z2w6od8KQdg9";
                let derived_key = sha512!(&key_bytes.to_vec().into());
                let spread_depth = 4;

                // source files to be synced
                let srcs_to_sync = vec![
                    src_root_canon.clone(),
                    dir!(&src_root_canon, "d1"),
                    file!(&src_root_canon, "f2"),
                    file!(&src_root_canon, "f3"),
                    file!(&src_root_canon, "f4"),
                ];

                // initial syncing results
                let (syncer, actions) = tester(&src_root_canon, &out_dir.path(), &srcs_to_sync, spread_depth, key_bytes);
                assert_eq!(actions.len(), 5);

                // make sure that if the encrypted files have modified times after that of the src
                // files, it is excluded from the sync actions
                let filepaths: Vec<_> = srcs_to_sync.iter().cloned().filter(|p| p.is_file()).collect();
                assert_eq!(filepaths.len(), 3);

                (0..3).fold(vec![], |mut acc, i| {
                    let filepath = filepaths.get(i).unwrap();
                    let to_mod = actions.iter().filter(|x| &x.src == filepath).nth(0).unwrap();
                    // create the file and its par dirs

                    dir!(&to_mod.dest.parent().unwrap());
                    file!(&to_mod.dest);

                    let new_actions: Vec<_> = syncer.sync_enc_dry().unwrap().collect();

                    assert_eq!(new_actions.len(), actions.len() - i - 1);

                    acc.push(filepath);
                    acc
                });
            }
        }
    }

    ///
    #[test]
    fn load() {
        let spread_depths = vec![1, 3, 5, 9, 17];
        let init_salts: HashSet<_> = spread_depths
            .par_iter()
            .cloned()
            .map(|spread_depth| {
                let src_root_canon = Path::new("src/").canonicalize().unwrap();
                assert!(src_root_canon.exists());

                let out_dir = tmpdir!().unwrap();
                let out_dir_canon = out_dir.path().canonicalize().unwrap();

                let init_key = sha512!(&b"WO5ZVq9BSKiSWvLBaR1hjlj7WXXeFoVAEbmSbwGKfdNOpvz0WzLy8eZbn7oAsS6o"
                    .to_vec()
                    .into());

                todo!()
                /*
                let expected = {
                    let syncer = Syncer::new(
                        false,
                        Mode::Encrypt,
                        &src_root_canon,
                        &out_dir_canon,
                        Some(KeyDerivSpecExt::Pbkdf2 {
                            num_iter_opt: Some(8124),
                            time_opt: None,
                        }),
                        Some(spread_depth),
                        init_key.clone(),
                    )
                    .unwrap();

                    let _: Vec<_> = syncer.sync_enc(false).unwrap().map(Result::unwrap).collect();
                    syncer.syncer_config
                };

                let result = Syncer::load(false, &out_dir_canon, &init_key).unwrap();

                assert_eq!(result, expected);
                expected.init_salt
                */
            })
            .collect();

        assert_eq!(init_salts.len(), spread_depths.len());
    }

    ///
    mod sync_enc {
        use super::*;

        ///
        #[test]
        fn same_key_unique_paths() {
            let src_root_canon = Path::new("src/").canonicalize().unwrap();

            let out_dir_1 = tmpdir!().unwrap();
            let out_dir_2 = tmpdir!().unwrap();

            let derived_key = sha512!(&b"PoU4PO2s8iDQlywUHbP9jdz0bnpw4j06Essdu6nRaM9bodfaMqyqjUv3vYS7Ak8W"
                .to_vec()
                .into());
            let spread_depth = 13;

            todo!()
            /*
            let file_sets: Vec<_> = vec![&out_dir_1.path(), &out_dir_2.path()]
                .into_par_iter()
                .map(|out_dir_canon| {
                    let _: Vec<_> = Syncer::new(
                        false,
                        Mode::Encrypt,
                        &src_root_canon,
                        out_dir_canon,
                        Some(KeyDerivSpecExt::Pbkdf2 {
                            num_iter_opt: Some(8124),
                            time_opt: None,
                        }),
                        Some(spread_depth),
                        derived_key.clone(),
                    )
                    .unwrap()
                    .sync_enc(false)
                    .unwrap()
                    .map(Result::unwrap)
                    .collect();
                    out_dir_canon
                })
                .map(|out_dir_canon| {
                    // relative paths, only files
                    find(out_dir_canon)
                        .map(Result::unwrap)
                        .filter(|pbuf| !pbuf.ends_with(out_dir_canon))
                        .filter(|pbuf| pbuf.is_file())
                        .map(|pbuf| subpath(&pbuf, out_dir_canon))
                        .map(Option::unwrap)
                        .collect::<HashSet<_>>()
                })
                .collect();

            assert_eq!(file_sets.len(), 2);
            assert!(file_sets.iter().all(|set| !set.contains(Path::new(""))));

            let file_sets_cleaned: Vec<_> = file_sets
                .into_iter()
                .map(|mut set| {
                    set.remove(Path::new(""));
                    set
                })
                .collect();

            let set1 = file_sets_cleaned.get(0).unwrap();
            let set2 = file_sets_cleaned.get(1).unwrap();

            assert!(set1.is_disjoint(set2));
            */
        }
    }

    macro_rules! dec_boiler {
        ( $src_root:expr ) => {{
            let src_root = Path::new($src_root).canonicalize().unwrap();
            let out_dir = tmpdir!().unwrap();
            let out_out_dir = tmpdir!().unwrap();
            dec_boiler!(impl src_root, out_dir, out_out_dir)
        }};
        ( $src_root:expr, $out_dir:expr ) => {{
            let src_root = Path::new($src_root).canonicalize().unwrap();
            let out_out_dir = tmpdir!().unwrap();
            dec_boiler!(impl src_root, $out_dir, out_out_dir)
        }};
        ( $src_root:expr, $out_dir:expr, $out_out_dir:expr ) => {{
            let src_root = Path::new($src_root).canonicalize().unwrap();
            dec_boiler!(impl src_root, $out_dir, $out_out_dir)
        }};
        ( impl $src_root:expr, $out_dir:expr, $out_out_dir:expr ) => {{
            let src_root = $src_root;
            let out_dir = $out_dir;
            let out_out_dir = $out_out_dir;
            let derived_key = sha512!(&path_as_string(&src_root).unwrap().to_string().into());
            let spread_depth = 7;

            todo!()
            /*
            let enc_syncer = Syncer::new(
                false,
                Mode::Encrypt,
                &src_root,
                out_dir.path(),
                Some(KeyDerivSpecExt::Pbkdf2 {
                    num_iter_opt: Some(1792u32),
                    time_opt: None,
                }),
                Some(spread_depth),
                derived_key.clone(),
            )
            .unwrap();
            let enc_actions: Vec<(Action, Duration)> = enc_syncer.sync_enc(false)?.map(Result::unwrap).collect();

            let dec_syncer = Syncer::new(
                false,
                Mode::Decrypt,
                out_dir.path(),
                out_out_dir.path(),
                None,
                None,
                derived_key,
            )?;

            assert_eq!(dec_syncer.syncer_config, enc_syncer.syncer_config);
            assert_eq!(dec_syncer.src_root, enc_syncer.out_dir);

            CsyncResult::Ok((
                src_root,
                out_dir,
                out_out_dir,
                spread_depth,
                enc_syncer,
                dec_syncer,
                enc_actions,
            ))
            */
        }};
    }

    ///
    mod sync_dec_dry {
        use super::*;

        ///
        macro_rules! testgen {
            ( $mod_name:ident, $src_root:literal ) => {
                mod $mod_name {
                    use super::*;

                    ///
                    #[test]
                    fn panics_if_decrypting_with_nonempty_out_dir() -> CsyncResult<()> {
                        todo!()
                        /*
                        let out_out_dir = tmpdir!().unwrap();
                        let fpath = out_out_dir.path().join(".tmpfile");
                        {
                            fopen_w(&fpath).unwrap();
                        }
                        let wrapper = || dec_boiler!($src_root, tmpdir!().unwrap(), out_out_dir);
                        match wrapper() {
                            Err(CsyncErr::DecryptionOutdirIsNonempty(_)) => Ok(()),
                            _ => panic!(),
                        }
                        */
                    }

                    ///
                    #[test]
                    fn inverse_of_sync_enc() -> CsyncResult<()> {
                        todo!()
                        /*
                        dbg!("before");
                        let (src_root, out_dir, out_out_dir, _, _, dec_syncer, enc_actions) = dec_boiler!($src_root).unwrap();
                        dbg!("after");
                        let dec_actions: Vec<_> = dec_syncer.sync_dec(false).unwrap().map(Result::unwrap).collect();

                        let out_dir_path = out_dir.path().canonicalize().unwrap();
                        let out_out_dir_path = out_out_dir.path().canonicalize().unwrap();

                        // checks about the src and dsts
                        {
                            let enc_map: HashMap<_, _> = enc_actions
                                .iter()
                                .cloned()
                                .map(|(x, _)| (x.src, x.dest))
                                .collect();
                            let dec_map: HashMap<_, _> = dec_actions
                                .iter()
                                .cloned()
                                .map(|(x, _)| (x.src, x.dest))
                                .collect();
                            assert_eq!(enc_map.len(), dec_map.len());

                            assert!(enc_map.keys().all(|src| src.starts_with(&src_root)));
                            assert!(enc_map.values().all(|dst| dst.starts_with(&out_dir_path)));

                            assert!(dec_map.keys().all(|src| src.starts_with(&out_dir_path)));
                            assert!(dec_map.values().all(|dst| dst.starts_with(&out_out_dir_path)));

                            assert_eq!(
                                enc_map.values().collect::<HashSet<_>>(),
                                dec_map.keys().collect::<HashSet<_>>()
                            );

                            enc_map.into_par_iter().for_each(|(src, dst)| {
                                let cleaned_enc_src = subpath_par(&src, &src_root).unwrap();

                                let dec_dst = dec_map.get(&dst).unwrap();
                                let cleaned_dec_dst = subpath(&dec_dst, &out_out_dir_path).unwrap();

                                assert_eq!(cleaned_enc_src, cleaned_dec_dst);
                            });
                        }
                        Ok(())
                        */
                    }
                }
            };
        }

        testgen!(src, "src");

        testgen!(src_main_rs, "src/main.rs");

        testgen!(stress_target_debug_build, "target/debug/build");
    }

    // TODO check that incremental encryption works
    // TODO check metadata contamination
}
*/
