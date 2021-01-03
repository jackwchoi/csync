mod util;

/// TODO
///
/// 1. syncing to a non-empty dir
///     1. if encrypting, collect to hashset and check for differences
///     1. if decrypting, force the dir to be non empty
/// 1. if using metadata that is recovered, make sure that passwords match
use crate::{
    crypt::{action::*, syncer::util::*},
    fs_util::*,
    prelude::*,
    secure_vec::*,
    specs::prelude::*,
};
use rayon::prelude::*;
use std::ffi::OsStr;
use std::{convert::TryFrom, io, os::unix::fs::PermissionsExt, path::Path};
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
    /// # Returns
    ///
    /// The specificatino of this syncer.
    #[inline]
    pub fn get_spec(&self) -> SyncerSpec {
        self.spec.clone()
    }

    /// # Parameters
    ///
    /// # Returns
    ///
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

    // init from an existing csync dir by loading the metadata
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
                            SyncerSpecExt::Encrypt { .. } => {
                                Syncer::with_spec(syncer_spec, init_key.clone(), Some(derived_key))
                            }
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
                                    salt_len,
                                    ..
                                } => {
                                    std::fs::create_dir_all($out_dir)?;
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
                                            salt_len,
                                        },
                                        init_key.clone(),
                                        Some(derived_key),
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

    // # Parameters
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
                SyncerSpecExt::Encrypt { out_dir, .. } => {
                    // if from_dir failed, outdir must either be empty or non-existent
                    match (out_dir.exists(), out_dir.is_dir()) {
                        (false, _) => (),
                        (true, true) => match std::fs::read_dir(out_dir).map(Iterator::count)? {
                            0 => (),
                            _ => csync_err!(IncrementalEncryptionDisabledForNow)?,
                        },
                        (true, false) => csync_err!(OutdirIsNotDir, out_dir.to_path_buf())?,
                    }

                    std::fs::create_dir_all(out_dir)?;
                    let spec = SyncerSpec::try_from(spec_ext)?;
                    Syncer::with_spec(spec, init_key, None)
                }
                SyncerSpecExt::Decrypt { .. } | SyncerSpecExt::Clean { .. } => todo!(),
            },
        }
    }

    //
    fn with_spec(spec: SyncerSpec, init_key: InitialKey, derived_key_opt: Option<DerivedKey>) -> CsyncResult<Self> {
        eprint!("{}", report_syncer_spec(&spec));
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
                // std::fs::create_dir_all(&out_dir)?;
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

    // Load metadata from an existing `csync` directory.
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

    /// 1. for the root cfile,
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
                salt_len,
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
                                    *salt_len,
                                    &src_pbuf.to_path_buf(),
                                    $dest,
                                    file_type,
                                    Some(perms.mode()),
                                    &self.derived_key,
                                ))
                            };
                        };

                        match std::fs::metadata(&cipherpath) {
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
                salt_len,
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
                    .map(move |(_, entry_res)| -> CsyncResult<Action> {
                        let cipherpath = entry_res?.path().canonicalize()?;
                        debug_assert!(is_canonical(&cipherpath).unwrap());
                        let (path, file_type, _) = cipherpath_to_path(*spread_depth, source, &cipherpath, &self.derived_key)?;
                        Action::new(
                            &self.spec,
                            *salt_len,
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

    // Miscellaneous checks.
    #[inline]
    fn check_rep(&self) {}
}
