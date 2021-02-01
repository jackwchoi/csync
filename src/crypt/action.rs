use crate::{
    crypt::util::*,
    fs_util::*,
    prelude::*,
    primitives::*,
    secure_vec::*,
    specs::{action_spec::*, syncer_spec::*},
    util::hash_file,
};
use std::{
    fmt::Debug,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

/// Conceptually a mapping from some path `src` to a different path `dest`.
///
/// `src` and `dest` are guarantede to be unique
#[derive(Clone, Debug)]
pub enum Action<'a> {
    Encode {
        dest: PathBuf,
        src: PathBuf,
        action_spec: ActionSpec,
        syncer_spec: &'a SyncerSpec,
        file_type: FileType,
        src_hash: CryptoSecureBytes,
    },
    Delete {
        path: PathBuf,
        file_type: FileType,
        file_size: usize,
    },
}

///
impl<'a> Action<'a> {
    /// # Parameters
    ///
    /// SALTS IN ENCRYPTION CONFIG WILL BE OVERWRTTEN
    pub fn new(
        syncer_spec: &'a SyncerSpec,
        salt_len: u16,
        src: &Path,
        dest: &Path,
        file_type: FileType,
        unix_mode_opt: Option<u32>,
        key_hash: &DerivedKey,
    ) -> CsyncResult<Action<'a>> {
        macro_rules! get_unix_mode {
            () => {
                Some(std::fs::metadata(src)?.permissions().mode())
            };
        };

        macro_rules! action {
            ( $cipher_spec:expr, $unix_mode:expr, $key_hash:expr ) => {
                Ok(Action::Encode {
                    action_spec: ActionSpec::new(&$cipher_spec.resalt(salt_len), salt_len, $unix_mode, $key_hash)?,
                    dest: dest.to_path_buf(),
                    file_type,
                    src: src.to_path_buf(),
                    syncer_spec,
                    src_hash: hash_file(&src, &key_hash.0)?,
                })
            };
        };
        match syncer_spec {
            SyncerSpec::Encrypt { cipher_spec, .. } => action!(cipher_spec, unix_mode_opt.or(get_unix_mode!()), key_hash),
            SyncerSpec::Decrypt { cipher_spec, .. } => action!(cipher_spec, unix_mode_opt.or(get_unix_mode!()), key_hash),
            SyncerSpec::Clean { .. } => todo!(),
        }
    }

    // # Returns
    //
    // 1. `Ok(Some(true))` if `dest` is out of date, and this manifest is necessary
    // 1. `Ok(Some(false)` if `dest` in NOT out of date, and this manifest is unnecessary
    // 1. `Ok(None)` if the concept of `out of date` does not apply and the result of this function
    //    should be ignored
    // 1. `Err(_)` if any error occurs
    pub fn out_of_date(&self) -> CsyncResult<Option<bool>> {
        // TODO do hash based checks
        // TODO bake this into csync_*crypt somehow?
        Ok(match self {
            Action::Encode {
                dest,
                syncer_spec,
                src_hash,
                ..
            } => match syncer_spec {
                SyncerSpec::Encrypt { .. } => match dest.exists() {
                    true => {
                        // TODO cache this so we only compute hash of src once
                        let dest_hash = load_meta(&dest)?;
                        Some(dest_hash != src_hash.0)
                    }
                    false => Some(true),
                },
                SyncerSpec::Decrypt { .. } => None,
                SyncerSpec::Clean { .. } => None,
            },
            Action::Delete { .. } => None,
        })
    }

    /// # Parameters
    ///
    /// 1. `arena`: some directory such that  `Action`
    pub fn manifest(self, arena: &Path, key_hash: &DerivedKey) -> CsyncResult<Self> {
        //
        let tid = thread_id::get().to_string();
        let action_arena = arena.join(tid);

        //
        create_dir_all_if_nexists(&action_arena)?;

        //for i in 0..RETRY_NUM as usize {
        //}
        let run = |action| match &action {
            Action::Encode { syncer_spec, .. } => match syncer_spec {
                SyncerSpec::Encrypt { .. } => action.encrypt(&action_arena, key_hash),
                SyncerSpec::Decrypt { .. } => action.decrypt(&action_arena, key_hash),
                _ => todo!(),
            },
            Action::Delete { path, .. } => match std::fs::remove_file(path) {
                Ok(_) => Ok(action),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(action),
                Err(err) => Err(err)?,
            },
        };

        let init_val = run(self.clone());
        (0..RETRY_NUM - 1).fold(init_val, |acc, _| match acc {
            Ok(_) => acc,
            Err(_) => run(self.clone()),
        })
    }

    ///
    fn encrypt(self, action_arena: &Path, key_hash: &DerivedKey) -> CsyncResult<Self> {
        let tmp_dest = action_arena.join("Action_encrypt");

        match &self {
            Action::Encode {
                dest,
                file_type,
                src,
                syncer_spec,
                action_spec,
                src_hash,
                ..
            } => {
                remove(&tmp_dest)?;
                {
                    // use a macro to circumvent the type system
                    macro_rules! csync {
                        ( $get_src:expr ) => {
                            csync_encrypt(
                                &syncer_spec,
                                &action_spec,
                                action_arena,
                                $get_src,
                                &mut fopen_w(&tmp_dest)?,
                                key_hash,
                                &src_hash.0,
                            )?
                        };
                    };
                    match file_type {
                        FileType::File => csync!(fopen_r(&src)?),
                        FileType::Dir => {
                            let rand_bytes = rng!(MIN_DIR_RAND_DATA_LEN, MAX_DIR_RAND_DATA_LEN);
                            csync!(rand_bytes.0.unsecure())
                        }
                    };
                }

                // eqivalent to `mkdir --parents "$(dirname $dest)"`
                match dest.parent() {
                    Some(parent) => create_dir_all_if_nexists(parent)?,
                    None => (),
                };

                // swap
                std::fs::rename(tmp_dest, &dest)?;

                Ok(self)
            }
            Action::Delete { .. } => todo!(),
        }
    }

    ///
    fn decrypt(self, action_arena: &Path, key_hash: &DerivedKey) -> CsyncResult<Self> {
        let tmp_dest = action_arena.join("Action_decrypt");

        match &self {
            Action::Encode {
                dest, file_type, src, ..
            } => {
                remove(&tmp_dest)?;
                let (_, action_spec) = csync_decrypt(
                    fopen_r(&src)?,
                    match file_type {
                        FileType::File => Some(fopen_w(&tmp_dest)?),
                        FileType::Dir => None,
                    },
                    key_hash,
                )?;

                match dest.parent() {
                    Some(parent) => create_dir_all_if_nexists(parent)?,
                    None => (),
                };
                match file_type {
                    FileType::File => (),
                    FileType::Dir => create_dir_all_if_nexists(&tmp_dest)?,
                };

                // set permission bits of `tmp_dest`
                {
                    let permission = std::fs::Permissions::from_mode(action_spec.get_unix_mode().unwrap());
                    std::fs::File::open(&tmp_dest)?.set_permissions(permission)?;
                }

                match std::fs::rename(&tmp_dest, &dest) {
                    Ok(_) => Ok(self),
                    Err(_) if *file_type == FileType::Dir && dest.is_dir() => Ok(self),
                    Err(err) => Err(err)?,
                }
            }
            Action::Delete { .. } => todo!(),
        }
    }
}

fn create_dir_all_if_nexists<P>(path: P) -> std::io::Result<()>
where
    P: AsRef<Path>,
{
    match path.as_ref().exists() {
        true => Ok(()),
        false => std::fs::create_dir_all(&path),
    }
}
