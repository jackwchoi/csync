use crate::{
    crypt::util::*,
    fs_util::*,
    prelude::*,
    primitives::*,
    secure_vec::*,
    specs::{action_spec::*, syncer_spec::*},
};
use std::{
    fmt::Debug,
    fs::{metadata, rename, File, Permissions},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

/// Conceptually a mapping from some path `src` to a different path `dest`.
///
/// `src` and `dest` are guarantede to be unique
#[derive(Debug)]
pub enum Action<'a> {
    Encode {
        dest: PathBuf,
        src: PathBuf,
        action_spec: ActionSpec,
        syncer_spec: &'a SyncerSpec,
        file_type: FileType,
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
                Some(metadata(src)?.permissions().mode())
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
                })
            };
        };
        match syncer_spec {
            SyncerSpec::Encrypt { cipher_spec, .. } => action!(cipher_spec, unix_mode_opt.or(get_unix_mode!()), key_hash),
            SyncerSpec::Decrypt { cipher_spec, .. } => action!(cipher_spec, unix_mode_opt.or(get_unix_mode!()), key_hash),
            SyncerSpec::Clean { .. } => todo!(),
        }
    }

    fn out_of_date(&self) -> Option<bool> {
        // TODO do hash based checks
        // TODO bake this into csync_*crypt somehow?
        match self {
            Action::Encode {
                src, dest, syncer_spec, ..
            } => match syncer_spec {
                SyncerSpec::Encrypt { .. } => {
                    todo!();
                    todo!()
                }
                SyncerSpec::Decrypt { .. } => None,
                SyncerSpec::Clean { .. } => None,
            },
            Action::Delete { .. } => None,
        }
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

        macro_rules! rm {
            ( $code:expr ) => {
                match $code {
                    Ok(_) => Ok(self),
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(self),
                    Err(err) => Err(err)?,
                }
            };
        }

        match &self {
            Action::Encode { syncer_spec, .. } => match syncer_spec {
                SyncerSpec::Encrypt { .. } => self.encrypt(&action_arena, key_hash),
                SyncerSpec::Decrypt { .. } => self.decrypt(&action_arena, key_hash),
                _ => todo!(),
            },
            Action::Delete { path, .. } => match std::fs::remove_file(path) {
                Ok(_) => Ok(self),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(self),
                Err(err) => Err(err)?,
            },
        }
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
                rename(tmp_dest, &dest)?;

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
                dest,
                file_type,
                src,
                syncer_spec,
                action_spec,
                ..
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
                    let permission = Permissions::from_mode(action_spec.get_unix_mode().unwrap());
                    File::open(&tmp_dest)?.set_permissions(permission)?;
                }

                match rename(&tmp_dest, &dest) {
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
