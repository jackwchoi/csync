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
    fs::{create_dir_all, metadata, rename, File, Permissions},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

/// Conceptually a mapping from some path `src` to a different path `dest`.
///
/// `src` and `dest` are guarantede to be unique
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Action {
    pub dest: PathBuf,
    pub src: PathBuf,
    action_spec: ActionSpec,
    syncer_spec: SyncerSpec,
    file_type: FileType,
}

///
impl Action {
    /// # Parameters
    ///
    /// SALTS IN ENCRYPTION CONFIG WILL BE OVERWRTTEN
    pub fn new(
        syncer_spec: &SyncerSpec,
        src: &Path,
        dest: &Path,
        file_type: FileType,
        unix_mode_opt: Option<u32>,
        key_hash: &DerivedKey,
    ) -> CsyncResult<Action> {
        macro_rules! get_unix_mode {
            () => {
                Some(metadata(src)?.permissions().mode())
            };
        };

        macro_rules! action {
            ( $cipher_spec:expr, $unix_mode:expr, $key_hash:expr ) => {
                Ok(Action {
                    action_spec: ActionSpec::new(&$cipher_spec.resalt(), $unix_mode, $key_hash)?,
                    dest: dest.to_path_buf(),
                    file_type,
                    src: src.to_path_buf(),
                    syncer_spec: syncer_spec.clone(),
                })
            };
        };
        match syncer_spec {
            SyncerSpec::Encrypt { cipher_spec, .. } => action!(cipher_spec, unix_mode_opt.or(get_unix_mode!()), key_hash),
            SyncerSpec::Decrypt { cipher_spec, .. } => action!(cipher_spec, get_unix_mode!(), key_hash),
            SyncerSpec::Clean { .. } => todo!(),
        }
    }

    /// # Parameters
    ///
    /// 1. `arena`: some directory such that  `Action`
    pub fn manifest(self, arena: &Path, key_hash: &DerivedKey) -> CsyncResult<Self> {
        let action_arena = arena.join(format!("{}", thread_id::get()));
        create_dir_all(&action_arena)?;

        match &self.syncer_spec {
            SyncerSpec::Encrypt { .. } => self.encrypt(&action_arena, key_hash),
            SyncerSpec::Decrypt { .. } => self.decrypt(&action_arena, key_hash),
            _ => todo!(),
        }
    }

    ///
    fn encrypt(self, action_arena: &Path, key_hash: &DerivedKey) -> CsyncResult<Self> {
        let tmp_dest = action_arena.join("Action_encrypt");

        remove(&tmp_dest)?;
        {
            // use a macro to circumvent the type system
            macro_rules! csync {
                ( $get_src:expr ) => {
                    csync_encrypt(
                        &self.syncer_spec,
                        &self.action_spec,
                        action_arena,
                        $get_src,
                        &mut fopen_w(&tmp_dest)?,
                        key_hash,
                    )?
                };
            };
            match self.file_type {
                FileType::File => csync!(fopen_r(&self.src)?),
                FileType::Dir => {
                    let rand_bytes = rng!(MIN_DIR_RAND_DATA_LEN, MAX_DIR_RAND_DATA_LEN);
                    csync!(rand_bytes.0.unsecure())
                }
            };
        }

        // eqivalent to `mkdir --parents "$(dirname $dest)"`
        match self.dest.parent() {
            Some(parent) => create_dir_all(parent)?,
            None => (),
        };

        // swap
        rename(tmp_dest, &self.dest)?;

        Ok(self)
    }

    ///
    fn decrypt(self, action_arena: &Path, key_hash: &DerivedKey) -> CsyncResult<Self> {
        let tmp_dest = action_arena.join("Action_decrypt");

        remove(&tmp_dest)?;
        let (_, action_spec) = csync_decrypt(
            fopen_r(&self.src)?,
            match self.file_type {
                FileType::File => Some(fopen_w(&tmp_dest)?),
                FileType::Dir => None,
            },
            key_hash,
        )?;

        match self.dest.parent() {
            Some(parent) => create_dir_all(parent)?,
            None => (),
        };
        match self.file_type {
            FileType::File => (),
            FileType::Dir => create_dir_all(&tmp_dest)?,
        };

        // set permission bits of `tmp_dest`
        {
            let permission = Permissions::from_mode(action_spec.get_unix_mode().unwrap());
            File::open(&tmp_dest)?.set_permissions(permission)?;
        }

        match rename(&tmp_dest, &self.dest) {
            Ok(_) => Ok(self),
            Err(_) if self.file_type == FileType::Dir && self.dest.is_dir() => Ok(self),
            Err(err) => Err(err)?,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{specs::key_deriv_spec::*, test_util::*};
    use rayon::{iter::ParallelBridge, prelude::*};
    use ring::pbkdf2::PBKDF2_HMAC_SHA512;

    /*
    ///
    mod inverse {
        use super::*;
        use crate::util::*;
        use std::{fs::metadata, io::Write};

        ///
        fn tester(uid: usize, src: &Path) {
            let tmpd = tmpdir!().unwrap();
            let tmpd = tmpd.path();

            let arena1 = tmpdir!().unwrap();
            let arena2 = tmpdir!().unwrap();

            let enc_dest = tmpd.join(&format!("_{}_enc_", uid));
            let salt = rng!(DEFAULT_SALT_LEN);
            let init_key = sha512!(&b"7khgaLPeWyebxsICUav7hG9buGriE2Hc".to_vec().into(), &salt);
            let derived_key = DerivedKey(sha512!(&b"7khgaLPeWyebxsICUav7hG9buGriE2Hc".to_vec().into(), &salt));
            let file_type = match src.is_dir() {
                true => FileType::Dir,
                false => FileType::File,
            };
            let out_dir = tmpdir!().unwrap();
            let syncer_spec = spec_ext_to_int(&SyncerSpecExt::Encrypt {
                auth_opt: Some(Default::default()),
                cipher_opt: Some(Default::default()),
                compressor_opt: Some(Default::default()),
                kd_spec_ext_opt: Some(KeyDerivSpecExt::Pbkdf2 {
                    alg_opt: None,
                    num_iter_opt: Some(100),
                    time_opt: None,
                }),
                out_dir: out_dir.path().to_path_buf(),
                source: Path::new("src").to_path_buf(),
                spread_depth_opt: None,
                verbose: false,
            })
            .unwrap();
            // src => enc_dest
            Action::new(&syncer_spec, &src, &enc_dest, file_type, None, &derived_key)
                .unwrap()
                .manifest(arena1.path(), &derived_key)
                .unwrap();

            // enc_dest => dec_dest
            let dec_dest = tmpd.join(basename(&src).unwrap());
            Action::new(&syncer_spec, &enc_dest, &dec_dest, file_type, None, &derived_key)
                .unwrap()
                .manifest(arena2.path(), &derived_key)
                .unwrap();

            assert_tree_eq(&src, &dec_dest).unwrap();
        }

        ///
        #[test]
        fn empty_dir() {
            let tmpd = tmpdir!().unwrap();
            tester(0, tmpd.path());
        }

        ///
        #[test]
        fn empty_file() {
            let tmpf = tmpfile!().unwrap();
            tester(0, tmpf.path());
        }

        ///
        #[test]
        fn text_files() {
            ascii_files()
                .enumerate()
                .par_bridge()
                .filter(|(_, p)| p.is_file())
                .for_each(|(uid, pbuf)| tester(uid, &pbuf));
        }

        ///
        #[test]
        fn binary_files() {
            bin_files()
                .enumerate()
                .filter(|(_, p)| p.is_file())
                .filter(|(_, p)| match p.extension().map(&std::ffi::OsStr::to_str) {
                    Some(Some("o")) => true,
                    _ => false,
                })
                .take(64)
                .par_bridge()
                .for_each(|(uid, pbuf)| tester(uid, &pbuf));
        }

        ///
        #[test]
        fn binary_file_perm() {
            let arena = tmpdir!().unwrap();
            let arena = arena.path();

            (0o600..0o1000).par_bridge().for_each(|mode| {
                let src_path = arena.join(mode.to_string());
                {
                    let mut tmpf = fopen_w(&src_path).unwrap();
                    let hash = sha512!(&path_as_str(&src_path).unwrap().into());
                    tmpf.write_all(hash.0.unsecure()).unwrap();

                    let perm = Permissions::from_mode(mode);
                    tmpf.set_permissions(perm).unwrap();
                }

                tester(mode as usize, &src_path)
            });
        }
    }
    */
}
