/// instead of `map_err(io_err)`, create custom err enum that looks something like enum { ty: TYPE,
/// message: String }
use crate::{
    encoder::{aes::*, crypt_encoder::*, hash::*, identity::*, zstd::*},
    fs_util::*,
    util::*,
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{create_dir_all, rename, File, Permissions},
    io::{self, BufRead, Read, Seek, SeekFrom, Write},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    str::from_utf8,
};

macro_rules! sha_aes_sha {
    ( $src:expr, $key_hash:expr ) => {
        sha_aes_sha!(impl $src, None, $key_hash)
    };
    ( $src:expr, $salt:expr, $key_hash:expr ) => {
        sha_aes_sha!(impl $src, Some($salt), $key_hash)
    };
    ( impl $src:expr, $salt_opt:expr, $key_hash:expr ) => {
        compose_encoders!(
            $src,
            HashEncoder => None,
            EncryptorAES => ($key_hash, $salt_opt),
            HashEncoder => None
        )
    };
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum Cipher {
    AES,
    // TODO ChaCha
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum Compressor {
    ZSTD,
    // TODO GZIP
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum Mode {
    DECRYPT,
    ENCRYPT,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum FileType {
    DIR,
    FILE,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct UnixMetadata {
    pub mode: Option<u32>,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct Action {
    pub src: PathBuf,
    pub dest: PathBuf,
    //
    pub file_type: FileType,
    pub metadata: UnixMetadata,
    pub spread_hash: Vec<u8>,
    pub sync_mode: Mode,
    pub uid: usize,
}

const MIN_PAD_LEN: u64 = 1;
const MAX_PAD_LEN: u64 = 1 << 11;
const PAD_DELIMITER: u8 = 0;

const MIN_DIR_RAND_DATA_LEN: u64 = 1 << 4;
const MAX_DIR_RAND_DATA_LEN: u64 = 1 << 10;

const_assert!(MAX_PAD_LEN == 2048);
const_assert!(MIN_DIR_RAND_DATA_LEN == 16);
const_assert!(MAX_DIR_RAND_DATA_LEN == 1024);

impl Action {
    /// # Parameters
    ///
    /// 1. `arena`: path to some dir such that  such that

    pub fn new(
        src: &Path,
        dest: &Path,
        file_type: FileType,
        metadata: &UnixMetadata,
        spread_hash: &[u8],
        sync_mode: Mode,
        uid: usize,
    ) -> Self {
        debug_assert!(match sync_mode {
            Mode::ENCRYPT => metadata.mode.is_some(),
            Mode::DECRYPT => metadata.mode.is_none(),
        });

        Action {
            src: src.to_path_buf(),
            dest: dest.to_path_buf(),
            file_type,
            metadata: metadata.clone(),
            spread_hash: Vec::from(spread_hash),
            sync_mode,
            uid,
        }
    }

    #[inline]
    pub fn manifest(self, arena: &Path, key_hash: &[u8]) -> io::Result<Self> {
        match self.sync_mode {
            Mode::ENCRYPT => self.encrypt(arena, key_hash),
            Mode::DECRYPT => self.decrypt(arena, key_hash),
        }
    }

    fn encrypt(self, arena: &Path, key_hash: &[u8]) -> io::Result<Self> {
        debug_assert_eq!(self.sync_mode, Mode::ENCRYPT);
        let tmp_dest = arena.join(format!("_encrypt_{}_1", self.uid));

        {
            let metadata_data = serde_json::to_string(&self.metadata).map_err(io_err)?;

            // use a macro to circumvent the type system
            macro_rules! csync {
                ( $get_src:expr ) => {
                    csync_encrypt(
                        arena,
                        $get_src,
                        &mut fopen_w(&tmp_dest)?,
                        self.uid,
                        metadata_data.as_bytes(),
                        &self.spread_hash,
                        key_hash,
                    )?
                };
            };
            match self.file_type {
                FileType::FILE => csync!(|| fopen_r(&self.src)),
                FileType::DIR => {
                    let rand_bytes = rng!(MIN_DIR_RAND_DATA_LEN, MAX_DIR_RAND_DATA_LEN);
                    csync!(|| io::Result::Ok(&rand_bytes[..]))
                }
            };
        }

        // eqivalent to `mkdir --parents "$(dirname $dest)"`
        match self.dest.parent() {
            Some(parent) => create_dir_all(parent)?,
            None => (),
        };
        // swap
        rename(tmp_dest, &self.dest).unwrap();

        Ok(self)
    }

    fn decrypt(self, arena: &Path, key_hash: &[u8]) -> io::Result<Self> {
        debug_assert_eq!(self.sync_mode, Mode::DECRYPT);
        let tmp_dest = arena.join(format!("_decrypt_{}_1", self.uid));

        let metadata_bytes = csync_decrypt(
            arena,
            self.file_type,
            || fopen_r(&self.src),
            match self.file_type {
                FileType::FILE => Some(fopen_w(&tmp_dest)?),
                FileType::DIR => None,
            },
            self.uid,
            &self.spread_hash,
            key_hash,
        )?;
        let metadata: UnixMetadata = match from_utf8(&metadata_bytes[..]).map(String::from) {
            Ok(json) => serde_json::from_str(&json).map_err(io_err)?,
            Err(_) => panic!("metadata recovery failed"),
        };
        //   Ok(serde_json::from_str(&json_string)?);

        match self.file_type {
            FileType::FILE => match self.dest.parent() {
                Some(parent) => create_dir_all(parent)?,
                None => (),
            },
            FileType::DIR => create_dir_all(&tmp_dest)?,
        };

        // set permission bits of `tmp_dest`
        {
            let permission = Permissions::from_mode(metadata.mode.unwrap());
            File::open(&tmp_dest)?.set_permissions(permission)?;
        }

        rename(&tmp_dest, &self.dest)?;

        Ok(self)
    }
}

/// Encrypt data into a custom format, decryptable using `csync_decrypt`.
///
/// # Format of the resulting file
///
/// The custom format has three distinct parts, `d1`, `d2` and `d3`, in order.
/// 1. `d1` is the first byte of the resulting data, used to indicate
/// 2. `d2`
/// 3. `d3`
///
/// # Parameters
///
/// 1. `tmpdir`: path to some directory such that no files in it have basenames prefixed with `uid`
///    followed by an underscore (`_`). For example if the `uid` is `5`, no files in `tmpdir` has
///    basenames starting with `5_`
/// 1. `file_type`:
/// 1. `src`:
/// 1. `uid`:
/// 1. `dest`:
/// 1. `salt`:
/// 1. `key_hash`:
///
/// # Returns
///
/// `Ok(())` if successful, `Err(_)` otherwise.
fn csync_encrypt<FR, R, W>(
    arena: &Path,
    get_src: FR,
    mut dest: &mut W,
    uid: usize,
    metadata: &[u8],
    salt: &[u8],
    key_hash: &[u8],
) -> io::Result<()>
where
    FR: Fn() -> io::Result<R>,
    R: Read,
    W: Write,
{
    debug_assert!(metadata.len() < std::u32::MAX as usize);
    // let tmp_dest = arena.join(&format!("_{}_csync_encrypt_1", uid));

    // step 1; pad the beginning with random bytes
    let rand_padding: Vec<_> = rng!(MIN_PAD_LEN, MAX_PAD_LEN)
        .into_iter()
        .filter(|byte| *byte != PAD_DELIMITER)
        .chain(vec![PAD_DELIMITER].into_iter())
        .collect();

    // step 2 => `enc_hash` = aes_enc(hash(content of `tmp_path_1`))
    let enc_hash = sha_aes_sha!(get_src()?, salt, key_hash)?.as_vec()?;

    // singleton_vec
    let hash_len = vec![{
        let len = enc_hash.len();
        debug_assert!((u8::MIN as usize) < len && len < (u8::MAX as usize));
        len as u8
    }];

    let meta_len_bytes = u32_to_u8s(metadata.len() as u32);

    // step 3 => `tmp_path_2` = hash_len + hash + enc_content
    //
    // conceptualizing the file as an array of bytes,
    //
    // 1. `file[ : i ]` throwaway random bytes
    // 2. `file[ i : i + 4 ]` metadata length, u32 as u8s
    // 3. `file[ i + 4 : j ]` metadata bytes
    // 4. `file[ j ]` is the length of the hash, let this be `n`
    // 5. `file[ j + 1 : k + 1 ]` is the encrypted checksum of the content
    // 6. `file[ k + 1 : ]` in the actual content
    compose_encoders!(
        rand_padding
            .chain(&meta_len_bytes[..])
            .chain(&metadata[..])
            .chain(&hash_len[..])
            .chain(&enc_hash[..])
            .chain(get_src()?),
        EncryptorAES => (key_hash, Some(salt))
    )?
    .read_all_to(&mut dest)?; // 3

    Ok(())
}

fn csync_decrypt<FR, R, W>(
    arena: &Path,
    file_type: FileType,
    get_src: FR,
    dest: Option<W>,
    uid: usize,
    salt: &[u8],
    key_hash: &[u8],
) -> io::Result<Vec<u8>>
where
    FR: Fn() -> io::Result<R>,
    R: Read + Seek,
    W: Write,
{
    let tmp_dest = arena.join(&format!("_{}_csync_decrypt_1", uid));

    let (expected_hash, metadata) = {
        // use Identity as the last one, to use the internal BufReader
        let mut decryptor = compose_encoders!(
            get_src()?,
            DecryptorAES => (key_hash, Some(salt)),
            IdentityEncoder => None
        )?;

        // 1. `file[ : i ]` throwaway random bytes
        // 2. `file[ i : i + 4 ]` metadata length, u32 as 4 u8s
        // 3. `file[ i + 4 : j ]` metadata bytes
        // 4. `file[ j ]` is the length of the hash, let this be `n`
        // 5. `file[ j + 1 : k + 1 ]` is the encrypted checksum of the content
        // 6. `file[ k + 1 : ]` in the actual content
        let pad_len = {
            let mut throwaway: Vec<u8> = Vec::with_capacity(MAX_PAD_LEN as usize);
            decryptor.read_until(PAD_DELIMITER, &mut throwaway)?;
            throwaway.len()
        };

        let metadata_len = u8s_to_u32(&read_exact(4, &mut decryptor)?);
        let metadata = read_exact(metadata_len as usize, &mut decryptor)?;

        let hash_len = *read_exact(1, &mut decryptor)?.get(0).unwrap() as usize;
        let hash = read_exact(hash_len, &mut decryptor)?;

        decryptor.read_all_to(&mut fopen_w(&tmp_dest)?)?;
        (hash, metadata)
    };

    let result_hash = sha_aes_sha!(fopen_r(&tmp_dest)?, salt, key_hash)?.as_vec()?;
    if result_hash != expected_hash {
        panic!("hashes don't match");
    }

    match file_type {
        FileType::FILE => {
            compose_encoders!(
                fopen_r(&tmp_dest)?,
                IdentityEncoder => None
            )?
            .read_all_to(&mut dest.unwrap())?;
        }
        FileType::DIR => debug_assert!(dest.is_none()),
    };

    Ok(metadata)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rayon::iter::ParallelBridge;
    use rayon::prelude::*;

    mod inverse {
        use super::*;
        use crate::test_util::*;
        use std::fs::metadata;

        fn tester(uid: usize, src: &Path) {
            let tmpd = tmpdir!().unwrap();
            let tmpd = tmpd.path();

            let arena1 = tmpdir!().unwrap();
            let arena2 = tmpdir!().unwrap();

            let enc_dest = tmpd.join(&format!("_{}_enc_", uid));
            let spread_hash = hash1!(path_as_str(&src).unwrap().as_bytes());
            let key_hash = hash1!(&spread_hash[..]);
            let src_bits = metadata(&src).unwrap().permissions().mode();
            let file_type = match src.is_dir() {
                true => FileType::DIR,
                false => FileType::FILE,
            };

            // src => enc_dest
            Action::new(
                &src,
                &enc_dest,
                file_type,
                &UnixMetadata { mode: Some(src_bits) },
                &spread_hash[..],
                Mode::ENCRYPT,
                uid,
            )
            .manifest(arena1.path(), &key_hash[..])
            .unwrap();

            // enc_dest => dec_dest
            let dec_dest = tmpd.join(basename(&src));
            Action::new(
                &enc_dest,
                &dec_dest,
                file_type,
                &UnixMetadata { mode: None },
                &spread_hash[..],
                Mode::DECRYPT,
                uid,
            )
            .manifest(arena2.path(), &key_hash[..])
            .unwrap();

            assert_tree_eq(&src, &dec_dest);
        }

        #[test]
        fn empty_dir() {
            let tmpd = tmpdir!().unwrap();
            tester(0, tmpd.path());
        }

        #[test]
        fn empty_file() {
            let tmpf = tmpfile!().unwrap();
            tester(0, tmpf.path());
        }

        #[test]
        fn text_files() {
            find("src")
                .enumerate()
                .par_bridge()
                .map(|(uid, pbuf_res)| (uid, pbuf_res.unwrap()))
                .filter(|(_, p)| p.is_file())
                .for_each(|(uid, pbuf)| tester(uid, &pbuf));
        }

        #[test]
        fn binary_file() {
            todo!();
            let tmpf = tmpfile!().unwrap();
        }

        #[test]
        fn binary_file_perm() {
            todo!();
        }
    }
}
