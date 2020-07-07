/// TODO
///
/// 1. syncing to a non-empty dir
///     1. if encrypting, collect to hashset and check for differences
///     1. if decrypting, force the dir to be non empty
/// 2. content of encrypted files
use crate::{
    crypt::action::*,
    encoder::{aes::*, crypt_encoder::*, hash::*, identity::*, text::*, zstd::*},
    fs_util::*,
    hasher::*,
    util::*,
};
use itertools::Itertools;
use rayon::prelude::*;
use ring::pbkdf2;
use serde::{Deserialize, Serialize};
use std::ffi::OsStr;
use std::{
    convert::TryInto,
    fs::{create_dir_all, read_dir, rename, Permissions},
    io::{self, ErrorKind, Read, Write},
    num::NonZeroU32,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    time::SystemTime,
    u8,
};
use tempfile::TempDir;
use walkdir::WalkDir;

const FILE_SUFFIX: &str = "csync";
const METADATA_FNAME: &str = "metadata.json.enc";

const METADATA_ADD_HASH_NUM_ITER: u32 = 1 << 16;

const_assert!(METADATA_ADD_HASH_NUM_ITER == 65536);

/// metadata that will be saved as a file at the root of the encrypted directory
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct SyncMetadata {
    compression_alg: Compressor,
    encryption_alg: Cipher,
    init_salt: Vec<u8>,
    pbkdf2_num_iter: u32,
    rehash_salt: Vec<u8>,
    spread_depth: u8,
}

#[derive(Debug)]
pub struct CryptSyncer {
    // some temp location where the encrypted files will be stored before
    // being moved to their final locations
    arena: TempDir,
    src_root: PathBuf,
    out_dir: PathBuf,
    rehash: Vec<u8>,
    // every field above is either user-supplied or derived from the metadata below
    metadata: SyncMetadata,
    sync_mode: Mode,
}

/// # Encryption Algorithm
///
/// The encryption process roughly has the form `encrypt <SRC> --out_dir <OUT>`, supplied with a
/// passphrase `pw`
///
/// 1. A length-16 array of bytes, `init_salt`, is generated using a cryptographically secure RNG.
/// 1. Let `key_hash` be the result of hashing `pw` with `pbkdf2`, init_salt` as the salt, and
///    `2^17 = 131,072` iterations.
/// 1. Let `rehash` be the result of hashing `key_hash` with 1 iteration, with length-16 array
///    of 0's as the salt.
/// 1. Let `S = { s1, s2, ..., sn }` be the set of all files and directories under `<SRC>`,
///    including  `<SRC>`. This is equivalent to the result of running `find <SRC>` in Bash.
/// 1. Let `O = { o1, o2, ..., on }` be the encrypted files to be created. `csync` can be
///    considered a bijective function going from `S` to `O`.
/// 1. Let `M` be the metadata necessary to decrypt and to continue encrypting.
///
/// Given some input file path of the form `path = d1/d2/.../dn/f`,
///
/// 1. let `path_hash = base64_pathsafe(pbkdf2(path, default_salt, 1 iter))`, and
///    `dir = path_hash[0]/path_hash[1]/path_hash[2]/path_hash[3]`, which helps achieve even spread
///    of files
/// 1. let `path_cipher = encrypt(path, init=path_hash[..4])`, which, given two similar paths like
///    `a/b/c/d/e/f/{g,h}`, helps make the two have dissimilar ciphertexts
/// 1. the final resulting path should be
///    `$dir/path_cipher[0:64]/path_cipher[64:128]/.../path_cipher[n-128:n]`
impl CryptSyncer {
    ///
    pub fn from_csync_dir(src_root: &Path, out_dir: &Path, key_hash: &[u8]) -> io::Result<Self> {
        //
        let SyncMetadata {
            compression_alg,
            encryption_alg,
            init_salt,
            pbkdf2_num_iter,
            rehash_salt,
            spread_depth,
        } = CryptSyncer::load_metadata(src_root, key_hash)?;

        CryptSyncer::new_priv(
            Mode::DECRYPT,
            compression_alg,
            encryption_alg,
            &init_salt[..],
            pbkdf2_num_iter,
            Some(rehash_salt),
            spread_depth,
            src_root,
            out_dir,
            key_hash,
        )
    }

    /// # Parameters
    #[inline]
    pub fn new(
        encryption_alg: Cipher,
        compression_alg: Compressor,
        src_root: &Path,
        out_dir: &Path,
        pbkdf2_num_iter: u32,
        spread_depth: u8,
        key_hash: &[u8],
    ) -> io::Result<Self> {
        CryptSyncer::new_priv(
            Mode::ENCRYPT,
            compression_alg,
            encryption_alg,
            &rng!(16)[..],
            pbkdf2_num_iter,
            None,
            spread_depth,
            src_root,
            out_dir,
            key_hash,
        )
    }

    fn check_out_dir(out_dir: &Path, sync_mode: Mode) {
        // `out_dir` doesn't have to exist, but requires case-by-case checks
        match out_dir.exists() {
            true if out_dir.is_file() => panic!("`-o/--out {:?}` cannot be a file", out_dir),
            true if out_dir.is_dir() => match sync_mode {
                Mode::ENCRYPT => (),
                Mode::DECRYPT => match read_dir(out_dir) {
                    Ok(ls) => assert_eq!(ls.count(), 0, "decrypting and dir is not empty"),
                    Err(err) => panic!("{}", err),
                },
            },
            true => panic!("filetype of {:?} is not supported", out_dir),
            false => (),
        }
    }

    /// Private constructor used by all other public constructors.
    ///
    /// # Parameters
    ///
    /// 1. `compression_alg`:
    /// 1. `encryption_alg`:
    /// 1. `init_salt`:
    /// 1. `rehash_opt`:
    /// 1. `rehash_salt_opt`:
    /// 1. `spread_depth`:
    /// 1. `src_root`:
    /// 1. `out_dir`:
    /// 1. `key_hash`:
    fn new_priv(
        sync_mode: Mode,
        compression_alg: Compressor,
        encryption_alg: Cipher,
        init_salt: &[u8],
        pbkdf2_num_iter: u32,
        rehash_salt_opt: Option<Vec<u8>>,
        spread_depth: u8,
        src_root: &Path,
        out_dir: &Path,
        key_hash: &[u8],
    ) -> io::Result<Self> {
        // `src_root` must exist
        assert!(src_root.exists(), "the source directory {:?} does not exist", src_root);
        CryptSyncer::check_out_dir(out_dir, sync_mode);

        // check algorithms
        match encryption_alg {
            Cipher::AES => (),
        };
        match compression_alg {
            Compressor::ZSTD => (),
        };

        // do this here because canonicalization requires the path to exist
        create_dir_all(&out_dir)?;

        // random salt generated for each encrypted vaults
        let rehash_salt = rehash_salt_opt.unwrap_or(rng!(16));
        let rehash = hash!(pbkdf2_num_iter, key_hash, &rehash_salt[..]);
        // TODO assertions about rehash and rehash salt

        match spread_depth {
            spread_depth if 0 < spread_depth && spread_depth <= 86 => Ok(Self {
                sync_mode,
                arena: tmpdir!()?,
                metadata: SyncMetadata {
                    compression_alg,
                    encryption_alg,
                    init_salt: Vec::from(init_salt),
                    pbkdf2_num_iter,
                    rehash_salt,
                    spread_depth,
                },
                src_root: src_root.canonicalize()?.to_path_buf(),
                out_dir: out_dir.canonicalize()?.to_path_buf(),
                rehash,
            }),
            _ => panic!("spread_depth `{}` is not in range (0, 86]", spread_depth),
        }
    }

    /// Load metadata from an existing `csync` directory.
    ///
    /// # Parameters
    ///
    /// 1. `src_root`: path to the root of an existing `csync` directory
    /// 1. `key_hash`: hash of the passphrase, to decrypt the metadata
    fn load_metadata(src_root: &Path, key_hash: &[u8]) -> io::Result<SyncMetadata> {
        let json_string = {
            let metadata_path = src_root.join(METADATA_FNAME);
            assert!(metadata_path.exists(), "metadata file {:?} does not exist", metadata_path);

            compose_encoders!(
                fopen_r(&metadata_path)?,
                DecryptorAES => (key_hash, None),
                ZstdDecoder => None
            )?
            .as_string()?
        };

        Ok(serde_json::from_str(&json_string)?)
    }

    fn dump_metadata(&self, hash_num_iter: u32, key_hash: &[u8]) -> io::Result<()> {
        // let key_hash = hash!(hash_num_iter, key_hash);

        let metadata_data = serde_json::to_string(&self.metadata).map_err(io_err)?;
        let metadata_data = metadata_data.as_bytes();

        let mut metadata_file = {
            let metadata_path = self.out_dir.join(METADATA_FNAME);
            assert!(!metadata_path.exists()); // TODO
            fopen_w(&metadata_path)?
        };

        // write the num iter as 4 u8's
        {
            let hash_num_iter_as_bytes = u32_to_u8s(hash_num_iter);
            // metadata_file.write_all(&hash_num_iter_as_bytes[..])?;
        }
        // write the actual content
        compose_encoders!(
            metadata_data,
            ZstdEncoder => None,
            EncryptorAES => (key_hash, None)
        )?
        .read_all_to(&mut metadata_file)?;

        Ok(())
    }

    // 1. for the root cfile,
    pub fn sync_enc<'a>(&'a self, key_hash: &'a [u8]) -> io::Result<impl ParallelIterator<Item = Action> + 'a> {
        debug_assert_eq!(self.sync_mode, Mode::ENCRYPT);
        self.check_rep();
        self.check_key(key_hash);
        self.dump_metadata(METADATA_ADD_HASH_NUM_ITER, key_hash)?;

        Ok(self
            .sync_enc_dry(key_hash)
            .map(move |action| action.manifest(self.arena.path(), key_hash))
            .map(Result::unwrap))
    }

    ///
    //pub fn sync_enc_dry<'a>(&'a self, key_hash: &'a [u8]) -> impl ParallelIterator<Item = Action> + 'a {
    pub fn sync_enc_dry<'a>(&'a self, key_hash: &'a [u8]) -> impl ParallelIterator<Item = Action> + 'a {
        debug_assert_eq!(self.sync_mode, Mode::ENCRYPT);
        self.check_rep();
        self.check_key(key_hash);
        CryptSyncer::check_out_dir(&self.out_dir, self.sync_mode);

        let src_root = self.src_root.clone();
        let out_dir = self.out_dir.clone();
        let spread_depth = self.metadata.spread_depth;
        let init_salt = self.metadata.init_salt.clone();
        meta_map(&src_root).filter_map(move |(uid, src_pbuf, perms, src_modtime, file_type)| {
            let spread = path_to_spread(spread_depth, &init_salt, &src_pbuf);
            let spread_hash = spread_to_hash(&spread);

            let cipherpath = {
                let cipher_basename = path_to_cipherpath(&src_root, &src_pbuf, file_type, &spread_hash, key_hash);
                out_dir.join(spread).join(cipher_basename)
            };

            // sugar
            let action = |dest| {
                Some(Action::new(
                    &src_pbuf.to_path_buf(),
                    dest,
                    file_type,
                    &UnixMetadata {
                        mode: Some(perms.mode()),
                    },
                    &spread_hash,
                    Mode::ENCRYPT,
                    uid,
                ))
            };

            match modified(&cipherpath) {
                // both files exist, so compare their modified times
                Ok(enc_mod) => match src_modtime.duration_since(enc_mod) {
                    // src was modified after enc, so include it
                    Ok(duration) if 0 < duration.as_nanos() => action(&cipherpath),
                    // enc was modified after src, so don't include it
                    _ => None,
                },
                Err(err) if err.kind() == ErrorKind::NotFound => action(&cipherpath),
                Err(err) => panic!("{:?}", err),
            }
        })
    }

    pub fn sync_dec(&self) {
        debug_assert_eq!(self.sync_mode, Mode::DECRYPT);
    }

    ///
    pub fn sync_dec_dry<'a>(&'a self, key_hash: &'a [u8]) -> impl ParallelIterator<Item = io::Result<Action>> + 'a {
        debug_assert_eq!(self.sync_mode, Mode::DECRYPT);
        self.check_rep();
        self.check_key(key_hash);
        CryptSyncer::check_out_dir(&self.out_dir, self.sync_mode);

        let spread_depth = self.metadata.spread_depth.clone();
        let src_root = self.src_root.clone();
        let out_dir = self.out_dir.clone();

        WalkDir::new(&self.src_root)
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
            .map(move |(uid, entry_res)| -> io::Result<Action> {
                let cipherpath = entry_res?.path().to_path_buf();
                let (path, file_type, spread_hash) = cipherpath_to_path(spread_depth, &src_root, &cipherpath, key_hash)?;
                Ok(Action::new(
                    &cipherpath,
                    &out_dir.join(path),
                    file_type,
                    &UnixMetadata { mode: None },
                    &spread_hash,
                    Mode::DECRYPT,
                    uid,
                ))
            })
    }

    /// Miscellaneous checks.
    #[inline]
    fn check_rep(&self) {
        debug_assert!(&0 < &self.metadata.spread_depth);
        debug_assert!(&self.src_root.exists());
        debug_assert!(is_canonical(&self.out_dir).unwrap());
        debug_assert!(is_canonical(&self.src_root).unwrap());
        debug_assert_eq!(self.metadata.init_salt.len(), 16);
        debug_assert_eq!(self.metadata.rehash_salt.len(), 16);
        debug_assert_eq!(self.rehash.len(), 64);
    }

    /// Check that the provided key has the same hash as the previously provided key.
    #[inline]
    fn check_key(&self, key_hash: &[u8]) {
        assert!(
            pbkdf2::verify(
                PBKDF2_ALGORITHM,
                NonZeroU32::new(self.metadata.pbkdf2_num_iter).unwrap(),
                &self.metadata.rehash_salt[..],
                key_hash,
                &self.rehash[..],
            )
            .is_ok(),
            "provided key does not match the original key"
        )
    }
}

/// Mapping from paths under `root` to some of its metadata.
///
///
fn meta_map(root: &Path) -> impl ParallelIterator<Item = (usize, PathBuf, Permissions, SystemTime, FileType)> {
    debug_assert!(is_canonical(&root).unwrap());
    WalkDir::new(root)
        .follow_links(true)
        .into_iter()
        .enumerate()
        .par_bridge()
        .map(|(uid, entry_res)| match entry_res {
            // :: DirEntry -> (PathBuf, SystemTime)
            // only handle regular files and dirs
            Ok(entry) => match (entry.metadata(), entry.file_type()) {
                (Ok(meta), ftype) => match meta.modified() {
                    // everything good
                    Ok(modified) if ftype.is_file() => (uid, entry.into_path(), meta.permissions(), modified, FileType::FILE),
                    Ok(modified) if ftype.is_dir() => (uid, entry.into_path(), meta.permissions(), modified, FileType::DIR),
                    // not a file or dir, maybe support later
                    Ok(_) => panic!("filetype not supported"),
                    Err(err) => panic!("cannon read modified time: {}", err),
                },
                (Err(err), _) => panic!("cannot read metadata: {}", err),
            },

            Err(err) => panic!("failed reading {}", err),
        })
}

/// # Parameters
///
/// 1. `spread_depth`: number of layers used in spreading; a max of `64 ^ spread_depth` number of
///    distinct directories can be created
/// 2. `path`: the path with which spread dirs will be created
fn path_to_spread(spread_depth: u8, init_salt: &[u8], path: &Path) -> PathBuf {
    debug_assert!(is_canonical(&path).unwrap());
    let spread_depth = spread_depth as usize;
    if spread_depth == 0 || 86 < spread_depth {
        panic!("spread_depth `{}` is not in the range (0, 86]", spread_depth);
    }

    // 'spread dirs are the depth-n dirs created with sha512 in order to spread out the files
    // into different dirs
    match path_as_str(path) {
        // compute a pathsafe-base64-encoded hash of the pathbuf
        Some(s) => match base32path(&hash1!(s.as_bytes(), init_salt)[..]) {
            // get the first spreaod_depth chars of the hash, with '/' interopersed
            Ok(hash) => PathBuf::from((&hash[..spread_depth]).chars().intersperse('/').collect::<String>()),
            Err(err) => panic!("base64 encoding failed: {}", err),
        },
        None => panic!("path has non unicode chars"),
    }
}

/// # Parameters
///
/// 1.
#[inline]
fn spread_to_hash(spread: &Path) -> Vec<u8> {
    // get a hash of the chars in the spread dir path, to use as the initialization
    // vector for the EncryptorAES
    hash1!(path_as_str(&spread)
        .unwrap()
        .chars()
        .filter(|c| c != &'/')
        .collect::<String>()
        .as_bytes())
}

/// # Parameters
///
/// 1. `src_root`:
/// 1. `src_path`:
/// 1. `file_type`:
/// 1. `spread_hash`:
/// 1. `key_hash`:
///
/// # Returns
///
/// a
fn path_to_cipherpath(
    src_root: &Path,
    src_path: &Path,
    file_type: FileType,
    spread_hash: &Vec<u8>,
    key_hash: &[u8],
) -> PathBuf {
    debug_assert!(src_path.starts_with(src_root));
    debug_assert!(is_canonical(src_root).unwrap());
    debug_assert!(is_canonical(src_path).unwrap());
    let aug_src_rel_path = {
        let src_rel_path = subpath_par(src_path, src_root).unwrap();

        let rand_bytes_string = {
            // deterministic seed given the rel path of the src file
            let src_seed: [u8; 32] = {
                let src_rel_path_str = path_as_str(&src_rel_path).unwrap();
                let src_seed = sha_aes_sha!(src_rel_path_str.as_bytes(), &spread_hash[..], key_hash)
                    .unwrap()
                    .as_vec()
                    .unwrap();
                (&src_seed[..32]).try_into().unwrap()
            };

            // generate somewhere between 40 to 200 random bytes
            let rand_bytes: Vec<_> = rng_seed!(&src_seed, 40, 200, u8::MIN, u8::MAX)
                .into_iter()
                .filter(|byte| &32 <= byte && byte <= &126)
                .collect();

            compose_encoders!(
                &rand_bytes[..],
                TextEncoder => &BASE32PATH
            )
            .unwrap()
            .as_string()
            .unwrap()
        };
        debug_assert!(0 < rand_bytes_string.len());

        let filetype_prefix = match file_type {
            FileType::FILE => "f",
            FileType::DIR => "d",
        };

        Path::new(&rand_bytes_string).join(filetype_prefix).join(src_rel_path)
    };

    // encrypt the entire path using the spread hash as the init vec
    let aug_src_rel_path_string = path_as_str(&aug_src_rel_path).unwrap();
    let aug_src_rel_path_bytes = aug_src_rel_path_string.as_bytes();
    let ciphertext = compose_encoders!(
        aug_src_rel_path_bytes,
        EncryptorAES => (key_hash, Some(&spread_hash)),
        TextEncoder => &BASE32PATH
    )
    .unwrap()
    .as_string()
    .unwrap();
    {
        debug_assert!(ciphertext.chars().all(|c| c != '/'));
        (0..12).for_each(|_| {
            let undo_cipher = compose_encoders!(
                ciphertext.as_bytes(),
                TextDecoder => &BASE32PATH,
                DecryptorAES => (key_hash, Some(&spread_hash[..]))
            )
            .unwrap()
            .as_vec()
            .unwrap();
            debug_assert_eq!(&undo_cipher[..], aug_src_rel_path_bytes);
        });
    }

    // group into chunks of 64 chars, then join them with '/'
    let without_ext = ciphertext
        .chars()
        .chunks(64)
        .into_iter()
        .map(|chunk| chunk.into_iter().collect::<String>())
        .join("/");

    PathBuf::from(format!("{}.{}", without_ext, FILE_SUFFIX))
}

fn cipherpath_to_path(
    spread_depth: u8,
    src_root: &Path,
    cipherpath: &Path,
    key_hash: &[u8],
) -> io::Result<(PathBuf, FileType, Vec<u8>)> {
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
    ));

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
        DecryptorAES => (key_hash, Some(&spread_hash[..]))
    )
    .unwrap()
    .as_string()
    .unwrap();

    let mut decrypted_comps = Path::new(&decrypted).components();
    decrypted_comps.next().unwrap(); // random padding
    let ftype = match decrypted_comps.next().unwrap().as_os_str().to_str() {
        Some("f") => FileType::FILE,
        Some("d") => FileType::DIR,
        _ => panic!("wrong number of comps"),
    };
    let decrypted_pbuf = PathBuf::from(decrypted_comps.as_path());

    Ok((decrypted_pbuf, ftype, spread_hash))
}

#[cfg(test)]
mod tests {
    use super::*;
    use colmac::*;
    use std::fs::{remove_dir_all, File};
    use Cipher::*;
    use Compressor::*;

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

    fn realpaths() -> Vec<PathBuf> {
        find(Path::new("src/"))
            .map(Result::unwrap)
            .map(|pbuf| pbuf.canonicalize().unwrap())
            .collect()
    }

    mod path_to_spread {
        use super::*;
        use std::collections::HashMap;
        use std::path::Component;

        /// 0 is an invalid spread depth, so it should panic
        #[test]
        #[should_panic]
        fn spread_depth_invalid_0() {
            let paths = realpaths();
            paths.into_iter().for_each(|path| {
                path_to_spread(0, &PBKDF2_SALT_DEFAULT, &path);
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
                    .map(|path| (path.as_path(), path_to_spread(count, &PBKDF2_SALT_DEFAULT, &path)))
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
        #[should_panic]
        fn spread_depth_invalid_87() {
            let paths = realpaths();
            paths.into_iter().for_each(|path| {
                path_to_spread(87, &PBKDF2_SALT_DEFAULT, &path);
            });
        }
    }

    mod spread_to_hash {
        use super::*;

        fn spreads_to_salts(spread_depth: u8, spreads: &Vec<PathBuf>) -> HashSet<Vec<u8>> {
            spreads.par_iter().map(|spread| spread_to_hash(&spread)).collect()
        }

        fn _parametrized_by_spread_depth(spread_depth: u8) {
            let (spreads, spreads_without_slashes): (Vec<_>, Vec<_>) = realpaths()
                .into_par_iter()
                .map(|path| path_to_spread(spread_depth, &PBKDF2_SALT_DEFAULT, &path))
                .map(|pb| {
                    (
                        pb.clone(),
                        PathBuf::from(path_as_str(&pb).unwrap().chars().filter(|c| c != &'/').collect::<String>()),
                    )
                })
                .unzip();

            // collect into set to check for collision
            let salts = spreads_to_salts(spread_depth, &spreads);
            let salts_without_slashes = spreads_to_salts(spread_depth, &spreads_without_slashes);

            // make sure that slashes are ignored when converting spreads to salts
            assert_eq!(salts_without_slashes, salts);
            // sanity check
            assert!(0.5 * spreads.len() as f64 <= salts.len() as f64);
            assert_eq!(salts.len(), salts_without_slashes.len());
        }

        #[test]
        fn parametrized_by_spread_depth() {
            vec![1, 5, 17, 23].into_par_iter().for_each(_parametrized_by_spread_depth);
        }
    }

    #[test]
    fn new() {
        let src_root = tmpdir!().unwrap();
        let src_root_canon = src_root.path().canonicalize().unwrap();

        // directory in which to put encrypted files
        let out_dir = tmpdir!().unwrap();
        let out_dir_canon = out_dir.path().canonicalize().unwrap();

        // actual syncing
        let key_hash = hash1!(b"aoisjfk1oalrchucroaehuntoeahuh");
        let spread_depth = 13;
        let pbkdf2_num_iter = 2u32;

        let syncer = CryptSyncer::new(
            AES,
            ZSTD,
            src_root.path(),
            out_dir.path(),
            pbkdf2_num_iter,
            spread_depth,
            &key_hash[..],
        )
        .unwrap();

        // syncer checks
        assert_eq!(syncer.src_root, src_root_canon);
        assert_eq!(syncer.out_dir, out_dir_canon);

        // metadata checks
        assert_eq!(syncer.metadata.spread_depth, spread_depth);
        assert_eq!(syncer.metadata.encryption_alg, Cipher::AES);
        assert_eq!(syncer.metadata.compression_alg, Compressor::ZSTD);
        assert_eq!(syncer.metadata.init_salt.len(), 16);
        assert_eq!(
            syncer.rehash,
            hash!(pbkdf2_num_iter, &key_hash[..], &syncer.metadata.rehash_salt[..])
        );
        assert_eq!(syncer.metadata.rehash_salt.len(), 16);
    }

    #[test]
    fn path_to_cipherpath_inverse_of_cipherpath_to_path() {
        let src_root = Path::new("src").canonicalize().unwrap();
        let init_salt = [72u8; 16];
        let key_hash = hash1!(b"ZofHNXwplsOmmpcjbD2ABH9RA1fTVAZbot5qznnA3EwUFSQ2coY2PNyGFkWcqb16");

        vec![1, 4, 8, 19, 62].into_iter().for_each(|spread_depth| {
            meta_map(&src_root).for_each(|(_, src_pbuf, _, _, file_type)| {
                let src_rel_path = subpath(&src_pbuf, &src_root.parent().unwrap()).unwrap();
                let spread = path_to_spread(spread_depth, &init_salt, &src_pbuf);
                let spread_hash = spread_to_hash(&spread);

                let ciphertext = path_to_cipherpath(&src_root, &src_pbuf, file_type, &spread_hash, &key_hash);
                let cipherpath = src_root.join(spread).join(ciphertext);

                let (decrypted, ret_file_type, ret_spread_hash) =
                    cipherpath_to_path(spread_depth, &src_root, &cipherpath, &key_hash).unwrap();

                assert_eq!(ret_file_type, file_type);
                assert_eq!(&decrypted, &src_rel_path);
                assert_eq!(spread_hash, ret_spread_hash);
            });
        })
    }

    mod sync_enc_dry {
        use super::*;

        mod aes_zstd {
            use super::*;

            /// constructs a syncer, calls `sync_enc_dry` and returns the actions.
            ///
            /// checks the following about each sync actions:
            /// 1. the path `src` starts with `src_root_canon`
            /// 1. the path `dest` starts with `out_dir_canon`
            /// 1. `spread_hash` is 64-bytes long
            /// 1. `sync_mode` is `ENCRYPT`
            /// 1. `file_type` is `FILE` or `DIR`
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
            ) -> (CryptSyncer, HashSet<Action>) {
                let (syncer, sync_actions): (_, HashSet<_>) = {
                    let key_hash = hash1!(key_bytes);
                    let syncer = CryptSyncer::new(AES, ZSTD, src_root, out_dir, 8u32, spread_depth, &key_hash[..]).unwrap();
                    let actions = syncer.sync_enc_dry(&key_hash[..]).collect();

                    (syncer, actions)
                };

                let src_root_canon = src_root.canonicalize().unwrap();
                let out_dir_canon = out_dir.canonicalize().unwrap();
                let (srcs, uids): (HashSet<_>, HashSet<_>) = sync_actions
                    .par_iter()
                    .cloned()
                    .map(
                        |Action {
                             src,
                             dest,
                             uid,
                             metadata,
                             spread_hash,
                             sync_mode,
                             file_type,
                         }| {
                            assert!(src.starts_with(&src_root_canon));
                            assert!(dest.starts_with(&out_dir_canon));
                            assert_eq!(dest.extension(), Some(OsStr::new(FILE_SUFFIX)));
                            assert_eq!(spread_hash.len(), 64);
                            assert_eq!(sync_mode, Mode::ENCRYPT);
                            assert!(file_type == FileType::FILE || file_type == FileType::DIR);
                            (src, uid)
                        },
                    )
                    .unzip();

                // make sure that all the source files are included
                assert_eq!(uids.len(), srcs.len());
                assert_eq!(&srcs_to_sync.iter().cloned().collect::<HashSet<_>>(), &srcs);
                (syncer, sync_actions)
            }

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

            #[test]
            fn short_names_no_filename_conflict_modified() {
                let src_root = tmpdir!().unwrap();
                let src_root_canon = src_root.path().canonicalize().unwrap();

                let out_dir = tmpdir!().unwrap();

                let key_bytes = b"Q6ocC0SuMlRtRcm8e2IfulI5ZCcLezune6md9yjTFLBnjUDNTTt9z2w6od8KQdg9";
                let key_hash = hash1!(key_bytes);
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

                    let new_actions: Vec<_> = syncer.sync_enc_dry(&key_hash).collect();

                    assert_eq!(new_actions.len(), actions.len() - i - 1);

                    acc.push(filepath);
                    acc
                });
            }
        }

        #[test]
        #[should_panic]
        fn different_key_panics() {
            let src_root = tmpdir!().unwrap();
            let out_dir = tmpdir!().unwrap();

            let key_hash_1 = hash1!(b"PoU4PO2s8iDQlywUHbP9jdz0bnpw4j06Essdu6nRaM9bodfaMqyqjUv3vYS7Ak8W");
            let key_hash_2 = hash1!(b"RBOlGRvgycr8lJ3qWWuYxvlrW6ByCijLrwIwGHxFsYI0h3Fz8W1uqVmTbtBZRlbp");
            let spread_depth = 9;

            let syncer = CryptSyncer::new(
                AES,
                ZSTD,
                &src_root.path(),
                &out_dir.path(),
                123u32,
                spread_depth,
                &key_hash_1[..],
            )
            .unwrap();

            syncer.sync_enc_dry(&key_hash_1[..]);
            syncer.sync_enc_dry(&key_hash_2[..]);

            todo!()
        }
    }

    #[test]
    fn load_metadata() {
        let spread_depths = vec![1, 3, 5, 9, 17];
        let init_salts: HashSet<_> = spread_depths
            .par_iter()
            .cloned()
            .map(|spread_depth| {
                let src_root_canon = Path::new("src/").canonicalize().unwrap();
                assert!(src_root_canon.exists());

                let out_dir = tmpdir!().unwrap();
                let out_dir_canon = out_dir.path().canonicalize().unwrap();

                let key_hash = hash1!(b"WO5ZVq9BSKiSWvLBaR1hjlj7WXXeFoVAEbmSbwGKfdNOpvz0WzLy8eZbn7oAsS6o");

                let expected = {
                    let syncer = CryptSyncer::new(
                        AES,
                        ZSTD,
                        &src_root_canon,
                        &out_dir_canon,
                        8124u32,
                        spread_depth,
                        &key_hash[..],
                    )
                    .unwrap();

                    let _: Vec<_> = syncer.sync_enc(&key_hash[..]).unwrap().collect();
                    syncer.metadata
                };

                let result = CryptSyncer::load_metadata(&out_dir_canon, &key_hash).unwrap();

                assert_eq!(result, expected);
                expected.init_salt
            })
            .collect();

        assert_eq!(init_salts.len(), spread_depths.len());
    }

    mod sync_enc {
        use super::*;

        #[test]
        fn same_key_unique_paths() {
            let src_root_canon = Path::new("src/").canonicalize().unwrap();

            let out_dir_1 = tmpdir!().unwrap();
            let out_dir_2 = tmpdir!().unwrap();

            let key_hash = hash1!(b"PoU4PO2s8iDQlywUHbP9jdz0bnpw4j06Essdu6nRaM9bodfaMqyqjUv3vYS7Ak8W");
            let spread_depth = 13;

            let file_sets: Vec<_> = vec![&out_dir_1.path(), &out_dir_2.path()]
                .into_par_iter()
                .map(|out_dir_canon| {
                    let _: Vec<_> = CryptSyncer::new(
                        AES,
                        ZSTD,
                        &src_root_canon,
                        out_dir_canon,
                        1982u32,
                        spread_depth,
                        &key_hash[..],
                    )
                    .unwrap()
                    .sync_enc(&key_hash[..])
                    .unwrap()
                    .collect();
                    out_dir_canon
                })
                .map(|out_dir_canon| {
                    // relative paths, only files
                    find(out_dir_canon)
                        .map(Result::unwrap)
                        .filter(|pbuf| !pbuf.ends_with(METADATA_FNAME) && !pbuf.ends_with(out_dir_canon))
                        .filter(|pbuf| pbuf.is_file())
                        .map(|pbuf| subpath(&pbuf, out_dir_canon))
                        .map(Option::unwrap)
                        .collect::<HashSet<_>>()
                })
                .collect();

            assert_eq!(file_sets.len(), 2);
            assert!(file_sets
                .iter()
                .all(|set| !set.contains(Path::new(METADATA_FNAME)) && !set.contains(Path::new(""))));

            let file_sets_cleaned: Vec<_> = file_sets
                .into_iter()
                .map(|mut set| {
                    set.remove(Path::new(METADATA_FNAME));
                    set.remove(Path::new(""));
                    set
                })
                .collect();

            let set1 = file_sets_cleaned.get(0).unwrap();
            let set2 = file_sets_cleaned.get(1).unwrap();

            assert!(set1.is_disjoint(set2));
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
            let key_hash = hash1!(path_as_str(&src_root).unwrap().as_bytes());
            let spread_depth = 7;

            let enc_syncer = CryptSyncer::new(
                AES,
                ZSTD,
                &src_root,
                out_dir.path(),
                1792u32,
                spread_depth,
                &key_hash[..],
            )
            .unwrap();
            let enc_actions: Vec<_> = enc_syncer.sync_enc(&key_hash[..]).unwrap().collect();

            let dec_syncer = CryptSyncer::from_csync_dir(out_dir.path(), out_out_dir.path(), &key_hash[..]).unwrap();

            assert_eq!(dec_syncer.metadata, enc_syncer.metadata);
            assert_eq!(&dec_syncer.rehash, &enc_syncer.rehash);
            assert_eq!(dec_syncer.src_root, enc_syncer.out_dir);

            (
                src_root,
                out_dir,
                out_out_dir,
                key_hash,
                spread_depth,
                enc_syncer,
                dec_syncer,
                enc_actions,
            )
        }};
    }

    mod sync_dec_dry {
        use super::*;

        macro_rules! testgen {
            ( $mod_name:ident, $src_root:literal ) => {
                mod $mod_name {
                    use super::*;

                    #[test]
                    #[should_panic]
                    fn panics_if_decrypting_with_a_different_key() {
                        let (_, _, _, _, _, _, dec_syncer, _) = dec_boiler!($src_root);
                        let different_key = hash1!(b"3qdL99ZiMY8zsEzRdvjAEA7SXjLphf7xtMkuL7ue36cYy7e0ACORAjxnJone7EYz");
                        dec_syncer.sync_dec_dry(&different_key[..]).collect::<Vec<_>>();
                    }

                    #[test]
                    #[should_panic]
                    fn panics_if_decrypting_with_nonempty_out_dir() {
                        let out_out_dir = tmpdir!().unwrap();
                        let fpath = out_out_dir.path().join(".tmpfile");
                        {
                            fopen_w(&fpath).unwrap();
                        }
                        assert!(fpath.exists());

                        let (_, _, _, _, _, _, _, _) = dec_boiler!($src_root, tmpdir!().unwrap(), out_out_dir);
                    }

                    #[test]
                    fn inverse_of_sync_enc() {
                        let (src_root, out_dir, out_out_dir, key_hash, _, _, dec_syncer, enc_actions) = dec_boiler!($src_root);
                        let dec_actions: Vec<_> = dec_syncer
                            .sync_dec_dry(&key_hash[..])
                            .map(|x| x.unwrap())
                            .collect();

                        let out_dir_path = out_dir.path().canonicalize().unwrap();
                        let out_out_dir_path = out_out_dir.path().canonicalize().unwrap();

                        // checks about the src and dsts
                        {
                            let enc_map: HashMap<_, _> = enc_actions.iter().cloned().map(|x| (x.src, x.dest)).collect();
                            let dec_map: HashMap<_, _> = dec_actions.iter().cloned().map(|x| (x.src, x.dest)).collect();
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

                        {
                            let enc_hashes: HashSet<_> = enc_actions.iter().map(|x| x.spread_hash.clone()).collect();
                            let dec_hashes: HashSet<_> = dec_actions.iter().map(|x| x.spread_hash.clone()).collect();

                            assert_eq!(enc_hashes, dec_hashes);
                        }
                    }
                }
            };
        }

        testgen!(src, "src");

        testgen!(src_main_rs, "src/main.rs");

        testgen!(stress_target_debug_build, "target/debug/build");
    }

    mod sync_dec {
        use super::*;
        use std::io::Read;
    }
}
