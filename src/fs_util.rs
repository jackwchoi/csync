/// THIS MOD SHOULD NOT USE THINGS FROM OTHER MODS IN THIS CRATE.
use std::{
    env,
    fs::{metadata, read_dir, File, OpenOptions, Permissions},
    io::{self, Error, ErrorKind},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    str,
    time::SystemTime,
};
use tempfile::{self, NamedTempFile, TempDir};
use walkdir::WalkDir;

macro_rules! tmpfile {
    () => {
        crate::fs_util::mktemp_file(None, "", "")
    };
    ( $out_dir:expr ) => {
        crate::fs_util::mktemp_file(Some($out_dir), "", "")
    };
    ( $out_dir:expr, $prefix:expr ) => {
        crate::fs_util::mktemp_file(Some($out_dir), $prefix, "")
    };
    ( $out_dir:expr, $prefix:expr, $suffix:expr ) => {
        crate::fs_util::mktemp_file(Some($out_dir), $prefix, $suffix)
    };
}

macro_rules! tmpdir {
    () => {
        crate::fs_util::mktemp_dir(None, "", "")
    };
    ( $out_dir:expr ) => {
        crate::fs_util::mktemp_dir(Some($out_dir), "", "")
    };
    ( $out_dir:expr, $prefix:expr ) => {
        crate::fs_util::mktemp_dir(Some($out_dir), $prefix, "")
    };
    ( $out_dir:expr, $prefix:expr, $suffix:expr ) => {
        crate::fs_util::mktemp_dir(Some($out_dir), $prefix, $suffix)
    };
}

#[inline]
pub fn mktemp_file(out_dir: Option<&Path>, prefix: &str, suffix: &str) -> io::Result<NamedTempFile> {
    tempfile::Builder::new()
        .prefix(prefix)
        .suffix(suffix)
        .tempfile_in(out_dir.unwrap_or(env::temp_dir().as_path()))
}

#[inline]
pub fn mktemp_dir(out_dir: Option<&Path>, prefix: &str, suffix: &str) -> io::Result<TempDir> {
    tempfile::Builder::new()
        .prefix(prefix)
        .suffix(suffix)
        .tempdir_in(out_dir.unwrap_or(env::temp_dir().as_path()))
}

#[inline]
pub fn modified(source: &Path) -> io::Result<SystemTime> {
    metadata(source)?.modified()
}

#[inline]
pub fn find<P>(root: P) -> impl Iterator<Item = io::Result<PathBuf>>
where
    P: AsRef<Path>,
{
    WalkDir::new(root).follow_links(true).into_iter().map(|entry| {
        entry
            .map(walkdir::DirEntry::into_path)
            .map_err(|err| Error::new(ErrorKind::Other, format!("{:?}", err)))
    })
}

#[inline]
pub fn ls<P>(root: P) -> io::Result<impl Iterator<Item = io::Result<PathBuf>>>
where
    P: AsRef<Path>,
{
    match read_dir(root) {
        Ok(iter) => Ok(iter.map(|entry_res| entry_res.map(|entry| entry.path()))),
        Err(err) => Err(err),
    }
}

pub fn fopen_w<P>(path: P) -> io::Result<File>
where
    P: AsRef<Path>,
{
    let file = OpenOptions::new().write(true).create(true).open(path)?;
    let perms = Permissions::from_mode(0o600);
    file.set_permissions(perms)?;
    Ok(file)
}

#[inline]
pub fn fopen_r<P>(path: P) -> io::Result<File>
where
    P: AsRef<Path>,
{
    OpenOptions::new().read(true).open(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use colmac::*;
    use std::collections::HashSet;
    use walkdir::DirEntry;

    mod walkdir_assumptions {
        use super::*;

        fn walk(root: &Path) -> HashSet<PathBuf> {
            WalkDir::new(root)
                .into_iter()
                .map(Result::unwrap)
                .map(DirEntry::into_path)
                .collect()
        }

        #[test]
        fn walkdir_includes_empty_root() {
            let tmpd = tmpdir!().unwrap();
            let tmpd_path = tmpd.path();

            let result: HashSet<_> = walk(tmpd_path);
            let expected: HashSet<_> = hashset![tmpd_path.to_path_buf()];
            assert_eq!(expected.len(), 1);
            assert_eq!(result, expected);
        }

        #[test]
        fn walkdir_includes_root() {
            let tmpd = tmpdir!().unwrap();
            let tmpd_path = tmpd.path();

            let tmpf_path = tmpd_path.join("f");
            let tmpf = fopen_w(&tmpf_path).unwrap();

            let result: HashSet<_> = walk(tmpd_path);
            let expected: HashSet<_> = vec![tmpd_path, &tmpf_path].into_iter().map(|p| p.to_path_buf()).collect();
            assert_eq!(expected.len(), 2);
            assert_eq!(result, expected);
        }
    }
}
