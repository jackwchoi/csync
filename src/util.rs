/// THIS MOD SHOULD NOT USE THINGS FROM OTHER MODS IN THIS CRATE.
use std::{
    fmt::Debug,
    io::{self, Error, Read},
    path::{Path, PathBuf},
};

pub const BUFFER_SIZE: usize = 1 << 16;

const_assert!(BUFFER_SIZE == 65536);

// TODO use a custom error struct instead of std::io::Error
macro_rules! err {
    ( $message:expr ) => {
        std::io::Error::new(std::io::ErrorKind::Other, $message)
    };
    ( $message:expr, $($arg:expr),* ) => {
        std::io::Error::new(std::io::ErrorKind::Other, format!($message, $($arg),*))
    };
}

/// `None` if
pub fn subpath(path: &Path, root: &Path) -> Option<PathBuf> {
    let root_comps_len = root.components().count();
    match path.starts_with(root) {
        true => Some(path.components().skip(root_comps_len).collect()),
        false => None,
    }
}

pub fn subpath_par(path: &Path, root: &Path) -> Option<PathBuf> {
    match root.parent() {
        Some(root_par) => subpath(path, root_par),
        None => subpath(path, root),
    }
}

/// Conversion from `&Path` to `String` in one shot.
#[inline]
pub fn path_as_str(path: &Path) -> Option<String> {
    path.as_os_str().to_str().map(String::from)
}

#[inline]
pub fn is_canonical(path: &Path) -> io::Result<bool> {
    Ok(&path.canonicalize()? == path)
}

#[inline]
pub fn u8s_to_u32(bytes: &[u8]) -> u32 {
    debug_assert_eq!(bytes.len(), 4);
    bytes
        .iter()
        .copied()
        .rev()
        .enumerate()
        .map(|(i, byte)| {
            let shift = 8 * i;
            (byte as u32) << shift
        })
        .sum()
}

#[inline]
pub fn u32_to_u8s(reg: u32) -> Vec<u8> {
    [0xFFu32, 0xFF00u32, 0xFF0000u32, 0xFF000000u32]
        .iter()
        .enumerate()
        .map(|(i, bits)| {
            let shift = 8 * i;
            ((reg & bits) >> shift) as u8
        })
        .rev()
        .collect()
}

#[inline]
pub fn io_err<D>(error: D) -> Error
where
    D: Debug,
{
    err!("{:?}", error)
}

/// check if the two iterators are equivalent
pub fn iter_eq<I, T>(mut iter_a: I, mut iter_b: I) -> bool
where
    I: Iterator<Item = T>,
    T: Eq,
{
    loop {
        let opt_a = iter_a.next();
        let opt_b = iter_b.next();

        match (opt_a, opt_b) {
            (None, None) => break true,
            (a, b) => match a == b {
                true => (),
                false => break false,
            },
        }
    }
}

/// read exactly count number of bytes from src
pub fn read_exact<R>(count: usize, src: &mut R) -> io::Result<Vec<u8>>
where
    R: Read,
{
    let mut reservoir: Vec<u8> = Vec::with_capacity(count);
    let mut buffer = vec![0u8; count];

    loop {
        match count - reservoir.len() {
            0 => break Ok(reservoir),
            bytes_left => match src.read(&mut buffer[..bytes_left])? {
                0 => break Err(err!("there was less than {} bytes", count)),
                bytes_read => (&buffer[..bytes_read]).iter().for_each(|byte| reservoir.push(*byte)),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{fs_util::*, test_util::*};
    use colmac::*;
    use itertools::Itertools;
    use rayon::prelude::*;
    use std::collections::HashSet;
    use std::u8;
    use walkdir::DirEntry;

    mod read_exact {
        use super::*;
        use std::io::Write;

        #[test]
        fn parametrized() {
            let out_dir = tmpdir!().unwrap();
            let tmpf = out_dir.path().join("f");

            {
                let mut f = fopen_w(&tmpf).unwrap();
                let data = drng_range(1024, 0, 100);
                f.write_all(&data[..]).unwrap();
            }

            vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 16, 32, 234, 981]
                .iter()
                .for_each(|count| {
                    let read = read_exact(*count, &mut fopen_r(&tmpf).unwrap()).unwrap();
                    assert_eq!(read.len(), *count);
                });
        }
    }

    mod subpath {
        use super::*;

        // path, root, expected
        fn test_data_no_panic<'a>() -> Vec<(&'a str, &'a str, &'a str)> {
            vec![
                // NOT root, empties
                ("", "", ""),
                ("a/o", "", "a/o"),
                // NOT root, no trailing slashes
                ("a/o/e/u", "a/o", "e/u"),
                // NOT root, one trailing slash
                ("a/o/e/u/", "a/o", "e/u"),
                ("a/o/e/u", "a/o/", "e/u"),
                // NOT root, trailing slashes
                ("a/o/e/u/", "a/o/", "e/u"),
                // root, no trailing slashes
                ("/a/o/e/u", "/a/o", "e/u"),
                // root, one trailing slash
                ("/a/o/e/u/", "/a/o", "e/u"),
                ("/a/o/e/u", "/a/o/", "e/u"),
                // root, trailing slashes
                ("/a/o/e/u/", "/a/o/", "e/u"),
                // just root
                ("/", "/", ""),
                ("/", "", "/"),
            ]
        }

        // path, root, expected
        fn test_data_panic<'a>() -> Vec<(&'a str, &'a str, &'a str)> {
            vec![
                // NOT root, empties
                ("", "/", ""),
                // NOT root, no trailing slashes
                ("a/o", "a/o/e/u", ""),
                // NOT root, one trailing slash
                ("a/o", "a/o/e/u/", ""),
                ("a/o/", "a/o/e/u", ""),
                // NOT root, trailing slashes
                ("a/o/", "a/o/e/u/", ""),
                // root, no trailing slashes
                ("/a/o", "/a/o/e/u", ""),
                // root, one trailing slash
                ("/a/o", "/a/o/e/u", ""),
                ("/a/o/", "/a/o/e/u", ""),
                // root, trailing slashes
                ("/a/o/", "/a/o/e/u/", ""),
            ]
        }

        fn result_expected<'a>(tuple: (&'a str, &'a str, &'a str)) -> (Option<PathBuf>, PathBuf) {
            let (path_str, root_str, expected_str) = tuple;
            let path = Path::new(path_str);
            let root = Path::new(root_str);
            let expected = Path::new(expected_str).to_path_buf();

            let result = subpath(path, root);
            (result, expected)
        }

        #[test]
        fn parametrized_success() {
            test_data_no_panic()
                .into_par_iter()
                .map(result_expected)
                .for_each(|(result_opt, expected)| {
                    assert_eq!(result_opt, Some(expected));
                });
        }

        #[test]
        fn parametrized_fail() {
            test_data_panic()
                .into_par_iter()
                .map(result_expected)
                .for_each(|(result_opt, _)| {
                    assert_eq!(result_opt, None);
                });
        }
    }

    #[test]
    fn iter_eq_str() {
        let data = vec![
            "",
            "*",
            "234",
            "RDZjpbyeUEVPb9RbF2C5WbQ3KhKRiMC1",
            "MDqXKdxp9bNpyDS0LE1FXBWCX6ui5FF8ZRsbDl7outwGEcE0VsaziLsfVkQDguSC",
        ];

        data.par_iter().for_each(|a| {
            data.par_iter().for_each(|b| {
                let a_chars = a.chars();
                let b_chars = b.chars();
                assert_eq!(iter_eq(a_chars, b_chars), a == b);
            })
        });
    }

    #[test]
    fn u8_u32_conversion_inverse() {
        drng_range(4 * 128, u8::MIN, u8::MAX)
            .into_iter()
            .chunks(4)
            .into_iter()
            .for_each(|chunk| {
                let u8s: Vec<u8> = chunk.collect();
                assert_eq!(u8s.len(), 4);
                let result = u32_to_u8s(u8s_to_u32(&u8s[..]));
                assert_eq!(result, u8s);
            });
    }
}
