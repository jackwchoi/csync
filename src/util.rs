use crate::{prelude::*, secure_vec::*};
use std::{
    convert::Into,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

///
pub fn adjust_value(value: f64, base_unit: &str) -> (String, String) {
    let (adjusted, unit) = match value {
        v if value < 1e03 => (v, format!(" {}", base_unit)),
        v if value < 1e06 => (v / 1e03, format!("K{}", base_unit)),
        v if value < 1e09 => (v / 1e06, format!("M{}", base_unit)),
        v if value < 1e12 => (v / 1e09, format!("G{}", base_unit)),
        v if value < 1e15 => (v / 1e12, format!("T{}", base_unit)),
        v if value < 1e18 => (v / 1e15, format!("P{}", base_unit)),
        v => (v, format!("many {}", base_unit)),
    };
    let adjusted_value = format!("{:.3}", adjusted);
    (adjusted_value, unit)
}

/// # Returns
///
/// The content of `defaultable_opt` if it exists.
///
/// Returns the default value if not present.
#[inline]
pub fn unwrap_or_default<D>(defaultable_opt: Option<D>) -> D
where
    D: Default,
{
    defaultable_opt.unwrap_or(Default::default())
}

///
#[inline]
pub fn serialize<'a, T>(strct: &'a T) -> CsyncResult<impl serde::Deserialize<'a> + Into<SecureBytes> + AsRef<[u8]>>
where
    T: std::fmt::Debug + serde::Serialize,
{
    match bincode::serialize(strct) {
        Ok(ser) => Ok(ser),
        Err(_) => csync_err!(SerdeFailed),
    }
}

///
#[inline]
pub fn deserialize<'a, T>(bytes: &'a [u8]) -> CsyncResult<T>
where
    T: std::fmt::Debug + serde::Deserialize<'a>,
{
    match bincode::deserialize(bytes) {
        Ok(de) => Ok(de),
        Err(_) => csync_err!(SerdeFailed),
    }
}

/// Read bytes from `r` and write them to `buf`, up to but not including the first occurrence
/// `delim` in the sequence.
///
/// For example if `r` contains the bytes `[10, 20, 30, 10, 20, 30]`, and `delim == 30`, the
/// first 3 bytes will be consumed from `r` and `[10, 20]` will be written to `buf`.
///
/// # Parameters
///
/// 1. `r`:
/// 1. `delim`:
/// 1. `buf`:
///
/// # Returns
///
/// Number of bytes read from `r`.
///
/// Taken from https://doc.rust-lang.org/src/std/io/mod.rs.html#1701 and adjusted.
pub fn read_until<BR, W>(r: &mut BR, delim: u8, buf: &mut W) -> std::io::Result<usize>
where
    BR: std::io::BufRead,
    W: std::io::Write,
{
    let mut read = 0;
    loop {
        let (done, used) = {
            // number of bytes the call to `fill_buf` grabbed
            let available = match r.fill_buf() {
                Ok(bytes) => bytes,
                Err(ref err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(err) => break Err(err),
            };
            // search for `delim` within `available`
            match memchr::memchr(delim, available) {
                // `available[i] == delim`
                Some(i) => {
                    buf.write_all(&available[..i])?;
                    (true, i + 1)
                }
                None => {
                    buf.write_all(&available[..])?;
                    (false, available.len())
                }
            }
        };

        r.consume(used);
        read += used;
        if done || used == 0 {
            break Ok(read);
        }
    }
}

/// # Returns
///
/// If `path = root.join(rel_path)` then `Some(rel_path)`, `None` otherwise.
pub fn subpath<P1, P2>(path: P1, root: P2) -> Option<PathBuf>
where
    P1: AsRef<Path>,
    P2: AsRef<Path>,
{
    let root_comps_len = root.as_ref().components().count();
    let without_root = match path.as_ref().starts_with(&root) {
        true => Some(path.as_ref().components().skip(root_comps_len).collect()),
        false => None,
    };

    // sanity check
    debug_assert!(match &without_root {
        Some(sub_p) => &root.as_ref().join(sub_p) == path.as_ref(),
        None => true,
    });

    without_root
}

/// # Returns
///
/// If `path = root.join(rel_path)` then `Some( basename(root).join(rel_path) )`, `None` otherwise.
pub fn subpath_par<P1, P2>(path: P1, root: P2) -> Option<PathBuf>
where
    P1: AsRef<Path>,
    P2: AsRef<Path>,
{
    subpath(path, &root).map(|rel_path| {
        let root_basename = Path::new(root.as_ref().file_name().unwrap());
        root_basename.join(rel_path)
    })
}

/// Conversion from `&Path` to `String` in one shot.
#[inline]
pub fn path_as_string<P>(path: P) -> Option<String>
where
    P: AsRef<Path>,
{
    path.as_ref().as_os_str().to_str().map(String::from)
}

///
#[inline]
pub fn start_timer() -> Instant {
    Instant::now()
}

///
#[inline]
pub fn end_timer(time: &Instant) -> Duration {
    time.elapsed()
}

///
macro_rules! time {
    ( $code:expr ) => {
        time!(false, "", $code)
    };
    ( $verbose:expr, $message:expr, $code:expr ) => {{
        if $verbose {
            eprint!("\n{}...", $message)
        };
        let start = crate::util::start_timer();
        let result = { $code };
        let elapsed = crate::util::end_timer(&start);

        if $verbose {
            eprintln!(" took {:?}", elapsed);
        }
        (result, elapsed)
    }};
}

///
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

///
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

/// read exactly `count` number of bytes from src
/// TODO optimize using tricks in read_until?
pub fn read_exact<R>(count: usize, src: &mut R) -> CsyncResult<Vec<u8>>
where
    R: std::io::Read,
{
    let mut reservoir: Vec<u8> = Vec::with_capacity(count);
    let mut buffer = vec![0u8; count];

    loop {
        match count - reservoir.len() {
            0 => break Ok(reservoir),
            bytes_left => match src.read(&mut buffer[..bytes_left])? {
                0 => break csync_err!(Other, format!("there was less than {:?} bytes", count)),
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

    ///
    mod read_exact {
        use super::*;
        use std::io::Write;

        ///
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

    ///
    mod subpath {
        use super::*;

        // path, root, expected
        ///
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

        ///
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

        ///
        fn result_expected<'a>(tuple: (&'a str, &'a str, &'a str)) -> (Option<PathBuf>, PathBuf) {
            let (path_str, root_str, expected_str) = tuple;
            let path = Path::new(path_str);
            let root = Path::new(root_str);
            let expected = Path::new(expected_str).to_path_buf();

            let result = subpath(path, root);
            (result, expected)
        }

        ///
        #[test]
        fn parametrized_success() {
            test_data_no_panic()
                .into_par_iter()
                .map(result_expected)
                .for_each(|(result_opt, expected)| {
                    assert_eq!(result_opt, Some(expected));
                });
        }

        ///
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

    ///
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

    ///
    #[test]
    fn u8_u32_conversion_inverse() {
        drng_range(4 * 128, std::u8::MIN, std::u8::MAX)
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
