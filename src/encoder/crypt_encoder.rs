use crate::util::*;
use std::{
    io::{self, Read, Write},
    str::from_utf8,
};

/// This trait helps make the encoding logic more functional.
///
/// Since `CryptEncoder` itself implements the `Read` trait, any struct that
/// impls the `Read` trait can be wrapped by in an arbitrarily many layers
/// of `CryptEncoder`s. The goal is to string together encoders much like
/// function compopsition.
///
/// For example encrypting the compressed content of a file may look something like
/// `EncryptorAES::wrap(Compressor::wrap(some_file))`.
pub trait CryptEncoder<R>: Read
where
    R: Read,
{
    /// read all content to `target`
    fn read_all_to<W>(&mut self, target: &mut W) -> io::Result<usize>
    where
        W: Write,
    {
        // temp buffer to hold data
        let mut buffer = [0u8; BUFFER_SIZE];
        let mut count = 0;

        Ok(loop {
            // keep reading self to buffer until self is empty
            match self.read(&mut buffer[..])? {
                0 => {
                    // means we are done reading
                    target.flush()?;
                    break count;
                }
                bytes_read => {
                    let data = &buffer[0..bytes_read];
                    target.write_all(data)?;
                    count += bytes_read
                }
            }
        })
    }

    /// return the content as a vector
    fn as_vec(&mut self) -> io::Result<Vec<u8>> {
        let mut result = Vec::new();
        self.read_all_to(&mut result)?;
        Ok(result)
    }

    /// return the content as a string
    fn as_string(&mut self) -> io::Result<String> {
        let as_vec = self.as_vec()?;
        from_utf8(&as_vec).map(String::from).map_err(io_err)
    }
}

/// Compose multiple CryptEncoders, just like function composing.
///
/// # Parameters
///
/// 1. `root`: initial data to be encoded, which implements `std::io::Read`
/// 1. `crypt_encoder`: name of the struct to use, which implements `crate::encoder::crypt_encoder`
/// 1.
///
/// # Examples
///
/// ```
/// #[macro_use]
/// extern crate cryptor;
///
/// let data: Vec<u8> = (0..64).collect();                  // data to encode
/// let key_hash: &[u8] = hash("some password".as_bytes()); // hash of the passphrase
/// let init_vec: &[u8] = &[0; 16]                          // initialization vector for the encryption
///
/// // nested encoder which encrypts data, then encodes it using base64
/// let ciphertext = compose_encoders!(
///     data,
///     EncryptorAES => (&key_hash, Some(&init_vec)),
///     TextEncoder => &data_encoding::BASE64
/// )
/// .unwrap()
/// .as_string()
/// .unwrap();
/// ```
macro_rules! compose_encoders {
    ( $root:expr, $( $crypt_encoder:ident => $meta:expr ),* ) => {{
        let cryptor = Ok($root);
        $(
            let cryptor = match cryptor {
                Ok(c) => $crypt_encoder::new(c, $meta),
                Err(err) => Err(err),
            };
        )*
        cryptor
    }};
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{encoder::zstd::*, fs_util::*};
    use std::fs::File;
    use std::path::Path;

    fn first_bytes(filepath: &Path, num_bytes: usize) -> Vec<u8> {
        File::open(filepath)
            .unwrap()
            .bytes()
            .take(num_bytes)
            .map(Result::unwrap)
            .collect()
    }

    #[test]
    fn dropped_read_all_to_overwrites() {
        let dir = tmpdir!().unwrap();
        let filepath = dir.path().join("tempfile");
        let tmpf = || fopen_w(&filepath).unwrap();
        {
            let mut file = tmpf();
            file.write("abcd".as_bytes()).unwrap();
            file.flush().unwrap();
        }

        compose_encoders!(
            File::open("Cargo.toml").unwrap(),
            ZstdEncoder => None
        )
        .unwrap()
        .read_all_to(&mut tmpf())
        .unwrap();

        assert!(&first_bytes(&filepath, 4)[..] != b"abcd");
    }

    #[test]
    fn no_drop_read_all_to_does_not_overwrite() {
        let dir = tmpdir!().unwrap();
        let filepath = dir.path().join("tempfile");
        let tmpf = || fopen_w(&filepath).unwrap();

        let mut file = tmpf();
        file.write("abcdabcd".as_bytes()).unwrap();
        file.flush().unwrap();
        assert_eq!(&first_bytes(&filepath, 8)[..], b"abcdabcd");

        compose_encoders!(
            File::open("Cargo.toml").unwrap(),
            ZstdEncoder => None
        )
        .unwrap()
        .read_all_to(&mut file)
        .unwrap();

        assert_eq!(&first_bytes(&filepath, 8)[..], b"abcdabcd");
    }
}
