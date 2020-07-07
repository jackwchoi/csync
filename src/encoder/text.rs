pub use crate::encoder::crypt_encoder::*;

use crate::util::*;
use data_encoding::Encoding;
use data_encoding_macro::*;
use std::{
    cmp::min,
    collections::VecDeque,
    io::{self, BufReader, Read},
};

pub const BASE32PATH: Encoding = new_encoding! {
    symbols: "abcdefghijklmnopqrstuvwxyz012345",
    padding: '_',
};

fn size_block(encoding: &Encoding) -> usize {
    // check that the encoding has 2^n number of symbols for some n
    let symbol_count = encoding.specification().symbols.len() as f64;
    let symbol_count_log2 = symbol_count.log2();
    debug_assert!(symbol_count_log2.fract() < 1e-10); // make sure it's int

    (symbol_count_log2 as usize) * 8
}

#[inline]
pub fn base32path<R>(readable: R) -> io::Result<String>
where
    R: Read,
{
    TextEncoder::new(readable, &BASE32PATH)?.as_string()
}

/// Customizable binary-to-text encoding
pub struct TextEncoder<R>
where
    R: Read,
{
    // encoding: Encoding, // what does the acutal encoding
    encoder: Box<dyn Fn(&[u8]) -> io::Result<Vec<u8>>>,
    block_size: usize, // min number of input bytes that encode to a pad-less output
    source: BufReader<R>,

    // buffers to hold leftovers from ...
    src_buf: VecDeque<u8>, // input bytes from the source
    enc_buf: VecDeque<u8>, // encoded output bytes

    // `src_buf_pull_size` is the max number of bytes we can pull from `src_buf` and transfer the
    // encoded content to enc_buf, without forcing `enc_buf` to resize
    src_buf_pull_size: usize, // ... `src_buf` ...
}

impl<R> TextEncoder<R>
where
    R: Read,
{
    pub fn new(source: R, encoding: &Encoding) -> io::Result<Self> {
        let encoding = encoding.clone();
        let block_size = size_block(&encoding);
        TextEncoder::new_custom(
            source,
            Box::new(move |data: &[u8]| Ok(Vec::from(encoding.encode(data).as_bytes()))),
            block_size,
        )
    }

    ///
    ///
    /// # Paramters
    ///
    /// 1. `source`: some struct that impl's the `std::io::Read` trait, from which the unencoded
    ///    data will be read.
    /// 1. `encoding`
    /// 1. `encoder`:
    /// 1. `encoding`
    pub fn new_custom(source: R, encoder: Box<dyn Fn(&[u8]) -> io::Result<Vec<u8>>>, block_size: usize) -> io::Result<Self> {
        // assuming that pulling happens when size < block size,
        //
        // base32 = 5 -> 8, so shuold only pull bufsize * 5/8
        let src_buf_pull_size = BUFFER_SIZE * block_size / 8;

        Ok(TextEncoder {
            block_size,
            encoder,
            source: BufReader::with_capacity(BUFFER_SIZE, source),
            enc_buf: VecDeque::with_capacity(BUFFER_SIZE),
            src_buf: VecDeque::with_capacity(BUFFER_SIZE),
            src_buf_pull_size,
        })
    }

    /// # Returns
    ///
    /// How many bytes were pulled into `self.src_buf`. 0 implies that we have reached the end of
    /// `self.source`.
    fn replenish_src_buf(&mut self) -> io::Result<usize> {
        debug_assert!(self.src_buf.len() < self.block_size);
        let mut buffer = [0u8; BUFFER_SIZE / 2];
        let bytes_read = self.source.read(&mut buffer[..])?;
        (&buffer[..bytes_read]).iter().for_each(|byte| self.src_buf.push_back(*byte));
        Ok(bytes_read)
    }

    /// # Returns
    ///
    /// How many bytes were pulled into `self.enc_buf`. 0 implies that we have reached the end of
    /// `self.source`.
    fn replenish_enc_buf(&mut self) -> io::Result<usize> {
        let block_count = self.src_buf.len() / self.block_size;
        let bytes_to_pull = match block_count {
            // this implies that we
            0 => self.src_buf.len() + self.replenish_src_buf()?,
            _ => block_count * self.block_size, // bytes
        };

        let bytes_to_pull = min(bytes_to_pull, self.src_buf_pull_size);
        debug_assert!(bytes_to_pull <= self.src_buf.len());

        match bytes_to_pull {
            0 => Ok(0), // done reading
            _ => {
                let bytes: Vec<u8> = (0..bytes_to_pull)
                    .map(|_| self.src_buf.pop_front())
                    .map(Option::unwrap)
                    .collect();

                Ok((self.encoder)(&bytes[..])?.iter().map(|b| self.enc_buf.push_back(*b)).count())
            }
        }
    }
}

// read 40 bits at a time, because base32 needs 5bit, whereas a byte is 8 bits
// read 5 bytes at a time
impl<R> Read for TextEncoder<R>
where
    R: Read,
{
    fn read(&mut self, target: &mut [u8]) -> io::Result<usize> {
        // try pushing enc buf
        if self.enc_buf.len() == 0 {
            // try populating enc_buf
            if self.src_buf.len() == 0 {
                self.replenish_src_buf()?;
            }
            self.replenish_enc_buf()?;
        }

        // transfer as much as possible from enc_buf to target
        match target.len() {
            0 => Ok(0), // we're done can't write any
            target_capacity => {
                // cannot write more than target's capacity or what's in enc buf
                let num_bytes_to_write = min(self.enc_buf.len(), target_capacity);
                Ok((0..num_bytes_to_write)
                    .map(|_| self.enc_buf.pop_front())
                    .map(Option::unwrap)
                    .enumerate()
                    .map(|(i, byte)| target[i] = byte)
                    .count())
            }
        }
    }
}

impl<R> CryptEncoder<R> for TextEncoder<R> where R: Read {}

///////////////////////////////////////////////////////////////

/// Customizable binary-to-text encoding
pub struct TextDecoder<R>
where
    R: Read,
{
    decoder: TextEncoder<R>,
}

impl<R> TextDecoder<R>
where
    R: Read,
{
    pub fn new(source: R, encoding: &Encoding) -> io::Result<Self> {
        let encoding = encoding.clone();
        let block_size = size_block(&encoding);
        Ok(TextDecoder {
            decoder: TextEncoder::new_custom(
                source,
                Box::new(move |data| Ok(encoding.decode(data).map_err(io_err)?.into_iter().collect())),
                block_size,
            )?,
        })
    }
}

impl<R> Read for TextDecoder<R>
where
    R: Read,
{
    fn read(&mut self, target: &mut [u8]) -> io::Result<usize> {
        self.decoder.read(target)
    }
}

impl<R> CryptEncoder<R> for TextDecoder<R> where R: Read {}

#[cfg(test)]
mod tests {
    use super::*;
    use rayon::prelude::*;

    mod encoder {
        use super::*;

        mod base16 {
            use super::*;
            use std::str;

            fn get_test_data<'a>() -> Vec<(&'a str, &'a str)> {
                vec![
                    ("", ""),
                    ("a", "61"),
                    ("b", "62"),
                    ("ab", "6162"),
                    (
                        "asoidjhxlkdjfad;:| !@$#^&*(_][",
                        "61736F69646A68786C6B646A6661643B3A7C20214024235E262A285F5D5B",
                    ),
                ]
            }

            #[test]
            fn parametrized() {
                get_test_data().into_par_iter().for_each(|(input, expected)| {
                    let input_bytes = input.as_bytes();
                    let result = TextEncoder::new(input_bytes, &data_encoding::HEXUPPER)
                        .unwrap()
                        .as_string()
                        .unwrap();

                    assert_eq!(&result[..], expected);
                });
            }
        }

        mod base32 {
            use super::*;
            use std::str;

            fn get_test_data<'a>() -> Vec<(&'a str, &'a str)> {
                // generated with base32 in GNU coreutils
                vec![
                    ("a", "ME======"),
                    ("b", "MI======"),
                    ("ab", "MFRA===="),
                    ("abc", "MFRGG==="),
                    ("abcd", "MFRGGZA="),
                    (
                        "asoidjhxlkdjfad;:| !@$#^&*(_][",
                        "MFZW62LENJUHQ3DLMRVGMYLEHM5HYIBBIASCGXRGFIUF6XK3",
                    ),
                ]
            }

            #[test]
            fn parametrized() {
                get_test_data().into_par_iter().for_each(|(input, expected)| {
                    let input_bytes = input.as_bytes();
                    let result = TextEncoder::new(input_bytes, &data_encoding::BASE32)
                        .unwrap()
                        .as_string()
                        .unwrap();

                    assert_eq!(&result[..], expected);
                });
            }
        }

        mod base32path {
            use super::*;
            use std::str;

            fn get_test_data<'a>() -> Vec<(&'a str, &'a str)> {
                // generated with base32 in GNU coreutils
                vec![
                    ("a", "me______"),
                    ("b", "mi______"),
                    ("ab", "mfra____"),
                    ("abc", "mfrgg___"),
                    ("abcd", "mfrggza_"),
                    (
                        "asoidjhxlkdjfad;:| !@$#^&*(_][",
                        "mfzw40lenjuhq1dlmrvgmylehm3hyibbiascgxrgfiuf4xk1",
                    ),
                ]
            }

            #[test]
            fn parametrized() {
                get_test_data().into_par_iter().for_each(|(input, expected)| {
                    let input_bytes = input.as_bytes();
                    let result = base32path(input_bytes).unwrap();

                    assert_eq!(&result[..], expected);
                });
            }
        }

        mod base64 {
            use super::*;
            use std::str;

            fn get_test_data<'a>() -> Vec<(&'a str, &'a str)> {
                // generated with base64 in GNU coreutils
                vec![
                    ("a", "YQ=="),
                    ("b", "Yg=="),
                    ("ab", "YWI="),
                    ("abc", "YWJj"),
                    ("abcd", "YWJjZA=="),
                    ("asoidjhxlkdjfad;:| !@$#^&*(_][", "YXNvaWRqaHhsa2RqZmFkOzp8ICFAJCNeJiooX11b"),
                ]
            }

            #[test]
            fn parametrized() {
                get_test_data().into_par_iter().for_each(|(input, expected)| {
                    let input_bytes = input.as_bytes();
                    let result = TextEncoder::new(input_bytes, &data_encoding::BASE64)
                        .unwrap()
                        .as_string()
                        .unwrap();

                    assert_eq!(&result[..], expected);
                });
            }
        }
    }

    mod decoder {
        use super::*;

        mod base16 {
            use super::*;

            fn get_test_data<'a>() -> Vec<(&'a str, &'a str)> {
                vec![
                    ("", ""),
                    ("a", "61"),
                    ("b", "62"),
                    ("ab", "6162"),
                    (
                        "asoidjhxlkdjfad;:| !@$#^&*(_][",
                        "61736F69646A68786C6B646A6661643B3A7C20214024235E262A285F5D5B",
                    ),
                ]
            }

            #[test]
            fn parametrized() {
                get_test_data().into_par_iter().for_each(|(expected, input)| {
                    let input_bytes = input.as_bytes();
                    let result = TextDecoder::new(input_bytes, &data_encoding::HEXUPPER)
                        .unwrap()
                        .as_string()
                        .unwrap();

                    assert_eq!(&result[..], expected);
                });
            }
        }

        mod base32 {
            use super::*;

            fn get_test_data<'a>() -> Vec<(&'a str, &'a str)> {
                // generated with base32 in GNU coreutils
                vec![
                    ("a", "ME======"),
                    ("b", "MI======"),
                    ("ab", "MFRA===="),
                    ("abc", "MFRGG==="),
                    ("abcd", "MFRGGZA="),
                    (
                        "asoidjhxlkdjfad;:| !@$#^&*(_][",
                        "MFZW62LENJUHQ3DLMRVGMYLEHM5HYIBBIASCGXRGFIUF6XK3",
                    ),
                ]
            }

            #[test]
            fn parametrized() {
                get_test_data().into_par_iter().for_each(|(expected, input)| {
                    let input_bytes = input.as_bytes();
                    let result = TextDecoder::new(input_bytes, &data_encoding::BASE32)
                        .unwrap()
                        .as_string()
                        .unwrap();

                    assert_eq!(&result[..], expected);
                });
            }
        }

        mod base64 {
            use super::*;

            fn get_test_data<'a>() -> Vec<(&'a str, &'a str)> {
                // generated with base64 in GNU coreutils
                vec![
                    ("a", "YQ=="),
                    ("b", "Yg=="),
                    ("ab", "YWI="),
                    ("abc", "YWJj"),
                    ("abcd", "YWJjZA=="),
                    ("asoidjhxlkdjfad;:| !@$#^&*(_][", "YXNvaWRqaHhsa2RqZmFkOzp8ICFAJCNeJiooX11b"),
                ]
            }

            #[test]
            fn parametrized() {
                get_test_data().into_par_iter().for_each(|(expected, input)| {
                    let input_bytes = input.as_bytes();
                    let result = TextDecoder::new(input_bytes, &data_encoding::BASE64)
                        .unwrap()
                        .as_string()
                        .unwrap();

                    assert_eq!(&result[..], expected);
                });
            }
        }
    }
}
