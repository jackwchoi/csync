pub use crate::encoder::crypt_encoder::*;

use crate::prelude::*;
use std::io::{self, BufReader, Read};
use zstd::stream::read::{Decoder, Encoder};

// encoder does all the work so bare bones
///
pub struct ZstdEncoder<R>
where
    R: Read,
{
    encoder: Encoder<BufReader<R>>,
}

//
///
impl<R> ZstdEncoder<R>
where
    R: Read,
{
    ///
    pub fn new(source: R, opt_level: Option<u8>) -> CsyncResult<Self> {
        let level: u8 = opt_level.unwrap_or(DEFAULT_ZSTD_LEVEL);
        assert!(level <= 22);

        Ok(Self {
            encoder: Encoder::new(source, level as i32)?,
        })
    }
}

// just read from zstd encoder
///
impl<R> Read for ZstdEncoder<R>
where
    R: Read,
{
    ///
    #[inline]
    fn read(&mut self, target: &mut [u8]) -> io::Result<usize> {
        self.encoder.read(target)
    }
}

///
impl<R> CryptEncoder<R> for ZstdEncoder<R> where R: Read {}

//////////////////////////////////////////////////////

///
pub struct ZstdDecoder<R>
where
    R: Read,
{
    decoder: Decoder<BufReader<R>>,
}

///
impl<R> ZstdDecoder<R>
where
    R: Read,
{
    ///
    pub fn new(source: R, _unused: Option<u8>) -> CsyncResult<Self> {
        Ok(Self {
            decoder: Decoder::new(source)?,
        })
    }
}

///
impl<R> Read for ZstdDecoder<R>
where
    R: Read,
{
    ///
    #[inline]
    fn read(&mut self, target: &mut [u8]) -> io::Result<usize> {
        self.decoder.read(target)
    }
}

///
impl<R> CryptEncoder<R> for ZstdDecoder<R> where R: Read {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::*;
    use rayon::{iter::ParallelBridge, prelude::*};

    ///
    fn gen(num_bits: u8) -> Vec<u8> {
        drng_range(1 << num_bits, 32, 126)
    }

    ///
    fn test_data() -> Vec<Vec<u8>> {
        vec![gen(12), gen(13), gen(14), gen(15)]
    }

    ///
    #[test]
    fn parametrized() {
        test_data().into_par_iter().for_each(|input_bytes| {
            let compressed = ZstdEncoder::new(&input_bytes[..], None).unwrap().as_vec().unwrap();

            let compressed_len = compressed.len() as f64;
            let input_len = input_bytes.len() as f64;
            assert!(compressed_len < input_len * 0.9);
        });
    }

    // make sure that f x = Decoder Encoder x = x
    ///
    #[test]
    fn parametrized_inverse() {
        (10..15)
            .map(|shl_by| 1 << shl_by)
            .par_bridge()
            .map(|num_bits| drng_range(num_bits, 32, 126))
            .for_each(|input_bytes| {
                let result = compose_encoders!(
                    &input_bytes[..],
                    ZstdEncoder => None,
                    ZstdDecoder => None
                )
                .unwrap()
                .as_vec()
                .unwrap();

                assert_eq!(input_bytes, result);
            });
    }
}
