pub use crate::encoder::crypt_encoder::*;

use crate::{prelude::*, secure_vec::*};
use ring::hmac::{self, Algorithm, Context};
use std::io::{self, BufReader, Read};

///
pub struct HmacEncoder<R>
where
    R: Read,
{
    ctx: Context,
    buffer_opt: Option<CryptoSecureBytes>,
    source: BufReader<R>,
}

/// only sha512 is supported for now
impl<R> HmacEncoder<R>
where
    R: Read,
{
    ///
    pub fn new(source: R, key_hash_opt: (&CryptoSecureBytes, Option<Algorithm>)) -> CsyncResult<Self> {
        let (key_hash, alg_opt) = key_hash_opt;
        let alg = alg_opt.unwrap_or(hmac::HMAC_SHA512);
        Ok(Self {
            ctx: {
                let hmac_key = hmac::Key::new(alg, key_hash.0.unsecure());
                hmac::Context::with_key(&hmac_key)
            },
            source: BufReader::new(source),
            buffer_opt: Some(CryptoSecureBytes(vec![].into())),
        })
    }

    ///
    #[inline]
    pub fn get_result(&self) -> Option<CryptoSecureBytes> {
        self.buffer_opt.clone()
    }
}

// read 40 bits at a time, because base32 needs 5bit, whereas a byte is 8 bits
// read 5 bytes at a time
///
impl<R> Read for HmacEncoder<R>
where
    R: Read,
{
    ///
    fn read(&mut self, mut target: &mut [u8]) -> io::Result<usize> {
        match self.source.read(&mut target)? {
            0 => {
                self.buffer_opt = Some(CryptoSecureBytes(self.ctx.clone().sign().as_ref().to_vec().into()));
                Ok(0)
            }
            bytes_read => {
                self.ctx.update(&target[..bytes_read]);
                Ok(bytes_read)
            }
        }
    }
}

///
impl<R> CryptEncoder<R> for HmacEncoder<R>
where
    R: Read,
{
    ///
    #[inline]
    fn get_inner(self) -> Option<R> {
        Some(self.source.into_inner())
    }

    ///
    #[inline]
    fn get_inner_ref(&self) -> Option<&R> {
        None
    }
}
