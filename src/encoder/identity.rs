pub use crate::encoder::crypt_encoder::*;

use crate::prelude::*;
use std::io::{self, BufRead, BufReader, Read};

///
pub struct IdentityEncoder<R>
where
    R: Read,
{
    src: BufReader<R>,
}

/// only sha512 is supported for now
impl<R> IdentityEncoder<R>
where
    R: Read,
{
    ///
    pub fn new(src: R, _unused: Option<usize>) -> CsyncResult<Self> {
        Ok(Self {
            src: BufReader::new(src),
        })
    }
}

///
impl<R> Read for IdentityEncoder<R>
where
    R: Read,
{
    ///
    fn read(&mut self, mut target: &mut [u8]) -> io::Result<usize> {
        self.src.read(&mut target)
    }
}

///
impl<R> BufRead for IdentityEncoder<R>
where
    R: Read,
{
    ///
    fn consume(&mut self, amt: usize) {
        self.src.consume(amt)
    }

    ///
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        self.src.fill_buf()
    }
}

///
impl<R> CryptEncoder<R> for IdentityEncoder<R> where R: Read {}
