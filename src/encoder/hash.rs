pub use crate::encoder::crypt_encoder::*;

use crate::{hasher::*, util::*};
use ring::digest;
use std::io::{self, BufReader, Read, Write};

pub struct HashEncoder<R>
where
    R: Read,
{
    buffer_cursor: usize,
    buffer_opt: Option<Vec<u8>>,
    source: BufReader<R>,
}

/// only sha512 is supported for now
impl<R> HashEncoder<R>
where
    R: Read,
{
    #[inline]
    pub fn new(source: R, _algorithm: Option<&digest::Algorithm>) -> io::Result<Self> {
        Ok(Self {
            source: BufReader::with_capacity(BUFFER_SIZE, source),
            buffer_opt: Some(vec![]),
            buffer_cursor: 0,
        })
    }

    #[inline]
    fn check_rep(&self) {
        debug_assert!(match &self.buffer_opt {
            Some(buffer) => buffer.len() == 0 || buffer.len() == 64,
            None => true,
        });
    }
}

// read 40 bits at a time, because base32 needs 5bit, whereas a byte is 8 bits
// read 5 bytes at a time
impl<R> Read for HashEncoder<R>
where
    R: Read,
{
    fn read(&mut self, mut target: &mut [u8]) -> io::Result<usize> {
        self.check_rep();
        // initialize buffer if we have to
        match &mut self.buffer_opt {
            // need to initialize the buffer
            Some(buffer) if buffer.len() == 0 => {
                let hash_vec = sha512_read(&mut self.source)?;
                debug_assert_eq!(hash_vec.len(), 64);
                self.buffer_opt = Some(hash_vec)
            }
            // has already been initalized
            _ => (),
        };
        self.check_rep();

        // write
        match &mut self.buffer_opt {
            // done
            None => Ok(0),
            // we have some buffer content
            Some(buffer) => match self.buffer_cursor {
                cursor if buffer.len() <= cursor => Ok(0),
                cursor => match target.write(&buffer[cursor..]) {
                    Ok(bytes_written) => {
                        self.buffer_cursor += bytes_written;
                        self.check_rep();
                        Ok(bytes_written)
                    }
                    Err(err) => Err(err),
                },
            },
        }
    }
}

impl<R> CryptEncoder<R> for HashEncoder<R> where R: Read {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{fs_util::*, util::*};
    use rayon::iter::ParallelBridge;
    use rayon::prelude::*;
    use walkdir::WalkDir;

    #[test]
    fn equivalent_to_sha512_read() {
        WalkDir::new("src/")
            .into_iter()
            .par_bridge()
            .map(Result::unwrap)
            .filter(|x| x.file_type().is_file())
            .for_each(|entry| {
                let f = || fopen_r(&entry.path()).unwrap();
                let through_encoders = compose_encoders!(
                    f(),
                    HashEncoder => None
                )
                .unwrap()
                .as_vec()
                .unwrap();
                let through_func = sha512_read(&mut f()).unwrap();
                assert_eq!(through_encoders, through_func);
            });
    }
}
