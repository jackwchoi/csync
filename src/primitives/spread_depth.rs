use serde::{Deserialize, Serialize};
use std::ops::Deref;

///
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct SpreadDepth(u8);

///
impl Deref for SpreadDepth {
    type Target = u8;

    /// TODO find where the zstd level is set
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

///
impl SpreadDepth {
    ///
    #[inline]
    pub fn new(byte: u8) -> Self {
        Self(byte)
    }
}
