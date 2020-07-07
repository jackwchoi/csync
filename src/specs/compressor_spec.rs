use serde::{Deserialize, Serialize};

///
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum CompressorSpec {
    Zstd { level: u8 },
    // TODO gzip
}

///
impl Default for CompressorSpec {
    #[inline]
    fn default() -> Self {
        Self::Zstd { level: 3 }
    }
}
