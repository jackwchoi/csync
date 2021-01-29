use serde::{Deserialize, Serialize};

///
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum AuthenticatorSpec {
    HmacSha512,
    // TODO Poly
}

///
impl Default for AuthenticatorSpec {
    fn default() -> Self {
        Self::HmacSha512
    }
}
