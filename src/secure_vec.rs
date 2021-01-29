use secstr::SecVec;
use serde::{
    de::{self, Deserializer, SeqAccess, Visitor},
    ser::{SerializeTupleStruct, Serializer},
    Deserialize, Serialize,
};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::iter::FromIterator;

/// The most commonly used concrete form.
pub type SecureBytes = SecureVec<u8>;

/// New-types
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct DerivedKey(pub CryptoSecureBytes);
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct InitialKey(pub CryptoSecureBytes);
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct RehashedKey(pub CryptoSecureBytes);
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct CryptoSecureBytes(pub SecureBytes);

///
/// # Comparison using `==`
///
/// `SecureVec` is a wrapper around `SecVec`, therefore comparing two instances of `SecureVec`
/// using `==` is a done in constant time, meaning TODO
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecureVec<T>(SecVec<T>)
where
    T: Copy + Eq + Hash;

///
impl<T> SecureVec<T>
where
    T: Copy + Eq + Hash,
{
    ///
    pub fn new(vec: Vec<T>) -> Self {
        Self(SecVec::new(vec))
    }

    ///
    pub fn unsecure(&self) -> &[T] {
        self.0.unsecure()
    }
}

///
impl<T> Hash for SecureVec<T>
where
    T: Copy + Eq + Hash,
{
    ///
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.unsecure().hash(state);
    }
}

///
impl<T> FromIterator<T> for SecureVec<T>
where
    T: Copy + Eq + Hash,
{
    ///
    fn from_iter<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = T>,
    {
        Self::new(iter.into_iter().collect::<Vec<_>>())
    }
}

///
impl Serialize for SecureBytes {
    ///
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut s = serializer.serialize_tuple_struct("SecureVec", 1)?;
        s.serialize_field(&self.0.unsecure().to_vec())?;
        s.end()
    }
}

///
impl<'de> de::Deserialize<'de> for SecureBytes {
    ///
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SecureVecVisitor;

        impl<'de> Visitor<'de> for SecureVecVisitor {
            type Value = SecureBytes;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct Duration")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<SecureBytes, V::Error>
            where
                V: SeqAccess<'de>,
            {
                let deserialized: Vec<u8> = seq.next_element()?.ok_or_else(|| de::Error::invalid_length(0, &self))?;
                Ok(SecureVec(SecVec::new(deserialized.to_vec())))
            }
        }

        const FIELDS: &'static [&'static str] = &["0"];
        deserializer.deserialize_struct("SecureVec", FIELDS, SecureVecVisitor)
    }
}

///
impl<T> From<&[T]> for SecureVec<T>
where
    T: Copy + Eq + Hash,
{
    ///
    fn from(vec: &[T]) -> SecureVec<T> {
        vec.to_vec().into()
    }
}
///
impl<T> From<Vec<T>> for SecureVec<T>
where
    T: Copy + Eq + Hash,
{
    ///
    fn from(vec: Vec<T>) -> SecureVec<T> {
        SecureVec::new(vec)
    }
}
///
impl From<String> for SecureBytes {
    ///
    fn from(string: String) -> SecureBytes {
        string.as_bytes().into()
    }
}
///
impl From<&str> for SecureBytes {
    ///
    fn from(string: &str) -> SecureBytes {
        string.as_bytes().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    ///
    mod serde_secure_vec {
        use super::*;
        use crate::util::*;

        ///
        macro_rules! test_gen {
            ( $fn_name:ident, $data:expr ) => {
                ///
                #[test]
                fn $fn_name() {
                    let original = SecureVec(SecVec::new($data));
                    let ser = &serialize(&original).unwrap().into();
                    let de: SecureBytes = deserialize(ser.unsecure()).unwrap();
                    assert_eq!(
                        de,
                        original,
                        "{:?} != {:?}",
                        original.0.unsecure(),
                        de.0.unsecure()
                    );
                }
            };
        }

        test_gen!(empty, vec![]);

        test_gen!(one1, vec![149]);
        test_gen!(one2, vec![196]);

        test_gen!(two1, vec![114, 91]);
        test_gen!(two2, vec![105, 37]);

        test_gen!(three, vec![187, 33, 87]);

        test_gen!(four, vec![188, 154, 4, 87]);
        test_gen!(eight, vec![120, 141, 52, 120, 126, 68, 112, 190]);

        test_gen!(
            ascii_bytes,
            b"uHpD7UwcrgZwYE6kQ00vEmeXXDgC3falE8jrNQJnaWjGEw7pgAhJ3nd9y5aUgBKN".to_vec()
        );

        test_gen!(
            rand_bytes,
            vec![
                147, 208, 170, 185, 140, 142, 213, 233, 22, 51, 190, 60, 31, 104, 76, 57, 57, 207, 126, 194, 163, 62, 218, 186,
                99, 28, 65, 235, 27, 2, 253, 174, 20, 212, 139, 15, 63, 176, 189, 90, 208, 78, 255, 208, 232, 42, 55, 33, 59,
                198, 57, 71, 164, 236, 219, 24, 215, 114, 235, 185, 21, 121, 192, 210, 88, 87, 144, 249, 209, 128, 135, 111,
                237, 103, 250, 25, 85, 148, 182, 56, 174, 210, 161, 165, 242, 238, 17, 156, 174, 107, 20, 223, 170, 244, 233,
                254, 130, 222, 205, 210, 195, 80, 142, 175, 34, 208, 55, 243, 160, 106, 187, 234, 251, 25, 236, 110, 84, 164,
                214, 32, 167, 209, 134, 34, 133, 180, 211, 4, 155, 186, 224, 107, 97, 148, 210, 1, 12, 222, 40, 228, 51, 217,
                132, 150, 119, 105, 210, 45, 156, 230, 197, 75, 222, 34, 96, 124, 71, 1, 215, 188, 234, 52, 89, 131, 102, 22,
                74, 206, 141, 52, 26, 21, 220, 3, 82, 242, 242, 203, 96, 218, 170, 180, 210, 143, 4, 243, 158, 252, 228, 31,
                217, 91, 6, 235, 75, 141, 51, 93, 130, 126, 46, 201, 164, 17, 124, 154, 14, 146, 219, 100, 229, 188, 93, 82,
                33, 186, 107, 106, 196, 211, 204, 249, 176, 156, 243, 34, 176, 177, 21, 152, 57, 20, 252, 59, 176, 14, 144, 7,
                147, 197, 198, 179, 48, 57, 63, 103, 249, 90, 200, 24, 197, 138, 69, 243, 109, 52
            ]
        );
    }
}
