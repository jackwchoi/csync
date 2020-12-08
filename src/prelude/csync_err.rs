pub use CsyncErr::*;

use crate::primitives::*;
use std::{
    fmt::{self, Display, Formatter},
    io,
    path::PathBuf,
};

///
pub type CsyncResult<T> = Result<T, CsyncErr>;

/// Enum used to classify different errors that `csync` can throw.
///
/// Each variant results in a unique exit code, which can be used for testing.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum CsyncErr {
    AuthenticationFail,                    // checksum verification failed for this file
    DecryptionOutdirIsNonempty(PathBuf),   // when decrypting, outdir must be empty
    HashSpecConflict,                      //
    IncrementalEncryptionDisabledForNow,   //
    InvalidSpreadDepth(usize),             // spread depth is outside of the allowed range
    MetadataLoadFailed(String),            // couldn't load this metadata file
    NonFatalReportFailed,                  //
    Other(String),                         // anything else
    OutdirIsNotDir(PathBuf),               // ...  decrypting ...
    PasswordConfirmationFail,              //
    PathContainsInvalidUtf8Bytes(PathBuf), //
    SerdeFailed,                           //
    SourceDoesNotExist(PathBuf),           //
    SourceDoesNotHaveFilename(PathBuf),    //
    SourceEqOutdir(PathBuf),               //
}

///
impl CsyncErr {
    /// Assign a unique exit code to each variant, mostly for testing purposes.
    ///
    /// DO NOT RELY ON THE EXACT NUMBERS, AS THEY MAY CHANGE IN THE FUTURE
    pub fn exit_code(&self) -> i32 {
        match self {
            AuthenticationFail => 32,
            DecryptionOutdirIsNonempty(_) => 33,
            HashSpecConflict => 34,
            IncrementalEncryptionDisabledForNow => 35,
            InvalidSpreadDepth(_) => 36,
            MetadataLoadFailed(_) => 37,
            NonFatalReportFailed => 38,
            Other(_) => 39,
            OutdirIsNotDir(_) => 40,
            PasswordConfirmationFail => 41,
            PathContainsInvalidUtf8Bytes(_) => 42,
            SerdeFailed => 43,
            SourceDoesNotExist(_) => 44,
            SourceDoesNotHaveFilename(_) => 45,
            SourceEqOutdir(_) => 46,
        }
    }
}

///
impl Display for CsyncErr {
    ///
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        //
        macro_rules! w {
            ( $( $arg:expr ),+ ) => {
                write!(f, $( $arg ),+)
            };
        }
        //
        match self {
            AuthenticationFail => w!("Authentication failed."),
            DecryptionOutdirIsNonempty(pbuf) => w!("Cannot decrypt to `--out={:?}` because it is not empty.", pbuf),
            HashSpecConflict => w!("Cannot specify the strength of the hash with params AND time."),
            InvalidSpreadDepth(depth) => w!("Spread depth `--spread={}` is not in the allowed range (0, 255]", depth),
            IncrementalEncryptionDisabledForNow => w!("Incremental Encryption is disabled for now"),
            MetadataLoadFailed(message) => w!("Could not load metadata file, password is prbs wrong: {}", message),
            NonFatalReportFailed => w!("Failed to report; is not fatal"),
            Other(desc) => w!("{}", desc),
            OutdirIsNotDir(pbuf) => w!("Cannot use `--out={:?}` because it is not a directory.", pbuf),
            PasswordConfirmationFail => w!("Could not confirm password"),
            PathContainsInvalidUtf8Bytes(pbuf) => w!("{:?} could not be converted to a string", pbuf),
            SerdeFailed => w!("(De)serialization failed"),
            SourceDoesNotExist(pbuf) => w!("Source does not exist under {:?}", pbuf),
            SourceDoesNotHaveFilename(pbuf) => w!("Source {:?} does not have a basename", pbuf),
            SourceEqOutdir(pbuf) => w!("Source cannot also be outdir: {:?}", pbuf),
        }
    }
}

///
macro_rules! csync_err {
    ( $variant:ident ) => {
        Err(CsyncErr::$variant)
    };
    ( $variant:ident, $( $field:expr ),* ) => {
        Err(CsyncErr::$variant($( $field ),*))
    };
}

/// TODO wait till try impl becomes stable
macro_rules! csync_unwrap_opt {
    ( $result:expr ) => {
        match $result {
            Some(x) => x,
            None => Err(CsyncErr::Other(format!("unwrapping a none")))?,
        }
    };
}

/// `impl std::error::Error -> CsyncErr`
impl<E> From<E> for CsyncErr
where
    E: std::error::Error,
{
    #[inline]
    fn from(err: E) -> Self {
        CsyncErr::Other(format!("{}", err))
    }
}

/// `CsyncErr -> std::io::Erorr`
impl From<CsyncErr> for io::Error {
    ///
    #[inline]
    fn from(err: CsyncErr) -> io::Error {
        io::Error::new(io::ErrorKind::Other, format!("{}", err))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rayon::prelude::*;
    use std::collections::HashSet;

    // check that the exit code of each variant is unique
    #[test]
    fn exit_codes_are_unique() {
        let variants = vec![
            AuthenticationFail,
            DecryptionOutdirIsNonempty(PathBuf::from("")),
            HashSpecConflict,
            IncrementalEncryptionDisabledForNow,
            InvalidSpreadDepth(3),
            MetadataLoadFailed("".to_string()),
            NonFatalReportFailed,
            Other("".to_string()),
            OutdirIsNotDir(PathBuf::from("")),
            PasswordConfirmationFail,
            PathContainsInvalidUtf8Bytes(PathBuf::from("")),
            SerdeFailed,
            SourceDoesNotExist(PathBuf::from("")),
            SourceDoesNotHaveFilename(PathBuf::from("")),
            SourceEqOutdir(PathBuf::from("")),
        ];
        // write it like this so that compilation fails when adding a new variant
        let exit_code_vec: Vec<_> = variants
            .par_iter()
            .filter(|v| match v {
                AuthenticationFail => true,
                DecryptionOutdirIsNonempty(_) => true,
                HashSpecConflict => true,
                IncrementalEncryptionDisabledForNow => true,
                InvalidSpreadDepth(_) => true,
                MetadataLoadFailed(_) => true,
                NonFatalReportFailed => true,
                Other(_) => true,
                OutdirIsNotDir(_) => true,
                PasswordConfirmationFail => true,
                PathContainsInvalidUtf8Bytes(_) => true,
                SerdeFailed => true,
                SourceDoesNotExist(_) => true,
                SourceDoesNotHaveFilename(_) => true,
                SourceEqOutdir(_) => true,
            })
            .map(CsyncErr::exit_code)
            .collect();

        let exit_code_set: HashSet<_> = exit_code_vec.iter().cloned().collect();
        assert_eq!(exit_code_vec.len(), exit_code_set.len());

        exit_code_set.into_iter().for_each(|exit_code| {
            assert!(0 < exit_code && exit_code < 256);
        });
    }
}
