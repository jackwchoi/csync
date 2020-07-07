#[macro_use]
extern crate static_assertions;
extern crate data_encoding_macro;

#[macro_use]
mod fs_util;
#[macro_use]
mod util;
#[macro_use]
mod hasher;
#[macro_use]
mod rand_util;
#[macro_use]
mod encoder;
#[macro_use]
mod test_util;

mod clargs;
mod crypt;

use std::path::PathBuf;
use structopt::StructOpt;

assert_cfg!(unix, "Only Unix systems are supported for now");

fn main() {
    let opts = clargs::Opts::from_args();
    println!("{:#?}", opts);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_is_unix() {
        assert!(cfg!(unix));
    }
}
