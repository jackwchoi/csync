pub use crate::tests_e2e::util::*;

// # Parameters
//
// 1. `$mod_name`
// 1. `$key`
// 1. `$( , $arg )*`: string args to pass to the csync prorcess
macro_rules! generate_mod {
    //
    ( $mod_name:ident, $key:literal $( , $arg:literal )* ) => {
        //
        mod $mod_name {
            use super::*;

            //
            macro_rules! generate_test {
                ( $fn_name:ident, $pbuf_and_tmpd:expr ) => {
                    generate_success_body!(
                        $fn_name,
                        $pbuf_and_tmpd,
                        $key
                        $( , $arg )*
                    );
                };
            }

            //
            generate_suite!(generate_test);
        }
    }
}
