use crate::{prelude::*, test_util::*, tests_e2e::util::*, util::*};

macro_rules! incremental_build_with_diff_keys {
    ( $fn_name:ident, $sources:expr, $key_1:literal, $key_2:literal ) => {
        #[test]
        fn $fn_name() {
            let source = tmpdir!().unwrap();
            let source = source.path();

            $sources.into_iter().for_each(|src: &str| {
                cp_r(src, &source);
            });

            let outdir = tmpdir!().unwrap();
            let outdir = outdir.path();

            macro_rules! encrypt {
                ( $exit_code:expr, $key:expr ) => {
                    check_encrypt!(
                        $exit_code,
                        &source,
                        &outdir,
                        &$key,
                        &$key,
                        path_as_str!(source),
                        &format!("-o {}", path_as_str!(&outdir))
                    )
                };
            }

            //
            let exit_code = 0;
            encrypt!(exit_code, $key_1);

            //
            let exit_code = CsyncErr::AuthenticationFail.exit_code();
            encrypt!(exit_code, $key_2);
        }
    };
}

incremental_build_with_diff_keys!(
    incremental_build_diff_key_nested_dirs_and_files,
    vec!["src/"],
    "9SrrPb1UNNqlauatXShO6u0bO5GdYQJmUUmpHdRki6u2FHqUFn6nuPX2SUIwNp17",
    "j068TeybDZB1bELyynhIgDT3GxSvHiK78ukNSGSyfPqm997FH3nXE4SJGpBZFegX"
);

incremental_build_with_diff_keys!(
    incremental_build_diff_key_empty,
    vec![],
    "wmI0Xi3h7Z6c4qM5Liuk5MLGjlEX0h1aQvzPxk5mwWkNfVJF4vyc04HEbYHctQTO",
    "dHTALSHPVIRa9qxCzjEuwlNHuLLNCcHd1O6m1NKkYnJdVFMvDiKkbTYuwVCrYcg7"
);

incremental_build_with_diff_keys!(
    incremental_build_diff_key_file,
    vec!["Cargo.toml"],
    "KPOUpuFhQaPS0Q5TkU8yqMP5De1KLdbccLJXgsRjdlr0KtES4pqNDwMpJDAbXI3B",
    "piPpu6Vd2wAN09ZfY1eN8UX4B2jLNIOnNFErrBPKI5jPgZ5dMZ8CoP54BezjdPRR"
);
