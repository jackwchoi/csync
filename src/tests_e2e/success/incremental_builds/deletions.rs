use crate::tests_e2e::success::incremental_builds::util::*;
use maplit::*;

// ./
// ├── d0/
// │  ├── d1/
// │  │  ├── d2/
// │  │  └── f1
// │  ├── d4/
// │  │  ├── f3
// │  │  └── f4
// │  ├── d5/
// │  │  ├── d6/
// │  │  └── d7/
// │  └── f2
// ├── d3/
// └── f0
//
// ./d0/
// ./d0/d1/
// ./d0/d1/d2/
// ./d0/d1/f1
// ./d0/d4/
// ./d0/d4/f3
// ./d0/d4/f4
// ./d0/d5/"
// ./d0/d5/d6
// ./d0/d5/d7
// ./d0/d5/d8
// ./d0/f2
// ./d3/
// ./f0

macro_rules! paths {
    () => {
        vec![
            "d0/",
            "d0/d1/",
            "d0/d1/d2/",
            "d0/d1/f1",
            "d0/d4/",
            "d0/d4/f3",
            "d0/d4/f4",
            "d0/d5/",
            "d0/d5/d6/",
            "d0/d5/d7/",
            "d0/d5/d8/",
            "d0/f2",
            "d3/",
            "f0",
        ]
    };
}

//
generate_incremental_build_success_test_func!(
    delete_nothing,
    tmpdir!().unwrap(),
    paths!(),
    hashset! {},
    "dcq100mDxK2f1slccaE5u6r49GrH5X3KjTgBXQJGEhaKJZk8EWqNVVTw5t9g7qqL"
);
//
generate_incremental_build_success_test_func!(
    delete_toplevel_file,
    tmpdir!().unwrap(),
    paths!(),
    hashset! {delete!("f0")},
    "80G3L0ybIYpzgdHbFS3YXGCvCi1e8Tc0stuQ26T8T7mKvttF0wxvoMcYNRiFSpKJ"
);
//
generate_incremental_build_success_test_func!(
    delete_toplevel_empty_dir,
    tmpdir!().unwrap(),
    paths!(),
    hashset! {delete!("d3/")},
    "aQYr0DxQbYsGxA5eQPlbdwd78lXYn8uyixSd7ci59KBMRFAjAi3HCtt0z1KvYT1u"
);
//
generate_incremental_build_success_test_func!(
    nested_empty_dir,
    tmpdir!().unwrap(),
    paths!(),
    hashset! {delete!("d0/d1/d2/")},
    "B9WlmZZbRThjGwUyypFz33jUcvxRKdH827X3PKzdFxODpaaTFvFRh3HvgW418fTU"
);
//
generate_incremental_build_success_test_func!(
    nested_file,
    tmpdir!().unwrap(),
    paths!(),
    hashset! {delete!("d0/d1/f1")},
    "Jgc99KQ2CifNNeFpTxzMfiAxMNw6aHNvNYq7hGRfMW4wU3fuPPa4XUF1NdU3LQ5s"
);
//
generate_incremental_build_success_test_func!(
    nested_dir_of_files,
    tmpdir!().unwrap(),
    paths!(),
    hashset! {delete!("d0/d4/"), delete!("d0/d4/f3"), delete!("d0/d4/f4")},
    "FpNquL7nH1ycnsWeMvvyUUH1gwRmdUzp5KIYWc45z9mDmlHrgir2LYir18BoNesI"
);
//
generate_incremental_build_success_test_func!(
    nested_dir_of_empty_dirs,
    tmpdir!().unwrap(),
    paths!(),
    hashset! {
        delete!("d0/d5/"),
        delete!("d0/d5/d6/"),
        delete!("d0/d5/d7/"),
        delete!("d0/d5/d8/")
    },
    "FpNquL7nH1ycnsWeMvvyUUH1gwRmdUzp5KIYWc45z9mDmlHrgir2LYir18BoNesI"
);
//
generate_incremental_build_success_test_func!(
    nested_dir_of_all,
    tmpdir!().unwrap(),
    paths!(),
    hashset! {
        delete!("d0/"),
        delete!("d0/d1/"),
        delete!("d0/d1/d2/"),
        delete!("d0/d1/f1"),
        delete!("d0/d4/"),
        delete!("d0/d4/f3"),
        delete!("d0/d4/f4"),
        delete!("d0/d5/"),
        delete!("d0/d5/d6/"),
        delete!("d0/d5/d7/"),
        delete!("d0/d5/d8/"),
        delete!("d0/f2")
    },
    "b1VV1nNCmwPKS2cIu8CFEHgg8HsSa1AOtfhjfzCNr2gEfmPaSrmOc33N1slcb5Im"
);

/*
"FLyPjJfFfRqjZsiEudkbJDcxtWntvVPtcgyYzF9Gz7OcvKWSU34XQEePvwyJXuKX"
"xOsHKomPrPsdIuf7lynKZaZKQrv60vHQ9WkYDvPWSgfJrDEm7T2A4izPvHSwwdOH"
"wHxZS6khMOgo80J3JfepWPIG1ENuvQsfoMezDCQhBvVHy1MicBG16cnpBMJZn9sS"
"wLT9WcAmEg4ma3hOpz72Fj0TkIi1h2jQGWBOg7zdxuIz6nRhd1uwGpCpljoCECtO"
"QN6nXe7B3KkQUHZZAKEvnncGfbYcoYZR1jXlEzO3CN4GXEJSTmYRzy1eFM6kJHZ4"
"xzcI2Y9tG2NBQj7E7vlZzmADW4B4XSlyR2fIID0ySZRBD5nNZoiLAbd5ryFiiiGK"
"WmgqBkDGyRqZ9gYFYrs3QQ3fPCyY6R7uX10Lz5hx40trINllm3BqtbaqamH8asvk"
"jwFxuYFpBPK0aaX8uwuGJ26ypgaKMne8BceRgLCUeHnuSkKm49bkeJJbqJ84yaN9"
"cfeCqNwQrFkXoB22vrSGLQbIMmX1Qwwj0pCQNEKgAPyCVr7kI7xjWHvsOxqC897y"
"kkYntCY2VyCXSCX4un3jTQpRJA93LahKGf4kQSnYkYmKMbokYgVfqJ8xMzbJhx78"
"KrTlIqkiEjqGMbKOylmnPA9IUnsD5GeWz9XBVBShY6q2cabclhDYzSoiApeLP64B"
*/

/*
#[test]
fn created_files_are_detected() {
    todo!();
}
#[test]
fn changed_files_are_detected() {
    todo!();
}
*/
