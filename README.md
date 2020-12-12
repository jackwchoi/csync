# CryptSync (`csync`)
<!--
[![csync crate](https://img.shields.io/crates/v/csync.svg)](https://crates.io/crates/csync)
[![Colmac documentation](https://docs.rs/colmac/badge.svg)](https://docs.rs/colmac)
-->

__UNSTABLE; DO NOT USE FOR IMPORTANT APPLICATIONS__

CryptSync (`csync`) is a tool designed to efficiently compress and encrypt a large set of files.

## Table of Contents

1. [CryptSync](#cryptsync)
    1. [Summary of `csync`](#summary-of-csync)
    1. [Motivation](#motivation)
    1. [Performance / Memory Usage](#performance--memory-usage)
        1. [TLDR](#tldr)
        1. [Asymptotic Properties](#asymptotic-properties)
    1. [Example](#example)
    1. [Installing](#installing)

## Summary of `csync`

```txt
csync 0.1.0
Jack <jackwchoi@pm.me>
Crypt-Sync (`csync`) creates a compressed and encrypted archive which can be incrementally updated, meaning that on
successive runs `csync` will only sync the files that have changed since the last sync.

`csync` uses the following default configurations which can be customized

TODO change Random salt:                  (4096-bit) Spread depth:                  (3) Authentication algorithm:
HMAC-SHA512 (_) Compression algorithm:        Zstandard (level-3) Encryption algorithm:         ChaCha20 (4096-bit salt)
Key-derivation algorithm:           Scrypt (log_n: 21, r: 8, p: 1, 4096-bit output, 4096-bit salt)

Project home page: `https://github.com/jackwchoi/csync`

USAGE:
    csync [FLAGS] [OPTIONS] <source> --out <out_dir>

FLAGS:
        --clean      Clean the csync directory, making it as compact as possible and TODO: TRUNCATING
    -d, --decrypt    Decrypt an existing csync directory.
    -h, --help       Prints help information
    -V, --version    Prints version information
    -v, --verbose    Print information like step-by-step reporting and timing informations.

OPTIONS:
        --auth <auth_opt>
            The authentication algorithm to use; supported algorithms are: `hmac-sha512`

        --cipher <cipher_opt>
            The encryption algorithm to use; supported algorithms are: `aes256cbc`

        --compressor <compressor_opt>
            The compression algorithm to use; supported algorithms are: `zstd`

    -o, --out <out_dir>
            The csync directory to be created. If a directory exists under this path, a csync directory will be created
            with a basename identical name as the source directory. If a directory does not exist under this path, one
            will be created.
        --pbkdf2-algorithm <pbkdf2_alg_opt>            supported options are `hmac-sha512`
    -n, --pbkdf2-num-iter <pbkdf2_num_iter_opt>        
        --pbkdf2-time <pbkdf2_time_to_hash_opt>        
        --salt-len <salt_len_opt>                      Salt length in bytes.
        --scrypt-log-n <scrypt_log_n_opt>              
        --scrypt-output-len <scrypt_output_len_opt>    
        --scrypt-p <scrypt_p_opt>                      
        --scrypt-r <scrypt_r_opt>                      
        --scrypt-time <scrypt_time_to_hash_opt>        
    -s, --spread-depth <spread_depth_opt>              TODO

ARGS:
    <source>    The source directory to csync.
```

### Configurability

Almost everything about csync can be configured. Below are some of those configurable aspects; default configs are __BOLDED__:
1. [Encryption](https://en.wikipedia.org/wiki/Encryption) algorithm, and its parameters
    1. [__`ChaCha20`__](https://en.wikipedia.org/wiki/Salsa20#ChaCha20_adoption)
    1. [`AES-256-CBC`](https://en.wikipedia.org/wiki/AES_implementations#Implementation_Considerations)
1. [Authentication](https://en.wikipedia.org/wiki/Authenticated_encryption) algorithm, and its parameters
    1. [__`HMAC-SHA512`__](https://en.wikipedia.org/wiki/HMAC)
1. [Key Derivation](https://en.wikipedia.org/wiki/Key_derivation_function) function, and its parameters
    1. [__`scrypt`__](https://en.wikipedia.org/wiki/Scrypt)
    1. [`PBKDF2`](https://en.wikipedia.org/wiki/PBKDF2)
1. [Compression](https://en.wikipedia.org/wiki/Scrypt) algorithm, and its parameters
    1. [__`Zstandard`__](https://en.wikipedia.org/wiki/Zstandard)
    1. ~~[`gzip`](https://en.wikipedia.org/wiki/Gzip)~~ COMING SOON

### Encryption

TODO

### Privacy

TODO

### Performance

TODO

### Privacy

TODO

1. compresses and encrypts files and directories
1. `csync` outputs a directory of files, instead of a single file
    1. great for cloud file storage services
    1. great for files that are frequently modified
1. constant memory usage
    1. processing millions of files uses the same amount of memory as processing 10
1. fully parallel at the file level
    1. every file is processed independently of one another, in parallel
    1. extract every bit of computing power your machine offers
1. no central point of failure
    1. TODO
1. file names are encrypted
1. directory structures are obfuscated
1. client-side
1. open source
1. authentication

`csync` aims to solve similar goals as tools like `Cryptomator`.

TODO TODO TODO

## Motivation

One easy way to create an encrypted and compressed backup of a directory is by creating an archive, like the following:
```bash
gtar -cf - some_dir/ |
  pigz --fast - |
  gpg --pinentry-mode=loopback -c - > archive.tar.gz.gpg
```

There are some pain points with this, mostly because this creates one large file:
1. Some cloud storage services don't allow files greater than some fixed size limit
1. Making small updates is impossible; you have to remake the whole archive

Crypt Sync aims to solve this problem by preserving the directory structure during the compression/encrpytion.

## Performance / Memory Usage

`Syncer` uses the following concepts/styles/paradigms to work on large sets of files
efficiently:
1. Data-parallelism: each file is processed independently of one another, in parallel
1. Lazy-evaluation: computations do not take place until they are absolutely necessary
1. Streaming: memory usage is constant and does not change over time

All of the above allow for some enticing properties, detailed below.

### TLDR
1. `Syncer`'s memory usage is the same regardless of whether you are working on 100 files or
   millions of files
1. if your machine has `k` times more cores than your friend's, `csync` will run `k` times faster
   on your machine

### Asymptotic Properties

Let:
1. `n` be the number of files `csync` operates on
1. `k` be the number of cores on your machine

Then the following properties of `csync` holds:
1. Runtime complexity grows linearly with `n`, in other words `O(n)`
1. Memory usage grows linearly with `k` but __CONSTANT with respect to `n`__, in other words `O(k)`.

## Example

For example running `csync` on the following `src/` directory would result in something like

```
src/
├── clargs.rs
├── crypt/
│  ├── crypt_syncer.rs
│  └── mod.rs
├── encoder/
│  ├── aes_cryptor.rs
│  ├── crypt_encoder.rs
│  ├── hash_encoder.rs
│  ├── identity_encoder.rs
│  ├── mod.rs
│  ├── text_decoder.rs
│  ├── text_encoder.rs
│  ├── zstd_decoder.rs
│  └── zstd_encoder.rs
├── hasher.rs
├── main.rs
└── util.rs
```

```
out/
├── 4/
│  └── 7/
│     └── CVLPKOrPtv_tMFTa0bt54swatTfnRyL0m6OdI77fNfSgr18UzF_mOh7fZbepuXCM/
│        └── QlV3naQGWJSAofUeW-dFv54G9OVVv1gsYNe6sKYwOKPWxOmqwQPljGR25e-pxaIt/
│           └── ua17cggPxRUywYtTVvaJtivYSh7bX25toYp9CXduCLUo5TNJ3qj2sz3QTqnyNv8G/
│              └── NzIqlATaJuI0ElYyG1x5arCLBWmuEzrEpS75pun7p83Xq1VlyHcfNthff2AvJEzX/
│                 └── b85lYFfHIJdbendj5dzLXy8tTM5ivoxsLTlsbAZVv5fqLirP7iHVlAHVPfYdxcZB
├── 7/
│  └── I/
│     └── Ha3zK28wA3RRoQzFkOW8r0DkpICXZoocW-MApH-GmmIVnXxFsfUcWDJGtSJa4E1E/
│        └── hciPMVoO4IFh52J74dXbyo3gcSEAQQOqohtT5xh5CF0dK3gdX2lkPEME8mHWq1Rw/
│           └── QHlKdS0p6gOfGE5hJxzYnkYDX0ZLoYIX4bCcQxU6msDB6WGO32YLtyu30z_NraXa/
│              └── QTbGInrkoGOpwwlNdol2kTX5lwFsxbMQ7uD2onRDRITNWN4msEOdv4WOqBgT-XaO/
│                 └── Sl1upgeZewCRyU0a1971738LKi9w
├── C/
│  └── X/
│     └── x_Q3lOvABfyRJRZ5yOzF_PZrrab9KZE_0rHiJJUgLHe1s9dD0UMARSJUEi6dlvmJ/
│        └── fVH8WmxJhHWlAGqPNkiR_6Icg_6I0TMsVG6ZCLlboiK_-vFaFBzenFTVXCGPWxWc/
│           └── dzGShApKwM7emFBrQFT33Qd1-IeB9TWfq23lDHN0WkRJ3veifewS0r0U6R2W7hAi/
│              └── LNhBEKUr1IYWun0_SSyjbZnUCju4gfiyyfeoptrvy7eOy4Gz4tLlU8cjSWMjRXXX/
│                 └── DGXUPoB3FyxbPIVespVCph_nEPcvHg==
├── e/
│  ├── a/
│  │  └── 7NzmocsGVNxUVvq2ZPG7nEDXNps1UdalEyss_rIMzrRmUG1rwvVvq3DC-0unsdCR/
│  │     └── CNcQPVNHaCEpCMvNVTnoPVSM5PEPawJpY4NV0582foI7OIj1qo-cmXQQ1srdSRDk/
│  │        └── XnXcXiepWg0iZ6VjKkhLWVduRSqi32x54vW7oHdFsX6hjfQx-QdiLOXQXz5BwawI/
│  │           └── S25S6ixWSPWfD_FwPAYwN4CvoCXMXAX2957huTdfc7QF4D2eg6q16_hfBZ53JJSl/
│  │              └── 5PPazc0aSThmo_LtN3Ge7gYcNAw=
│  └── U/
│     └── kDj7DarqREw_RN0wDg7ngzUqgOqzBMutoH-naT1pB04oOzQmtE80OD9XuN8BFPbD/
│        └── ntr3PA==
├── h/
│  └── d/
│     └── 6rLKJD8kln4-VJFJevlAU7PxDutmQOPO_42mZBjILSRXCeKZND23QK3eK0kJId0C/
│        └── FNJxZkKP3EOqZ4qxjfGAjQ-LrVBS2XDHWA==
├── metadata.json.enc
└── ...
```

## Installing

```bash
cargo install csync
```

# TODO's

1. https://github.com/fdehau/tui-rs
1. better reporting of files that were not able to be synced
1. better interface for checking `out_dir`
1. handle symlinks
