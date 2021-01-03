# CryptSync (`csync`)

[![csync crate](https://img.shields.io/crates/v/csync.svg)](https://crates.io/crates/csync)
  
CryptSync (`csync`) efficiently compresses and encrypts a large set of files and directories.

## Motivation

One way to backup a set of files with data compression and encryption is to use an archival tool like `tar`,
followed by a compressor like `gzip`, followed by an encryption tool like `gpg`, like so:
```bash
gtar -cf - "$SOURCE" |
    gzip |
    gpg --pinentry-mode=loopback -c - > "$BACKUP_FILE"
```

This process has the following benefits:
1. it creates one large file that holds the compressed/encrypted data

However it has the following drawbacks:
1. it creates one large file
    1. every update forces the creation of the file from scratch
    1. if we work with thousands of files and gigabytes of data, we don't want to create it from scratch every time
1. the user is responsible for choosing the right tools to make it performant
1. need to know about many different tools and settings

## Features

1. __SECURITY__
    1. o
1. __PRIVACY__
    1. client side
1. __PERFORMANCE__
    1. fully parallel: designed to utilize 100% of your machine
    1. 100% Rust
1. __FUTURE PROOF__
    1. almost all aspects of `csync` can be customized

## Summary of `csync`

### a

```txt
$ csync --help
csync 0.1.0
CryptSync (`csync`) efficiently compresses and encrypts a set of files and directories.

See the help-page for each subcommand like `csync <SUBCOMMAND> --help`, for example `csync encrypt --help`.

Project home page: `https://github.com/jackwchoi/csync`

USAGE:
    csync <SUBCOMMAND>

FLAGS:
    -h, --help       
            Prints help information

    -V, --version    
            Prints version information


SUBCOMMANDS:
    clean      Clean a `csync` directory by making it as compact as possible
    decrypt    Decrypt a `csync` directory back to its plaintext form
    encrypt    Encrypt a file/directory to a compressed/encrypted `csync` directory
    help       Prints this message or the help of the given subcommand(s)
```

### a

```txt
$ csync encrypt --help
csync-encrypt 0.1.0
Encrypt a file/directory to a compressed/encrypted `csync` directory

USAGE:
    csync encrypt [FLAGS] [OPTIONS] <source> --out-dir <out-dir>

FLAGS:
    -h, --help                   
            Prints help information

        --key-deriv-by-params    
            Indicates that key derivation algorithms should use their explicit parameters rather than approximating them
            based on `--key-deriv-time`.
            
            For example, `csync encrypt src -o out` uses `scrypt` with parameters that obey the default value of `--key-
            deriv-time`. Running `csync encrypt src -o out --key-deriv-by-params` runs `scrypt` using `--scrypt-
            log-n`, `--scrypt-r, `--scrypt-p`.
    -V, --version                
            Prints version information

    -v, --verbose                
            Print information like step-by-step reporting and timing informations


OPTIONS:
        --auth <auth>
            Authentication algorithm to use; supported algorithms are [`hmac-sha512`] [default: hmac-sha512]

        --cipher <cipher>
            Encryption algorithm to use; supported algorithms are [`aes256cbc`, `chacha20`] [default: chacha20]

        --compressor <compressor>
            Compression algorithm to use; supported algorithms are [`zstd`] [default: zstd]

        --key-deriv-alg <key-deriv-alg>            
            supported options are `scrypt`, `pbkdf2` [default: scrypt]

        --key-deriv-time <key-deriv-time>
            Number of seconds the key derivation process should take on this machine. `csync` will figure out the
            approximate parameters [default: 4]
        --num-threads <num-threads-opt>
            Number of threads to use; defaults to the number of cores available on the machine

    -o, --out-dir <out-dir>
            `csync` directory in which compressed/encrypted files will be stored. This directory must be empty or be
            another `csync` directory that accepts the password from this session
        --pbkdf2-alg <pbkdf2-alg>
            Use this algorithm within `pbkdf2`; supported options are `hmac-sha512` [default: hmac-sha512]

        --pbkdf2-num-iter <pbkdf2-num-iter>
            Number of iterations for `pbkdf2`; ignored unless `--key-deriv-by-params` is specified [default: 131072]

        --salt-len <salt-len>                      
            Use salts that are this many bytes long [default: 512]

        --scrypt-log-n <scrypt-log-n>
            `log_2(n)` parameter for `scrypt`; ignored unless `--key-deriv-by-params` is specified [default: 15]

        --scrypt-output-len <scrypt-output-len>    
            Length of the output of `scrypt`, in bytes [default: 512]

        --scrypt-p <scrypt-p>
            `p` parameter for `scrypt`; ignored unless `--key-deriv-by-params` is specified [default: 1]

        --scrypt-r <scrypt-r>
            `r` parameter for `scrypt`; ignored unless `--key-deriv-by-params` is specified [default: 8]

        --spread-depth <spread-depth>
            Evenly distribute the compressed/encrypted files into `64^(spread_depth)` different directories [default: 3]

        --zstd-level <zstd-level>                  
            Compression level for `zstd`, allowed range is 1-19 [default: 3]


ARGS:
    <source>    
            The source directory to csync
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

```txt
$ ./target/release/csync encrypt src/crypt/syncer/ -vo out
  Enter your password:
Confirm your password:

Encrypting: "src/crypt/syncer" -> "out"

                     Random salt:                  (4096-bit)
                    Spread depth:                  (3)
        Authentication algorithm:      HMAC-SHA512 (_)
           Compression algorithm:        Zstandard (level-3)
            Encryption algorithm:         ChaCha20 (4096-bit salt)
        Key-derivation algorithm:           Scrypt (log_n: 21, r: 8, p: 1, 4096-bit output, 4096-bit salt)

Generating a derived key... took 6.210620084s

Using 8 threads...
  3.000  files |  31.406 KB ->  22.114 KB in 23.405ms =   1.342 MB/s...
                   Files synced:   3.000  files
                      Data read:  31.406 KB
                    Data stored:  22.114 KB
                     Throughput:   1.342 MB/sec
                       Duration: 23.403ms

$ tree src/crypt/syncer/ out/
src/crypt/syncer/
├── mod.rs
└── util.rs
out/
├── i/
│  └── y/
│     └── p/
│        └── vfhhoerwpawv15w4oxobzftrciq4glsmln0laopoio5u2scpxh22wvakgegl1yis/
│           └── gilcskj3y5bcmm3sbyesy3xpewqwutlmb0et2jphashj21u4choob0x41cfavhml/
│              └── 5z4sbkeoh1nktskmwud20sdffkjegd2irfehuwzn3sqk0ktefk3a____.csync
├── t/
│  └── v/
│     └── 5/
│        └── lx2aquvjzphemsdwmjnypbuuwcrto3044cwkxc2dpzdun3kvveieik2mvqbsstne/
│           └── wrgxdp40k4w4mz0150b3zdvvhgeexl4r1ffq3wezn0og1nq0t3hzoxjw1aiusbjk/
│              └── afh4red5comhp34rxfvl4scm32______.csync
└── u/
   └── g/
      └── q/
         └── dab1yu0moucvuzjgbnhafjv2tvzeuyy52pypuj5kvnj35kglchwpjmwyqtavopw3/
            └── 1acun2nk5p2oh05qlatfjycerinfzj54umo04h2k3fhehza0wcba3ztppzoi3l2i/
               └── 1a0f2kxujkfyce1jfain0uzk3f2ufgsoqrck2viovg3iaj15uw5a____.csync
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
