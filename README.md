# CryptSync (`csync`)

[![csync crate](https://img.shields.io/crates/v/csync.svg)](https://crates.io/crates/csync)

CryptSync (`csync`) efficiently compresses and encrypts a large set of files and directories.

```bash
$ csync encrypt src/crypt/syncer/ -vo out
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

## Features

1. __SECURITY__
    1. Encryption algorithms: [`AES`](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard), [`Chacha20`](https://en.wikipedia.org/wiki/Salsa20#ChaCha_variant) and more to come
    1. Key-derivation algorithms: [`scrypt`](https://en.wikipedia.org/wiki/Scrypt), [`pbkdf2`](https://en.wikipedia.org/wiki/PBKDF2) and more to come
    1. Cryptographically secure pseudorandom number generators: [Chacha20](https://rust-random.github.io/rand/rand_chacha/struct.ChaCha20Rng.html)
    1. Cryptographically secure pseudorandom salts, generated for each file, and for each session
    1. File names and contents are encrypted and obfuscated
    1. Directory structures are obfuscated
1. __PRIVACY__
    1. Open source!
    1. Client-side: no network communication and self contained
1. __PERFORMANCE__
    1. Fully parallel: designed to utilize 100% of your machine's computing power
    1. Rust!
    1. Incremental encryption: only the changed files are updated 
1. __FUTURE PROOF__
    1. almost all aspects of `csync` can be customized and configured
        1. `csync` uses the encryption and key-derivation algorithms, as well as their parameters of your choosing

## Motivation

One way to compress, encrypt and backup a set of files is to create a compressed/encrypted archival file, like so:
```bash
gtar -cf - "$SOURCE" |
    gzip |
    gpg --pinentry-mode=loopback -c - > "$BACKUP_FILE"
```

This workflow has the following benefits:
1. Simple: it creates one large file that holds the compressed/encrypted data

However it has the following drawbacks:
1. Simple: it creates one large file
    1. Each update forces the file to be recreated from scratch
    1. This is inefficient when you are only changing a small number of files
1. Users are responsible for ensuring performance and security
1. Users need to know about many tools and their parameters

`csync` tries to solve these issues by choosing configurations that make sense, is performant,
and is secure.

## Details of `csync`

### Configurability

Almost everything about `csync` can be configured (default configurations are __bolded__). See the following help page:

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
