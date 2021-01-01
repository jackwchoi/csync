# CryptSync (`csync`)
<!--
[![csync crate](https://img.shields.io/crates/v/csync.svg)](https://crates.io/crates/csync)
[![Colmac documentation](https://docs.rs/colmac/badge.svg)](https://docs.rs/colmac)
-->

CryptSync (`csync`) is a tool designed to efficiently compress and encrypt a large set of files.

## Summary of `csync`

```txt
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
$ tree src/crypt
src/crypt/
├── action.rs
├── mod.rs
├── syncer/
│  ├── mod.rs
│  └── util.rs
└── util.rs
```

```txt
$ csync 'src/crypt/' --outdir 'out/' --verbose
Enter your password:
Confirm your password:

Encrypting: "$ROOT/src/crypt" -> "$ROOT/out"

                     Random salt:                  (4096-bit)
                    Spread depth:                  (3)
        Authentication algorithm:      HMAC-SHA512 (_)
           Compression algorithm:        Zstandard (level-3)
            Encryption algorithm:         ChaCha20 (4096-bit salt)
        Key-derivation algorithm:           Scrypt (log_n: 20, r: 8, p: 1, 4096-bit output, 4096-bit salt)

Generating a derived key... took 2.991910668s

Using 8 threads...
  7.000  files |  57.933 KB ->  47.574 KB in 29.097ms =   1.991 MB/s...
                   Files synced:   7.000  files
                      Data read:  57.933 KB
                    Data stored:  47.574 KB
                     Throughput:   1.988 MB/sec
                       Duration: 29.145ms

$ tree out/
out/
├── 1/
│  └── l/
│     └── q/
│        └── q0kgbcgyzyss5n32cakciklf4y4zmw1m0msin1gwudstxz5q3pb51hfnavk2f4lf/
│           └── 35enr2c5ramae___.csync
├── 3/
│  └── j/
│     └── 0/
│        └── arx1yybo3rsjr1tvjj4epms3ew3rao0utb415nzh5q15csl005uslg0aypebd1v3/
│           └── glxmfiu3bfozi___.csync
├── h/
│  └── d/
│     └── q/
│        └── ocazg1kbjnmymsmejhzaybz0w3sd1huybsdqpdu35km4stt31w3q1razzt4uc20a/
│           └── ix3ymwjsvjxrft3b5vnridhvdrzylbv1r4dsadgehyt51jp5gp2ilmzeyghknwiu/
│              └── hde45o5fb5t51fkyjkimjmihyzjnxit45lfbypuumzolzbisveia____.csync
├── k/
│  └── o/
│     └── k/
│        └── b5qiyt1skidya1kbo1lo0amyrmnnodn5ntqfp4wzhgffmjdmyjerf2hd52izhnpo/
│           └── r5wh024ds1xlk5ddldzg5bwwszp5xkbkzzkjkmcr0vne21n3igisdomow2dxdzhv/
│              └── epbdpp4xy2obs0iq2s2p3fx1hg2k54c1f44y0xumzmzk2l33jxya____.csync
├── l/
│  └── d/
│     └── u/
│        └── 1fy30pvd0kvr0sjbjodxyvoyqkcbv3ov2szwnrtvadgveb0v300yzmandcehnv3k/
│           └── mrrby0udldiuibtuzgg1qcptblvz3v1lsvqohf2lxuw5xllj4gqptsogq2u0rm2v/
│              └── inocfehgezzvlketfc3vigusw2gegibe341yjrjqxykaf1xjj3xqaazc3iwa0rfi/
│                 └── whr55mcznbnkzc3ifo0reqeggposgzlxmu5cnwy_.csync
├── s/
│  └── m/
│     └── s/
│        └── k5mboo02fy1xogzxnkpw4v1mgkxjdoqfr3q302uulompd5zjalg15avniaed2brk/
│           └── by0ihjaqx4yn4zubyuthf020c5e55fvt0olkzppt0ekx3qug15m31vikv2vgv4vz/
│              └── ix14xujwu2qofnu1se3dc5yfsq______.csync
└── t/
   └── q/
      └── b/
         └── 14apjbznabrnjimoxiaoe3doijihcrrxzufs05zpo5hqjxpbpsos0kmyvlc3e4t1/
            └── bu4knwmniunoffq33qabdopgtlpppszkdcs2vqjftdacnfcrqjijventetsyed5g/
               └── idtoaegcirgbmpxgdaadxuapq2pxjgbzhq4b0g2aodlkcg1tne2yizp4jer2iws0/
                  └── wcjistel210vu___.csync
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
