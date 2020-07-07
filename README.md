# Crypt Sync
<!--
[![csync crate](https://img.shields.io/crates/v/csync.svg)](https://crates.io/crates/csync)
[![Colmac documentation](https://docs.rs/colmac/badge.svg)](https://docs.rs/colmac)
-->

Crypt Sync encrypts and optionally compresses files and directories, while preserving the file structure.

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
