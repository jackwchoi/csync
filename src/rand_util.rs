use crate::secure_vec::*;
use rand_chacha::{
    rand_core::{CryptoRng, RngCore, SeedableRng},
    ChaCha20Rng,
};
use std::convert::TryInto;

// # Returns
//
// A cryptographically secure pseudo-random, optionally using the provided seed.
//
// If seed is provided, `SeedableRng::from_seed` is called using it.
// Else, `SeedableRng::from_entropy` is used.
fn seedable_rng(seed_opt: Option<&CryptoSecureBytes>) -> impl CryptoRng + RngCore {
    match seed_opt {
        Some(seed) => {
            let seed_hash = sha512!(&seed.0);
            let seed_hash_32 = (seed_hash.0.unsecure()[..32]).try_into().unwrap();
            ChaCha20Rng::from_seed(seed_hash_32)
        }
        None => ChaCha20Rng::from_entropy(),
    }
}

///
pub fn rand_bytes_range(
    seed_opt: Option<&CryptoSecureBytes>,
    min_byte: u8,
    max_byte: u8,
    num_bytes: usize,
) -> CryptoSecureBytes {
    let buffer = {
        let mut rng = seedable_rng(seed_opt);
        let mut buffer = vec![0u8; num_bytes as usize];
        rng.fill_bytes(&mut buffer[..]);
        buffer
    };
    debug_assert!(min_byte < max_byte);
    let width = max_byte - min_byte;

    CryptoSecureBytes(
        buffer
            .into_iter()
            .map(|byte| byte as f64 / std::u8::MAX as f64)
            .map(|x| x * width as f64)
            .map(|x| x + min_byte as f64)
            .map(|x| x as u8)
            .collect(),
    )
}

/// # Parameters
///
/// 1. `seed_opt`: uses this seed if present, entropy otherwise
/// 1. `min`: such that the returned number will be no less than this number
/// 1. `max`: such that the returned number will be no greater than this number
///
/// # Returns
///
/// A random `u64` in the range `[min, max]`.
pub fn rand_u64(seed_opt: Option<&CryptoSecureBytes>, min: u64, max: u64) -> u64 {
    debug_assert!(min < max);
    let ru64 = {
        let mut rng = seedable_rng(seed_opt);
        rng.next_u64()
    };

    let ratio = ru64 as f64 / std::u64::MAX as f64;
    let width = (max - min) as f64;
    let adjusted_ratio = (ratio * width) as u64;
    adjusted_ratio + min
}

/// Generate pseudo-random bytes.
///
/// This macro is a convenience wrapper around the function `crate::rand_util::rand_bytes_range`.
///
/// # Examples
///
/// ```
/// // generate `n` number of bytes in range `[0, 256)`
/// let bytes = rng!(n);
///
/// // generate `n` number of bytes in range `[min_byte, max_byte]`
/// let bytes = rng!(n, min_byte, max_byte);
///
/// // choose a random number in range `[min_num_bytes, max_num_bytes]`, inclusive,
/// // and generate this many bytes in range `[0, 256)`
/// let bytes = rng!(min_num_byte, max_num_byte);
///
/// // choose a random number in range `[min_num_bytes, max_num_bytes]`, inclusive,
/// // and generate this many bytes in range `[min_byte, max_byte]`
/// let bytes = rng!(min_num_byte, max_num_byte, min_byte, max_byte);
/// ```
macro_rules! rng {
    ( $num_bytes:expr ) => {
        rng!($num_bytes, std::u8::MIN, std::u8::MAX)
    };
    ( $num_bytes:expr, $min_byte:expr, $max_byte:expr ) => {
        crate::rand_util::rand_bytes_range(None, $min_byte, $max_byte, $num_bytes)
    };
    ( $min_num_bytes:expr, $max_num_bytes:expr ) => {
        rng!($min_num_bytes, $max_num_bytes, std::u8::MIN, std::u8::MAX)
    };
    ( $min_num_bytes:expr, $max_num_bytes:expr, $min_byte:expr, $max_byte:expr ) => {{
        let rand_u64 = crate::rand_util::rand_u64(None, $min_num_bytes, $max_num_bytes);
        debug_assert!($min_num_bytes <= rand_u64 && rand_u64 <= $max_num_bytes);
        rng!(rand_u64 as usize, $min_byte, $max_byte)
    }};
}

/// Like `rng!`, except that there is an additional
macro_rules! rng_seed {
    ( $seed:expr, $num_bytes:expr ) => {
        rng_seed!($seed, $num_bytes, std::u8::MIN, std::u8::MAX)
    };
    ( $seed:expr, $num_bytes:expr, $min_byte:expr, $max_byte:expr ) => {
        crate::rand_util::rand_bytes_range(Some($seed), $min_byte, $max_byte, $num_bytes)
    };
    ( $seed:expr, $min_num_bytes:expr, $max_num_bytes:expr ) => {
        rng_seed!($seed, $min_num_bytes, $max_num_bytes, std::u8::MIN, std::u8::MAX)
    };
    ( $seed:expr, $min_num_bytes:expr, $max_num_bytes:expr, $min_byte:expr, $max_byte:expr ) => {{
        let rand_u64 = crate::rand_util::rand_u64(Some($seed), $min_num_bytes, $max_num_bytes);
        debug_assert!($min_num_bytes <= rand_u64 && rand_u64 <= $max_num_bytes);
        rng_seed!($seed, rand_u64 as usize, $min_byte, $max_byte)
    }};
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    ///
    #[test]
    fn rng_seed_is_deterministic() {
        //
        (0..10).map(|t| 1 << t).for_each(|num_bytes| {
            //
            assert_eq!(
                //
                1,
                //
                (0..4)
                    .map(|_| {
                        // create `num_bytes` number of random bytes, with the same seed
                        rng_seed!(
                            &sha512!(&b"8MUbwkVc1bKCUQmyXi5zlYvdlThsBEfxrmomSkIeAoFG3VsCWpQIyFC8W5D1R5R2"
                                .to_vec()
                                .into()),
                            num_bytes
                        )
                    })
                    .collect::<HashSet<_>>()
                    .len()
            );
        });
    }

    ///
    #[test]
    fn rand_bytes_range_respected() {
        let min_byte = 100;
        let max_byte = 105;
        let byte_count = 1 << 15;
        let bytes = rng!(byte_count, min_byte, max_byte);
        assert_eq!(bytes.0.unsecure().len(), byte_count as usize);
        assert!(bytes
            .0
            .unsecure()
            .iter()
            .copied()
            .all(|rand_byte| min_byte <= rand_byte && rand_byte <= max_byte));
    }
}
