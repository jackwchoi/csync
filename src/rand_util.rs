use rand_chacha::{
    rand_core::{RngCore, SeedableRng},
    ChaCha20Rng,
};
use std::convert::TryInto;

fn seedable_rng(seed_opt: Option<&[u8]>) -> impl RngCore {
    match seed_opt {
        Some(seed) => {
            let seed_hash = hash1!(&seed[..]);
            let seed_hash_32 = (&seed_hash[..32]).try_into().unwrap();
            ChaCha20Rng::from_seed(seed_hash_32)
        }
        None => ChaCha20Rng::from_entropy(),
    }
}

pub fn rand_bytes_range(seed_opt: Option<&[u8]>, min_byte: u8, max_byte: u8, num_bytes: usize) -> Vec<u8> {
    let mut rng = seedable_rng(seed_opt);

    let mut buffer: Vec<u8> = vec![0; num_bytes as usize];
    rng.fill_bytes(&mut buffer[..]);

    debug_assert!(min_byte < max_byte);
    let width = max_byte - min_byte;

    buffer
        .into_iter()
        .map(|byte| byte as f64 / std::u8::MAX as f64)
        .map(|x| x * width as f64)
        .map(|x| x + min_byte as f64)
        .map(|x| x as u8)
        .collect()
}

#[inline]
pub fn rand_u64(seed_opt: Option<&[u8]>, min: u64, max: u64) -> u64 {
    debug_assert!(min < max);
    let mut rng = seedable_rng(seed_opt);

    let ru64 = rng.next_u64();

    let ratio = ru64 as f64 / std::u64::MAX as f64;
    let width = (max - min) as f64;
    let adjusted_ratio = (ratio * width) as u64;
    adjusted_ratio + min
}

// rng with random seed
macro_rules! rng {
    // generate `$num_bytes` number of bytes uniformly distrubuted in the range `[0, 256)`
    ( $num_bytes:expr ) => {
        rng!($num_bytes, std::u8::MIN, std::u8::MAX)
    };
    // generate `$num_bytes` number of bytes uniformly distrubuted in the range `[$min_byte, $max_byte)`
    ( $num_bytes:expr, $min_byte:expr, $max_byte:expr ) => {
        crate::rand_util::rand_bytes_range(None, $min_byte, $max_byte, $num_bytes)
    };

    // 1. randomly choose a byte in the range `[$min_num_bytes, $max_num_bytes]`, call it `rand_num_bytes`
    // 2. generate `rand_num_bytes` number of bytes, uniformly distrubuted in the range `[0, 256)`
    ( $min_num_bytes:expr, $max_num_bytes:expr ) => {
        rng!($min_num_bytes, $max_num_bytes, std::u8::MIN, std::u8::MAX)
    };
    // 1. randomly choose a byte in the range `[$min_num_bytes, $max_num_bytes]`, call it `rand_num_bytes`
    // 2. generate `rand_num_bytes` number of bytes, uniformly distrubuted in the range `[$min_byte, $max_byte]`
    ( $min_num_bytes:expr, $max_num_bytes:expr, $min_byte:expr, $max_byte:expr ) => {{
        let rand_u64 = crate::rand_util::rand_u64(None, $min_num_bytes, $max_num_bytes);
        debug_assert!($min_num_bytes <= rand_u64 && rand_u64 <= $max_num_bytes);
        rng!(rand_u64 as usize, $min_byte, $max_byte)
    }};
}

// rng with provided seed seed
macro_rules! rng_seed {
    // generate `$num_bytes` number of bytes uniformly distrubuted in the range `[0, 256)`
    ( $seed:expr, $num_bytes:expr ) => {
        rng_seed!($seed, $num_bytes, std::u8::MIN, std::u8::MAX)
    };
    // generate `$num_bytes` number of bytes, uniformly distrubuted in the range `[$min_byte, $max_byte)`
    ( $seed:expr, $num_bytes:expr, $min_byte:expr, $max_byte:expr ) => {
        crate::rand_util::rand_bytes_range(Some($seed), $min_byte, $max_byte, $num_bytes)
    };

    // 1. randomly choose a byte in the range `[$min_num_bytes, $max_num_bytes]`, call it `rand_num_bytes`
    // 2. generate `rand_num_bytes` number of bytes, uniformly distrubuted in the range `[0, 256)`
    ( $seed:expr, $min_num_bytes:expr, $max_num_bytes:expr ) => {
        rng_seed!($seed, $min_num_bytes, $max_num_bytes, std::u8::MIN, std::u8::MAX)
    };
    // 1. randomly choose a byte in the range `[$min_num_bytes, $max_num_bytes]`, call it `rand_num_bytes`
    // 2. generate `rand_num_bytes` number of bytes, uniformly distrubuted in the range `[$min_byte, $max_byte]`
    ( $seed:expr, $min_num_bytes:expr, $max_num_bytes:expr, $min_byte:expr, $max_byte:expr ) => {{
        let rand_u64 = crate::rand_util::rand_u64(Some($seed), $min_num_bytes, $max_num_bytes);
        debug_assert!($min_num_bytes <= rand_u64 && rand_u64 <= $max_num_bytes);
        rng_seed!($seed, rand_u64 as usize, $min_byte, $max_byte)
    }};
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::*;
    use std::collections::HashSet;

    #[test]
    fn drng_is_deterministic() {
        let num_bytes = (0..10).map(|t| 1 << t);

        num_bytes.for_each(|num_bytes| {
            let rands: HashSet<_> = (0..4).map(|_| drng_range(num_bytes, 32, 126)).collect();
            assert_eq!(1, rands.len());
        });
    }

    #[test]
    fn rand_bytes_range_respected() {
        let min_byte = 100;
        let max_byte = 105;
        let byte_count = 1 << 15;
        let bytes = rng!(byte_count, min_byte, max_byte);
        assert_eq!(bytes.len(), byte_count as usize);
        assert!(bytes
            .into_iter()
            .all(|rand_byte| min_byte <= rand_byte && rand_byte <= max_byte));
    }
}
