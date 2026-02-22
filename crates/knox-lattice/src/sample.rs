use crate::params::{ETA, N, Q};
use crate::poly::Poly;

/// Expand `seed` into pseudo-random bytes using counter-mode BLAKE3.
/// Each 32-byte block = BLAKE3(domain || ctr_le64 || seed).
/// One call generates all bytes needed — no per-coefficient hashing.
fn counter_expand(domain: &[u8], seed: &[u8], need: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(need + 32);
    let mut ctr = 0u64;
    while out.len() < need {
        let mut h = blake3::Hasher::new();
        h.update(domain);
        h.update(&ctr.to_le_bytes());
        h.update(seed);
        out.extend_from_slice(h.finalize().as_bytes());
        ctr += 1;
    }
    out
}

/// Sample a uniformly random polynomial in Z_q[x]/(x^N+1).
/// Uses 2-byte rejection sampling: mask to 14 bits, accept if < Q.
/// Acceptance rate ~75% → needs ~2730 bytes → ~86 BLAKE3 blocks (one pass).
pub fn sample_uniform(seed: &[u8]) -> Poly {
    let mut coeffs = [0i64; N];
    let mut filled = 0usize;
    // Pre-generate enough bytes for expected rejection rate + headroom.
    let buf = counter_expand(b"knox-lattice-uniform", seed, N * 3);
    let mut pos = 0;
    while filled < N {
        if pos + 2 > buf.len() {
            // Extremely unlikely — just re-expand with offset seed.
            let extra = counter_expand(b"knox-lattice-uniform-ext", &buf[..32], N);
            let v = u16::from_le_bytes([extra[0], extra[1]]) as u64 & 0x3FFF;
            if v < Q {
                coeffs[filled] = v as i64;
                filled += 1;
            }
            break;
        }
        let v = u16::from_le_bytes([buf[pos], buf[pos + 1]]) as u64 & 0x3FFF;
        pos += 2;
        if v < Q {
            coeffs[filled] = v as i64;
            filled += 1;
        }
    }
    Poly::from_coeffs(coeffs)
}

/// Sample a centered binomial polynomial with parameter ETA=2.
/// Each coefficient = popcount(a_bits[2]) - popcount(b_bits[2]).
/// Needs 4 bits per coefficient → N/2 = 512 bytes total — **one** BLAKE3 pass.
pub fn sample_cbd(seed: &[u8]) -> Poly {
    // 4 bits per coefficient (2 bits for a, 2 bits for b), packed as nibbles.
    // 1024 coefficients × 4 bits / 8 = 512 bytes.
    let buf = counter_expand(b"knox-lattice-cbd", seed, N / 2);
    let mut coeffs = [0i64; N];
    for i in 0..N {
        let byte = buf[i / 2];
        let nibble = if i % 2 == 0 { byte & 0x0F } else { (byte >> 4) & 0x0F };
        // lower 2 bits → a, upper 2 bits → b
        let a = (nibble & 0x03).count_ones() as i64;
        let b = ((nibble >> 2) & 0x03).count_ones() as i64;
        coeffs[i] = (a - b).clamp(-ETA, ETA);
    }
    Poly::from_coeffs(coeffs)
}

/// Hash arbitrary data to a uniform polynomial in Z_q[x]/(x^N+1).
pub fn hash_to_poly(data: &[u8]) -> Poly {
    let mut h = blake3::Hasher::new();
    h.update(b"knox-lattice-sample-hash-to-poly-v1");
    h.update(&(data.len() as u64).to_le_bytes());
    h.update(data);
    let digest = h.finalize();
    sample_uniform(digest.as_bytes())
}
