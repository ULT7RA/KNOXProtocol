use crate::params::{ETA, N, Q};
use bincode::{Decode, Encode};
use knox_crypto::os_random_bytes;

// ---------------------------------------------------------------------------
// NTT constants for Z_q[x]/(x^N + 1), N=1024, Q=12289.
//
// The ring supports a negacyclic (twisted) NTT because Q-1 = 12288 = 2^12*3
// admits a primitive 2N=2048-th root of unity.
//
// Derivation:
//   g  = 11  (primitive root mod 12289, verified: ord(g) = 12288)
//   ψ  = g^(12288/2048) = g^6 = 1945  (primitive 2048th root of unity)
//
// Verification:
//   ψ^2048 ≡ 1 (mod Q)  ✓
//   ψ^1024 ≡ -1 (mod Q) ✓  (required for negacyclic mapping x^N ≡ -1)
//
// NTT twiddle table layout (1-indexed, k = 1..N-1):
//   tw[k] = ψ^bit_rev(k, log2 N)   (forward)
//   tw_inv[k] = ψ^(-bit_rev(k, log2 N))  (inverse)
//
// The forward DIT butterfly uses tw in ascending k order.
// The inverse (exact transpose) uses tw_inv in descending k order,
// traversing groups within each stage from high start to low start.
//
// Inverses:
//   ψ^(-1) ≡ 4050 (mod 12289)
//   N^(-1) ≡ 12277 (mod 12289)
// ---------------------------------------------------------------------------

const PSI: u64 = 1945; // primitive 2N-th root of unity mod Q
const PSI_INV: u64 = 4050; // ψ^(-1) mod Q
const N_INV: u64 = 12277; // N^(-1) mod Q

/// Flat twiddle table for the negacyclic NTT, 1-indexed (index 0 unused).
/// tw_fwd[k] = ψ^(bit_rev(k, log2 N)) mod Q,  k = 1..N-1.
/// tw_inv[k] = ψ^(-bit_rev(k, log2 N)) mod Q, k = 1..N-1.
static NTT_TW_FWD: std::sync::OnceLock<Vec<u64>> = std::sync::OnceLock::new();
static NTT_TW_INV: std::sync::OnceLock<Vec<u64>> = std::sync::OnceLock::new();

#[inline(always)]
fn mod_mul(a: u64, b: u64) -> u64 {
    ((a as u128 * b as u128) % Q as u128) as u64
}

fn bit_reverse(mut x: usize, log2n: u32) -> usize {
    let mut r = 0usize;
    for _ in 0..log2n {
        r = (r << 1) | (x & 1);
        x >>= 1;
    }
    r
}

/// Returns the forward twiddle table (length N, index 0 unused).
pub fn ntt_tw_fwd() -> &'static Vec<u64> {
    NTT_TW_FWD.get_or_init(|| {
        let log2n = N.trailing_zeros();
        // Precompute all needed powers: ψ^e for e in {bit_rev(k) | k=1..N-1}.
        // The maximum bit_rev value is N-1, so we need ψ^0 through ψ^(N-1).
        let mut pows = vec![1u64; N];
        for k in 1..N {
            pows[k] = mod_mul(pows[k - 1], PSI);
        }
        let mut table = vec![0u64; N]; // table[0] unused
        for k in 1..N {
            table[k] = pows[bit_reverse(k, log2n)];
        }
        table
    })
}

/// Returns the inverse twiddle table (length N, index 0 unused).
pub fn ntt_tw_inv() -> &'static Vec<u64> {
    NTT_TW_INV.get_or_init(|| {
        let log2n = N.trailing_zeros();
        let mut pows = vec![1u64; N];
        for k in 1..N {
            pows[k] = mod_mul(pows[k - 1], PSI_INV);
        }
        let mut table = vec![0u64; N];
        for k in 1..N {
            table[k] = pows[bit_reverse(k, log2n)];
        }
        table
    })
}

/// Forward negacyclic NTT in-place.
///
/// Maps polynomial coefficients in Z_q (canonical [0, Q)) to the NTT domain.
/// Pointwise multiplication in NTT domain equals negacyclic convolution (mod x^N+1).
///
/// Algorithm: Cooley-Tukey DIT butterfly.
/// The twiddle for group k (1-indexed, k increments sequentially each butterfly pair)
/// is ψ^(bit_rev(k, log2 N)), which encodes both the cyclic-NTT root of unity and
/// the negacyclic pre-twist simultaneously in a single pass.
pub fn ntt_forward(a: &mut [u64; N]) {
    let tw = ntt_tw_fwd();
    let mut k = 1usize;
    let mut len = N >> 1; // start with half = 512, full span = N
    while len >= 1 {
        let mut start = 0;
        while start < N {
            let w = tw[k];
            k += 1;
            let end = start + len;
            for j in start..end {
                let u = a[j];
                let v = mod_mul(a[j + len], w);
                a[j] = if u + v >= Q { u + v - Q } else { u + v };
                a[j + len] = if u >= v { u - v } else { u + Q - v };
            }
            start += 2 * len;
        }
        len >>= 1;
    }
}

/// Inverse negacyclic NTT in-place.
///
/// The exact transpose of `ntt_forward`: stages are run in reverse order and
/// groups within each stage are processed from high starting index to low.
/// Twiddle factors are ψ^(-bit_rev(k)) consumed in descending k order.
/// Final scaling by N^(-1) completes the inversion.
pub fn ntt_inverse(a: &mut [u64; N]) {
    let tw = ntt_tw_inv();
    let mut k = N - 1; // descending through the twiddle table
    let mut len = 1usize;
    while len < N {
        // Process groups from high start to low — transpose of the forward traversal.
        let mut start = N - 2 * len;
        loop {
            let w = tw[k];
            k -= 1;
            let end = start + len;
            for j in start..end {
                let u = a[j];
                let v = a[j + len];
                a[j] = if u + v >= Q { u + v - Q } else { u + v };
                let diff = if u >= v { u - v } else { u + Q - v };
                a[j + len] = mod_mul(diff, w);
            }
            if start == 0 {
                break;
            }
            start -= 2 * len;
        }
        len <<= 1;
    }
    // Scale every coefficient by N^(-1) mod Q.
    for coeff in a.iter_mut() {
        *coeff = mod_mul(*coeff, N_INV);
    }
}

/// Pointwise multiplication of two NTT-domain arrays mod Q.
pub fn ntt_pointwise_mul(a: &[u64; N], b: &[u64; N]) -> [u64; N] {
    let mut out = [0u64; N];
    for i in 0..N {
        out[i] = mod_mul(a[i], b[i]);
    }
    out
}

/// In-place NTT pointwise multiplication: a[i] = a[i] * b[i] mod Q.
#[inline]
pub fn ntt_pointwise_mul_in_place(a: &mut [u64; N], b: &[u64; N]) {
    for i in 0..N {
        a[i] = mod_mul(a[i], b[i]);
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Poly {
    coeffs: [i64; N],
}

impl Poly {
    pub fn zero() -> Self {
        Self { coeffs: [0; N] }
    }

    pub fn constant(value: u64) -> Self {
        let mut out = Self::zero();
        out.coeffs[0] = reduce(value as i128);
        out
    }

    pub fn from_coeffs(mut coeffs: [i64; N]) -> Self {
        for c in &mut coeffs {
            *c = reduce(*c as i128);
        }
        Self { coeffs }
    }

    pub fn coeffs(&self) -> &[i64; N] {
        &self.coeffs
    }

    pub fn is_canonical_mod_q(&self) -> bool {
        self.coeffs.iter().all(|c| *c >= 0 && *c < Q as i64)
    }

    pub fn add(&self, other: &Self) -> Self {
        let mut out = [0i64; N];
        for (i, slot) in out.iter_mut().enumerate().take(N) {
            *slot = reduce(self.coeffs[i] as i128 + other.coeffs[i] as i128);
        }
        Self { coeffs: out }
    }

    pub fn sub(&self, other: &Self) -> Self {
        let mut out = [0i64; N];
        for (i, slot) in out.iter_mut().enumerate().take(N) {
            *slot = reduce(self.coeffs[i] as i128 - other.coeffs[i] as i128);
        }
        Self { coeffs: out }
    }

    pub fn scalar_mul(&self, scalar: u64) -> Self {
        let s = (scalar % Q) as i128;
        let mut out = [0i64; N];
        for (i, slot) in out.iter_mut().enumerate().take(N) {
            *slot = reduce(self.coeffs[i] as i128 * s);
        }
        Self { coeffs: out }
    }

    /// Negacyclic polynomial multiplication in Z_q[x]/(x^N+1) using NTT.
    ///
    /// Complexity: O(N log N) versus the O(N²) naive convolution.
    /// Delegates to `mul_ntt`.
    pub fn mul(&self, other: &Self) -> Self {
        self.mul_ntt(other)
    }

    /// NTT-accelerated negacyclic multiplication in Z_q[x]/(x^N+1).
    ///
    /// Uses the twisted (negacyclic) NTT with primitive 2N-th root of unity
    /// ψ=1945 (mod Q=12289), so that pointwise multiplication in NTT domain
    /// corresponds exactly to polynomial multiplication mod x^N+1.
    pub fn mul_ntt(&self, other: &Self) -> Self {
        // Lift i64 coefficients to canonical u64 form in [0, Q).
        let mut a = [0u64; N];
        let mut b = [0u64; N];
        for i in 0..N {
            a[i] = self.coeffs[i].rem_euclid(Q as i64) as u64;
            b[i] = other.coeffs[i].rem_euclid(Q as i64) as u64;
        }

        // Forward twisted NTT on both operands.
        ntt_forward(&mut a);
        ntt_forward(&mut b);

        // Pointwise multiply in NTT domain.
        let mut c = ntt_pointwise_mul(&a, &b);

        // Inverse twisted NTT to recover product coefficients.
        ntt_inverse(&mut c);

        // Convert back to i64 canonical form.
        let mut out = [0i64; N];
        for i in 0..N {
            out[i] = c[i] as i64;
        }
        Self { coeffs: out }
    }

    pub fn inf_norm(&self) -> i64 {
        self.coeffs.iter().map(|x| x.abs()).max().unwrap_or(0)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(N * 2);
        for c in &self.coeffs {
            let reduced = (*c).rem_euclid(Q as i64) as u16;
            out.extend_from_slice(&reduced.to_le_bytes());
        }
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != N * 2 {
            return Err("invalid poly byte length".to_string());
        }
        let mut coeffs = [0i64; N];
        for (idx, chunk) in bytes.chunks_exact(2).enumerate() {
            let coeff = u16::from_le_bytes([chunk[0], chunk[1]]) as u64;
            if coeff >= Q {
                return Err("invalid poly coefficient".to_string());
            }
            coeffs[idx] = coeff as i64;
        }
        Ok(Self { coeffs })
    }

    pub fn from_hash(domain: &[u8], payload: &[u8]) -> Self {
        let mut coeffs = [0i64; N];
        for (i, coeff) in coeffs.iter_mut().enumerate().take(N) {
            let mut h = blake3::Hasher::new();
            h.update(domain);
            h.update(payload);
            h.update(&(i as u32).to_le_bytes());
            let digest = h.finalize();
            let mut b = [0u8; 8];
            b.copy_from_slice(&digest.as_bytes()[..8]);
            *coeff = reduce(u64::from_le_bytes(b) as i128);
        }
        Self { coeffs }
    }

    pub fn sample_short(seed_tag: &[u8], payload: &[u8]) -> Self {
        let mut coeffs = [0i64; N];
        let span = (ETA * 2 + 1) as u16;
        let accept_bound = 256u16 - (256u16 % span);
        for (i, coeff) in coeffs.iter_mut().enumerate().take(N) {
            let mut ctr = 0u32;
            loop {
                let mut h = blake3::Hasher::new();
                h.update(seed_tag);
                h.update(payload);
                h.update(&(i as u32).to_le_bytes());
                h.update(&ctr.to_le_bytes());
                let digest = h.finalize();
                let byte = digest.as_bytes()[0] as u16;
                if byte < accept_bound {
                    let centered = (byte % span) as i64 - ETA;
                    *coeff = centered;
                    break;
                }
                ctr = ctr.wrapping_add(1);
            }
        }
        Self { coeffs }
    }

    pub fn random_short_checked() -> Result<Self, String> {
        let mut bytes = [0u8; N];
        os_random_bytes(&mut bytes).map_err(|e| format!("rng failure: {e}"))?;
        let mut coeffs = [0i64; N];
        for i in 0..N {
            let span = (ETA * 2 + 1) as u8;
            let centered = (bytes[i] % span) as i64 - ETA;
            coeffs[i] = centered;
        }
        Ok(Self { coeffs })
    }

    pub fn random_short() -> Self {
        Self::random_short_checked().expect("rng failure: random short polynomial generation")
    }

    pub fn random_uniform_checked() -> Result<Self, String> {
        let mut bytes = [0u8; N * 2];
        os_random_bytes(&mut bytes).map_err(|e| format!("rng failure: {e}"))?;
        let mut coeffs = [0i64; N];
        for (idx, chunk) in bytes.chunks_exact(2).enumerate() {
            let val = u16::from_le_bytes([chunk[0], chunk[1]]) as u64;
            coeffs[idx] = (val % Q) as i64;
        }
        Ok(Self { coeffs })
    }
}

pub fn reduce(v: i128) -> i64 {
    v.rem_euclid(Q as i128) as i64
}
