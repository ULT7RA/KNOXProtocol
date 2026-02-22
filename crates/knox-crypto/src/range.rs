use crate::hash::{hash_to_point, hash_to_scalar};
use crate::pedersen::pedersen_h_point;
use crate::rng::os_random_bytes;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;

#[derive(Clone, Debug)]
pub struct InnerProductProof {
    pub l_vec: Vec<[u8; 32]>,
    pub r_vec: Vec<[u8; 32]>,
    pub a: [u8; 32],
    pub b: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct RangeProof {
    pub a: [u8; 32],
    pub s: [u8; 32],
    pub t1: [u8; 32],
    pub t2: [u8; 32],
    pub tau_x: [u8; 32],
    pub mu: [u8; 32],
    pub t_hat: [u8; 32],
    pub ip_proof: InnerProductProof,
}

#[derive(Clone)]
struct Generators {
    g: Vec<RistrettoPoint>,
    h: Vec<RistrettoPoint>,
}

fn generators(n: usize) -> Generators {
    let mut g = Vec::with_capacity(n);
    let mut h = Vec::with_capacity(n);
    for i in 0..n {
        let mut idx = [0u8; 8];
        idx.copy_from_slice(&(i as u64).to_le_bytes());
        g.push(hash_to_point(b"knox-gen-g", &idx));
        h.push(hash_to_point(b"knox-gen-h", &idx));
    }
    Generators { g, h }
}

fn random_scalar() -> Result<Scalar, String> {
    let mut bytes = [0u8; 64];
    os_random_bytes(&mut bytes)?;
    Ok(Scalar::from_bytes_mod_order_wide(&bytes))
}

fn inner_product(a: &[Scalar], b: &[Scalar]) -> Scalar {
    let mut acc = Scalar::ZERO;
    for (ai, bi) in a.iter().zip(b.iter()) {
        acc += ai * bi;
    }
    acc
}

fn vec_add(a: &[Scalar], b: &[Scalar]) -> Vec<Scalar> {
    a.iter().zip(b.iter()).map(|(x, y)| x + y).collect()
}

fn vec_sub(a: &[Scalar], b: &[Scalar]) -> Vec<Scalar> {
    a.iter().zip(b.iter()).map(|(x, y)| x - y).collect()
}

fn vec_mul_scalar(a: &[Scalar], s: Scalar) -> Vec<Scalar> {
    a.iter().map(|x| x * s).collect()
}

fn vec_hadamard(a: &[Scalar], b: &[Scalar]) -> Vec<Scalar> {
    a.iter().zip(b.iter()).map(|(x, y)| x * y).collect()
}

fn powers(base: Scalar, n: usize) -> Vec<Scalar> {
    let mut out = Vec::with_capacity(n);
    let mut cur = Scalar::ONE;
    for _ in 0..n {
        out.push(cur);
        cur *= base;
    }
    out
}

fn vector_commit(
    g: &[RistrettoPoint],
    h: &[RistrettoPoint],
    a: &[Scalar],
    b: &[Scalar],
) -> RistrettoPoint {
    let mut acc = RistrettoPoint::default();
    for i in 0..a.len() {
        acc += a[i] * g[i];
        acc += b[i] * h[i];
    }
    acc
}

fn fs_yz(
    commitment: &CompressedRistretto,
    a_point: &RistrettoPoint,
    s_point: &RistrettoPoint,
) -> (Scalar, Scalar) {
    let mut transcript = Vec::new();
    transcript.extend_from_slice(b"knox-bp-v1");
    transcript.extend_from_slice(commitment.as_bytes());
    transcript.extend_from_slice(a_point.compress().as_bytes());
    transcript.extend_from_slice(s_point.compress().as_bytes());
    let y = hash_to_scalar(b"knox-bp-y", &transcript);
    transcript.extend_from_slice(y.to_bytes().as_slice());
    let z = hash_to_scalar(b"knox-bp-z", &transcript);
    (y, z)
}

fn fs_x(
    commitment: &CompressedRistretto,
    a_point: &RistrettoPoint,
    s_point: &RistrettoPoint,
    t1_point: &RistrettoPoint,
    t2_point: &RistrettoPoint,
    y: Scalar,
    z: Scalar,
) -> Scalar {
    let mut transcript = Vec::new();
    transcript.extend_from_slice(b"knox-bp-v1-x");
    transcript.extend_from_slice(commitment.as_bytes());
    transcript.extend_from_slice(a_point.compress().as_bytes());
    transcript.extend_from_slice(s_point.compress().as_bytes());
    transcript.extend_from_slice(t1_point.compress().as_bytes());
    transcript.extend_from_slice(t2_point.compress().as_bytes());
    transcript.extend_from_slice(y.to_bytes().as_slice());
    transcript.extend_from_slice(z.to_bytes().as_slice());
    hash_to_scalar(b"knox-bp-x", &transcript)
}

fn fs_ip_x(
    l_point: &RistrettoPoint,
    r_point: &RistrettoPoint,
    p_point: &RistrettoPoint,
    round: u32,
) -> Scalar {
    let mut data = Vec::new();
    data.extend_from_slice(b"knox-ip-v1");
    data.extend_from_slice(&round.to_le_bytes());
    data.extend_from_slice(p_point.compress().as_bytes());
    data.extend_from_slice(l_point.compress().as_bytes());
    data.extend_from_slice(r_point.compress().as_bytes());
    hash_to_scalar(b"knox-ip-x", &data)
}

pub fn prove_range(value: u64, blind: Scalar) -> Result<RangeProof, String> {
    let n = 64usize;
    let gens = generators(n);
    let h_point = pedersen_h_point();
    let commitment = crate::pedersen::commit(value, &blind);

    let mut a_l = Vec::with_capacity(n);
    let mut a_r = Vec::with_capacity(n);
    for i in 0..n {
        let bit = ((value >> i) & 1) as u64;
        let b = Scalar::from(bit);
        a_l.push(b);
        a_r.push(b - Scalar::ONE);
    }

    let mut s_l = Vec::with_capacity(n);
    let mut s_r = Vec::with_capacity(n);
    for _ in 0..n {
        s_l.push(random_scalar()?);
        s_r.push(random_scalar()?);
    }

    let alpha = random_scalar()?;
    let rho = random_scalar()?;

    let a_point = vector_commit(&gens.g, &gens.h, &a_l, &a_r) + alpha * RISTRETTO_BASEPOINT_POINT;
    let s_point = vector_commit(&gens.g, &gens.h, &s_l, &s_r) + rho * RISTRETTO_BASEPOINT_POINT;

    let (y, z) = fs_yz(&commitment, &a_point, &s_point);

    let y_pows = powers(y, n);
    let two_pows: Vec<Scalar> = (0..n).map(|i| Scalar::from(1u64 << i)).collect();

    let z_vec = vec_mul_scalar(&vec![Scalar::ONE; n], z);
    let l0 = vec_sub(&a_l, &z_vec);
    let a_r_plus_z = vec_add(&a_r, &z_vec);
    let r0 = vec_add(
        &vec_hadamard(&a_r_plus_z, &y_pows),
        &vec_mul_scalar(&two_pows, z * z),
    );

    let l1 = s_l.clone();
    let r1 = vec_hadamard(&s_r, &y_pows);

    let t1 = inner_product(&l0, &r1) + inner_product(&l1, &r0);
    let t2 = inner_product(&l1, &r1);

    let tau1 = random_scalar()?;
    let tau2 = random_scalar()?;

    let t1_point = t1 * h_point + tau1 * RISTRETTO_BASEPOINT_POINT;
    let t2_point = t2 * h_point + tau2 * RISTRETTO_BASEPOINT_POINT;

    let x = fs_x(&commitment, &a_point, &s_point, &t1_point, &t2_point, y, z);

    let l = vec_add(&l0, &vec_mul_scalar(&l1, x));
    let r = vec_add(&r0, &vec_mul_scalar(&r1, x));
    let t_hat = inner_product(&l, &r);

    let tau_x = tau2 * x * x + tau1 * x + z * z * blind;
    let mu = alpha + rho * x;

    let h_inv: Vec<Scalar> = y_pows.iter().map(|y_i| y_i.invert()).collect();
    let h_prime: Vec<RistrettoPoint> = gens
        .h
        .iter()
        .zip(h_inv.iter())
        .map(|(h_i, inv)| h_i * inv)
        .collect();

    let mut g_sum = RistrettoPoint::default();
    let mut h_sum = RistrettoPoint::default();
    for i in 0..n {
        g_sum += gens.g[i];
        h_sum += h_prime[i] * y_pows[i];
    }

    let mut p = a_point + s_point * x;
    p += g_sum * (-z);
    let mut h_term = RistrettoPoint::default();
    for i in 0..n {
        h_term += h_prime[i] * (y_pows[i] * z + two_pows[i] * z * z);
    }
    p += h_term;
    p += h_point * t_hat;
    p -= RISTRETTO_BASEPOINT_POINT * mu;

    let ip_proof = inner_product_prove(&gens.g, &h_prime, p, &l, &r, h_point);

    Ok(RangeProof {
        a: a_point.compress().to_bytes(),
        s: s_point.compress().to_bytes(),
        t1: t1_point.compress().to_bytes(),
        t2: t2_point.compress().to_bytes(),
        tau_x: tau_x.to_bytes(),
        mu: mu.to_bytes(),
        t_hat: t_hat.to_bytes(),
        ip_proof,
    })
}

pub fn verify_range(commitment: &CompressedRistretto, proof: &RangeProof) -> bool {
    let n = 64usize;
    let gens = generators(n);
    let h_point = pedersen_h_point();

    let a_point = match CompressedRistretto(proof.a).decompress() {
        Some(p) => p,
        None => return false,
    };
    let s_point = match CompressedRistretto(proof.s).decompress() {
        Some(p) => p,
        None => return false,
    };
    let t1_point = match CompressedRistretto(proof.t1).decompress() {
        Some(p) => p,
        None => return false,
    };
    let t2_point = match CompressedRistretto(proof.t2).decompress() {
        Some(p) => p,
        None => return false,
    };
    let c_point = match commitment.decompress() {
        Some(p) => p,
        None => return false,
    };

    let (y, z) = fs_yz(commitment, &a_point, &s_point);

    let y_pows = powers(y, n);
    let two_pows: Vec<Scalar> = (0..n).map(|i| Scalar::from(1u64 << i)).collect();

    let x = fs_x(commitment, &a_point, &s_point, &t1_point, &t2_point, y, z);

    let tau_x = match Option::<Scalar>::from(Scalar::from_canonical_bytes(proof.tau_x)) {
        Some(v) => v,
        None => return false,
    };
    let mu = match Option::<Scalar>::from(Scalar::from_canonical_bytes(proof.mu)) {
        Some(v) => v,
        None => return false,
    };
    let t_hat = match Option::<Scalar>::from(Scalar::from_canonical_bytes(proof.t_hat)) {
        Some(v) => v,
        None => return false,
    };

    let z2 = z * z;
    let z3 = z2 * z;
    let mut sum_y = Scalar::ZERO;
    let mut sum_2 = Scalar::ZERO;
    for i in 0..n {
        sum_y += y_pows[i];
        sum_2 += two_pows[i];
    }
    let delta = (z - z2) * sum_y - z3 * sum_2;
    let lhs = t_hat * h_point + tau_x * RISTRETTO_BASEPOINT_POINT;
    let rhs = t1_point * x + t2_point * x * x + c_point * z2 + h_point * delta;
    if lhs != rhs {
        return false;
    }

    let h_inv: Vec<Scalar> = y_pows.iter().map(|y_i| y_i.invert()).collect();
    let h_prime: Vec<RistrettoPoint> = gens
        .h
        .iter()
        .zip(h_inv.iter())
        .map(|(h_i, inv)| h_i * inv)
        .collect();

    let mut g_sum = RistrettoPoint::default();
    for i in 0..n {
        g_sum += gens.g[i];
    }
    let mut p = a_point + s_point * x + g_sum * (-z);

    let mut h_term = RistrettoPoint::default();
    for i in 0..n {
        h_term += h_prime[i] * (y_pows[i] * z + two_pows[i] * z * z);
    }
    p += h_term;
    p += h_point * t_hat;
    p -= RISTRETTO_BASEPOINT_POINT * mu;

    inner_product_verify(&gens.g, &h_prime, p, h_point, &proof.ip_proof)
}

fn inner_product_prove(
    g: &[RistrettoPoint],
    h: &[RistrettoPoint],
    p: RistrettoPoint,
    a: &[Scalar],
    b: &[Scalar],
    u: RistrettoPoint,
) -> InnerProductProof {
    let mut g_vec = g.to_vec();
    let mut h_vec = h.to_vec();
    let mut a_vec = a.to_vec();
    let mut b_vec = b.to_vec();
    let mut p_point = p;

    let mut l_vec = Vec::new();
    let mut r_vec = Vec::new();

    let mut round = 0u32;
    while a_vec.len() > 1 {
        let n = a_vec.len();
        let n2 = n / 2;

        let (a_l, a_r) = a_vec.split_at(n2);
        let (b_l, b_r) = b_vec.split_at(n2);
        let (g_l, g_r) = g_vec.split_at(n2);
        let (h_l, h_r) = h_vec.split_at(n2);

        let c_l = inner_product(a_l, b_r);
        let c_r = inner_product(a_r, b_l);

        let mut l_point = RistrettoPoint::default();
        let mut r_point = RistrettoPoint::default();
        for i in 0..n2 {
            l_point += a_l[i] * g_r[i];
            l_point += b_r[i] * h_l[i];
            r_point += a_r[i] * g_l[i];
            r_point += b_l[i] * h_r[i];
        }
        l_point += u * c_l;
        r_point += u * c_r;

        l_vec.push(l_point.compress().to_bytes());
        r_vec.push(r_point.compress().to_bytes());

        let x = fs_ip_x(&l_point, &r_point, &p_point, round);
        let x_inv = x.invert();

        let mut g_new = Vec::with_capacity(n2);
        let mut h_new = Vec::with_capacity(n2);
        let mut a_new = Vec::with_capacity(n2);
        let mut b_new = Vec::with_capacity(n2);

        for i in 0..n2 {
            g_new.push(g_l[i] * x_inv + g_r[i] * x);
            h_new.push(h_l[i] * x + h_r[i] * x_inv);
            a_new.push(a_l[i] * x + a_r[i] * x_inv);
            b_new.push(b_l[i] * x_inv + b_r[i] * x);
        }

        p_point = l_point * (x * x) + p_point + r_point * (x_inv * x_inv);

        g_vec = g_new;
        h_vec = h_new;
        a_vec = a_new;
        b_vec = b_new;
        round = round.saturating_add(1);
    }

    InnerProductProof {
        l_vec,
        r_vec,
        a: a_vec[0].to_bytes(),
        b: b_vec[0].to_bytes(),
    }
}

fn inner_product_verify(
    g: &[RistrettoPoint],
    h: &[RistrettoPoint],
    p: RistrettoPoint,
    u: RistrettoPoint,
    proof: &InnerProductProof,
) -> bool {
    if proof.l_vec.len() != proof.r_vec.len() {
        return false;
    }
    if !g.len().is_power_of_two() || g.len() != h.len() {
        return false;
    }
    let expected_rounds = g.len().trailing_zeros() as usize;
    if proof.l_vec.len() != expected_rounds {
        return false;
    }
    let mut g_vec = g.to_vec();
    let mut h_vec = h.to_vec();
    let mut p_point = p;

    for (round, (l_bytes, r_bytes)) in proof.l_vec.iter().zip(proof.r_vec.iter()).enumerate() {
        let l_point = match CompressedRistretto(*l_bytes).decompress() {
            Some(p) => p,
            None => return false,
        };
        let r_point = match CompressedRistretto(*r_bytes).decompress() {
            Some(p) => p,
            None => return false,
        };
        let x = fs_ip_x(&l_point, &r_point, &p_point, round as u32);
        let x_inv = x.invert();

        let n2 = g_vec.len() / 2;
        let (g_l, g_r) = g_vec.split_at(n2);
        let (h_l, h_r) = h_vec.split_at(n2);
        let mut g_new = Vec::with_capacity(n2);
        let mut h_new = Vec::with_capacity(n2);
        for i in 0..n2 {
            g_new.push(g_l[i] * x_inv + g_r[i] * x);
            h_new.push(h_l[i] * x + h_r[i] * x_inv);
        }
        p_point = l_point * (x * x) + p_point + r_point * (x_inv * x_inv);
        g_vec = g_new;
        h_vec = h_new;
    }

    if g_vec.len() != 1 || h_vec.len() != 1 {
        return false;
    }
    let a = match Option::<Scalar>::from(Scalar::from_canonical_bytes(proof.a)) {
        Some(v) => v,
        None => return false,
    };
    let b = match Option::<Scalar>::from(Scalar::from_canonical_bytes(proof.b)) {
        Some(v) => v,
        None => return false,
    };
    let lhs = p_point;
    let rhs = g_vec[0] * a + h_vec[0] * b + u * (a * b);
    lhs == rhs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_proof_roundtrip() {
        let values = [0u64, 1, 2, 10, 12345, 1u64 << 20, u32::MAX as u64];
        for value in values {
            let blind = Scalar::from(42u64);
            let proof = prove_range(value, blind).expect("prove_range failed");
            let commit = crate::pedersen::commit(value, &blind);
            assert!(
                verify_range(&commit, &proof),
                "range proof failed for {value}"
            );
        }
    }
}
