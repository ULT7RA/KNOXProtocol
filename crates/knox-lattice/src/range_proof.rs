use crate::commitment::{
    commit_value, verify_opening, CommitmentOpening, LatticeCommitment, LatticeCommitmentKey,
};
use crate::params::Q;
use crate::poly::Poly;
use bincode::{Decode, Encode};
use getrandom::getrandom;

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct BitOrProof {
    pub a0: Poly,
    pub a1: Poly,
    pub e0: Poly,
    pub e1: Poly,
    pub z0: Poly,
    pub z1: Poly,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct LinearProof {
    pub a: Poly,
    pub z: Poly,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct LatticeRangeProof {
    pub bit_commitments: Vec<LatticeCommitment>,
    pub bit_or_proofs: Vec<BitOrProof>,
    pub balance_proof: LinearProof,
}

pub fn prove_range_u64(
    key: &LatticeCommitmentKey,
    commitment: &LatticeCommitment,
    opening: &CommitmentOpening,
) -> Result<LatticeRangeProof, String> {
    if !verify_opening(key, commitment, opening) {
        return Err("opening does not match commitment".to_string());
    }

    let mut bit_commitments = Vec::with_capacity(64);
    let mut bit_or_proofs = Vec::with_capacity(64);
    let mut weighted_random = Poly::zero();

    for bit_idx in 0..64 {
        let bit = (opening.value >> bit_idx) & 1;
        let bit_random = Poly::random_short_checked()?;
        let bit_commitment = commit_value(key, bit, &bit_random);
        let or_proof = prove_bit_or(key, &bit_commitment, bit, &bit_random)?;

        let weight = pow2_mod_q(bit_idx);
        weighted_random = weighted_random.add(&bit_random.scalar_mul(weight));
        bit_commitments.push(bit_commitment);
        bit_or_proofs.push(or_proof);
    }

    let weighted_commitment = weighted_commit_sum(&bit_commitments);
    let delta_commitment = commitment.sub(&weighted_commitment);
    let delta_random = opening.randomness.sub(&weighted_random);

    let k = Poly::random_short_checked()?;
    let a = key.a.mul(&k);
    let e = linear_challenge_poly(commitment, &delta_commitment, &bit_commitments, &a);
    let z = k.add(&delta_random.mul(&e));

    Ok(LatticeRangeProof {
        bit_commitments,
        bit_or_proofs,
        balance_proof: LinearProof { a, z },
    })
}

pub fn verify_range_u64(
    key: &LatticeCommitmentKey,
    commitment: &LatticeCommitment,
    proof: &LatticeRangeProof,
) -> bool {
    if !commitment.c.is_canonical_mod_q() {
        return false;
    }
    if proof.bit_commitments.len() != 64 || proof.bit_or_proofs.len() != 64 {
        return false;
    }
    if !proof.balance_proof.a.is_canonical_mod_q() || !proof.balance_proof.z.is_canonical_mod_q() {
        return false;
    }
    if proof
        .bit_commitments
        .iter()
        .any(|c| !c.c.is_canonical_mod_q())
    {
        return false;
    }

    for i in 0..64 {
        if !verify_bit_or(key, &proof.bit_commitments[i], &proof.bit_or_proofs[i]) {
            return false;
        }
    }

    let weighted_commitment = weighted_commit_sum(&proof.bit_commitments);
    let delta_commitment = commitment.sub(&weighted_commitment);
    let e = linear_challenge_poly(
        commitment,
        &delta_commitment,
        &proof.bit_commitments,
        &proof.balance_proof.a,
    );

    let lhs = key.a.mul(&proof.balance_proof.z);
    let rhs = proof.balance_proof.a.add(&delta_commitment.c.mul(&e));
    lhs == rhs
}

fn prove_bit_or(
    key: &LatticeCommitmentKey,
    bit_commitment: &LatticeCommitment,
    bit: u64,
    randomness: &Poly,
) -> Result<BitOrProof, String> {
    let target0 = bit_commitment.c.clone();
    let target1 = bit_commitment.c.sub(&key.b);

    if bit == 0 {
        let real_k = Poly::random_short_checked()?;
        let a0 = key.a.mul(&real_k);

        let e1 = random_challenge_poly(b"knox-lattice-range-rand-e1-v2")?;
        let z1 = Poly::random_uniform_checked()?;
        let a1 = key.a.mul(&z1).sub(&target1.mul(&e1));

        let e = bit_challenge_poly(bit_commitment, &a0, &a1);
        let e0 = e.sub(&e1);
        let z0 = real_k.add(&randomness.mul(&e0));

        Ok(BitOrProof {
            a0,
            a1,
            e0,
            e1,
            z0,
            z1,
        })
    } else {
        let e0 = random_challenge_poly(b"knox-lattice-range-rand-e0-v2")?;
        let z0 = Poly::random_uniform_checked()?;
        let a0 = key.a.mul(&z0).sub(&target0.mul(&e0));

        let real_k = Poly::random_short_checked()?;
        let a1 = key.a.mul(&real_k);

        let e = bit_challenge_poly(bit_commitment, &a0, &a1);
        let e1 = e.sub(&e0);
        let z1 = real_k.add(&randomness.mul(&e1));

        Ok(BitOrProof {
            a0,
            a1,
            e0,
            e1,
            z0,
            z1,
        })
    }
}

fn verify_bit_or(
    key: &LatticeCommitmentKey,
    bit_commitment: &LatticeCommitment,
    proof: &BitOrProof,
) -> bool {
    if !bit_commitment.c.is_canonical_mod_q()
        || !proof.a0.is_canonical_mod_q()
        || !proof.a1.is_canonical_mod_q()
        || !proof.e0.is_canonical_mod_q()
        || !proof.e1.is_canonical_mod_q()
        || !proof.z0.is_canonical_mod_q()
        || !proof.z1.is_canonical_mod_q()
    {
        return false;
    }

    let target0 = bit_commitment.c.clone();
    let target1 = bit_commitment.c.sub(&key.b);

    let lhs0 = key.a.mul(&proof.z0);
    let rhs0 = proof.a0.add(&target0.mul(&proof.e0));
    if lhs0 != rhs0 {
        return false;
    }

    let lhs1 = key.a.mul(&proof.z1);
    let rhs1 = proof.a1.add(&target1.mul(&proof.e1));
    if lhs1 != rhs1 {
        return false;
    }

    let expected_e = bit_challenge_poly(bit_commitment, &proof.a0, &proof.a1);
    proof.e0.add(&proof.e1) == expected_e
}

fn weighted_commit_sum(commitments: &[LatticeCommitment]) -> LatticeCommitment {
    let mut sum = LatticeCommitment { c: Poly::zero() };
    for (idx, c) in commitments.iter().enumerate() {
        let weight = pow2_mod_q(idx);
        sum = sum.add(&c.scalar_mul(weight));
    }
    sum
}

fn bit_challenge_poly(bit_commitment: &LatticeCommitment, a0: &Poly, a1: &Poly) -> Poly {
    challenge_poly(
        b"knox-lattice-range-bit-challenge-v2",
        b"knox-lattice-range-bit-poly-v2",
        &[&bit_commitment.to_bytes(), &a0.to_bytes(), &a1.to_bytes()],
    )
}

fn linear_challenge_poly(
    commitment: &LatticeCommitment,
    delta_commitment: &LatticeCommitment,
    bit_commitments: &[LatticeCommitment],
    a: &Poly,
) -> Poly {
    let mut pieces = vec![
        commitment.to_bytes(),
        delta_commitment.to_bytes(),
        a.to_bytes(),
    ];
    for c in bit_commitments {
        pieces.push(c.to_bytes());
    }
    let refs = pieces.iter().map(Vec::as_slice).collect::<Vec<_>>();
    challenge_poly(
        b"knox-lattice-range-linear-challenge-v2",
        b"knox-lattice-range-linear-poly-v2",
        &refs,
    )
}

fn random_challenge_poly(domain: &[u8]) -> Result<Poly, String> {
    let mut seed = [0u8; 32];
    getrandom(&mut seed).map_err(|e| format!("rng failure: {e}"))?;
    Ok(Poly::from_hash(domain, &seed))
}

fn hash_challenge_bytes(domain: &[u8], pieces: &[&[u8]]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(domain);
    for piece in pieces {
        h.update(&(*piece).len().to_le_bytes());
        h.update(piece);
    }
    *h.finalize().as_bytes()
}

fn challenge_poly(transcript_domain: &[u8], poly_domain: &[u8], pieces: &[&[u8]]) -> Poly {
    let challenge = hash_challenge_bytes(transcript_domain, pieces);
    Poly::from_hash(poly_domain, &challenge)
}

fn pow2_mod_q(idx: usize) -> u64 {
    if idx >= 64 {
        return 0;
    }
    ((1u128 << idx) % Q as u128) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commitment::{commit_value, CommitmentOpening, LatticeCommitmentKey};
    use crate::poly::Poly;

    #[test]
    fn range_proof_round_trip() {
        let key = LatticeCommitmentKey::derive();
        let opening = CommitmentOpening {
            value: 123_456_789,
            randomness: Poly::sample_short(b"test", b"range-open"),
        };
        let commitment = commit_value(&key, opening.value, &opening.randomness);
        let proof = prove_range_u64(&key, &commitment, &opening).expect("range proof");
        assert!(verify_range_u64(&key, &commitment, &proof));
    }
}
