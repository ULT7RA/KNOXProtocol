use crate::poly::Poly;
use bincode::{Decode, Encode};

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct LatticeCommitmentKey {
    pub a: Poly,
    pub b: Poly,
}

impl LatticeCommitmentKey {
    pub fn derive() -> Self {
        let a = Poly::from_hash(b"knox-lattice-commitment", b"A");
        let b = Poly::from_hash(b"knox-lattice-commitment", b"B");
        Self { a, b }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct LatticeCommitment {
    pub c: Poly,
}

impl LatticeCommitment {
    pub fn add(&self, other: &Self) -> Self {
        Self {
            c: self.c.add(&other.c),
        }
    }

    pub fn sub(&self, other: &Self) -> Self {
        Self {
            c: self.c.sub(&other.c),
        }
    }

    pub fn scalar_mul(&self, scalar: u64) -> Self {
        Self {
            c: self.c.scalar_mul(scalar),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.c.to_bytes()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct CommitmentOpening {
    pub value: u64,
    pub randomness: Poly,
}

pub fn commit_value(
    key: &LatticeCommitmentKey,
    value: u64,
    randomness: &Poly,
) -> LatticeCommitment {
    // C = A*r + B*v mod (q, x^n + 1)
    let ar = key.a.mul(randomness);
    let bv = key.b.mul(&Poly::constant(value));
    LatticeCommitment { c: ar.add(&bv) }
}

pub fn verify_opening(
    key: &LatticeCommitmentKey,
    commitment: &LatticeCommitment,
    opening: &CommitmentOpening,
) -> bool {
    let expected = commit_value(key, opening.value, &opening.randomness);
    expected == *commitment
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poly::Poly;

    #[test]
    fn homomorphic_addition_preserves_opening() {
        let key = LatticeCommitmentKey::derive();
        let o1 = CommitmentOpening {
            value: 7,
            randomness: Poly::sample_short(b"test", b"r1"),
        };
        let o2 = CommitmentOpening {
            value: 9,
            randomness: Poly::sample_short(b"test", b"r2"),
        };
        let c1 = commit_value(&key, o1.value, &o1.randomness);
        let c2 = commit_value(&key, o2.value, &o2.randomness);
        let combined = c1.add(&c2);
        let o3 = CommitmentOpening {
            value: o1.value + o2.value,
            randomness: o1.randomness.add(&o2.randomness),
        };
        assert!(verify_opening(&key, &combined, &o3));
    }
}
