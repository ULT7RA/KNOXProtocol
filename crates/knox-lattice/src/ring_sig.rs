use crate::params::MAX_RING_SIZE;
use crate::poly::Poly;
use bincode::{Decode, Encode};

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct LatticeSecretKey {
    pub s: Poly,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct LatticePublicKey {
    pub p: Poly,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct LatticeKeyImage {
    pub tag: Poly,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct LatticeRingSignature {
    pub c0: [u8; 32],
    pub responses: Vec<Poly>,
    pub key_image: LatticeKeyImage,
}

pub fn keygen() -> (LatticeSecretKey, LatticePublicKey) {
    let sk = LatticeSecretKey {
        s: Poly::random_short(),
    };
    let pk = public_from_secret(&sk);
    (sk, pk)
}

pub fn public_from_secret(secret: &LatticeSecretKey) -> LatticePublicKey {
    LatticePublicKey {
        p: ring_generator().mul(&secret.s),
    }
}

pub fn key_image(secret: &LatticeSecretKey, public: &LatticePublicKey) -> LatticeKeyImage {
    let hp = hash_to_poly(b"knox-lattice-ring-h", &public.p.to_bytes());
    LatticeKeyImage {
        tag: hp.mul(&secret.s),
    }
}

pub fn key_image_id(image: &LatticeKeyImage) -> [u8; 32] {
    *blake3::hash(&image.tag.to_bytes()).as_bytes()
}

pub fn sign_ring(
    msg: &[u8],
    ring: &[LatticePublicKey],
    signer_index: usize,
    secret: &LatticeSecretKey,
) -> Result<LatticeRingSignature, String> {
    if ring.is_empty() {
        return Err("ring is empty".to_string());
    }
    if ring.len() > MAX_RING_SIZE {
        return Err("ring is too large".to_string());
    }
    if ring.len() < 2 {
        return Err("ring must contain at least 2 members".to_string());
    }
    if signer_index >= ring.len() {
        return Err("signer index out of bounds".to_string());
    }

    let expected = public_from_secret(secret);
    if ring[signer_index] != expected {
        return Err("signer secret does not match ring member".to_string());
    }

    let n = ring.len();
    let g = ring_generator();
    let image = key_image(secret, &ring[signer_index]);
    let mut challenges = vec![[0u8; 32]; n];
    let mut responses = vec![Poly::zero(); n];

    let alpha = Poly::random_short_checked()?;
    let hp_signer = hash_to_poly(b"knox-lattice-ring-h", &ring[signer_index].p.to_bytes());
    let l_signer = g.mul(&alpha);
    let r_signer = hp_signer.mul(&alpha);
    let next = (signer_index + 1) % n;
    challenges[next] = challenge_bytes(msg, &l_signer, &r_signer);

    let mut idx = next;
    while idx != signer_index {
        responses[idx] = Poly::random_short_checked()?.add(&Poly::zero());
        let hp = hash_to_poly(b"knox-lattice-ring-h", &ring[idx].p.to_bytes());
        let c_poly = challenge_poly(&challenges[idx]);
        let l = g.mul(&responses[idx]).add(&ring[idx].p.mul(&c_poly));
        let r = hp.mul(&responses[idx]).add(&image.tag.mul(&c_poly));
        let next_idx = (idx + 1) % n;
        challenges[next_idx] = challenge_bytes(msg, &l, &r);
        idx = next_idx;
    }

    let signer_c = challenge_poly(&challenges[signer_index]);
    responses[signer_index] = alpha.sub(&secret.s.mul(&signer_c));

    Ok(LatticeRingSignature {
        c0: challenges[0],
        responses,
        key_image: image,
    })
}

pub fn verify_ring(msg: &[u8], ring: &[LatticePublicKey], sig: &LatticeRingSignature) -> bool {
    if ring.is_empty() || ring.len() != sig.responses.len() {
        return false;
    }
    if ring.len() > MAX_RING_SIZE {
        return false;
    }
    if ring.iter().any(|member| !member.p.is_canonical_mod_q()) {
        return false;
    }
    if !sig.key_image.tag.is_canonical_mod_q()
        || sig.responses.iter().any(|resp| !resp.is_canonical_mod_q())
    {
        return false;
    }

    let g = ring_generator();
    let mut c = sig.c0;
    for (idx, member) in ring.iter().enumerate() {
        let hp = hash_to_poly(b"knox-lattice-ring-h", &member.p.to_bytes());
        let c_poly = challenge_poly(&c);
        let l = g.mul(&sig.responses[idx]).add(&member.p.mul(&c_poly));
        let r = hp
            .mul(&sig.responses[idx])
            .add(&sig.key_image.tag.mul(&c_poly));
        c = challenge_bytes(msg, &l, &r);
    }
    c == sig.c0
}

fn challenge_bytes(msg: &[u8], l: &Poly, r: &Poly) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"knox-lattice-ring-challenge");
    h.update(msg);
    h.update(&l.to_bytes());
    h.update(&r.to_bytes());
    *h.finalize().as_bytes()
}

fn challenge_poly(challenge: &[u8; 32]) -> Poly {
    hash_to_poly(b"knox-lattice-ring-challenge-poly", challenge)
}

pub(crate) fn ring_generator() -> Poly {
    hash_to_poly(b"knox-lattice-ring-gen", b"G")
}

pub(crate) fn hash_to_poly(domain: &[u8], payload: &[u8]) -> Poly {
    Poly::from_hash(domain, payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_signature_verifies_and_links() {
        let mut ring = Vec::new();
        let mut secrets = Vec::new();
        for _ in 0..8 {
            let (sk, pk) = keygen();
            secrets.push(sk);
            ring.push(pk);
        }

        let msg = b"knox-lattice-ring-test";
        let sig = sign_ring(msg, &ring, 3, &secrets[3]).expect("sign");
        assert!(verify_ring(msg, &ring, &sig));
        assert!(!verify_ring(b"tampered", &ring, &sig));

        let tag_a = key_image_id(&sig.key_image);
        let tag_b = key_image_id(&key_image(&secrets[3], &ring[3]));
        assert_eq!(tag_a, tag_b);
    }
}
