use crate::poly::Poly;
use crate::ring_sig::{public_from_secret, ring_generator, LatticePublicKey, LatticeSecretKey};
use bincode::{Decode, Encode};

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct LatticeConsensusSignature {
    pub challenge_bytes: [u8; 32],
    pub response: Poly,
}

pub fn consensus_secret_from_seed(seed: &[u8; 32]) -> LatticeSecretKey {
    LatticeSecretKey {
        s: Poly::sample_short(b"knox-lattice-consensus-secret-v1", seed),
    }
}

pub fn consensus_public_from_secret(secret: &LatticeSecretKey) -> LatticePublicKey {
    public_from_secret(secret)
}

pub fn consensus_public_key_id(public: &LatticePublicKey) -> [u8; 32] {
    *blake3::hash(&public.p.to_bytes()).as_bytes()
}

pub fn encode_consensus_public_key(public: &LatticePublicKey) -> Vec<u8> {
    public.p.to_bytes()
}

pub fn decode_consensus_public_key(bytes: &[u8]) -> Result<LatticePublicKey, String> {
    Ok(LatticePublicKey {
        p: Poly::from_bytes(bytes)?,
    })
}

pub fn sign_consensus(secret: &LatticeSecretKey, message: &[u8; 32]) -> Result<Vec<u8>, String> {
    let public = consensus_public_from_secret(secret);
    let nonce = deterministic_nonce(secret, message);
    let announce = ring_generator().mul(&nonce);
    let challenge_bytes = consensus_challenge_bytes(message, &public, &announce);
    let challenge_poly = consensus_challenge_poly(&challenge_bytes);
    let response = nonce.add(&secret.s.mul(&challenge_poly));
    let sig = LatticeConsensusSignature {
        challenge_bytes,
        response,
    };
    bincode::encode_to_vec(sig, bincode::config::standard()).map_err(|e| e.to_string())
}

pub fn verify_consensus(public: &LatticePublicKey, message: &[u8; 32], signature: &[u8]) -> bool {
    let Ok((sig, consumed)) = bincode::decode_from_slice::<LatticeConsensusSignature, _>(
        signature,
        bincode::config::standard(),
    ) else {
        return false;
    };
    if consumed != signature.len() {
        return false;
    }
    if !public.p.is_canonical_mod_q() || !sig.response.is_canonical_mod_q() {
        return false;
    }
    let challenge_poly = consensus_challenge_poly(&sig.challenge_bytes);
    let announce = ring_generator()
        .mul(&sig.response)
        .sub(&public.p.mul(&challenge_poly));
    consensus_challenge_bytes(message, public, &announce) == sig.challenge_bytes
}

fn deterministic_nonce(secret: &LatticeSecretKey, message: &[u8; 32]) -> Poly {
    let mut h = blake3::Hasher::new();
    h.update(b"knox-lattice-consensus-nonce-v2");
    h.update(message);
    h.update(&secret.s.to_bytes());
    let digest = h.finalize();
    Poly::sample_short(b"knox-lattice-consensus-nonce-sample-v2", digest.as_bytes())
}

fn consensus_challenge_bytes(
    message: &[u8; 32],
    public: &LatticePublicKey,
    announce: &Poly,
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"knox-lattice-consensus-challenge-v2");
    h.update(message);
    h.update(&public.p.to_bytes());
    h.update(&announce.to_bytes());
    *h.finalize().as_bytes()
}

fn consensus_challenge_poly(challenge_bytes: &[u8; 32]) -> Poly {
    Poly::from_hash(b"knox-lattice-consensus-challenge-poly-v2", challenge_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consensus_signature_round_trip() {
        let sk = consensus_secret_from_seed(&[9u8; 32]);
        let pk = consensus_public_from_secret(&sk);
        let msg = [7u8; 32];
        let sig = sign_consensus(&sk, &msg).expect("sign");
        assert!(verify_consensus(&pk, &msg, &sig));
        let mut tampered = sig.clone();
        tampered[0] ^= 0x80;
        assert!(!verify_consensus(&pk, &msg, &tampered));
    }

    #[test]
    fn consensus_public_key_id_is_stable() {
        let sk = consensus_secret_from_seed(&[3u8; 32]);
        let pk = consensus_public_from_secret(&sk);
        let id_a = consensus_public_key_id(&pk);
        let id_b = consensus_public_key_id(&pk);
        assert_eq!(id_a, id_b);
    }
}
