use crate::hash::hash_to_scalar;
use crate::rng::os_random_bytes;
use blake3::Hasher;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Debug, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey(pub [u8; 32]);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicKey(pub [u8; 32]);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Signature {
    pub r: [u8; 32],
    pub s: [u8; 32],
}

pub fn keypair_from_secret(secret: SecretKey) -> (SecretKey, PublicKey) {
    let scalar = Scalar::from_bytes_mod_order(secret.0);
    let point = scalar * RISTRETTO_BASEPOINT_POINT;
    (secret, PublicKey(point.compress().to_bytes()))
}

pub fn generate_keypair() -> Result<(SecretKey, PublicKey), String> {
    let mut wide = [0u8; 64];
    os_random_bytes(&mut wide)?;
    let scalar = Scalar::from_bytes_mod_order_wide(&wide);
    wide.zeroize();
    let secret = SecretKey(scalar.to_bytes());
    Ok(keypair_from_secret(secret))
}

pub fn public_from_secret(secret: &SecretKey) -> PublicKey {
    let scalar = Scalar::from_bytes_mod_order(secret.0);
    let point = scalar * RISTRETTO_BASEPOINT_POINT;
    PublicKey(point.compress().to_bytes())
}

pub fn sign(secret: &SecretKey, msg: &[u8]) -> Result<Signature, String> {
    let mut nonce = [0u8; 64];
    os_random_bytes(&mut nonce)?;
    let scalar = Scalar::from_bytes_mod_order(secret.0);
    let k = derive_nonce_scalar(secret, msg, &nonce);
    nonce.zeroize();
    let r_point = k * RISTRETTO_BASEPOINT_POINT;
    let r_bytes = r_point.compress().to_bytes();
    let pk = public_from_secret(secret);
    let e = derive_challenge_scalar(&r_bytes, &pk.0, msg);
    let s = k + e * scalar;
    Ok(Signature {
        r: r_bytes,
        s: s.to_bytes(),
    })
}

pub fn verify(public: &PublicKey, msg: &[u8], sig: &Signature) -> bool {
    let r_point = match CompressedRistretto(sig.r).decompress() {
        Some(p) => p,
        None => return false,
    };
    let pk_point = match CompressedRistretto(public.0).decompress() {
        Some(p) => p,
        None => return false,
    };
    let e = derive_challenge_scalar(&sig.r, &public.0, msg);
    let s = match Option::<Scalar>::from(Scalar::from_canonical_bytes(sig.s)) {
        Some(s) => s,
        None => return false,
    };
    let lhs = s * RISTRETTO_BASEPOINT_POINT;
    let rhs = r_point + e * pk_point;
    lhs == rhs
}

fn derive_nonce_scalar(secret: &SecretKey, msg: &[u8], entropy: &[u8; 64]) -> Scalar {
    let mut h = Hasher::new();
    h.update(b"knox-sig-nonce-input-v2");
    h.update(&secret.0);
    h.update(&(msg.len() as u64).to_le_bytes());
    h.update(msg);
    h.update(entropy);
    let seed = h.finalize();
    hash_to_scalar(b"knox-sig-nonce-v2", seed.as_bytes())
}

fn derive_challenge_scalar(r_bytes: &[u8; 32], public: &[u8; 32], msg: &[u8]) -> Scalar {
    let mut h = Hasher::new();
    h.update(b"knox-sig-chal-input-v2");
    h.update(r_bytes);
    h.update(public);
    h.update(&(msg.len() as u64).to_le_bytes());
    h.update(msg);
    let seed = h.finalize();
    hash_to_scalar(b"knox-sig-chal-v2", seed.as_bytes())
}

pub fn signature_to_bytes(sig: &Signature) -> [u8; 64] {
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&sig.r);
    out[32..].copy_from_slice(&sig.s);
    out
}

pub fn signature_from_bytes(bytes: &[u8; 64]) -> Signature {
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&bytes[..32]);
    s.copy_from_slice(&bytes[32..]);
    Signature { r, s }
}
