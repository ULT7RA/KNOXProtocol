use crate::hash::hash_to_scalar;
use crate::schnorr::{PublicKey, SecretKey};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

pub fn derive_shared(view_pub: &PublicKey, r: &Scalar) -> Result<RistrettoPoint, String> {
    let view_point = CompressedRistretto(view_pub.0)
        .decompress()
        .ok_or_else(|| "invalid view public key".to_string())?;
    Ok(r * view_point)
}

pub fn derive_one_time_pub(
    view_pub: &PublicKey,
    spend_pub: &PublicKey,
    r: &Scalar,
) -> Result<PublicKey, String> {
    let shared = derive_shared(view_pub, r)?;
    let tweak = hash_to_scalar(b"knox-stealth", shared.compress().as_bytes());
    let spend_point = CompressedRistretto(spend_pub.0)
        .decompress()
        .ok_or_else(|| "invalid spend public key".to_string())?;
    let dest = spend_point + RISTRETTO_BASEPOINT_POINT * tweak;
    Ok(PublicKey(dest.compress().to_bytes()))
}

pub fn recover_one_time_secret(
    view_secret: &SecretKey,
    spend_secret: &SecretKey,
    r_pub: &PublicKey,
) -> Result<SecretKey, String> {
    let view_scalar = Scalar::from_bytes_mod_order(view_secret.0);
    let r_point = CompressedRistretto(r_pub.0)
        .decompress()
        .ok_or_else(|| "invalid tx pub key".to_string())?;
    let shared = view_scalar * r_point;
    let tweak = hash_to_scalar(b"knox-stealth", shared.compress().as_bytes());
    let spend_scalar = Scalar::from_bytes_mod_order(spend_secret.0);
    let one_time = spend_scalar + tweak;
    Ok(SecretKey(one_time.to_bytes()))
}
