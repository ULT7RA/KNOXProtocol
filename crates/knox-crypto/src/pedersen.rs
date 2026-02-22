use crate::hash::hash_to_point;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use std::sync::OnceLock;

fn pedersen_h() -> RistrettoPoint {
    static H_POINT: OnceLock<RistrettoPoint> = OnceLock::new();
    *H_POINT.get_or_init(|| hash_to_point(b"knox-pedersen", b"H"))
}

pub fn commit(value: u64, blind: &Scalar) -> CompressedRistretto {
    let h = pedersen_h();
    let v = Scalar::from(value);
    (v * h + blind * RISTRETTO_BASEPOINT_POINT).compress()
}

pub fn commitment_point(commitment: &[u8; 32]) -> Option<RistrettoPoint> {
    CompressedRistretto(*commitment).decompress()
}

pub fn pedersen_h_point() -> RistrettoPoint {
    pedersen_h()
}
