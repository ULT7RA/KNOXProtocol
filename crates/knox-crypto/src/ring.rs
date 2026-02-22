use crate::hash::{hash_to_point, hash_to_scalar};
use crate::rng::os_random_bytes;
use crate::schnorr::{PublicKey, SecretKey};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

#[derive(Clone, Debug)]
pub struct MlsagSignature {
    pub c1: Scalar,
    pub responses: Vec<Vec<Scalar>>,
    pub key_images: Vec<[u8; 32]>,
}

pub fn key_image(secret: &SecretKey, public: &PublicKey) -> Result<[u8; 32], String> {
    let sk = Scalar::from_bytes_mod_order(secret.0);
    let p = CompressedRistretto(public.0)
        .decompress()
        .ok_or_else(|| "invalid public key".to_string())?;
    let hp = hash_to_point(b"knox-ring-h", p.compress().as_bytes());
    Ok((sk * hp).compress().to_bytes())
}

fn challenge(msg: &[u8], l_points: &[RistrettoPoint], r_points: &[RistrettoPoint]) -> Scalar {
    let mut data = Vec::new();
    data.extend_from_slice(msg);
    for p in l_points {
        data.extend_from_slice(p.compress().as_bytes());
    }
    for p in r_points {
        data.extend_from_slice(p.compress().as_bytes());
    }
    hash_to_scalar(b"knox-mlsag-chal", &data)
}

pub fn sign_mlsag(
    msg: &[u8],
    ring: &[Vec<PublicKey>],
    secret_keys: &[SecretKey],
    signer_index: usize,
) -> Result<MlsagSignature, String> {
    let ring_size = ring.len();
    let key_count = ring[0].len();

    let mut key_images = Vec::with_capacity(key_count);
    for j in 0..key_count {
        let pubkey = &ring[signer_index][j];
        let sk = secret_keys
            .get(j)
            .ok_or_else(|| "secret key count mismatch".to_string())?;
        key_images.push(key_image(sk, pubkey)?);
    }

    let mut alpha = vec![Scalar::ZERO; key_count];
    for j in 0..key_count {
        let mut alpha_bytes = [0u8; 64];
        os_random_bytes(&mut alpha_bytes).map_err(|e| format!("rng failure: {e}"))?;
        alpha[j] = Scalar::from_bytes_mod_order_wide(&alpha_bytes);
    }

    let mut c = vec![Scalar::ZERO; ring_size];
    let mut responses = vec![vec![Scalar::ZERO; key_count]; ring_size];

    let mut l_points = vec![RistrettoPoint::default(); key_count];
    let mut r_points = vec![RistrettoPoint::default(); key_count];
    for j in 0..key_count {
        l_points[j] = alpha[j] * RISTRETTO_BASEPOINT_POINT;
        let pubkey = &ring[signer_index][j];
        let p = CompressedRistretto(pubkey.0)
            .decompress()
            .ok_or_else(|| "invalid ring public key".to_string())?;
        let hp = hash_to_point(b"knox-ring-h", p.compress().as_bytes());
        r_points[j] = alpha[j] * hp;
    }

    let next = (signer_index + 1) % ring_size;
    c[next] = challenge(msg, &l_points, &r_points);

    for i in 0..ring_size {
        let idx = (signer_index + 1 + i) % ring_size;
        if idx == signer_index {
            break;
        }
        for j in 0..key_count {
            let mut r_bytes = [0u8; 64];
            os_random_bytes(&mut r_bytes).map_err(|e| format!("rng failure: {e}"))?;
            responses[idx][j] = Scalar::from_bytes_mod_order_wide(&r_bytes);

            let pubkey = &ring[idx][j];
            let p = CompressedRistretto(pubkey.0)
                .decompress()
                .ok_or_else(|| "invalid ring public key".to_string())?;
            let hp = hash_to_point(b"knox-ring-h", p.compress().as_bytes());
            let key_image_point = CompressedRistretto(key_images[j])
                .decompress()
                .ok_or_else(|| "invalid key image".to_string())?;

            l_points[j] = responses[idx][j] * RISTRETTO_BASEPOINT_POINT + c[idx] * p;
            r_points[j] = responses[idx][j] * hp + c[idx] * key_image_point;
        }
        let next_idx = (idx + 1) % ring_size;
        c[next_idx] = challenge(msg, &l_points, &r_points);
    }

    for j in 0..key_count {
        let sk = match secret_keys.get(j) {
            Some(s) => Scalar::from_bytes_mod_order(s.0),
            None => return Err("secret key index out of bounds".to_string()),
        };
        responses[signer_index][j] = alpha[j] - c[signer_index] * sk;
    }

    for a in &mut alpha {
        *a = Scalar::ZERO;
    }

    Ok(MlsagSignature {
        c1: c[0],
        responses,
        key_images,
    })
}

pub fn verify_mlsag(msg: &[u8], ring: &[Vec<PublicKey>], sig: &MlsagSignature) -> bool {
    let ring_size = ring.len();
    if ring_size == 0 {
        return false;
    }
    let key_count = ring[0].len();
    if sig.responses.len() != ring_size {
        return false;
    }
    if sig.key_images.len() != key_count {
        return false;
    }
    for row in &sig.responses {
        if row.len() != key_count {
            return false;
        }
    }

    let mut c = sig.c1;
    let mut l_points = vec![RistrettoPoint::default(); key_count];
    let mut r_points = vec![RistrettoPoint::default(); key_count];

    for i in 0..ring_size {
        for j in 0..key_count {
            let pubkey = &ring[i][j];
            let p = match CompressedRistretto(pubkey.0).decompress() {
                Some(p) => p,
                None => return false,
            };
            let hp = hash_to_point(b"knox-ring-h", p.compress().as_bytes());
            let key_image_point = match CompressedRistretto(sig.key_images[j]).decompress() {
                Some(p) => p,
                None => return false,
            };
            let r_ij = sig.responses[i][j];
            l_points[j] = r_ij * RISTRETTO_BASEPOINT_POINT + c * p;
            r_points[j] = r_ij * hp + c * key_image_point;
        }
        c = challenge(msg, &l_points, &r_points);
    }

    c == sig.c1
}
