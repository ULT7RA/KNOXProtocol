use blake3::Hasher;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

fn domain_key(tag: &[u8]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(b"knox-domain-key-v1");
    h.update(&(tag.len() as u64).to_le_bytes());
    h.update(tag);
    *h.finalize().as_bytes()
}

fn new_domain_hasher(tag: &[u8]) -> Hasher {
    let key = domain_key(tag);
    Hasher::new_keyed(&key)
}

pub fn hash_bytes(tag: &[u8], data: &[u8]) -> [u8; 32] {
    let mut hasher = new_domain_hasher(tag);
    hasher.update(&(data.len() as u64).to_le_bytes());
    hasher.update(data);
    let out = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(out.as_bytes());
    bytes
}

pub fn hash_to_scalar(tag: &[u8], data: &[u8]) -> Scalar {
    let mut hasher = new_domain_hasher(tag);
    hasher.update(&(data.len() as u64).to_le_bytes());
    hasher.update(data);
    let mut wide = [0u8; 64];
    let mut reader = hasher.finalize_xof();
    reader.fill(&mut wide);
    Scalar::from_bytes_mod_order_wide(&wide)
}

pub fn hash_to_point(tag: &[u8], data: &[u8]) -> RistrettoPoint {
    let mut hasher = new_domain_hasher(tag);
    hasher.update(&(data.len() as u64).to_le_bytes());
    hasher.update(data);
    let mut wide = [0u8; 64];
    let mut reader = hasher.finalize_xof();
    reader.fill(&mut wide);
    RistrettoPoint::from_uniform_bytes(&wide)
}
