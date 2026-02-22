use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

#[derive(Clone)]
pub struct Prng {
    inner: ChaCha20Rng,
}

impl Prng {
    pub fn new(seed: [u8; 32]) -> Self {
        Self {
            inner: ChaCha20Rng::from_seed(seed),
        }
    }

    pub fn fill_bytes(&mut self, out: &mut [u8]) {
        self.inner.fill_bytes(out)
    }
}

pub fn os_random_bytes(out: &mut [u8]) -> Result<(), String> {
    getrandom::getrandom(out).map_err(|e| format!("getrandom failed: {e}"))
}
