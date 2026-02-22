use crate::params::{CLH_DIMENSION_GROWTH, CLH_UPDATE_INTERVAL, N, Q};

#[derive(Clone, Debug)]
pub struct ImmunityState {
    pub accumulated_entropy: [u8; 64],
    pub effective_n: usize,
    pub hardening_factor: u64,
    pub last_update_height: u64,
    pub solutions_absorbed: u64,
}

impl ImmunityState {
    pub fn genesis() -> Self {
        Self {
            accumulated_entropy: [0u8; 64],
            effective_n: N,
            hardening_factor: 0,
            last_update_height: 0,
            solutions_absorbed: 0,
        }
    }

    pub fn absorb_contribution(&mut self, contribution: &[u8; 32], height: u64) {
        let mut h0 = blake3::Hasher::new();
        h0.update(b"knox-lattice-immunity-accum-v2");
        h0.update(&self.accumulated_entropy);
        h0.update(contribution);
        h0.update(&height.to_le_bytes());
        h0.update(&self.solutions_absorbed.to_le_bytes());
        let head = h0.finalize();

        let mut h1 = blake3::Hasher::new();
        h1.update(b"knox-lattice-immunity-accum-v2-tail");
        h1.update(head.as_bytes());
        h1.update(contribution);
        h1.update(&height.to_le_bytes());
        let tail = h1.finalize();

        self.accumulated_entropy[..32].copy_from_slice(head.as_bytes());
        self.accumulated_entropy[32..].copy_from_slice(tail.as_bytes());
        self.solutions_absorbed = self.solutions_absorbed.saturating_add(1);
        if height > 0 && height % CLH_UPDATE_INTERVAL == 0 {
            self.harden(height);
        }
    }

    pub fn absorb_solution(
        &mut self,
        short_vector: &[i64],
        clh_contribution: &[u8; 32],
        height: u64,
    ) {
        let mut h = blake3::Hasher::new();
        h.update(b"knox-lattice-immunity-solution");
        for coeff in short_vector {
            h.update(&coeff.to_le_bytes());
        }
        h.update(clh_contribution);
        h.update(&height.to_le_bytes());
        let sol = h.finalize();
        self.absorb_contribution(sol.as_bytes(), height);
    }

    pub fn harden(&mut self, height: u64) {
        let updates = height / CLH_UPDATE_INTERVAL;
        self.effective_n = N + updates as usize * CLH_DIMENSION_GROWTH;
        self.hardening_factor = updates;
        self.last_update_height = height;
    }

    pub fn security_bits(&self) -> f64 {
        (self.effective_n as f64) * (Q as f64).log2() / 2.0
    }

    pub fn difficulty_modifier(&self) -> f64 {
        (1.0_f64 - self.hardening_factor as f64 * 0.0001_f64).max(0.80)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.accumulated_entropy);
        out.extend_from_slice(&(self.effective_n as u64).to_le_bytes());
        out.extend_from_slice(&self.hardening_factor.to_le_bytes());
        out.extend_from_slice(&self.last_update_height.to_le_bytes());
        out.extend_from_slice(&self.solutions_absorbed.to_le_bytes());
        out
    }

    pub fn hash(&self) -> [u8; 32] {
        *blake3::hash(&self.to_bytes()).as_bytes()
    }
}
