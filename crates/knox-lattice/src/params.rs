// ULT7Rock Lattice parameters.

pub const N: usize = 1024;
pub const Q: u64 = 12289;
pub const ETA: i64 = 2;
pub const GAMMA: i64 = 19;
pub const LAMBDA: usize = 128;

pub const TARGET_BLOCK_TIME_SECS: u64 = 45;
pub const BLOCKS_PER_YEAR: u64 = 701_560;
pub const ANNUAL_ESCALATION: f64 = 0.08;
pub const DIFFICULTY_WINDOW: u64 = 120;

pub const MEMORY_BASE_BYTES: usize = 64 * 1024 * 1024;
pub const MEMORY_ANNUAL_GROWTH: f64 = 0.04;

pub const MIN_SEQ_STEPS: u64 = 1_000;

pub const CLH_UPDATE_INTERVAL: u64 = 10_000;
pub const CLH_DIMENSION_GROWTH: usize = 1;

pub const DEFAULT_RING_SIZE: usize = 32;
pub const MAX_RING_SIZE: usize = 64;

// Progressive output encryption parameters.
pub const TX_BASE_SECURITY_BITS: u32 = 128;
pub const TX_SECURITY_GROWTH_PER_BLOCK: u32 = 1;
pub const TX_MAX_SECURITY_BITS: u32 = 4096;
pub const TX_KDF_ROUND_BITS: u32 = 64;
