use knox_types::{BlockHeader, LatticeProof};
use std::ffi::{c_char, c_int, c_void, CString};
use std::path::Path;

const CUDA_FATBIN: &[u8] = include_bytes!("kernelcuda.fatbin");

use crate::params::{
    ANNUAL_ESCALATION, BLOCKS_PER_YEAR, MEMORY_ANNUAL_GROWTH, MEMORY_BASE_BYTES, MIN_SEQ_STEPS, N,
};
use crate::poly::{ntt_forward, ntt_inverse, ntt_pointwise_mul_in_place};
use crate::sample::{hash_to_poly, sample_cbd};
use crate::velox_reaper;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MiningMode {
    Cpu,
    Gpu,
    Hybrid,
}

impl Default for MiningMode {
    fn default() -> Self {
        Self::Hybrid
    }
}

impl MiningMode {
    pub fn parse(v: &str) -> Self {
        match v.trim().to_ascii_lowercase().as_str() {
            "cpu" => Self::Cpu,
            "gpu" => Self::Gpu,
            "hybrid" => Self::Hybrid,
            _ => Self::Hybrid,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Cpu => "cpu",
            Self::Gpu => "gpu",
            Self::Hybrid => "hybrid",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MiningBackend {
    Auto,
    Cpu,
    OpenCl,
    Cuda,
}

impl Default for MiningBackend {
    fn default() -> Self {
        Self::Auto
    }
}

impl MiningBackend {
    pub fn parse(v: &str) -> Self {
        match v.trim().to_ascii_lowercase().as_str() {
            "auto" => Self::Auto,
            "cpu" => Self::Cpu,
            "opencl" | "open_cl" | "ocl" => Self::OpenCl,
            "cuda" => Self::Cuda,
            _ => Self::Auto,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Cpu => "cpu",
            Self::OpenCl => "opencl",
            Self::Cuda => "cuda",
        }
    }
}

#[derive(Clone, Debug)]
pub struct MiningProfile {
    pub mode: MiningMode,
    pub backend: MiningBackend,
    pub difficulty_bits: Option<u32>,
    pub seq_steps: Option<u64>,
    pub memory_bytes: Option<u32>,
    pub cpu_util: u8,
    pub gpu_util: u8,
    pub gpu_device_id: Option<u32>,
    pub cuda_device_ordinal: Option<u32>,
}

impl Default for MiningProfile {
    fn default() -> Self {
        Self {
            mode: MiningMode::Hybrid,
            backend: MiningBackend::Auto,
            difficulty_bits: None,
            seq_steps: None,
            memory_bytes: None,
            cpu_util: 70,
            gpu_util: 100,
            gpu_device_id: None,
            cuda_device_ordinal: None,
        }
    }
}

impl MiningProfile {
    pub fn from_env() -> Self {
        let mode = std::env::var("KNOX_NODE_MINING_MODE")
            .ok()
            .map(|v| MiningMode::parse(&v))
            .unwrap_or_default();
        let backend = std::env::var("KNOX_NODE_MINING_BACKEND")
            .ok()
            .map(|v| MiningBackend::parse(&v))
            .unwrap_or_default();
        let difficulty_bits = parse_env_u32("KNOX_NODE_MINING_DIFFICULTY_BITS");
        let seq_steps = parse_env_u64("KNOX_NODE_MINING_SEQ_STEPS");
        let memory_bytes = parse_env_u32("KNOX_NODE_MINING_MEMORY_BYTES");
        let cpu_util = parse_env_u8("KNOX_NODE_MINING_CPU_UTIL")
            .unwrap_or(70)
            .clamp(1, 100);
        let gpu_util = parse_env_u8("KNOX_NODE_MINING_GPU_UTIL")
            .unwrap_or(90)
            .clamp(1, 100);
        let gpu_device_id = parse_env_u32("KNOX_NODE_GPU_DEVICE_ID");
        let cuda_device_ordinal = parse_env_u32("KNOX_NODE_CUDA_DEVICE_ORDINAL");
        Self {
            mode,
            backend,
            difficulty_bits,
            seq_steps,
            memory_bytes,
            cpu_util,
            gpu_util,
            gpu_device_id,
            cuda_device_ordinal,
        }
    }
}

#[derive(Clone, Debug)]
pub struct MiningBackendStatus {
    pub mode: MiningMode,
    pub configured_backend: MiningBackend,
    pub active_backend: MiningBackend,
    pub available_backends: Vec<MiningBackend>,
    pub fallback_active: bool,
    pub warning: Option<String>,
    pub device_label: String,
}

impl MiningBackendStatus {
    pub fn to_log_line(&self) -> String {
        let available = if self.available_backends.is_empty() {
            "none".to_string()
        } else {
            self.available_backends
                .iter()
                .map(MiningBackend::as_str)
                .collect::<Vec<_>>()
                .join("|")
        };
        let warning = self
            .warning
            .as_ref()
            .map(|v| sanitize_log_value(v))
            .unwrap_or_else(|| "none".to_string());
        format!(
            "active={} configured={} mode={} available={} fallback={} device={} warning={}",
            self.active_backend.as_str(),
            self.configured_backend.as_str(),
            self.mode.as_str(),
            available,
            if self.fallback_active { 1 } else { 0 },
            sanitize_log_value(&self.device_label),
            warning
        )
    }
}

pub fn header_challenge(header: &BlockHeader) -> [u8; 32] {
    let mut data = Vec::with_capacity(1 + 8 + 4 + 32 * 5 + 8 + 32);
    data.push(b'L');
    data.extend_from_slice(&header.height.to_le_bytes());
    data.extend_from_slice(&header.round.to_le_bytes());
    data.extend_from_slice(&header.prev.0);
    data.extend_from_slice(&header.tx_root.0);
    data.extend_from_slice(&header.slash_root.0);
    data.extend_from_slice(&header.state_root.0);
    data.extend_from_slice(&header.timestamp_ms.to_le_bytes());
    data.extend_from_slice(&header.proposer);
    *blake3::hash(&data).as_bytes()
}

pub fn difficulty_bits(height: u64) -> u32 {
    if let Some(bits) = debug_u32("KNOX_LATTICE_DEBUG_DIFFICULTY_BITS") {
        return bits.max(1);
    }
    if mining_debug_enabled() {
        return 6;
    }
    let year = height as f64 / BLOCKS_PER_YEAR as f64;
    let scaled = 12.0 * (1.0 + ANNUAL_ESCALATION).powf(year);
    scaled.round().clamp(10.0, 28.0) as u32
}

pub fn memory_bytes(height: u64) -> u32 {
    if let Some(bytes) = debug_u32("KNOX_LATTICE_DEBUG_MEMORY_BYTES") {
        return bytes.max(1024);
    }
    if mining_debug_enabled() {
        return 8 * 1024 * 1024;
    }
    let year = height as f64 / BLOCKS_PER_YEAR as f64;
    let growth = (1.0 + MEMORY_ANNUAL_GROWTH).powf(year);
    (MEMORY_BASE_BYTES as f64 * growth).round() as u32
}

pub fn sequential_steps(height: u64) -> u64 {
    if let Some(steps) = debug_u64("KNOX_LATTICE_DEBUG_SEQ_STEPS") {
        return steps.max(1);
    }
    if mining_debug_enabled() {
        return 64;
    }
    let year = height as f64 / BLOCKS_PER_YEAR as f64;
    (MIN_SEQ_STEPS as f64 * (1.0 + 0.05 * year)).round() as u64
}

pub fn mining_debug_enabled() -> bool {
    if std::env::var("KNOX_MAINNET_LOCK").ok().as_deref() == Some("1") {
        return false;
    }
    std::env::var("KNOX_LATTICE_MINING_DEBUG")
        .ok()
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn debug_u32(key: &str) -> Option<u32> {
    if !mining_debug_enabled() {
        return None;
    }
    std::env::var(key).ok()?.trim().parse::<u32>().ok()
}

fn debug_u64(key: &str) -> Option<u64> {
    if !mining_debug_enabled() {
        return None;
    }
    std::env::var(key).ok()?.trim().parse::<u64>().ok()
}

fn parse_env_u32(key: &str) -> Option<u32> {
    std::env::var(key).ok()?.trim().parse::<u32>().ok()
}

fn parse_env_u64(key: &str) -> Option<u64> {
    std::env::var(key).ok()?.trim().parse::<u64>().ok()
}

fn parse_env_u8(key: &str) -> Option<u8> {
    std::env::var(key).ok()?.trim().parse::<u8>().ok()
}

fn parse_env_bool(key: &str) -> Option<bool> {
    let raw = std::env::var(key).ok()?;
    let v = raw.trim().to_ascii_lowercase();
    if v.is_empty() {
        return None;
    }
    match v.as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

#[cfg(windows)]
fn detect_dll_windows(name: &str) -> bool {
    static CACHE: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<String, bool>>> = std::sync::OnceLock::new();
    let mut cache = CACHE.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new())).lock().unwrap();
    if let Some(&res) = cache.get(name) {
        return res;
    }

    let windir = std::env::var("WINDIR").unwrap_or_else(|_| "C:\\Windows".to_string());
    let candidates = [
        format!("{windir}\\System32\\{name}"),
        format!("{windir}\\SysWOW64\\{name}"),
    ];
    if candidates.iter().any(|p| Path::new(p).exists()) {
        cache.insert(name.to_string(), true);
        return true;
    }

    let c_name = match std::ffi::CString::new(name) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let handle = unsafe { load_library_a(c_name.as_ptr()) };
    let found = !handle.is_null();
    // Intentionally NEVER call free_library(handle) here.
    // Calling FreeLibrary on nvcuda.dll or OpenCL unloads driver components
    // and corrupts internal state (STATUS_STACK_BUFFER_OVERRUN).
    cache.insert(name.to_string(), found);
    found
}

fn detect_opencl_backend() -> bool {
    if let Some(v) = parse_env_bool("KNOX_FORCE_OPENCL_AVAILABLE") {
        return v;
    }
    #[cfg(windows)]
    {
        detect_dll_windows("OpenCL.dll")
    }
    #[cfg(not(windows))]
    {
        Path::new("/usr/lib/libOpenCL.so").exists()
            || Path::new("/usr/lib/libOpenCL.so.1").exists()
            || Path::new("/usr/lib/x86_64-linux-gnu/libOpenCL.so").exists()
            || Path::new("/usr/lib/x86_64-linux-gnu/libOpenCL.so.1").exists()
    }
}

fn detect_cuda_backend() -> bool {
    if let Some(v) = parse_env_bool("KNOX_FORCE_CUDA_AVAILABLE") {
        return v;
    }
    #[cfg(windows)]
    {
        detect_dll_windows("nvcuda.dll")
    }
    #[cfg(not(windows))]
    {
        Path::new("/usr/lib/libcuda.so").exists()
            || Path::new("/usr/lib/libcuda.so.1").exists()
            || Path::new("/usr/lib/x86_64-linux-gnu/libcuda.so").exists()
            || Path::new("/usr/lib/x86_64-linux-gnu/libcuda.so.1").exists()
    }
}

pub fn detect_available_backends() -> Vec<MiningBackend> {
    let mut out = vec![MiningBackend::Cpu];
    if detect_opencl_backend() {
        out.push(MiningBackend::OpenCl);
    }
    if detect_cuda_backend() {
        out.push(MiningBackend::Cuda);
    }
    out
}

fn sanitize_log_value(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    for ch in v.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.' || ch == '|' {
            out.push(ch);
        } else if ch.is_whitespace() {
            out.push('_');
        }
    }
    if out.is_empty() {
        "none".to_string()
    } else {
        out
    }
}

fn resolve_active_backend(
    mode: MiningMode,
    configured: MiningBackend,
    available: &[MiningBackend],
) -> (MiningBackend, bool, Option<String>) {
    let has_opencl = available.contains(&MiningBackend::OpenCl);
    let has_cuda = available.contains(&MiningBackend::Cuda);
    let has_cpu = available.contains(&MiningBackend::Cpu);
    let gpu_preferred = if has_cuda {
        Some(MiningBackend::Cuda)
    } else if has_opencl {
        Some(MiningBackend::OpenCl)
    } else if has_cpu {
        Some(MiningBackend::Cpu)
    } else {
        None
    };

    if mode == MiningMode::Cpu {
        return (
            MiningBackend::Cpu,
            configured != MiningBackend::Cpu && configured != MiningBackend::Auto,
            if configured != MiningBackend::Cpu && configured != MiningBackend::Auto {
                Some("cpu_mode_forces_cpu_backend".to_string())
            } else {
                None
            },
        );
    }

    let wanted = match configured {
        MiningBackend::Auto => gpu_preferred.unwrap_or(MiningBackend::Cpu),
        MiningBackend::Cpu => MiningBackend::Cpu,
        MiningBackend::OpenCl => MiningBackend::OpenCl,
        MiningBackend::Cuda => MiningBackend::Cuda,
    };
    match wanted {
        MiningBackend::Cuda if has_cuda => (MiningBackend::Cuda, false, None),
        MiningBackend::OpenCl if has_opencl => (MiningBackend::OpenCl, false, None),
        MiningBackend::Cpu if has_cpu => {
            if mode == MiningMode::Gpu {
                (
                    MiningBackend::Cpu,
                    true,
                    Some("gpu_mode_requested_but_no_gpu_backend_available".to_string()),
                )
            } else {
                (MiningBackend::Cpu, false, None)
            }
        }
        _ => {
            if has_cuda {
                (
                    MiningBackend::Cuda,
                    true,
                    Some(format!(
                        "requested_backend_unavailable_{}_using_cuda",
                        wanted.as_str()
                    )),
                )
            } else if has_opencl {
                (
                    MiningBackend::OpenCl,
                    true,
                    Some(format!(
                        "requested_backend_unavailable_{}_using_opencl",
                        wanted.as_str()
                    )),
                )
            } else if has_cpu {
                (
                    MiningBackend::Cpu,
                    true,
                    Some(format!(
                        "requested_backend_unavailable_{}_using_cpu",
                        wanted.as_str()
                    )),
                )
            } else {
                (
                    MiningBackend::Cpu,
                    true,
                    Some("no_backend_available_defaulting_cpu".to_string()),
                )
            }
        }
    }
}

fn leading_zero_bits(hash: &[u8; 32]) -> u32 {
    let mut out = 0u32;
    for b in hash {
        if *b == 0 {
            out += 8;
            continue;
        }
        out += b.leading_zeros();
        break;
    }
    out
}

// ---------------------------------------------------------------------------
// ULT7Rock lattice sequential chain
//
// Computes an NTT-domain multiplication chain of `steps` iterations anchored
// in the block's header hash and a per-nonce starting polynomial.
//
// Returns:
//   (s_final_bytes, digest)
//
// Where:
//   s_final_bytes -- Poly::to_bytes() of the final inverse-NTT polynomial
//                    (2 048 bytes, N x u16 little-endian in [0, Q)).
//   digest        -- BLAKE3("ult7rock-block-v1" || nonce_le8 || s_final_bytes),
//                    the 32-byte value that must satisfy the difficulty target.
//
// The `a_hat` argument is the NTT-domain representation of
// hash_to_poly(header_hash).  It is constant for every nonce in the same
// block and must be pre-computed once by the caller.
fn lattice_sequential_chain(
    a_hat: &[u64; N],
    header_hash: &[u8; 32],
    nonce: u64,
    steps: u64,
) -> (Vec<u8>, [u8; 32]) {
    // Per-nonce seed: header_hash || nonce_le8.
    let mut seed = [0u8; 40];
    seed[..32].copy_from_slice(header_hash);
    seed[32..].copy_from_slice(&nonce.to_le_bytes());

    // Sample a small starting polynomial from the CBD distribution and
    // lift it into the NTT domain for the iterative multiplication chain.
    let s_start = sample_cbd(&seed);
    let mut s_hat = Box::new([0u64; N]);
    for (i, c) in s_start.coeffs().iter().enumerate() {
        s_hat[i] = c.rem_euclid(crate::params::Q as i64) as u64;
    }
    ntt_forward(&mut s_hat);

    // Iterative NTT-domain chain: s_hat = s_hat * a_hat, repeated `steps` times.
    // We break homomorphism by XORing the step index, requiring true sequential evaluation.
    for s in 0..steps {
        ntt_pointwise_mul_in_place(&mut s_hat, a_hat);
        for i in 0..N {
            s_hat[i] = (s_hat[i] ^ s) % (crate::params::Q as u64);
        }
    }

    // Inverse-transform to recover coefficient-domain polynomial, then serialise
    // to 2 048 bytes (N x u16 little-endian, coefficients reduced to [0, Q)).
    ntt_inverse(&mut s_hat);
    let mut final_coeffs = Box::new([0i64; N]);
    for (i, v) in s_hat.iter().enumerate() {
        final_coeffs[i] = *v as i64;
    }
    let s_final = crate::poly::Poly::from_coeffs(*final_coeffs);
    let s_final_bytes = s_final.to_bytes(); // 2 048 bytes

    // Commitment: BLAKE3 over domain tag + nonce + full polynomial bytes.
    // This 32-byte digest is what must satisfy the difficulty target.
    let digest = {
        let mut h = blake3::Hasher::new();
        h.update(b"ult7rock-block-v1");
        h.update(&nonce.to_le_bytes());
        h.update(&s_final_bytes);
        *h.finalize().as_bytes()
    };

    (s_final_bytes, digest)
}

/// Pre-computes the fixed NTT-domain block challenge polynomial.
///
/// Call once per block; pass `a_hat` to every `try_mine_nonce` call to avoid
/// repeating the hash-to-poly and forward-NTT work for each nonce candidate.
fn block_a_hat(header_hash: &[u8; 32]) -> [u64; N] {
    let a = hash_to_poly(header_hash);
    let mut a_hat = Box::new([0u64; N]);
    for (i, c) in a.coeffs().iter().enumerate() {
        a_hat[i] = c.rem_euclid(crate::params::Q as i64) as u64;
    }
    ntt_forward(&mut a_hat);
    *a_hat
}

// DEAD_CODE_SENTINEL: sequential_proof retained as a stub so downstream
// callers outside this crate that may reference it compile without changes.
// The ULT7Rock lattice chain (lattice_sequential_chain) replaces it fully.
#[allow(dead_code)]
pub fn sequential_proof(header_hash: &[u8; 32], nonce: u64, steps: u64) -> [u8; 32] {
    let mut input = Vec::with_capacity(32 + 8);
    input.extend_from_slice(header_hash);
    input.extend_from_slice(&nonce.to_le_bytes());
    let mut h = *blake3::hash(&input).as_bytes();
    for i in 0..steps {
        let mut step = Vec::with_capacity(32 + 8 + 32);
        step.extend_from_slice(&h);
        step.extend_from_slice(&i.to_le_bytes());
        step.extend_from_slice(header_hash);
        h = *blake3::hash(&step).as_bytes();
    }
    h
}

/// VeloxReaper memory-hard pass anchored to the lattice chain output.
///
/// Replaces Argon2id with a pure-lattice DAG that bottlenecks on DRAM
/// latency.  The polynomial bytes from the sequential chain serve as the
/// seed; the previous block hash provides chain binding.
pub fn memory_proof(
    lattice_poly_bytes: &[u8],
    prev_hash: &[u8; 32],
    height: u64,
) -> Result<[u8; 32], String> {
    velox_reaper::memory_proof(lattice_poly_bytes, prev_hash, height)
}

// Retained as a dead-code stub for any external callers that may reference it.
#[allow(dead_code)]
fn pow_hash_legacy(header_hash: &[u8; 32], seq: &[u8; 32], mem: &[u8; 32], nonce: u64) -> [u8; 32] {
    let mut data = Vec::with_capacity(32 + 32 + 32 + 8);
    data.extend_from_slice(header_hash);
    data.extend_from_slice(seq);
    data.extend_from_slice(mem);
    data.extend_from_slice(&nonce.to_le_bytes());
    *blake3::hash(&data).as_bytes()
}

fn clh_contribution(seq: &[u8; 32], mem: &[u8; 32], pow: &[u8; 32]) -> [u8; 32] {
    let mut data = Vec::with_capacity(96);
    data.extend_from_slice(seq);
    data.extend_from_slice(mem);
    data.extend_from_slice(pow);
    *blake3::hash(&data).as_bytes()
}

/// Attempts to produce a valid `LatticeProof` for `nonce`.
///
/// Returns `None` immediately when the commitment digest does not satisfy the
/// difficulty target, keeping the hot-path branch prediction well-defined.
fn try_mine_nonce(
    a_hat: &[u64; N],
    header_hash: &[u8; 32],
    prev_hash: &[u8; 32],
    nonce: u64,
    difficulty_bits: u32,
    steps: u64,
    height: u64,
) -> Option<LatticeProof> {
    let (poly_bytes, digest) = lattice_sequential_chain(a_hat, header_hash, nonce, steps);

    // Fast-reject: most nonces fail here before touching VeloxReaper DAG.
    if leading_zero_bits(&digest) < difficulty_bits.max(1) {
        return None;
    }

    // BLAKE3 digest of the polynomial bytes — stored in `sequential_chain`
    // so the verifier can reconstruct and compare without transmitting 2 048 bytes.
    let seq_digest: [u8; 32] = *blake3::hash(&poly_bytes).as_bytes();

    let mem_hash = memory_proof(&poly_bytes, prev_hash, height).ok()?;
    let contrib = clh_contribution(&seq_digest, &mem_hash, &digest);

    Some(LatticeProof {
        nonce,
        sequential_chain: seq_digest,
        memory_hash: mem_hash,
        pow_hash: digest,
        clh_contribution: contrib,
        difficulty_bits: difficulty_bits.max(1),
    })
}

fn seed_s_hat_for_nonce(header_hash: &[u8; 32], nonce: u64) -> [u64; N] {
    let mut seed = [0u8; 40];
    seed[..32].copy_from_slice(header_hash);
    seed[32..].copy_from_slice(&nonce.to_le_bytes());
    let s_start = sample_cbd(&seed);
    let mut s_hat = Box::new([0u64; N]);
    for (i, c) in s_start.coeffs().iter().enumerate() {
        s_hat[i] = c.rem_euclid(crate::params::Q as i64) as u64;
    }
    ntt_forward(&mut s_hat);
    *s_hat
}

fn proof_from_s_hat_after_chain(
    header: &BlockHeader,
    nonce: u64,
    difficulty_bits: u32,
    height: u64,
    s_hat_after: &[u64],
) -> Option<LatticeProof> {
    if s_hat_after.len() != N {
        return None;
    }
    let mut s_hat_box = Box::new([0u64; N]);
    s_hat_box.copy_from_slice(s_hat_after);
    ntt_inverse(&mut s_hat_box);
    let mut coeffs = Box::new([0i64; N]);
    for (i, v) in s_hat_box.iter().enumerate() {
        coeffs[i] = *v as i64;
    }
    let poly = crate::poly::Poly::from_coeffs(*coeffs);
    let poly_bytes = poly.to_bytes();
    let digest = {
        let mut h = blake3::Hasher::new();
        h.update(b"ult7rock-block-v1");
        h.update(&nonce.to_le_bytes());
        h.update(&poly_bytes);
        *h.finalize().as_bytes()
    };
    if leading_zero_bits(&digest) < difficulty_bits.max(1) {
        return None;
    }
    let seq_digest: [u8; 32] = *blake3::hash(&poly_bytes).as_bytes();
    let mem_hash = memory_proof(&poly_bytes, &header.prev.0, height).ok()?;
    let contrib = clh_contribution(&seq_digest, &mem_hash, &digest);
    Some(LatticeProof {
        nonce,
        sequential_chain: seq_digest,
        memory_hash: mem_hash,
        pow_hash: digest,
        clh_contribution: contrib,
        difficulty_bits: difficulty_bits.max(1),
    })
}

pub fn mine_block_proof(header: &BlockHeader, worker_id: u64) -> LatticeProof {
    mine_block_proof_with_difficulty(header, worker_id, difficulty_bits(header.height))
}

pub fn mine_block_proof_with_difficulty(
    header: &BlockHeader,
    worker_id: u64,
    difficulty_bits: u32,
) -> LatticeProof {
    let steps = sequential_steps(header.height);
    mine_block_proof_custom(header, worker_id, difficulty_bits, steps, header.height)
}

fn mine_block_proof_custom(
    header: &BlockHeader,
    worker_id: u64,
    difficulty_bits: u32,
    steps: u64,
    height: u64,
) -> LatticeProof {
    let header_hash = header_challenge(header);
    // Pre-compute the fixed block challenge once — reused for every nonce.
    let a_hat = block_a_hat(&header_hash);
    let mut nonce = worker_id.wrapping_mul(50_000_000);

    loop {
        nonce = nonce.wrapping_add(1);
        if let Some(proof) = try_mine_nonce(
            &a_hat,
            &header_hash,
            &header.prev.0,
            nonce,
            difficulty_bits,
            steps,
            height,
        ) {
            return proof;
        }
    }
}

fn gpu_nonce_batch_size(profile: &MiningProfile) -> usize {
    let util = (profile.gpu_util as usize).clamp(1, 100);
    // Keep enough in-flight work to saturate modern GPUs; low util still gets
    // a floor to avoid launch overhead dominating.
    let scaled = util.saturating_mul(2048);
    scaled.clamp(8_192, 262_144)
}

fn opencl_chain_batch_size(profile: &MiningProfile) -> usize {
    let util = (profile.gpu_util as usize).max(1);
    util.saturating_mul(2).clamp(8, 128)
}

enum GpuNonceSource {
    OpenCl(OpenClChainSource),
    Cuda(CudaNonceSource),
}

impl GpuNonceSource {
    // OpenCL path applies the lattice chain in place over NTT seeds.
    // CUDA path currently emits nonce ranges for CPU-side lattice evaluation.
    fn apply_or_fill(
        &mut self,
        base_nonce: u64,
        a_hat: &[u64; N],
        steps: u64,
        out: &mut [u64],
    ) -> Result<(), String> {
        match self {
            Self::OpenCl(src) => src.apply_chain(a_hat, steps, out),
            Self::Cuda(src) => src.fill_nonces(base_nonce, out),
        }
    }
}

fn mine_block_proof_gpu_assisted(
    header: &BlockHeader,
    worker_id: u64,
    difficulty_bits: u32,
    steps: u64,
    height: u64,
    backend: MiningBackend,
    profile: &MiningProfile,
) -> Result<LatticeProof, String> {
    let batch_size = if backend == MiningBackend::OpenCl {
        opencl_chain_batch_size(profile)
    } else {
        gpu_nonce_batch_size(profile)
    };
    let mut nonces = vec![0u64; batch_size];
    let mut chain_states = if backend == MiningBackend::OpenCl {
        vec![0u64; batch_size * N]
    } else {
        Vec::new()
    };
    thread_local! {
        static OPENCL_CACHE: std::cell::RefCell<Option<(u32, usize, OpenClChainSource)>> = std::cell::RefCell::new(None);
    }
    // CudaNonceSource holds raw CUDA pointers that are not Send by default.
    // The CUDA driver manages its own internal thread safety, so it is safe to
    // share one instance across threads as long as we serialise access through
    // the Mutex.  We express this with an explicit unsafe Send impl.
    struct SendCudaSource(CudaNonceSource);
    unsafe impl Send for SendCudaSource {}
    static CUDA_GLOBAL: std::sync::OnceLock<std::sync::Mutex<Option<(u32, usize, SendCudaSource)>>> =
        std::sync::OnceLock::new();
    
    match backend {
        MiningBackend::OpenCl => OPENCL_CACHE.with(|c| {
            let ordinal = profile.gpu_device_id.unwrap_or(0);
            let mut b = c.borrow_mut();
            if b.is_none() || b.as_ref().unwrap().0 != ordinal || b.as_ref().unwrap().1 != batch_size {
                if let Ok(src) = OpenClChainSource::new(ordinal, batch_size) {
                    *b = Some((ordinal, batch_size, src));
                }
            }
            if b.is_none() { Err("gpu_backend_required".to_string()) } else { Ok(()) }
        })?,
        MiningBackend::Cuda => {
            let ordinal = profile.cuda_device_ordinal.unwrap_or(0);
            let mut b = CUDA_GLOBAL.get_or_init(|| std::sync::Mutex::new(None)).lock().unwrap();
            if b.is_none() || b.as_ref().unwrap().0 != ordinal {
                eprintln!("[cuda] init ordinal={} batch={}", ordinal, batch_size);
                if let Ok(src) = CudaNonceSource::new(ordinal) {
                    eprintln!("[cuda] init ok");
                    *b = Some((ordinal, batch_size, SendCudaSource(src)));
                } else {
                    eprintln!("[cuda] init FAILED");
                }
            }
            if let Some((_, cached_batch, _)) = b.as_mut() {
                if *cached_batch != batch_size {
                    eprintln!("[cuda] batch update {} -> {}", *cached_batch, batch_size);
                    *cached_batch = batch_size;
                }
            }
            if b.is_none() { return Err("gpu_backend_required".to_string()); }
        },
        _ => return Err("gpu_backend_required".to_string()),
    };

    let header_hash = header_challenge(header);
    // Pre-compute the fixed block challenge once for the entire mining session.
    let a_hat = block_a_hat(&header_hash);
    let mut nonce_base = worker_id.wrapping_mul(50_000_000).wrapping_add(1);

    loop {
        for (i, n) in nonces.iter_mut().enumerate() {
            *n = nonce_base.wrapping_add(i as u64);
        }
        if backend == MiningBackend::OpenCl {
            for (lane, nonce) in nonces.iter().copied().enumerate() {
                let seeded = seed_s_hat_for_nonce(&header_hash, nonce);
                let off = lane * N;
                chain_states[off..off + N].copy_from_slice(&seeded);
            }
            OPENCL_CACHE.with(|c| {
                let mut b = c.borrow_mut();
                b.as_mut().unwrap().2.apply_chain(&a_hat, steps, &mut chain_states)
            })?;
            for (lane, nonce) in nonces.iter().copied().enumerate() {
                let off = lane * N;
                if let Some(proof) = proof_from_s_hat_after_chain(
                    header,
                    nonce,
                    difficulty_bits,
                    height,
                    &chain_states[off..off + N],
                ) {
                    return Ok(proof);
                }
            }
        } else {
            let offload_res = {
                let mut b = CUDA_GLOBAL.get_or_init(|| std::sync::Mutex::new(None)).lock().unwrap();
                b.as_mut().unwrap().2.0.offload_mine(
                    &header_hash, &a_hat,
                    crate::poly::ntt_tw_fwd(), crate::poly::ntt_tw_inv(),
                    nonce_base, steps as u32, difficulty_bits, batch_size
                )
            }?;
            if let Some(winning_nonce) = offload_res {
                if let Some(proof) = try_mine_nonce(
                    &a_hat, &header_hash, &header.prev.0,
                    winning_nonce, difficulty_bits, steps, height
                ) {
                    return Ok(proof);
                }
            }
        }
        nonce_base = nonce_base.wrapping_add(batch_size as u64);
    }
}

struct DynamicLibrary {
    handle: *mut c_void,
}

impl DynamicLibrary {
    fn open(candidates: &[&str]) -> Result<Self, String> {
        for candidate in candidates {
            let c_name = CString::new(*candidate).map_err(|e| e.to_string())?;
            #[cfg(windows)]
            let handle = unsafe { load_library_a(c_name.as_ptr()) };
            #[cfg(unix)]
            let handle = unsafe { dlopen(c_name.as_ptr(), RTLD_NOW) };
            if !handle.is_null() {
                return Ok(Self { handle });
            }
        }
        Err(format!(
            "dynamic_library_not_found_{}",
            candidates.join("|")
        ))
    }

    unsafe fn symbol_raw(&self, name: &str) -> Result<*mut c_void, String> {
        let c_name = CString::new(name).map_err(|e| e.to_string())?;
        #[cfg(windows)]
        let ptr = unsafe { get_proc_address(self.handle, c_name.as_ptr()) };
        #[cfg(unix)]
        let ptr = unsafe { dlsym(self.handle, c_name.as_ptr()) };
        if ptr.is_null() {
            return Err(format!("missing_symbol_{name}"));
        }
        Ok(ptr)
    }
}

impl Drop for DynamicLibrary {
    fn drop(&mut self) {
        // Intentionally do NOT unload GPU driver libraries (nvcuda.dll / libcuda.so /
        // OpenCL ICD loader).  These are driver components that must remain resident for
        // the full process lifetime.  Repeatedly calling FreeLibrary / dlclose corrupts
        // the CUDA driver's internal heap allocator, producing STATUS_STACK_BUFFER_OVERRUN
        // (0xC0000409) and spurious multi-terabyte allocation failures on the next
        // cuModuleLoadData call.  The OS reclaims all handles at process exit.
        let _ = self.handle; // suppress unused-field lint
    }
}

unsafe fn load_symbol<T: Copy>(lib: &DynamicLibrary, name: &str) -> Result<T, String> {
    let raw = unsafe { lib.symbol_raw(name)? };
    Ok(unsafe { std::mem::transmute_copy::<*mut c_void, T>(&raw) })
}

unsafe fn load_symbol_any<T: Copy>(lib: &DynamicLibrary, names: &[&str]) -> Result<T, String> {
    for name in names {
        if let Ok(sym) = unsafe { load_symbol::<T>(lib, name) } {
            return Ok(sym);
        }
    }
    Err(format!("missing_symbol_variants_{}", names.join("|")))
}

#[cfg(windows)]
#[link(name = "kernel32")]
unsafe extern "system" {
    fn LoadLibraryA(lp_lib_file_name: *const c_char) -> *mut c_void;
    fn GetProcAddress(h_module: *mut c_void, lp_proc_name: *const c_char) -> *mut c_void;
    fn FreeLibrary(h_lib_module: *mut c_void) -> c_int;
}

#[cfg(windows)]
unsafe fn load_library_a(name: *const c_char) -> *mut c_void {
    unsafe { LoadLibraryA(name) }
}

#[cfg(windows)]
unsafe fn get_proc_address(module: *mut c_void, proc_name: *const c_char) -> *mut c_void {
    unsafe { GetProcAddress(module, proc_name) }
}

#[cfg(windows)]
unsafe fn free_library(module: *mut c_void) {
    unsafe {
        let _ = FreeLibrary(module);
    }
}

#[cfg(unix)]
const RTLD_NOW: c_int = 2;

#[cfg(unix)]
#[link(name = "dl")]
unsafe extern "C" {
    fn dlopen(filename: *const c_char, flags: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
    fn dlclose(handle: *mut c_void) -> c_int;
}

type ClInt = i32;
type ClUint = u32;
type ClUlong = u64;
type ClBool = u32;
type ClDeviceType = ClUlong;
type ClMemFlags = ClUlong;
type ClPlatformId = *mut c_void;
type ClDeviceId = *mut c_void;
type ClContext = *mut c_void;
type ClCommandQueue = *mut c_void;
type ClProgram = *mut c_void;
type ClKernel = *mut c_void;
type ClMem = *mut c_void;
type ClEvent = *mut c_void;
type ClContextErrCb =
    Option<unsafe extern "C" fn(*const c_char, *const c_void, usize, *mut c_void)>;
type ClBuildCb = Option<unsafe extern "C" fn(ClProgram, *mut c_void)>;

const CL_SUCCESS: ClInt = 0;
const CL_TRUE: ClBool = 1;
const CL_DEVICE_TYPE_GPU: ClDeviceType = 1 << 2;
const CL_MEM_READ_WRITE: ClMemFlags = 1 << 0;
const CL_PROGRAM_BUILD_LOG: ClUint = 0x1183;

type ClGetPlatformIds = unsafe extern "C" fn(ClUint, *mut ClPlatformId, *mut ClUint) -> ClInt;
type ClGetDeviceIds =
    unsafe extern "C" fn(ClPlatformId, ClDeviceType, ClUint, *mut ClDeviceId, *mut ClUint) -> ClInt;
type ClCreateContext = unsafe extern "C" fn(
    *const isize,
    ClUint,
    *const ClDeviceId,
    ClContextErrCb,
    *mut c_void,
    *mut ClInt,
) -> ClContext;
type ClCreateCommandQueue =
    unsafe extern "C" fn(ClContext, ClDeviceId, ClUlong, *mut ClInt) -> ClCommandQueue;
type ClCreateProgramWithSource = unsafe extern "C" fn(
    ClContext,
    ClUint,
    *const *const c_char,
    *const usize,
    *mut ClInt,
) -> ClProgram;
type ClBuildProgram = unsafe extern "C" fn(
    ClProgram,
    ClUint,
    *const ClDeviceId,
    *const c_char,
    ClBuildCb,
    *mut c_void,
) -> ClInt;
type ClGetProgramBuildInfo =
    unsafe extern "C" fn(ClProgram, ClDeviceId, ClUint, usize, *mut c_void, *mut usize) -> ClInt;
type ClCreateKernel = unsafe extern "C" fn(ClProgram, *const c_char, *mut ClInt) -> ClKernel;
type ClCreateBuffer =
    unsafe extern "C" fn(ClContext, ClMemFlags, usize, *mut c_void, *mut ClInt) -> ClMem;
type ClSetKernelArg = unsafe extern "C" fn(ClKernel, ClUint, usize, *const c_void) -> ClInt;
type ClEnqueueNdRangeKernel = unsafe extern "C" fn(
    ClCommandQueue,
    ClKernel,
    ClUint,
    *const usize,
    *const usize,
    *const usize,
    ClUint,
    *const ClEvent,
    *mut ClEvent,
) -> ClInt;
type ClEnqueueReadBuffer = unsafe extern "C" fn(
    ClCommandQueue,
    ClMem,
    ClBool,
    usize,
    usize,
    *mut c_void,
    ClUint,
    *const ClEvent,
    *mut ClEvent,
) -> ClInt;
type ClEnqueueWriteBuffer = unsafe extern "C" fn(
    ClCommandQueue,
    ClMem,
    ClBool,
    usize,
    usize,
    *const c_void,
    ClUint,
    *const ClEvent,
    *mut ClEvent,
) -> ClInt;
type ClFinish = unsafe extern "C" fn(ClCommandQueue) -> ClInt;
type ClReleaseMemObject = unsafe extern "C" fn(ClMem) -> ClInt;
type ClReleaseKernel = unsafe extern "C" fn(ClKernel) -> ClInt;
type ClReleaseProgram = unsafe extern "C" fn(ClProgram) -> ClInt;
type ClReleaseCommandQueue = unsafe extern "C" fn(ClCommandQueue) -> ClInt;
type ClReleaseContext = unsafe extern "C" fn(ClContext) -> ClInt;

struct OpenClFns {
    get_platform_ids: ClGetPlatformIds,
    get_device_ids: ClGetDeviceIds,
    create_context: ClCreateContext,
    create_command_queue: ClCreateCommandQueue,
    create_program_with_source: ClCreateProgramWithSource,
    build_program: ClBuildProgram,
    get_program_build_info: ClGetProgramBuildInfo,
    create_kernel: ClCreateKernel,
    create_buffer: ClCreateBuffer,
    set_kernel_arg: ClSetKernelArg,
    enqueue_nd_range_kernel: ClEnqueueNdRangeKernel,
    enqueue_read_buffer: ClEnqueueReadBuffer,
    enqueue_write_buffer: ClEnqueueWriteBuffer,
    finish: ClFinish,
    release_mem_object: ClReleaseMemObject,
    release_kernel: ClReleaseKernel,
    release_program: ClReleaseProgram,
    release_command_queue: ClReleaseCommandQueue,
    release_context: ClReleaseContext,
}

struct OpenClChainSource {
    _lib: DynamicLibrary,
    fns: OpenClFns,
    context: ClContext,
    queue: ClCommandQueue,
    program: ClProgram,
    kernel: ClKernel,
    a_hat_buffer: ClMem,
    state_buffer: ClMem,
    state_bytes: usize,
    batch_size: usize,
}

impl OpenClChainSource {
    fn new(device_ordinal: u32, batch_size: usize) -> Result<Self, String> {
        #[cfg(windows)]
        let candidates = ["OpenCL.dll"];
        #[cfg(not(windows))]
        let candidates = ["libOpenCL.so.1", "libOpenCL.so"];
        let lib = DynamicLibrary::open(&candidates)?;
        let fns = unsafe {
            OpenClFns {
                get_platform_ids: load_symbol(&lib, "clGetPlatformIDs")?,
                get_device_ids: load_symbol(&lib, "clGetDeviceIDs")?,
                create_context: load_symbol(&lib, "clCreateContext")?,
                create_command_queue: load_symbol(&lib, "clCreateCommandQueue")?,
                create_program_with_source: load_symbol(&lib, "clCreateProgramWithSource")?,
                build_program: load_symbol(&lib, "clBuildProgram")?,
                get_program_build_info: load_symbol(&lib, "clGetProgramBuildInfo")?,
                create_kernel: load_symbol(&lib, "clCreateKernel")?,
                create_buffer: load_symbol(&lib, "clCreateBuffer")?,
                set_kernel_arg: load_symbol(&lib, "clSetKernelArg")?,
                enqueue_nd_range_kernel: load_symbol(&lib, "clEnqueueNDRangeKernel")?,
                enqueue_read_buffer: load_symbol(&lib, "clEnqueueReadBuffer")?,
                enqueue_write_buffer: load_symbol(&lib, "clEnqueueWriteBuffer")?,
                finish: load_symbol(&lib, "clFinish")?,
                release_mem_object: load_symbol(&lib, "clReleaseMemObject")?,
                release_kernel: load_symbol(&lib, "clReleaseKernel")?,
                release_program: load_symbol(&lib, "clReleaseProgram")?,
                release_command_queue: load_symbol(&lib, "clReleaseCommandQueue")?,
                release_context: load_symbol(&lib, "clReleaseContext")?,
            }
        };

        let mut platform_count = 0u32;
        cl_ok(
            unsafe { (fns.get_platform_ids)(0, std::ptr::null_mut(), &mut platform_count) },
            "clGetPlatformIDs_count",
        )?;
        if platform_count == 0 {
            return Err("opencl_no_platforms".to_string());
        }
        let mut platforms = vec![std::ptr::null_mut(); platform_count as usize];
        cl_ok(
            unsafe {
                (fns.get_platform_ids)(platform_count, platforms.as_mut_ptr(), std::ptr::null_mut())
            },
            "clGetPlatformIDs_list",
        )?;

        let mut devices = Vec::<ClDeviceId>::new();
        for platform in platforms {
            let mut count = 0u32;
            let rc = unsafe {
                (fns.get_device_ids)(
                    platform,
                    CL_DEVICE_TYPE_GPU,
                    0,
                    std::ptr::null_mut(),
                    &mut count,
                )
            };
            if rc != CL_SUCCESS || count == 0 {
                continue;
            }
            let mut local = vec![std::ptr::null_mut(); count as usize];
            cl_ok(
                unsafe {
                    (fns.get_device_ids)(
                        platform,
                        CL_DEVICE_TYPE_GPU,
                        count,
                        local.as_mut_ptr(),
                        std::ptr::null_mut(),
                    )
                },
                "clGetDeviceIDs_list",
            )?;
            devices.extend(local);
        }
        if devices.is_empty() {
            return Err("opencl_no_gpu_device".to_string());
        }
        let selected = devices[(device_ordinal as usize).min(devices.len() - 1)];

        let mut err = 0i32;
        let context = unsafe {
            (fns.create_context)(
                std::ptr::null(),
                1,
                &selected,
                None,
                std::ptr::null_mut(),
                &mut err,
            )
        };
        if context.is_null() || err != CL_SUCCESS {
            return Err(format!("opencl_create_context_failed_{err}"));
        }
        let queue = unsafe { (fns.create_command_queue)(context, selected, 0, &mut err) };
        if queue.is_null() || err != CL_SUCCESS {
            unsafe {
                let _ = (fns.release_context)(context);
            }
            return Err(format!("opencl_create_queue_failed_{err}"));
        }

        let source = CString::new(OPENCL_CHAIN_KERNEL).map_err(|e| e.to_string())?;
        let source_ptrs = [source.as_ptr()];
        let source_lens = [OPENCL_CHAIN_KERNEL.len()];
        let program = unsafe {
            (fns.create_program_with_source)(
                context,
                1,
                source_ptrs.as_ptr(),
                source_lens.as_ptr(),
                &mut err,
            )
        };
        if program.is_null() || err != CL_SUCCESS {
            unsafe {
                let _ = (fns.release_command_queue)(queue);
                let _ = (fns.release_context)(context);
            }
            return Err(format!("opencl_create_program_failed_{err}"));
        }
        let build_rc = unsafe {
            (fns.build_program)(
                program,
                1,
                &selected,
                std::ptr::null(),
                None,
                std::ptr::null_mut(),
            )
        };
        if build_rc != CL_SUCCESS {
            let mut log_size = 0usize;
            let _ = unsafe {
                (fns.get_program_build_info)(
                    program,
                    selected,
                    CL_PROGRAM_BUILD_LOG,
                    0,
                    std::ptr::null_mut(),
                    &mut log_size,
                )
            };
            let mut log = vec![0u8; log_size.max(1)];
            let _ = unsafe {
                (fns.get_program_build_info)(
                    program,
                    selected,
                    CL_PROGRAM_BUILD_LOG,
                    log.len(),
                    log.as_mut_ptr() as *mut c_void,
                    std::ptr::null_mut(),
                )
            };
            unsafe {
                let _ = (fns.release_program)(program);
                let _ = (fns.release_command_queue)(queue);
                let _ = (fns.release_context)(context);
            }
            return Err(format!(
                "opencl_build_program_failed_{}_{}",
                build_rc,
                String::from_utf8_lossy(&log).trim_end_matches('\0')
            ));
        }

        let kernel_name = CString::new("knox_apply_chain").map_err(|e| e.to_string())?;
        let kernel = unsafe { (fns.create_kernel)(program, kernel_name.as_ptr(), &mut err) };
        if kernel.is_null() || err != CL_SUCCESS {
            unsafe {
                let _ = (fns.release_program)(program);
                let _ = (fns.release_command_queue)(queue);
                let _ = (fns.release_context)(context);
            }
            return Err(format!("opencl_create_kernel_failed_{err}"));
        }

        let a_hat_bytes = N
            .checked_mul(std::mem::size_of::<u64>())
            .ok_or_else(|| "opencl_a_hat_size_overflow".to_string())?;
        let state_bytes = batch_size
            .checked_mul(N)
            .and_then(|v| v.checked_mul(std::mem::size_of::<u64>()))
            .ok_or_else(|| "opencl_state_size_overflow".to_string())?;
        let a_hat_buffer = unsafe {
            (fns.create_buffer)(
                context,
                CL_MEM_READ_WRITE,
                a_hat_bytes,
                std::ptr::null_mut(),
                &mut err,
            )
        };
        if a_hat_buffer.is_null() || err != CL_SUCCESS {
            unsafe {
                let _ = (fns.release_kernel)(kernel);
                let _ = (fns.release_program)(program);
                let _ = (fns.release_command_queue)(queue);
                let _ = (fns.release_context)(context);
            }
            return Err(format!("opencl_create_buffer_failed_{err}"));
        }
        let state_buffer = unsafe {
            (fns.create_buffer)(
                context,
                CL_MEM_READ_WRITE,
                state_bytes,
                std::ptr::null_mut(),
                &mut err,
            )
        };
        if state_buffer.is_null() || err != CL_SUCCESS {
            unsafe {
                let _ = (fns.release_mem_object)(a_hat_buffer);
                let _ = (fns.release_kernel)(kernel);
                let _ = (fns.release_program)(program);
                let _ = (fns.release_command_queue)(queue);
                let _ = (fns.release_context)(context);
            }
            return Err(format!("opencl_create_state_buffer_failed_{err}"));
        }

        Ok(Self {
            _lib: lib,
            fns,
            context,
            queue,
            program,
            kernel,
            a_hat_buffer,
            state_buffer,
            state_bytes,
            batch_size,
        })
    }

    fn apply_chain(
        &mut self,
        a_hat: &[u64; N],
        steps: u64,
        states: &mut [u64],
    ) -> Result<(), String> {
        if states.len() != self.batch_size * N {
            return Err("opencl_states_size_mismatch".to_string());
        }
        if states.len().saturating_mul(std::mem::size_of::<u64>()) > self.state_bytes {
            return Err("opencl_state_buffer_too_small".to_string());
        }
        cl_ok(
            unsafe {
                (self.fns.enqueue_write_buffer)(
                    self.queue,
                    self.a_hat_buffer,
                    CL_TRUE,
                    0,
                    N.saturating_mul(std::mem::size_of::<u64>()),
                    a_hat.as_ptr() as *const c_void,
                    0,
                    std::ptr::null(),
                    std::ptr::null_mut(),
                )
            },
            "clEnqueueWriteBuffer_a_hat",
        )?;
        cl_ok(
            unsafe {
                (self.fns.set_kernel_arg)(
                    self.kernel,
                    0,
                    std::mem::size_of::<ClMem>(),
                    &self.a_hat_buffer as *const ClMem as *const c_void,
                )
            },
            "clSetKernelArg_a_hat",
        )?;
        cl_ok(
            unsafe {
                (self.fns.set_kernel_arg)(
                    self.kernel,
                    1,
                    std::mem::size_of::<ClMem>(),
                    &self.state_buffer as *const ClMem as *const c_void,
                )
            },
            "clSetKernelArg_state",
        )?;
        cl_ok(
            unsafe {
                (self.fns.set_kernel_arg)(
                    self.kernel,
                    2,
                    std::mem::size_of::<u64>(),
                    &steps as *const u64 as *const c_void,
                )
            },
            "clSetKernelArg_steps",
        )?;
        cl_ok(
            unsafe {
                (self.fns.enqueue_write_buffer)(
                    self.queue,
                    self.state_buffer,
                    CL_TRUE,
                    0,
                    states.len().saturating_mul(std::mem::size_of::<u64>()),
                    states.as_ptr() as *const c_void,
                    0,
                    std::ptr::null(),
                    std::ptr::null_mut(),
                )
            },
            "clEnqueueWriteBuffer_state",
        )?;
        let global = [self.batch_size];
        cl_ok(
            unsafe {
                (self.fns.enqueue_nd_range_kernel)(
                    self.queue,
                    self.kernel,
                    1,
                    std::ptr::null(),
                    global.as_ptr(),
                    std::ptr::null(),
                    0,
                    std::ptr::null(),
                    std::ptr::null_mut(),
                )
            },
            "clEnqueueNDRangeKernel",
        )?;
        cl_ok(
            unsafe { (self.fns.finish)(self.queue) },
            "clFinish_after_kernel",
        )?;
        cl_ok(
            unsafe {
                (self.fns.enqueue_read_buffer)(
                    self.queue,
                    self.state_buffer,
                    CL_TRUE,
                    0,
                    states.len().saturating_mul(std::mem::size_of::<u64>()),
                    states.as_mut_ptr() as *mut c_void,
                    0,
                    std::ptr::null(),
                    std::ptr::null_mut(),
                )
            },
            "clEnqueueReadBuffer",
        )?;
        cl_ok(
            unsafe { (self.fns.finish)(self.queue) },
            "clFinish_after_read",
        )
    }
}

impl Drop for OpenClChainSource {
    fn drop(&mut self) {
        unsafe {
            if !self.state_buffer.is_null() {
                let _ = (self.fns.release_mem_object)(self.state_buffer);
            }
            if !self.a_hat_buffer.is_null() {
                let _ = (self.fns.release_mem_object)(self.a_hat_buffer);
            }
            if !self.kernel.is_null() {
                let _ = (self.fns.release_kernel)(self.kernel);
            }
            if !self.program.is_null() {
                let _ = (self.fns.release_program)(self.program);
            }
            if !self.queue.is_null() {
                let _ = (self.fns.release_command_queue)(self.queue);
            }
            if !self.context.is_null() {
                let _ = (self.fns.release_context)(self.context);
            }
        }
    }
}

type CuResult = i32;
type CuDevice = i32;
type CuContext = *mut c_void;
type CuModule = *mut c_void;
type CuFunction = *mut c_void;
type CuStream = *mut c_void;
type CuDevicePtr = u64;

const CUDA_SUCCESS: CuResult = 0;

type CuInit = unsafe extern "C" fn(u32) -> CuResult;
type CuDeviceGetCount = unsafe extern "C" fn(*mut c_int) -> CuResult;
type CuDeviceGet = unsafe extern "C" fn(*mut CuDevice, c_int) -> CuResult;
type CuCtxCreate = unsafe extern "C" fn(*mut CuContext, u32, CuDevice) -> CuResult;
type CuCtxDestroy = unsafe extern "C" fn(CuContext) -> CuResult;
type CuModuleLoadData = unsafe extern "C" fn(*mut CuModule, *const c_void) -> CuResult;
type CuModuleUnload = unsafe extern "C" fn(CuModule) -> CuResult;
type CuModuleGetFunction =
    unsafe extern "C" fn(*mut CuFunction, CuModule, *const c_char) -> CuResult;
type CuMemAlloc = unsafe extern "C" fn(*mut CuDevicePtr, usize) -> CuResult;
type CuMemFree = unsafe extern "C" fn(CuDevicePtr) -> CuResult;
type CuMemcpyDtoH = unsafe extern "C" fn(*mut c_void, CuDevicePtr, usize) -> CuResult;
type CuMemcpyHtoD = unsafe extern "C" fn(CuDevicePtr, *const std::ffi::c_void, usize) -> CuResult;
type CuLaunchKernel = unsafe extern "C" fn(
    CuFunction,
    u32,
    u32,
    u32,
    u32,
    u32,
    u32,
    u32,
    CuStream,
    *mut *mut c_void,
    *mut *mut c_void,
) -> CuResult;
type CuCtxSynchronize = unsafe extern "C" fn() -> CuResult;
type CuCtxSetCurrent = unsafe extern "C" fn(CuContext) -> CuResult;
type CuStreamCreate = unsafe extern "C" fn(*mut CuStream, u32) -> CuResult;
type CuStreamDestroy = unsafe extern "C" fn(CuStream) -> CuResult;
type CuStreamSynchronize = unsafe extern "C" fn(CuStream) -> CuResult;

struct CudaFns {
    init: CuInit,
    device_get_count: CuDeviceGetCount,
    device_get: CuDeviceGet,
    ctx_create: CuCtxCreate,
    ctx_destroy: CuCtxDestroy,
    ctx_set_current: CuCtxSetCurrent,
    module_load_data: CuModuleLoadData,
    module_unload: CuModuleUnload,
    module_get_function: CuModuleGetFunction,
    mem_alloc: CuMemAlloc,
    mem_free: CuMemFree,
    memcpy_dtoh: CuMemcpyDtoH,
    memcpy_htod: CuMemcpyHtoD,
    launch_kernel: CuLaunchKernel,
    ctx_synchronize: CuCtxSynchronize,
    stream_create: CuStreamCreate,
    stream_destroy: CuStreamDestroy,
    stream_synchronize: CuStreamSynchronize,
}




struct CudaNonceSource {
    _lib: DynamicLibrary,
    fns: CudaFns,
    context: CuContext,
    module: CuModule,
    kernel: CuFunction,
    
    header_hash_ptr: CuDevicePtr,
    a_hat_ptr: CuDevicePtr,
    twiddle_fwd_ptr: CuDevicePtr,
    twiddle_inv_ptr: CuDevicePtr,
    // Double-buffering: 2 streams + 2 output buffer pairs (flag + nonce).
    // Slot N's kernel runs on streams[N]; results land in out_flag_ptrs[N] / out_nonce_ptrs[N].
    streams: [CuStream; 2],
    out_nonce_ptrs: [CuDevicePtr; 2],
    out_flag_ptrs: [CuDevicePtr; 2],
    // Which slot has a kernel currently in-flight (None on first call).
    pending_slot: Option<usize>,
    // Which slot will be used for the next launch.
    current_slot: usize,
    // Reused host-side staging buffers to avoid per-launch allocations.
    host_a_32: Vec<u32>,
    host_fw_32: Vec<u32>,
    host_iv_32: Vec<u32>,
    // Cache the last uploaded header so static GPU data is only re-uploaded on block change.
    cached_header: [u8; 32],
}

impl CudaNonceSource {
    fn new(device_ordinal: u32) -> Result<Self, String> {
        #[cfg(windows)]
        let candidates = ["nvcuda.dll"];
        #[cfg(not(windows))]
        let candidates = ["libcuda.so.1", "libcuda.so"];
        let lib = DynamicLibrary::open(&candidates)?;
        let fns = unsafe {
            CudaFns {
                init: load_symbol(&lib, "cuInit")?,
                device_get_count: load_symbol(&lib, "cuDeviceGetCount")?,
                device_get: load_symbol(&lib, "cuDeviceGet")?,
                ctx_create: load_symbol_any(&lib, &["cuCtxCreate_v2", "cuCtxCreate"])?,
                ctx_destroy: load_symbol_any(&lib, &["cuCtxDestroy_v2", "cuCtxDestroy"])?,
                ctx_set_current: load_symbol(&lib, "cuCtxSetCurrent")?,
                module_load_data: load_symbol(&lib, "cuModuleLoadData")?,
                module_unload: load_symbol(&lib, "cuModuleUnload")?,
                module_get_function: load_symbol(&lib, "cuModuleGetFunction")?,
                mem_alloc: load_symbol_any(&lib, &["cuMemAlloc_v2", "cuMemAlloc"])?,
                mem_free: load_symbol_any(&lib, &["cuMemFree_v2", "cuMemFree"])?,
                memcpy_dtoh: load_symbol_any(&lib, &["cuMemcpyDtoH_v2", "cuMemcpyDtoH"])?,
                memcpy_htod: load_symbol_any(&lib, &["cuMemcpyHtoD_v2", "cuMemcpyHtoD"])?,
                launch_kernel: load_symbol(&lib, "cuLaunchKernel")?,
                ctx_synchronize: load_symbol(&lib, "cuCtxSynchronize")?,
                stream_create: load_symbol(&lib, "cuStreamCreate")?,
                stream_destroy: load_symbol(&lib, "cuStreamDestroy")?,
                stream_synchronize: load_symbol(&lib, "cuStreamSynchronize")?,
            }
        };

        if let Err(e) = cuda_ok(unsafe { (fns.init)(0) }, "cuInit") {
            eprintln!("[cuda] cuInit failed: {}", e);
            return Err(e);
        }
        let mut count = 0 as c_int;
        cuda_ok(unsafe { (fns.device_get_count)(&mut count as *mut _) }, "cuDeviceGetCount")?;
        if count <= 0 { return Err("cuda_no_gpu_device".to_string()); }
        let mut device = 0i32;
        let selected = (device_ordinal as c_int).min(count - 1);
        cuda_ok(unsafe { (fns.device_get)(&mut device as *mut _, selected) }, "cuDeviceGet")?;

        let mut context: CuContext = std::ptr::null_mut();
        cuda_ok(unsafe { (fns.ctx_create)(&mut context as *mut _, 0, device) }, "cuCtxCreate")?;

        let mut module = std::ptr::null_mut();
        if let Err(e) = cuda_ok(unsafe { (fns.module_load_data)(&mut module as *mut _, CUDA_FATBIN.as_ptr() as *const _) }, "cuModuleLoadData") {
            eprintln!("[cuda] cuModuleLoadData failed: {} (fatbin size={})", e, CUDA_FATBIN.len());
            unsafe { let _ = (fns.ctx_destroy)(context); }
            return Err(e);
        }
        let kernel_name = std::ffi::CString::new("knox_full_offload").map_err(|e| e.to_string())?;
        let mut kernel = std::ptr::null_mut();
        if let Err(e) = cuda_ok(unsafe { (fns.module_get_function)(&mut kernel as *mut _, module, kernel_name.as_ptr()) }, "cuModuleGetFunction") {
            eprintln!("[cuda] cuModuleGetFunction('knox_full_offload') failed: {}", e);
            unsafe { let _ = (fns.module_unload)(module); let _ = (fns.ctx_destroy)(context); }
            return Err(e);
        }

        let mut header_hash_ptr = 0u64;
        let mut a_hat_ptr = 0u64;
        let mut twiddle_fwd_ptr = 0u64;
        let mut twiddle_inv_ptr = 0u64;
        let mut out_nonce_ptr0 = 0u64;
        let mut out_nonce_ptr1 = 0u64;
        let mut out_flag_ptr0 = 0u64;
        let mut out_flag_ptr1 = 0u64;
        let mut stream0: CuStream = std::ptr::null_mut();
        let mut stream1: CuStream = std::ptr::null_mut();

        unsafe {
        cuda_ok(unsafe { (fns.mem_alloc)(&mut header_hash_ptr as *mut _, 32) }, "cuMemAlloc_header")?;
        cuda_ok(unsafe { (fns.mem_alloc)(&mut a_hat_ptr as *mut _, (N * 4) as usize) }, "cuMemAlloc_ahat")?;
        cuda_ok(unsafe { (fns.mem_alloc)(&mut twiddle_fwd_ptr as *mut _, (N * 4) as usize) }, "cuMemAlloc_fwd")?;
        cuda_ok(unsafe { (fns.mem_alloc)(&mut twiddle_inv_ptr as *mut _, (N * 4) as usize) }, "cuMemAlloc_inv")?;
        cuda_ok(unsafe { (fns.mem_alloc)(&mut out_nonce_ptr0 as *mut _, 8) }, "cuMemAlloc_nonce0")?;
        cuda_ok(unsafe { (fns.mem_alloc)(&mut out_nonce_ptr1 as *mut _, 8) }, "cuMemAlloc_nonce1")?;
        cuda_ok(unsafe { (fns.mem_alloc)(&mut out_flag_ptr0 as *mut _, 4) }, "cuMemAlloc_flag0")?;
        cuda_ok(unsafe { (fns.mem_alloc)(&mut out_flag_ptr1 as *mut _, 4) }, "cuMemAlloc_flag1")?;
        cuda_ok(unsafe { (fns.stream_create)(&mut stream0 as *mut _, 0) }, "cuStreamCreate_0")?;
        cuda_ok(unsafe { (fns.stream_create)(&mut stream1 as *mut _, 0) }, "cuStreamCreate_1")?;
        }

        Ok(Self {
            _lib: lib, fns, context, module, kernel,
            header_hash_ptr, a_hat_ptr, twiddle_fwd_ptr, twiddle_inv_ptr,
            streams: [stream0, stream1],
            out_nonce_ptrs: [out_nonce_ptr0, out_nonce_ptr1],
            out_flag_ptrs: [out_flag_ptr0, out_flag_ptr1],
            pending_slot: None,
            current_slot: 0,
            host_a_32: vec![0u32; N],
            host_fw_32: vec![0u32; N],
            host_iv_32: vec![0u32; N],
            cached_header: [0u8; 32],
        })
    }

    fn fill_nonces(&mut self, _base: u64, _out: &mut [u64]) -> Result<(), String> {
        Ok(()) // unused now, handled in mine loop
    }

    fn offload_mine(&mut self, header_hash: &[u8; 32], a_hat: &[u64; N],
                    twiddle_fwd: &[u64], twiddle_inv: &[u64],
                    base_nonce: u64, steps: u32, difficulty_bits: u32, batch_size: usize) -> Result<Option<u64>, String> {

        // Bind the CUDA context to whatever Tokio worker thread we're on.
        // cuCtxCreate only binds to the creating thread; without this call,
        // any thread rotation causes all CUDA ops to run with no context
        // → driver reads garbage → 113 GB phantom allocation → crash.
        cuda_ok(unsafe { (self.fns.ctx_set_current)(self.context) }, "cuCtxSetCurrent")?;

        // ---- Phase 1: collect result from the previously-launched slot (if any) ----
        // We sync *before* touching shared static buffers so there's no write-while-read race
        // if the header changed and we need to re-upload a_hat / twiddles.
        let prev_result: Option<u64> = if let Some(pending) = self.pending_slot {
            cuda_ok(unsafe { (self.fns.stream_synchronize)(self.streams[pending]) }, "cuStreamSynchronize")?;
            let mut host_flag = [0u32];
            cuda_ok(unsafe { (self.fns.memcpy_dtoh)(host_flag.as_mut_ptr() as *mut _, self.out_flag_ptrs[pending], 4) }, "cuMemcpyDtoH_flag")?;
            if host_flag[0] == 1 {
                let mut host_nonce = [0u64];
                cuda_ok(unsafe { (self.fns.memcpy_dtoh)(host_nonce.as_mut_ptr() as *mut _, self.out_nonce_ptrs[pending], 8) }, "cuMemcpyDtoH_nonce")?;
                Some(host_nonce[0])
            } else {
                None
            }
        } else {
            None
        };

        // ---- Phase 2: launch next kernel on current_slot asynchronously ----
        let slot = self.current_slot;
        let stream = self.streams[slot];
        let zero_flag = [0u32];

        // Only re-upload static block data when the header changes (new block).
        // Safe: pending slot's stream was synced above, so GPU is done reading these buffers.
        if *header_hash != self.cached_header {
            for i in 0..N {
                self.host_a_32[i] = a_hat[i] as u32;
                self.host_fw_32[i] = twiddle_fwd[i] as u32;
                self.host_iv_32[i] = twiddle_inv[i] as u32;
            }
            cuda_ok(unsafe { (self.fns.memcpy_htod)(self.header_hash_ptr, header_hash.as_ptr() as *const _, 32) }, "cuMemcpyHtoD_header")?;
            cuda_ok(unsafe { (self.fns.memcpy_htod)(self.a_hat_ptr, self.host_a_32.as_ptr() as *const _, N * 4) }, "cuMemcpyHtoD_ahat")?;
            cuda_ok(unsafe { (self.fns.memcpy_htod)(self.twiddle_fwd_ptr, self.host_fw_32.as_ptr() as *const _, N * 4) }, "cuMemcpyHtoD_fwd")?;
            cuda_ok(unsafe { (self.fns.memcpy_htod)(self.twiddle_inv_ptr, self.host_iv_32.as_ptr() as *const _, N * 4) }, "cuMemcpyHtoD_inv")?;
            self.cached_header = *header_hash;
        }

        // Reset this slot's output flag so the kernel can set it if it finds a nonce.
        cuda_ok(unsafe { (self.fns.memcpy_htod)(self.out_flag_ptrs[slot], zero_flag.as_ptr() as *const _, 4) }, "cuMemcpyHtoD_flag")?;

        let block_x = 256u32;
        let grid_x = ((batch_size as u32).saturating_add(block_x - 1)) / block_x;

        let mut p_header = self.header_hash_ptr;
        let mut p_ahat = self.a_hat_ptr;
        let mut p_tw_fwd = self.twiddle_fwd_ptr;
        let mut p_tw_inv = self.twiddle_inv_ptr;
        let mut p_nonce = base_nonce;
        let mut p_steps = steps;
        let mut p_diff = difficulty_bits;
        let mut p_out_nonce = self.out_nonce_ptrs[slot];
        let mut p_out_flag = self.out_flag_ptrs[slot];

        let mut params = [
            &mut p_header as *mut _ as *mut c_void,
            &mut p_ahat as *mut _ as *mut c_void,
            &mut p_tw_fwd as *mut _ as *mut c_void,
            &mut p_tw_inv as *mut _ as *mut c_void,
            &mut p_nonce as *mut _ as *mut c_void,
            &mut p_steps as *mut _ as *mut c_void,
            &mut p_diff as *mut _ as *mut c_void,
            &mut p_out_nonce as *mut _ as *mut c_void,
            &mut p_out_flag as *mut _ as *mut c_void,
        ];

        // Launch asynchronously on this slot's stream — GPU runs while CPU returns.
        cuda_ok(unsafe { (self.fns.launch_kernel)(
            self.kernel, grid_x.max(1), 1, 1, block_x, 1, 1, 16384,
            stream, params.as_mut_ptr(), std::ptr::null_mut()
        ) }, "cuLaunchKernel")?;

        // Advance the double-buffer: next call will sync this slot and launch on the other.
        self.pending_slot = Some(slot);
        self.current_slot = 1 - slot;

        // Return the result from the *previous* kernel (one-batch pipeline delay).
        // The caller retries until a nonce is found; a single-batch delay is inconsequential.
        Ok(prev_result)
    }
}



fn cl_ok(code: ClInt, what: &str) -> Result<(), String> {
    if code == CL_SUCCESS {
        Ok(())
    } else {
        Err(format!("{what}_failed_{code}"))
    }
}

fn cuda_ok(code: CuResult, what: &str) -> Result<(), String> {
    if code == CUDA_SUCCESS {
        Ok(())
    } else {
        Err(format!("{what}_failed_{code}"))
    }
}

// ---------------------------------------------------------------------------
// OpenCL kernel: lattice sequential chain in NTT domain (full offload step).
//
// Each lane owns one candidate state of size N and applies:
//   state[i] = state[i] * a_hat[i] mod Q
// for `steps` iterations.
//
// Host performs inverse NTT + digest + memory proof after kernel completion.
// ---------------------------------------------------------------------------
const OPENCL_CHAIN_KERNEL: &str = r#"
#define KNOX_N 1024UL
#define KNOX_Q 12289UL

__kernel void knox_apply_chain(__global const ulong *a_hat,
                               __global ulong *states,
                               ulong steps)
{
    const ulong lane = (ulong)get_global_id(0);
    const ulong base = lane * KNOX_N;
    for (ulong s = 0UL; s < steps; ++s) {
        for (ulong i = 0UL; i < KNOX_N; ++i) {
            const ulong lhs = states[base + i];
            const ulong rhs = a_hat[i];
            ulong val = (lhs * rhs) % KNOX_Q;
            val ^= s;
            states[base + i] = val % KNOX_Q;
        }
    }
}
"#;

// CUDA runtime loads the embedded fatbin at startup.

pub fn mine_block_proof_with_profile(
    header: &BlockHeader,
    worker_id: u64,
    expected_difficulty_bits: u32,
    profile: &MiningProfile,
) -> Result<(LatticeProof, MiningBackendStatus), String> {
    let available = detect_available_backends();
    let (active_backend, mut fallback_active, mut warning) =
        resolve_active_backend(profile.mode, profile.backend, &available);

    let difficulty = expected_difficulty_bits.max(1);
    let mut steps = sequential_steps(header.height);
    let height = header.height;

    // Keep mainnet deterministic: explicit profile overrides only apply in debug mode.
    if mining_debug_enabled() {
        if let Some(v) = profile.seq_steps {
            steps = v.max(1);
        }
    }

    let backend_salt = match active_backend {
        MiningBackend::Auto => 0x0A0A_0A0A_0A0A_0A0A,
        MiningBackend::Cpu => 0x4350_552D_4D49_4E45,
        MiningBackend::OpenCl => 0x4F50_454E_434C_2D31,
        MiningBackend::Cuda => 0x4355_4441_2D4D_494E,
    };
    let mode_salt = match profile.mode {
        MiningMode::Cpu => 0x4350_552D_4D4F_4445,
        MiningMode::Gpu => 0x4750_552D_4D4F_4445,
        MiningMode::Hybrid => 0x4849_4252_4944_2D31,
    };
    let effective_worker_id = worker_id ^ backend_salt ^ mode_salt;
    if profile.mode == MiningMode::Gpu
        && active_backend != MiningBackend::OpenCl
        && active_backend != MiningBackend::Cuda
    {
        let status = MiningBackendStatus {
            mode: profile.mode,
            configured_backend: profile.backend,
            active_backend,
            available_backends: available,
            fallback_active: true,
            warning: Some("gpu_mode_requires_opencl_or_cuda".to_string()),
            device_label: "gpu-unavailable".to_string(),
        };
        return Err(status.to_log_line());
    }

    let proof = match active_backend {
        MiningBackend::OpenCl | MiningBackend::Cuda => {
            match mine_block_proof_gpu_assisted(
                header,
                effective_worker_id,
                difficulty,
                steps,
                height,
                active_backend,
                profile,
            ) {
                Ok(proof) => proof,
                Err(err) => {
                    if profile.mode == MiningMode::Gpu {
                        return Err(format!(
                            "gpu_mode_runtime_failure backend={} error={}",
                            active_backend.as_str(),
                            sanitize_log_value(&err)
                        ));
                    }
                    fallback_active = true;
                    let tag = format!(
                        "{}_runtime_error_{}",
                        active_backend.as_str(),
                        sanitize_log_value(&err)
                    );
                    warning = Some(match warning {
                        Some(prev) => format!("{prev}|{tag}"),
                        None => tag,
                    });
                    mine_block_proof_custom(header, effective_worker_id, difficulty, steps, height)
                }
            }
        }
        _ => mine_block_proof_custom(header, effective_worker_id, difficulty, steps, height),
    };

    let device_label = match active_backend {
        MiningBackend::Cuda => profile
            .cuda_device_ordinal
            .map(|v| format!("cuda-{v}"))
            .unwrap_or_else(|| "cuda-auto".to_string()),
        MiningBackend::OpenCl => profile
            .gpu_device_id
            .map(|v| format!("opencl-{v}"))
            .unwrap_or_else(|| "opencl-auto".to_string()),
        _ => "cpu-main".to_string(),
    };
    Ok((
        proof,
        MiningBackendStatus {
            mode: profile.mode,
            configured_backend: profile.backend,
            active_backend,
            available_backends: available,
            fallback_active,
            warning,
            device_label,
        },
    ))
}

pub fn verify_block_proof(header: &BlockHeader, proof: &LatticeProof) -> bool {
    verify_block_proof_with_difficulty(header, proof, difficulty_bits(header.height))
}

pub fn verify_block_proof_with_difficulty(
    header: &BlockHeader,
    proof: &LatticeProof,
    expected_difficulty_bits: u32,
) -> bool {
    explain_block_proof_failure_with_difficulty(header, proof, expected_difficulty_bits).is_none()
}

fn short_hash(hash: &[u8; 32]) -> String {
    hash[..6].iter().map(|b| format!("{b:02x}")).collect()
}

pub fn explain_block_proof_failure_with_difficulty(
    header: &BlockHeader,
    proof: &LatticeProof,
    expected_difficulty_bits: u32,
) -> Option<String> {
    let header_hash = header_challenge(header);
    let expected_bits = expected_difficulty_bits.max(1);
    if proof.difficulty_bits != expected_bits {
        return Some(format!(
            "difficulty mismatch expected={} got={}",
            expected_bits, proof.difficulty_bits
        ));
    }

    // Recompute the ULT7Rock lattice chain from the nonce stored in the proof.
    let steps = sequential_steps(header.height);
    let a_hat = block_a_hat(&header_hash);
    let (poly_bytes, digest) = lattice_sequential_chain(&a_hat, &header_hash, proof.nonce, steps);

    // The pow_hash field holds the BLAKE3 commitment digest that met the target.
    if digest != proof.pow_hash {
        return Some(format!(
            "pow_hash mismatch expected={} got={}",
            short_hash(&digest),
            short_hash(&proof.pow_hash)
        ));
    }
    let got_bits = leading_zero_bits(&digest);
    if got_bits < proof.difficulty_bits {
        return Some(format!(
            "insufficient leading zero bits expected>={} got={}",
            proof.difficulty_bits, got_bits
        ));
    }

    // The sequential_chain field holds BLAKE3(poly_bytes) — verify it matches.
    let expected_seq_digest: [u8; 32] = *blake3::hash(&poly_bytes).as_bytes();
    if expected_seq_digest != proof.sequential_chain {
        return Some(format!(
            "sequential chain mismatch expected={} got={}",
            short_hash(&expected_seq_digest),
            short_hash(&proof.sequential_chain)
        ));
    }

    // Verify the VeloxReaper memory-hard pass over the full polynomial bytes.
    let mem_hash = match memory_proof(&poly_bytes, &header.prev.0, header.height) {
        Ok(v) => v,
        Err(err) => {
            return Some(format!(
                "memory proof recompute failed: {}",
                sanitize_log_value(&err)
            ))
        }
    };
    if mem_hash != proof.memory_hash {
        return Some(format!(
            "memory hash mismatch expected={} got={}",
            short_hash(&mem_hash),
            short_hash(&proof.memory_hash)
        ));
    }

    let expected_clh = clh_contribution(&expected_seq_digest, &mem_hash, &digest);
    if expected_clh != proof.clh_contribution {
        return Some(format!(
            "clh contribution mismatch expected={} got={}",
            short_hash(&expected_clh),
            short_hash(&proof.clh_contribution)
        ));
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_parser_accepts_expected_values() {
        assert_eq!(MiningBackend::parse("auto"), MiningBackend::Auto);
        assert_eq!(MiningBackend::parse("cpu"), MiningBackend::Cpu);
        assert_eq!(MiningBackend::parse("opencl"), MiningBackend::OpenCl);
        assert_eq!(MiningBackend::parse("ocl"), MiningBackend::OpenCl);
        assert_eq!(MiningBackend::parse("cuda"), MiningBackend::Cuda);
    }

    #[test]
    fn mode_parser_accepts_expected_values() {
        assert_eq!(MiningMode::parse("cpu"), MiningMode::Cpu);
        assert_eq!(MiningMode::parse("gpu"), MiningMode::Gpu);
        assert_eq!(MiningMode::parse("hybrid"), MiningMode::Hybrid);
        assert_eq!(MiningMode::parse("unknown"), MiningMode::Hybrid);
    }

    #[test]
    fn detect_backends_always_includes_cpu() {
        let available = detect_available_backends();
        assert!(available.contains(&MiningBackend::Cpu));
    }

    #[test]
    fn gpu_mode_requires_real_gpu_backend() {
        std::env::set_var("KNOX_FORCE_OPENCL_AVAILABLE", "0");
        std::env::set_var("KNOX_FORCE_CUDA_AVAILABLE", "0");
        let header = BlockHeader {
            version: 1,
            height: 1,
            round: 0,
            prev: knox_types::Hash32::ZERO,
            tx_root: knox_types::Hash32::ZERO,
            slash_root: knox_types::Hash32::ZERO,
            state_root: knox_types::Hash32::ZERO,
            timestamp_ms: 0,
            proposer: [7u8; 32],
            qc: None,
        };
        let profile = MiningProfile {
            mode: MiningMode::Gpu,
            backend: MiningBackend::Auto,
            ..MiningProfile::default()
        };
        let out = mine_block_proof_with_profile(&header, 1, 1, &profile);
        assert!(out.is_err());
        std::env::remove_var("KNOX_FORCE_OPENCL_AVAILABLE");
        std::env::remove_var("KNOX_FORCE_CUDA_AVAILABLE");
    }
}
