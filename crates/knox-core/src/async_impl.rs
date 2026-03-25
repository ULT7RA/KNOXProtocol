use knox_consensus::{ConsensusConfig, ValidatorSet};
use getrandom::getrandom;
use knox_lattice::{
    consensus_public_key_id, consensus_secret_from_seed, sign_consensus,
    coinbase_split, decode_coinbase_payload, encode_coinbase_payload, encrypt_amount_with_level,
    mine_block_proof_with_profile, private_coinbase_outputs, tx_hardening_level,
    verify_consensus, LatticeCoinbasePayload, LatticeCommitment, LatticeCommitmentKey,
    LatticeOutput, LatticePublicKey, LatticeSecretKey, MiningProfile,
};
use knox_ledger::Ledger;
use knox_p2p::{Message, Network, NetworkConfig, NetworkSender};
use knox_types::{
    hash_bytes, merkle_root, Address, Block, BlockHeader, Hash32, LatticeProof, SlashEvidence, Transaction,
    WalletRequest, WalletResponse,
};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{interval, Duration};

const MAX_MEMPOOL_TX: usize = 50_000;
// Diamond-auth requests include full block payloads; keep headroom for
// larger blocks to avoid mid-write resets between peer nodes.
const MAX_RPC_BYTES: usize = 512 * 1024 * 1024;
const MAX_RPC_BLOCKS: u32 = 512;
const RATE_LIMIT_SUBMIT_PER_SEC: u32 = 10;
const RATE_LIMIT_BLOCKS_PER_SEC: u32 = 5;
const RATE_LIMIT_DECOYS_PER_SEC: u32 = 5;
const MAX_SLASHES_PER_BLOCK: usize = 128;
const MAX_DECOY_SCAN_BLOCKS: u64 = 5_000;
const MAX_DECOY_CANDIDATES: usize = 200_000;
const DECOY_CACHE_TTL_MS: u64 = 10_000;
const DIAMOND_AUTH_RPC_TIMEOUT_MS: u64 = 10_000;
const MAX_DIAMOND_AUTH_ENDPOINTS: usize = 32;
const DEFAULT_SYNC_BLOCKS_RESPONSE_MAX_BYTES: usize = 128 * 1024 * 1024;
const SYNC_GETBLOCKS_MAX_COUNT: u32 = 512;
const DEFAULT_SYNC_RETRY_MS: u64 = 1_000;
const DEFAULT_SYNC_STALL_MS: u64 = 4_000;
const SYNC_STALL_BACKOFF_CAP_MS: u64 = 30_000;
const DEFAULT_SYNC_BOOTSTRAP_DORMANT_MS: u64 = 15_000;
const SYNC_BOOTSTRAP_DORMANT_LOG_MS: u64 = 30_000;
const SYNC_REQUEST_DEDUP_MS: u64 = 1_500;
const MAX_RECENT_SYNC_REQUESTS: usize = 32;
const DEFAULT_UPSTREAM_SYNC_TIMEOUT_MS: u64 = 120_000;
const MAX_UPSTREAM_SYNC_BATCH_LOOPS: usize = 8;
const DEFAULT_UPSTREAM_SYNC_BATCH_COUNT: u32 = 64;
const CHAIN_CONTINUITY_CHECK_MS: u64 = 5_000;
const DEFAULT_CHAIN_CONTINUITY_UNAVAILABLE_GRACE_MS: u64 = 20_000;
const CHAIN_CONTINUITY_MISMATCH_RECOVERY_STREAK: u32 = 3;

/// Grace period (ms) that non-elected miners must wait before proposing.
/// Gives the ForgeTitan-elected leader time to submit first.
const FORGE_GRACE_MS: u64 = 90_000; // 2× TARGET_BLOCK_TIME_MS

/// Scan window for miner registry: only look at the last WINDOW blocks.
/// 3840 blocks ≈ 48hrs at 45s target.  Keeps the scan bounded regardless
/// of total chain length, and ensures stale/offline miners age out.
const FORGE_REGISTRY_WINDOW: u64 = knox_types::FORGE_TENURE_BLOCKS;

// ── ForgeTitan Election (stateless — computed purely from ledger) ────
//
// Every ForgeTitan (and every node) can compute the same election result
// for any height because the inputs are:
//   1. The block at (height - 1) → prev_hash  (chain state)
//   2. The set of proposer IDs in the last WINDOW blocks  (chain state)
//   3. Deterministic weight formula  (protocol constant)
//   4. Deterministic hash-based random selection  (protocol constant)
//
// Adding a new ForgeTitan VM requires zero coordination — it syncs the
// chain and immediately serves identical election results.  Miners query
// ANY ForgeTitan (or multiple for redundancy) and get the same answer.

/// Miner info tracked by the election registry.
#[derive(Clone, Debug)]
struct MinerInfo {
    proposer_id: [u8; 32],
    /// Earliest height this miner appeared in the scan window.
    first_seen_height: u64,
    /// Total blocks proposed within the scan window.
    blocks_in_window: u64,
}

#[derive(Clone, Copy, Debug)]
struct RecentSyncRequest {
    from_height: u64,
    sent_at_ms: u64,
}

#[derive(Clone, Copy, Debug)]
struct ChainCheckpoint {
    height: u64,
    hash: Hash32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LocalCheckpointStatus {
    Pending,
    Match,
    Mismatch(Hash32),
}

fn parse_chain_checkpoint_env() -> Result<Option<ChainCheckpoint>, String> {
    let combined = std::env::var("KNOX_CHAIN_CHECKPOINT")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());
    let height = std::env::var("KNOX_CHAIN_CHECKPOINT_HEIGHT")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());
    let hash = std::env::var("KNOX_CHAIN_CHECKPOINT_HASH")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());
    if let Some(spec) = combined {
        if height.is_some() || hash.is_some() {
            return Err(
                "set either KNOX_CHAIN_CHECKPOINT or KNOX_CHAIN_CHECKPOINT_HEIGHT/KNOX_CHAIN_CHECKPOINT_HASH, not both"
                    .to_string(),
            );
        }
        return parse_chain_checkpoint_spec(&spec).map(Some);
    }
    match (height, hash) {
        (None, None) => Ok(None),
        (Some(_), None) | (None, Some(_)) => {
            Err("both KNOX_CHAIN_CHECKPOINT_HEIGHT and KNOX_CHAIN_CHECKPOINT_HASH are required".to_string())
        }
        (Some(height), Some(hash)) => {
            let parsed_height = height
                .parse::<u64>()
                .map_err(|_| format!("invalid KNOX_CHAIN_CHECKPOINT_HEIGHT '{}'", height))?;
            let parsed_hash = parse_hash32_hex(&hash)
                .map_err(|err| format!("invalid KNOX_CHAIN_CHECKPOINT_HASH: {}", err))?;
            Ok(Some(ChainCheckpoint {
                height: parsed_height,
                hash: parsed_hash,
            }))
        }
    }
}

fn parse_chain_checkpoint_spec(spec: &str) -> Result<ChainCheckpoint, String> {
    let mut parts = spec.splitn(2, ':');
    let height_part = parts.next().unwrap_or("").trim();
    let hash_part = parts
        .next()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            "KNOX_CHAIN_CHECKPOINT must be '<height>:<64-hex-hash>'".to_string()
        })?;
    let parsed_height = height_part
        .parse::<u64>()
        .map_err(|_| format!("invalid checkpoint height '{}'", height_part))?;
    let parsed_hash =
        parse_hash32_hex(hash_part).map_err(|err| format!("invalid checkpoint hash: {}", err))?;
    Ok(ChainCheckpoint {
        height: parsed_height,
        hash: parsed_hash,
    })
}

fn parse_hash32_hex(input: &str) -> Result<Hash32, String> {
    let hex = input
        .trim()
        .strip_prefix("0x")
        .or_else(|| input.trim().strip_prefix("0X"))
        .unwrap_or(input.trim());
    if hex.len() != 64 {
        return Err(format!("expected 64 hex chars, got {}", hex.len()));
    }
    let bytes = hex.as_bytes();
    let mut out = [0u8; 32];
    for idx in 0..32 {
        let hi = decode_hex_nibble(bytes[idx * 2])?;
        let lo = decode_hex_nibble(bytes[idx * 2 + 1])?;
        out[idx] = (hi << 4) | lo;
    }
    Ok(Hash32(out))
}

fn decode_hex_nibble(ch: u8) -> Result<u8, String> {
    match ch {
        b'0'..=b'9' => Ok(ch - b'0'),
        b'a'..=b'f' => Ok(ch - b'a' + 10),
        b'A'..=b'F' => Ok(ch - b'A' + 10),
        _ => Err(format!("invalid hex char '{}'", ch as char)),
    }
}

fn checkpoint_mismatch_in_blocks(blocks: &[Block], checkpoint: ChainCheckpoint) -> Option<Hash32> {
    blocks
        .iter()
        .find(|block| block.header.height == checkpoint.height)
        .map(|block| hash_header_for_link(&block.header))
        .filter(|hash| *hash != checkpoint.hash)
}

fn local_checkpoint_status(
    ledger: &Ledger,
    checkpoint: ChainCheckpoint,
) -> Result<LocalCheckpointStatus, String> {
    let local_tip = ledger.height().unwrap_or(0);
    if local_tip < checkpoint.height {
        return Ok(LocalCheckpointStatus::Pending);
    }
    let Some(block) = ledger.get_block(checkpoint.height)? else {
        return Err(format!(
            "local chain missing block at checkpoint height {}",
            checkpoint.height
        ));
    };
    let local_hash = hash_header_for_link(&block.header);
    if local_hash == checkpoint.hash {
        Ok(LocalCheckpointStatus::Match)
    } else {
        Ok(LocalCheckpointStatus::Mismatch(local_hash))
    }
}

fn prune_recent_sync_requests(
    recent_sync_requests: &mut VecDeque<RecentSyncRequest>,
    now: u64,
) {
    while recent_sync_requests
        .front()
        .map(|req| now.saturating_sub(req.sent_at_ms) > SYNC_REQUEST_DEDUP_MS)
        .unwrap_or(false)
    {
        recent_sync_requests.pop_front();
    }
}

fn try_send_sync_getblocks(
    network: &Network,
    recent_sync_requests: &mut VecDeque<RecentSyncRequest>,
    from_height: u64,
    max_count: u32,
    now: u64,
    force: bool,
) -> bool {
    prune_recent_sync_requests(recent_sync_requests, now);
    if !force
        && recent_sync_requests
            .iter()
            .any(|req| req.from_height == from_height)
    {
        return false;
    }
    let sent = network.try_send(Message::GetBlocks {
        from_height,
        max_count,
    });
    if sent {
        if recent_sync_requests.len() >= MAX_RECENT_SYNC_REQUESTS {
            recent_sync_requests.pop_front();
        }
        recent_sync_requests.push_back(RecentSyncRequest {
            from_height,
            sent_at_ms: now,
        });
    }
    sent
}

/// Build the active miner registry by scanning the last WINDOW blocks.
/// This is O(WINDOW) — bounded at ~3840 blocks regardless of chain length.
/// Returns a deterministically-sorted list of active miners.
fn build_miner_registry(
    ledger: &knox_ledger::Ledger,
    tip_height: u64,
) -> Vec<MinerInfo> {
    use std::collections::HashMap;
    let window_start = tip_height.saturating_sub(FORGE_REGISTRY_WINDOW);
    let mut miners: HashMap<[u8; 32], MinerInfo> = HashMap::new();

    let mut h = tip_height;
    loop {
        if h < window_start { break; }
        if let Some(block) = ledger.get_block(h).ok().flatten() {
            let pid = block.header.proposer;
            let entry = miners.entry(pid).or_insert(MinerInfo {
                proposer_id: pid,
                first_seen_height: h,
                blocks_in_window: 0,
            });
            entry.blocks_in_window += 1;
            if h < entry.first_seen_height {
                entry.first_seen_height = h;
            }
        }
        if h == 0 { break; }
        h -= 1;
    }

    let mut result: Vec<MinerInfo> = miners.into_values().collect();
    // Sort by proposer_id for deterministic ordering across all ForgeTitans
    result.sort_by(|a, b| a.proposer_id.cmp(&b.proposer_id));
    result
}

/// Compute election weights for each miner.
///
/// Weight model:
///   - New miners (< 48hrs tenure): weight ramps linearly 10 → 1000
///   - Veterans (≥ 48hrs): weight = 1000 (fair equal chance)
///   - Top miner (most blocks in window): +2.5% bonus
///
/// All inputs are chain-derived → every node computes identical weights.
fn compute_election_weights(miners: &[MinerInfo], tip_height: u64) -> Vec<u64> {
    if miners.is_empty() { return vec![]; }

    let max_blocks = miners.iter().map(|m| m.blocks_in_window).max().unwrap_or(0);

    miners.iter().map(|m| {
        let tenure = tip_height.saturating_sub(m.first_seen_height);
        let base = if tenure >= knox_types::FORGE_TENURE_BLOCKS {
            1000u64
        } else {
            (tenure * 1000) / knox_types::FORGE_TENURE_BLOCKS.max(1)
        };
        // Floor of 10 so brand-new miners still have a small chance
        let base = base.max(10);
        // Top miner bonus: 2.5%
        if m.blocks_in_window == max_blocks && max_blocks > 0 {
            base + (base * knox_types::FORGE_TOP_MINER_BONUS_PPM / 1_000_000)
        } else {
            base
        }
    }).collect()
}

/// Weighted deterministic election for a given height.
///
/// Entropy = hash(prev_block_hash || height), same on every node.
/// Selection = weighted cumulative distribution over sorted miners.
fn forge_elect_leader(
    prev_hash: &Hash32,
    height: u64,
    miners: &[MinerInfo],
    weights: &[u64],
) -> Option<[u8; 32]> {
    if miners.is_empty() || weights.is_empty() { return None; }
    let total_weight: u64 = weights.iter().sum();
    if total_weight == 0 { return None; }

    let mut data = Vec::with_capacity(40);
    data.extend_from_slice(&prev_hash.0);
    data.extend_from_slice(&height.to_le_bytes());
    let h = hash_bytes(&data);
    let mut idx_bytes = [0u8; 8];
    idx_bytes.copy_from_slice(&h.0[..8]);
    let roll = u64::from_le_bytes(idx_bytes) % total_weight;

    let mut cumulative = 0u64;
    for (i, &w) in weights.iter().enumerate() {
        cumulative += w;
        if roll < cumulative {
            return Some(miners[i].proposer_id);
        }
    }
    Some(miners.last()?.proposer_id)
}

/// Full election query: build registry, compute weights, elect leader.
/// Pure function of ledger state — any ForgeTitan produces the same result.
fn forge_election_for_height(
    ledger: &knox_ledger::Ledger,
    height: u64,
) -> Option<knox_types::ForgeElectionResult> {
    let tip = ledger.height().ok()?;
    if height == 0 { return None; }
    let prev_height = height.saturating_sub(1);
    let prev_block = ledger.get_block(prev_height).ok().flatten()?;
    let prev_hash = hash_header_for_link(&prev_block.header);

    let miners = build_miner_registry(ledger, tip);
    if miners.is_empty() { return None; }
    let weights = compute_election_weights(&miners, tip);
    let leader = forge_elect_leader(&prev_hash, height, &miners, &weights)?;

    Some(knox_types::ForgeElectionResult {
        height,
        leader,
        active_miners: miners.len() as u32,
        is_leader: false, // caller sets this based on their own proposer_id
    })
}

fn sync_blocks_response_max_bytes() -> usize {
    std::env::var("KNOX_SYNC_BLOCKS_RESPONSE_MAX_BYTES")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .map(|v| v.clamp(256 * 1024, 128 * 1024 * 1024))
        .unwrap_or(DEFAULT_SYNC_BLOCKS_RESPONSE_MAX_BYTES)
}

#[derive(Clone)]
struct LocalPrng {
    seed: [u8; 32],
    counter: u64,
}

impl LocalPrng {
    fn new(seed: [u8; 32]) -> Self {
        Self { seed, counter: 0 }
    }

    fn fill_bytes(&mut self, out: &mut [u8]) {
        let mut written = 0usize;
        while written < out.len() {
            let mut h = blake3::Hasher::new();
            h.update(b"knox-core-prng-v1");
            h.update(&self.seed);
            h.update(&self.counter.to_le_bytes());
            let block = h.finalize();
            self.counter = self.counter.saturating_add(1);
            let bytes = block.as_bytes();
            let take = (out.len() - written).min(bytes.len());
            out[written..written + take].copy_from_slice(&bytes[..take]);
            written += take;
        }
    }
}

fn fill_os_random(buf: &mut [u8]) -> Result<(), String> {
    getrandom(buf).map_err(|e| format!("os randomness unavailable: {e}"))
}

#[derive(Clone, Default)]
struct RateLimiter {
    inner: Arc<Mutex<HashMap<IpAddr, RateState>>>,
}

#[derive(Clone, Copy)]
struct RateState {
    window_start_ms: u64,
    count: u32,
}

#[derive(Clone, Default)]
struct DecoyCache {
    inner: Arc<Mutex<DecoyCacheState>>,
}

#[derive(Default)]
struct DecoyCacheState {
    built_ms: u64,
    tip: u64,
    candidates: Vec<(knox_types::RingMember, u32)>,
}
pub struct NodeConfig {
    pub data_dir: String,
    pub network: NetworkConfig,
    pub consensus: ConsensusConfig,
    pub validators: ValidatorSet,
    pub consensus_keypair: Option<(LatticeSecretKey, LatticePublicKey)>,
    pub rpc_bind: String,
    pub miner_address: Address,
    pub treasury_address: Address,
    pub dev_address: Address,
    pub premine_address: Address,
    pub mining_enabled: bool,
    pub mining_profile: MiningProfile,
    pub diamond_authenticators: Vec<LatticePublicKey>,
    pub diamond_auth_quorum: usize,
    pub diamond_auth_endpoints: Vec<String>,
}

#[derive(Clone)]
struct MempoolEntry {
    tx: Transaction,
    received_ms: u64,
}

struct PendingMiningProposal {
    header: BlockHeader,
    txs: Vec<Transaction>,
    slashes: Vec<SlashEvidence>,
    proposer_sig: Vec<u8>,
    result_rx:
        tokio::sync::oneshot::Receiver<Result<(LatticeProof, String), String>>,
}

fn proposal_target_matches_current_chain(
    ledger: &Ledger,
    proposal_height: u64,
    proposal_prev: Hash32,
) -> bool {
    let has_genesis = ledger.get_block(0).ok().flatten().is_some();
    let expected_height = if has_genesis {
        ledger.height().unwrap_or(0).saturating_add(1)
    } else {
        0
    };
    if proposal_height != expected_height {
        return false;
    }
    if proposal_height == 0 {
        return true;
    }
    let Some(parent) = ledger
        .get_block(proposal_height.saturating_sub(1))
        .ok()
        .flatten()
    else {
        return false;
    };
    hash_header_for_link(&parent.header) == proposal_prev
}

fn cancel_pending_mining_if_stale(
    ledger: &Arc<Mutex<Ledger>>,
    pending_mining: &mut Option<PendingMiningProposal>,
    reason: &str,
) {
    let Some((height, prev)) = pending_mining
        .as_ref()
        .map(|pending| (pending.header.height, pending.header.prev))
    else {
        return;
    };
    let still_current = match ledger.lock() {
        Ok(l) => proposal_target_matches_current_chain(&l, height, prev),
        Err(_) => false,
    };
    if !still_current {
        eprintln!("[StarForge] cancel pending mining h={} — {}", height, reason);
        *pending_mining = None;
    }
}

pub struct Node {
    ledger: Arc<Mutex<Ledger>>,
    network: Network,
    mempool: Arc<Mutex<Vec<MempoolEntry>>>,
    slash_pool: Arc<Mutex<Vec<SlashEvidence>>>,
    secret: LatticeSecretKey,
    public: LatticePublicKey,
    rpc_bind: String,
    miner_address: Address,
    treasury_address: Address,
    dev_address: Address,
    premine_address: Address,
    mining_enabled: bool,
    mining_profile: MiningProfile,
    mine_tick_ms: u64,
    diamond_authenticators: Vec<LatticePublicKey>,
    diamond_auth_quorum: usize,
    diamond_auth_endpoints: Vec<String>,
}

impl Node {
    pub async fn new(cfg: NodeConfig) -> Result<Self, String> {
        let mut ledger =
            Ledger::open(&format!("{}/ledger", cfg.data_dir)).map_err(|e| e.to_string())?;
        let round_tick_ms = (cfg.consensus.max_round_ms / 4).max(250);
        let (secret, public) = match cfg.consensus_keypair {
            Some(pair) => pair,
            None => {
                let mut seed = [0u8; 32];
                fill_os_random(&mut seed)?;
                let secret = consensus_secret_from_seed(&seed);
                let public = knox_lattice::consensus_public_from_secret(&secret);
                (secret, public)
            }
        };
        // Open mining: no validator whitelist. Optional Diamond Authenticator
        // certs can be enforced at the ledger layer.
        ledger.set_validators(Vec::new());
        ledger.set_diamond_authenticators(
            cfg.diamond_authenticators.clone(),
            cfg.diamond_auth_quorum,
        );
        let mut net_config = cfg.network.clone();
        net_config.lattice_public = Some(public.p.to_bytes());
        net_config.lattice_secret = Some(secret.s.to_bytes());
        let network = Network::bind(net_config)
            .await
            .map_err(|e| e.to_string())?;

        Ok(Self {
            ledger: Arc::new(Mutex::new(ledger)),
            network,
            mempool: Arc::new(Mutex::new(Vec::new())),
            slash_pool: Arc::new(Mutex::new(Vec::new())),
            secret,
            public,
            rpc_bind: cfg.rpc_bind,
            miner_address: cfg.miner_address,
            treasury_address: cfg.treasury_address,
            dev_address: cfg.dev_address,
            premine_address: cfg.premine_address,
            mining_enabled: cfg.mining_enabled,
            mining_profile: cfg.mining_profile,
            mine_tick_ms: round_tick_ms,
            diamond_authenticators: cfg.diamond_authenticators,
            diamond_auth_quorum: cfg.diamond_auth_quorum,
            diamond_auth_endpoints: cfg.diamond_auth_endpoints,
        })
    }

    pub async fn run(self) {
        let rknox_ledger = self.ledger.clone();
        let rpc_mempool = self.mempool.clone();
        let rpc_network = self.network.sender();
        let rpc_bind = self.rpc_bind.clone();
        let rpc_secret = self.secret.clone();
        if rpc_bind != "-" {
            tokio::spawn(async move {
                loop {
                    let res = run_rpc(
                        rpc_bind.clone(),
                        rknox_ledger.clone(),
                        rpc_mempool.clone(),
                        rpc_network.clone(),
                        rpc_secret.clone(),
                    )
                    .await;
                    match res {
                        Ok(()) => {
                            eprintln!("[StarForge] rpc server exited; restarting");
                        }
                        Err(err) => {
                            eprintln!("[StarForge] rpc server error: {}", err);
                        }
                    }
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            });
        }

        let mut ticker = interval(Duration::from_millis(self.mine_tick_ms));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut network = self.network;
        let ledger = self.ledger.clone();
        let mempool = self.mempool.clone();
        let slash_pool = self.slash_pool.clone();
        let secret = self.secret;
        let public = self.public;
        let proposer_id = consensus_public_key_id(&public);
        let miner_address = self.miner_address;
        let treasury_address = self.treasury_address;
        let dev_address = self.dev_address;
        let premine_address = self.premine_address;
        let mining_enabled = self.mining_enabled;
        let mining_profile = self.mining_profile.clone();
        let diamond_authenticators = self.diamond_authenticators.clone();
        let diamond_auth_quorum = self.diamond_auth_quorum.max(1);
        let diamond_auth_endpoints = self.diamond_auth_endpoints.clone();
        let mut last_propose_ms = 0u64;
        let mainnet_locked =
            std::env::var("KNOX_MAINNET_LOCK").ok().as_deref() == Some("1");
        let min_peers_for_mining = std::env::var("KNOX_MIN_PEERS_FOR_MINING")
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .unwrap_or(0);
        let mut min_local_height_for_mining = std::env::var("KNOX_MIN_LOCAL_HEIGHT_FOR_MINING")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .unwrap_or(0);
        let fork_guard_pause_ms = std::env::var("KNOX_FORK_GUARD_PAUSE_MS")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .unwrap_or(knox_types::TARGET_BLOCK_TIME_MS.saturating_mul(2))
            .max(5_000);
        let mut last_peer_gate_log_ms = 0u64;
        let mut fork_guard_pause_until_ms = 0u64;
        let mut last_fork_guard_log_ms = 0u64;
        let mut chain_continuity_ok = true;
        let mut chain_continuity_checked_once = false;
        let mut chain_continuity_reason = String::new();
        let mut last_chain_continuity_check_ms = 0u64;
        let mut last_chain_continuity_log_ms = 0u64;
        let mut last_chain_continuity_ok_ms = 0u64;
        let mut chain_continuity_mismatch_streak = 0u32;
        let mut last_chain_continuity_mismatch_signature = String::new();
        let mut last_backend_line = String::new();
        // ForgeTitan election: miners query upstream RPC for the elected
        // leader before proposing.  The election is computed from chain state
        // so all ForgeTitans (and local nodes) produce the same result.
        // When KNOX_FORGE_ELECTION=1 (or unset with upstream RPC available),
        // the node queries its upstream RPC for the election result.
        let forge_election_enabled = std::env::var("KNOX_FORGE_ELECTION")
            .map(|v| v.trim() != "0")
            .unwrap_or(true); // enabled by default
        if forge_election_enabled {
            eprintln!(
                "[StarForge] ForgeTitan election enabled — grace_ms={}",
                FORGE_GRACE_MS
            );
        }
        let sync_retry_ms = std::env::var("KNOX_SYNC_RETRY_MS")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .unwrap_or(DEFAULT_SYNC_RETRY_MS)
            .max(1_000);
        let sync_stall_ms = std::env::var("KNOX_SYNC_STALL_MS")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .unwrap_or(DEFAULT_SYNC_STALL_MS)
            .max(sync_retry_ms);
        let sync_bootstrap_dormant_ms = std::env::var("KNOX_SYNC_BOOTSTRAP_DORMANT_MS")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .unwrap_or(DEFAULT_SYNC_BOOTSTRAP_DORMANT_MS)
            .clamp(5_000, 3_600_000);
        let upstream_sync_timeout = Duration::from_millis(
            std::env::var("KNOX_NODE_UPSTREAM_SYNC_TIMEOUT_MS")
                .ok()
                .and_then(|v| v.trim().parse::<u64>().ok())
                .unwrap_or(DEFAULT_UPSTREAM_SYNC_TIMEOUT_MS)
                .clamp(1_000, 300_000),
        );
        let upstream_sync_batch_count = std::env::var("KNOX_NODE_UPSTREAM_SYNC_BATCH_COUNT")
            .ok()
            .and_then(|v| v.trim().parse::<u32>().ok())
            .unwrap_or(DEFAULT_UPSTREAM_SYNC_BATCH_COUNT)
            .clamp(1, MAX_RPC_BLOCKS);
        let mut current_upstream_sync_batch_count = upstream_sync_batch_count;
        let chain_continuity_fail_closed = std::env::var("KNOX_CHAIN_CONTINUITY_FAIL_CLOSED")
            .ok()
            .map(|v| {
                let value = v.trim().to_ascii_lowercase();
                !matches!(value.as_str(), "0" | "false" | "no")
            })
            .unwrap_or(mainnet_locked);
        let chain_continuity_unavailable_grace_ms = std::env::var(
            "KNOX_CHAIN_CONTINUITY_UNAVAILABLE_GRACE_MS",
        )
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(DEFAULT_CHAIN_CONTINUITY_UNAVAILABLE_GRACE_MS)
        .clamp(5_000, 300_000);
        let upstream_sync_rpc = std::env::var("KNOX_NODE_UPSTREAM_RPC")
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty());
        let mut chain_checkpoint_config_error: Option<String> = None;
        let chain_checkpoint = match parse_chain_checkpoint_env() {
            Ok(checkpoint) => checkpoint,
            Err(err) => {
                chain_checkpoint_config_error = Some(err.clone());
                chain_continuity_ok = false;
                chain_continuity_reason =
                    format!("invalid checkpoint configuration: {}", err);
                None
            }
        };
        if let Some(checkpoint) = chain_checkpoint {
            eprintln!(
                "[StarForge] canonical checkpoint enabled h={} hash={}",
                checkpoint.height,
                hex_hash(checkpoint.hash)
            );
        }
        if let Some(err) = chain_checkpoint_config_error.as_deref() {
            eprintln!(
                "[StarForge] checkpoint configuration error: {}",
                err
            );
        }
        if upstream_sync_rpc.is_none() {
            if chain_continuity_fail_closed {
                chain_continuity_ok = false;
                chain_continuity_reason =
                    "canonical upstream RPC not configured".to_string();
                eprintln!(
                    "[StarForge] canonical chain enforcement active — KNOX_NODE_UPSTREAM_RPC is required in mainnet lock mode"
                );
            } else {
                chain_continuity_ok = true;
                chain_continuity_checked_once = true;
                last_chain_continuity_ok_ms = now_ms();
            }
        } else if chain_continuity_fail_closed {
            chain_continuity_ok = false;
            chain_continuity_reason = "awaiting trusted chain continuity check".to_string();
            eprintln!(
                "[StarForge] canonical continuity fail-closed enabled — mining waits for verified continuity"
            );
        } else {
            last_chain_continuity_ok_ms = now_ms();
        }
        eprintln!(
            "[StarForge] upstream sync config batch={} timeout_ms={} rpc={}",
            upstream_sync_batch_count,
            upstream_sync_timeout.as_millis(),
            upstream_sync_rpc.as_deref().unwrap_or("<disabled>")
        );
        let sync_auto_reset_on_conflict = !matches!(
            std::env::var("KNOX_SYNC_AUTO_RESET_ON_CONFLICT")
                .ok()
                .map(|v| v.trim().to_ascii_lowercase())
                .as_deref(),
            Some("0" | "false" | "no")
        );
        let no_mine_node = matches!(
            std::env::var("KNOX_NODE_NO_MINE")
                .ok()
                .map(|v| v.trim().to_ascii_lowercase())
                .as_deref(),
            Some("1" | "true" | "yes")
        );
        let mut last_sync_request_ms = 0u64;
        let mut consecutive_stall_syncs: u32 = 0;
        let mut last_sync_progress_ms = now_ms();
        let mut last_sync_progress_height = ledger
            .lock()
            .ok()
            .and_then(|l| l.height().ok())
            .unwrap_or(0);
        let mut bootstrap_genesis_stall_count: u32 = 0;
        let mut last_blocks_response_ms = now_ms();
        let mut genesis_mismatch_hits: u32 = 0;
        let mut sync_conflict_hits: u32 = 0;
        let mut sync_conflict_height: u64 = 0;
        let mut fork_oo_stall_count: u32 = 0;
        let mut fork_oo_peer_max_h: u64 = 0;
        const FORK_OO_RECOVERY_THRESHOLD: u32 = 5;
        let mut pending_mining: Option<PendingMiningProposal> = None;
        let mut last_getblocks_served_up_to: u64 = 0;
        let mut last_getblocks_served_ms: u64 = 0;
        let mut last_getblocks_empty_height: u64 = 0;
        let mut last_getblocks_empty_ms: u64 = 0;
        let mut recent_sync_requests = VecDeque::with_capacity(8);
        let mut bootstrap_sync_dormant = false;
        let mut bootstrap_sync_dormant_since_ms = 0u64;
        let mut last_bootstrap_dormant_log_ms = 0u64;
        let mut last_active_peers = network.active_peer_count();

        // If ledger is empty (no genesis yet), proactively request from h=0
        // after peers have had time to connect.
        {
            let has_genesis = ledger.lock().ok()
                .and_then(|l| l.get_block(0).ok().flatten())
                .is_some();
            if !has_genesis {
                let sync_sender = network.sender();
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    eprintln!("[StarForge] ledger empty at boot — requesting sync from h=0");
                    sync_sender
                        .try_send(knox_p2p::Message::GetBlocks {
                            from_height: 0,
                            max_count: SYNC_GETBLOCKS_MAX_COUNT,
                        });
                });
            }
        }

        loop {
            if let Some(pending) = pending_mining.as_mut() {
                match pending.result_rx.try_recv() {
                    Ok(result) => {
                        let pending_ready = pending_mining
                            .take()
                            .expect("pending mining must exist when result arrives");
                        let PendingMiningProposal {
                            header,
                            txs,
                            slashes,
                            proposer_sig,
                            result_rx: _,
                        } = pending_ready;
                        let (lattice_proof, backend_line) = match result {
                            Ok(v) => v,
                            Err(err) => {
                                eprintln!("[StarForge] mining_runtime_error {}", err);
                                tokio::time::sleep(Duration::from_millis(1200)).await;
                                continue;
                            }
                        };
                        let proposal_still_current = match ledger.lock() {
                            Ok(l) => {
                                proposal_target_matches_current_chain(&l, header.height, header.prev)
                            }
                            Err(_) => false,
                        };
                        if !proposal_still_current {
                            eprintln!(
                                "[StarForge] discard stale mined proposal h={} — chain changed while proof was running",
                                header.height
                            );
                            continue;
                        }
                        if backend_line != last_backend_line {
                            eprintln!("[StarForge] mining_runtime {}", backend_line);
                            last_backend_line = backend_line;
                        }
                        let mut block = Block {
                            header,
                            txs,
                            slashes,
                            proposer_sig,
                            lattice_proof,
                        };
                        if !diamond_authenticators.is_empty() {
                            match build_diamond_auth_bundle(
                                &block,
                                &diamond_authenticators,
                                diamond_auth_quorum,
                                &diamond_auth_endpoints,
                            )
                            .await
                            {
                                Ok(bundle) => {
                                    block.proposer_sig = bundle;
                                }
                                Err(err) => {
                                    eprintln!(
                                        "[StarForge] diamond auth quorum unmet h={}: {}",
                                        block.header.height, err
                                    );
                                    continue;
                                }
                            }
                        }
                        let proposal_still_current = match ledger.lock() {
                            Ok(l) => {
                                proposal_target_matches_current_chain(&l, block.header.height, block.header.prev)
                            }
                            Err(_) => false,
                        };
                        if !proposal_still_current {
                            eprintln!(
                                "[StarForge] discard stale mined proposal h={} — chain changed before finalize",
                                block.header.height
                            );
                            continue;
                        }
                        if let Some(checkpoint) = chain_checkpoint {
                            if block.header.height == checkpoint.height {
                                let local_hash = hash_header_for_link(&block.header);
                                if local_hash != checkpoint.hash {
                                    eprintln!(
                                        "[StarForge] reject local proposal h={} checkpoint mismatch expected={} got={}",
                                        checkpoint.height,
                                        hex_hash(checkpoint.hash),
                                        hex_hash(local_hash)
                                    );
                                    continue;
                                }
                            }
                        }
                        if append_finalized_block(&block, &ledger, &mempool) {
                            if block.header.height > last_sync_progress_height {
                                last_sync_progress_height = block.header.height;
                                last_sync_progress_ms = now_ms();
                                consecutive_stall_syncs = 0;
                            }
                            network.try_send(Message::Block(block));
                        }
                        continue;
                    }
                    Err(tokio::sync::oneshot::error::TryRecvError::Empty) => {}
                    Err(tokio::sync::oneshot::error::TryRecvError::Closed) => {
                        pending_mining = None;
                        eprintln!("[StarForge] mining worker closed before delivering proof");
                    }
                }
            }
            tokio::select! {
                biased;
                Some(first_env) = network.inbound.recv() => {
                    // Batch-drain: collect this message + all queued messages
                    // to avoid per-message select! overhead starving inbound.
                    let mut pending_msgs = vec![first_env];
                    while pending_msgs.len() < 128 {
                        match network.inbound.try_recv() {
                            Ok(env) => pending_msgs.push(env),
                            Err(_) => break,
                        }
                    }
                    if pending_msgs.len() > 1 {
                        eprintln!("[StarForge] inbound batch-drain: {} messages", pending_msgs.len());
                    }
                    for env in pending_msgs {
                    match env.msg {
                        Message::Tx(tx) => {
                            let tx_ok = match ledger.lock() {
                                Ok(l) => l.verify_tx(&tx).is_ok(),
                                Err(_) => false,
                            };
                            if tx_ok {
                                let mut accepted = false;
                                if let Ok(mut mp) = mempool.lock() {
                                    if mempool_has_conflict(&mp, &tx) {
                                        continue;
                                    }
                                    if mp.len() >= MAX_MEMPOOL_TX {
                                        evict_one(&mut mp);
                                    }
                                    if mp.len() < MAX_MEMPOOL_TX {
                                        mp.push(MempoolEntry {
                                            tx: tx.clone(),
                                            received_ms: now_ms(),
                                        });
                                        accepted = true;
                                    }
                                }
                                if accepted {
                                    network.try_send(Message::Tx(tx));
                                }
                            }
                        }
                        Message::Block(block) => {
                            if bootstrap_sync_dormant {
                                bootstrap_sync_dormant = false;
                                bootstrap_sync_dormant_since_ms = 0;
                                last_bootstrap_dormant_log_ms = 0;
                                bootstrap_genesis_stall_count = 0;
                                last_sync_request_ms = 0;
                                eprintln!(
                                    "[StarForge] waking sync from dormancy: received peer block h={}",
                                    block.header.height
                                );
                            }
                            if let Some(checkpoint) = chain_checkpoint {
                                if block.header.height == checkpoint.height {
                                    let peer_hash = hash_header_for_link(&block.header);
                                    if peer_hash != checkpoint.hash {
                                        if sync_conflict_height == checkpoint.height {
                                            sync_conflict_hits =
                                                sync_conflict_hits.saturating_add(1);
                                        } else {
                                            sync_conflict_height = checkpoint.height;
                                            sync_conflict_hits = 1;
                                        }
                                        eprintln!(
                                            "[StarForge] reject peer block h={} checkpoint mismatch expected={} got={} hit={}",
                                            checkpoint.height,
                                            hex_hash(checkpoint.hash),
                                            hex_hash(peer_hash),
                                            sync_conflict_hits
                                        );
                                        continue;
                                    }
                                }
                            }
                            let verify = match ledger.lock() {
                                Ok(l) => l.verify_block(&block),
                                Err(_) => Err("ledger lock poisoned".to_string()),
                            };
                            match verify {
                                Ok(()) => {
                                    let appended = append_finalized_block(&block, &ledger, &mempool);
                                    if appended {
                                        if block.header.height > last_sync_progress_height {
                                            last_sync_progress_height = block.header.height;
                                            last_sync_progress_ms = now_ms();
                                        }
                                        cancel_pending_mining_if_stale(
                                            &ledger,
                                            &mut pending_mining,
                                            "peer block advanced local chain",
                                        );
                                        network.try_send(Message::Block(block));
                                    } else if block.header.height > 0 {
                                        // append failed with "already exists" — check if we need
                                        // to replace a conflicting tip block (fork choice).
                                        let replaced = match ledger.lock() {
                                            Ok(l) => {
                                                let tip = l.height().unwrap_or(0);
                                                if block.header.height == tip {
                                                    l.replace_tip_block(&block)
                                                } else {
                                                    Err("not at tip".to_string())
                                                }
                                            }
                                            Err(_) => Err("lock poisoned".to_string()),
                                        };
                                        match replaced {
                                            Ok(()) => {
                                                eprintln!(
                                                    "[StarForge] tip replaced h={} with peer block (fork choice)",
                                                    block.header.height
                                                );
                                                // Cancel any pending mining for the old tip
                                                pending_mining = None;
                                                sync_conflict_hits = 0;
                                                sync_conflict_height = 0;
                                                network.try_send(Message::Block(block));
                                            }
                                            Err(_) => {} // Not at tip or verification failed — ignore
                                        }
                                    }
                                }
                                Err(err) => {
                                    eprintln!(
                                        "[StarForge] reject proposal h={} r={}: {}",
                                        block.header.height, block.header.round, err
                                    );
                                    if err.contains("missing parent") || err.contains("prev hash mismatch") {
                                        let (our_tip, has_genesis) = match ledger.lock() {
                                            Ok(l) => (
                                                l.height().unwrap_or(0),
                                                l.get_block(0).unwrap_or(None).is_some(),
                                            ),
                                            Err(_) => (0, false),
                                        };
                                        let from = if has_genesis {
                                            our_tip.saturating_add(1)
                                        } else {
                                            0
                                        };
                                        // Only arm fork-guard for near-tip conflicts. Far-ahead proposals from
                                        // peers should not pause local mining or force replay-from-tip-2 loops.
                                        let height_gap = block.header.height.saturating_sub(our_tip);
                                        if height_gap <= 8 {
                                            let guard_until = now_ms().saturating_add(fork_guard_pause_ms);
                                            if guard_until > fork_guard_pause_until_ms {
                                                fork_guard_pause_until_ms = guard_until;
                                            }
                                            if pending_mining.is_some() {
                                                eprintln!(
                                                    "[StarForge] fork guard canceling pending mining at local tip {}",
                                                    our_tip
                                                );
                                                pending_mining = None;
                                            }
                                        }
                                        let sent_at = now_ms();
                                        if try_send_sync_getblocks(
                                            &network,
                                            &mut recent_sync_requests,
                                            from,
                                            SYNC_GETBLOCKS_MAX_COUNT,
                                            sent_at,
                                            false,
                                        ) {
                                            if height_gap <= 8 {
                                                eprintln!(
                                                    "[StarForge] fork guard active ({} ms) — requesting sync from h={}",
                                                    fork_guard_pause_ms, from
                                                );
                                            } else {
                                                eprintln!(
                                                    "[StarForge] ignoring far-ahead proposal h={} (local_tip={}, gap={}) — requesting forward sync from h={}",
                                                    block.header.height, our_tip, height_gap, from
                                                );
                                            }
                                            last_sync_request_ms = sent_at;
                                        }
                                    }
                                }
                            }
                        }
                        Message::GetBlocks { from_height, max_count } => {
                            // Dedup: skip stale requests if we recently served
                            // blocks covering this range (prevents queue buildup
                            // from flooding peers).
                            {
                                let now_dedup = now_ms();
                                if from_height < last_getblocks_served_up_to
                                    && now_dedup.saturating_sub(last_getblocks_served_ms) < 3_000
                                {
                                    continue;
                                }
                                // Also skip if we recently had nothing to serve for
                                // this height — prevents empty-response flood.
                                if from_height >= last_getblocks_empty_height
                                    && last_getblocks_empty_height > 0
                                    && now_dedup.saturating_sub(last_getblocks_empty_ms) < 5_000
                                {
                                    continue;
                                }
                            }
                            let per_batch_cap =
                                (max_count as u64).clamp(1, SYNC_GETBLOCKS_MAX_COUNT as u64);
                            let max_bytes = sync_blocks_response_max_bytes();
                            let blocks = if let Ok(l) = ledger.lock() {
                                let mut out = Vec::new();
                                let mut used_bytes = 0usize;
                                for h in from_height..from_height.saturating_add(per_batch_cap) {
                                    match l.get_block_with_size(h) {
                                        Ok(Some((b, block_bytes))) => {
                                            let next_bytes = used_bytes.saturating_add(block_bytes);
                                            if !out.is_empty() && next_bytes > max_bytes {
                                                break;
                                            }
                                            out.push(b);
                                            used_bytes = next_bytes;
                                            if used_bytes >= max_bytes {
                                                break;
                                            }
                                        }
                                        _ => break,
                                    }
                                }
                                out
                            } else {
                                Vec::new()
                            };
                            if !blocks.is_empty() {
                                let served_end = from_height.saturating_add(blocks.len() as u64);
                                last_getblocks_served_up_to = served_end;
                                last_getblocks_served_ms = now_ms();
                                eprintln!(
                                    "[StarForge] serving {} blocks from h={}",
                                    blocks.len(),
                                    from_height
                                );
                                let sent = network.try_send(Message::Blocks(blocks));
                                if !sent {
                                    eprintln!("[StarForge] WARN: Blocks try_send failed (outbound full) for h={}", from_height);
                                }
                            } else {
                                // Nothing to serve — record so we can skip duplicate
                                // requests for this height for a few seconds.
                                last_getblocks_empty_height = from_height;
                                last_getblocks_empty_ms = now_ms();
                            }
                        }
                        Message::Blocks(blocks) => {
                            if !blocks.is_empty() {
                                if bootstrap_sync_dormant {
                                    let first_h =
                                        blocks.first().map(|b| b.header.height).unwrap_or(0);
                                    bootstrap_sync_dormant = false;
                                    bootstrap_sync_dormant_since_ms = 0;
                                    last_bootstrap_dormant_log_ms = 0;
                                    bootstrap_genesis_stall_count = 0;
                                    last_sync_request_ms = 0;
                                    eprintln!(
                                        "[StarForge] waking sync from dormancy: received block batch from h={}",
                                        first_h
                                    );
                                }
                                last_blocks_response_ms = now_ms();
                                let first_h = blocks.first().map(|b| b.header.height).unwrap_or(0);
                                let last_h = blocks.last().map(|b| b.header.height).unwrap_or(0);
                                eprintln!(
                                    "[StarForge] sync batch received count={} range={}..{}",
                                    blocks.len(),
                                    first_h,
                                    last_h
                                );
                                // Raise the mining gate if peers are ahead of our initial tip.
                                if min_local_height_for_mining > 0 && last_h > min_local_height_for_mining {
                                    eprintln!(
                                        "[StarForge] raising mining gate {} -> {} (peer blocks ahead)",
                                        min_local_height_for_mining, last_h
                                    );
                                    min_local_height_for_mining = last_h;
                                }
                            }
                            if let Some(checkpoint) = chain_checkpoint {
                                if let Some(peer_hash) =
                                    checkpoint_mismatch_in_blocks(&blocks, checkpoint)
                                {
                                    let first_h =
                                        blocks.first().map(|b| b.header.height).unwrap_or(0);
                                    let last_h =
                                        blocks.last().map(|b| b.header.height).unwrap_or(0);
                                    if sync_conflict_height == checkpoint.height {
                                        sync_conflict_hits =
                                            sync_conflict_hits.saturating_add(1);
                                    } else {
                                        sync_conflict_height = checkpoint.height;
                                        sync_conflict_hits = 1;
                                    }
                                    eprintln!(
                                        "[StarForge] reject sync batch range={}..{} checkpoint mismatch h={} expected={} got={} hit={}",
                                        first_h,
                                        last_h,
                                        checkpoint.height,
                                        hex_hash(checkpoint.hash),
                                        hex_hash(peer_hash),
                                        sync_conflict_hits
                                    );
                                    continue;
                                }
                            }
                            let batch_result = match ledger.lock() {
                                Ok(l) => l.append_sync_batch(&blocks),
                                Err(_) => {
                                    eprintln!("[StarForge] sync stop: ledger lock poisoned");
                                    continue;
                                }
                            };
                            let applied_count = batch_result.applied_count;
                            let progressed_count = batch_result.progressed_count;
                            let skipped_out_of_order = batch_result.skipped_out_of_order;
                            let already_exists_count = batch_result.already_exists_count;
                            if let Some(last_height) = batch_result.last_progress_height {
                                eprintln!(
                                    "[StarForge] sync progressed {} block(s) (new={} existing={}) through h={}",
                                    progressed_count,
                                    applied_count,
                                    already_exists_count,
                                    last_height
                                );
                                if last_height > last_sync_progress_height {
                                    last_sync_progress_height = last_height;
                                    last_sync_progress_ms = now_ms();
                                }
                                genesis_mismatch_hits = 0;
                                cancel_pending_mining_if_stale(
                                    &ledger,
                                    &mut pending_mining,
                                    "sync batch advanced local chain",
                                );
                            }
                            if let (Some(stop_height), Some(e)) =
                                (batch_result.stop_height, batch_result.stop_error.as_deref())
                            {
                                let lower_err = e.to_ascii_lowercase();
                                let conflict_like = e.contains("conflicting block at height")
                                    || lower_err.contains("prev hash mismatch")
                                    || lower_err.contains("missing parent")
                                    || lower_err.contains("timestamp is earlier than parent");
                                if conflict_like {
                                    if sync_conflict_height == stop_height {
                                        sync_conflict_hits =
                                            sync_conflict_hits.saturating_add(1);
                                    } else {
                                        sync_conflict_height = stop_height;
                                        sync_conflict_hits = 1;
                                    }
                                    eprintln!(
                                        "[StarForge] sync conflict h={} hit={}",
                                        stop_height, sync_conflict_hits
                                    );
                                }
                                eprintln!("[StarForge] sync stop h={}: {}", stop_height, e);
                                let low_height = stop_height <= 1;
                                let likely_mismatch = e.contains("prev hash mismatch")
                                    || e.contains("missing parent")
                                    || e.to_lowercase().contains("genesis");
                                if low_height && likely_mismatch {
                                    genesis_mismatch_hits =
                                        genesis_mismatch_hits.saturating_add(1);
                                    if genesis_mismatch_hits >= 3 {
                                        eprintln!(
                                            "[StarForge] sync blocked at low height; likely genesis mismatch between local embedded genesis and peer network"
                                        );
                                    }
                                }
                            }
                            if !blocks.is_empty() && progressed_count == 0 {
                                let first_h = blocks.first().map(|b| b.header.height).unwrap_or(0);
                                let last_h = blocks.last().map(|b| b.header.height).unwrap_or(0);
                                eprintln!(
                                    "[StarForge] sync batch made no progress range={}..{} already_exists={} skipped_out_of_order={}",
                                    first_h,
                                    last_h,
                                    already_exists_count,
                                    skipped_out_of_order
                                );
                                let local_tip = match ledger.lock() {
                                    Ok(l) => l.height().unwrap_or(0),
                                    Err(_) => 0,
                                };
                                if last_h <= local_tip {
                                    // If the entire batch is already behind local tip, immediately
                                    // ask forward again instead of waiting for the stall ticker.
                                    let from = local_tip.saturating_add(1);
                                    let sent_at = now_ms();
                                    if try_send_sync_getblocks(
                                        &network,
                                        &mut recent_sync_requests,
                                        from,
                                        SYNC_GETBLOCKS_MAX_COUNT,
                                        sent_at,
                                        false,
                                    ) {
                                        eprintln!(
                                            "[StarForge] sync stale batch behind tip (local_tip={}) — requesting sync from h={}",
                                            local_tip, from
                                        );
                                        last_sync_request_ms = sent_at;
                                    }
                                }
                                let allow_mining_node_reset = min_local_height_for_mining > 0
                                    && local_tip.saturating_add(1) < min_local_height_for_mining;
                                let allow_sync_reset = no_mine_node || allow_mining_node_reset;
                                // Mining nodes stuck at the same conflict height 5+ times
                                // are definitively on a fork — override the mining guard.
                                let force_reset = sync_conflict_hits >= 5
                                    && sync_conflict_height == local_tip.saturating_add(1);
                                if sync_auto_reset_on_conflict
                                    && (allow_sync_reset || force_reset)
                                    && sync_conflict_hits >= 3
                                {
                                    eprintln!(
                                        "[StarForge] sync conflict persists at h={} (hits={}); clearing local ledger for full resync",
                                        sync_conflict_height, sync_conflict_hits
                                    );
                                    let cleared = match ledger.lock() {
                                        Ok(l) => l.clear_chain(),
                                        Err(_) => Err("ledger lock poisoned".to_string()),
                                    };
                                    match cleared {
                                        Ok(()) => {
                                            last_sync_progress_height = 0;
                                            last_sync_progress_ms = now_ms();
                                            last_blocks_response_ms = now_ms();
                                            bootstrap_genesis_stall_count = 0;
                                            genesis_mismatch_hits = 0;
                                            sync_conflict_hits = 0;
                                            sync_conflict_height = 0;
                                            fork_oo_stall_count = 0;
                                            fork_oo_peer_max_h = 0;
                                            recent_sync_requests.clear();
                                            let sent_at = now_ms();
                                            if try_send_sync_getblocks(
                                                &network,
                                                &mut recent_sync_requests,
                                                0,
                                                SYNC_GETBLOCKS_MAX_COUNT,
                                                sent_at,
                                                true,
                                            ) {
                                                last_sync_request_ms = sent_at;
                                            }
                                        }
                                        Err(err) => {
                                            eprintln!(
                                                "[StarForge] sync auto-reset failed: {}",
                                                err
                                            );
                                        }
                                    }
                                }
                                // Fork recovery: when peers consistently send blocks
                                // that we can't apply (out-of-order), it means we're
                                // likely on a different fork. This covers three cases:
                                // (a) peer blocks AHEAD of our tip (first_h > local_tip)
                                // (b) peer blocks OVERLAP our chain but don't match
                                //     (all out-of-order, none applied — diverged fork)
                                // (c) batch at local_tip+1 rejected with prev hash mismatch
                                //     (zero OO skips, zero progress — classic chain split)
                                let oo_fork_signal = skipped_out_of_order > 0
                                    && (first_h > local_tip
                                        || (already_exists_count == 0 && first_h <= local_tip));
                                let tip_mismatch_signal = progressed_count == 0
                                    && skipped_out_of_order == 0
                                    && already_exists_count == 0
                                    && first_h == local_tip.saturating_add(1)
                                    && batch_result
                                        .stop_error
                                        .as_deref()
                                        .map(|e| {
                                            let l = e.to_ascii_lowercase();
                                            l.contains("prev hash mismatch")
                                                || l.contains("missing parent")
                                        })
                                        .unwrap_or(false);
                                let fork_signal = oo_fork_signal || tip_mismatch_signal;
                                if fork_signal {
                                    fork_oo_stall_count = fork_oo_stall_count.saturating_add(1);
                                    fork_oo_peer_max_h = fork_oo_peer_max_h.max(last_h);
                                    if fork_oo_stall_count % 5 == 0 {
                                        eprintln!(
                                            "[StarForge] fork detector: {} consecutive out-of-order stalls (peer chain up to h={}, local tip h={})",
                                            fork_oo_stall_count, fork_oo_peer_max_h, local_tip
                                        );
                                    }
                                    if sync_auto_reset_on_conflict
                                        && fork_oo_stall_count >= FORK_OO_RECOVERY_THRESHOLD
                                    {
                                        eprintln!(
                                            "[StarForge] FORK RECOVERY: {} consecutive out-of-order stalls, \
                                             peer chain at h={} vs local h={}; clearing chain for full resync",
                                            fork_oo_stall_count, fork_oo_peer_max_h, local_tip
                                        );
                                        let cleared = match ledger.lock() {
                                            Ok(l) => l.clear_chain(),
                                            Err(_) => Err("ledger lock poisoned".to_string()),
                                        };
                                        match cleared {
                                            Ok(()) => {
                                                last_sync_progress_height = 0;
                                                last_sync_progress_ms = now_ms();
                                                last_blocks_response_ms = now_ms();
                                                bootstrap_genesis_stall_count = 0;
                                                genesis_mismatch_hits = 0;
                                                sync_conflict_hits = 0;
                                                sync_conflict_height = 0;
                                                fork_oo_stall_count = 0;
                                                fork_oo_peer_max_h = 0;
                                                recent_sync_requests.clear();
                                                let sent_at = now_ms();
                                                if try_send_sync_getblocks(
                                                    &network,
                                                    &mut recent_sync_requests,
                                                    0,
                                                    SYNC_GETBLOCKS_MAX_COUNT,
                                                    sent_at,
                                                    true,
                                                ) {
                                                    last_sync_request_ms = sent_at;
                                                }
                                            }
                                            Err(err) => {
                                                eprintln!(
                                                    "[StarForge] FORK RECOVERY failed: {}",
                                                    err
                                                );
                                            }
                                        }
                                    }
                                }
                            }
                            if progressed_count > 0 {
                                sync_conflict_hits = 0;
                                sync_conflict_height = 0;
                                fork_oo_stall_count = 0;
                                fork_oo_peer_max_h = 0;
                                // Keep draining forward without waiting for the stall timer.
                                let next_from = match ledger.lock() {
                                    Ok(l) => l.height().unwrap_or(0).saturating_add(1),
                                    Err(_) => 0,
                                };
                                let sent_at = now_ms();
                                if try_send_sync_getblocks(
                                    &network,
                                    &mut recent_sync_requests,
                                    next_from,
                                    SYNC_GETBLOCKS_MAX_COUNT,
                                    sent_at,
                                    false,
                                ) {
                                    eprintln!(
                                        "[StarForge] sync continue from h={} after progressing {} block(s)",
                                        next_from,
                                        progressed_count
                                    );
                                    last_sync_request_ms = sent_at;
                                }
                            }
                        }
                        Message::Vote(_) => {}
                        Message::Handshake { tip, .. } => {
                            if bootstrap_sync_dormant && tip > 0 {
                                bootstrap_sync_dormant = false;
                                bootstrap_sync_dormant_since_ms = 0;
                                last_bootstrap_dormant_log_ms = 0;
                                bootstrap_genesis_stall_count = 0;
                                last_sync_request_ms = 0;
                                eprintln!(
                                    "[StarForge] waking sync from dormancy: peer handshake advertises tip={}",
                                    tip
                                );
                            }
                        }
                        Message::TimeoutVote(_) => {}
                        Message::TimeoutCertificate(_) => {}
                        Message::Slash(ev) => {
                            if let Ok(mut pool) = slash_pool.lock() {
                                pool.push(ev);
                            }
                        }
                        Message::Ping(nonce) => {
                            network.try_send(Message::Pong(nonce));
                        }
                        _ => {}
                    }
                    } // end for env in pending_msgs
                }
                _ = ticker.tick() => {
                    let now = now_ms();
                    let prev_active_peers = last_active_peers;
                    let active_peers = network.active_peer_count();
                    if bootstrap_sync_dormant && active_peers > prev_active_peers {
                        bootstrap_sync_dormant = false;
                        bootstrap_sync_dormant_since_ms = 0;
                        last_bootstrap_dormant_log_ms = 0;
                        bootstrap_genesis_stall_count = 0;
                        last_sync_request_ms = 0;
                        eprintln!(
                            "[StarForge] waking sync from dormancy: peers {} -> {}",
                            prev_active_peers, active_peers
                        );
                    }
                    last_active_peers = active_peers;
                    if let Some(checkpoint) = chain_checkpoint {
                        let checkpoint_status = match ledger.lock() {
                            Ok(l) => local_checkpoint_status(&l, checkpoint),
                            Err(_) => Err("ledger lock poisoned".to_string()),
                        };
                        match checkpoint_status {
                            Ok(LocalCheckpointStatus::Pending) | Ok(LocalCheckpointStatus::Match) => {}
                            Ok(LocalCheckpointStatus::Mismatch(local_hash)) => {
                                chain_continuity_ok = false;
                                chain_continuity_checked_once = true;
                                chain_continuity_reason = format!(
                                    "checkpoint mismatch at h={} local={} expected={}",
                                    checkpoint.height,
                                    hex_hash(local_hash),
                                    hex_hash(checkpoint.hash)
                                );
                                if now.saturating_sub(last_chain_continuity_log_ms) >= 10_000 {
                                    eprintln!(
                                        "[StarForge] checkpoint mismatch at h={} local={} expected={} — mining disabled until checkpoint realigns",
                                        checkpoint.height,
                                        hex_hash(local_hash),
                                        hex_hash(checkpoint.hash)
                                    );
                                    last_chain_continuity_log_ms = now;
                                }
                                if sync_auto_reset_on_conflict {
                                    eprintln!(
                                        "[StarForge] checkpoint recovery: clearing local chain for full resync"
                                    );
                                    let cleared = match ledger.lock() {
                                        Ok(l) => l.clear_chain(),
                                        Err(_) => Err("ledger lock poisoned".to_string()),
                                    };
                                    match cleared {
                                        Ok(()) => {
                                            last_sync_progress_height = 0;
                                            last_sync_progress_ms = now_ms();
                                            last_blocks_response_ms = now_ms();
                                            bootstrap_genesis_stall_count = 0;
                                            genesis_mismatch_hits = 0;
                                            sync_conflict_hits = 0;
                                            sync_conflict_height = 0;
                                            fork_oo_stall_count = 0;
                                            fork_oo_peer_max_h = 0;
                                            chain_continuity_ok = false;
                                            chain_continuity_checked_once = false;
                                            pending_mining = None;
                                            recent_sync_requests.clear();
                                            let sent_at = now_ms();
                                            if try_send_sync_getblocks(
                                                &network,
                                                &mut recent_sync_requests,
                                                0,
                                                SYNC_GETBLOCKS_MAX_COUNT,
                                                sent_at,
                                                true,
                                            ) {
                                                last_sync_request_ms = sent_at;
                                            }
                                            continue;
                                        }
                                        Err(err) => {
                                            eprintln!(
                                                "[StarForge] checkpoint recovery failed: {}",
                                                err
                                            );
                                        }
                                    }
                                }
                            }
                            Err(err) => {
                                chain_continuity_ok = false;
                                chain_continuity_reason =
                                    format!("checkpoint verification failed: {}", err);
                                if now.saturating_sub(last_chain_continuity_log_ms) >= 10_000 {
                                    eprintln!(
                                        "[StarForge] checkpoint verification error: {}",
                                        err
                                    );
                                    last_chain_continuity_log_ms = now;
                                }
                            }
                        }
                    }
                    if let Some(upstream_rpc) = upstream_sync_rpc.as_deref() {
                        if now.saturating_sub(last_chain_continuity_check_ms) >= CHAIN_CONTINUITY_CHECK_MS {
                            last_chain_continuity_check_ms = now;
                            match verify_chain_continuity(&ledger, upstream_rpc, upstream_sync_timeout).await {
                                Ok(Some(status)) => {
                                    chain_continuity_checked_once = true;
                                    if status.ok {
                                        chain_continuity_ok = true;
                                        chain_continuity_reason.clear();
                                        last_chain_continuity_ok_ms = now;
                                        chain_continuity_mismatch_streak = 0;
                                        last_chain_continuity_mismatch_signature.clear();
                                    } else {
                                        chain_continuity_ok = false;
                                        chain_continuity_reason = format!(
                                            "mismatch at h={} local={} upstream={}",
                                            status.shared_height,
                                            status.local_hash,
                                            status.upstream_hash
                                        );
                                        let mismatch_signature = format!(
                                            "{}:{}:{}",
                                            status.shared_height,
                                            status.local_hash,
                                            status.upstream_hash
                                        );
                                        if mismatch_signature
                                            == last_chain_continuity_mismatch_signature
                                        {
                                            chain_continuity_mismatch_streak =
                                                chain_continuity_mismatch_streak.saturating_add(1);
                                        } else {
                                            last_chain_continuity_mismatch_signature =
                                                mismatch_signature;
                                            chain_continuity_mismatch_streak = 1;
                                        }
                                        if now.saturating_sub(last_chain_continuity_log_ms) >= 10_000 {
                                            eprintln!(
                                                "[StarForge] chain continuity mismatch at h={} (local_tip={} upstream_tip={}) local={} upstream={} — mining disabled until chain realigns",
                                                status.shared_height,
                                                status.local_tip,
                                                status.upstream_tip,
                                                status.local_hash,
                                                status.upstream_hash
                                            );
                                            last_chain_continuity_log_ms = now;
                                        }
                                        // Recover not only immediate tip divergence, but also
                                        // persistent continuity mismatch while sync remains stalled.
                                        let tip_diverged = status.shared_height
                                            >= status.local_tip.saturating_sub(1);
                                        let persistent_stalled_mismatch = status.local_tip
                                            > status.shared_height.saturating_add(1)
                                            && now.saturating_sub(last_sync_progress_ms)
                                                >= sync_stall_ms
                                            && chain_continuity_mismatch_streak
                                                >= CHAIN_CONTINUITY_MISMATCH_RECOVERY_STREAK;
                                        if sync_auto_reset_on_conflict
                                            && (tip_diverged || persistent_stalled_mismatch)
                                        {
                                            let recovery_reason = if tip_diverged {
                                                format!(
                                                    "tip diverged at h={}",
                                                    status.shared_height
                                                )
                                            } else {
                                                format!(
                                                    "persistent mismatch while stalled (streak={} shared_h={} local_tip={} upstream_tip={})",
                                                    chain_continuity_mismatch_streak,
                                                    status.shared_height,
                                                    status.local_tip,
                                                    status.upstream_tip
                                                )
                                            };
                                            eprintln!(
                                                "[StarForge] chain continuity recovery: {} — clearing ledger for full resync",
                                                recovery_reason
                                            );
                                            let cleared = match ledger.lock() {
                                                Ok(l) => l.clear_chain(),
                                                Err(_) => Err("ledger lock poisoned".to_string()),
                                            };
                                            match cleared {
                                                Ok(()) => {
                                                    last_sync_progress_height = 0;
                                                    last_sync_progress_ms = now_ms();
                                                    last_blocks_response_ms = now_ms();
                                                    bootstrap_genesis_stall_count = 0;
                                                    genesis_mismatch_hits = 0;
                                                    sync_conflict_hits = 0;
                                                    sync_conflict_height = 0;
                                                    fork_oo_stall_count = 0;
                                                    fork_oo_peer_max_h = 0;
                                                    chain_continuity_ok = false;
                                                    chain_continuity_checked_once = false;
                                                    chain_continuity_mismatch_streak = 0;
                                                    last_chain_continuity_mismatch_signature
                                                        .clear();
                                                    pending_mining = None;
                                                    recent_sync_requests.clear();
                                                    let sent_at = now_ms();
                                                    if try_send_sync_getblocks(
                                                        &network,
                                                        &mut recent_sync_requests,
                                                        0,
                                                        SYNC_GETBLOCKS_MAX_COUNT,
                                                        sent_at,
                                                        true,
                                                    ) {
                                                        last_sync_request_ms = sent_at;
                                                    }
                                                }
                                                Err(err) => {
                                                    eprintln!(
                                                        "[StarForge] chain continuity recovery failed: {}",
                                                        err
                                                    );
                                                }
                                            }
                                        }
                                    }
                                }
                                Ok(None) => {
                                    chain_continuity_mismatch_streak = 0;
                                    last_chain_continuity_mismatch_signature.clear();
                                    if chain_continuity_fail_closed {
                                        chain_continuity_ok = false;
                                        if chain_continuity_reason.is_empty() {
                                            chain_continuity_reason =
                                                "waiting for continuity anchor".to_string();
                                        }
                                    }
                                }
                                Err(err) => {
                                    chain_continuity_mismatch_streak = 0;
                                    last_chain_continuity_mismatch_signature.clear();
                                    if chain_continuity_fail_closed {
                                        let unavailable_ms =
                                            now.saturating_sub(last_chain_continuity_ok_ms);
                                        if !chain_continuity_checked_once
                                            || unavailable_ms >= chain_continuity_unavailable_grace_ms
                                        {
                                            chain_continuity_ok = false;
                                            chain_continuity_reason = if chain_continuity_checked_once {
                                                format!(
                                                    "trusted continuity unavailable for {} ms",
                                                    unavailable_ms
                                                )
                                            } else {
                                                "awaiting first trusted continuity check".to_string()
                                            };
                                        }
                                    }
                                    if now.saturating_sub(last_chain_continuity_log_ms) >= 10_000 {
                                        eprintln!("[StarForge] chain continuity check unavailable: {}", err);
                                        last_chain_continuity_log_ms = now;
                                    }
                                }
                            }
                        }
                        let (local_tip, has_genesis) = match ledger.lock() {
                            Ok(l) => (
                                l.height().unwrap_or(0),
                                l.get_block(0).unwrap_or(None).is_some(),
                            ),
                            Err(_) => (0, false),
                        };
                        let must_catch_up = min_local_height_for_mining > 0
                            && local_tip < min_local_height_for_mining;
                        let should_try_upstream_sync = must_catch_up || local_tip == 0;
                        let stalled_rpc = now.saturating_sub(last_sync_progress_ms) >= sync_retry_ms;
                        if should_try_upstream_sync && stalled_rpc {
                            let mut batch_loops = 0usize;
                            // When genesis is missing, request from h=0 so the
                            // upstream RPC sends the genesis block first.
                            let mut next_from = if has_genesis {
                                local_tip.saturating_add(1)
                            } else {
                                0
                            };
                            while batch_loops < MAX_UPSTREAM_SYNC_BATCH_LOOPS {
                                batch_loops = batch_loops.saturating_add(1);
                                last_sync_request_ms = now_ms();
                                let rpc_limit =
                                    current_upstream_sync_batch_count.min(MAX_RPC_BLOCKS).max(1);
                                match rpc_get_blocks_with_timeout(
                                    upstream_rpc,
                                    next_from,
                                    rpc_limit,
                                    upstream_sync_timeout,
                                )
                                .await
                                {
                                    Ok(blocks) => {
                                        if blocks.is_empty() {
                                            break;
                                        }
                                        let first_h =
                                            blocks.first().map(|b| b.header.height).unwrap_or(0);
                                        let last_h =
                                            blocks.last().map(|b| b.header.height).unwrap_or(0);
                                        eprintln!(
                                            "[StarForge] upstream sync batch received count={} range={}..{}",
                                            blocks.len(),
                                            first_h,
                                            last_h
                                        );
                                        if let Some(checkpoint) = chain_checkpoint {
                                            if let Some(peer_hash) =
                                                checkpoint_mismatch_in_blocks(&blocks, checkpoint)
                                            {
                                                if sync_conflict_height == checkpoint.height {
                                                    sync_conflict_hits =
                                                        sync_conflict_hits.saturating_add(1);
                                                } else {
                                                    sync_conflict_height = checkpoint.height;
                                                    sync_conflict_hits = 1;
                                                }
                                                eprintln!(
                                                    "[StarForge] upstream sync rejected range={}..{} checkpoint mismatch h={} expected={} got={} hit={}",
                                                    first_h,
                                                    last_h,
                                                    checkpoint.height,
                                                    hex_hash(checkpoint.hash),
                                                    hex_hash(peer_hash),
                                                    sync_conflict_hits
                                                );
                                                break;
                                            }
                                        }
                                        let batch_result = match ledger.lock() {
                                            Ok(l) => l.append_sync_batch(&blocks),
                                            Err(_) => {
                                                eprintln!(
                                                    "[StarForge] upstream sync stop: ledger lock poisoned"
                                                );
                                                break;
                                            }
                                        };
                                        let applied_count = batch_result.applied_count;
                                        let progressed_count = batch_result.progressed_count;
                                        if let Some(last_height) =
                                            batch_result.last_progress_height
                                        {
                                            eprintln!(
                                                "[StarForge] upstream sync progressed {} block(s) (new={} existing={}) through h={}",
                                                progressed_count,
                                                applied_count,
                                                batch_result.already_exists_count,
                                                last_height
                                            );
                                            if last_height > last_sync_progress_height {
                                                last_sync_progress_height = last_height;
                                                last_sync_progress_ms = now_ms();
                                            }
                                            genesis_mismatch_hits = 0;
                                            cancel_pending_mining_if_stale(
                                                &ledger,
                                                &mut pending_mining,
                                                "upstream sync advanced local chain",
                                            );
                                        }
                                        if batch_result.skipped_out_of_order > 0 {
                                            let local_tip = match ledger.lock() {
                                                Ok(l) => l.height().unwrap_or(0),
                                                Err(_) => 0,
                                            };
                                            eprintln!(
                                                "[StarForge] upstream sync skipped {} out-of-order block(s) at local_tip={}",
                                                batch_result.skipped_out_of_order,
                                                local_tip
                                            );
                                        }
                                        if let (Some(stop_height), Some(e)) = (
                                            batch_result.stop_height,
                                            batch_result.stop_error.as_deref(),
                                        ) {
                                            let lower_err = e.to_ascii_lowercase();
                                            if e.contains("conflicting block at height")
                                                || lower_err.contains("prev hash mismatch")
                                                || lower_err.contains("missing parent")
                                                || lower_err.contains("timestamp is earlier than parent")
                                            {
                                                if sync_conflict_height == stop_height {
                                                    sync_conflict_hits =
                                                        sync_conflict_hits.saturating_add(1);
                                                } else {
                                                    sync_conflict_height = stop_height;
                                                    sync_conflict_hits = 1;
                                                }
                                                eprintln!(
                                                    "[StarForge] sync conflict h={} hit={}",
                                                    stop_height,
                                                    sync_conflict_hits
                                                );
                                            }
                                            eprintln!(
                                                "[StarForge] upstream sync stop h={}: {}",
                                                stop_height,
                                                e
                                            );
                                        }
                                        if progressed_count == 0 {
                                            break;
                                        }
                                        sync_conflict_hits = 0;
                                        sync_conflict_height = 0;
                                        fork_oo_stall_count = 0;
                                        fork_oo_peer_max_h = 0;
                                        if applied_count as u32 >= rpc_limit
                                            && current_upstream_sync_batch_count
                                                < upstream_sync_batch_count
                                        {
                                            current_upstream_sync_batch_count =
                                                (current_upstream_sync_batch_count.saturating_mul(2))
                                                    .min(upstream_sync_batch_count)
                                                    .max(1);
                                            eprintln!(
                                                "[StarForge] upstream sync batch size increased to {}",
                                                current_upstream_sync_batch_count
                                            );
                                        }
                                        next_from = match ledger.lock() {
                                            Ok(l) => l.height().unwrap_or(0).saturating_add(1),
                                            Err(_) => 0,
                                        };
                                        if progressed_count < blocks.len() {
                                            break;
                                        }
                                        if next_from > min_local_height_for_mining
                                            && min_local_height_for_mining > 0
                                        {
                                            break;
                                        }
                                    }
                                    Err(err) => {
                                        let lower_err = err.to_ascii_lowercase();
                                        let mut should_retry_smaller_batch = false;
                                        if (lower_err.contains("response too large")
                                            || lower_err.contains("read len timeout")
                                            || lower_err.contains("read body timeout"))
                                            && current_upstream_sync_batch_count > 1
                                        {
                                            let next_batch =
                                                (current_upstream_sync_batch_count / 2).max(1);
                                            if next_batch != current_upstream_sync_batch_count {
                                                current_upstream_sync_batch_count = next_batch;
                                                should_retry_smaller_batch = true;
                                                eprintln!(
                                                    "[StarForge] upstream sync batch size reduced to {} after error: {}",
                                                    current_upstream_sync_batch_count, err
                                                );
                                            }
                                        }
                                        eprintln!(
                                            "[StarForge] upstream sync request from h={} failed (batch={}): {}",
                                            next_from, rpc_limit, err
                                        );
                                        if should_retry_smaller_batch {
                                            continue;
                                        }
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    if active_peers > 0 && now.saturating_sub(last_sync_request_ms) >= sync_retry_ms {
                        let (tip, has_genesis) = match ledger.lock() {
                            Ok(l) => (
                                l.height().unwrap_or(0),
                                l.get_block(0).unwrap_or(None).is_some(),
                            ),
                            Err(_) => (0, false),
                        };
                        let bootstrap_has_genesis = has_genesis && tip == 0;
                        let stalled = has_genesis
                            && tip <= last_sync_progress_height
                            && now.saturating_sub(last_sync_progress_ms) >= sync_stall_ms;
                        let no_block_response_ms = now.saturating_sub(last_blocks_response_ms);
                        if bootstrap_has_genesis {
                            if !bootstrap_sync_dormant
                                && no_block_response_ms >= sync_bootstrap_dormant_ms
                            {
                                bootstrap_sync_dormant = true;
                                bootstrap_sync_dormant_since_ms = now;
                                last_bootstrap_dormant_log_ms = now;
                                eprintln!(
                                    "[StarForge] sync dormancy entered at tip=0 after {} ms without block responses (peers={})",
                                    no_block_response_ms, active_peers
                                );
                            } else if bootstrap_sync_dormant
                                && now.saturating_sub(last_bootstrap_dormant_log_ms)
                                    >= SYNC_BOOTSTRAP_DORMANT_LOG_MS
                            {
                                eprintln!(
                                    "[StarForge] sync dormancy active for {} ms at tip=0 (peers={})",
                                    now.saturating_sub(bootstrap_sync_dormant_since_ms),
                                    active_peers
                                );
                                last_bootstrap_dormant_log_ms = now;
                            }
                        } else if bootstrap_sync_dormant {
                            bootstrap_sync_dormant = false;
                            bootstrap_sync_dormant_since_ms = 0;
                            last_bootstrap_dormant_log_ms = 0;
                            bootstrap_genesis_stall_count = 0;
                        }
                        if !has_genesis || stalled || (bootstrap_has_genesis && !bootstrap_sync_dormant) {
                            // Exponential backoff for stalled-at-tip sync requests.
                            // Bootstrap always uses base retry rate; stalled uses 2^n * 1s capped at 30s.
                            let effective_retry = if stalled && !bootstrap_has_genesis {
                                let backoff_ms = (sync_retry_ms << consecutive_stall_syncs.min(5))
                                    .min(SYNC_STALL_BACKOFF_CAP_MS);
                                backoff_ms
                            } else {
                                consecutive_stall_syncs = 0;
                                sync_retry_ms
                            };
                            if now.saturating_sub(last_sync_request_ms) < effective_retry {
                                // Skip — backoff not elapsed yet.
                            } else {
                                let dual_probe = bootstrap_has_genesis
                                    && bootstrap_genesis_stall_count >= 3
                                    && no_block_response_ms >= sync_stall_ms;
                                let from = if !has_genesis {
                                    0
                                } else if bootstrap_has_genesis {
                                    if bootstrap_genesis_stall_count >= 3 { 0 } else { 1 }
                                } else {
                                    tip.saturating_add(1)
                                };
                                let reason = if !has_genesis {
                                    "bootstrap-no-genesis"
                                } else if bootstrap_has_genesis {
                                    if from == 0 {
                                        "bootstrap-has-genesis-fallback0"
                                    } else {
                                        "bootstrap-has-genesis"
                                    }
                                } else {
                                    "stalled"
                                };
                                let mut sent_any = false;
                                if try_send_sync_getblocks(
                                    &network,
                                    &mut recent_sync_requests,
                                    from,
                                    SYNC_GETBLOCKS_MAX_COUNT,
                                    now,
                                    false,
                                ) {
                                    eprintln!(
                                        "[StarForge] sync request from h={} (tip={}, peers={}, reason={})",
                                        from, tip, active_peers, reason
                                    );
                                    sent_any = true;
                                }
                                if dual_probe {
                                    let probe_from = if from == 0 { 1 } else { 0 };
                                    if try_send_sync_getblocks(
                                        &network,
                                        &mut recent_sync_requests,
                                        probe_from,
                                        SYNC_GETBLOCKS_MAX_COUNT,
                                        now,
                                        false,
                                    ) {
                                        eprintln!(
                                            "[StarForge] sync probe from h={} (tip=0, peers={}, reason=bootstrap-dual-probe)",
                                            probe_from, active_peers
                                        );
                                        sent_any = true;
                                    }
                                }
                                if sent_any {
                                    if stalled && !bootstrap_has_genesis {
                                        consecutive_stall_syncs =
                                            consecutive_stall_syncs.saturating_add(1);
                                    }
                                    last_sync_request_ms = now;
                                    if bootstrap_has_genesis {
                                        bootstrap_genesis_stall_count =
                                            bootstrap_genesis_stall_count.saturating_add(1);
                                    } else if tip > 0 {
                                        bootstrap_genesis_stall_count = 0;
                                    }
                                }
                            } // end effective_retry else
                        }
                    }
                    if !mining_enabled {
                        continue;
                    }
                    if let Some(err) = chain_checkpoint_config_error.as_deref() {
                        if pending_mining.is_some() {
                            eprintln!(
                                "[StarForge] cancel pending mining while checkpoint config is invalid"
                            );
                            pending_mining = None;
                        }
                        if now.saturating_sub(last_chain_continuity_log_ms) > 10_000 {
                            eprintln!(
                                "[StarForge] mining paused: invalid checkpoint configuration ({})",
                                err
                            );
                            last_chain_continuity_log_ms = now;
                        }
                        continue;
                    }
                    if min_peers_for_mining > 0 {
                        if active_peers < min_peers_for_mining {
                            if now.saturating_sub(last_peer_gate_log_ms) > 10_000 {
                                eprintln!(
                                    "[StarForge] mining paused: active peers {} below required {}",
                                    active_peers, min_peers_for_mining
                                );
                                last_peer_gate_log_ms = now;
                            }
                            continue;
                        }
                    }
                    let local_tip = match ledger.lock() {
                        Ok(l) => l.height().unwrap_or(0),
                        Err(_) => 0,
                    };
                    if min_local_height_for_mining > 0 {
                        if local_tip < min_local_height_for_mining {
                            if now.saturating_sub(last_peer_gate_log_ms) > 10_000 {
                                eprintln!(
                                    "[StarForge] mining paused: local tip {} below required startup height {}",
                                    local_tip, min_local_height_for_mining
                                );
                                last_peer_gate_log_ms = now;
                            }
                            continue;
                        }
                    }
                    if let Some(checkpoint) = chain_checkpoint {
                        let checkpoint_status = match ledger.lock() {
                            Ok(l) => local_checkpoint_status(&l, checkpoint),
                            Err(_) => Err("ledger lock poisoned".to_string()),
                        };
                        match checkpoint_status {
                            Ok(LocalCheckpointStatus::Match) => {}
                            Ok(LocalCheckpointStatus::Pending) => {
                                if pending_mining.is_some() {
                                    eprintln!(
                                        "[StarForge] cancel pending mining while waiting for checkpoint sync"
                                    );
                                    pending_mining = None;
                                }
                                if now.saturating_sub(last_chain_continuity_log_ms) > 10_000 {
                                    eprintln!(
                                        "[StarForge] mining paused: waiting to reach checkpoint h={} (local_tip={})",
                                        checkpoint.height,
                                        local_tip
                                    );
                                    last_chain_continuity_log_ms = now;
                                }
                                continue;
                            }
                            Ok(LocalCheckpointStatus::Mismatch(local_hash)) => {
                                if pending_mining.is_some() {
                                    eprintln!(
                                        "[StarForge] cancel pending mining while checkpoint mismatch is active"
                                    );
                                    pending_mining = None;
                                }
                                if now.saturating_sub(last_chain_continuity_log_ms) > 10_000 {
                                    eprintln!(
                                        "[StarForge] mining paused: checkpoint mismatch h={} local={} expected={}",
                                        checkpoint.height,
                                        hex_hash(local_hash),
                                        hex_hash(checkpoint.hash)
                                    );
                                    last_chain_continuity_log_ms = now;
                                }
                                continue;
                            }
                            Err(err) => {
                                if pending_mining.is_some() {
                                    eprintln!(
                                        "[StarForge] cancel pending mining while checkpoint verification fails"
                                    );
                                    pending_mining = None;
                                }
                                if now.saturating_sub(last_chain_continuity_log_ms) > 10_000 {
                                    eprintln!(
                                        "[StarForge] mining paused: checkpoint verification failed ({})",
                                        err
                                    );
                                    last_chain_continuity_log_ms = now;
                                }
                                continue;
                            }
                        }
                    }
                    if now < fork_guard_pause_until_ms {
                        if pending_mining.is_some() {
                            eprintln!("[StarForge] cancel pending mining while fork guard is active");
                            pending_mining = None;
                        }
                        if now.saturating_sub(last_fork_guard_log_ms) > 10_000 {
                            eprintln!(
                                "[StarForge] mining paused by fork guard for {} ms",
                                fork_guard_pause_until_ms.saturating_sub(now)
                            );
                            last_fork_guard_log_ms = now;
                        }
                        continue;
                    }
                    if !chain_continuity_ok {
                        if pending_mining.is_some() {
                            eprintln!(
                                "[StarForge] cancel pending mining while chain continuity is unverified"
                            );
                            pending_mining = None;
                        }
                        if now.saturating_sub(last_chain_continuity_log_ms) > 10_000 {
                            eprintln!(
                                "[StarForge] mining paused: chain continuity not verified ({})",
                                if chain_continuity_reason.is_empty() {
                                    "waiting for trusted chain confirmation"
                                } else {
                                    &chain_continuity_reason
                                }
                            );
                            last_chain_continuity_log_ms = now;
                        }
                        continue;
                    }
                    {
                        let ts_now = now_ms();
                        let (height, proposer_streak, mining_rules, prev_block, prev, parent_ts, elected_leader) = match ledger.lock() {
                            Ok(l) => {
                                let tip = l.height().unwrap_or(0);
                                let has_genesis = l.get_block(0).unwrap_or(None).is_some();
                                let height = if has_genesis { tip.saturating_add(1) } else { 0 };
                                let streak = proposer_streak_for_height(&l, height, proposer_id, ts_now);
                                let rules = match l.mining_rules_for_height(height, now) {
                                    Ok(r) => r,
                                    Err(err) => {
                                        eprintln!("[StarForge] mining rules failed: {}", err);
                                        continue;
                                    }
                                };
                                let prev = if height > 0 { l.get_block(height.saturating_sub(1)).ok().flatten() } else { None };
                                let prev_hash = prev
                                    .as_ref()
                                    .map(|b| hash_header_for_link(&b.header))
                                    .unwrap_or(Hash32::ZERO);
                                let parent_ts = prev
                                    .as_ref()
                                    .map(|b| b.header.timestamp_ms)
                                    .unwrap_or(0);
                                let elected_leader = if forge_election_enabled && height > 1 {
                                    forge_election_for_height(&l, height).map(|election| election.leader)
                                } else {
                                    None
                                };
                                (height, streak, rules, prev, prev_hash, parent_ts, elected_leader)
                            }
                            Err(_) => continue,
                        };
                        if !mining_rules.allow_proposal {
                            continue;
                        }
                        // ── ForgeTitan election gate ──
                        // Query the local ledger for the election result.
                        // All nodes compute the same result from chain state,
                        // so this works whether we're a ForgeTitan or a miner.
                        if let Some(elected_leader) = elected_leader {
                            if elected_leader != proposer_id {
                                let grace_expires = parent_ts.saturating_add(FORGE_GRACE_MS);
                                if ts_now < grace_expires {
                                    continue;
                                }
                            }
                        }
                        // The block timestamp spacing rule (min_spacing_ms check below)
                        // enforces minimum block intervals at the consensus layer.
                        // No additional propose-attempt cooldown needed — PoW solve
                        // time naturally spaces proposals.
                        let propose_interval_ms: u64 = 0;
                        if pending_mining.is_some() {
                            // A proof is already being generated; keep the loop responsive
                            // for inbound sync traffic until that proposal resolves.
                            continue;
                        }
                        if now.saturating_sub(last_propose_ms) < propose_interval_ms {
                            continue;
                        }
                        last_propose_ms = now;
                        let mut txs = take_mempool(&mempool, knox_types::MAX_BLOCK_TX);
                        let slashes = take_slashes(&slash_pool, MAX_SLASHES_PER_BLOCK);
                        eprintln!(
                            "[StarForge] propose attempt h={} r=0 txs={} slashes={}",
                            height,
                            txs.len(),
                            slashes.len()
                        );
                        let coinbase = match build_coinbase(height, proposer_streak, &miner_address, &treasury_address, &dev_address, &premine_address, &txs) {
                            Ok(cb) => cb,
                            Err(err) => {
                                eprintln!("[StarForge] coinbase build failed: {}", err);
                                continue;
                            }
                        };
                        txs.insert(0, coinbase);
                        let tx_hashes = txs
                            .iter()
                            .filter_map(|t| bincode::encode_to_vec(t, bincode::config::standard()).ok().map(|v| hash_bytes(&v)))
                            .collect::<Vec<_>>();
                        let tx_root = merkle_root(&tx_hashes);
                        let slash_root = slash_root(&slashes);
                        let state_root = knox_types::compute_state_root(height, prev, tx_root, slash_root);
                        if let Some(parent) = prev_block.as_ref() {
                            let min_next = parent
                                .header
                                .timestamp_ms
                                .saturating_add(mining_rules.min_spacing_ms);
                            // Do not synthesize future timestamps; wait until local wall clock reaches the minimum spacing.
                            if ts_now < min_next {
                                continue;
                            }
                        }
                        let proposal_still_current = match ledger.lock() {
                            Ok(l) => proposal_target_matches_current_chain(&l, height, prev),
                            Err(_) => false,
                        };
                        if !proposal_still_current {
                            eprintln!(
                                "[StarForge] proposal aborted h={} — chain changed before mining start",
                                height
                            );
                            continue;
                        }
                        let header = BlockHeader {
                            version: 1,
                            height,
                            round: 0,
                            prev,
                            tx_root,
                            slash_root,
                            state_root,
                            timestamp_ms: ts_now,
                            proposer: proposer_id,
                            qc: None,
                        };
                        if let Some(checkpoint) = chain_checkpoint {
                            if header.height == checkpoint.height {
                                let proposed_hash = hash_header_for_link(&header);
                                if proposed_hash != checkpoint.hash {
                                    eprintln!(
                                        "[StarForge] proposal aborted h={} checkpoint mismatch expected={} got={}",
                                        checkpoint.height,
                                        hex_hash(checkpoint.hash),
                                        hex_hash(proposed_hash)
                                    );
                                    continue;
                                }
                            }
                        }
                        let hash = hash_header_for_signing(&header);
                        let sig = match sign_consensus(&secret, &hash.0) {
                            Ok(sig) => sig,
                            Err(err) => {
                                eprintln!("[StarForge] proposer sign failed: {}", err);
                                continue;
                            }
                        };
                        let mut worker_id_bytes = [0u8; 8];
                        worker_id_bytes.copy_from_slice(&proposer_id[..8]);
                        let worker_id = u64::from_le_bytes(worker_id_bytes);
                        let profile_for_mine = mining_profile.clone();
                        let header_for_mine = header.clone();
                        let expected_difficulty_bits = mining_rules.expected_difficulty_bits;
                        let (proof_tx, proof_rx) = tokio::sync::oneshot::channel();
                        tokio::task::spawn_blocking(move || {
                            let result = mine_block_proof_with_profile(
                                &header_for_mine,
                                worker_id,
                                expected_difficulty_bits,
                                &profile_for_mine,
                            )
                            .map(|(proof, status)| (proof, status.to_log_line()));
                            let _ = proof_tx.send(result);
                        });
                        pending_mining = Some(PendingMiningProposal {
                            header,
                            txs,
                            slashes,
                            proposer_sig: sig,
                            result_rx: proof_rx,
                        });
                    }
                }
            }
        }
    }
}

async fn build_diamond_auth_bundle(
    block: &Block,
    authenticators: &[LatticePublicKey],
    quorum: usize,
    endpoints: &[String],
) -> Result<Vec<u8>, String> {
    if endpoints.is_empty() {
        return Err("no diamond auth endpoints configured".to_string());
    }
    let mut matched = HashSet::new();
    let mut sigs: Vec<Vec<u8>> = Vec::new();
    let msg = hash_header_for_signing(&block.header);
    let mut tried = 0usize;
    for endpoint in endpoints.iter().take(MAX_DIAMOND_AUTH_ENDPOINTS) {
        tried = tried.saturating_add(1);
        let sig = match request_diamond_signature(endpoint, block).await {
            Ok(sig) => sig,
            Err(err) => {
                eprintln!(
                    "[StarForge] diamond auth endpoint {} failed: {}",
                    endpoint, err
                );
                continue;
            }
        };
        let mut matched_idx = None;
        for (idx, pk) in authenticators.iter().enumerate() {
            if matched.contains(&idx) {
                continue;
            }
            if verify_consensus(pk, &msg.0, &sig) {
                matched_idx = Some(idx);
                break;
            }
        }
        if let Some(idx) = matched_idx {
            matched.insert(idx);
            sigs.push(sig);
            if matched.len() >= quorum {
                break;
            }
        }
    }
    if matched.len() < quorum {
        return Err(format!(
            "matched {}/{} signatures across {} endpoint(s)",
            matched.len(),
            quorum,
            tried
        ));
    }
    eprintln!(
        "[StarForge] diamond auth cert collected {}/{} for h={}",
        matched.len(),
        quorum,
        block.header.height
    );
    let payload = bincode::encode_to_vec(&sigs, bincode::config::standard())
        .map_err(|e| format!("diamond auth bundle encode failed: {e}"))?;
    let mut out = Vec::with_capacity(b"knox-auth-v1".len() + payload.len());
    out.extend_from_slice(b"knox-auth-v1");
    out.extend_from_slice(&payload);
    Ok(out)
}

async fn request_diamond_signature(endpoint: &str, block: &Block) -> Result<Vec<u8>, String> {
    let req = WalletRequest::SignDiamondCert(block.clone());
    let resp = rpc_request_with_timeout(
        endpoint,
        req,
        Duration::from_millis(DIAMOND_AUTH_RPC_TIMEOUT_MS),
    )
    .await?;
    match resp {
        WalletResponse::DiamondCert(Some(sig)) => Ok(sig),
        WalletResponse::DiamondCert(None) => Err("authenticator rejected candidate".to_string()),
        _ => Err("unexpected response".to_string()),
    }
}

fn rpc_endpoint_candidates(addrs: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for candidate in addrs
        .split(|c: char| c == ',' || c.is_whitespace())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        if seen.insert(candidate.to_string()) {
            out.push(candidate.to_string());
        }
    }
    out
}

async fn rpc_request_single_with_timeout(
    addr: &str,
    req: WalletRequest,
    timeout_dur: Duration,
) -> Result<WalletResponse, String> {
    let mut stream = tokio::time::timeout(timeout_dur, TcpStream::connect(addr))
        .await
        .map_err(|_| format!("connect timeout: {addr}"))?
        .map_err(|e| format!("connect {addr} failed: {e}"))?;
    let bytes = bincode::encode_to_vec(req, bincode::config::standard())
        .map_err(|e| format!("encode request failed: {e}"))?;
    let mut out = Vec::with_capacity(4 + bytes.len());
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&bytes);
    tokio::time::timeout(timeout_dur, stream.write_all(&out))
        .await
        .map_err(|_| format!("write timeout: {addr}"))?
        .map_err(|e| format!("write {addr} failed: {e}"))?;
    let mut len_buf = [0u8; 4];
    tokio::time::timeout(timeout_dur, stream.read_exact(&mut len_buf))
        .await
        .map_err(|_| format!("read len timeout: {addr}"))?
        .map_err(|e| format!("read len {addr} failed: {e}"))?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len == 0 || len > MAX_RPC_BYTES {
        return Err(format!(
            "node upstream rpc response too large ({} bytes > {} byte cap)",
            len, MAX_RPC_BYTES
        ));
    }
    let mut buf = vec![0u8; len];
    tokio::time::timeout(timeout_dur, stream.read_exact(&mut buf))
        .await
        .map_err(|_| format!("read body timeout: {addr}"))?
        .map_err(|e| format!("read body {addr} failed: {e}"))?;
    let (resp, _): (WalletResponse, usize) =
        bincode::decode_from_slice(
            &buf,
            bincode::config::standard().with_limit::<{ 512 * 1024 * 1024 }>(),
        )
            .map_err(|e| format!("decode response failed: {e}"))?;
    Ok(resp)
}

async fn rpc_request_with_timeout(
    addrs: &str,
    req: WalletRequest,
    timeout_dur: Duration,
) -> Result<WalletResponse, String> {
    let endpoints = rpc_endpoint_candidates(addrs);
    if endpoints.is_empty() {
        return Err("no upstream rpc endpoints configured".to_string());
    }
    let endpoint_count = endpoints.len();
    let mut errors = Vec::new();
    for endpoint in endpoints {
        match rpc_request_single_with_timeout(&endpoint, req.clone(), timeout_dur).await {
            Ok(resp) => return Ok(resp),
            Err(err) => errors.push(err),
        }
    }
    if endpoint_count > 1 {
        let host_errors: Vec<String> = errors
            .iter()
            .map(|err| {
                err
                    .strip_prefix("connect ")
                    .and_then(|rest| rest.split_once(" failed:"))
                    .map(|(host, detail)| format!("{} failed:{}", host, detail))
                    .unwrap_or_else(|| err.clone())
            })
            .collect();
        return Err(format!(
            "all upstream rpc endpoints failed [{}]: {}",
            endpoint_count,
            host_errors.join(" | ")
        ));
    }
    Err(format!(
        "all upstream rpc endpoints failed: {}",
        errors.join(" | ")
    ))
}

async fn rpc_get_blocks_with_timeout(
    addr: &str,
    start: u64,
    limit: u32,
    timeout_dur: Duration,
) -> Result<Vec<Block>, String> {
    match rpc_request_with_timeout(addr, WalletRequest::GetBlocks(start, limit), timeout_dur).await?
    {
        WalletResponse::Blocks(blocks) => Ok(blocks),
        _ => Err("unexpected get-blocks response".to_string()),
    }
}

async fn rpc_get_tip_with_timeout(addr: &str, timeout_dur: Duration) -> Result<u64, String> {
    match rpc_request_with_timeout(addr, WalletRequest::GetTip, timeout_dur).await? {
        WalletResponse::Tip(height) => Ok(height),
        _ => Err("unexpected get-tip response".to_string()),
    }
}

async fn rpc_get_block_with_timeout(
    addr: &str,
    height: u64,
    timeout_dur: Duration,
) -> Result<Option<Block>, String> {
    match rpc_request_with_timeout(addr, WalletRequest::GetBlock(height), timeout_dur).await? {
        WalletResponse::Block(block) => Ok(block),
        _ => Err("unexpected get-block response".to_string()),
    }
}

struct ChainContinuityStatus {
    ok: bool,
    shared_height: u64,
    local_tip: u64,
    upstream_tip: u64,
    local_hash: String,
    upstream_hash: String,
}

async fn verify_chain_continuity(
    ledger: &Arc<Mutex<Ledger>>,
    upstream_rpc: &str,
    timeout_dur: Duration,
) -> Result<Option<ChainContinuityStatus>, String> {
    let (local_tip, has_genesis, local_genesis_hash, local_anchor_hash) = {
        let l = ledger
            .lock()
            .map_err(|_| "ledger lock poisoned".to_string())?;
        let local_tip = l.height().unwrap_or(0);
        let Some(genesis) = l.get_block(0).unwrap_or(None) else {
            return Ok(None);
        };
        let local_genesis_hash = hash_header_for_link(&genesis.header);
        let local_anchor_hash = if local_tip == 0 {
            local_genesis_hash
        } else {
            let anchor = l
                .get_block(local_tip)
                .map_err(|e| format!("local anchor lookup failed: {e}"))?
                .ok_or_else(|| format!("local anchor block missing at h={local_tip}"))?;
            hash_header_for_link(&anchor.header)
        };
        (local_tip, true, local_genesis_hash, local_anchor_hash)
    };
    if !has_genesis {
        return Ok(None);
    }

    let upstream_tip = rpc_get_tip_with_timeout(upstream_rpc, timeout_dur).await?;
    let upstream_genesis = rpc_get_block_with_timeout(upstream_rpc, 0, timeout_dur)
        .await?
        .ok_or_else(|| "upstream genesis missing".to_string())?;
    let upstream_genesis_hash = hash_header_for_link(&upstream_genesis.header);
    if upstream_genesis_hash != local_genesis_hash {
        return Ok(Some(ChainContinuityStatus {
            ok: false,
            shared_height: 0,
            local_tip,
            upstream_tip,
            local_hash: hex_hash(local_genesis_hash),
            upstream_hash: hex_hash(upstream_genesis_hash),
        }));
    }

    let shared_height = local_tip.min(upstream_tip);
    let local_hash = if shared_height == local_tip {
        local_anchor_hash
    } else {
        let l = ledger
            .lock()
            .map_err(|_| "ledger lock poisoned".to_string())?;
        let local_shared = l
            .get_block(shared_height)
            .map_err(|e| format!("local shared block lookup failed: {e}"))?
            .ok_or_else(|| format!("local shared block missing at h={shared_height}"))?;
        hash_header_for_link(&local_shared.header)
    };
    let upstream_shared = rpc_get_block_with_timeout(upstream_rpc, shared_height, timeout_dur)
        .await?
        .ok_or_else(|| format!("upstream shared block missing at h={shared_height}"))?;
    let upstream_hash = hash_header_for_link(&upstream_shared.header);
    Ok(Some(ChainContinuityStatus {
        ok: local_hash == upstream_hash,
        shared_height,
        local_tip,
        upstream_tip,
        local_hash: hex_hash(local_hash),
        upstream_hash: hex_hash(upstream_hash),
    }))
}

fn append_finalized_block(
    block: &Block,
    ledger: &Arc<Mutex<Ledger>>,
    mempool: &Arc<Mutex<Vec<MempoolEntry>>>,
) -> bool {
    let height = block.header.height;
    let result = match ledger.lock() {
        Ok(l) => l.append_block(block),
        Err(_) => Err("ledger lock poisoned".to_string()),
    };
    match result {
        Ok(()) => {
            let reward_log = coinbase_reward_log(block);
            if height == 0 {
                eprintln!(
                    "[StarForge] sealed genesis block (premine minted) txs={}{}",
                    block.txs.len(),
                    reward_log
                );
            } else {
                eprintln!(
                    "[StarForge] sealed block {} txs={}{}",
                    height,
                    block.txs.len(),
                    reward_log
                );
            }
            if let Ok(mut mp) = mempool.lock() {
                let mut spent_images = HashSet::new();
                for tx in &block.txs {
                    for input in &tx.inputs {
                        spent_images.insert(input.key_image);
                    }
                }
                mp.retain(|entry| {
                    for input in &entry.tx.inputs {
                        if spent_images.contains(&input.key_image) {
                            return false;
                        }
                    }
                    true
                });
            }
            true
        }
        Err(err) if err.contains("already exists") => false,
        Err(err) => {
            eprintln!("[StarForge] append block {} failed: {}", height, err);
            false
        }
    }
}

fn coinbase_reward_log(block: &Block) -> String {
    let Some(coinbase) = block.txs.first() else {
        return String::new();
    };
    if !coinbase.coinbase {
        return String::new();
    }
    let Ok(payload) = decode_coinbase_payload(&coinbase.extra) else {
        return String::new();
    };
    let split = coinbase_split(block.header.height, 0, 1);
    let mut cursor = 0usize;
    let miner = payload.amounts.get(cursor).copied().unwrap_or(0);
    cursor = cursor.saturating_add(1);
    let treasury = if split.treasury > 0 {
        let value = payload.amounts.get(cursor).copied().unwrap_or(0);
        cursor = cursor.saturating_add(1);
        value
    } else {
        0
    };
    let dev = if split.dev > 0 {
        let value = payload.amounts.get(cursor).copied().unwrap_or(0);
        cursor = cursor.saturating_add(1);
        value
    } else {
        0
    };
    let premine = if split.premine > 0 {
        payload.amounts.get(cursor).copied().unwrap_or(0)
    } else {
        0
    };
    format!(
        " rewards miner={} treasury={} dev={} premine={}",
        miner, treasury, dev, premine
    )
}

async fn run_rpc(
    bind: String,
    ledger: Arc<Mutex<Ledger>>,
    mempool: Arc<Mutex<Vec<MempoolEntry>>>,
    network: NetworkSender,
    rpc_secret: LatticeSecretKey,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(bind).await?;
    if let Ok(addr) = listener.local_addr() {
        eprintln!("[StarForge] rpc listening on {}", addr);
    }
    let allow_remote_rpc = std::env::var("KNOX_NODE_RPC_ALLOW_REMOTE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(true);
    let limiter = RateLimiter::default();
    let decoy_cache = DecoyCache::default();
    // Per-height anti-equivocation guard for Diamond Auth signatures.
    // A signer only signs one candidate hash per height while running.
    let signed_heights: Arc<Mutex<HashMap<u64, Hash32>>> = Arc::new(Mutex::new(HashMap::new()));
    loop {
        let (mut stream, addr) = listener.accept().await?;
        let ledger = ledger.clone();
        let mempool = mempool.clone();
        let network = network.clone();
        let limiter = limiter.clone();
        let decoy_cache = decoy_cache.clone();
        let rpc_secret = rpc_secret.clone();
        let allow_remote_rpc = allow_remote_rpc;
        let signed_heights = signed_heights.clone();
        tokio::spawn(async move {
            let is_remote = !addr.ip().is_loopback();
            let mut len_buf = [0u8; 4];
            if let Err(err) = stream.read_exact(&mut len_buf).await {
                if is_remote {
                    eprintln!("[StarForge] rpc read len failed from {addr}: {err}");
                }
                return;
            }
            let len = u32::from_le_bytes(len_buf) as usize;
            if len == 0 || len > MAX_RPC_BYTES {
                if is_remote {
                    eprintln!(
                        "[StarForge] rpc reject oversize request from {addr}: len={len} max={MAX_RPC_BYTES}"
                    );
                }
                return;
            }
            let mut buf = vec![0u8; len];
            if let Err(err) = stream.read_exact(&mut buf).await {
                if is_remote {
                    eprintln!("[StarForge] rpc read body failed from {addr}: {err}");
                }
                return;
            }
            let request = match bincode::decode_from_slice::<WalletRequest, _>(
                &buf,
                bincode::config::standard().with_limit::<4194304>(),
            ) {
                Ok((req, _)) => req,
                Err(err) => {
                    if is_remote {
                        eprintln!(
                            "[StarForge] rpc decode failed from {addr}: len={len} err={err}"
                        );
                    }
                    return;
                }
            };
            // Keep normal wallet RPC local-only unless explicitly enabled.
            // Diamond auth signing still needs to be reachable by peer nodes.
            if is_remote
                && !allow_remote_rpc
                && !matches!(&request, WalletRequest::SignDiamondCert(_) | WalletRequest::GetForgeElection(_))
            {
                eprintln!("[StarForge] rpc rejected remote request from {addr}");
                return;
            }
            let response = match request {
                WalletRequest::GetTip => {
                    let height = match ledger.lock() {
                        Ok(l) => l.height().unwrap_or(0),
                        Err(_) => 0,
                    };
                    WalletResponse::Tip(height)
                }
                WalletRequest::GetBlock(h) => {
                    if !limiter.allow(addr.ip(), RATE_LIMIT_BLOCKS_PER_SEC, now_ms()) {
                        WalletResponse::Block(None)
                    } else {
                        let block = match ledger.lock() {
                            Ok(l) => l.get_block(h).unwrap_or(None),
                            Err(_) => None,
                        };
                        WalletResponse::Block(block)
                    }
                }
                WalletRequest::GetBlocks(start, limit) => {
                    if !limiter.allow(addr.ip(), RATE_LIMIT_BLOCKS_PER_SEC, now_ms()) {
                        WalletResponse::Blocks(Vec::new())
                    } else {
                        let mut blocks = Vec::new();
                        let mut h = start;
                        let max = limit.min(MAX_RPC_BLOCKS);
                        if let Ok(ledger) = ledger.lock() {
                            for _ in 0..max {
                                match ledger.get_block(h).ok().flatten() {
                                    Some(block) => {
                                        blocks.push(block);
                                        h = h.saturating_add(1);
                                    }
                                    None => break,
                                }
                            }
                        }
                        WalletResponse::Blocks(blocks)
                    }
                }
                WalletRequest::SubmitTx(tx) => {
                    let allowed = limiter.allow(addr.ip(), RATE_LIMIT_SUBMIT_PER_SEC, now_ms());
                    if !allowed {
                        eprintln!("[StarForge] submit tx rejected: rate limit");
                        WalletResponse::SubmitResult(false)
                    } else {
                        let verify = match ledger.lock() {
                            Ok(l) => l.verify_tx(&tx),
                            Err(_) => Err("ledger lock poisoned".to_string()),
                        };
                        let ok = verify.is_ok();
                        if let Err(e) = verify {
                            eprintln!("[StarForge] submit tx rejected: {e}");
                        }
                        let mut accepted = false;
                        let mut broadcast_tx = None;
                        if ok {
                            {
                                if let Ok(mut mp) = mempool.lock() {
                                    if mempool_has_conflict(&mp, &tx) {
                                        eprintln!("[StarForge] submit tx rejected: key image conflict in mempool");
                                    } else {
                                        if mp.len() >= MAX_MEMPOOL_TX {
                                            evict_one(&mut mp);
                                        }
                                        if mp.len() < MAX_MEMPOOL_TX {
                                            mp.push(MempoolEntry {
                                                tx: tx.clone(),
                                                received_ms: now_ms(),
                                            });
                                            accepted = true;
                                            broadcast_tx = Some(tx);
                                        }
                                    }
                                }
                            }
                        }
                        if let Some(tx) = broadcast_tx {
                            let _ = network.try_send(Message::Tx(tx));
                        }
                        WalletResponse::SubmitResult(accepted)
                    }
                }
                WalletRequest::GetDecoys(count) => {
                    let allowed = limiter.allow(addr.ip(), RATE_LIMIT_DECOYS_PER_SEC, now_ms());
                    if !allowed {
                        WalletResponse::Decoys(Vec::new())
                    } else {
                        let count = (count as usize)
                            .clamp(knox_types::MIN_DECOY_COUNT, knox_types::MAX_DECOY_COUNT);
                        if count == 0 {
                            WalletResponse::Decoys(Vec::new())
                        } else {
                            let mut seed = [0u8; 32];
                            if fill_os_random(&mut seed).is_err() {
                                WalletResponse::Decoys(Vec::new())
                            } else {
                                let mut prng = LocalPrng::new(seed);
                                let mut candidates = Vec::new();
                                if let Ok(ledger) = ledger.lock() {
                                    let tip = ledger.height().unwrap_or(0);
                                    candidates = decoy_cache.get_or_rebuild(&ledger, tip, now_ms());
                                }
                                let decoys = weighted_sample_decoys(&candidates, count, &mut prng);
                                WalletResponse::Decoys(decoys)
                            }
                        }
                    }
                }
                WalletRequest::GetNetworkTelemetry => {
                    let telemetry = match ledger.lock() {
                        Ok(l) => {
                            l.network_telemetry(now_ms())
                                .unwrap_or(knox_types::NetworkTelemetry {
                                    tip_height: 0,
                                    tip_hash: Hash32::ZERO,
                                    total_hardening: 0,
                                    active_miners_recent: 0,
                                    current_difficulty_bits: 0,
                                    tip_proposer_streak: 0,
                                    next_streak_if_same_proposer: 0,
                                    streak_bonus_ppm: 0,
                                    surge_phase: "unknown".to_string(),
                                    surge_countdown_ms: 0,
                                    surge_block_index: 0,
                                    surge_blocks_remaining: 0,
                                })
                        }
                        Err(_) => knox_types::NetworkTelemetry {
                            tip_height: 0,
                            tip_hash: Hash32::ZERO,
                            total_hardening: 0,
                            active_miners_recent: 0,
                            current_difficulty_bits: 0,
                            tip_proposer_streak: 0,
                            next_streak_if_same_proposer: 0,
                            streak_bonus_ppm: 0,
                            surge_phase: "unknown".to_string(),
                            surge_countdown_ms: 0,
                            surge_block_index: 0,
                            surge_blocks_remaining: 0,
                        },
                    };
                    WalletResponse::NetworkTelemetry(telemetry)
                }
                WalletRequest::GetFibWall(limit) => {
                    let wall = match ledger.lock() {
                        Ok(l) => l
                            .fibonacci_wall((limit as usize).max(1))
                            .unwrap_or_else(|_| Vec::new()),
                        Err(_) => Vec::new(),
                    };
                    WalletResponse::FibWall(wall)
                }
                WalletRequest::SignDiamondCert(block) => {
                    if is_remote {
                        eprintln!(
                            "[StarForge] diamond sign rpc from {} h={} r={} txs={}",
                            addr,
                            block.header.height,
                            block.header.round,
                            block.txs.len()
                        );
                    }
                    let signer_msg = hash_header_for_signing(&block.header);
                    let verify = match ledger.lock() {
                        Ok(l) => l.verify_block_for_diamond_auth(&block),
                        Err(_) => Err("ledger lock poisoned".to_string()),
                    };
                    match verify {
                        Ok(()) => {
                            let lock_state = match signed_heights.lock() {
                                Ok(mut signed) => {
                                    // Best-effort pruning to cap memory growth.
                                    let floor = block.header.height.saturating_sub(256);
                                    signed.retain(|h, _| *h >= floor);
                                    match signed.get(&block.header.height) {
                                        Some(existing) if existing != &signer_msg => Some(false),
                                        Some(_) => Some(true),
                                        None => {
                                            signed.insert(block.header.height, signer_msg.clone());
                                            Some(true)
                                        }
                                    }
                                }
                                Err(_) => None,
                            };
                            match lock_state {
                                Some(true) => {
                                    let sig = sign_consensus(&rpc_secret, &signer_msg.0).ok();
                                    if sig.is_some() {
                                        eprintln!(
                                            "[StarForge] diamond sign accepted h={} r={}",
                                            block.header.height, block.header.round
                                        );
                                    }
                                    WalletResponse::DiamondCert(sig)
                                }
                                Some(false) => {
                                    eprintln!(
                                        "[StarForge] diamond sign rejected h={} r={}: already signed different candidate at this height",
                                        block.header.height, block.header.round
                                    );
                                    WalletResponse::DiamondCert(None)
                                }
                                None => {
                                    eprintln!(
                                        "[StarForge] diamond sign rejected h={} r={}: signer lock poisoned",
                                        block.header.height, block.header.round
                                    );
                                    WalletResponse::DiamondCert(None)
                                }
                            }
                        }
                        Err(err) => {
                            eprintln!(
                                "[StarForge] diamond sign rejected h={} r={}: {}",
                                block.header.height, block.header.round, err
                            );
                            WalletResponse::DiamondCert(None)
                        }
                    }
                }
                WalletRequest::GetForgeElection(height) => {
                    let result = match ledger.lock() {
                        Ok(l) => forge_election_for_height(&l, height),
                        Err(_) => None,
                    };
                    match result {
                        Some(r) => WalletResponse::ForgeElection(r),
                        None => WalletResponse::ForgeElection(knox_types::ForgeElectionResult {
                            height,
                            leader: [0u8; 32],
                            active_miners: 0,
                            is_leader: false,
                        }),
                    }
                }
            };
            let bytes = match bincode::encode_to_vec(response, bincode::config::standard()) {
                Ok(v) => v,
                Err(_) => return,
            };
            let mut out = Vec::with_capacity(4 + bytes.len());
            out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            out.extend_from_slice(&bytes);
            if let Err(err) = stream.write_all(&out).await {
                if is_remote {
                    eprintln!("[StarForge] rpc write response failed to {addr}: {err}");
                }
            }
        });
    }
}

impl DecoyCache {
    fn get_or_rebuild(
        &self,
        ledger: &Ledger,
        tip: u64,
        now_ms: u64,
    ) -> Vec<(knox_types::RingMember, u32)> {
        let Ok(mut state) = self.inner.lock() else {
            return Vec::new();
        };
        let stale = now_ms.saturating_sub(state.built_ms) > DECOY_CACHE_TTL_MS;
        if stale || state.tip != tip {
            state.candidates = collect_decoy_candidates_indexed(ledger, tip);
            state.tip = tip;
            state.built_ms = now_ms;
        }
        state.candidates.clone()
    }
}

fn collect_decoy_candidates_indexed(
    ledger: &Ledger,
    tip: u64,
) -> Vec<(knox_types::RingMember, u32)> {
    let newest_allowed = tip.saturating_sub(knox_types::MIN_DECOY_AGE_BLOCKS);
    let window = knox_types::DECOY_SAMPLE_WINDOW_BLOCKS.min(MAX_DECOY_SCAN_BLOCKS);
    let mut candidates = Vec::new();
    let members =
        match ledger.decoy_members_window(tip, window, newest_allowed, MAX_DECOY_CANDIDATES) {
            Ok(v) => v,
            Err(_) => return Vec::new(),
        };
    for (member, h) in members {
        let age = tip.saturating_sub(h);
        let weight = decoy_weight(age);
        candidates.push((member, weight));
    }
    candidates
}

fn now_ms() -> u64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    now.as_millis() as u64
}

fn decoy_weight(age_blocks: u64) -> u32 {
    if age_blocks < 30 {
        1
    } else if age_blocks < 720 {
        10
    } else if age_blocks < 5_000 {
        7
    } else {
        4
    }
}

fn weighted_sample_decoys(
    candidates: &[(knox_types::RingMember, u32)],
    count: usize,
    prng: &mut LocalPrng,
) -> Vec<knox_types::RingMember> {
    if candidates.is_empty() || count == 0 {
        return Vec::new();
    }
    let mut scored = Vec::with_capacity(candidates.len());
    for (member, weight) in candidates {
        if *weight == 0 {
            continue;
        }
        let u = random_unit_f64(prng);
        let key = -u.ln() / (*weight as f64);
        scored.push((key, member.clone()));
    }
    scored.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));
    scored
        .into_iter()
        .take(count)
        .map(|(_, member)| member)
        .collect()
}

fn random_unit_f64(prng: &mut LocalPrng) -> f64 {
    let mut bytes = [0u8; 8];
    prng.fill_bytes(&mut bytes);
    let v = u64::from_le_bytes(bytes);
    let unit = ((v >> 11) as f64) / ((1u64 << 53) as f64);
    if unit <= 0.0 {
        f64::EPSILON
    } else if unit >= 1.0 {
        1.0 - f64::EPSILON
    } else {
        unit
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_member(id: u8) -> knox_types::RingMember {
        knox_types::RingMember {
            out_ref: knox_types::OutputRef {
                tx: knox_types::Hash32([id; 32]),
                index: id as u16,
            },
            one_time_pub: [id; 32],
            commitment: [id.wrapping_add(1); 32],
            lattice_spend_pub: Vec::new(),
        }
    }

    #[test]
    fn weighted_sampler_respects_requested_count() {
        let mut candidates = Vec::new();
        for i in 0..64u8 {
            candidates.push((dummy_member(i), 5));
        }
        let mut prng = LocalPrng::new([3u8; 32]);
        let out = weighted_sample_decoys(&candidates, 31, &mut prng);
        assert_eq!(out.len(), 31);
    }

    #[test]
    fn weighted_sampler_handles_empty() {
        let mut prng = LocalPrng::new([1u8; 32]);
        let out = weighted_sample_decoys(&[], 8, &mut prng);
        assert!(out.is_empty());
    }
}

fn slash_root(slashes: &[SlashEvidence]) -> Hash32 {
    if slashes.is_empty() {
        return Hash32::ZERO;
    }
    let leaves = slashes.iter().map(slash_leaf_hash).collect::<Vec<_>>();
    knox_types::merkle_root(&leaves)
}

fn slash_leaf_hash(ev: &SlashEvidence) -> Hash32 {
    let mut data = Vec::new();
    data.extend_from_slice(b"knox-slash-v1");
    for vote in [&ev.vote_a, &ev.vote_b] {
        data.extend_from_slice(&vote.height.to_le_bytes());
        data.extend_from_slice(&vote.round.to_le_bytes());
        data.extend_from_slice(&vote.block_hash.0);
        data.extend_from_slice(&vote.voter.to_le_bytes());
        data.extend_from_slice(&(vote.sig.len() as u32).to_le_bytes());
        data.extend_from_slice(&vote.sig);
    }
    hash_bytes(&data)
}

fn hash_header_for_signing(header: &BlockHeader) -> Hash32 {
    let mut data = Vec::new();
    data.extend_from_slice(b"knox-header-v1");
    data.extend_from_slice(&header.version.to_le_bytes());
    data.extend_from_slice(&header.height.to_le_bytes());
    data.extend_from_slice(&header.round.to_le_bytes());
    data.extend_from_slice(&header.prev.0);
    data.extend_from_slice(&header.tx_root.0);
    data.extend_from_slice(&header.slash_root.0);
    data.extend_from_slice(&header.state_root.0);
    data.extend_from_slice(&header.timestamp_ms.to_le_bytes());
    data.extend_from_slice(&header.proposer);
    if let Some(qc) = &header.qc {
        data.push(1);
        data.extend_from_slice(&qc.height.to_le_bytes());
        data.extend_from_slice(&qc.round.to_le_bytes());
        data.extend_from_slice(&qc.block_hash.0);
        data.extend_from_slice(&(qc.sigs.len() as u32).to_le_bytes());
        for sig in &qc.sigs {
            data.extend_from_slice(&sig.validator.to_le_bytes());
            data.extend_from_slice(&(sig.sig.len() as u32).to_le_bytes());
            data.extend_from_slice(&sig.sig);
        }
    } else {
        data.push(0);
    }
    hash_bytes(&data)
}

fn hash_header_for_link(header: &BlockHeader) -> Hash32 {
    let mut h = header.clone();
    // Chain linkage must be independent of locally assembled QC signatures.
    h.qc = None;
    hash_header_for_signing(&h)
}

fn hex_hash(hash: Hash32) -> String {
    let mut out = String::with_capacity(64);
    for b in hash.0 {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{:02x}", b);
    }
    out
}

impl RateLimiter {
    fn allow(&self, ip: IpAddr, limit_per_sec: u32, now_ms: u64) -> bool {
        let Ok(mut map) = self.inner.lock() else {
            return false;
        };
        let entry = map.entry(ip).or_insert(RateState {
            window_start_ms: now_ms,
            count: 0,
        });
        if now_ms.saturating_sub(entry.window_start_ms) >= 1000 {
            entry.window_start_ms = now_ms;
            entry.count = 0;
        }
        if entry.count >= limit_per_sec {
            return false;
        }
        entry.count += 1;
        true
    }
}

fn evict_one(mempool: &mut Vec<MempoolEntry>) {
    if mempool.is_empty() {
        return;
    }
    let mut min_idx = 0;
    let mut min_fee = mempool[0].tx.fee;
    let mut oldest = mempool[0].received_ms;
    for (idx, entry) in mempool.iter().enumerate().skip(1) {
        if entry.tx.fee < min_fee || (entry.tx.fee == min_fee && entry.received_ms < oldest) {
            min_fee = entry.tx.fee;
            oldest = entry.received_ms;
            min_idx = idx;
        }
    }
    mempool.remove(min_idx);
}

fn mempool_has_conflict(mempool: &[MempoolEntry], tx: &Transaction) -> bool {
    let mut images = HashSet::new();
    for input in &tx.inputs {
        images.insert(input.key_image);
    }
    for entry in mempool {
        for input in &entry.tx.inputs {
            if images.contains(&input.key_image) {
                return true;
            }
        }
    }
    false
}

fn take_mempool(mempool: &Arc<Mutex<Vec<MempoolEntry>>>, max: usize) -> Vec<Transaction> {
    let Ok(mut mp) = mempool.lock() else {
        return Vec::new();
    };
    if mp.is_empty() {
        return Vec::new();
    }
    mp.sort_by(|a, b| {
        b.tx.fee
            .cmp(&a.tx.fee)
            .then_with(|| a.received_ms.cmp(&b.received_ms))
    });
    let take = mp.len().min(max);
    let entries = mp.drain(..take).collect::<Vec<_>>();
    entries.into_iter().map(|e| e.tx).collect()
}

fn take_slashes(pool: &Arc<Mutex<Vec<SlashEvidence>>>, max: usize) -> Vec<SlashEvidence> {
    let Ok(mut p) = pool.lock() else {
        return Vec::new();
    };
    if p.is_empty() {
        return Vec::new();
    }
    let take = p.len().min(max);
    p.drain(..take).collect::<Vec<_>>()
}

fn build_coinbase(
    height: u64,
    streak: u64,
    miner: &Address,
    treasury: &Address,
    dev: &Address,
    premine: &Address,
    txs: &[Transaction],
) -> Result<Transaction, String> {
    let fees: u64 = txs.iter().map(|t| t.fee).sum();
    let split = coinbase_split(height, fees, streak);

    let mut recipients: Vec<(&Address, u64)> = Vec::new();
    recipients.push((miner, split.miner));
    if split.treasury > 0 {
        recipients.push((treasury, split.treasury));
    }
    if split.dev > 0 {
        recipients.push((dev, split.dev));
    }
    if split.premine > 0 {
        recipients.push((premine, split.premine));
    }

    let commitment_key = LatticeCommitmentKey::derive();
    let private_outputs = private_coinbase_outputs(&commitment_key, split)?;
    if private_outputs.len() != recipients.len() {
        return Err("coinbase lattice output count mismatch".to_string());
    }

    let mut outputs = Vec::with_capacity(recipients.len());
    let mut amounts = Vec::with_capacity(recipients.len());
    let mut lattice_outputs = Vec::with_capacity(outputs.len());
    let mut openings = Vec::with_capacity(outputs.len());
    let enc_level = tx_hardening_level(height);
    for (idx, (recipient, amount)) in recipients.iter().enumerate() {
        let private = &private_outputs[idx];
        if private.amount != *amount {
            return Err("coinbase lattice amount mismatch".to_string());
        }

        let recipient_pub = lattice_public_from_serialized(&recipient.lattice_spend_pub)?;
        let eph_secret = knox_lattice::Poly::random_short_checked()?;
        let stealth = knox_lattice::stealth::send_to_stealth_with_ephemeral(
            &recipient_pub,
            &recipient_pub,
            &eph_secret,
        );
        let shared_bytes = lattice_shared_seed(&stealth.one_time_public, &stealth.ephemeral_public);
        let blind = blind_bytes_from_opening(&private.opening);
        let (enc_amount, enc_blind) =
            encrypt_amount_with_level(&shared_bytes, *amount, &blind, enc_level);

        let lattice_out = LatticeOutput {
            stealth_address: stealth.one_time_public.clone(),
            ephemeral_public: stealth.ephemeral_public.clone(),
            commitment: private.commitment.clone(),
            range_proof: private.range_proof.clone(),
            enc_amount,
            enc_blind,
            enc_level,
        };
        let tx_out = knox_types::TxOut {
            one_time_pub: compatibility_pubkey_tag(
                b"knox-wallet-one-time-v2",
                &stealth.one_time_public.p.to_bytes(),
            ),
            tx_pub: compatibility_pubkey_tag(
                b"knox-wallet-ephemeral-v2",
                &stealth.ephemeral_public.p.to_bytes(),
            ),
            commitment: lattice_commitment_digest(&lattice_out.commitment),
            lattice_spend_pub: stealth.one_time_public.p.to_bytes(),
            enc_amount,
            enc_blind,
            enc_level,
            memo: if idx == 0 {
                miner_operator_identity(recipient)
            } else {
                [0u8; 32]
            },
            range_proof: lattice_range_placeholder(&lattice_out.range_proof),
        };
        outputs.push(tx_out);
        amounts.push(*amount);
        lattice_outputs.push(lattice_out);
        openings.push(private.opening.clone());
    }

    let payload = LatticeCoinbasePayload {
        amounts: amounts.clone(),
        outputs: lattice_outputs,
        openings,
    };
    let extra = encode_coinbase_payload(&payload)?;

    Ok(Transaction {
        version: 3,
        coinbase: true,
        coinbase_proof: Vec::new(),
        inputs: Vec::new(),
        outputs,
        fee: 0,
        extra,
    })
}

fn miner_operator_identity(addr: &Address) -> [u8; 32] {
    let mut data = Vec::with_capacity(26 + addr.view.len());
    data.extend_from_slice(b"knox-miner-operator-v1");
    data.extend_from_slice(&addr.view);
    hash_bytes(&data).0
}

fn lattice_public_from_serialized(bytes: &[u8]) -> Result<LatticePublicKey, String> {
    let poly = knox_lattice::Poly::from_bytes(bytes)
        .map_err(|_| "invalid lattice public key bytes".to_string())?;
    Ok(LatticePublicKey { p: poly })
}

fn lattice_commitment_digest(commitment: &LatticeCommitment) -> [u8; 32] {
    hash_bytes(&commitment.to_bytes()).0
}

fn lattice_shared_seed(
    one_time_public: &LatticePublicKey,
    ephemeral_public: &LatticePublicKey,
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"knox-lattice-shared-seed-v2");
    h.update(&one_time_public.p.to_bytes());
    h.update(&ephemeral_public.p.to_bytes());
    *h.finalize().as_bytes()
}

fn compatibility_pubkey_tag(domain: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(domain);
    h.update(payload);
    *h.finalize().as_bytes()
}

fn blind_bytes_from_opening(opening: &knox_lattice::CommitmentOpening) -> [u8; 32] {
    let mut out = [0u8; 32];
    let r_bytes = opening.randomness.to_bytes();
    out.copy_from_slice(&blake3::hash(&r_bytes).as_bytes()[..32]);
    out
}

fn proposer_streak_for_height(
    ledger: &Ledger,
    height: u64,
    proposer: [u8; 32],
    current_timestamp_ms: u64,
) -> u64 {
    if height == 0 {
        return 1;
    }
    let mut streak = 1u64;
    let mut h = height.saturating_sub(1);
    let mut prev_ts = current_timestamp_ms;
    loop {
        let Some(block) = ledger.get_block(h).ok().flatten() else {
            break;
        };
        if block.header.proposer != proposer {
            break;
        }
        if prev_ts.saturating_sub(block.header.timestamp_ms) > 3 * knox_types::TARGET_BLOCK_TIME_MS {
            break;
        }
        streak = streak.saturating_add(1);
        if streak >= knox_types::STREAK_MAX_COUNT || h == 0 {
            break;
        }
        prev_ts = block.header.timestamp_ms;
        h = h.saturating_sub(1);
    }
    streak
}

fn lattice_range_placeholder(proof: &knox_lattice::LatticeRangeProof) -> knox_types::RangeProof {
    let encoded = bincode::encode_to_vec(proof, bincode::config::standard()).unwrap_or_default();
    let derive = |tag: &[u8]| -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(b"knox-range-compat-v2");
        h.update(tag);
        h.update(&encoded);
        *h.finalize().as_bytes()
    };
    let mut l_vec = Vec::new();
    let mut r_vec = Vec::new();
    for idx in 0..4u8 {
        l_vec.push(derive(&[b'l', idx]));
        r_vec.push(derive(&[b'r', idx]));
    }
    knox_types::RangeProof {
        a: derive(b"a"),
        s: derive(b"s"),
        t1: derive(b"t1"),
        t2: derive(b"t2"),
        tau_x: derive(b"tau_x"),
        mu: derive(b"mu"),
        t_hat: derive(b"t_hat"),
        ip_proof: knox_types::InnerProductProof {
            l_vec,
            r_vec,
            a: derive(b"ipa"),
            b: derive(b"ipb"),
        },
    }
}
