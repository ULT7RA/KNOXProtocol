use knox_consensus::{ConsensusConfig, ConsensusMessage, PulsarBft, ValidatorSet};
use knox_crypto::os_random_bytes;
use knox_lattice::{
    consensus_public_key_id, consensus_secret_from_seed, sign_consensus,
    coinbase_split, encode_coinbase_payload, encrypt_amount_with_level,
    mine_block_proof_with_profile, private_coinbase_outputs, tx_hardening_level,
    LatticeCoinbasePayload, LatticeCommitment, LatticeCommitmentKey, LatticeOutput,
    LatticePublicKey, LatticeSecretKey, MiningProfile,
};
use knox_ledger::Ledger;
use knox_p2p::{Message, Network, NetworkConfig, NetworkSender};
use knox_types::{
    hash_bytes, merkle_root, Address, Block, BlockHeader, Hash32, SlashEvidence, Transaction,
    WalletRequest, WalletResponse,
};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::{interval, Duration};

const MAX_MEMPOOL_TX: usize = 50_000;
const MAX_RPC_BYTES: usize = 2 * 1024 * 1024;
const MAX_RPC_BLOCKS: u32 = 200;
const RATE_LIMIT_SUBMIT_PER_SEC: u32 = 10;
const RATE_LIMIT_BLOCKS_PER_SEC: u32 = 5;
const RATE_LIMIT_DECOYS_PER_SEC: u32 = 5;
const MAX_SLASHES_PER_BLOCK: usize = 128;
const MAX_DECOY_SCAN_BLOCKS: u64 = 5_000;
const MAX_DECOY_CANDIDATES: usize = 200_000;
const DECOY_CACHE_TTL_MS: u64 = 10_000;

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
}

#[derive(Clone)]
struct MempoolEntry {
    tx: Transaction,
    received_ms: u64,
}

pub struct Node {
    ledger: Arc<Mutex<Ledger>>,
    consensus: Arc<Mutex<PulsarBft>>,
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
    round_tick_ms: u64,
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
                os_random_bytes(&mut seed)?;
                let secret = consensus_secret_from_seed(&seed);
                let public = knox_lattice::consensus_public_from_secret(&secret);
                (secret, public)
            }
        };
        ledger.set_validators(cfg.validators.validators.clone());
        let mut consensus =
            PulsarBft::new(cfg.consensus, cfg.validators, secret.clone(), public.clone());
        let tip = ledger.height().unwrap_or(0);
        let has_tip_block = ledger.get_block(tip).unwrap_or(None).is_some();
        let next_height = if has_tip_block {
            tip.saturating_add(1)
        } else {
            0
        };
        consensus.set_height(next_height);
        if let Ok(list) = ledger.slashed_list() {
            consensus.apply_slashed(&list);
        }
        let mut net_config = cfg.network.clone();
        net_config.lattice_public = Some(public.p.to_bytes());
        net_config.lattice_secret = Some(secret.s.to_bytes());
        let network = Network::bind(net_config)
            .await
            .map_err(|e| e.to_string())?;

        Ok(Self {
            ledger: Arc::new(Mutex::new(ledger)),
            consensus: Arc::new(Mutex::new(consensus)),
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
            round_tick_ms,
        })
    }

    pub async fn run(self) {
        let rknox_ledger = self.ledger.clone();
        let rpc_mempool = self.mempool.clone();
        let rpc_network = self.network.sender();
        let rpc_bind = self.rpc_bind.clone();
        if rpc_bind != "-" {
            tokio::spawn(async move {
                let _ = run_rpc(rpc_bind, rknox_ledger, rpc_mempool, rpc_network).await;
            });
        }

        let mut ticker = interval(Duration::from_millis(self.round_tick_ms));
        let mut network = self.network;
        let consensus = self.consensus.clone();
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
        let mut last_propose_ms = 0u64;
        let min_peers_for_mining = std::env::var("KNOX_MIN_PEERS_FOR_MINING")
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .unwrap_or(1)
            .max(1); // Never allow mining with 0 peers
        let mut last_peer_gate_log_ms = 0u64;
        let mut last_backend_line = String::new();

        loop {
            tokio::select! {
                Some(env) = network.inbound.recv() => {
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
                                    network.send(Message::Tx(tx)).await;
                                }
                            }
                        }
                        Message::Block(block) => {
                            if verify_block(&block, &ledger) {
                                if let Ok(mut con) = consensus.lock() {
                                    let out = con.on_message(ConsensusMessage::Proposal(block.clone()));
                                    handle_consensus_output(out, &ledger, &mut network, &slash_pool).await;
                                }
                            } else if let Ok(l) = ledger.lock() {
                                if let Err(err) = l.verify_block(&block) {
                                    eprintln!(
                                        "[knox-node] reject proposal h={} r={}: {}",
                                        block.header.height, block.header.round, err
                                    );
                                }
                            }
                        }
                        Message::Vote(vote) => {
                            if let Ok(mut con) = consensus.lock() {
                                let out = con.on_message(ConsensusMessage::Vote(vote));
                                handle_consensus_output(out, &ledger, &mut network, &slash_pool).await;
                            }
                        }
                        Message::TimeoutVote(vote) => {
                            if let Ok(mut con) = consensus.lock() {
                                let out = con.on_message(ConsensusMessage::TimeoutVote(vote));
                                handle_consensus_output(out, &ledger, &mut network, &slash_pool).await;
                            }
                        }
                        Message::TimeoutCertificate(tc) => {
                            if let Ok(mut con) = consensus.lock() {
                                let out = con.on_message(ConsensusMessage::TimeoutCertificate(tc));
                                handle_consensus_output(out, &ledger, &mut network, &slash_pool).await;
                            }
                        }
                        Message::Slash(ev) => {
                            if let Ok(mut con) = consensus.lock() {
                                let valid = con.verify_slash_evidence(&ev);
                                let out = con.on_message(ConsensusMessage::Slash(ev.clone()));
                                handle_consensus_output(out, &ledger, &mut network, &slash_pool).await;
                                if valid {
                                    if let Ok(mut pool) = slash_pool.lock() {
                                        pool.push(ev);
                                    }
                                }
                            }
                        }
                        Message::Ping(nonce) => {
                            network.send(Message::Pong(nonce)).await;
                        }
                        _ => {}
                    }
                }
                _ = ticker.tick() => {
                    let now = now_ms();
                    let (tick_out, height, round, is_leader) = {
                        let Ok(mut con) = consensus.lock() else {
                            continue;
                        };
                        let out = con.on_tick(now);
                        let height = con.height();
                        let round = con.round();
                        let is_leader = con.is_leader(height, round);
                        (out, height, round, is_leader)
                    };
                    handle_consensus_output(tick_out, &ledger, &mut network, &slash_pool).await;
                    if !mining_enabled {
                        continue;
                    }
                    if min_peers_for_mining > 0 {
                        let active_peers = network.active_peer_count();
                        if active_peers < min_peers_for_mining {
                            if now.saturating_sub(last_peer_gate_log_ms) > 10_000 {
                                eprintln!(
                                    "[knox-node] mining paused: active peers {} below required {}",
                                    active_peers, min_peers_for_mining
                                );
                                last_peer_gate_log_ms = now;
                            }
                            continue;
                        }
                    }
                    if is_leader {
                        let (proposer_streak, mining_rules) = match ledger.lock() {
                            Ok(l) => {
                                let streak = proposer_streak_for_height(&l, height, proposer_id);
                                let rules = match l.mining_rules_for_height(height, now) {
                                    Ok(r) => r,
                                    Err(err) => {
                                        eprintln!("[knox-node] mining rules failed: {}", err);
                                        continue;
                                    }
                                };
                                (streak, rules)
                            }
                            Err(_) => continue,
                        };
                        if !mining_rules.allow_proposal {
                            continue;
                        }
                        let propose_interval_ms = if mining_rules.min_spacing_ms == 0 {
                            0
                        } else {
                            knox_types::TARGET_BLOCK_TIME_MS
                        };
                        if now.saturating_sub(last_propose_ms) < propose_interval_ms {
                            continue;
                        }
                        last_propose_ms = now;
                        let mut txs = take_mempool(&mempool, knox_types::MAX_BLOCK_TX);
                        let slashes = take_slashes(&slash_pool, MAX_SLASHES_PER_BLOCK);
                        eprintln!(
                            "[knox-node] propose attempt h={} r={} txs={} slashes={}",
                            height,
                            round,
                            txs.len(),
                            slashes.len()
                        );
                        let coinbase = match build_coinbase(height, proposer_streak, &miner_address, &treasury_address, &dev_address, &premine_address, &txs) {
                            Ok(cb) => cb,
                            Err(err) => {
                                eprintln!("[knox-node] coinbase build failed: {}", err);
                                continue;
                            }
                        };
                        txs.insert(0, coinbase);
                        let prev_block = ledger
                            .lock()
                            .ok()
                            .and_then(|l| l.get_block(height.saturating_sub(1)).ok().flatten());
                        let prev = prev_block
                            .as_ref()
                            .map(|b| hash_header_for_link(&b.header))
                            .unwrap_or(Hash32::ZERO);
                        let tx_hashes = txs
                            .iter()
                            .filter_map(|t| bincode::encode_to_vec(t, bincode::config::standard()).ok().map(|v| hash_bytes(&v)))
                            .collect::<Vec<_>>();
                        let tx_root = merkle_root(&tx_hashes);
                        let slash_root = slash_root(&slashes);
                        let state_root = knox_types::compute_state_root(height, prev, tx_root, slash_root);
                        let ts_now = now_ms();
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
                        let header = BlockHeader {
                            version: 1,
                            height,
                            round,
                            prev,
                            tx_root,
                            slash_root,
                            state_root,
                            timestamp_ms: ts_now,
                            proposer: proposer_id,
                            qc: None,
                        };
                        let hash = hash_header_for_signing(&header);
                        let sig = match sign_consensus(&secret, &hash.0) {
                            Ok(sig) => sig,
                            Err(err) => {
                                eprintln!("[knox-node] proposer sign failed: {}", err);
                                continue;
                            }
                        };
                        let mut worker_id_bytes = [0u8; 8];
                        worker_id_bytes.copy_from_slice(&proposer_id[..8]);
                        let worker_id = u64::from_le_bytes(worker_id_bytes);
                        let (lattice_proof, backend_status) = match mine_block_proof_with_profile(
                            &header,
                            worker_id,
                            mining_rules.expected_difficulty_bits,
                            &mining_profile,
                        ) {
                            Ok(v) => v,
                            Err(err) => {
                                eprintln!("[knox-node] mining_runtime_error {}", err);
                                tokio::time::sleep(Duration::from_millis(1200)).await;
                                continue;
                            }
                        };
                        let backend_line = backend_status.to_log_line();
                        if backend_line != last_backend_line {
                            eprintln!("[knox-node] mining_runtime {}", backend_line);
                            last_backend_line = backend_line;
                        }
                        let block = Block {
                            header,
                            txs,
                            slashes,
                            proposer_sig: sig,
                            lattice_proof,
                        };
                        let (out, local_out, local_votes) = {
                            let Ok(mut con) = consensus.lock() else {
                                continue;
                            };
                            let out = con.try_propose(block.clone());
                            let local_out = con.on_message(ConsensusMessage::Proposal(block.clone()));
                            let mut votes = Vec::new();
                            for msg in &local_out.messages {
                                if let ConsensusMessage::Vote(vote) = msg {
                                    votes.push(vote.clone());
                                }
                            }
                            (out, local_out, votes)
                        };
                        handle_consensus_output(out, &ledger, &mut network, &slash_pool).await;
                        handle_consensus_output(local_out, &ledger, &mut network, &slash_pool).await;
                        for vote in local_votes {
                            if let Ok(mut con) = consensus.lock() {
                                let out = con.on_message(ConsensusMessage::Vote(vote));
                                handle_consensus_output(out, &ledger, &mut network, &slash_pool).await;
                            }
                        }
                        network.send(Message::Block(block)).await;
                    }
                }
            }
        }
    }
}

async fn handle_consensus_output(
    out: knox_consensus::ConsensusOutput,
    ledger: &Arc<Mutex<Ledger>>,
    network: &mut Network,
    slash_pool: &Arc<Mutex<Vec<SlashEvidence>>>,
) {
    for msg in out.messages {
        match msg {
            ConsensusMessage::Proposal(block) => {
                network.send(Message::Block(block)).await;
            }
            ConsensusMessage::Vote(vote) => {
                network.send(Message::Vote(vote)).await;
            }
            ConsensusMessage::TimeoutVote(vote) => {
                network.send(Message::TimeoutVote(vote)).await;
            }
            ConsensusMessage::TimeoutCertificate(tc) => {
                network.send(Message::TimeoutCertificate(tc)).await;
            }
            ConsensusMessage::Slash(ev) => {
                network.send(Message::Slash(ev.clone())).await;
                if let Ok(mut pool) = slash_pool.lock() {
                    pool.push(ev);
                    if pool.len() > 10_000 {
                        let drain = pool.len().saturating_sub(10_000);
                        pool.drain(0..drain);
                    }
                }
            }
        }
    }
    for block in out.finalized {
        let height = block.header.height;
        let result = match ledger.lock() {
            Ok(l) => l.append_block(&block),
            Err(_) => Err("ledger lock poisoned".to_string()),
        };
        match result {
            Ok(()) => {
                if height == 0 {
                    eprintln!(
                        "[knox-node] sealed genesis block (premine minted) txs={}",
                        block.txs.len()
                    );
                } else {
                    eprintln!(
                        "[knox-node] sealed block {} txs={}",
                        height,
                        block.txs.len()
                    );
                }
            }
            Err(err) => {
                eprintln!("[knox-node] append block {} failed: {}", height, err);
            }
        }
    }
}

fn verify_block(block: &Block, ledger: &Arc<Mutex<Ledger>>) -> bool {
    match ledger.lock() {
        Ok(l) => l.verify_block(block).is_ok(),
        Err(_) => false,
    }
}

async fn run_rpc(
    bind: String,
    ledger: Arc<Mutex<Ledger>>,
    mempool: Arc<Mutex<Vec<MempoolEntry>>>,
    network: NetworkSender,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(bind).await?;
    let allow_remote_rpc = std::env::var("KNOX_NODE_RPC_ALLOW_REMOTE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let limiter = RateLimiter::default();
    let decoy_cache = DecoyCache::default();
    loop {
        let (mut stream, addr) = listener.accept().await?;
        let ledger = ledger.clone();
        let mempool = mempool.clone();
        let network = network.clone();
        let limiter = limiter.clone();
        let decoy_cache = decoy_cache.clone();
        let allow_remote_rpc = allow_remote_rpc;
        tokio::spawn(async move {
            if !allow_remote_rpc && !addr.ip().is_loopback() {
                return;
            }
            let mut len_buf = [0u8; 4];
            if stream.read_exact(&mut len_buf).await.is_err() {
                return;
            }
            let len = u32::from_le_bytes(len_buf) as usize;
            if len == 0 || len > MAX_RPC_BYTES {
                return;
            }
            let mut buf = vec![0u8; len];
            if stream.read_exact(&mut buf).await.is_err() {
                return;
            }
            let request = match bincode::decode_from_slice::<WalletRequest, _>(
                &buf,
                bincode::config::standard(),
            ) {
                Ok((req, _)) => req,
                Err(_) => return,
            };
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
                        eprintln!("[knox-node] submit tx rejected: rate limit");
                        WalletResponse::SubmitResult(false)
                    } else {
                        let verify = match ledger.lock() {
                            Ok(l) => l.verify_tx(&tx),
                            Err(_) => Err("ledger lock poisoned".to_string()),
                        };
                        let ok = verify.is_ok();
                        if let Err(e) = verify {
                            eprintln!("[knox-node] submit tx rejected: {e}");
                        }
                        let mut accepted = false;
                        let mut broadcast_tx = None;
                        if ok {
                            {
                                if let Ok(mut mp) = mempool.lock() {
                                    if mempool_has_conflict(&mp, &tx) {
                                        eprintln!("[knox-node] submit tx rejected: key image conflict in mempool");
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
                            let _ = network.send(Message::Tx(tx)).await;
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
                            if knox_crypto::os_random_bytes(&mut seed).is_err() {
                                WalletResponse::Decoys(Vec::new())
                            } else {
                                let mut prng = knox_crypto::Prng::new(seed);
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
            };
            let bytes = match bincode::encode_to_vec(response, bincode::config::standard()) {
                Ok(v) => v,
                Err(_) => return,
            };
            let mut out = Vec::with_capacity(4 + bytes.len());
            out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            out.extend_from_slice(&bytes);
            let _ = stream.write_all(&out).await;
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
    prng: &mut knox_crypto::Prng,
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

fn random_unit_f64(prng: &mut knox_crypto::Prng) -> f64 {
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
        let mut prng = knox_crypto::Prng::new([3u8; 32]);
        let out = weighted_sample_decoys(&candidates, 31, &mut prng);
        assert_eq!(out.len(), 31);
    }

    #[test]
    fn weighted_sampler_handles_empty() {
        let mut prng = knox_crypto::Prng::new([1u8; 32]);
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

    let mut outputs = Vec::new();
    let mut amounts = Vec::new();
    let mut push_output = |addr: &Address, amount: u64| -> Result<(), String> {
        let out = coinbase_output(height, addr, amount)?;
        outputs.push(out);
        amounts.push(amount);
        Ok(())
    };

    push_output(miner, split.miner)?;
    if split.treasury > 0 {
        push_output(treasury, split.treasury)?;
    }
    if split.dev > 0 {
        push_output(dev, split.dev)?;
    }
    if split.premine > 0 {
        push_output(premine, split.premine)?;
    }

    let commitment_key = LatticeCommitmentKey::derive();
    let private_outputs = private_coinbase_outputs(&commitment_key, split)?;
    if private_outputs.len() != outputs.len() || private_outputs.len() != amounts.len() {
        return Err("coinbase lattice output count mismatch".to_string());
    }

    let mut lattice_outputs = Vec::with_capacity(outputs.len());
    let mut openings = Vec::with_capacity(outputs.len());
    for i in 0..outputs.len() {
        let tx_out = &mut outputs[i];
        let private = &private_outputs[i];
        let stealth_address = lattice_public_from_serialized(&tx_out.lattice_spend_pub)?;
        let lattice_out = LatticeOutput {
            stealth_address,
            ephemeral_public: lattice_public_from_bytes(b"knox-coinbase-ephemeral", &tx_out.tx_pub),
            commitment: private.commitment.clone(),
            range_proof: private.range_proof.clone(),
            enc_amount: tx_out.enc_amount,
            enc_blind: tx_out.enc_blind,
            enc_level: tx_out.enc_level,
        };
        tx_out.commitment = lattice_commitment_digest(&lattice_out.commitment);
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

fn coinbase_output(height: u64, addr: &Address, amount: u64) -> Result<knox_types::TxOut, String> {
    let (r, r_pub) = random_scalar_and_pub()?;
    let view_pub = knox_crypto::PublicKey(addr.view);
    let spend_pub = knox_crypto::PublicKey(addr.spend);
    let one_time_pub = knox_crypto::derive_one_time_pub(&view_pub, &spend_pub, &r)?;
    let recipient_lattice_pub = lattice_public_from_serialized(&addr.lattice_spend_pub)?;

    let blind = random_scalar_bytes()?;
    let commit = knox_crypto::pedersen_commit(amount, &scalar_from_bytes(&blind));
    let proof = knox_crypto::prove_range(amount, scalar_from_bytes(&blind))?;
    let shared = shared_secret_sender(&r, &view_pub)?;
    let shared_bytes = shared.compress().to_bytes();
    let one_time_lattice_pub = lattice_output_public_from_shared(
        &recipient_lattice_pub,
        &shared_bytes,
        &one_time_pub.0,
        &r_pub.0,
    );
    let enc_level = tx_hardening_level(height);
    let (enc_amount, enc_blind) =
        encrypt_amount_with_level(&shared_bytes, amount, &blind, enc_level);

    Ok(knox_types::TxOut {
        one_time_pub: one_time_pub.0,
        tx_pub: r_pub.0,
        commitment: commit.to_bytes(),
        lattice_spend_pub: one_time_lattice_pub.p.to_bytes(),
        enc_amount,
        enc_blind,
        enc_level,
        memo: [0u8; 32],
        range_proof: to_range_types(&proof),
    })
}

fn random_scalar_and_pub(
) -> Result<(curve25519_dalek::scalar::Scalar, knox_crypto::PublicKey), String> {
    let mut seed = [0u8; 32];
    knox_crypto::os_random_bytes(&mut seed)?;
    let scalar = curve25519_dalek::scalar::Scalar::from_bytes_mod_order(seed);
    let point = scalar * curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    Ok((scalar, knox_crypto::PublicKey(point.compress().to_bytes())))
}

fn random_scalar_bytes() -> Result<[u8; 32], String> {
    let mut bytes = [0u8; 32];
    knox_crypto::os_random_bytes(&mut bytes)?;
    Ok(bytes)
}

fn lattice_public_from_bytes(domain: &[u8], bytes: &[u8]) -> LatticePublicKey {
    LatticePublicKey {
        p: knox_lattice::Poly::from_hash(domain, bytes),
    }
}

fn lattice_public_from_serialized(bytes: &[u8]) -> Result<LatticePublicKey, String> {
    let poly = knox_lattice::Poly::from_bytes(bytes)
        .map_err(|_| "invalid lattice public key bytes".to_string())?;
    Ok(LatticePublicKey { p: poly })
}

fn lattice_tweak_from_shared(
    shared_secret: &[u8; 32],
    one_time_pub: &[u8; 32],
    tx_pub: &[u8; 32],
) -> knox_lattice::Poly {
    let mut data = Vec::with_capacity(32 + 32 + 32);
    data.extend_from_slice(shared_secret);
    data.extend_from_slice(one_time_pub);
    data.extend_from_slice(tx_pub);
    knox_lattice::Poly::sample_short(b"knox-wallet-lattice-output-tweak-v1", &data)
}

fn lattice_output_public_from_shared(
    base_public: &LatticePublicKey,
    shared_secret: &[u8; 32],
    one_time_pub: &[u8; 32],
    tx_pub: &[u8; 32],
) -> LatticePublicKey {
    let tweak = lattice_tweak_from_shared(shared_secret, one_time_pub, tx_pub);
    let tweak_public = knox_lattice::ring_sig::public_from_secret(&knox_lattice::LatticeSecretKey {
        s: tweak,
    });
    LatticePublicKey {
        p: base_public.p.add(&tweak_public.p),
    }
}

fn lattice_commitment_digest(commitment: &LatticeCommitment) -> [u8; 32] {
    hash_bytes(&commitment.to_bytes()).0
}

fn scalar_from_bytes(bytes: &[u8; 32]) -> curve25519_dalek::scalar::Scalar {
    curve25519_dalek::scalar::Scalar::from_bytes_mod_order(*bytes)
}

fn shared_secret_sender(
    r: &curve25519_dalek::scalar::Scalar,
    view_pub: &knox_crypto::PublicKey,
) -> Result<curve25519_dalek::ristretto::RistrettoPoint, String> {
    let view_point = curve25519_dalek::ristretto::CompressedRistretto(view_pub.0)
        .decompress()
        .ok_or_else(|| "invalid view public key".to_string())?;
    Ok(r * view_point)
}

fn proposer_streak_for_height(ledger: &Ledger, height: u64, proposer: [u8; 32]) -> u64 {
    if height == 0 {
        return 1;
    }
    let mut streak = 1u64;
    let mut h = height.saturating_sub(1);
    loop {
        let Some(block) = ledger.get_block(h).ok().flatten() else {
            break;
        };
        if block.header.proposer != proposer {
            break;
        }
        streak = streak.saturating_add(1);
        if streak >= knox_types::STREAK_MAX_COUNT || h == 0 {
            break;
        }
        h = h.saturating_sub(1);
    }
    streak
}

fn to_range_types(proof: &knox_crypto::RangeProof) -> knox_types::RangeProof {
    knox_types::RangeProof {
        a: proof.a,
        s: proof.s,
        t1: proof.t1,
        t2: proof.t2,
        tau_x: proof.tau_x,
        mu: proof.mu,
        t_hat: proof.t_hat,
        ip_proof: knox_types::InnerProductProof {
            l_vec: proof.ip_proof.l_vec.clone(),
            r_vec: proof.ip_proof.r_vec.clone(),
            a: proof.ip_proof.a,
            b: proof.ip_proof.b,
        },
    }
}
