use bincode::{Decode, Encode};
use blake3::Hasher;

pub type Amount = u64;
pub const ATOMS_PER_COIN: Amount = 100_000_000;

pub const TOTAL_SUPPLY: Amount = 69_696_969 * ATOMS_PER_COIN;
pub const GENESIS_PREMINE: Amount = 2_696_969 * ATOMS_PER_COIN;
pub const DEV_FUND_TOTAL: u64 = 0;
pub const DEV_FUND_VEST_YEARS: u32 = 0;
pub const YEAR_1_UNLOCK: u64 = 0;
pub const YEAR_2_UNLOCK: u64 = 0;
pub const PUBLIC_SUPPLY: Amount = 67_000_000 * ATOMS_PER_COIN;
pub const EMISSION_YEARS: u64 = 21;

/// Protocol architect commitment — BLAKE3 domain anchor for genesis integrity.
/// This value is derived from a preimage known only to the protocol architect.
/// Verifiable via: BLAKE3(preimage) == ARCHITECT_COMMITMENT.
pub const ARCHITECT_COMMITMENT: [u8; 32] = [
    0x23, 0x0e, 0x2f, 0xfd, 0xb3, 0x6d, 0xe1, 0x7a,
    0xcf, 0x4b, 0xae, 0xa7, 0x06, 0x2c, 0x5b, 0x34,
    0x08, 0xed, 0xb7, 0xfe, 0x7a, 0x3d, 0x09, 0x39,
    0x5c, 0x6a, 0x4f, 0xef, 0xa0, 0xd7, 0xe2, 0xbf,
];

pub const TARGET_BLOCK_TIME_MS: u64 = 45_000;
pub const MIN_BLOCK_TIME_MS: u64 = 30_000;
pub const MAX_BLOCK_TIME_MS: u64 = 60_000;

pub const MAX_BLOCK_TX: usize = 12000;
pub const MAX_BLOCK_BYTES: usize = 128 * 1024 * 1024;
pub const LEDGER_SNAPSHOT_INTERVAL_BLOCKS: u64 = 500;

pub const DEFAULT_DECOY_COUNT: usize = 31;
pub const MIN_DECOY_COUNT: usize = 15;
pub const MAX_DECOY_COUNT: usize = 64;
pub const DECOY_SAMPLE_WINDOW_BLOCKS: u64 = 120_000;
pub const MIN_DECOY_AGE_BLOCKS: u64 = 1;
pub const P2P_RELAY_DELAY_MIN_MS: u64 = 120;
pub const P2P_RELAY_DELAY_MAX_MS: u64 = 900;
pub const COVER_TRAFFIC_MIN_BYTES: usize = 384;

// Block streak reward tuning (deterministic fixed-point math).
pub const STREAK_RATE_PPM: u64 = 16_180; // 1.6180% per streak step
pub const STREAK_CAP_MULTIPLIER_PPM: u64 = 1_618_000; // 1.618x base max
pub const STREAK_MAX_COUNT: u64 = 34;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Encode, Decode)]
pub struct Hash32(pub [u8; 32]);

impl Hash32 {
    pub const ZERO: Hash32 = Hash32([0u8; 32]);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub struct NetworkId(pub u32);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub struct OutputRef {
    pub tx: Hash32,
    pub index: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Address {
    pub view: [u8; 32],
    pub spend: [u8; 32],
    pub lattice_spend_pub: Vec<u8>,
}

#[derive(Clone, Debug, Encode, Decode)]
pub struct RingMember {
    pub out_ref: OutputRef,
    pub one_time_pub: [u8; 32],
    pub commitment: [u8; 32],
    pub lattice_spend_pub: Vec<u8>,
}

#[derive(Clone, Debug, Encode, Decode)]
pub struct MlsagSignature {
    pub c1: [u8; 32],
    pub responses: Vec<Vec<[u8; 32]>>,
    pub key_images: Vec<[u8; 32]>,
}

#[derive(Clone, Debug, Encode, Decode)]
pub struct InnerProductProof {
    pub l_vec: Vec<[u8; 32]>,
    pub r_vec: Vec<[u8; 32]>,
    pub a: [u8; 32],
    pub b: [u8; 32],
}

#[derive(Clone, Debug, Encode, Decode)]
pub struct RangeProof {
    pub a: [u8; 32],
    pub s: [u8; 32],
    pub t1: [u8; 32],
    pub t2: [u8; 32],
    pub tau_x: [u8; 32],
    pub mu: [u8; 32],
    pub t_hat: [u8; 32],
    pub ip_proof: InnerProductProof,
}

#[derive(Clone, Debug, Encode, Decode)]
pub struct TxIn {
    pub ring: Vec<RingMember>,
    pub key_image: [u8; 32],
    pub pseudo_commit: [u8; 32],
    pub signature: MlsagSignature,
}

#[derive(Clone, Debug, Encode, Decode)]
pub struct TxOut {
    pub one_time_pub: [u8; 32],
    pub tx_pub: [u8; 32],
    pub commitment: [u8; 32],
    pub lattice_spend_pub: Vec<u8>,
    pub enc_amount: [u8; 32],
    pub enc_blind: [u8; 32],
    pub enc_level: u32,
    pub memo: [u8; 32],
    pub range_proof: RangeProof,
}

#[derive(Clone, Debug, Encode, Decode)]
pub struct Transaction {
    pub version: u16,
    pub coinbase: bool,
    pub coinbase_proof: Vec<[u8; 64]>,
    pub inputs: Vec<TxIn>,
    pub outputs: Vec<TxOut>,
    pub fee: Amount,
    pub extra: Vec<u8>,
}

#[derive(Clone, Debug, Encode, Decode)]
pub struct VoteSignature {
    pub validator: u16,
    pub sig: Vec<u8>,
}

#[derive(Clone, Debug, Encode, Decode)]
pub struct Vote {
    pub height: u64,
    pub round: u32,
    pub block_hash: Hash32,
    pub voter: u16,
    pub sig: Vec<u8>,
}

#[derive(Clone, Debug, Encode, Decode)]
pub struct TimeoutVote {
    pub height: u64,
    pub round: u32,
    pub voter: u16,
    pub sig: Vec<u8>,
}

#[derive(Clone, Debug, Encode, Decode)]
pub struct TimeoutCertificate {
    pub height: u64,
    pub round: u32,
    pub sigs: Vec<VoteSignature>,
}

#[derive(Clone, Debug, Encode, Decode)]
pub struct SlashEvidence {
    pub vote_a: Vote,
    pub vote_b: Vote,
}

#[derive(Clone, Debug, Encode, Decode)]
pub struct QuorumCertificate {
    pub height: u64,
    pub round: u32,
    pub block_hash: Hash32,
    pub sigs: Vec<VoteSignature>,
}

#[derive(Clone, Debug, Encode, Decode)]
pub struct BlockHeader {
    pub version: u16,
    pub height: u64,
    pub round: u32,
    pub prev: Hash32,
    pub tx_root: Hash32,
    pub slash_root: Hash32,
    pub state_root: Hash32,
    pub timestamp_ms: u64,
    pub proposer: [u8; 32],
    pub qc: Option<QuorumCertificate>,
}

#[derive(Clone, Debug, Encode, Decode)]
pub struct Block {
    pub header: BlockHeader,
    pub txs: Vec<Transaction>,
    pub slashes: Vec<SlashEvidence>,
    pub proposer_sig: Vec<u8>,
    pub lattice_proof: LatticeProof,
}

#[derive(Clone, Debug, Encode, Decode)]
pub struct LatticeProof {
    pub nonce: u64,
    pub sequential_chain: [u8; 32],
    pub memory_hash: [u8; 32],
    pub pow_hash: [u8; 32],
    pub clh_contribution: [u8; 32],
    pub difficulty_bits: u32,
}

#[derive(Clone, Debug, Encode, Decode)]
pub struct CoinbaseMeta {
    pub amounts: Vec<Amount>,
}

#[derive(Clone, Debug, Encode, Decode)]
pub struct NetworkTelemetry {
    pub tip_height: u64,
    pub tip_hash: Hash32,
    pub total_hardening: u64,
    pub active_miners_recent: u32,
    pub current_difficulty_bits: u32,
    pub tip_proposer_streak: u64,
    pub next_streak_if_same_proposer: u64,
    pub streak_bonus_ppm: u64,
    pub surge_phase: String,
    pub surge_countdown_ms: u64,
    pub surge_block_index: u64,
    pub surge_blocks_remaining: u64,
}

#[derive(Clone, Debug, Encode, Decode)]
pub struct FibWallEntry {
    pub block_height: u64,
    pub timestamp_ms: u64,
    pub month_start_ms: u64,
    pub label: String,
    pub proposer: [u8; 32],
}

#[derive(Clone, Debug, Encode, Decode)]
pub enum WalletRequest {
    GetTip,
    GetBlock(u64),
    GetBlocks(u64, u32),
    SubmitTx(Transaction),
    GetDecoys(u32),
    GetNetworkTelemetry,
    GetFibWall(u32),
    SignDiamondCert(Block),
    /// ForgeTitan election query: returns the elected leader for the given height.
    GetForgeElection(u64),
}

#[derive(Clone, Debug, Encode, Decode)]
pub enum WalletResponse {
    Tip(u64),
    Block(Option<Block>),
    Blocks(Vec<Block>),
    SubmitResult(bool),
    Decoys(Vec<RingMember>),
    NetworkTelemetry(NetworkTelemetry),
    FibWall(Vec<FibWallEntry>),
    DiamondCert(Option<Vec<u8>>),
    /// ForgeTitan election result.
    ForgeElection(ForgeElectionResult),
}

/// Result of a ForgeTitan election query.
#[derive(Clone, Debug, Encode, Decode)]
pub struct ForgeElectionResult {
    pub height: u64,
    /// The elected leader's proposer ID for this height.
    pub leader: [u8; 32],
    /// Number of known active miners in the registry.
    pub active_miners: u32,
    /// True if the querying node should propose (always true for leader,
    /// false for others until grace period expires).
    pub is_leader: bool,
}

/// 48 hours of blocks at TARGET_BLOCK_TIME_MS (45s) = 3840 blocks.
pub const FORGE_TENURE_BLOCKS: u64 = 48 * 3600 * 1000 / TARGET_BLOCK_TIME_MS;
/// Top miner bonus: 2.5% increased election weight.
pub const FORGE_TOP_MINER_BONUS_PPM: u64 = 25_000; // 2.5% in parts-per-million

pub fn hash_bytes(data: &[u8]) -> Hash32 {
    let mut hasher = Hasher::new();
    hasher.update(data);
    let out = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(out.as_bytes());
    Hash32(bytes)
}

pub fn hash_header_for_signing(header: &BlockHeader) -> Hash32 {
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

pub fn hash_header_for_link(header: &BlockHeader) -> Hash32 {
    let mut h = header.clone();
    h.qc = None;
    hash_header_for_signing(&h)
}

pub fn hash_vote_for_signing(vote: &Vote) -> Hash32 {
    let mut data = Vec::new();
    data.extend_from_slice(b"knox-vote-v1");
    data.extend_from_slice(&vote.height.to_le_bytes());
    data.extend_from_slice(&vote.round.to_le_bytes());
    data.extend_from_slice(&vote.block_hash.0);
    data.extend_from_slice(&vote.voter.to_le_bytes());
    hash_bytes(&data)
}

pub fn hash_timeout_vote_for_signing(vote: &TimeoutVote) -> Hash32 {
    let mut data = Vec::new();
    data.extend_from_slice(b"knox-timeout-v1");
    data.extend_from_slice(&vote.height.to_le_bytes());
    data.extend_from_slice(&vote.round.to_le_bytes());
    data.extend_from_slice(&vote.voter.to_le_bytes());
    hash_bytes(&data)
}

pub fn merkle_root(leaves: &[Hash32]) -> Hash32 {
    if leaves.is_empty() {
        return Hash32::ZERO;
    }
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity((level.len() + 1) / 2);
        for pair in level.chunks(2) {
            let mut data = Vec::with_capacity(66);
            data.push(b'N');
            data.extend_from_slice(&pair[0].0);
            if pair.len() == 2 {
                data.extend_from_slice(&pair[1].0);
            } else {
                // Domain-separate odd leaf folding to avoid [A,B,C] == [A,B,C,C] ambiguity.
                data.push(b'O');
            }
            next.push(hash_bytes(&data));
        }
        level = next;
    }
    level[0]
}

pub fn compute_state_root(
    height: u64,
    prev: Hash32,
    tx_root: Hash32,
    slash_root: Hash32,
) -> Hash32 {
    let mut data = Vec::with_capacity(1 + 8 + 32 + 32 + 32 + 32);
    data.push(b'S');
    data.extend_from_slice(&height.to_le_bytes());
    data.extend_from_slice(&prev.0);
    data.extend_from_slice(&tx_root.0);
    data.extend_from_slice(&slash_root.0);
    // Bind the architect's cryptographic commitment to the genesis state root.
    // This value is permanently verifiable on-chain at block 0.
    if height == 0 {
        data.extend_from_slice(&ARCHITECT_COMMITMENT);
    }
    hash_bytes(&data)
}
