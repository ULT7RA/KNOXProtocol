pub mod block;
pub mod coinbase;
pub mod commitment;
pub mod consensus_sig;
pub mod error;
pub mod governance;
pub mod immunity;
pub mod key_image;
pub mod mining;
pub mod params;
pub mod poly;
pub mod range_proof;
pub mod ring_sig;
pub mod sample;
pub mod stealth;
pub mod surge;
pub mod transaction;
pub mod velox_reaper;

pub use block::{apply_block_immunity, verify_block_view, LatticeBlockView};
pub use coinbase::{
    coinbase_split, decode_coinbase_payload, encode_coinbase_payload, private_coinbase_outputs,
    CoinbaseSplit, LatticeCoinbasePayload, PrivateCoinbaseOutput, LATTICE_COINBASE_EXTRA_MAGIC,
};
pub use commitment::{
    commit_value, verify_opening, CommitmentOpening, LatticeCommitment, LatticeCommitmentKey,
};
pub use consensus_sig::{
    consensus_public_from_secret, consensus_public_key_id, consensus_secret_from_seed,
    decode_consensus_public_key, encode_consensus_public_key, sign_consensus, verify_consensus,
    LatticeConsensusSignature,
};
pub use error::LatticeError;
pub use governance::{
    governance_phase, proposal_active_at, GovernancePhase, GovernanceProposal, GovernanceState,
    GovernanceVote, ParamChange,
};
pub use immunity::ImmunityState;
pub use key_image::{derive_key_image, derive_key_image_id, KeyImageSet};
pub use mining::{
    detect_available_backends, difficulty_bits, header_challenge, mine_block_proof,
    mine_block_proof_with_difficulty, mine_block_proof_with_profile, mining_debug_enabled,
    explain_block_proof_failure_with_difficulty, verify_block_proof,
    verify_block_proof_with_difficulty, MiningBackend, MiningBackendStatus, MiningMode,
    MiningProfile,
};
pub use poly::Poly;
pub use range_proof::{prove_range_u64, verify_range_u64, LatticeRangeProof};
pub use ring_sig::{
    key_image, key_image_id, keygen, sign_ring, verify_ring, LatticeKeyImage, LatticePublicKey,
    LatticeRingSignature, LatticeSecretKey,
};
pub use sample::{hash_to_poly, sample_cbd, sample_uniform};
pub use stealth::{
    build_address, recover_one_time_secret, scan_with_view_key, send_to_stealth,
    LatticeAddressKeys, LatticeStealthOutput,
};
pub use surge::{
    month_bounds_utc_ms, surge_difficulty_bits, surge_phase, surge_start_ms, SurgePhase,
    SURGE_BLOCK_CAP, SURGE_COOLDOWN_MS, SURGE_DURATION_MS, SURGE_PHI, SURGE_WARNING_MS,
};
pub use transaction::{
    build_private_output, decode_lattice_tx_extra, decrypt_amount_with_level,
    encode_lattice_tx_extra, encrypt_amount_with_level, fee_commitment, kdf_rounds_for_level,
    signing_message, tx_hardening_level, verify_output, verify_transaction, LatticeInput,
    LatticeOutput, LatticeOutputOpening, LatticeTransaction, LatticeTransactionView,
    LATTICE_TX_EXTRA_MAGIC,
};
