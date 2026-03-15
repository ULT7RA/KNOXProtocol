use knox_lattice::{
    consensus_public_key_id, verify_consensus, LatticePublicKey,
    coinbase_split, decode_coinbase_payload, decode_lattice_tx_extra, difficulty_bits,
    explain_block_proof_failure_with_difficulty,
    month_bounds_utc_ms, surge_difficulty_bits, surge_phase, surge_start_ms,
    verify_opening as verify_lattice_opening,
    verify_range_u64 as verify_lattice_range, verify_transaction as verify_lattice_transaction,
    CommitmentOpening, LatticeCommitmentKey, LatticeInput, LatticeOutput, SurgePhase, SURGE_BLOCK_CAP,
    SURGE_DURATION_MS,
};
use knox_storage::Db;
use knox_types::{
    hash_bytes, hash_header_for_link, hash_header_for_signing, hash_vote_for_signing, Block,
    Hash32, OutputRef, QuorumCertificate, RingMember, SlashEvidence, Transaction, TxIn, TxOut,
    Vote, MAX_BLOCK_BYTES, MIN_BLOCK_TIME_MS,
};
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_FUTURE_DRIFT_MS: u64 = 2 * 60 * 1000;

#[derive(Clone, Copy, Debug)]
pub struct MiningRules {
    pub phase: SurgePhase,
    pub expected_difficulty_bits: u32,
    pub min_spacing_ms: u64,
    pub allow_proposal: bool,
}

pub struct Ledger {
    db: Db,
    validators: Vec<LatticePublicKey>,
    diamond_authenticators: Vec<LatticePublicKey>,
    diamond_auth_quorum: usize,
}

#[derive(Debug, Default)]
pub struct SyncApplyBatchResult {
    pub applied_count: usize,
    pub progressed_count: usize,
    pub already_exists_count: usize,
    pub skipped_out_of_order: usize,
    pub stop_height: Option<u64>,
    pub stop_error: Option<String>,
    pub last_applied_height: Option<u64>,
    pub last_progress_height: Option<u64>,
}

enum AppendBlockOutcome {
    Applied,
    AlreadyExistsAdvanced,
    AlreadyExistsStale,
    OutOfOrder,
}

impl Ledger {
    pub fn open(path: &str) -> Result<Self, String> {
        let db = Db::open(path)?;
        Ok(Self {
            db,
            validators: Vec::new(),
            diamond_authenticators: Vec::new(),
            diamond_auth_quorum: 0,
        })
    }

    pub fn set_validators(&mut self, validators: Vec<LatticePublicKey>) {
        self.validators = validators;
    }

    pub fn set_diamond_authenticators(
        &mut self,
        authenticators: Vec<LatticePublicKey>,
        quorum: usize,
    ) {
        self.diamond_authenticators = authenticators;
        self.diamond_auth_quorum = quorum;
    }

    pub fn append_block(&self, block: &Block) -> Result<(), String> {
        let tip = self.height()?;
        let has_genesis = self.get_block(0)?.is_some();
        let mut expected_next = if has_genesis {
            tip.saturating_add(1)
        } else {
            0
        };
        let mut cum_hardening = self.cumulative_hardening()?;
        match self.append_block_with_meta(block, &mut expected_next, &mut cum_hardening)? {
            AppendBlockOutcome::Applied => {
                let height = block.header.height;
                self.persist_chain_meta(height, cum_hardening)?;
                Ok(())
            }
            AppendBlockOutcome::AlreadyExistsAdvanced | AppendBlockOutcome::AlreadyExistsStale => {
                Err(format!("block height {} already exists", block.header.height))
            }
            AppendBlockOutcome::OutOfOrder => Err(format!(
                "unexpected block height: got {}, expected {}",
                block.header.height, expected_next
            )),
        }
    }

    pub fn append_sync_batch(&self, blocks: &[Block]) -> SyncApplyBatchResult {
        let mut result = SyncApplyBatchResult::default();
        if blocks.is_empty() {
            return result;
        }

        let tip = match self.height() {
            Ok(tip) => tip,
            Err(err) => {
                result.stop_error = Some(err);
                result.stop_height = blocks.first().map(|b| b.header.height);
                return result;
            }
        };
        let has_genesis = match self.get_block(0) {
            Ok(block) => block.is_some(),
            Err(err) => {
                result.stop_error = Some(err);
                result.stop_height = blocks.first().map(|b| b.header.height);
                return result;
            }
        };
        let mut expected_next = if has_genesis {
            tip.saturating_add(1)
        } else {
            0
        };
        let mut cum_hardening = match self.cumulative_hardening() {
            Ok(value) => value,
            Err(err) => {
                result.stop_error = Some(err);
                result.stop_height = blocks.first().map(|b| b.header.height);
                return result;
            }
        };

        for block in blocks {
            match self.append_block_with_meta(block, &mut expected_next, &mut cum_hardening) {
                Ok(AppendBlockOutcome::Applied) => {
                    result.applied_count = result.applied_count.saturating_add(1);
                    result.progressed_count = result.progressed_count.saturating_add(1);
                    result.last_applied_height = Some(block.header.height);
                    result.last_progress_height = Some(block.header.height);
                }
                Ok(AppendBlockOutcome::AlreadyExistsAdvanced) => {
                    result.progressed_count = result.progressed_count.saturating_add(1);
                    result.already_exists_count =
                        result.already_exists_count.saturating_add(1);
                    result.last_progress_height = Some(block.header.height);
                }
                Ok(AppendBlockOutcome::AlreadyExistsStale) => {
                    result.already_exists_count =
                        result.already_exists_count.saturating_add(1);
                }
                Ok(AppendBlockOutcome::OutOfOrder) => {
                    result.skipped_out_of_order =
                        result.skipped_out_of_order.saturating_add(1);
                }
                Err(err) => {
                    result.stop_height = Some(block.header.height);
                    result.stop_error = Some(err);
                    break;
                }
            }
        }

        if let Some(last_height) = result.last_progress_height {
            if let Err(err) = self.persist_chain_meta(last_height, cum_hardening) {
                result.stop_height = Some(last_height);
                result.stop_error = Some(format!("persist-meta: {err}"));
            }
        }

        result
    }

    pub fn replace_from_genesis(&mut self, blocks: &[Block]) -> Result<(), String> {
        if blocks.is_empty() {
            return Err("replacement chain is empty".to_string());
        }
        if blocks[0].header.height != 0 {
            return Err("replacement chain must start at height 0".to_string());
        }
        for pair in blocks.windows(2) {
            let prev = pair[0].header.height;
            let next = pair[1].header.height;
            if next != prev.saturating_add(1) {
                return Err(format!(
                    "replacement chain is non-contiguous at {} -> {}",
                    prev, next
                ));
            }
        }

        let mut verify_dir = std::env::temp_dir();
        verify_dir.push(format!("knox-ledger-verify-{}", now_ms()));
        fs::create_dir_all(&verify_dir).map_err(|e| format!("verify mkdir: {e}"))?;
        let verify_path = verify_dir.to_string_lossy().to_string();
        let mut verify_ledger = Ledger::open(&verify_path).map_err(|e| format!("verify open: {e}"))?;
        verify_ledger.set_validators(self.validators.clone());
        verify_ledger.set_diamond_authenticators(
            self.diamond_authenticators.clone(),
            self.diamond_auth_quorum,
        );
        for block in blocks {
            verify_ledger
                .append_block(block)
                .map_err(|e| format!("verify replacement chain failed: {e}"))?;
        }

        self.db.clear().map_err(|e| format!("clear db: {e}"))?;
        for block in blocks {
            self.append_block(block)
                .map_err(|e| format!("apply replacement chain failed: {e}"))?;
        }

        let _ = fs::remove_dir_all(&verify_dir);
        Ok(())
    }

    pub fn clear_chain(&self) -> Result<(), String> {
        self.db.clear().map_err(|e| format!("clear db: {e}"))?;
        Ok(())
    }

    /// Replace the block at the current tip with `new_block` if the new block
    /// wins the deterministic fork-choice tiebreaker (lower block hash wins).
    /// Only succeeds when `new_block.header.height == self.height()` and the
    /// new block passes full verification.  Existing UTXO / decoy state for
    /// the replaced block is NOT rolled back — the next sync-reset will
    /// rebuild it.  This is safe because the only caller is the conflict
    /// handler which expects a full resync shortly after.
    pub fn replace_tip_block(&self, new_block: &Block) -> Result<(), String> {
        let tip = self.height()?;
        let h = new_block.header.height;
        if h != tip {
            return Err(format!(
                "replace_tip_block: height {h} != current tip {tip}"
            ));
        }
        // Deterministic tiebreaker: lower block hash wins.
        let existing = self.get_block(h)?
            .ok_or_else(|| format!("replace_tip: no existing block at h={h}"))?;
        let existing_hash = hash_header_for_link(&existing.header);
        let incoming_hash = hash_header_for_link(&new_block.header);
        if incoming_hash.0 >= existing_hash.0 {
            return Err(format!(
                "replace_tip: incoming hash >= existing (tiebreaker lost)"
            ));
        }
        self.verify_block_for_sync(new_block)
            .map_err(|e| format!("replace_tip verify: {e}"))?;
        let key = block_key(h);
        let bytes = bincode::encode_to_vec(new_block, bincode::config::standard())
            .map_err(|e| format!("replace_tip encode: {e}"))?;
        self.db
            .put(&key, &bytes)
            .map_err(|e| format!("replace_tip db-put: {e}"))?;
        Ok(())
    }

    fn append_block_with_meta(
        &self,
        block: &Block,
        expected_next: &mut u64,
        cum_hardening: &mut u64,
    ) -> Result<AppendBlockOutcome, String> {
        let height = block.header.height;
        if let Some(existing) = self.get_block(height)? {
            let existing_hash = hash_header_for_link(&existing.header);
            let incoming_hash = hash_header_for_link(&block.header);
            if existing_hash == incoming_hash {
                if height == *expected_next {
                    *cum_hardening =
                        cum_hardening.saturating_add(block.lattice_proof.difficulty_bits as u64);
                    *expected_next = expected_next.saturating_add(1);
                    return Ok(AppendBlockOutcome::AlreadyExistsAdvanced);
                }
                return Ok(AppendBlockOutcome::AlreadyExistsStale);
            }
            return Err(format!(
                "conflicting block at height {} already committed",
                height
            ));
        }
        if height != *expected_next {
            return Ok(AppendBlockOutcome::OutOfOrder);
        }
        self.verify_block_for_sync(block)
            .map_err(|e| format!("verify: {e}"))?;
        let key = block_key(height);
        let bytes = bincode::encode_to_vec(block, bincode::config::standard())
            .map_err(|e| format!("encode: {e}"))?;
        if bytes.len() > MAX_BLOCK_BYTES {
            return Err(format!(
                "block serialized size {} exceeds max {} bytes",
                bytes.len(),
                MAX_BLOCK_BYTES
            ));
        }
        self.db
            .put(&key, &bytes)
            .map_err(|e| format!("db-put-block: {e}"))?;
        let mut decoy_bucket = Vec::new();
        for tx in &block.txs {
            self.apply_tx(tx, height, &mut decoy_bucket)
                .map_err(|e| format!("apply-tx: {e}"))?;
        }
        self.store_decoy_bucket(height, &decoy_bucket)
            .map_err(|e| format!("decoy-bucket: {e}"))?;
        for ev in &block.slashes {
            self.record_slash(ev.vote_a.voter)?;
        }
        *cum_hardening = cum_hardening.saturating_add(block.lattice_proof.difficulty_bits as u64);
        *expected_next = expected_next.saturating_add(1);
        Ok(AppendBlockOutcome::Applied)
    }

    fn cumulative_hardening(&self) -> Result<u64, String> {
        match self
            .db
            .get(b"cum_hardening")
            .map_err(|e| format!("db-get-cum: {e}"))?
        {
            Some(b) if b.len() == 8 => {
                let mut arr = [0u8; 8];
                arr.copy_from_slice(&b);
                Ok(u64::from_le_bytes(arr))
            }
            _ => Ok(0),
        }
    }

    fn persist_chain_meta(&self, height: u64, cum_hardening: u64) -> Result<(), String> {
        self.db
            .put(b"height", &height.to_le_bytes())
            .map_err(|e| format!("db-put-height: {e}"))?;
        self.db
            .put(b"cum_hardening", &cum_hardening.to_le_bytes())
            .map_err(|e| format!("db-put-cum: {e}"))?;
        Ok(())
    }

    pub fn get_block(&self, height: u64) -> Result<Option<Block>, String> {
        Ok(self.get_block_with_size(height)?.map(|(b, _)| b))
    }

    pub fn get_block_with_size(&self, height: u64) -> Result<Option<(Block, usize)>, String> {
        let key = block_key(height);
        let raw = match self.db.get(&key) {
            Ok(v) => v,
            Err(err) => {
                eprintln!(
                    "[knox-ledger] get_block failed at h={}: {}",
                    height, err
                );
                return Err(err);
            }
        };
        match raw {
            Some(bytes) => {
                let encoded_len = bytes.len();
                let decoded: Result<(Block, usize), _> = bincode::decode_from_slice(
                    &bytes,
                    bincode::config::standard().with_limit::<{ MAX_BLOCK_BYTES }>(),
                );
                match decoded {
                    Ok((b, _)) => Ok(Some((b, encoded_len))),
                    Err(err) => {
                        eprintln!(
                            "[knox-ledger] CRITICAL db decode error for block {} ({} bytes): {:?}",
                            height, encoded_len, err
                        );
                        // Fallback: local DB data is trusted, so try unbounded decode if limit failed (e.g. huge genesis)
                        let fallback: Result<(Block, usize), _> =
                            bincode::decode_from_slice(&bytes, bincode::config::standard());
                        match fallback {
                            Ok((b, _)) => {
                                eprintln!(
                                    "[knox-ledger] RECOVERED block {} using unbounded decode",
                                    height
                                );
                                Ok(Some((b, encoded_len)))
                            }
                            Err(e2) => {
                                eprintln!(
                                    "[knox-ledger] FATAL unbound decode failed for block {}: {:?}",
                                    height, e2
                                );
                                Ok(None)
                            }
                        }
                    }
                }
            }
            None => Ok(None),
        }
    }

    pub fn height(&self) -> Result<u64, String> {
        match self.db.get(b"height")? {
            Some(bytes) if bytes.len() == 8 => {
                let mut arr = [0u8; 8];
                arr.copy_from_slice(&bytes);
                Ok(u64::from_le_bytes(arr))
            }
            _ => Ok(0),
        }
    }

    pub fn verify_tx(&self, tx: &Transaction) -> Result<(), String> {
        if tx.coinbase {
            return Err("coinbase cannot be verified without block context".to_string());
        }
        verify_non_coinbase(self, tx)
    }

    pub fn verify_block(&self, block: &Block) -> Result<(), String> {
        self.verify_block_internal(block, true, false)
    }

    pub fn verify_block_for_diamond_auth(&self, block: &Block) -> Result<(), String> {
        self.verify_block_internal(block, false, false)
    }

    pub fn verify_block_for_sync(&self, block: &Block) -> Result<(), String> {
        self.verify_block_internal(block, true, true)
    }

    fn trust_fast_sync_blocks() -> bool {
        matches!(
            std::env::var("KNOX_TRUST_SYNC_BLOCKS")
                .ok()
                .as_deref()
                .map(|v| v.trim()),
            Some("1") | Some("true") | Some("TRUE") | Some("yes") | Some("YES")
        )
    }

    fn verify_block_internal(
        &self,
        block: &Block,
        enforce_diamond_auth: bool,
        fast_sync: bool,
    ) -> Result<(), String> {
        let trust_sync = fast_sync && Self::trust_fast_sync_blocks();
        if block.header.version != 1 {
            return Err("unsupported block version".to_string());
        }
        if !fast_sync && !self.validators.is_empty() {
            let proposer_idx = self
                .validators
                .iter()
                .position(|pk| consensus_public_key_id(pk) == block.header.proposer)
                .ok_or_else(|| "block proposer is not in validator set".to_string())?
                as u16;
            if self.slashed_list()?.contains(&proposer_idx) {
                return Err("block proposer is slashed".to_string());
            }
            let proposer_pk = self
                .validators
                .get(proposer_idx as usize)
                .ok_or_else(|| "block proposer index missing".to_string())?;
            let signer_msg = hash_header_for_signing(&block.header);
            if !verify_consensus(proposer_pk, &signer_msg.0, &block.proposer_sig) {
                return Err("proposer signature invalid".to_string());
            }
            if let Some(qc) = &block.header.qc {
                verify_quorum_certificate(qc, &self.validators, &self.slashed_list()?)?;
            }
        }
        // If validators is empty, open mining mode: anyone can propose — no
        // proposer/QC checks applied.
        if block.txs.is_empty() {
            return Err("empty block".to_string());
        }
        if block.txs.len() > knox_types::MAX_BLOCK_TX {
            return Err("block has too many transactions".to_string());
        }
        let encoded_block = bincode::encode_to_vec(block, bincode::config::standard())
            .map_err(|e| format!("block encode failed: {e}"))?;
        if encoded_block.len() > MAX_BLOCK_BYTES {
            return Err(format!(
                "block serialized size {} exceeds max {} bytes",
                encoded_block.len(),
                MAX_BLOCK_BYTES
            ));
        }
        let tx_hashes = block
            .txs
            .iter()
            .map(|t| {
                bincode::encode_to_vec(t, bincode::config::standard())
                    .map(|v| hash_bytes(&v))
                    .map_err(|e| format!("tx encode failed: {e}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let expected_tx_root = knox_types::merkle_root(&tx_hashes);
        if expected_tx_root != block.header.tx_root {
            return Err("tx root mismatch".to_string());
        }
        let expected_state_root = knox_types::compute_state_root(
            block.header.height,
            block.header.prev,
            block.header.tx_root,
            block.header.slash_root,
        );
        if expected_state_root != block.header.state_root {
            return Err("state root mismatch".to_string());
        }
        let mining_rules = if trust_sync {
            None
        } else {
            let now = now_ms();
            if block.header.timestamp_ms > now.saturating_add(MAX_FUTURE_DRIFT_MS) {
                return Err("block timestamp too far in future".to_string());
            }
            let rules = self.mining_rules_for_height(block.header.height, block.header.timestamp_ms)?;
            if !rules.allow_proposal {
                return Err("surge cooldown active".to_string());
            }
            Some(rules)
        };
        if block.header.height == 0 {
            if block.header.prev != Hash32::ZERO {
                return Err("genesis prev must be zero".to_string());
            }
        } else {
            let prev_h = block.header.height.saturating_sub(1);
            let prev = self
                .get_block(prev_h)?
                .ok_or_else(|| "missing parent block".to_string())?;
            if block.header.timestamp_ms < prev.header.timestamp_ms {
                return Err("block timestamp is earlier than parent".to_string());
            }
            if let Some(rules) = mining_rules.as_ref() {
                if block
                    .header
                    .timestamp_ms
                    .saturating_sub(prev.header.timestamp_ms)
                    < rules.min_spacing_ms
                {
                    return Err("block timestamp spacing below minimum".to_string());
                }
            }
            let expected_prev = header_link_hash(&prev.header);
            if block.header.prev != expected_prev {
                return Err("prev hash mismatch".to_string());
            }
        }
        // Genesis block (height 0) is trusted by definition — skip PoW check.
        if block.header.height > 0 && !trust_sync {
            if let Some(reason) = explain_block_proof_failure_with_difficulty(
                &block.header,
                &block.lattice_proof,
                mining_rules
                    .as_ref()
                    .map(|rules| rules.expected_difficulty_bits)
                    .unwrap_or_else(|| difficulty_bits(block.header.height)),
            ) {
                return Err(format!("lattice proof invalid: {reason}"));
            }
        }
        if !fast_sync && enforce_diamond_auth && !self.diamond_authenticators.is_empty() {
            verify_diamond_authenticator_cert(
                block,
                &self.diamond_authenticators,
                self.diamond_auth_quorum.max(1),
            )?;
        }
        let coinbase = &block.txs[0];
        if !coinbase.coinbase {
            return Err("missing coinbase".to_string());
        }
        let mut block_key_images = HashSet::new();
        for tx in block.txs.iter().skip(1) {
            if tx.coinbase {
                return Err("multiple coinbase".to_string());
            }
            for input in &tx.inputs {
                if !block_key_images.insert(input.key_image) {
                    return Err("duplicate key image in block".to_string());
                }
            }
            if !fast_sync {
                verify_non_coinbase(self, tx)?;
            }
        }

        if !trust_sync {
            let fees: u64 = block.txs.iter().skip(1).map(|t| t.fee).sum();
            let streak = proposer_streak_for_height(
                self,
                block.header.height,
                block.header.proposer,
                block.header.timestamp_ms,
            )?;
            verify_coinbase(coinbase, block.header.height, fees, streak)?;
        }
        if !fast_sync {
            verify_slashes(block, &self.validators)?;
        }
        let expected_slash_root = slash_root(&block.slashes);
        if expected_slash_root != block.header.slash_root {
            return Err("slash root mismatch".to_string());
        }
        Ok(())
    }

    pub fn mining_rules_for_next_block(&self, timestamp_ms: u64) -> Result<MiningRules, String> {
        let tip = self.height()?;
        let has_genesis = self.get_block(0)?.is_some();
        let next_height = if has_genesis {
            tip.saturating_add(1)
        } else {
            0
        };
        self.mining_rules_for_height(next_height, timestamp_ms)
    }

    pub fn mining_rules_for_height(
        &self,
        height: u64,
        timestamp_ms: u64,
    ) -> Result<MiningRules, String> {
        let base_bits = difficulty_bits(height);
        let tip = self.height()?;
        let has_genesis = self.get_block(0)?.is_some();
        if !has_genesis {
            return Ok(MiningRules {
                phase: SurgePhase::Normal,
                expected_difficulty_bits: base_bits,
                min_spacing_ms: MIN_BLOCK_TIME_MS,
                allow_proposal: true,
            });
        }
        // Use 30-day periods anchored to genesis timestamp so the surge
        // fires exactly once every 30 days from chain launch.
        const PERIOD_MS: u64 = 30 * 24 * 60 * 60 * 1000;
        let genesis_ts_ms = self.get_block(0)?
            .map(|b| b.header.timestamp_ms)
            .unwrap_or(timestamp_ms);
        let elapsed = timestamp_ms.saturating_sub(genesis_ts_ms);
        let period_idx = elapsed / PERIOD_MS;
        let month_start = genesis_ts_ms.saturating_add(period_idx * PERIOD_MS);
        let month_end = month_start.saturating_add(PERIOD_MS);
        let month_duration = PERIOD_MS;
        let Some((first_height, first_block)) =
            self.first_block_in_window(tip, month_start, month_end)?
        else {
            return Ok(MiningRules {
                phase: SurgePhase::Normal,
                expected_difficulty_bits: base_bits,
                min_spacing_ms: MIN_BLOCK_TIME_MS,
                allow_proposal: true,
            });
        };
        let first_hash = header_link_hash(&first_block.header).0;
        let start_ms = surge_start_ms(first_block.header.timestamp_ms, first_hash, month_duration);
        let time_end_ms = start_ms.saturating_add(SURGE_DURATION_MS);
        let (prior_surge_blocks, cap_ts) = self.prior_surge_stats(
            first_height,
            tip,
            month_start,
            month_end,
            start_ms,
            time_end_ms,
        )?;
        let phase = surge_phase(
            timestamp_ms,
            first_block.header.timestamp_ms,
            first_hash,
            month_duration,
            prior_surge_blocks,
            cap_ts,
        );
        let (expected_difficulty_bits, min_spacing_ms, allow_proposal) = match phase {
            SurgePhase::Active { block_index, .. } => {
                (surge_difficulty_bits(base_bits, block_index), 0, true)
            }
            SurgePhase::Cooldown { .. } => (base_bits, MIN_BLOCK_TIME_MS, false),
            SurgePhase::Normal | SurgePhase::Warning { .. } => (base_bits, MIN_BLOCK_TIME_MS, true),
        };
        Ok(MiningRules {
            phase,
            expected_difficulty_bits,
            min_spacing_ms,
            allow_proposal,
        })
    }

    fn first_block_in_window(
        &self,
        tip: u64,
        month_start: u64,
        month_end: u64,
    ) -> Result<Option<(u64, Block)>, String> {
        let mut h = tip;
        let mut first: Option<(u64, Block)> = None;
        loop {
            let Some(block) = self.get_block(h)? else {
                if h == 0 {
                    break;
                }
                h = h.saturating_sub(1);
                continue;
            };
            let ts = block.header.timestamp_ms;
            if ts < month_start {
                break;
            }
            if ts < month_end {
                first = Some((h, block));
            }
            if h == 0 {
                break;
            }
            h = h.saturating_sub(1);
        }
        Ok(first)
    }

    fn prior_surge_stats(
        &self,
        first_height: u64,
        tip: u64,
        month_start: u64,
        month_end: u64,
        surge_start_ms: u64,
        surge_end_ms: u64,
    ) -> Result<(u64, Option<u64>), String> {
        let mut prior = 0u64;
        let mut cap_ts = None;
        for h in first_height..=tip {
            let Some(block) = self.get_block(h)? else {
                continue;
            };
            let ts = block.header.timestamp_ms;
            if ts < month_start || ts >= month_end {
                continue;
            }
            if ts >= surge_start_ms && ts < surge_end_ms {
                if prior < SURGE_BLOCK_CAP {
                    prior = prior.saturating_add(1);
                    if prior == SURGE_BLOCK_CAP {
                        cap_ts = Some(ts);
                        break;
                    }
                }
            }
        }
        Ok((prior, cap_ts))
    }

    pub fn network_telemetry(
        &self,
        timestamp_ms: u64,
    ) -> Result<knox_types::NetworkTelemetry, String> {
        let tip = self.height()?;
        let tip_block = self.get_block(tip)?;
        let tip_hash = tip_block
            .as_ref()
            .map(|b| header_link_hash(&b.header))
            .unwrap_or(Hash32::ZERO);
        let rules = self.mining_rules_for_next_block(timestamp_ms)?;
        let total_hardening = self.total_hardening_score(tip)?;
        let active_miners = self.active_miners_recent(tip, 2048)?;
        let (tip_proposer_streak, next_streak_if_same_proposer, streak_bonus_ppm) =
            if let Some(block) = tip_block.as_ref() {
                let streak =
                    proposer_streak_for_height(self, tip.saturating_add(1), block.header.proposer, timestamp_ms)?;
                let next = streak.saturating_add(1).min(knox_types::STREAK_MAX_COUNT);
                (streak, next, streak_bonus_ppm(streak))
            } else {
                (0, 0, 0)
            };

        let (surge_phase, surge_countdown_ms, surge_block_index, surge_blocks_remaining) =
            match rules.phase {
                SurgePhase::Normal => ("normal".to_string(), 0, 0, 0),
                SurgePhase::Warning { starts_in_ms } => ("warning".to_string(), starts_in_ms, 0, 0),
                SurgePhase::Active {
                    block_index,
                    remaining_blocks,
                    ends_in_ms,
                } => (
                    "active".to_string(),
                    ends_in_ms,
                    block_index,
                    remaining_blocks,
                ),
                SurgePhase::Cooldown { ends_in_ms } => ("cooldown".to_string(), ends_in_ms, 0, 0),
            };

        Ok(knox_types::NetworkTelemetry {
            tip_height: tip,
            tip_hash,
            total_hardening,
            active_miners_recent: active_miners,
            current_difficulty_bits: rules.expected_difficulty_bits,
            tip_proposer_streak,
            next_streak_if_same_proposer,
            streak_bonus_ppm,
            surge_phase,
            surge_countdown_ms,
            surge_block_index,
            surge_blocks_remaining,
        })
    }

    pub fn fibonacci_wall(&self, limit: usize) -> Result<Vec<knox_types::FibWallEntry>, String> {
        let tip = self.height()?;
        let mut entries = Vec::new();
        if let Some(genesis) = self.get_block(0)? {
            let (month_start, _) = month_bounds_utc_ms(genesis.header.timestamp_ms);
            entries.push(knox_types::FibWallEntry {
                block_height: 0,
                timestamp_ms: genesis.header.timestamp_ms,
                month_start_ms: month_start,
                label: "GENESIS BLOCK 0 - ULT7RA & Rockasaurus Rex (Block Owners)".to_string(),
                proposer: genesis.header.proposer,
            });
        }

        let mut months: BTreeMap<u64, Vec<(u64, u64, [u8; 32], [u8; 32])>> = BTreeMap::new();
        for h in 0..=tip {
            let Some(block) = self.get_block(h)? else {
                continue;
            };
            let ts = block.header.timestamp_ms;
            let (month_start, _) = month_bounds_utc_ms(ts);
            months.entry(month_start).or_default().push((
                h,
                ts,
                block.header.proposer,
                header_link_hash(&block.header).0,
            ));
        }

        for (month_start, mut blocks) in months {
            if blocks.is_empty() {
                continue;
            }
            blocks.sort_by_key(|(h, _, _, _)| *h);
            let first = blocks[0];
            let (_, month_end) = month_bounds_utc_ms(first.1);
            let month_duration = month_end.saturating_sub(month_start);
            let surge_start = surge_start_ms(first.1, first.3, month_duration);
            let surge_end = surge_start.saturating_add(SURGE_DURATION_MS);

            let mut count = 0u64;
            for (h, ts, proposer, _) in blocks {
                if ts < surge_start || ts >= surge_end {
                    continue;
                }
                count = count.saturating_add(1);
                if count == SURGE_BLOCK_CAP {
                    entries.push(knox_types::FibWallEntry {
                        block_height: h,
                        timestamp_ms: ts,
                        month_start_ms: month_start,
                        label: "Golden Block 16180".to_string(),
                        proposer,
                    });
                    break;
                }
            }
        }

        entries.sort_by_key(|e| e.block_height);
        if limit == 0 || entries.len() <= limit {
            return Ok(entries);
        }
        let mut out = Vec::new();
        if let Some(genesis) = entries.first().cloned() {
            out.push(genesis);
        }
        let tail_keep = limit.saturating_sub(out.len());
        if tail_keep > 0 {
            let tail_start = entries.len().saturating_sub(tail_keep);
            for e in entries.into_iter().skip(tail_start) {
                if e.block_height == 0 && !out.is_empty() {
                    continue;
                }
                out.push(e);
            }
        }
        Ok(out)
    }

    fn total_hardening_score(&self, tip: u64) -> Result<u64, String> {
        // Fast path: read the single cumulative key maintained by append_block.
        if let Some(b) = self.db.get(b"cum_hardening").map_err(|e| format!("db-get-cum: {e}"))? {
            if b.len() == 8 {
                let mut arr = [0u8; 8];
                arr.copy_from_slice(&b);
                return Ok(u64::from_le_bytes(arr));
            }
        }
        // Migration path: key absent on nodes that pre-date this change.
        // Compute the cumulative score once from existing blocks and persist it.
        let mut total = 0u64;
        for h in 0..=tip {
            let Some(block) = self.get_block(h)? else {
                continue;
            };
            total = total.saturating_add(block.lattice_proof.difficulty_bits as u64);
        }
        self.db.put(b"cum_hardening", &total.to_le_bytes()).map_err(|e| format!("db-put-cum: {e}"))?;
        Ok(total)
    }

    fn active_miners_recent(&self, tip: u64, lookback: u64) -> Result<u32, String> {
        let start = tip.saturating_sub(lookback.saturating_sub(1));
        let mut operator_ids = HashSet::new();
        let mut legacy_proposers = HashSet::new();
        for h in start..=tip {
            let Some(block) = self.get_block(h)? else {
                continue;
            };
            if let Some(operator_id) = coinbase_operator_identity(&block) {
                operator_ids.insert(operator_id);
            } else {
                legacy_proposers.insert(block.header.proposer);
            }
        }
        if !operator_ids.is_empty() {
            Ok(operator_ids.len() as u32)
        } else {
            Ok(legacy_proposers.len() as u32)
        }
    }

    fn apply_tx(
        &self,
        tx: &Transaction,
        height: u64,
        decoys: &mut Vec<RingMember>,
    ) -> Result<(), String> {
        let tx_hash = tx_hash(tx);
        for (index, output) in tx.outputs.iter().enumerate() {
            let out_ref = OutputRef {
                tx: tx_hash,
                index: index as u16,
            };
            store_output(&self.db, &out_ref, output, height)?;
            decoys.push(RingMember {
                out_ref,
                one_time_pub: output.one_time_pub,
                commitment: output.commitment,
                lattice_spend_pub: output.lattice_spend_pub.clone(),
            });
        }
        if !tx.coinbase {
            for input in &tx.inputs {
                self.db.put(&spent_key(&input.key_image), &[1u8])?;
            }
        }
        Ok(())
    }

    fn store_decoy_bucket(&self, height: u64, members: &[RingMember]) -> Result<(), String> {
        let key = decoy_bucket_key(height);
        let bytes = bincode::encode_to_vec(members, bincode::config::standard())
            .map_err(|e| e.to_string())?;
        self.db.put(&key, &bytes)
    }

    pub fn decoy_members_window(
        &self,
        tip: u64,
        window: u64,
        newest_allowed: u64,
        max_members: usize,
    ) -> Result<Vec<(RingMember, u64)>, String> {
        let start = tip.saturating_sub(window);
        let end = newest_allowed.min(tip);
        let mut out = Vec::new();
        for h in start..=end {
            let key = decoy_bucket_key(h);
            let Some(bytes) = self.db.get(&key)? else {
                continue;
            };
            let (members, _): (Vec<RingMember>, usize) =
                bincode::decode_from_slice(&bytes, bincode::config::standard().with_limit::<{ 32 * 1024 * 1024 }>())
                    .map_err(|e| e.to_string())?;
            for m in members {
                out.push((m, h));
                if out.len() >= max_members {
                    return Ok(out);
                }
            }
        }
        Ok(out)
    }

    fn is_spent(&self, key_image: &[u8; 32]) -> Result<bool, String> {
        Ok(self.db.get(&spent_key(key_image))?.is_some())
    }

    fn record_slash(&self, validator: u16) -> Result<(), String> {
        let mut list = self.slashed_list()?;
        if !list.contains(&validator) {
            list.push(validator);
            let bytes = bincode::encode_to_vec(&list, bincode::config::standard())
                .map_err(|e| e.to_string())?;
            self.db.put(b"slashed", &bytes)?;
        }
        Ok(())
    }

    pub fn slashed_list(&self) -> Result<Vec<u16>, String> {
        match self.db.get(b"slashed")? {
            Some(bytes) => {
                let (list, _): (Vec<u16>, usize) =
                    bincode::decode_from_slice(&bytes, bincode::config::standard().with_limit::<{ 32 * 1024 * 1024 }>())
                        .map_err(|e| e.to_string())?;
                Ok(list)
            }
            None => Ok(Vec::new()),
        }
    }
}

fn verify_non_coinbase(ledger: &Ledger, tx: &Transaction) -> Result<(), String> {
    if tx.version != 3 {
        return Err("unsupported tx version (lattice v3 required)".to_string());
    }
    verify_non_coinbase_lattice(ledger, tx)
}

fn verify_non_coinbase_lattice(ledger: &Ledger, tx: &Transaction) -> Result<(), String> {
    if tx.inputs.is_empty() || tx.outputs.is_empty() {
        return Err("tx must have inputs and outputs".to_string());
    }
    let lattice_tx = decode_lattice_tx_extra(&tx.extra)?;
    if lattice_tx.inputs.len() != tx.inputs.len() {
        return Err("lattice payload input mismatch".to_string());
    }
    if lattice_tx.outputs.len() != tx.outputs.len() {
        return Err("lattice payload output mismatch".to_string());
    }
    if lattice_tx.fee != tx.fee {
        return Err("lattice payload fee mismatch".to_string());
    }
    for (idx, out) in tx.outputs.iter().enumerate() {
        if out.enc_amount != lattice_tx.outputs[idx].enc_amount
            || out.enc_blind != lattice_tx.outputs[idx].enc_blind
            || out.enc_level != lattice_tx.outputs[idx].enc_level
        {
            return Err("lattice output encryption mismatch".to_string());
        }
        let lattice_out_pub = lattice_public_from_output(out)?;
        if lattice_tx.outputs[idx].stealth_address != lattice_out_pub {
            return Err("lattice stealth key mismatch".to_string());
        }
        if out.commitment != lattice_commitment_digest(&lattice_tx.outputs[idx].commitment) {
            return Err("lattice commitment digest mismatch".to_string());
        }
    }

    let mut seen_images = HashSet::new();
    for (idx, input) in tx.inputs.iter().enumerate() {
        let lattice_image = knox_lattice::derive_key_image_id(&lattice_tx.inputs[idx].key_image);
        if input.key_image != lattice_image {
            return Err("lattice key image mismatch".to_string());
        }
        if !seen_images.insert(input.key_image) {
            return Err("duplicate key image".to_string());
        }
        if ledger.is_spent(&input.key_image)? {
            return Err("key image already spent".to_string());
        }
        if !verify_ring_members(ledger, input) {
            return Err("ring members invalid".to_string());
        }
        if !verify_lattice_ring_linkage(input, &lattice_tx.inputs[idx]) {
            return Err("outer ring does not match lattice ring".to_string());
        }
    }

    let msg = tx_lattice_signing_hash(tx).0;
    let key = LatticeCommitmentKey::derive();
    verify_lattice_transaction(&key, &lattice_tx, &msg)
}

fn verify_coinbase(tx: &Transaction, height: u64, fees: u64, streak: u64) -> Result<(), String> {
    if !tx.coinbase || !tx.inputs.is_empty() {
        return Err("invalid coinbase".to_string());
    }
    if tx.fee != 0 {
        return Err("coinbase fee must be zero".to_string());
    }
    if tx.version != 3 {
        return Err("unsupported coinbase version (lattice v3 required)".to_string());
    }
    verify_coinbase_lattice(tx, height, fees, streak)
}

fn verify_coinbase_lattice(
    tx: &Transaction,
    height: u64,
    fees: u64,
    streak: u64,
) -> Result<(), String> {
    let payload = decode_coinbase_payload(&tx.extra)?;
    if payload.amounts.len() != tx.outputs.len()
        || payload.outputs.len() != tx.outputs.len()
        || payload.openings.len() != tx.outputs.len()
    {
        return Err("coinbase lattice payload mismatch".to_string());
    }

    let split = coinbase_split(height, fees, streak);
    let mut expected = vec![split.miner];
    if split.treasury > 0 {
        expected.push(split.treasury);
    }
    if split.dev > 0 {
        expected.push(split.dev);
    }
    if split.premine > 0 {
        expected.push(split.premine);
    }
    if payload.amounts != expected {
        return Err("coinbase amounts incorrect".to_string());
    }

    let key = LatticeCommitmentKey::derive();
    for i in 0..tx.outputs.len() {
        let amount = payload.amounts[i];
        let opening: &CommitmentOpening = &payload.openings[i];
        let lattice_out: &LatticeOutput = &payload.outputs[i];
        let out = &tx.outputs[i];
        if opening.value != amount {
            return Err("coinbase opening amount mismatch".to_string());
        }
        if !verify_lattice_opening(&key, &lattice_out.commitment, opening) {
            return Err("coinbase opening invalid".to_string());
        }
        if !verify_lattice_range(&key, &lattice_out.commitment, &lattice_out.range_proof) {
            return Err("coinbase lattice range invalid".to_string());
        }
        if out.enc_amount != lattice_out.enc_amount
            || out.enc_blind != lattice_out.enc_blind
            || out.enc_level != lattice_out.enc_level
        {
            return Err("coinbase encrypted amount mismatch".to_string());
        }
        let lattice_out_pub = lattice_public_from_output(out)?;
        if lattice_out.stealth_address != lattice_out_pub {
            return Err("coinbase lattice stealth key mismatch".to_string());
        }
        if out.commitment != lattice_commitment_digest(&lattice_out.commitment) {
            return Err("coinbase commitment digest mismatch".to_string());
        }
    }
    Ok(())
}

fn coinbase_operator_identity(block: &Block) -> Option<[u8; 32]> {
    let coinbase = block.txs.first()?;
    if !coinbase.coinbase {
        return None;
    }
    let memo = coinbase.outputs.first()?.memo;
    if memo == [0u8; 32] {
        None
    } else {
        Some(memo)
    }
}

fn proposer_streak_for_height(
    ledger: &Ledger,
    height: u64,
    proposer: [u8; 32],
    current_timestamp_ms: u64,
) -> Result<u64, String> {
    if height == 0 {
        return Ok(1);
    }
    let mut streak = 1u64;
    let mut h = height.saturating_sub(1);
    let mut prev_ts = current_timestamp_ms;
    loop {
        let Some(block) = ledger.get_block(h)? else {
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
    Ok(streak)
}

fn streak_bonus_ppm(streak: u64) -> u64 {
    if streak <= 1 {
        return 0;
    }
    let mut multiplier_ppm = 1_000_000u64;
    let steps = streak
        .saturating_sub(1)
        .min(knox_types::STREAK_MAX_COUNT.saturating_sub(1));
    for _ in 0..steps {
        multiplier_ppm =
            multiplier_ppm.saturating_mul(1_000_000 + knox_types::STREAK_RATE_PPM) / 1_000_000;
    }
    let cap = knox_types::STREAK_CAP_MULTIPLIER_PPM;
    let capped = multiplier_ppm.min(cap);
    capped.saturating_sub(1_000_000)
}

fn header_link_hash(header: &knox_types::BlockHeader) -> Hash32 {
    hash_header_for_link(header)
}

fn verify_ring_members(ledger: &Ledger, input: &TxIn) -> bool {
    if input.ring.is_empty() {
        return false;
    }
    let ring_len = input.ring.len();
    let min_ring = knox_types::MIN_DECOY_COUNT + 1;
    let max_ring = knox_types::MAX_DECOY_COUNT + 1;
    if ring_len < min_ring || ring_len > max_ring {
        return false;
    }
    let mut seen_members = HashSet::new();
    let tip = ledger.height().unwrap_or(0);
    for member in &input.ring {
        if !seen_members.insert((member.out_ref.tx, member.out_ref.index)) {
            return false;
        }
        let out = match output_by_ref(ledger, &member.out_ref) {
            Ok(Some(o)) => o,
            _ => return false,
        };
        if out.one_time_pub != member.one_time_pub
            || out.commitment != member.commitment
            || out.lattice_spend_pub != member.lattice_spend_pub
        {
            return false;
        }
        let out_h = match output_height(ledger, &member.out_ref) {
            Ok(Some(h)) => h,
            _ => return false,
        };
        if tip.saturating_sub(out_h) < knox_types::MIN_DECOY_AGE_BLOCKS {
            return false;
        }
    }
    true
}

fn verify_lattice_ring_linkage(input: &TxIn, lattice_input: &LatticeInput) -> bool {
    if input.ring.len() != lattice_input.ring.len() {
        return false;
    }
    for (outer, inner) in input.ring.iter().zip(lattice_input.ring.iter()) {
        let Ok(expected) = lattice_public_from_member(outer) else {
            return false;
        };
        if *inner != expected {
            return false;
        }
    }
    true
}

fn lattice_public_from_member(member: &RingMember) -> Result<LatticePublicKey, String> {
    let poly = knox_lattice::Poly::from_bytes(&member.lattice_spend_pub)
        .map_err(|_| "ring member lattice public key invalid".to_string())?;
    Ok(LatticePublicKey { p: poly })
}

fn lattice_public_from_output(out: &TxOut) -> Result<LatticePublicKey, String> {
    let poly = knox_lattice::Poly::from_bytes(&out.lattice_spend_pub)
        .map_err(|_| "output lattice public key invalid".to_string())?;
    Ok(LatticePublicKey { p: poly })
}

fn verify_quorum_certificate(
    qc: &QuorumCertificate,
    validators: &[LatticePublicKey],
    slashed: &[u16],
) -> Result<(), String> {
    if validators.is_empty() {
        return Err("qc cannot be verified without validators".to_string());
    }
    let quorum = (validators.len() * 2 / 3) + 1;
    let mut valid = 0usize;
    let mut seen = HashSet::new();
    for sig in &qc.sigs {
        if !seen.insert(sig.validator) {
            continue;
        }
        if slashed.contains(&sig.validator) {
            continue;
        }
        let Some(pk) = validators.get(sig.validator as usize) else {
            continue;
        };
        let vote = Vote {
            height: qc.height,
            round: qc.round,
            block_hash: qc.block_hash,
            voter: sig.validator,
            sig: sig.sig.clone(),
        };
        let hash = hash_vote_for_signing(&vote);
        if verify_consensus(pk, &hash.0, &sig.sig) {
            valid += 1;
        }
    }
    if valid < quorum {
        return Err(format!(
            "quorum certificate has insufficient valid signatures: {valid}/{quorum}"
        ));
    }
    Ok(())
}

fn verify_diamond_authenticator_cert(
    block: &Block,
    authenticators: &[LatticePublicKey],
    quorum: usize,
) -> Result<(), String> {
    const AUTH_BUNDLE_TAG: &[u8] = b"knox-auth-v1";
    let sigs: Vec<Vec<u8>> = if block.proposer_sig.starts_with(AUTH_BUNDLE_TAG) {
        let payload = &block.proposer_sig[AUTH_BUNDLE_TAG.len()..];
        let (decoded, _): (Vec<Vec<u8>>, usize) =
            bincode::decode_from_slice(payload, bincode::config::standard())
                .map_err(|e| format!("auth bundle decode failed: {e}"))?;
        decoded
    } else {
        vec![block.proposer_sig.clone()]
    };
    if sigs.is_empty() {
        return Err("missing diamond authenticator signature(s)".to_string());
    }
    let msg = hash_header_for_signing(&block.header);
    let mut matched = HashSet::new();
    for sig in &sigs {
        for (idx, pk) in authenticators.iter().enumerate() {
            if matched.contains(&idx) {
                continue;
            }
            if verify_consensus(pk, &msg.0, sig) {
                matched.insert(idx);
                break;
            }
        }
    }
    if matched.len() < quorum {
        return Err(format!(
            "diamond authenticator quorum not met: {}/{}",
            matched.len(),
            quorum
        ));
    }
    Ok(())
}

fn verify_slashes(block: &Block, validators: &[LatticePublicKey]) -> Result<(), String> {
    if block.slashes.is_empty() {
        return Ok(());
    }
    if validators.is_empty() {
        return Err("slash evidence cannot be verified without validator set".to_string());
    }
    let mut seen = HashSet::new();
    for ev in &block.slashes {
        let a = &ev.vote_a;
        let b = &ev.vote_b;
        if a.voter != b.voter {
            return Err("slash evidence voter mismatch".to_string());
        }
        if a.height != b.height || a.round != b.round {
            return Err("slash evidence height/round mismatch".to_string());
        }
        if a.block_hash == b.block_hash {
            return Err("slash evidence identical block hash".to_string());
        }
        let key = (a.height, a.round, a.voter);
        if !seen.insert(key) {
            return Err("duplicate slash evidence".to_string());
        }
        verify_vote_sig(validators, a)?;
        verify_vote_sig(validators, b)?;
    }
    Ok(())
}

fn verify_vote_sig(validators: &[LatticePublicKey], vote: &knox_types::Vote) -> Result<(), String> {
    let pk = validators
        .get(vote.voter as usize)
        .ok_or_else(|| "slash evidence voter out of range".to_string())?;
    let hash = knox_types::hash_vote_for_signing(vote);
    if !verify_consensus(pk, &hash.0, &vote.sig) {
        return Err("slash evidence signature invalid".to_string());
    }
    Ok(())
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

fn lattice_commitment_digest(commitment: &knox_lattice::LatticeCommitment) -> [u8; 32] {
    hash_bytes(&commitment.to_bytes()).0
}

fn tx_signing_hash(tx: &Transaction) -> Hash32 {
    tx_signing_hash_impl(tx, true)
}

fn tx_lattice_signing_hash(tx: &Transaction) -> Hash32 {
    tx_signing_hash_impl(tx, false)
}

fn tx_signing_hash_impl(tx: &Transaction, include_extra: bool) -> Hash32 {
    let mut data = Vec::new();
    data.extend_from_slice(b"knox-tx-sign-v1");
    data.extend_from_slice(&tx.version.to_le_bytes());
    data.push(if tx.coinbase { 1 } else { 0 });
    data.extend_from_slice(&(tx.inputs.len() as u32).to_le_bytes());
    for input in &tx.inputs {
        data.extend_from_slice(&(input.ring.len() as u32).to_le_bytes());
        for member in &input.ring {
            data.extend_from_slice(&member.out_ref.tx.0);
            data.extend_from_slice(&member.out_ref.index.to_le_bytes());
            data.extend_from_slice(&member.one_time_pub);
            data.extend_from_slice(&member.commitment);
            data.extend_from_slice(&(member.lattice_spend_pub.len() as u32).to_le_bytes());
            data.extend_from_slice(&member.lattice_spend_pub);
        }
        data.extend_from_slice(&input.key_image);
        data.extend_from_slice(&input.pseudo_commit);
    }
    data.extend_from_slice(&(tx.outputs.len() as u32).to_le_bytes());
    for out in &tx.outputs {
        data.extend_from_slice(&out.one_time_pub);
        data.extend_from_slice(&out.tx_pub);
        data.extend_from_slice(&out.commitment);
        data.extend_from_slice(&(out.lattice_spend_pub.len() as u32).to_le_bytes());
        data.extend_from_slice(&out.lattice_spend_pub);
        data.extend_from_slice(&out.enc_amount);
        data.extend_from_slice(&out.enc_blind);
        data.extend_from_slice(&out.enc_level.to_le_bytes());
        data.extend_from_slice(&out.memo);
    }
    data.extend_from_slice(&tx.fee.to_le_bytes());
    if include_extra {
        data.extend_from_slice(&(tx.extra.len() as u32).to_le_bytes());
        data.extend_from_slice(&tx.extra);
    } else {
        data.extend_from_slice(&0u32.to_le_bytes());
    }
    hash_bytes(&data)
}

fn tx_hash(tx: &Transaction) -> Hash32 {
    let mut data = Vec::new();
    data.extend_from_slice(b"knox-tx-hash-v1");
    data.extend_from_slice(&tx_signing_hash(tx).0);
    data.extend_from_slice(&(tx.inputs.len() as u32).to_le_bytes());
    for input in &tx.inputs {
        data.extend_from_slice(&input.signature.c1);
        data.extend_from_slice(&(input.signature.responses.len() as u32).to_le_bytes());
        for row in &input.signature.responses {
            data.extend_from_slice(&(row.len() as u32).to_le_bytes());
            for s in row {
                data.extend_from_slice(s);
            }
        }
        data.extend_from_slice(&(input.signature.key_images.len() as u32).to_le_bytes());
        for ki in &input.signature.key_images {
            data.extend_from_slice(ki);
        }
    }
    data.extend_from_slice(&(tx.outputs.len() as u32).to_le_bytes());
    for out in &tx.outputs {
        data.extend_from_slice(&out.range_proof.a);
        data.extend_from_slice(&out.range_proof.s);
        data.extend_from_slice(&out.range_proof.t1);
        data.extend_from_slice(&out.range_proof.t2);
        data.extend_from_slice(&out.range_proof.tau_x);
        data.extend_from_slice(&out.range_proof.mu);
        data.extend_from_slice(&out.range_proof.t_hat);
        data.extend_from_slice(&(out.range_proof.ip_proof.l_vec.len() as u32).to_le_bytes());
        for l in &out.range_proof.ip_proof.l_vec {
            data.extend_from_slice(l);
        }
        data.extend_from_slice(&(out.range_proof.ip_proof.r_vec.len() as u32).to_le_bytes());
        for r in &out.range_proof.ip_proof.r_vec {
            data.extend_from_slice(r);
        }
        data.extend_from_slice(&out.range_proof.ip_proof.a);
        data.extend_from_slice(&out.range_proof.ip_proof.b);
    }
    data.extend_from_slice(&(tx.coinbase_proof.len() as u32).to_le_bytes());
    for sig in &tx.coinbase_proof {
        data.extend_from_slice(sig);
    }
    hash_bytes(&data)
}

fn store_output(db: &Db, out_ref: &OutputRef, output: &TxOut, height: u64) -> Result<(), String> {
    let key = output_key(out_ref);
    let bytes =
        bincode::encode_to_vec(output, bincode::config::standard()).map_err(|e| e.to_string())?;
    db.put(&key, &bytes)?;
    db.put(&output_height_key(out_ref), &height.to_le_bytes())
}

fn spent_key(key_image: &[u8; 32]) -> [u8; 33] {
    let mut key = [0u8; 33];
    key[0] = b's';
    key[1..].copy_from_slice(key_image);
    key
}

fn output_height_key(out_ref: &OutputRef) -> Vec<u8> {
    let mut key = Vec::with_capacity(1 + 32 + 2);
    key.push(b'h');
    key.extend_from_slice(&out_ref.tx.0);
    key.extend_from_slice(&out_ref.index.to_le_bytes());
    key
}

fn output_key(out_ref: &OutputRef) -> Vec<u8> {
    let mut key = Vec::with_capacity(1 + 32 + 2);
    key.push(b'o');
    key.extend_from_slice(&out_ref.tx.0);
    key.extend_from_slice(&out_ref.index.to_le_bytes());
    key
}

fn decoy_bucket_key(height: u64) -> [u8; 9] {
    let mut key = [0u8; 9];
    key[0] = b'd';
    key[1..].copy_from_slice(&height.to_le_bytes());
    key
}

fn output_height(ledger: &Ledger, out_ref: &OutputRef) -> Result<Option<u64>, String> {
    match ledger.db.get(&output_height_key(out_ref))? {
        Some(bytes) if bytes.len() == 8 => {
            let mut arr = [0u8; 8];
            arr.copy_from_slice(&bytes);
            Ok(Some(u64::from_le_bytes(arr)))
        }
        _ => Ok(None),
    }
}

fn output_by_ref(ledger: &Ledger, out_ref: &OutputRef) -> Result<Option<TxOut>, String> {
    let Some(bytes) = ledger.db.get(&output_key(out_ref))? else {
        return Ok(None);
    };
    let (out, _): (TxOut, usize) =
        bincode::decode_from_slice(&bytes, bincode::config::standard().with_limit::<{ 32 * 1024 * 1024 }>())
            .map_err(|e| e.to_string())?;
    Ok(Some(out))
}

fn block_key(height: u64) -> [u8; 9] {
    let mut key = [0u8; 9];
    key[0] = b'b';
    key[1..].copy_from_slice(&height.to_le_bytes());
    key
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use knox_lattice::{
        consensus_public_from_secret, consensus_secret_from_seed, sign_consensus, LatticeCommitment,
        LatticeKeyImage, LatticeRingSignature, Poly,
    };
    use knox_types::{
        Hash32, MlsagSignature, OutputRef, QuorumCertificate, RingMember, Vote, VoteSignature,
    };

    fn sample_member(seed: u8, index: u16) -> RingMember {
        let mut material = Vec::with_capacity(3);
        material.push(seed);
        material.extend_from_slice(&index.to_le_bytes());
        let lattice_pub = Poly::from_hash(b"knox-ledger-test-member", &material).to_bytes();
        RingMember {
            out_ref: OutputRef {
                tx: Hash32([seed; 32]),
                index,
            },
            one_time_pub: [seed.wrapping_add(1); 32],
            commitment: [seed.wrapping_add(2); 32],
            lattice_spend_pub: lattice_pub,
        }
    }

    fn sample_lattice_input(ring: Vec<knox_lattice::LatticePublicKey>) -> LatticeInput {
        LatticeInput {
            ring,
            ring_signature: LatticeRingSignature {
                c0: [0u8; 32],
                responses: Vec::new(),
                key_image: LatticeKeyImage { tag: Poly::zero() },
            },
            key_image: LatticeKeyImage { tag: Poly::zero() },
            pseudo_commitment: LatticeCommitment { c: Poly::zero() },
        }
    }

    fn sample_txin(ring: Vec<RingMember>) -> TxIn {
        TxIn {
            ring,
            key_image: [0u8; 32],
            pseudo_commit: [0u8; 32],
            signature: MlsagSignature {
                c1: [0u8; 32],
                responses: Vec::new(),
                key_images: Vec::new(),
            },
        }
    }

    #[test]
    fn lattice_ring_linkage_accepts_exact_match() {
        let outer_ring = vec![
            sample_member(10, 0),
            sample_member(11, 1),
            sample_member(12, 2),
            sample_member(13, 3),
        ];
        let inner_ring = outer_ring
            .iter()
            .map(|m| lattice_public_from_member(m).expect("valid member lattice key"))
            .collect::<Vec<_>>();

        let txin = sample_txin(outer_ring);
        let lattice_input = sample_lattice_input(inner_ring);
        assert!(verify_lattice_ring_linkage(&txin, &lattice_input));
    }

    #[test]
    fn lattice_ring_linkage_rejects_any_mismatch() {
        let outer_ring = vec![
            sample_member(20, 0),
            sample_member(21, 1),
            sample_member(22, 2),
            sample_member(23, 3),
        ];
        let mut inner_ring = outer_ring
            .iter()
            .map(|m| lattice_public_from_member(m).expect("valid member lattice key"))
            .collect::<Vec<_>>();
        inner_ring[1] = knox_lattice::LatticePublicKey {
            p: Poly::from_hash(b"knox-ledger-test-signer", b"override-1"),
        };

        let txin = sample_txin(outer_ring);
        let lattice_input = sample_lattice_input(inner_ring);
        assert!(!verify_lattice_ring_linkage(&txin, &lattice_input));
    }

    #[test]
    fn lattice_ring_linkage_rejects_invalid_member_encoding() {
        let mut outer_ring = vec![sample_member(30, 0), sample_member(31, 1), sample_member(32, 2)];
        outer_ring[1].lattice_spend_pub = vec![1, 2, 3];
        let inner_ring = vec![
            knox_lattice::LatticePublicKey {
                p: Poly::from_hash(b"knox-ledger-test", b"0"),
            },
            knox_lattice::LatticePublicKey {
                p: Poly::from_hash(b"knox-ledger-test", b"1"),
            },
            knox_lattice::LatticePublicKey {
                p: Poly::from_hash(b"knox-ledger-test", b"2"),
            },
        ];

        let txin = sample_txin(outer_ring);
        let lattice_input = sample_lattice_input(inner_ring);
        assert!(!verify_lattice_ring_linkage(&txin, &lattice_input));
    }

    fn make_qc_sig(
        secret: &knox_lattice::LatticeSecretKey,
        validator: u16,
        height: u64,
        round: u32,
        block_hash: Hash32,
    ) -> VoteSignature {
        let vote = Vote {
            height,
            round,
            block_hash,
            voter: validator,
            sig: Vec::new(),
        };
        let hash = hash_vote_for_signing(&vote);
        let sig = sign_consensus(secret, &hash.0).expect("qc vote sign");
        VoteSignature { validator, sig }
    }

    #[test]
    fn qc_verification_requires_quorum_of_distinct_valid_signers() {
        let sk0 = consensus_secret_from_seed(&[0x51; 32]);
        let sk1 = consensus_secret_from_seed(&[0x52; 32]);
        let sk2 = consensus_secret_from_seed(&[0x53; 32]);
        let validators = vec![
            consensus_public_from_secret(&sk0),
            consensus_public_from_secret(&sk1),
            consensus_public_from_secret(&sk2),
        ];
        let block_hash = Hash32([0xAB; 32]);

        let valid_qc = QuorumCertificate {
            height: 99,
            round: 4,
            block_hash,
            sigs: vec![
                make_qc_sig(&sk0, 0, 99, 4, block_hash),
                make_qc_sig(&sk1, 1, 99, 4, block_hash),
                make_qc_sig(&sk2, 2, 99, 4, block_hash),
            ],
        };
        assert!(verify_quorum_certificate(&valid_qc, &validators, &[]).is_ok());

        let dup = make_qc_sig(&sk0, 0, 99, 4, block_hash);
        let duplicate_only = QuorumCertificate {
            height: 99,
            round: 4,
            block_hash,
            sigs: vec![dup.clone(), dup.clone(), dup],
        };
        assert!(verify_quorum_certificate(&duplicate_only, &validators, &[]).is_err());

        let forged = QuorumCertificate {
            height: 99,
            round: 4,
            block_hash,
            sigs: vec![
                make_qc_sig(&sk0, 0, 99, 4, block_hash),
                VoteSignature {
                    validator: 1,
                    sig: vec![0u8; 16],
                },
                make_qc_sig(&sk2, 2, 99, 4, block_hash),
            ],
        };
        assert!(verify_quorum_certificate(&forged, &validators, &[]).is_err());
    }
}
