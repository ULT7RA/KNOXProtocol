use crate::commitment::{commit_value, CommitmentOpening, LatticeCommitment, LatticeCommitmentKey};
use crate::range_proof::{prove_range_u64, LatticeRangeProof};
use crate::transaction::tx_hardening_level;
use crate::transaction::LatticeOutput;
use bincode::{Decode, Encode};

pub const LATTICE_COINBASE_EXTRA_MAGIC: &[u8; 7] = b"KXCBV1\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CoinbaseSplit {
    pub streak: u64,
    pub miner: u64,
    pub treasury: u64,
    pub dev: u64,
    pub premine: u64,
    pub total: u64,
    pub enc_level: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateCoinbaseOutput {
    pub amount: u64,
    pub commitment: LatticeCommitment,
    pub opening: CommitmentOpening,
    pub range_proof: LatticeRangeProof,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct LatticeCoinbasePayload {
    pub amounts: Vec<u64>,
    pub outputs: Vec<LatticeOutput>,
    pub openings: Vec<CommitmentOpening>,
}

pub fn coinbase_split(height: u64, fees: u64, streak: u64) -> CoinbaseSplit {
    let blocks_per_year = (365u64 * 24 * 60 * 60 * 1000) / knox_types::TARGET_BLOCK_TIME_MS;
    let emission_blocks = blocks_per_year.saturating_mul(knox_types::EMISSION_YEARS);
    let base = knox_types::PUBLIC_SUPPLY / emission_blocks.max(1);
    let remainder = knox_types::PUBLIC_SUPPLY % emission_blocks.max(1);
    let public_reward = if height < remainder { base + 1 } else { base };
    let treasury = public_reward / 100;
    let miner_base = public_reward.saturating_sub(treasury);
    let miner = apply_streak_reward(miner_base, streak).saturating_add(fees);
    let dev = dev_reward(height, blocks_per_year);
    let premine = if height == 0 {
        knox_types::GENESIS_PREMINE
    } else {
        0
    };
    let total = miner
        .saturating_add(treasury)
        .saturating_add(dev)
        .saturating_add(premine);
    CoinbaseSplit {
        streak,
        miner,
        treasury,
        dev,
        premine,
        total,
        enc_level: tx_hardening_level(height),
    }
}

pub fn apply_streak_reward(base: u64, streak: u64) -> u64 {
    if base == 0 {
        return 0;
    }
    let mut reward = base;
    let steps = streak
        .saturating_sub(1)
        .min(knox_types::STREAK_MAX_COUNT.saturating_sub(1));
    for _ in 0..steps {
        reward = reward.saturating_mul(1_000_000 + knox_types::STREAK_RATE_PPM) / 1_000_000;
    }
    let cap = base.saturating_mul(knox_types::STREAK_CAP_MULTIPLIER_PPM) / 1_000_000;
    reward.min(cap.max(base))
}

pub fn private_coinbase_outputs(
    key: &LatticeCommitmentKey,
    split: CoinbaseSplit,
) -> Result<Vec<PrivateCoinbaseOutput>, String> {
    let amounts = [split.miner, split.treasury, split.dev, split.premine];
    let mut out = Vec::new();
    for amount in amounts {
        if amount == 0 {
            continue;
        }
        let opening = CommitmentOpening {
            value: amount,
            randomness: crate::poly::Poly::random_short_checked()?,
        };
        let commitment = commit_value(key, amount, &opening.randomness);
        let range_proof = prove_range_u64(key, &commitment, &opening)?;
        out.push(PrivateCoinbaseOutput {
            amount,
            commitment,
            opening,
            range_proof,
        });
    }
    Ok(out)
}

pub fn encode_coinbase_payload(payload: &LatticeCoinbasePayload) -> Result<Vec<u8>, String> {
    let mut out = Vec::from(LATTICE_COINBASE_EXTRA_MAGIC.as_slice());
    let bytes =
        bincode::encode_to_vec(payload, bincode::config::standard()).map_err(|e| e.to_string())?;
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&bytes);
    Ok(out)
}

pub fn decode_coinbase_payload(extra: &[u8]) -> Result<LatticeCoinbasePayload, String> {
    if extra.len() < LATTICE_COINBASE_EXTRA_MAGIC.len() + 4 {
        return Err("coinbase lattice payload missing".to_string());
    }
    if &extra[..LATTICE_COINBASE_EXTRA_MAGIC.len()] != LATTICE_COINBASE_EXTRA_MAGIC {
        return Err("coinbase lattice payload magic mismatch".to_string());
    }
    let mut len = [0u8; 4];
    len.copy_from_slice(
        &extra[LATTICE_COINBASE_EXTRA_MAGIC.len()..LATTICE_COINBASE_EXTRA_MAGIC.len() + 4],
    );
    let payload_len = u32::from_le_bytes(len) as usize;
    let start = LATTICE_COINBASE_EXTRA_MAGIC.len() + 4;
    let end = start.saturating_add(payload_len);
    if end > extra.len() {
        return Err("coinbase lattice payload truncated".to_string());
    }
    if end != extra.len() {
        return Err("coinbase lattice payload trailing bytes".to_string());
    }
    let (payload, consumed): (LatticeCoinbasePayload, usize) =
        bincode::decode_from_slice(&extra[start..end], bincode::config::standard().with_limit::<{ 32 * 1024 * 1024 }>())
            .map_err(|e| e.to_string())?;
    if consumed != payload_len {
        return Err("coinbase lattice payload invalid length".to_string());
    }
    Ok(payload)
}

fn dev_reward(height: u64, blocks_per_year: u64) -> u64 {
    if knox_types::DEV_FUND_TOTAL == 0 || knox_types::DEV_FUND_VEST_YEARS == 0 {
        return 0;
    }
    let dev_blocks = blocks_per_year.saturating_mul(knox_types::DEV_FUND_VEST_YEARS as u64);
    if dev_blocks == 0 || height >= dev_blocks {
        return 0;
    }
    let base = knox_types::DEV_FUND_TOTAL / dev_blocks;
    let remainder = knox_types::DEV_FUND_TOTAL % dev_blocks;
    if height < remainder {
        base + 1
    } else {
        base
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commitment::LatticeCommitmentKey;
    use crate::range_proof::verify_range_u64;

    #[test]
    fn coinbase_split_balances() {
        let split = coinbase_split(0, 17, 1);
        assert_eq!(
            split.total,
            split.miner + split.treasury + split.dev + split.premine
        );
        assert!(split.premine > 0);
    }

    #[test]
    fn private_coinbase_outputs_prove_ranges() {
        let key = LatticeCommitmentKey::derive();
        let split = coinbase_split(0, 0, 1);
        let outputs = private_coinbase_outputs(&key, split).expect("outputs");
        assert!(!outputs.is_empty());
        for out in outputs {
            assert!(verify_range_u64(&key, &out.commitment, &out.range_proof));
        }
    }

    #[test]
    fn streak_reward_increases_and_caps() {
        let base = 1_000_000u64;
        let r1 = apply_streak_reward(base, 1);
        let r2 = apply_streak_reward(base, 2);
        let r34 = apply_streak_reward(base, 34);
        let r99 = apply_streak_reward(base, 99);
        assert_eq!(r1, base);
        assert!(r2 > r1);
        assert!(r34 >= r2);
        assert_eq!(r99, r34);
    }

    #[test]
    fn decode_coinbase_payload_rejects_trailing_bytes() {
        let payload = LatticeCoinbasePayload {
            amounts: Vec::new(),
            outputs: Vec::new(),
            openings: Vec::new(),
            message: None,
        };
        let mut encoded = encode_coinbase_payload(&payload).expect("encode payload");
        encoded.extend_from_slice(&[0xCC, 0xDD]);
        let err = decode_coinbase_payload(&encoded).expect_err("trailing bytes must fail");
        assert!(err.contains("trailing bytes"));
    }
}
