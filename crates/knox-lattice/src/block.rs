use knox_types::{BlockHeader, LatticeProof};

use crate::immunity::ImmunityState;
use crate::mining::verify_block_proof;
use crate::transaction::{verify_transaction, LatticeTransaction};
use crate::LatticeCommitmentKey;

#[derive(Clone, Debug)]
pub struct LatticeBlockView {
    pub header: BlockHeader,
    pub proof: LatticeProof,
    pub immunity_hash: [u8; 32],
    pub txs: Vec<LatticeTransaction>,
}

impl LatticeBlockView {
    pub fn from_parts(
        header: BlockHeader,
        proof: LatticeProof,
        immunity: &ImmunityState,
        txs: Vec<LatticeTransaction>,
    ) -> Self {
        Self {
            header,
            proof,
            immunity_hash: immunity.hash(),
            txs,
        }
    }
}

pub fn verify_block_view(
    key: &LatticeCommitmentKey,
    block: &LatticeBlockView,
    message_domain: &[u8],
) -> Result<(), String> {
    if !verify_block_proof(&block.header, &block.proof) {
        return Err("invalid PoTM proof".to_string());
    }
    if block.txs.is_empty() {
        return Err("block has no transactions".to_string());
    }
    for (idx, tx) in block.txs.iter().enumerate() {
        let mut msg = Vec::new();
        msg.extend_from_slice(message_domain);
        msg.extend_from_slice(&block.header.height.to_le_bytes());
        msg.extend_from_slice(&(idx as u64).to_le_bytes());
        verify_transaction(key, tx, &msg)?;
    }
    Ok(())
}

pub fn apply_block_immunity(prev: &ImmunityState, block: &LatticeBlockView) -> ImmunityState {
    let mut next = prev.clone();
    let short = short_from_contribution(&block.proof.clh_contribution);
    next.absorb_solution(&short, &block.proof.clh_contribution, block.header.height);
    next
}

fn short_from_contribution(bytes: &[u8; 32]) -> Vec<i64> {
    let mut out = Vec::with_capacity(32);
    for b in bytes {
        out.push((*b as i16 - 128) as i64);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coinbase::coinbase_split;
    use crate::commitment::LatticeCommitmentKey;
    use crate::mining::mine_block_proof;
    use crate::ring_sig::{key_image, keygen, sign_ring};
    use crate::transaction::{
        build_private_output, fee_commitment, tx_hardening_level, LatticeInput, LatticeTransaction,
    };
    use knox_types::{Hash32, QuorumCertificate};

    fn header(height: u64) -> BlockHeader {
        BlockHeader {
            version: 1,
            height,
            round: 0,
            prev: Hash32::ZERO,
            tx_root: Hash32::ZERO,
            slash_root: Hash32::ZERO,
            state_root: Hash32::ZERO,
            timestamp_ms: 0,
            proposer: [0u8; 32],
            qc: None::<QuorumCertificate>,
        }
    }

    #[test]
    fn immunity_advances_with_block() {
        let mut imm = ImmunityState::genesis();
        let h = header(1);
        let proof = mine_block_proof(&h, 1);
        let block = LatticeBlockView {
            header: h.clone(),
            proof: proof.clone(),
            immunity_hash: imm.hash(),
            txs: vec![dummy_tx()],
        };
        let next = apply_block_immunity(&imm, &block);
        assert_ne!(next.hash(), imm.hash());
        imm = next;
        assert!(imm.solutions_absorbed > 0);
    }

    #[test]
    fn verify_block_accepts_valid_tx_and_proof() {
        let key = LatticeCommitmentKey::derive();
        let h = header(1);
        let proof = mine_block_proof(&h, 7);
        let tx = dummy_tx();
        let block = LatticeBlockView {
            header: h,
            proof,
            immunity_hash: [0u8; 32],
            txs: vec![tx],
        };
        assert!(verify_block_view(&key, &block, b"knox-block").is_ok());
    }

    fn dummy_tx() -> LatticeTransaction {
        let key = LatticeCommitmentKey::derive();
        let (sk, pk0) = keygen();
        let (_a, pk1) = keygen();
        let (_b, pk2) = keygen();
        let ring = vec![pk0.clone(), pk1, pk2];
        let mut msg = Vec::new();
        msg.extend_from_slice(b"knox-block");
        msg.extend_from_slice(&1u64.to_le_bytes());
        msg.extend_from_slice(&0u64.to_le_bytes());
        let sig = sign_ring(&msg, &ring, 0, &sk).expect("ring");
        let (out, _) = build_private_output(
            &key,
            pk0.clone(),
            pk0.clone(),
            50,
            tx_hardening_level(1),
            &[9u8; 32],
        )
        .expect("out");
        let input = LatticeInput {
            ring,
            ring_signature: sig,
            key_image: key_image(&sk, &pk0),
            // Use matching commitment so transaction balance relation holds.
            pseudo_commitment: out.commitment.clone(),
        };
        let _ = coinbase_split(0, 0, 1);
        LatticeTransaction {
            inputs: vec![input],
            outputs: vec![out],
            fee: 0,
            fee_commitment: fee_commitment(&key, 0),
        }
    }
}
