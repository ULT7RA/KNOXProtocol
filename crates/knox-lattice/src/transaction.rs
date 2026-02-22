use crate::commitment::{
    commit_value, verify_opening, CommitmentOpening, LatticeCommitment, LatticeCommitmentKey,
};
use crate::key_image::derive_key_image_id;
use crate::params::{
    TX_BASE_SECURITY_BITS, TX_KDF_ROUND_BITS, TX_MAX_SECURITY_BITS, TX_SECURITY_GROWTH_PER_BLOCK,
};
use crate::poly::Poly;
use crate::range_proof::{prove_range_u64, verify_range_u64, LatticeRangeProof};
use crate::ring_sig::{verify_ring, LatticeKeyImage, LatticePublicKey, LatticeRingSignature};
use bincode::{Decode, Encode};
use std::collections::HashSet;

pub const LATTICE_TX_EXTRA_MAGIC: &[u8; 8] = b"KXLTXV1\0";

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct LatticeInput {
    pub ring: Vec<LatticePublicKey>,
    pub ring_signature: LatticeRingSignature,
    pub key_image: LatticeKeyImage,
    pub pseudo_commitment: LatticeCommitment,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct LatticeOutput {
    pub stealth_address: LatticePublicKey,
    pub ephemeral_public: LatticePublicKey,
    pub commitment: LatticeCommitment,
    pub range_proof: LatticeRangeProof,
    pub enc_amount: [u8; 32],
    pub enc_blind: [u8; 32],
    pub enc_level: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct LatticeTransaction {
    pub inputs: Vec<LatticeInput>,
    pub outputs: Vec<LatticeOutput>,
    pub fee: u64,
    pub fee_commitment: LatticeCommitment,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct LatticeOutputOpening {
    pub amount: u64,
    pub opening: CommitmentOpening,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct LatticeTransactionView {
    pub inputs: Vec<[u8; 32]>,
    pub outputs: Vec<[u8; 32]>,
    pub fee: u64,
}

pub fn tx_hardening_level(height: u64) -> u32 {
    let growth = (height as u128)
        .saturating_mul(TX_SECURITY_GROWTH_PER_BLOCK as u128)
        .min(u32::MAX as u128) as u32;
    TX_BASE_SECURITY_BITS
        .saturating_add(growth)
        .min(TX_MAX_SECURITY_BITS)
}

pub fn kdf_rounds_for_level(level: u32) -> u32 {
    if level <= TX_BASE_SECURITY_BITS {
        return 1;
    }
    1 + (level - TX_BASE_SECURITY_BITS) / TX_KDF_ROUND_BITS
}

pub fn encrypt_amount_with_level(
    shared_secret: &[u8; 32],
    amount: u64,
    blind: &[u8; 32],
    level: u32,
) -> ([u8; 32], [u8; 32]) {
    let key_amount = derive_mask(b"knox-enc-amount", shared_secret, level);
    let key_blind = derive_mask(b"knox-enc-blind", shared_secret, level);
    let mut amount_block = derive_mask(b"knox-enc-amount-mask", shared_secret, level);
    amount_block[..8].copy_from_slice(&amount.to_le_bytes());

    let mut enc_amount = [0u8; 32];
    let mut enc_blind = [0u8; 32];
    for i in 0..32 {
        enc_amount[i] = amount_block[i] ^ key_amount[i];
        enc_blind[i] = blind[i] ^ key_blind[i];
    }
    (enc_amount, enc_blind)
}

pub fn decrypt_amount_with_level(
    shared_secret: &[u8; 32],
    enc_amount: [u8; 32],
    enc_blind: [u8; 32],
    level: u32,
) -> (u64, [u8; 32]) {
    let key_amount = derive_mask(b"knox-enc-amount", shared_secret, level);
    let key_blind = derive_mask(b"knox-enc-blind", shared_secret, level);

    let mut amt = [0u8; 8];
    for i in 0..8 {
        amt[i] = enc_amount[i] ^ key_amount[i];
    }
    let amount = u64::from_le_bytes(amt);

    let mut blind = [0u8; 32];
    for i in 0..32 {
        blind[i] = enc_blind[i] ^ key_blind[i];
    }
    (amount, blind)
}

pub fn build_private_output(
    key: &LatticeCommitmentKey,
    stealth_address: LatticePublicKey,
    ephemeral_public: LatticePublicKey,
    amount: u64,
    level: u32,
    shared_secret: &[u8; 32],
) -> Result<(LatticeOutput, LatticeOutputOpening), String> {
    let randomness = Poly::random_short_checked()?;
    let commitment = commit_value(key, amount, &randomness);
    let opening = CommitmentOpening {
        value: amount,
        randomness,
    };
    let range_proof = prove_range_u64(key, &commitment, &opening)?;

    let mut blind_bytes = [0u8; 32];
    let r_bytes = opening.randomness.to_bytes();
    blind_bytes.copy_from_slice(&blake3::hash(&r_bytes).as_bytes()[..32]);
    let (enc_amount, enc_blind) =
        encrypt_amount_with_level(shared_secret, amount, &blind_bytes, level);

    Ok((
        LatticeOutput {
            stealth_address,
            ephemeral_public,
            commitment,
            range_proof,
            enc_amount,
            enc_blind,
            enc_level: level,
        },
        LatticeOutputOpening { amount, opening },
    ))
}

pub fn verify_output(
    key: &LatticeCommitmentKey,
    out: &LatticeOutput,
    opening: &LatticeOutputOpening,
) -> bool {
    if opening.amount != opening.opening.value {
        return false;
    }
    if !verify_opening(key, &out.commitment, &opening.opening) {
        return false;
    }
    verify_range_u64(key, &out.commitment, &out.range_proof)
}

pub fn verify_transaction(
    key: &LatticeCommitmentKey,
    tx: &LatticeTransaction,
    message: &[u8],
) -> Result<(), String> {
    if tx.outputs.is_empty() {
        return Err("transaction has no outputs".to_string());
    }

    let mut seen_images = HashSet::new();
    for input in &tx.inputs {
        if input.ring.is_empty() {
            return Err("input ring is empty".to_string());
        }
        if input.key_image != input.ring_signature.key_image {
            return Err("key image mismatch".to_string());
        }
        let image_id = derive_key_image_id(&input.key_image);
        if !seen_images.insert(image_id) {
            return Err("duplicate key image".to_string());
        }
        if !verify_ring(message, &input.ring, &input.ring_signature) {
            return Err("ring signature failed".to_string());
        }
    }

    for out in &tx.outputs {
        if !verify_range_u64(key, &out.commitment, &out.range_proof) {
            return Err("range proof failed".to_string());
        }
    }

    let mut net = tx.fee_commitment.c.clone();
    for input in &tx.inputs {
        net = net.add(&input.pseudo_commitment.c);
    }
    for out in &tx.outputs {
        net = net.sub(&out.commitment.c);
    }
    if net != Poly::zero() {
        return Err("homomorphic balance failed".to_string());
    }

    Ok(())
}

pub fn fee_commitment(key: &LatticeCommitmentKey, fee: u64) -> LatticeCommitment {
    commit_value(key, fee, &Poly::zero())
}

pub fn signing_message(tx: &LatticeTransaction) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"knox-lattice-tx-signing-view");

    h.update(&(tx.inputs.len() as u32).to_le_bytes());
    for input in &tx.inputs {
        h.update(&derive_key_image_id(&input.key_image));
    }

    h.update(&(tx.outputs.len() as u32).to_le_bytes());
    for out in &tx.outputs {
        let mut out_hash = blake3::Hasher::new();
        out_hash.update(b"knox-lattice-output-id");
        out_hash.update(&out.commitment.to_bytes());
        out_hash.update(&out.enc_amount);
        out_hash.update(&out.enc_blind);
        out_hash.update(&out.enc_level.to_le_bytes());
        h.update(out_hash.finalize().as_bytes());
    }

    h.update(&tx.fee.to_le_bytes());
    *h.finalize().as_bytes()
}

pub fn encode_lattice_tx_extra(tx: &LatticeTransaction) -> Result<Vec<u8>, String> {
    let mut out = Vec::from(LATTICE_TX_EXTRA_MAGIC.as_slice());
    let payload =
        bincode::encode_to_vec(tx, bincode::config::standard()).map_err(|e| e.to_string())?;
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&payload);
    Ok(out)
}

pub fn decode_lattice_tx_extra(extra: &[u8]) -> Result<LatticeTransaction, String> {
    if extra.len() < LATTICE_TX_EXTRA_MAGIC.len() + 4 {
        return Err("lattice payload missing".to_string());
    }
    if &extra[..LATTICE_TX_EXTRA_MAGIC.len()] != LATTICE_TX_EXTRA_MAGIC {
        return Err("not a lattice payload".to_string());
    }
    let mut len_bytes = [0u8; 4];
    len_bytes
        .copy_from_slice(&extra[LATTICE_TX_EXTRA_MAGIC.len()..LATTICE_TX_EXTRA_MAGIC.len() + 4]);
    let payload_len = u32::from_le_bytes(len_bytes) as usize;
    let payload_start = LATTICE_TX_EXTRA_MAGIC.len() + 4;
    let payload_end = payload_start.saturating_add(payload_len);
    if payload_end > extra.len() {
        return Err("truncated lattice payload".to_string());
    }
    if payload_end != extra.len() {
        return Err("invalid lattice payload trailing bytes".to_string());
    }
    let (decoded, consumed): (LatticeTransaction, usize) = bincode::decode_from_slice(
        &extra[payload_start..payload_end],
        bincode::config::standard(),
    )
    .map_err(|e| e.to_string())?;
    if consumed != payload_len {
        return Err("invalid lattice payload length".to_string());
    }
    Ok(decoded)
}

fn derive_mask(domain: &[u8], shared_secret: &[u8; 32], level: u32) -> [u8; 32] {
    let rounds = kdf_rounds_for_level(level);

    let mut hasher = blake3::Hasher::new();
    hasher.update(b"knox-lattice-tx-kdf");
    hasher.update(domain);
    hasher.update(&level.to_le_bytes());
    hasher.update(shared_secret);
    let mut state = *hasher.finalize().as_bytes();

    for round in 0..rounds {
        let mut step = blake3::Hasher::new();
        step.update(b"knox-lattice-tx-kdf-round");
        step.update(domain);
        step.update(&level.to_le_bytes());
        step.update(&round.to_le_bytes());
        step.update(shared_secret);
        step.update(&state);
        state = *step.finalize().as_bytes();
    }

    state
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_image::derive_key_image_id;
    use crate::ring_sig::{key_image, keygen, sign_ring};

    #[test]
    fn encryption_round_trip_by_level() {
        let shared = [7u8; 32];
        let blind = [9u8; 32];
        let amount = 42_123_987u64;
        let level = tx_hardening_level(500);

        let (enc_amount, enc_blind) = encrypt_amount_with_level(&shared, amount, &blind, level);
        let (decoded_amount, decoded_blind) =
            decrypt_amount_with_level(&shared, enc_amount, enc_blind, level);
        assert_eq!(decoded_amount, amount);
        assert_eq!(decoded_blind, blind);
    }

    #[test]
    fn higher_level_changes_ciphertext() {
        let shared = [3u8; 32];
        let blind = [5u8; 32];
        let amount = 123u64;
        let l1 = tx_hardening_level(1);
        let l2 = tx_hardening_level(1500);
        let c1 = encrypt_amount_with_level(&shared, amount, &blind, l1);
        let c2 = encrypt_amount_with_level(&shared, amount, &blind, l2);
        assert_ne!(c1, c2);
    }

    #[test]
    fn tx_verification_checks_balance_and_images() {
        let key = LatticeCommitmentKey::derive();
        let (sk0, pk0) = keygen();
        let (_sk1, pk1) = keygen();
        let (_sk2, pk2) = keygen();
        let ring = vec![pk0.clone(), pk1, pk2];
        let msg = b"tx-msg";
        let sig = sign_ring(msg, &ring, 0, &sk0).expect("ring sign");
        let image = key_image(&sk0, &pk0);

        let (out, out_open) = build_private_output(
            &key,
            pk0.clone(),
            pk0,
            100,
            tx_hardening_level(1),
            &[8u8; 32],
        )
        .expect("output");
        assert!(verify_output(&key, &out, &out_open));
        let pseudo = out.commitment.clone();

        let tx = LatticeTransaction {
            inputs: vec![LatticeInput {
                ring,
                ring_signature: sig,
                key_image: image.clone(),
                pseudo_commitment: pseudo,
            }],
            outputs: vec![out],
            fee: 0,
            fee_commitment: fee_commitment(&key, 0),
        };

        assert!(verify_transaction(&key, &tx, msg).is_ok());

        let dup = LatticeTransaction {
            inputs: vec![
                tx.inputs[0].clone(),
                LatticeInput {
                    ring: tx.inputs[0].ring.clone(),
                    ring_signature: tx.inputs[0].ring_signature.clone(),
                    key_image: image,
                    pseudo_commitment: tx.inputs[0].pseudo_commitment.clone(),
                },
            ],
            outputs: tx.outputs.clone(),
            fee: 0,
            fee_commitment: fee_commitment(&key, 0),
        };
        let err = verify_transaction(&key, &dup, msg).expect_err("duplicate image");
        assert!(err.contains("duplicate key image"));
        assert_eq!(
            derive_key_image_id(&dup.inputs[0].key_image),
            derive_key_image_id(&dup.inputs[1].key_image)
        );
    }

    #[test]
    fn ring_signature_fails_on_wrong_message() {
        let key = LatticeCommitmentKey::derive();
        let (sk, pk) = keygen();
        let (_a, p1) = keygen();
        let (_b, p2) = keygen();
        let ring = vec![pk.clone(), p1, p2];
        let sig = sign_ring(b"m1", &ring, 0, &sk).expect("ring");
        let input = LatticeInput {
            ring,
            ring_signature: sig,
            key_image: key_image(&sk, &pk),
            pseudo_commitment: commit_value(&key, 50, &Poly::zero()),
        };
        let (out, _) =
            build_private_output(&key, pk.clone(), pk, 50, tx_hardening_level(2), &[1u8; 32])
                .expect("out");
        let tx = LatticeTransaction {
            inputs: vec![input],
            outputs: vec![out],
            fee: 0,
            fee_commitment: fee_commitment(&key, 0),
        };
        let err = verify_transaction(&key, &tx, b"m2").expect_err("must fail");
        assert!(err.contains("ring signature failed"));
    }

    #[test]
    fn decode_lattice_tx_extra_rejects_trailing_bytes() {
        let tx = LatticeTransaction {
            inputs: Vec::new(),
            outputs: Vec::new(),
            fee: 0,
            fee_commitment: LatticeCommitment { c: Poly::zero() },
        };
        let mut encoded = encode_lattice_tx_extra(&tx).expect("encode lattice extra");
        encoded.extend_from_slice(&[0xAA, 0xBB]);
        let err = decode_lattice_tx_extra(&encoded).expect_err("trailing bytes must fail");
        assert!(err.contains("trailing bytes"));
    }
}
