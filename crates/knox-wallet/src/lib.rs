use argon2::Argon2;
use blake3::Hasher;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use getrandom::getrandom;
use knox_lattice::ring_sig::public_from_secret as lattice_public_from_secret;
use knox_lattice::{
    build_private_output, commit_value as lattice_commit_value, decode_coinbase_payload,
    decode_lattice_tx_extra,
    decrypt_amount_with_level, derive_key_image_id, encode_lattice_tx_extra,
    fee_commitment as lattice_fee_commitment, key_image as lattice_key_image,
    recover_one_time_secret as lattice_recover_one_time_secret, sign_ring as lattice_sign_ring,
    tx_hardening_level, LatticeCommitment, LatticeCommitmentKey, LatticeInput, LatticeOutput,
    LatticeOutputOpening, LatticePublicKey, LatticeRangeProof, LatticeSecretKey,
    LatticeStealthOutput, LatticeTransaction, Poly, scan_with_view_key,
};
use knox_lattice::stealth::send_to_stealth_with_ephemeral;
use knox_types::{
    hash_bytes as hash_tx_bytes, Address, Hash32, OutputRef, RingMember, Transaction, TxIn, TxOut,
    MAX_DECOY_COUNT, MIN_DECOY_COUNT,
};
use std::collections::HashSet;
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::OnceLock;
use std::time::Duration;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

const WALLET_MAGIC_V1: &[u8; 4] = b"PCW1";
const WALLET_MAGIC_V2: &[u8; 4] = b"PCW2";
const LATTICE_PUBKEY_BYTES: usize = knox_lattice::params::N * 2;
const WALLET_DECODE_LIMIT: usize = 32 * 1024 * 1024;
const DEFAULT_VISIBLE_SUBADDRESSES: u32 = 2;
const DEFAULT_SCAN_GAP: u32 = 32;

#[derive(Clone, Debug, bincode::Encode, bincode::Decode)]
pub struct Note {
    pub out_ref: OutputRef,
    pub one_time_pub: [u8; 32],
    pub tx_pub: [u8; 32],
    pub lattice_spend_pub: Vec<u8>,
    pub lattice_one_time_secret: Vec<u8>,
    pub one_time_secret: [u8; 32],
    pub commitment: [u8; 32],
    pub amount: u64,
    pub blinding: [u8; 32],
    pub key_image: [u8; 32],
    pub subaddress_index: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, bincode::Encode, bincode::Decode)]
pub enum RewardKind {
    Miner,
    Treasury,
    Dev,
    Premine,
}

#[derive(Clone, Debug, PartialEq, Eq, bincode::Encode, bincode::Decode)]
pub struct RewardRecord {
    pub block_height: u64,
    pub block_hash: Hash32,
    pub tx_hash: Hash32,
    pub output_index: u16,
    pub amount: u64,
    pub subaddress_index: u32,
    pub kind: RewardKind,
}

#[derive(Clone, Debug, bincode::Encode, bincode::Decode)]
pub struct WalletState {
    pub view_secret: [u8; 32],
    pub spend_secret: [u8; 32],
    pub view_public: [u8; 32],
    pub spend_public: [u8; 32],
    pub notes: Vec<Note>,
    pub reward_records: Vec<RewardRecord>,
    pub spent_images: Vec<[u8; 32]>,
    pub last_height: u64,
    pub subaddress_indices: Vec<u32>,
    pub next_subaddress_index: u32,
}

#[derive(Clone, Debug, bincode::Encode, bincode::Decode)]
struct WalletStateV3 {
    view_secret: [u8; 32],
    spend_secret: [u8; 32],
    view_public: [u8; 32],
    spend_public: [u8; 32],
    notes: Vec<Note>,
    spent_images: Vec<[u8; 32]>,
    last_height: u64,
    subaddress_indices: Vec<u32>,
    next_subaddress_index: u32,
}

#[derive(Clone, Debug, bincode::Encode, bincode::Decode)]
struct WalletStateV1 {
    view_secret: [u8; 32],
    spend_secret: [u8; 32],
    view_public: [u8; 32],
    spend_public: [u8; 32],
    notes: Vec<NoteV1>,
    spent_images: Vec<[u8; 32]>,
    last_height: u64,
}

#[derive(Clone, Debug, bincode::Encode, bincode::Decode)]
struct NoteV1 {
    out_ref: OutputRef,
    one_time_pub: [u8; 32],
    one_time_secret: [u8; 32],
    commitment: [u8; 32],
    amount: u64,
    blinding: [u8; 32],
    key_image: [u8; 32],
}

#[derive(Clone, Debug, bincode::Encode, bincode::Decode)]
struct WalletStateV2 {
    view_secret: [u8; 32],
    spend_secret: [u8; 32],
    view_public: [u8; 32],
    spend_public: [u8; 32],
    notes: Vec<NoteV2>,
    spent_images: Vec<[u8; 32]>,
    last_height: u64,
    subaddress_indices: Vec<u32>,
    next_subaddress_index: u32,
}

#[derive(Clone, Debug, bincode::Encode, bincode::Decode)]
struct NoteV2 {
    out_ref: OutputRef,
    one_time_pub: [u8; 32],
    one_time_secret: [u8; 32],
    commitment: [u8; 32],
    amount: u64,
    blinding: [u8; 32],
    key_image: [u8; 32],
    subaddress_index: u32,
}

impl Drop for WalletState {
    fn drop(&mut self) {
        self.view_secret.zeroize();
        self.spend_secret.zeroize();
        self.notes.zeroize();
        self.spent_images.zeroize();
    }
}

impl zeroize::Zeroize for Note {
    fn zeroize(&mut self) {
        self.one_time_secret.zeroize();
        self.blinding.zeroize();
        self.key_image.zeroize();
        self.commitment.zeroize();
        self.one_time_pub.zeroize();
        self.tx_pub.zeroize();
        self.lattice_spend_pub.zeroize();
        self.lattice_one_time_secret.zeroize();
        self.amount = 0;
        self.subaddress_index = 0;
    }
}

#[derive(Clone, Copy, Debug)]
struct SecretKey([u8; 32]);

#[derive(Clone, Copy, Debug)]
struct PublicKey([u8; 32]);

impl WalletState {
    pub fn address(&self) -> Address {
        self.address_at(0).unwrap_or_else(|| {
            let lattice_pub = lattice_base_public_from_seed(&self.spend_secret);
            Address {
                view: self.view_public,
                spend: self.spend_public,
                lattice_spend_pub: lattice_pub.p.to_bytes(),
            }
        })
    }

    pub fn address_at(&self, index: u32) -> Option<Address> {
        let (sk, pk) = subaddress_keys(self, index).ok()?;
        let lattice_pub = lattice_base_public_from_seed(&sk.0);
        Some(Address {
            view: self.view_public,
            spend: pk.0,
            lattice_spend_pub: lattice_pub.p.to_bytes(),
        })
    }
}

fn recompute_note_key_images(state: &mut WalletState) {
    let view_secret = state.view_secret;
    let spend_secret = state.spend_secret;
    for note in &mut state.notes {
        let (secret, public) = match lattice_spend_keypair_for_note(&view_secret, &spend_secret, note) {
            Ok(pair) => pair,
            Err(_) => {
                let fallback_secret = lattice_secret_from_one_time_secret(&note.one_time_secret);
                let fallback_public = lattice_public_from_secret(&fallback_secret);
                (fallback_secret, fallback_public)
            }
        };
        note.key_image = derive_key_image_id(&lattice_key_image(&secret, &public));
        note.lattice_spend_pub = public.p.to_bytes();
        note.lattice_one_time_secret = secret.s.to_bytes();
    }
}

pub fn create_wallet(path: &str) -> Result<WalletState, String> {
    let view_sk = random_secret_bytes()?;
    let spend_sk = random_secret_bytes()?;
    let view_pk = derive_public_tag(b"knox-wallet-view-pub-v2", &view_sk);
    let spend_pk = derive_public_tag(b"knox-wallet-spend-pub-v2", &spend_sk);
    let state = WalletState {
        view_secret: view_sk,
        spend_secret: spend_sk,
        view_public: view_pk,
        spend_public: spend_pk,
        notes: Vec::new(),
        reward_records: Vec::new(),
        spent_images: Vec::new(),
        last_height: 0,
        subaddress_indices: vec![0, 1],
        next_subaddress_index: 2,
    };
    save_wallet(path, &state)?;
    Ok(state)
}

pub fn load_wallet(path: &str) -> Result<WalletState, String> {
    let mut file = fs::File::open(path).map_err(|e| e.to_string())?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).map_err(|e| e.to_string())?;
    let pass = wallet_passphrase()?;
    let is_encrypted = buf.starts_with(WALLET_MAGIC_V2) || buf.starts_with(WALLET_MAGIC_V1);
    if passphrase_required() && !is_encrypted {
        return Err("wallet must be encrypted (set KNOX_WALLET_PASSPHRASE_FILE or KNOX_WALLET_PASSPHRASE and resave)".to_string());
    }
    let raw = if is_encrypted {
        let pass = pass.ok_or_else(|| "wallet is encrypted; passphrase required".to_string())?;
        decrypt_wallet(&buf, &pass)?
    } else {
        buf
    };
    if let Ok(mut state) = decode_wallet_state_current(&raw) {
        ensure_default_subaddresses(&mut state);
        recompute_note_key_images(&mut state);
        return Ok(state);
    }

    if let Ok(legacy_v3) = decode_wallet_state_v3(&raw) {
        let mut state = WalletState {
            view_secret: legacy_v3.view_secret,
            spend_secret: legacy_v3.spend_secret,
            view_public: legacy_v3.view_public,
            spend_public: legacy_v3.spend_public,
            notes: legacy_v3.notes,
            reward_records: Vec::new(),
            spent_images: legacy_v3.spent_images,
            last_height: legacy_v3.last_height,
            subaddress_indices: legacy_v3.subaddress_indices,
            next_subaddress_index: legacy_v3.next_subaddress_index,
        };
        ensure_default_subaddresses(&mut state);
        recompute_note_key_images(&mut state);
        return Ok(state);
    }

    if let Ok(legacy_v2) = decode_wallet_state_v2(&raw) {
        let mut state = WalletState {
            view_secret: legacy_v2.view_secret,
            spend_secret: legacy_v2.spend_secret,
            view_public: legacy_v2.view_public,
            spend_public: legacy_v2.spend_public,
            notes: legacy_v2
                .notes
                .into_iter()
                .map(|n| Note {
                    out_ref: n.out_ref,
                    one_time_pub: n.one_time_pub,
                    tx_pub: [0u8; 32],
                    lattice_spend_pub: Vec::new(),
                    lattice_one_time_secret: Vec::new(),
                    one_time_secret: n.one_time_secret,
                    commitment: n.commitment,
                    amount: n.amount,
                    blinding: n.blinding,
                    key_image: n.key_image,
                    subaddress_index: n.subaddress_index,
                })
                .collect(),
            reward_records: Vec::new(),
            spent_images: legacy_v2.spent_images,
            last_height: legacy_v2.last_height,
            subaddress_indices: legacy_v2.subaddress_indices,
            next_subaddress_index: legacy_v2.next_subaddress_index,
        };
        ensure_default_subaddresses(&mut state);
        recompute_note_key_images(&mut state);
        return Ok(state);
    }

    let legacy = decode_wallet_state_v1(&raw).map_err(|e| e.to_string())?;
    let mut state = WalletState {
        view_secret: legacy.view_secret,
        spend_secret: legacy.spend_secret,
        view_public: legacy.view_public,
        spend_public: legacy.spend_public,
        notes: legacy
            .notes
            .into_iter()
            .map(|n| Note {
                out_ref: n.out_ref,
                one_time_pub: n.one_time_pub,
                tx_pub: [0u8; 32],
                lattice_spend_pub: Vec::new(),
                lattice_one_time_secret: Vec::new(),
                one_time_secret: n.one_time_secret,
                commitment: n.commitment,
                amount: n.amount,
                blinding: n.blinding,
                key_image: n.key_image,
                subaddress_index: 0,
            })
            .collect(),
        reward_records: Vec::new(),
        spent_images: legacy.spent_images,
        last_height: legacy.last_height,
        subaddress_indices: vec![0, 1],
        next_subaddress_index: 2,
    };
    ensure_default_subaddresses(&mut state);
    recompute_note_key_images(&mut state);
    Ok(state)
}

fn decode_wallet_state_current(raw: &[u8]) -> Result<WalletState, bincode::error::DecodeError> {
    if let Ok((state, _)) = bincode::decode_from_slice::<WalletState, _>(
        raw,
        bincode::config::standard().with_limit::<WALLET_DECODE_LIMIT>(),
    ) {
        return Ok(state);
    }
    let (state, _) = bincode::decode_from_slice::<WalletState, _>(
        raw,
        bincode::config::legacy().with_limit::<WALLET_DECODE_LIMIT>(),
    )?;
    Ok(state)
}

fn decode_wallet_state_v3(raw: &[u8]) -> Result<WalletStateV3, bincode::error::DecodeError> {
    if let Ok((state, _)) = bincode::decode_from_slice::<WalletStateV3, _>(
        raw,
        bincode::config::standard().with_limit::<WALLET_DECODE_LIMIT>(),
    ) {
        return Ok(state);
    }
    let (state, _) = bincode::decode_from_slice::<WalletStateV3, _>(
        raw,
        bincode::config::legacy().with_limit::<WALLET_DECODE_LIMIT>(),
    )?;
    Ok(state)
}

fn decode_wallet_state_v2(raw: &[u8]) -> Result<WalletStateV2, bincode::error::DecodeError> {
    if let Ok((state, _)) = bincode::decode_from_slice::<WalletStateV2, _>(
        raw,
        bincode::config::standard().with_limit::<WALLET_DECODE_LIMIT>(),
    ) {
        return Ok(state);
    }
    let (state, _) = bincode::decode_from_slice::<WalletStateV2, _>(
        raw,
        bincode::config::legacy().with_limit::<WALLET_DECODE_LIMIT>(),
    )?;
    Ok(state)
}

fn decode_wallet_state_v1(raw: &[u8]) -> Result<WalletStateV1, bincode::error::DecodeError> {
    if let Ok((state, _)) = bincode::decode_from_slice::<WalletStateV1, _>(
        raw,
        bincode::config::standard().with_limit::<WALLET_DECODE_LIMIT>(),
    ) {
        return Ok(state);
    }
    let (state, _) = bincode::decode_from_slice::<WalletStateV1, _>(
        raw,
        bincode::config::legacy().with_limit::<WALLET_DECODE_LIMIT>(),
    )?;
    Ok(state)
}

pub fn save_wallet(path: &str, state: &WalletState) -> Result<(), String> {
    let bytes =
        bincode::encode_to_vec(state, bincode::config::standard()).map_err(|e| e.to_string())?;
    let pass = wallet_passphrase()?;
    if passphrase_required() && pass.is_none() {
        return Err("passphrase required (set KNOX_WALLET_REQUIRE_PASSPHRASE=1)".to_string());
    }
    let out = if let Some(pass) = pass {
        encrypt_wallet(&bytes, &pass)?
    } else {
        bytes
    };
    let mut file = fs::File::create(path).map_err(|e| e.to_string())?;
    file.write_all(&out).map_err(|e| e.to_string())
}

fn wallet_passphrase() -> Result<Option<String>, String> {
    static CACHE: OnceLock<Option<String>> = OnceLock::new();
    if let Some(cached) = CACHE.get() {
        return Ok(cached.clone());
    }
    if let Ok(path) = env::var("KNOX_WALLET_PASSPHRASE_FILE") {
        let p = path.trim();
        if !p.is_empty() {
            if let Ok(v) = fs::read_to_string(p) {
                let t = v.trim().to_string();
                if !t.is_empty() {
                    let _ = CACHE.set(Some(t.clone()));
                    return Ok(Some(t));
                }
            }
        }
    }
    if let Ok(v) = env::var("KNOX_WALLET_PASSPHRASE") {
        if !v.trim().is_empty() {
            let _ = CACHE.set(Some(v.clone()));
            return Ok(Some(v));
        }
    }
    if passphrase_required() {
        let pass = read_passphrase_stdin()?;
        if pass.trim().is_empty() {
            return Err("passphrase required".to_string());
        }
        let pass = pass.trim_end_matches(&['\r', '\n'][..]).to_string();
        let _ = CACHE.set(Some(pass.clone()));
        return Ok(Some(pass));
    }
    let _ = CACHE.set(None);
    Ok(None)
}

fn passphrase_required() -> bool {
    env::var("KNOX_WALLET_REQUIRE_PASSPHRASE").ok().as_deref() == Some("1")
}

fn read_passphrase_stdin() -> Result<String, String> {
    use std::io::{self, Read};
    eprintln!("Enter wallet passphrase (stdin):");
    let mut input = String::new();
    let mut stdin = io::stdin();
    let mut buf = [0u8; 1];
    while input.len() < 1024 {
        let n = stdin.read(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        let ch = buf[0] as char;
        if ch == '\n' {
            break;
        }
        input.push(ch);
    }
    if input.trim().is_empty() {
        return Err("no passphrase provided on stdin".to_string());
    }
    Ok(input)
}

fn derive_key(pass: &str, salt: &[u8; 32]) -> Result<[u8; 32], String> {
    let mut key = [0u8; 32];
    let argon = Argon2::default();
    argon
        .hash_password_into(pass.as_bytes(), salt, &mut key)
        .map_err(|e| format!("argon2 kdf failed: {e}"))?;
    Ok(key)
}

fn derive_key_legacy(pass: &str, salt: &[u8; 32], label: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(b"knox-wallet-kdf");
    hasher.update(label);
    hasher.update(pass.as_bytes());
    hasher.update(salt);
    let out = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(out.as_bytes());
    key
}

fn fill_os_random(out: &mut [u8]) -> Result<(), String> {
    getrandom(out).map_err(|e| format!("getrandom failed: {e}"))
}

fn random_secret_bytes() -> Result<[u8; 32], String> {
    let mut out = [0u8; 32];
    fill_os_random(&mut out)?;
    Ok(out)
}

fn derive_secret_tag(domain: &[u8], seed: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(domain);
    h.update(seed);
    *h.finalize().as_bytes()
}

fn derive_public_tag(domain: &[u8], secret: &[u8; 32]) -> [u8; 32] {
    derive_secret_tag(domain, secret)
}

fn encrypt_wallet(plain: &[u8], pass: &str) -> Result<Vec<u8>, String> {
    let mut salt = [0u8; 32];
    fill_os_random(&mut salt)?;
    let mut nonce = [0u8; 24];
    fill_os_random(&mut nonce)?;
    let key = derive_key(pass, &salt)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key).map_err(|_| "invalid key".to_string())?;
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), plain)
        .map_err(|_| "wallet encrypt failed".to_string())?;

    let mut out = Vec::with_capacity(4 + 32 + 24 + ciphertext.len());
    out.extend_from_slice(WALLET_MAGIC_V2);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

fn decrypt_wallet(buf: &[u8], pass: &str) -> Result<Vec<u8>, String> {
    if buf.len() < 4 {
        return Err("wallet file too short".to_string());
    }
    if &buf[..4] == WALLET_MAGIC_V2 {
        return decrypt_wallet_v2(buf, pass);
    }
    if &buf[..4] == WALLET_MAGIC_V1 {
        return decrypt_wallet_v1(buf, pass);
    }
    Err("invalid wallet magic".to_string())
}

fn decrypt_wallet_v2(buf: &[u8], pass: &str) -> Result<Vec<u8>, String> {
    if buf.len() < 4 + 32 + 24 {
        return Err("wallet file too short".to_string());
    }
    let mut salt = [0u8; 32];
    salt.copy_from_slice(&buf[4..36]);
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&buf[36..60]);
    let ciphertext = &buf[60..];
    let key = derive_key(pass, &salt)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key).map_err(|_| "invalid key".to_string())?;
    cipher
        .decrypt(XNonce::from_slice(&nonce), ciphertext)
        .map_err(|_| "wallet decrypt failed".to_string())
}

fn decrypt_wallet_v1(buf: &[u8], pass: &str) -> Result<Vec<u8>, String> {
    if buf.len() < 4 + 32 + 32 + 32 {
        return Err("wallet file too short".to_string());
    }
    let mut salt = [0u8; 32];
    salt.copy_from_slice(&buf[4..36]);
    let nonce = &buf[36..68];
    let mac = &buf[68..100];
    let cipher = &buf[100..];
    let enc_key = derive_key_legacy(pass, &salt, b"enc");
    let mac_key = derive_key_legacy(pass, &salt, b"mac");

    let mut mac_hasher = Hasher::new_keyed(&mac_key);
    mac_hasher.update(b"knox-wallet-mac");
    mac_hasher.update(nonce);
    mac_hasher.update(cipher);
    let expected = mac_hasher.finalize();
    if mac.ct_eq(expected.as_bytes()).unwrap_u8() == 0 {
        return Err("wallet MAC check failed".to_string());
    }

    let mut keystream = vec![0u8; cipher.len()];
    let mut enc_hasher = Hasher::new_keyed(&enc_key);
    enc_hasher.update(b"knox-wallet-enc");
    enc_hasher.update(nonce);
    let mut reader = enc_hasher.finalize_xof();
    reader.fill(&mut keystream);

    let mut plain = Vec::with_capacity(cipher.len());
    for (b, k) in cipher.iter().zip(keystream.iter()) {
        plain.push(b ^ k);
    }
    Ok(plain)
}

pub fn address_to_string(addr: &Address) -> String {
    let mut out = String::from("knox1");
    out.push_str(&hex(&addr.view));
    out.push_str(&hex(&addr.spend));
    out.push_str(&hex(&addr.lattice_spend_pub));
    out
}

pub fn address_from_string(s: &str) -> Result<Address, String> {
    if !s.starts_with("knox1") {
        return Err("invalid address prefix".to_string());
    }
    let data = &s[5..];
    let expected_len = 64 + 64 + (LATTICE_PUBKEY_BYTES * 2);
    if data.len() != expected_len {
        return Err(format!(
            "invalid address length: expected {} hex chars after prefix",
            expected_len
        ));
    }
    let view = hex_decode(&data[..64])?;
    let spend = hex_decode(&data[64..128])?;
    let lattice_spend_pub = hex_decode(&data[128..])?;
    if view.len() != 32 || spend.len() != 32 {
        return Err("invalid address bytes".to_string());
    }
    knox_lattice::Poly::from_bytes(&lattice_spend_pub)
        .map_err(|_| "invalid lattice spend public key bytes".to_string())?;
    let mut view_bytes = [0u8; 32];
    let mut spend_bytes = [0u8; 32];
    view_bytes.copy_from_slice(&view);
    spend_bytes.copy_from_slice(&spend);
    Ok(Address {
        view: view_bytes,
        spend: spend_bytes,
        lattice_spend_pub,
    })
}

pub fn sync_wallet(state: &mut WalletState, rpc_addr: &str) -> Result<(), String> {
    let tip = rpc_get_tip(rpc_addr)?;
    if tip < state.last_height {
        state.notes.clear();
        state.reward_records.clear();
        state.spent_images.clear();
        state.last_height = 0;
    }
    let view_sk = SecretKey(state.view_secret);
    ensure_default_subaddresses(state);
    let mut subkeys: Vec<(u32, SecretKey, PublicKey)> = Vec::new();
    for idx in scan_subaddress_indices(state) {
        if let Ok((sk, pk)) = subaddress_keys(state, idx) {
            subkeys.push((idx, sk, pk));
        }
    }
    if subkeys.is_empty() {
        subkeys.push((
            0,
            SecretKey(state.spend_secret),
            PublicKey(state.spend_public),
        ));
    }
    let mut h = state.last_height;
    const SYNC_BATCH: u32 = 64;
    while h <= tip {
        let remaining = tip.saturating_sub(h) + 1;
        let limit = remaining.min(SYNC_BATCH as u64) as u32;
        let blocks = rpc_get_blocks(rpc_addr, h, limit)?;
        if blocks.is_empty() {
            break;
        }
        for block in blocks {
            let block_height = block.header.height;
            let block_hash = header_link_hash(&block.header);
            for tx in block.txs {
                for input in &tx.inputs {
                    if state.notes.iter().any(|n| n.key_image == input.key_image)
                        && !state.spent_images.contains(&input.key_image)
                    {
                        state.spent_images.push(input.key_image);
                    }
                }
                let tx_hash = match bincode::encode_to_vec(&tx, bincode::config::standard()) {
                    Ok(bytes) => hash_tx_bytes(&bytes),
                    Err(_) => continue,
                };
                let lattice_outputs: Option<Vec<_>> = if tx.coinbase {
                    decode_coinbase_payload(&tx.extra)
                        .ok()
                        .map(|p| p.outputs)
                } else {
                    decode_lattice_tx_extra(&tx.extra)
                        .ok()
                        .map(|ltx| ltx.outputs)
                };
                for (idx, out) in tx.outputs.iter().enumerate() {
                    let lattice_out = lattice_outputs
                        .as_ref()
                        .and_then(|outs| outs.get(idx));
                    for (sub_idx, spend_sk, spend_pk) in &subkeys {
                        if let Some(note) = try_decrypt_output(
                            &view_sk,
                            spend_sk,
                            spend_pk,
                            out,
                            lattice_out,
                            tx_hash,
                            idx as u16,
                            *sub_idx,
                            block_height,
                            tx.coinbase,
                        ) {
                            if !state.subaddress_indices.contains(sub_idx) {
                                state.subaddress_indices.push(*sub_idx);
                                state.subaddress_indices.sort_unstable();
                                state.subaddress_indices.dedup();
                            }
                            state.next_subaddress_index =
                                state.next_subaddress_index.max(sub_idx.saturating_add(1));
                            if !state.notes.iter().any(|n| {
                                n.out_ref.tx == note.out_ref.tx
                                    && n.out_ref.index == note.out_ref.index
                            }) {
                                state.notes.push(note.clone());
                            }
                            if tx.coinbase {
                                record_reward_event(
                                    state,
                                    &note,
                                    block_height,
                                    block_hash,
                                    tx_hash,
                                    idx as u16,
                                );
                            }
                            break;
                        }
                    }
                }
            }
            h = h.saturating_add(1);
        }
    }
    state.last_height = tip + 1;
    Ok(())
}

pub fn reset_scan_state(state: &mut WalletState) {
    state.notes.clear();
    state.reward_records.clear();
    state.spent_images.clear();
    state.last_height = 0;
    ensure_default_subaddresses(state);
}

pub fn create_wallet_from_node_key(
    node_key_path: &str,
    wallet_path: &str,
) -> Result<WalletState, String> {
    let (sk, _pk) = load_node_key(node_key_path)?;
    create_wallet_from_node_secret(sk, wallet_path)
}

pub fn create_wallet_from_node_key_bytes(
    node_key_bytes: &[u8],
    wallet_path: &str,
) -> Result<WalletState, String> {
    let (sk, _pk) = load_node_key_bytes(node_key_bytes)?;
    create_wallet_from_node_secret(sk, wallet_path)
}

pub fn repair_wallet_from_node_key(
    node_key_path: &str,
    wallet_path: &str,
    rpc_addr: &str,
) -> Result<WalletState, String> {
    let mut state = create_wallet_from_node_key(node_key_path, wallet_path)?;
    sync_wallet(&mut state, rpc_addr)?;
    save_wallet(wallet_path, &state)?;
    Ok(state)
}

fn create_wallet_from_node_secret(sk: SecretKey, wallet_path: &str) -> Result<WalletState, String> {
    let view_sk = derive_secret_tag(b"knox-wallet-view-v2", &sk.0);
    let spend_sk = derive_secret_tag(b"knox-wallet-spend-v2", &sk.0);
    let view_pk = derive_public_tag(b"knox-wallet-view-pub-v2", &view_sk);
    let spend_pk = derive_public_tag(b"knox-wallet-spend-pub-v2", &spend_sk);
    let state = WalletState {
        view_secret: view_sk,
        spend_secret: spend_sk,
        view_public: view_pk,
        spend_public: spend_pk,
        notes: Vec::new(),
        reward_records: Vec::new(),
        spent_images: Vec::new(),
        last_height: 0,
        subaddress_indices: vec![0, 1],
        next_subaddress_index: 2,
    };
    save_wallet(wallet_path, &state)?;
    Ok(state)
}

pub fn list_wallet_addresses(state: &WalletState) -> Vec<(u32, Address)> {
    let mut state = state.clone();
    ensure_default_subaddresses(&mut state);
    let mut out = Vec::new();
    for idx in &state.subaddress_indices {
        if let Some(addr) = state.address_at(*idx) {
            out.push((*idx, addr));
        }
    }
    if out.is_empty() {
        out.push((0, state.address()));
    }
    out
}

pub fn create_subaddress(state: &mut WalletState) -> Result<Address, String> {
    let idx = state.next_subaddress_index;
    let addr = state
        .address_at(idx)
        .ok_or_else(|| "failed to derive subaddress".to_string())?;
    state.subaddress_indices.push(idx);
    state.subaddress_indices.sort_unstable();
    state.subaddress_indices.dedup();
    state.next_subaddress_index = idx.saturating_add(1);
    Ok(addr)
}

pub fn wallet_balance(state: &WalletState) -> u64 {
    state
        .notes
        .iter()
        .filter(|n| !state.spent_images.contains(&n.key_image))
        .map(|n| n.amount)
        .sum()
}

pub fn wallet_balances_by_subaddress(state: &WalletState) -> Vec<(u32, u64)> {
    let mut out = Vec::new();
    let mut indices = state.subaddress_indices.clone();
    if indices.is_empty() {
        indices.push(0);
    }
    indices.sort_unstable();
    indices.dedup();
    for idx in indices {
        let balance = state
            .notes
            .iter()
            .filter(|n| n.subaddress_index == idx)
            .filter(|n| !state.spent_images.contains(&n.key_image))
            .map(|n| n.amount)
            .sum();
        out.push((idx, balance));
    }
    out
}

pub fn wallet_reward_records(state: &WalletState) -> &[RewardRecord] {
    &state.reward_records
}

pub fn wallet_reward_totals(state: &WalletState) -> [(RewardKind, u64); 4] {
    let mut miner = 0u64;
    let mut treasury = 0u64;
    let mut dev = 0u64;
    let mut premine = 0u64;
    for record in &state.reward_records {
        match record.kind {
            RewardKind::Miner => miner = miner.saturating_add(record.amount),
            RewardKind::Treasury => treasury = treasury.saturating_add(record.amount),
            RewardKind::Dev => dev = dev.saturating_add(record.amount),
            RewardKind::Premine => premine = premine.saturating_add(record.amount),
        }
    }
    [
        (RewardKind::Miner, miner),
        (RewardKind::Treasury, treasury),
        (RewardKind::Dev, dev),
        (RewardKind::Premine, premine),
    ]
}

pub fn build_transaction(
    state: &mut WalletState,
    rpc_addr: &str,
    to: &Address,
    amount: u64,
    fee: u64,
    ring_size: usize,
) -> Result<Transaction, String> {
    if ring_size < MIN_DECOY_COUNT || ring_size > MAX_DECOY_COUNT {
        return Err(format!(
            "decoy count must be between {} and {}",
            MIN_DECOY_COUNT, MAX_DECOY_COUNT
        ));
    }
    let mut selected = Vec::new();
    let mut total = 0u64;
    for note in &state.notes {
        if state.spent_images.contains(&note.key_image) {
            continue;
        }
        selected.push(note.clone());
        total += note.amount;
        if total >= amount + fee {
            break;
        }
    }
    if total < amount + fee {
        return Err("insufficient funds".to_string());
    }

    let change = total - amount - fee;

    let mut input_drafts = Vec::new();
    for note in &selected {
        let (lattice_secret, lattice_public) =
            lattice_spend_keypair_for_note(&state.view_secret, &state.spend_secret, note)?;
        let ring = build_ring(rpc_addr, note, ring_size)?;
        let true_lattice_pub = if note.lattice_spend_pub.len() == LATTICE_PUBKEY_BYTES {
            note.lattice_spend_pub.clone()
        } else {
            lattice_public.p.to_bytes()
        };
        let true_member = RingMember {
            out_ref: note.out_ref,
            one_time_pub: note.one_time_pub,
            commitment: note.commitment,
            lattice_spend_pub: true_lattice_pub,
        };
        let signer_index = sample_index(ring.len() + 1)?;
        let mut ring = ring;
        ring.insert(signer_index, true_member);

        input_drafts.push(InputDraft {
            ring,
            signer_index,
            note_amount: note.amount,
            lattice_secret,
            lattice_public,
        });
    }

    let mut output_plan: Vec<(Address, u64)> = Vec::new();
    output_plan.push((to.clone(), amount));
    if change > 0 {
        output_plan.push((state.address(), change));
    }

    let mut output_drafts = Vec::with_capacity(output_plan.len());
    let chain_tip = rpc_get_tip(rpc_addr).unwrap_or(state.last_height);
    let enc_level = tx_hardening_level(chain_tip.saturating_add(1));
    for (addr, out_amount) in &output_plan {
        let blind = random_scalar_bytes()?;
        output_drafts.push(make_output_with_blind(
            addr,
            *out_amount,
            &blind,
            enc_level,
        )?);
    }
    let commitment_key = LatticeCommitmentKey::derive();
    let outputs = output_drafts
        .iter()
        .map(|d| d.tx_out.clone())
        .collect::<Vec<_>>();
    let lattice_outputs = output_drafts
        .iter()
        .map(|d| d.lattice_out.clone())
        .collect::<Vec<_>>();
    let output_openings = output_drafts
        .iter()
        .map(|d| d.opening.clone())
        .collect::<Vec<_>>();

    // Choose input pseudo-commit randomness so sum(inputs)+fee == sum(outputs) commitment-wise.
    let mut output_random_sum = Poly::zero();
    for opening in &output_openings {
        output_random_sum = output_random_sum.add(&opening.opening.randomness);
    }
    let mut input_randomness = Vec::with_capacity(input_drafts.len());
    let mut running_input_sum = Poly::zero();
    for i in 0..input_drafts.len() {
        let r = if i + 1 == input_drafts.len() {
            output_random_sum.sub(&running_input_sum)
        } else {
            let rand = Poly::random_short_checked()?;
            running_input_sum = running_input_sum.add(&rand);
            rand
        };
        input_randomness.push(r);
    }

    let mut inputs = Vec::with_capacity(input_drafts.len());
    let mut lattice_inputs = Vec::with_capacity(input_drafts.len());
    let mut lattice_secrets = Vec::with_capacity(input_drafts.len());
    for (idx, draft) in input_drafts.iter().enumerate() {
        let secret = draft.lattice_secret.clone();
        let signer_public = draft.lattice_public.clone();
        let ring = draft
            .ring
            .iter()
            .map(lattice_public_from_member)
            .collect::<Result<Vec<_>, _>>()?;
        let lattice_image = lattice_key_image(&secret, &signer_public);
        let image_id = derive_key_image_id(&lattice_image);
        let pseudo_commitment =
            lattice_commit_value(&commitment_key, draft.note_amount, &input_randomness[idx]);

        inputs.push(TxIn {
            ring: draft.ring.clone(),
            key_image: image_id,
            pseudo_commit: lattice_commitment_digest(&pseudo_commitment),
            signature: knox_types::MlsagSignature {
                c1: [0u8; 32],
                responses: Vec::new(),
                key_images: Vec::new(),
            },
        });
        lattice_inputs.push(LatticeInput {
            ring,
            ring_signature: knox_lattice::LatticeRingSignature {
                c0: [0u8; 32],
                responses: Vec::new(),
                key_image: lattice_image.clone(),
            },
            key_image: lattice_image,
            pseudo_commitment,
        });
        lattice_secrets.push(secret);
    }

    let mut tx = Transaction {
        version: 3,
        coinbase: false,
        coinbase_proof: Vec::new(),
        inputs,
        outputs,
        fee,
        extra: Vec::new(),
    };

    let mut lattice_tx = LatticeTransaction {
        inputs: lattice_inputs,
        outputs: lattice_outputs,
        fee,
        fee_commitment: lattice_fee_commitment(&commitment_key, fee),
    };
    let msg = tx_lattice_signing_hash(&tx).0;
    for (i, draft) in input_drafts.iter().enumerate() {
        let sig = lattice_sign_ring(
            &msg,
            &lattice_tx.inputs[i].ring,
            draft.signer_index,
            &lattice_secrets[i],
        )?;
        lattice_tx.inputs[i].ring_signature = sig;
        tx.inputs[i].key_image = derive_key_image_id(&lattice_tx.inputs[i].key_image);
        tx.inputs[i].pseudo_commit =
            lattice_commitment_digest(&lattice_tx.inputs[i].pseudo_commitment);
    }
    for i in 0..tx.outputs.len() {
        tx.outputs[i].commitment = lattice_commitment_digest(&lattice_tx.outputs[i].commitment);
    }

    tx.extra = encode_lattice_tx_extra(&lattice_tx)?;
    if cfg!(debug_assertions) {
        knox_lattice::verify_transaction(&commitment_key, &lattice_tx, &msg)
            .map_err(|e| format!("lattice tx self-check failed: {e}"))?;
    }

    Ok(tx)
}

fn build_ring(rpc_addr: &str, note: &Note, ring_size: usize) -> Result<Vec<RingMember>, String> {
    let mut ring: Vec<RingMember> = Vec::with_capacity(ring_size);
    let mut seen: HashSet<(Hash32, u16)> = HashSet::with_capacity(ring_size + 1);
    seen.insert((note.out_ref.tx, note.out_ref.index));
    let mut attempts = 0;
    while ring.len() < ring_size && attempts < 5 {
        attempts += 1;
        let batch = rpc_get_decoys(rpc_addr, ring_size as u32)?;
        for member in batch {
            if ring.len() >= ring_size {
                break;
            }
            let key = (member.out_ref.tx, member.out_ref.index);
            if seen.insert(key) {
                ring.push(member);
            }
        }
    }
    if ring.len() < ring_size {
        return Err("unable to build ring with unique decoys".to_string());
    }
    Ok(ring)
}

pub fn submit_transaction(rpc_addr: &str, tx: &Transaction) -> Result<bool, String> {
    let response = rpc_submit_tx(rpc_addr, tx.clone())?;
    Ok(response)
}

pub fn upstream_tip(rpc_addr: &str) -> Result<u64, String> {
    rpc_get_tip(rpc_addr)
}

pub fn network_telemetry(rpc_addr: &str) -> Result<knox_types::NetworkTelemetry, String> {
    match rpc_get_network_telemetry(rpc_addr) {
        Ok(t) => Ok(t),
        Err(primary_err) => rpc_get_network_telemetry_fallback(rpc_addr)
            .map_err(|fallback_err| format!("{primary_err}; fallback failed: {fallback_err}")),
    }
}

pub fn fibonacci_wall(rpc_addr: &str, limit: u32) -> Result<Vec<knox_types::FibWallEntry>, String> {
    rpc_get_fib_wall(rpc_addr, limit)
}

pub fn recent_blocks(rpc_addr: &str, limit: u32) -> Result<Vec<knox_types::Block>, String> {
    let lim = limit.clamp(1, 128);
    let tip = rpc_get_tip(rpc_addr)?;
    let span = lim.saturating_sub(1) as u64;
    let start = tip.saturating_sub(span);
    let mut blocks = rpc_get_blocks(rpc_addr, start, lim)?;
    blocks.sort_by_key(|b| b.header.height);
    blocks.reverse();
    Ok(blocks)
}

pub fn mark_submitted_transaction(state: &mut WalletState, tx: &Transaction) {
    for input in &tx.inputs {
        if !state.spent_images.contains(&input.key_image) {
            state.spent_images.push(input.key_image);
        }
    }
}

struct InputDraft {
    ring: Vec<RingMember>,
    signer_index: usize,
    note_amount: u64,
    lattice_secret: LatticeSecretKey,
    lattice_public: LatticePublicKey,
}

struct WalletOutputDraft {
    tx_out: TxOut,
    lattice_out: LatticeOutput,
    opening: LatticeOutputOpening,
}

fn make_output_with_blind(
    addr: &Address,
    amount: u64,
    blind: &[u8; 32],
    enc_level: u32,
) -> Result<WalletOutputDraft, String> {
    let _ = blind;
    let commitment_key = LatticeCommitmentKey::derive();
    let recipient_lattice_pub = lattice_public_from_serialized(&addr.lattice_spend_pub)?;
    let ephemeral_secret = Poly::random_short_checked()?;
    let stealth = send_to_stealth_with_ephemeral(
        &recipient_lattice_pub,
        &recipient_lattice_pub,
        &ephemeral_secret,
    );
    let shared = lattice_shared_seed(&stealth.one_time_public, &stealth.ephemeral_public);
    let (lattice_out, opening) = build_private_output(
        &commitment_key,
        stealth.one_time_public.clone(),
        stealth.ephemeral_public.clone(),
        amount,
        enc_level,
        &shared,
    )?;

    let tx_out = TxOut {
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
        enc_amount: lattice_out.enc_amount,
        enc_blind: lattice_out.enc_blind,
        enc_level,
        memo: [0u8; 32],
        range_proof: lattice_range_placeholder(&lattice_out.range_proof),
    };

    Ok(WalletOutputDraft {
        tx_out,
        lattice_out,
        opening,
    })
}

fn try_decrypt_output(
    view_sk: &SecretKey,
    spend_sk: &SecretKey,
    _spend_pk: &PublicKey,
    out: &TxOut,
    lattice_out: Option<&LatticeOutput>,
    tx_hash: Hash32,
    index: u16,
    subaddress_index: u32,
    block_height: u64,
    is_coinbase: bool,
) -> Option<Note> {
    let lattice_out = lattice_out?;
    let one_time_public = lattice_public_from_serialized(&out.lattice_spend_pub).ok()?;
    if one_time_public != lattice_out.stealth_address {
        return if is_coinbase {
            try_decrypt_output_legacy_coinbase(
                view_sk,
                spend_sk,
                _spend_pk,
                out,
                tx_hash,
                index,
                subaddress_index,
                block_height,
            )
        } else {
            None
        };
    }
    let spend_secret = lattice_base_secret_from_seed(&spend_sk.0);
    let spend_public = lattice_public_from_secret(&spend_secret);
    // Coinbase outputs are constructed with spend_public used as both view and spend key,
    // so we must scan using spend_secret as the view key for coinbase transactions.
    let view_secret = if is_coinbase {
        spend_secret.clone()
    } else {
        lattice_view_secret_from_seed(&view_sk.0)
    };
    let stealth = LatticeStealthOutput {
        one_time_public: one_time_public.clone(),
        ephemeral_public: lattice_out.ephemeral_public.clone(),
    };
    if !scan_with_view_key(&view_secret, &spend_public, &stealth) {
        return if is_coinbase {
            try_decrypt_output_legacy_coinbase(
                view_sk,
                spend_sk,
                _spend_pk,
                out,
                tx_hash,
                index,
                subaddress_index,
                block_height,
            )
        } else {
            None
        };
    }
    let recovered_secret =
        lattice_recover_one_time_secret(&view_secret, &spend_secret, &stealth.ephemeral_public);
    let recovered_public = lattice_public_from_secret(&recovered_secret);
    if recovered_public != one_time_public {
        return None;
    }

    let default_level = tx_hardening_level(block_height);
    let level = if out.enc_level == 0 {
        default_level
    } else {
        out.enc_level
    };
    let shared_bytes = lattice_shared_seed(&one_time_public, &stealth.ephemeral_public);
    let (amount, blind) =
        decrypt_amount_with_level(&shared_bytes, out.enc_amount, out.enc_blind, level);
    let ki = derive_key_image_id(&lattice_key_image(&recovered_secret, &recovered_public));
    let legacy_one_time = compatibility_pubkey_tag(
        b"knox-wallet-legacy-secret-v2",
        &recovered_secret.s.to_bytes(),
    );

    Some(Note {
        out_ref: OutputRef { tx: tx_hash, index },
        one_time_pub: out.one_time_pub,
        tx_pub: out.tx_pub,
        lattice_spend_pub: out.lattice_spend_pub.clone(),
        lattice_one_time_secret: recovered_secret.s.to_bytes(),
        one_time_secret: legacy_one_time,
        commitment: out.commitment,
        amount,
        blinding: blind,
        key_image: ki,
        subaddress_index,
    })
}

fn try_decrypt_output_legacy_coinbase(
    view_sk: &SecretKey,
    spend_sk: &SecretKey,
    spend_pk: &PublicKey,
    out: &TxOut,
    tx_hash: Hash32,
    index: u16,
    subaddress_index: u32,
    block_height: u64,
) -> Option<Note> {
    let tx_pub = PublicKey(out.tx_pub);
    let shared = legacy_shared_secret_receiver(view_sk, &tx_pub)?;
    let tweak = legacy_hash_to_scalar(b"knox-stealth", shared.compress().as_bytes());
    let spend_point = CompressedRistretto(spend_pk.0).decompress()?;
    let dest = spend_point + tweak * RISTRETTO_BASEPOINT_POINT;
    if dest.compress().to_bytes() != out.one_time_pub {
        return None;
    }

    let default_level = tx_hardening_level(block_height);
    let level = if out.enc_level == 0 {
        default_level
    } else {
        out.enc_level
    };
    let shared_bytes = shared.compress().to_bytes();
    let (amount, blind) =
        decrypt_amount_with_level(&shared_bytes, out.enc_amount, out.enc_blind, level);
    let one_time_secret = legacy_recover_one_time_secret(view_sk, spend_sk, &tx_pub)?;
    let lattice_base_secret = lattice_base_secret_from_seed(&spend_sk.0);
    let lattice_secret = legacy_lattice_output_secret_from_shared(
        &lattice_base_secret,
        &shared_bytes,
        &out.one_time_pub,
        &out.tx_pub,
    );
    let lattice_public = lattice_public_from_secret(&lattice_secret);
    let out_lattice_public = lattice_public_from_serialized(&out.lattice_spend_pub).ok()?;
    if lattice_public != out_lattice_public {
        return None;
    }
    let ki = derive_key_image_id(&lattice_key_image(&lattice_secret, &lattice_public));

    Some(Note {
        out_ref: OutputRef { tx: tx_hash, index },
        one_time_pub: out.one_time_pub,
        tx_pub: out.tx_pub,
        lattice_spend_pub: out.lattice_spend_pub.clone(),
        lattice_one_time_secret: lattice_secret.s.to_bytes(),
        one_time_secret: one_time_secret.0,
        commitment: out.commitment,
        amount,
        blinding: blind,
        key_image: ki,
        subaddress_index,
    })
}

fn random_scalar_bytes() -> Result<[u8; 32], String> {
    let mut bytes = [0u8; 32];
    fill_os_random(&mut bytes)?;
    Ok(bytes)
}

fn lattice_secret_from_one_time_secret(secret: &[u8; 32]) -> LatticeSecretKey {
    LatticeSecretKey {
        s: Poly::sample_short(b"knox-wallet-lattice-secret", secret),
    }
}

fn lattice_base_secret_from_seed(spend_secret: &[u8; 32]) -> LatticeSecretKey {
    LatticeSecretKey {
        s: Poly::sample_short(b"knox-wallet-lattice-base-v1", spend_secret),
    }
}

fn lattice_view_secret_from_seed(view_secret: &[u8; 32]) -> LatticeSecretKey {
    LatticeSecretKey {
        s: Poly::sample_short(b"knox-wallet-lattice-view-v1", view_secret),
    }
}

fn lattice_base_public_from_seed(spend_secret: &[u8; 32]) -> LatticePublicKey {
    let base_secret = lattice_base_secret_from_seed(spend_secret);
    lattice_public_from_secret(&base_secret)
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

fn lattice_range_placeholder(proof: &LatticeRangeProof) -> knox_types::RangeProof {
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

fn lattice_public_from_serialized(bytes: &[u8]) -> Result<LatticePublicKey, String> {
    let poly = Poly::from_bytes(bytes).map_err(|_| "invalid lattice public key bytes".to_string())?;
    Ok(LatticePublicKey { p: poly })
}

fn lattice_public_from_member(member: &RingMember) -> Result<LatticePublicKey, String> {
    lattice_public_from_serialized(&member.lattice_spend_pub)
}

fn lattice_commitment_digest(commitment: &LatticeCommitment) -> [u8; 32] {
    *blake3::hash(&commitment.to_bytes()).as_bytes()
}

fn sample_index(upper: usize) -> Result<usize, String> {
    if upper == 0 {
        return Err("ring size is zero".to_string());
    }
    let bound = upper as u64;
    let max = u64::MAX - (u64::MAX % bound);
    loop {
        let mut buf = [0u8; 8];
        fill_os_random(&mut buf)?;
        let v = u64::from_le_bytes(buf);
        if v < max {
            return Ok((v % bound) as usize);
        }
    }
}

fn subaddress_spend_secret(master_spend_secret: &[u8; 32], index: u32) -> [u8; 32] {
    if index == 0 {
        return *master_spend_secret;
    }
    let mut h = blake3::Hasher::new();
    h.update(b"knox-subaddress-v2");
    h.update(master_spend_secret);
    h.update(&index.to_le_bytes());
    *h.finalize().as_bytes()
}

fn subaddress_keys(state: &WalletState, index: u32) -> Result<(SecretKey, PublicKey), String> {
    if index == 0 {
        return Ok((SecretKey(state.spend_secret), PublicKey(state.spend_public)));
    }
    let secret = SecretKey(subaddress_spend_secret(&state.spend_secret, index));
    let public = PublicKey(derive_public_tag(b"knox-wallet-spend-pub-v2", &secret.0));
    Ok((secret, public))
}

fn lattice_spend_keypair_for_note(
    _view_secret: &[u8; 32],
    _spend_secret: &[u8; 32],
    note: &Note,
) -> Result<(LatticeSecretKey, LatticePublicKey), String> {
    if note.lattice_one_time_secret.len() == LATTICE_PUBKEY_BYTES {
        let poly = Poly::from_bytes(&note.lattice_one_time_secret)
            .map_err(|_| "invalid note lattice secret bytes".to_string())?;
        let secret = LatticeSecretKey { s: poly };
        let public = lattice_public_from_secret(&secret);
        if note.lattice_spend_pub.len() == LATTICE_PUBKEY_BYTES {
            let expected = lattice_public_from_serialized(&note.lattice_spend_pub)?;
            if public == expected {
                return Ok((secret, public));
            }
        } else {
            return Ok((secret, public));
        }
    }
    let fallback_secret = lattice_secret_from_one_time_secret(&note.one_time_secret);
    let fallback_public = lattice_public_from_secret(&fallback_secret);
    Ok((fallback_secret, fallback_public))
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
    hash_tx_bytes(&data)
}

fn rpc_get_tip(addr: &str) -> Result<u64, String> {
    let resp = rpc_request(addr, knox_types::WalletRequest::GetTip)?;
    match resp {
        knox_types::WalletResponse::Tip(h) => Ok(h),
        _ => Err("unexpected response".to_string()),
    }
}

fn rpc_get_blocks(addr: &str, start: u64, limit: u32) -> Result<Vec<knox_types::Block>, String> {
    let resp = rpc_request(addr, knox_types::WalletRequest::GetBlocks(start, limit))?;
    match resp {
        knox_types::WalletResponse::Blocks(b) => Ok(b),
        _ => Err("unexpected response".to_string()),
    }
}

fn rpc_get_decoys(addr: &str, count: u32) -> Result<Vec<RingMember>, String> {
    let resp = rpc_request(addr, knox_types::WalletRequest::GetDecoys(count))?;
    match resp {
        knox_types::WalletResponse::Decoys(d) => Ok(d),
        _ => Err("unexpected response".to_string()),
    }
}

fn rpc_submit_tx(addr: &str, tx: Transaction) -> Result<bool, String> {
    let resp = rpc_request(addr, knox_types::WalletRequest::SubmitTx(tx))?;
    match resp {
        knox_types::WalletResponse::SubmitResult(ok) => Ok(ok),
        _ => Err("unexpected response".to_string()),
    }
}

fn rpc_get_network_telemetry(addr: &str) -> Result<knox_types::NetworkTelemetry, String> {
    let resp = rpc_request(addr, knox_types::WalletRequest::GetNetworkTelemetry)?;
    match resp {
        knox_types::WalletResponse::NetworkTelemetry(t) => Ok(t),
        _ => Err("unexpected response".to_string()),
    }
}

fn rpc_get_network_telemetry_fallback(addr: &str) -> Result<knox_types::NetworkTelemetry, String> {
    const BATCH_SIZE: u32 = 50;
    let tip = rpc_get_tip(addr)?;
    let mut start = 0u64;
    let mut total_hardening = 0u64;
    let mut active_operator_ids = HashSet::new();
    let mut legacy_proposers = HashSet::new();
    let mut prev_proposer: Option<[u8; 32]> = None;
    let mut current_run = 0u64;
    let mut tip_proposer_streak = 0u64;
    let mut tip_hash = Hash32::ZERO;
    let mut current_difficulty_bits = 0u32;

    while start <= tip {
        let remaining = tip.saturating_sub(start).saturating_add(1);
        let limit = remaining.min(BATCH_SIZE as u64) as u32;
        let mut batch = rpc_get_blocks(addr, start, limit)?;
        if batch.is_empty() {
            break;
        }
        batch.sort_by_key(|b| b.header.height);
        for block in batch {
            let h = block.header.height;
            total_hardening =
                total_hardening.saturating_add(block.lattice_proof.difficulty_bits as u64);
            if tip.saturating_sub(h) < 2048 {
                if let Some(operator_id) = coinbase_operator_identity(&block) {
                    active_operator_ids.insert(operator_id);
                } else {
                    legacy_proposers.insert(block.header.proposer);
                }
            }
            match prev_proposer {
                Some(prev) if prev == block.header.proposer => {
                    current_run = current_run.saturating_add(1);
                }
                _ => {
                    current_run = 1;
                    prev_proposer = Some(block.header.proposer);
                }
            }
            if h == tip {
                tip_hash = header_link_hash(&block.header);
                current_difficulty_bits = block.lattice_proof.difficulty_bits;
                tip_proposer_streak = current_run;
            }
        }
        start = start.saturating_add(limit as u64);
    }

    if tip_proposer_streak == 0 {
        if let Some(block) = rpc_get_blocks(addr, tip, 1)?.into_iter().next() {
            tip_hash = header_link_hash(&block.header);
            current_difficulty_bits = block.lattice_proof.difficulty_bits;
            tip_proposer_streak = 1;
            if let Some(operator_id) = coinbase_operator_identity(&block) {
                active_operator_ids.insert(operator_id);
            } else {
                legacy_proposers.insert(block.header.proposer);
            }
        }
    }

    let next_streak_if_same_proposer = if tip_proposer_streak == 0 {
        0
    } else {
        tip_proposer_streak
            .saturating_add(1)
            .min(knox_types::STREAK_MAX_COUNT)
    };
    let streak_bonus_ppm = streak_bonus_ppm(tip_proposer_streak);

    Ok(knox_types::NetworkTelemetry {
        tip_height: tip,
        tip_hash,
        total_hardening,
        active_miners_recent: if !active_operator_ids.is_empty() {
            active_operator_ids.len() as u32
        } else {
            legacy_proposers.len() as u32
        },
        current_difficulty_bits,
        tip_proposer_streak,
        next_streak_if_same_proposer,
        streak_bonus_ppm,
        surge_phase: "legacy".to_string(),
        surge_countdown_ms: 0,
        surge_block_index: 0,
        surge_blocks_remaining: 0,
    })
}

fn legacy_hash_to_scalar(tag: &[u8], data: &[u8]) -> Scalar {
    let mut domain = Hasher::new();
    domain.update(b"knox-domain-key-v1");
    domain.update(&(tag.len() as u64).to_le_bytes());
    domain.update(tag);
    let key = *domain.finalize().as_bytes();

    let mut hasher = Hasher::new_keyed(&key);
    hasher.update(&(data.len() as u64).to_le_bytes());
    hasher.update(data);
    let mut wide = [0u8; 64];
    let mut reader = hasher.finalize_xof();
    reader.fill(&mut wide);
    Scalar::from_bytes_mod_order_wide(&wide)
}

fn legacy_scalar_from_bytes(bytes: &[u8; 32]) -> Scalar {
    Scalar::from_bytes_mod_order(*bytes)
}

fn legacy_shared_secret_receiver(
    view_sk: &SecretKey,
    tx_pub: &PublicKey,
) -> Option<curve25519_dalek::ristretto::RistrettoPoint> {
    let r_point = CompressedRistretto(tx_pub.0).decompress()?;
    let view_scalar = legacy_scalar_from_bytes(&view_sk.0);
    Some(view_scalar * r_point)
}

fn legacy_recover_one_time_secret(
    view_secret: &SecretKey,
    spend_secret: &SecretKey,
    r_pub: &PublicKey,
) -> Option<SecretKey> {
    let view_scalar = Scalar::from_bytes_mod_order(view_secret.0);
    let r_point = CompressedRistretto(r_pub.0).decompress()?;
    let shared = view_scalar * r_point;
    let tweak = legacy_hash_to_scalar(b"knox-stealth", shared.compress().as_bytes());
    let spend_scalar = Scalar::from_bytes_mod_order(spend_secret.0);
    Some(SecretKey((spend_scalar + tweak).to_bytes()))
}

fn legacy_lattice_tweak_from_shared(
    shared_secret: &[u8; 32],
    one_time_pub: &[u8; 32],
    tx_pub: &[u8; 32],
) -> Poly {
    let mut data = Vec::with_capacity(96);
    data.extend_from_slice(shared_secret);
    data.extend_from_slice(one_time_pub);
    data.extend_from_slice(tx_pub);
    Poly::sample_short(b"knox-wallet-lattice-output-tweak-v1", &data)
}

fn legacy_lattice_output_secret_from_shared(
    base_secret: &LatticeSecretKey,
    shared_secret: &[u8; 32],
    one_time_pub: &[u8; 32],
    tx_pub: &[u8; 32],
) -> LatticeSecretKey {
    let tweak = legacy_lattice_tweak_from_shared(shared_secret, one_time_pub, tx_pub);
    LatticeSecretKey {
        s: base_secret.s.add(&tweak),
    }
}

fn wallet_scan_gap() -> u32 {
    env::var("KNOX_WALLET_SCAN_GAP")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(DEFAULT_SCAN_GAP)
}

fn ensure_default_subaddresses(state: &mut WalletState) {
    for idx in 0..DEFAULT_VISIBLE_SUBADDRESSES {
        if !state.subaddress_indices.contains(&idx) {
            state.subaddress_indices.push(idx);
        }
    }
    state.subaddress_indices.sort_unstable();
    state.subaddress_indices.dedup();
    state.next_subaddress_index = state
        .next_subaddress_index
        .max(
            state
                .subaddress_indices
                .iter()
                .copied()
                .max()
                .unwrap_or(0)
                .saturating_add(1),
        )
        .max(DEFAULT_VISIBLE_SUBADDRESSES);
}

fn scan_subaddress_indices(state: &WalletState) -> Vec<u32> {
    let upper = state
        .next_subaddress_index
        .max(DEFAULT_VISIBLE_SUBADDRESSES)
        .saturating_add(wallet_scan_gap());
    (0..upper).collect()
}

fn reward_kind_for_coinbase_output(height: u64, output_index: usize) -> Option<RewardKind> {
    let split = knox_lattice::coinbase::coinbase_split(height, 0, 1);
    let mut cursor = 0usize;
    if output_index == cursor {
        return Some(RewardKind::Miner);
    }
    cursor = cursor.saturating_add(1);
    if split.treasury > 0 {
        if output_index == cursor {
            return Some(RewardKind::Treasury);
        }
        cursor = cursor.saturating_add(1);
    }
    if split.dev > 0 {
        if output_index == cursor {
            return Some(RewardKind::Dev);
        }
        cursor = cursor.saturating_add(1);
    }
    if split.premine > 0 && output_index == cursor {
        return Some(RewardKind::Premine);
    }
    None
}

fn record_reward_event(
    state: &mut WalletState,
    note: &Note,
    block_height: u64,
    block_hash: Hash32,
    tx_hash: Hash32,
    output_index: u16,
) {
    if state
        .reward_records
        .iter()
        .any(|record| record.tx_hash == tx_hash && record.output_index == output_index)
    {
        return;
    }
    let Some(kind) = reward_kind_for_coinbase_output(block_height, output_index as usize) else {
        return;
    };
    state.reward_records.push(RewardRecord {
        block_height,
        block_hash,
        tx_hash,
        output_index,
        amount: note.amount,
        subaddress_index: note.subaddress_index,
        kind,
    });
}

fn coinbase_operator_identity(block: &knox_types::Block) -> Option<[u8; 32]> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reward_kind_maps_genesis_outputs_in_order() {
        let split = knox_lattice::coinbase::coinbase_split(0, 0, 1);
        assert_eq!(reward_kind_for_coinbase_output(0, 0), Some(RewardKind::Miner));
        assert_eq!(reward_kind_for_coinbase_output(0, 1), Some(RewardKind::Treasury));
        let mut next = 2usize;
        if split.dev > 0 {
            assert_eq!(reward_kind_for_coinbase_output(0, next), Some(RewardKind::Dev));
            next = next.saturating_add(1);
        }
        assert_eq!(
            reward_kind_for_coinbase_output(0, next),
            Some(RewardKind::Premine)
        );
        assert_eq!(reward_kind_for_coinbase_output(0, next.saturating_add(1)), None);
    }

    #[test]
    fn balances_group_by_subaddress_and_ignore_spent_notes() {
        let mut state = WalletState {
            view_secret: [0u8; 32],
            spend_secret: [0u8; 32],
            view_public: [0u8; 32],
            spend_public: [0u8; 32],
            notes: vec![
                Note {
                    out_ref: OutputRef {
                        tx: Hash32([1u8; 32]),
                        index: 0,
                    },
                    one_time_pub: [0u8; 32],
                    tx_pub: [0u8; 32],
                    lattice_spend_pub: Vec::new(),
                    lattice_one_time_secret: Vec::new(),
                    one_time_secret: [0u8; 32],
                    commitment: [0u8; 32],
                    amount: 10,
                    blinding: [0u8; 32],
                    key_image: [1u8; 32],
                    subaddress_index: 0,
                },
                Note {
                    out_ref: OutputRef {
                        tx: Hash32([2u8; 32]),
                        index: 1,
                    },
                    one_time_pub: [0u8; 32],
                    tx_pub: [0u8; 32],
                    lattice_spend_pub: Vec::new(),
                    lattice_one_time_secret: Vec::new(),
                    one_time_secret: [0u8; 32],
                    commitment: [0u8; 32],
                    amount: 20,
                    blinding: [0u8; 32],
                    key_image: [2u8; 32],
                    subaddress_index: 1,
                },
            ],
            reward_records: Vec::new(),
            spent_images: vec![[2u8; 32]],
            last_height: 0,
            subaddress_indices: vec![0, 1],
            next_subaddress_index: 2,
        };
        ensure_default_subaddresses(&mut state);
        assert_eq!(wallet_balances_by_subaddress(&state), vec![(0, 10), (1, 0)]);
    }
}

fn rpc_get_fib_wall(addr: &str, limit: u32) -> Result<Vec<knox_types::FibWallEntry>, String> {
    let resp = rpc_request(addr, knox_types::WalletRequest::GetFibWall(limit))?;
    match resp {
        knox_types::WalletResponse::FibWall(wall) => Ok(wall),
        _ => Err("unexpected response".to_string()),
    }
}

fn header_link_hash(header: &knox_types::BlockHeader) -> Hash32 {
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
    data.push(0);
    hash_tx_bytes(&data)
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
    multiplier_ppm
        .min(knox_types::STREAK_CAP_MULTIPLIER_PPM)
        .saturating_sub(1_000_000)
}

fn rpc_request(
    addr: &str,
    req: knox_types::WalletRequest,
) -> Result<knox_types::WalletResponse, String> {
    const MAX_RPC_RESPONSE_BYTES: usize = 512 * 1024 * 1024;
    let connect_timeout_ms = std::env::var("KNOX_RPC_CONNECT_TIMEOUT_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(15000)
        .clamp(200, 30000);
    let io_timeout_ms = std::env::var("KNOX_RPC_IO_TIMEOUT_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(120000)
        .clamp(200, 120000);
    let connect_timeout = Duration::from_millis(connect_timeout_ms);
    let io_timeout = Duration::from_millis(io_timeout_ms);

    let mut stream = connect_with_timeout(addr, connect_timeout)?;
    stream
        .set_read_timeout(Some(io_timeout))
        .map_err(|e| format!("set read timeout failed: {e}"))?;
    stream
        .set_write_timeout(Some(io_timeout))
        .map_err(|e| format!("set write timeout failed: {e}"))?;
    let bytes =
        bincode::encode_to_vec(req, bincode::config::standard()).map_err(|e| e.to_string())?;
    let mut out = Vec::with_capacity(4 + bytes.len());
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&bytes);
    stream.write_all(&out).map_err(|e| e.to_string())?;
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).map_err(|e| e.to_string())?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len == 0 || len > MAX_RPC_RESPONSE_BYTES {
        return Err(format!(
            "wallet rpc response too large ({} bytes > {} byte cap)",
            len, MAX_RPC_RESPONSE_BYTES
        ));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).map_err(|e| e.to_string())?;
    let (resp, _): (knox_types::WalletResponse, usize) = bincode::decode_from_slice(
        &buf,
        bincode::config::standard().with_limit::<{ 512 * 1024 * 1024 }>(),
    )
    .map_err(|e| e.to_string())?;
    Ok(resp)
}

fn connect_with_timeout(addr: &str, timeout: Duration) -> Result<TcpStream, String> {
    let addrs: Vec<SocketAddr> = addr
        .to_socket_addrs()
        .map_err(|e| format!("resolve {addr} failed: {e}"))?
        .collect();
    if addrs.is_empty() {
        return Err(format!("resolve {addr} returned no addresses"));
    }
    let mut last_err = None;
    for a in addrs {
        match TcpStream::connect_timeout(&a, timeout) {
            Ok(s) => return Ok(s),
            Err(e) => last_err = Some(format!("{a}: {e}")),
        }
    }
    Err(format!(
        "connect {addr} failed: {}",
        last_err.unwrap_or_else(|| "unknown error".to_string())
    ))
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn load_node_key(path: &str) -> Result<(SecretKey, PublicKey), String> {
    let bytes = fs::read(path).map_err(|e| e.to_string())?;
    load_node_key_bytes(&bytes)
}

fn load_node_key_bytes(bytes: &[u8]) -> Result<(SecretKey, PublicKey), String> {
    if bytes.len() == 64 {
        let mut sk = [0u8; 32];
        sk.copy_from_slice(&bytes[..32]);
        let sk = SecretKey(sk);
        let derived = PublicKey(derive_public_tag(b"knox-node-public-v2", &sk.0));
        return Ok((sk, derived));
    }
    if let Some(text) = decode_text(bytes) {
        let text = text.trim();
        if text.len() == 64 || text.len() == 128 {
            let raw = hex_decode(text)?;
            if raw.len() == 32 {
                let mut sk = [0u8; 32];
                sk.copy_from_slice(&raw);
                let sk = SecretKey(sk);
                let pk = PublicKey(derive_public_tag(b"knox-node-public-v2", &sk.0));
                return Ok((sk, pk));
            }
            if raw.len() == 64 {
                let mut sk = [0u8; 32];
                sk.copy_from_slice(&raw[..32]);
                let sk = SecretKey(sk);
                let pk = PublicKey(derive_public_tag(b"knox-node-public-v2", &sk.0));
                return Ok((sk, pk));
            }
        }
    }
    Err("invalid node key format".to_string())
}

fn decode_text(bytes: &[u8]) -> Option<String> {
    if bytes.len() >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF {
        if let Ok(text) = String::from_utf8(bytes[3..].to_vec()) {
            return Some(text);
        }
    }
    if let Ok(text) = String::from_utf8(bytes.to_vec()) {
        return Some(text);
    }
    if bytes.len() >= 2 {
        if bytes[0] == 0xFF && bytes[1] == 0xFE {
            let mut u16s = Vec::with_capacity((bytes.len() - 2) / 2);
            for chunk in bytes[2..].chunks_exact(2) {
                u16s.push(u16::from_le_bytes([chunk[0], chunk[1]]));
            }
            if let Ok(text) = String::from_utf16(&u16s) {
                return Some(text);
            }
        } else if bytes[0] == 0xFE && bytes[1] == 0xFF {
            let mut u16s = Vec::with_capacity((bytes.len() - 2) / 2);
            for chunk in bytes[2..].chunks_exact(2) {
                u16s.push(u16::from_be_bytes([chunk[0], chunk[1]]));
            }
            if let Ok(text) = String::from_utf16(&u16s) {
                return Some(text);
            }
        } else if bytes[1] == 0 {
            let mut u16s = Vec::with_capacity(bytes.len() / 2);
            for chunk in bytes.chunks_exact(2) {
                u16s.push(u16::from_le_bytes([chunk[0], chunk[1]]));
            }
            if let Ok(text) = String::from_utf16(&u16s) {
                return Some(text);
            }
        } else if bytes[0] == 0 {
            let mut u16s = Vec::with_capacity(bytes.len() / 2);
            for chunk in bytes.chunks_exact(2) {
                u16s.push(u16::from_be_bytes([chunk[0], chunk[1]]));
            }
            if let Ok(text) = String::from_utf16(&u16s) {
                return Some(text);
            }
        }
    }
    None
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("hex length".to_string());
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for i in (0..bytes.len()).step_by(2) {
        out.push((from_hex(bytes[i])? << 4) | from_hex(bytes[i + 1])?);
    }
    Ok(out)
}

fn from_hex(c: u8) -> Result<u8, String> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err("invalid hex".to_string()),
    }
}
