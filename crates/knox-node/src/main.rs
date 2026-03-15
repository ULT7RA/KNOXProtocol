use knox_consensus::{ConsensusConfig, ValidatorSet};
use knox_core::{Node, NodeConfig};
use getrandom::getrandom;
use knox_ledger::Ledger;
use knox_lattice::{
    consensus_public_from_secret, consensus_public_key_id, consensus_secret_from_seed,
    decode_consensus_public_key, LatticePublicKey, MiningProfile,
};
use knox_p2p::NetworkConfig;
use knox_types::{hash_bytes, Address, Block};
use std::fs;
use std::path::Path;
#[cfg(unix)]
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

const LATTICE_PUBKEY_BYTES: usize = knox_lattice::params::N * 2;

#[derive(Clone, Copy)]
struct SecretKey([u8; 32]);

#[derive(Clone, Copy)]
struct PublicKey([u8; 32]);

fn main() {
    if std::env::var("KNOX_NODE_EXIT_IMMEDIATELY").is_ok() {
        eprintln!("[FORGERing] immediate exit");
        return;
    }
    eprintln!("[FORGERing] entered");
    if std::env::var("KNOX_NODE_SMOKE").is_ok() {
        return;
    }
    eprintln!("[FORGERing] building runtime");
    // Run the async runtime on a dedicated large-stack thread so mining paths
    // cannot exhaust the default process main-thread stack on Windows.
    let handle = std::thread::Builder::new()
        .name("knox-main-runtime".to_string())
        .stack_size(64 * 1024 * 1024)
        .spawn(|| {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .thread_stack_size(32 * 1024 * 1024)
                .enable_io()
                .enable_time()
                .build()
                .expect("tokio runtime");
            eprintln!("[FORGERing] runtime built");
            rt.block_on(async_main());
        })
        .expect("spawn runtime thread");
    if let Err(err) = handle.join() {
        eprintln!("[FORGERing] runtime thread panicked: {:?}", err);
    }
}

async fn async_main() {
    eprintln!("[FORGERing] starting");
    let mut args = std::env::args().skip(1);
    let data_dir = args.next().unwrap_or_else(|| "./data".to_string());
    let bind = args.next().unwrap_or_else(|| "0.0.0.0:9735".to_string());
    let rpc_bind = args.next().unwrap_or_else(|| "127.0.0.1:9736".to_string());
    let peers_csv = args.next().unwrap_or_default();
    let fifth_arg = args.next();
    let (_validators_path, miner_addr_arg) = match fifth_arg {
        // Backward-compatible: if arg#5 is already an address, treat it as miner address.
        Some(v) if v.starts_with("knox1") || v.starts_with("KNOX1") => (String::new(), Some(v)),
        Some(v) => (v, args.next()),
        None => (String::new(), None),
    };
    if std::env::var("KNOX_PRINT_GENESIS_HASH").ok().as_deref() == Some("1") {
        match print_genesis_hash(&data_dir) {
            Ok(Some(h)) => {
                println!("{h}");
                return;
            }
            Ok(None) => {
                eprintln!("no genesis block found");
                return;
            }
            Err(e) => {
                eprintln!("genesis hash error: {e}");
                std::process::exit(1);
            }
        }
    }
    let lock = match load_mainnet_lock() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("mainnet lock config error: {e}");
            std::process::exit(1);
        }
    };
    if let Some(lock) = &lock {
        if let Err(e) = enforce_mainnet_preflight(lock, &data_dir) {
            eprintln!("mainnet lock violation: {e}");
            std::process::exit(1);
        }
    }

    eprintln!("[FORGERing] loading keypair");
    let keypair = load_or_create_keypair(&data_dir).unwrap_or_else(|e| {
        eprintln!("key error: {e}");
        std::process::exit(1);
    });
    let consensus_secret = consensus_secret_from_seed(&keypair.0.0);
    let consensus_public = consensus_public_from_secret(&consensus_secret);

    let peers = peers_csv
        .split(',')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect::<Vec<_>>();
    let (diamond_authenticators, diamond_auth_quorum) =
        load_diamond_authenticators().unwrap_or_else(|e| {
            eprintln!("diamond authenticator config error: {e}");
            std::process::exit(1);
        });
    let diamond_auth_endpoints = load_diamond_auth_endpoints();
    if !diamond_authenticators.is_empty() {
        eprintln!(
            "[FORGERing] diamond auth enabled authenticators={} quorum={} endpoints={}",
            diamond_authenticators.len(),
            diamond_auth_quorum,
            diamond_auth_endpoints.len()
        );
    }

    let miner_address = match miner_addr_arg {
        Some(addr) => match parse_address(&addr) {
            Ok(a) => a,
            Err(e) => {
                eprintln!("miner address error: {e}");
                std::process::exit(1);
            }
        },
        None => derive_address_from_node_key(&keypair.0),
    };
    if !rpc_bind.starts_with("127.0.0.1:") && rpc_bind != "-" {
        let allow_remote = std::env::var("KNOX_NODE_RPC_ALLOW_REMOTE")
            .map(|v| {
                let v = v.trim();
                v == "1" || v.eq_ignore_ascii_case("true")
            })
            .unwrap_or(false);
        if !allow_remote {
            eprintln!(
                "rpc bind error: remote RPC is disabled by default (set KNOX_NODE_RPC_ALLOW_REMOTE=1 to override)"
            );
            std::process::exit(1);
        }
    }
    if let Err(e) = enforce_existing_genesis(lock.as_ref(), &data_dir) {
        eprintln!("genesis consistency violation: {e}");
        std::process::exit(1);
    }

    // Emit ledger tip stats so the desktop UI can pre-populate height and
    // hardening without waiting for the first sealed block.
    // Hardening is computed directly from the difficulty schedule (deterministic
    // per height) rather than scanning blocks, so it is always correct regardless
    // of whether the local ledger has synced all blocks yet.
    {
        if let Err(err) = seed_embedded_genesis(&data_dir) {
            eprintln!("embedded genesis seed error: {err}");
            std::process::exit(1);
        }
        let ledger_path = format!("{}/ledger", data_dir);
        if let Ok(ledger) = Ledger::open(&ledger_path) {
            let tip = ledger.height().unwrap_or(0);
            let hardening: u64 = (0..=tip)
                .map(|h| knox_lattice::difficulty_bits(h) as u64)
                .sum();
            eprintln!("[FORGERing] ledger tip h={} hardening={}", tip, hardening);
        }
    }

    let premine_address = lock
        .as_ref()
        .map(|l| l.premine_address.clone())
        .unwrap_or_else(|| miner_address.clone());
    let treasury_address = lock
        .as_ref()
        .and_then(|l| l.treasury_address.clone())
        .unwrap_or_else(|| miner_address.clone());
    let p2p_protocol_version = std::env::var("KNOX_P2P_PROTOCOL_VERSION")
        .ok()
        .and_then(|v| v.trim().parse::<u32>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(2);
    let p2p_genesis_hash_hex = lock
        .as_ref()
        .and_then(|l| l.genesis_hash_hex.clone())
        .map(Ok)
        .unwrap_or_else(embedded_genesis_hash_hex);
    let p2p_genesis_hash = match p2p_genesis_hash_hex
        .and_then(|h| parse_hash32_hex(&h))
    {
        Ok(v) => v,
        Err(e) => {
            eprintln!("p2p genesis hash config error: {e}");
            std::process::exit(1);
        }
    };

    let cfg = NodeConfig {
        data_dir,
        network: NetworkConfig {
            bind,
            peers,
            max_peers: 1024,
            pad_bytes: 1024,
            cover_interval_ms: 5000,
            lattice_public: Some(consensus_public.p.to_bytes()),
            lattice_secret: Some(consensus_secret.s.to_bytes()),
            protocol_version: p2p_protocol_version,
            genesis_hash: p2p_genesis_hash,
        },
        consensus: ConsensusConfig {
            epoch_length: 120,
            committee_size: 100,
            max_round_ms: 10_000,
        },
        validators: ValidatorSet { validators: Vec::new() },
        consensus_keypair: Some((consensus_secret, consensus_public)),
        rpc_bind,
        miner_address: miner_address.clone(),
        treasury_address,
        dev_address: miner_address.clone(),
        premine_address,
        mining_enabled: mining_enabled(),
        mining_profile: MiningProfile::from_env(),
        diamond_authenticators,
        diamond_auth_quorum,
        diamond_auth_endpoints,
    };

    eprintln!("[FORGERing] starting node");
    match Node::new(cfg).await {
        Ok(node) => node.run().await,
        Err(err) => {
            eprintln!("node init error: {err}");
        }
    }
}

fn seed_embedded_genesis(data_dir: &str) -> Result<(), String> {
    const EMBEDDED_GENESIS: &[u8] = include_bytes!("genesis.bin");
    if EMBEDDED_GENESIS.is_empty() {
        return Ok(());
    }
    let ledger_path = format!("{}/ledger", data_dir);
    let ledger = Ledger::open(&ledger_path).map_err(|e| e.to_string())?;
    if ledger.get_block(0)?.is_some() {
        return Ok(());
    }
    let (block, _): (Block, usize) =
        bincode::decode_from_slice(EMBEDDED_GENESIS, bincode::config::standard())
            .map_err(|e| format!("embedded genesis decode failed: {e}"))?;
    ledger
        .append_block(&block)
        .map_err(|e| format!("embedded genesis append failed: {e}"))?;
    eprintln!("[FORGERing] seeded embedded genesis h=0");
    Ok(())
}

fn derive_address_from_node_key(sk: &SecretKey) -> Address {
    if std::env::var("KNOX_NODE_ADDRESS_RAW").ok().as_deref() == Some("1") {
        let pk = public_from_secret(sk);
        let lattice_pub = lattice_base_public_from_seed(&sk.0);
        return Address {
            view: pk.0,
            spend: pk.0,
            lattice_spend_pub: lattice_pub.p.to_bytes(),
        };
    }
    let view_sk = derive_secret_tag(b"knox-wallet-view-v2", &sk.0);
    let spend_sk = derive_secret_tag(b"knox-wallet-spend-v2", &sk.0);
    let view_pk = public_from_secret(&SecretKey(view_sk));
    let spend_pk = public_from_secret(&SecretKey(spend_sk));
    let lattice_pub = lattice_base_public_from_seed(&spend_sk);
    Address {
        view: view_pk.0,
        spend: spend_pk.0,
        lattice_spend_pub: lattice_pub.p.to_bytes(),
    }
}

fn load_or_create_keypair(data_dir: &str) -> Result<(SecretKey, PublicKey), String> {
    if std::env::var("KNOX_NODE_EPHEMERAL_KEY").is_ok() {
        eprintln!("[FORGERing] ephemeral keypair (no file IO)");
        let sk = SecretKey(random_secret_bytes()?);
        let pk = public_from_secret(&sk);
        return Ok((sk, pk));
    }
    if let Ok(hex) = std::env::var("KNOX_NODE_KEY_HEX") {
        let hex = hex.trim();
        if hex.len() == 64 {
            let raw = hex_decode(hex)?;
            if raw.len() == 32 {
                let mut sk = [0u8; 32];
                sk.copy_from_slice(&raw);
                let pk = public_from_secret(&SecretKey(sk));
                eprintln!("[FORGERing] key loaded from env");
                return Ok((SecretKey(sk), pk));
            }
        }
        return Err("KNOX_NODE_KEY_HEX must be 64 hex chars (secret key only)".to_string());
    }

    let path = Path::new(data_dir).join("node.key");
    eprintln!("[FORGERing] key file: {}", path.display());
    #[cfg(unix)]
    if let Ok(meta) = fs::metadata(&path) {
        let mode = meta.permissions().mode() & 0o777;
        if mode != 0o600 {
            return Err(format!(
                "node key permissions must be 0o600 (found {:o})",
                mode
            ));
        }
    }
    if let Ok(bytes) = fs::read(&path) {
        eprintln!("[FORGERing] key bytes: {}", bytes.len());
        if bytes.len() == 64 {
            let mut sk = [0u8; 32];
            sk.copy_from_slice(&bytes[..32]);
            let pk = public_from_secret(&SecretKey(sk));
            eprintln!("[FORGERing] key loaded (raw)");
            return Ok((SecretKey(sk), pk));
        }
        if let Some(text) = decode_text(&bytes) {
            let text = text.trim();
            eprintln!("[FORGERing] key text len: {}", text.len());
            if text.len() == 128 {
                let raw = hex_decode(text)?;
                if raw.len() == 64 {
                    let mut sk = [0u8; 32];
                    sk.copy_from_slice(&raw[..32]);
                    let pk = public_from_secret(&SecretKey(sk));
                    eprintln!("[FORGERing] key loaded (hex)");
                    return Ok((SecretKey(sk), pk));
                }
            }
        } else {
            eprintln!("[FORGERing] key text decode failed");
        }
    }
    eprintln!("[FORGERing] generating keypair");
    fs::create_dir_all(data_dir).map_err(|e| e.to_string())?;
    let sk = SecretKey(random_secret_bytes()?);
    let pk = public_from_secret(&sk);
    let mut bytes = Vec::with_capacity(64);
    bytes.extend_from_slice(&sk.0);
    bytes.extend_from_slice(&pk.0);
    #[cfg(unix)]
    {
        let mut f = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| e.to_string())?;
        f.write_all(&bytes).map_err(|e| e.to_string())?;
    }
    #[cfg(not(unix))]
    {
        fs::write(path, bytes).map_err(|e| e.to_string())?;
    }
    eprintln!("[FORGERing] key generated and saved");
    Ok((sk, pk))
}

fn load_diamond_authenticators() -> Result<(Vec<LatticePublicKey>, usize), String> {
    let raw = std::env::var("KNOX_DIAMOND_AUTH_PUBKEYS").unwrap_or_default();
    let quorum = std::env::var("KNOX_DIAMOND_AUTH_QUORUM")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(2)
        .max(1);
    if raw.trim().is_empty() {
        return Ok((Vec::new(), quorum));
    }
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for item in raw.split(',') {
        let hex = item.trim();
        if hex.is_empty() {
            continue;
        }
        let bytes = hex_decode(hex)?;
        let pk = decode_consensus_public_key(&bytes)?;
        let id = consensus_public_key_id(&pk);
        if seen.insert(id) {
            out.push(pk);
        }
    }
    if !out.is_empty() && quorum > out.len() {
        return Err(format!(
            "KNOX_DIAMOND_AUTH_QUORUM={} exceeds configured authenticators {}",
            quorum,
            out.len()
        ));
    }
    Ok((out, quorum))
}

fn load_diamond_auth_endpoints() -> Vec<String> {
    let raw = std::env::var("KNOX_DIAMOND_AUTH_ENDPOINTS").unwrap_or_default();
    if raw.trim().is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for item in raw.split(',') {
        let endpoint = item.trim().to_string();
        if endpoint.is_empty() {
            continue;
        }
        if seen.insert(endpoint.clone()) {
            out.push(endpoint);
        }
    }
    out
}

#[derive(Clone)]
struct MainnetLock {
    premine_address: Address,
    treasury_address: Option<Address>,
    genesis_hash_hex: Option<String>,
}

fn load_mainnet_lock() -> Result<Option<MainnetLock>, String> {
    if std::env::var("KNOX_MAINNET_LOCK").ok().as_deref() != Some("1") {
        return Ok(None);
    }
    let premine_str = std::env::var("KNOX_MAINNET_PREMINE_ADDRESS").map_err(|_| {
        "KNOX_MAINNET_PREMINE_ADDRESS is required when KNOX_MAINNET_LOCK=1".to_string()
    })?;
    let premine_address = parse_address(&premine_str)?;
    let treasury_address = std::env::var("KNOX_MAINNET_TREASURY_ADDRESS")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .map(|v| parse_address(&v))
        .transpose()?;
    let genesis_hash_hex = std::env::var("KNOX_MAINNET_GENESIS_HASH")
        .ok()
        .map(|v| v.trim().to_ascii_lowercase())
        .filter(|v| !v.is_empty());
    Ok(Some(MainnetLock {
        premine_address,
        treasury_address,
        genesis_hash_hex,
    }))
}

fn enforce_mainnet_preflight(
    lock: &MainnetLock,
    data_dir: &str,
) -> Result<(), String> {
    let _ = lock;
    for forbidden in [
        "KNOX_NODE_EPHEMERAL_KEY",
        "KNOX_NODE_SKIP_VALIDATORS",
        "KNOX_NODE_KEY_HEX",
        "KNOX_NODE_ADDRESS_RAW",
        "KNOX_NODE_ALLOW_ANY_VALIDATORS_PATH",
        "KNOX_P2P_PSK",
        "KNOX_P2P_ALLOW_PLAINTEXT",
        "KNOX_ALLOW_UNSAFE_OVERRIDES",
        "KNOX_LATTICE_OPEN_MINING",
        "KNOX_LATTICE_MINING_DEBUG",
        "KNOX_LATTICE_DEBUG_DIFFICULTY_BITS",
        "KNOX_LATTICE_DEBUG_SEQ_STEPS",
        "KNOX_LATTICE_DEBUG_MEMORY_BYTES",
        "KNOX_NODE_MINING_MODE",
        "KNOX_NODE_MINING_BACKEND",
        "KNOX_NODE_MINING_DIFFICULTY_BITS",
        "KNOX_NODE_MINING_SEQ_STEPS",
        "KNOX_NODE_MINING_MEMORY_BYTES",
        "KNOX_NODE_MINING_CPU_UTIL",
        "KNOX_NODE_MINING_GPU_UTIL",
        "KNOX_NODE_GPU_DEVICE_ID",
        "KNOX_NODE_CUDA_DEVICE_ORDINAL",
        "KNOX_DESKTOP_LOCAL_ALLOW_UNVERIFIED",
    ] {
        if std::env::var(forbidden).is_ok() {
            return Err(format!("{forbidden} is forbidden in mainnet lock mode"));
        }
    }
    let key_path = Path::new(data_dir).join("node.key");
    if !key_path.exists() {
        return Err(format!(
            "missing required node key file: {}",
            key_path.display()
        ));
    }
    #[cfg(unix)]
    {
        let mode = fs::metadata(&key_path)
            .map_err(|e| format!("node key metadata failed: {e}"))?
            .permissions()
            .mode()
            & 0o777;
        if mode != 0o600 {
            return Err(format!(
                "node.key must have mode 0o600 in mainnet lock mode (found {:o})",
                mode
            ));
        }
    }
    Ok(())
}

fn enforce_existing_genesis(lock: Option<&MainnetLock>, data_dir: &str) -> Result<(), String> {
    let embedded = embedded_genesis_hash_hex()?;
    let expected = match lock.and_then(|l| l.genesis_hash_hex.as_ref()) {
        Some(v) => {
            if *v != embedded {
                return Err(format!(
                    "configured KNOX_MAINNET_GENESIS_HASH does not match embedded genesis (configured {v}, embedded {embedded})"
                ));
            }
            v.clone()
        }
        None => embedded,
    };
    let ledger = Ledger::open(&format!("{}/ledger", data_dir)).map_err(|e| e.to_string())?;
    let block0 = match ledger.get_block(0)? {
        Some(b) => b,
        None => return Ok(()),
    };
    let header_bytes = bincode::encode_to_vec(&block0.header, bincode::config::standard())
        .map_err(|e| e.to_string())?;
    let got = hex_encode(&hash_bytes(&header_bytes).0);
    if got != expected {
        return Err(format!(
            "genesis hash mismatch (expected {expected}, got {got}). remove '{}/ledger' and resync",
            data_dir
        ));
    }
    Ok(())
}

fn embedded_genesis_hash_hex() -> Result<String, String> {
    const EMBEDDED_GENESIS: &[u8] = include_bytes!("genesis.bin");
    if EMBEDDED_GENESIS.is_empty() {
        return Err("embedded genesis is empty".to_string());
    }
    let (block, _): (Block, usize) =
        bincode::decode_from_slice(EMBEDDED_GENESIS, bincode::config::standard())
            .map_err(|e| format!("embedded genesis decode failed: {e}"))?;
    let header_bytes = bincode::encode_to_vec(&block.header, bincode::config::standard())
        .map_err(|e| format!("embedded genesis header encode failed: {e}"))?;
    Ok(hex_encode(&hash_bytes(&header_bytes).0))
}

fn mining_enabled() -> bool {
    if let Ok(val) = std::env::var("KNOX_NODE_NO_MINE") {
        let val = val.trim();
        if val == "1" || val.eq_ignore_ascii_case("true") {
            return false;
        }
    }
    if let Ok(val) = std::env::var("KNOX_NODE_MINING") {
        let val = val.trim();
        if val == "0" || val.eq_ignore_ascii_case("false") {
            return false;
        }
    }
    true
}

fn print_genesis_hash(data_dir: &str) -> Result<Option<String>, String> {
    let ledger = Ledger::open(&format!("{}/ledger", data_dir)).map_err(|e| e.to_string())?;
    let block0 = match ledger.get_block(0)? {
        Some(b) => b,
        None => return Ok(None),
    };
    let header_bytes = bincode::encode_to_vec(&block0.header, bincode::config::standard())
        .map_err(|e| e.to_string())?;
    let digest = hash_bytes(&header_bytes);
    Ok(Some(hex_encode(&digest.0)))
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
        if bytes.len() >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE {
            let mut u16s = Vec::with_capacity((bytes.len() - 2) / 2);
            for chunk in bytes[2..].chunks_exact(2) {
                u16s.push(u16::from_le_bytes([chunk[0], chunk[1]]));
            }
            if let Ok(text) = String::from_utf16(&u16s) {
                return Some(text);
            }
        } else if bytes.len() >= 2 && bytes[0] == 0xFE && bytes[1] == 0xFF {
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

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return Err("hex string length must be even".to_string());
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let hi = from_hex(bytes[i])?;
        let lo = from_hex(bytes[i + 1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn parse_hash32_hex(s: &str) -> Result<[u8; 32], String> {
    let bytes = hex_decode(s)?;
    if bytes.len() != 32 {
        return Err(format!("expected 32-byte hash, got {} bytes", bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn from_hex(c: u8) -> Result<u8, String> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err("invalid hex char".to_string()),
    }
}

fn parse_address(s: &str) -> Result<Address, String> {
    let s = s.trim();
    if !s.starts_with("knox1") {
        return Err("address must start with knox1".to_string());
    }
    let data = &s[5..];
    let expected_len = 64 + 64 + (LATTICE_PUBKEY_BYTES * 2);
    if data.len() != expected_len {
        return Err(format!(
            "address length must be {} hex chars",
            expected_len
        ));
    }
    let view = hex_decode(&data[..64])?;
    let spend = hex_decode(&data[64..128])?;
    let lattice_spend_pub = hex_decode(&data[128..])?;
    if view.len() != 32 || spend.len() != 32 {
        return Err("address bytes invalid".to_string());
    }
    knox_lattice::Poly::from_bytes(&lattice_spend_pub)
        .map_err(|_| "address lattice key invalid".to_string())?;
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

fn lattice_base_public_from_seed(spend_secret: &[u8; 32]) -> knox_lattice::LatticePublicKey {
    let secret = knox_lattice::LatticeSecretKey {
        s: knox_lattice::Poly::sample_short(b"knox-wallet-lattice-base-v1", spend_secret),
    };
    knox_lattice::ring_sig::public_from_secret(&secret)
}

fn public_from_secret(secret: &SecretKey) -> PublicKey {
    PublicKey(derive_secret_tag(b"knox-node-public-v2", &secret.0))
}

fn derive_secret_tag(domain: &[u8], seed: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(domain);
    h.update(seed);
    *h.finalize().as_bytes()
}

fn random_secret_bytes() -> Result<[u8; 32], String> {
    let mut out = [0u8; 32];
    getrandom(&mut out).map_err(|e| format!("getrandom failed: {e}"))?;
    Ok(out)
}
