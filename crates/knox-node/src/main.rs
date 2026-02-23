use knox_consensus::{ConsensusConfig, ValidatorSet};
use knox_core::{Node, NodeConfig};
use knox_crypto::{generate_keypair, hash_to_scalar, public_from_secret, PublicKey, SecretKey};
use knox_ledger::Ledger;
use knox_lattice::{
    consensus_public_from_secret, consensus_public_key_id, consensus_secret_from_seed,
    decode_consensus_public_key, encode_consensus_public_key, LatticePublicKey, MiningProfile,
};
use knox_p2p::NetworkConfig;
use knox_types::{hash_bytes, Address};
use std::fs;
use std::io::Write;
use std::path::Path;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

const LATTICE_PUBKEY_BYTES: usize = knox_lattice::params::N * 2;
const GENESIS_BYTES: &[u8] = include_bytes!("genesis.bin");

fn main() {
    if std::env::var("KNOX_NODE_EXIT_IMMEDIATELY").is_ok() {
        eprintln!("[knox-node] immediate exit");
        return;
    }
    eprintln!("[knox-node] entered");
    if std::env::var("KNOX_NODE_SMOKE").is_ok() {
        return;
    }
    eprintln!("[knox-node] building runtime");
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
            eprintln!("[knox-node] runtime built");
            rt.block_on(async_main());
        })
        .expect("spawn runtime thread");
    if let Err(err) = handle.join() {
        eprintln!("[knox-node] runtime thread panicked: {:?}", err);
    }
}

async fn async_main() {
    eprintln!("[knox-node] starting");
    let mut args = std::env::args().skip(1);
    let data_dir = args.next().unwrap_or_else(|| "./data".to_string());
    let bind = args.next().unwrap_or_else(|| "0.0.0.0:9735".to_string());
    let rpc_bind = args.next().unwrap_or_else(|| "127.0.0.1:9736".to_string());
    let peers_csv = args.next().unwrap_or_default();
    let validators_path = args
        .next()
        .unwrap_or_else(|| format!("{}/validators.txt", data_dir));
    let miner_addr_arg = args.next();
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
        if let Err(e) = enforce_mainnet_preflight(lock, &data_dir, &validators_path) {
            eprintln!("mainnet lock violation: {e}");
            std::process::exit(1);
        }
    }

    eprintln!("[knox-node] loading keypair");
    let keypair = load_or_create_keypair(&data_dir).unwrap_or_else(|e| {
        eprintln!("key error: {e}");
        std::process::exit(1);
    });
    let consensus_secret = consensus_secret_from_seed(&keypair.0.0);
    let consensus_public = consensus_public_from_secret(&consensus_secret);

    eprintln!("[knox-node] loading validators");
    let validators = load_validators(&data_dir, &validators_path, consensus_public.clone())
        .unwrap_or_else(|e| {
            eprintln!("validators error: {e}");
            std::process::exit(1);
        });

    let peers = peers_csv
        .split(',')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect::<Vec<_>>();

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
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        if !allow_remote {
            eprintln!(
                "rpc bind error: remote RPC is disabled by default (set KNOX_NODE_RPC_ALLOW_REMOTE=1 to override)"
            );
            std::process::exit(1);
        }
    }
    if let Some(lock) = &lock {
        if miner_address != lock.premine_address {
            eprintln!(
                "mainnet lock violation: premine/miner address mismatch (expected {})",
                address_to_string(&lock.premine_address)
            );
            std::process::exit(1);
        }
        if let Err(e) = enforce_validators_hash(lock, &validators_path) {
            eprintln!("mainnet lock violation: {e}");
            std::process::exit(1);
        }
        if let Err(e) = enforce_existing_genesis(lock, &data_dir) {
            eprintln!("mainnet lock violation: {e}");
            std::process::exit(1);
        }
    }

    seed_genesis_if_empty(&data_dir, &validators.validators);

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
        },
        consensus: ConsensusConfig {
            epoch_length: 120,
            committee_size: 100,
            max_round_ms: 10_000,
        },
        validators,
        consensus_keypair: Some((consensus_secret, consensus_public)),
        rpc_bind,
        miner_address: miner_address.clone(),
        treasury_address: miner_address.clone(),
        dev_address: miner_address.clone(),
        premine_address: miner_address,
        mining_enabled: mining_enabled(),
        mining_profile: MiningProfile::from_env(),
    };

    eprintln!("[knox-node] starting node");
    match Node::new(cfg).await {
        Ok(node) => node.run().await,
        Err(err) => {
            eprintln!("node init error: {err}");
        }
    }
}

fn derive_address_from_node_key(sk: &SecretKey) -> Address {
    if std::env::var("KNOX_NODE_ADDRESS_RAW").ok().as_deref() == Some("1") {
        let pk = public_from_secret(sk);
        let lattice_pub = lattice_base_public_from_curve_spend_secret(&sk.0);
        return Address {
            view: pk.0,
            spend: pk.0,
            lattice_spend_pub: lattice_pub.p.to_bytes(),
        };
    }
    let view_sk = hash_to_scalar(b"knox-wallet-view", &sk.0).to_bytes();
    let spend_sk = hash_to_scalar(b"knox-wallet-spend", &sk.0).to_bytes();
    let view_pk = public_from_secret(&SecretKey(view_sk));
    let spend_pk = public_from_secret(&SecretKey(spend_sk));
    let lattice_pub = lattice_base_public_from_curve_spend_secret(&spend_sk);
    Address {
        view: view_pk.0,
        spend: spend_pk.0,
        lattice_spend_pub: lattice_pub.p.to_bytes(),
    }
}

fn load_or_create_keypair(data_dir: &str) -> Result<(SecretKey, PublicKey), String> {
    if std::env::var("KNOX_NODE_EPHEMERAL_KEY").is_ok() {
        eprintln!("[knox-node] ephemeral keypair (no file IO)");
        return generate_keypair();
    }
    if let Ok(hex) = std::env::var("KNOX_NODE_KEY_HEX") {
        let hex = hex.trim();
        if hex.len() == 64 {
            let raw = hex_decode(hex)?;
            if raw.len() == 32 {
                let mut sk = [0u8; 32];
                sk.copy_from_slice(&raw);
                let pk = public_from_secret(&SecretKey(sk));
                eprintln!("[knox-node] key loaded from env");
                return Ok((SecretKey(sk), pk));
            }
        }
        return Err("KNOX_NODE_KEY_HEX must be 64 hex chars (secret key only)".to_string());
    }

    let path = Path::new(data_dir).join("node.key");
    eprintln!("[knox-node] key file: {}", path.display());
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
        eprintln!("[knox-node] key bytes: {}", bytes.len());
        if bytes.len() == 64 {
            let mut sk = [0u8; 32];
            let mut pk = [0u8; 32];
            sk.copy_from_slice(&bytes[..32]);
            pk.copy_from_slice(&bytes[32..]);
            eprintln!("[knox-node] key loaded (raw)");
            return Ok((SecretKey(sk), PublicKey(pk)));
        }
        if let Some(text) = decode_text(&bytes) {
            let text = text.trim();
            eprintln!("[knox-node] key text len: {}", text.len());
            if text.len() == 128 {
                let raw = hex_decode(text)?;
                if raw.len() == 64 {
                    let mut sk = [0u8; 32];
                    let mut pk = [0u8; 32];
                    sk.copy_from_slice(&raw[..32]);
                    pk.copy_from_slice(&raw[32..]);
                    eprintln!("[knox-node] key loaded (hex)");
                    return Ok((SecretKey(sk), PublicKey(pk)));
                }
            }
        } else {
            eprintln!("[knox-node] key text decode failed");
        }
    }
    eprintln!("[knox-node] generating keypair");
    fs::create_dir_all(data_dir).map_err(|e| e.to_string())?;
    let (sk, pk) = generate_keypair()?;
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
    eprintln!("[knox-node] key generated and saved");
    Ok((sk, pk))
}

#[derive(Clone)]
struct MainnetLock {
    premine_address: Address,
    validators_hash_hex: String,
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
    let validators_hash_hex = std::env::var("KNOX_MAINNET_VALIDATORS_HASH").map_err(|_| {
        "KNOX_MAINNET_VALIDATORS_HASH is required when KNOX_MAINNET_LOCK=1".to_string()
    })?;
    let genesis_hash_hex = std::env::var("KNOX_MAINNET_GENESIS_HASH")
        .ok()
        .map(|v| v.trim().to_ascii_lowercase())
        .filter(|v| !v.is_empty());
    Ok(Some(MainnetLock {
        premine_address,
        validators_hash_hex: validators_hash_hex.trim().to_ascii_lowercase(),
        genesis_hash_hex,
    }))
}

fn enforce_mainnet_preflight(
    lock: &MainnetLock,
    data_dir: &str,
    validators_path: &str,
) -> Result<(), String> {
    let _ = lock;
    for forbidden in [
        "KNOX_NODE_EPHEMERAL_KEY",
        "KNOX_NODE_SKIP_VALIDATORS",
        "KNOX_NODE_KEY_HEX",
        "KNOX_NODE_ADDRESS_RAW",
        "KNOX_NODE_ALLOW_ANY_VALIDATORS_PATH",
        "KNOX_P2P_PSK",
        "KNOX_P2P_PSK_SERVICE",
        "KNOX_P2P_PSK_ACCOUNT",
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
    if !Path::new(validators_path).exists() {
        return Err(format!(
            "missing required validators file: {validators_path}"
        ));
    }
    Ok(())
}

fn enforce_validators_hash(lock: &MainnetLock, validators_path: &str) -> Result<(), String> {
    let bytes = fs::read(validators_path).map_err(|e| e.to_string())?;
    let digest = hash_bytes(&bytes);
    let got = hex_encode(&digest.0);
    if got != lock.validators_hash_hex {
        return Err(format!(
            "validators hash mismatch (expected {}, got {})",
            lock.validators_hash_hex, got
        ));
    }
    Ok(())
}

fn enforce_existing_genesis(lock: &MainnetLock, data_dir: &str) -> Result<(), String> {
    let expected = match &lock.genesis_hash_hex {
        Some(v) => v,
        None => return Ok(()),
    };
    let ledger = Ledger::open(&format!("{}/ledger", data_dir)).map_err(|e| e.to_string())?;
    let block0 = match ledger.get_block(0)? {
        Some(b) => b,
        None => return Ok(()),
    };
    let header_bytes = bincode::encode_to_vec(&block0.header, bincode::config::standard())
        .map_err(|e| e.to_string())?;
    let got = hex_encode(&hash_bytes(&header_bytes).0);
    if &got != expected {
        return Err(format!(
            "genesis hash mismatch (expected {expected}, got {got})"
        ));
    }
    Ok(())
}

fn mining_enabled() -> bool {
    if let Ok(val) = std::env::var("KNOX_NODE_NO_MINE") {
        if val == "1" || val.eq_ignore_ascii_case("true") {
            return false;
        }
    }
    if let Ok(val) = std::env::var("KNOX_NODE_MINING") {
        if val == "0" || val.eq_ignore_ascii_case("false") {
            return false;
        }
    }
    true
}

fn load_validators(
    data_dir: &str,
    path: &str,
    local_pk: LatticePublicKey,
) -> Result<ValidatorSet, String> {
    if std::env::var("KNOX_NODE_SKIP_VALIDATORS").is_ok() {
        eprintln!("[knox-node] validators skipped (env)");
        return Ok(ValidatorSet {
            validators: vec![local_pk],
        });
    }
    let path_obj = Path::new(path);
    let parent = path_obj.parent().unwrap_or(Path::new("."));
    fs::create_dir_all(parent).map_err(|e| format!("validators parent create failed: {e}"))?;
    let canonical_parent = normalize_path(parent).map_err(|e| {
        format!(
            "validators parent normalize failed ({}): {e}",
            parent.display()
        )
    })?;
    let canonical_data = normalize_path(Path::new(data_dir))
        .map_err(|e| format!("data dir normalize failed ({}): {e}", data_dir))?;
    let allow_any = std::env::var("KNOX_NODE_ALLOW_ANY_VALIDATORS_PATH")
        .ok()
        .as_deref()
        == Some("1");
    let canonical_validators = normalize_path(path_obj).map_err(|e| {
        format!(
            "validators path normalize failed ({}): {e}",
            path_obj.display()
        )
    })?;
    if !allow_any
        && !path_within(&canonical_parent, &canonical_data)
        && !path_within(&canonical_validators, &canonical_data)
    {
        return Err(format!(
            "validators path must be inside node data dir (set KNOX_NODE_ALLOW_ANY_VALIDATORS_PATH=1 to override); parent={}, validators={}, data={}",
            canonical_parent.display(),
            canonical_validators.display(),
            canonical_data.display()
        ));
    }
    if Path::new(path).exists() {
        let meta =
            fs::symlink_metadata(path).map_err(|e| format!("validators metadata failed: {e}"))?;
        if !meta.file_type().is_file() || meta.file_type().is_symlink() {
            return Err("validators path must be a regular file".to_string());
        }
    }
    if let Ok(text) = read_text_file(path) {
        let mut vals = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let bytes = hex_decode(line)?;
            let pk = decode_consensus_public_key(&bytes)?;
            let id = consensus_public_key_id(&pk);
            if seen.insert(id) {
                vals.push(pk);
            }
        }
        if vals.is_empty() {
            vals.push(local_pk);
        } else {
            // When set, ensure the local node can participate as a validator
            // (mine blocks) even if its key is not in the validators file.
            let include_local = std::env::var("KNOX_NODE_INCLUDE_LOCAL_VALIDATOR")
                .ok()
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);
            if include_local {
                let local_id = consensus_public_key_id(&local_pk);
                if !seen.contains(&local_id) {
                    vals.push(local_pk);
                }
            }
        }
        Ok(ValidatorSet { validators: vals })
    } else {
        let line = hex_encode(&encode_consensus_public_key(&local_pk));
        fs::create_dir_all(Path::new(path).parent().unwrap_or(Path::new(".")))
            .map_err(|e| format!("validators dir create failed: {e}"))?;
        fs::write(path, format!("{}\n", line))
            .map_err(|e| format!("validators write failed: {e}"))?;
        Ok(ValidatorSet {
            validators: vec![local_pk],
        })
    }
}

fn normalize_path(p: &Path) -> Result<std::path::PathBuf, String> {
    match p.canonicalize() {
        Ok(v) => Ok(v),
        Err(_) => {
            let joined = if p.is_absolute() {
                p.to_path_buf()
            } else {
                std::env::current_dir().map_err(|e| e.to_string())?.join(p)
            };
            Ok(joined)
        }
    }
}

fn path_within(child: &Path, base: &Path) -> bool {
    #[cfg(windows)]
    {
        let c = child
            .to_string_lossy()
            .replace('/', "\\")
            .to_ascii_lowercase();
        let b = base
            .to_string_lossy()
            .replace('/', "\\")
            .to_ascii_lowercase();
        return c == b || c.starts_with(&(b + "\\"));
    }
    #[cfg(not(windows))]
    {
        child == base || child.starts_with(base)
    }
}

fn seed_genesis_if_empty(data_dir: &str, validators: &[LatticePublicKey]) {
    let ledger_path = format!("{}/ledger", data_dir);
    let mut ledger = match Ledger::open(&ledger_path) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("[knox-node] genesis seed: ledger open failed: {e}");
            return;
        }
    };
    match ledger.get_block(0) {
        Ok(Some(_)) => return,
        Ok(None) => {}
        Err(e) => {
            eprintln!("[knox-node] genesis seed: get_block failed: {e}");
            return;
        }
    }
    let (block, _): (knox_types::Block, usize) = match bincode::decode_from_slice(
        GENESIS_BYTES,
        bincode::config::standard().with_limit::<{ 32 * 1024 * 1024 }>(),
    ) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("[knox-node] genesis seed: decode failed: {e}");
            return;
        }
    };
    ledger.set_validators(validators.to_vec());
    match ledger.append_block(&block) {
        Ok(()) => eprintln!("[knox-node] genesis seeded from bundle (h=0)"),
        Err(e) => eprintln!("[knox-node] genesis seed: append failed: {e}"),
    }
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

fn read_text_file(path: &str) -> Result<String, String> {
    let bytes = fs::read(path).map_err(|e| e.to_string())?;
    decode_text(&bytes).ok_or_else(|| "unsupported text encoding".to_string())
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

fn address_to_string(addr: &Address) -> String {
    let mut out = String::from("knox1");
    out.push_str(&hex_encode(&addr.view));
    out.push_str(&hex_encode(&addr.spend));
    out.push_str(&hex_encode(&addr.lattice_spend_pub));
    out
}

fn lattice_base_public_from_curve_spend_secret(
    spend_secret: &[u8; 32],
) -> knox_lattice::LatticePublicKey {
    let secret = knox_lattice::LatticeSecretKey {
        s: knox_lattice::Poly::sample_short(b"knox-wallet-lattice-base-v1", spend_secret),
    };
    knox_lattice::ring_sig::public_from_secret(&secret)
}
