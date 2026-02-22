use bincode::{Decode, Encode};
use blake3::Hasher;
use chacha20poly1305::{aead::Aead, KeyInit, XChaCha20Poly1305, XNonce};
use knox_crypto::{os_random_bytes, Prng};
use knox_types::{
    Block, SlashEvidence, TimeoutCertificate, TimeoutVote, Transaction, Vote,
    COVER_TRAFFIC_MIN_BYTES, P2P_RELAY_DELAY_MAX_MS, P2P_RELAY_DELAY_MIN_MS,
};
use std::collections::HashMap;
use std::net::IpAddr;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::{sleep, Duration};

const MAX_MESSAGE_BYTES: usize = 4 * 1024 * 1024;
const PEER_QUEUE_SIZE: usize = 1024;
const MAX_INBOUND_MSG_PER_SEC: u32 = 200;
const MAX_INBOUND_PER_IP: usize = 8;
const MAX_INBOUND_IP_STATE: usize = 8_192;
const INBOUND_STATE_TTL_MS: u64 = 5 * 60_000;
const HANDSHAKE_POW_BITS: u32 = 16;
const MAX_POW_STEPS: u64 = 5_000_000;
const FRAME_PLAINTEXT: u8 = 0;
const FRAME_ENCRYPTED: u8 = 1;
const MAX_REPLAY_SESSIONS: usize = 16_384;
const REPLAY_TTL_MS: u64 = 24 * 60 * 60 * 1000;

fn unsafe_overrides_enabled() -> bool {
    if std::env::var("KNOX_MAINNET_LOCK").ok().as_deref() == Some("1") {
        return false;
    }
    if !cfg!(debug_assertions) {
        return false;
    }
    std::env::var("KNOX_ALLOW_UNSAFE_OVERRIDES")
        .ok()
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

#[derive(Clone, Default)]
struct InboundLimiter {
    inner: Arc<Mutex<HashMap<IpAddr, RateState>>>,
}

#[derive(Clone, Copy)]
struct RateState {
    window_start_ms: u64,
    count: u32,
}

#[derive(Clone, Default)]
struct InboundCounts {
    inner: Arc<Mutex<HashMap<IpAddr, usize>>>,
}

#[derive(Clone, Default)]
struct ReplayProtector {
    inner: Arc<Mutex<HashMap<[u8; 16], ReplayState>>>,
}

#[derive(Clone, Copy)]
struct ReplayState {
    max_seq: u64,
    seen_ms: u64,
}

fn seed_prng() -> Result<[u8; 32], String> {
    let mut seed = [0u8; 32];
    os_random_bytes(&mut seed)?;
    Ok(seed)
}

fn random_session_id() -> Result<[u8; 16], String> {
    let mut id = [0u8; 16];
    os_random_bytes(&mut id)?;
    Ok(id)
}

#[derive(Clone, Debug)]
pub struct NetworkConfig {
    pub bind: String,
    pub peers: Vec<String>,
    pub max_peers: usize,
    pub pad_bytes: usize,
    pub cover_interval_ms: u64,
    pub lattice_public: Option<Vec<u8>>,
    pub lattice_secret: Option<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Encode, Decode)]
pub struct PeerId(pub [u8; 32]);

#[derive(Clone, Debug, Encode, Decode)]
pub enum Message {
    Ping(u64),
    Pong(u64),
    Handshake {
        peer_id: PeerId,
        tip: u64,
        pow_nonce: u64,
        lattice_ephemeral: Option<Vec<u8>>,
        lattice_public: Option<Vec<u8>>,
    },
    Tx(Transaction),
    Block(Block),
    Vote(Vote),
    TimeoutVote(TimeoutVote),
    TimeoutCertificate(TimeoutCertificate),
    Slash(SlashEvidence),
    Cover(Vec<u8>),
}

#[derive(Clone, Debug, Encode, Decode)]
pub struct Envelope {
    pub msg: Message,
    pub session_id: [u8; 16],
    pub sequence: u64,
    pub padding: Vec<u8>,
}

pub struct Network {
    _cfg: NetworkConfig,
    pub inbound: mpsc::Receiver<Envelope>,
    outbound: mpsc::Sender<Envelope>,
    _peers: Arc<Mutex<HashMap<String, mpsc::Sender<Envelope>>>>,
    _peer_id: PeerId,
    session_id: [u8; 16],
    next_sequence: Arc<AtomicU64>,
    active_peers: Arc<AtomicU64>,
}

#[derive(Clone)]
pub struct NetworkSender {
    outbound: mpsc::Sender<Envelope>,
    session_id: [u8; 16],
    next_sequence: Arc<AtomicU64>,
}

impl Network {
    pub async fn bind(cfg: NetworkConfig) -> std::io::Result<Self> {
        let session_id =
            random_session_id().map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        let next_sequence = Arc::new(AtomicU64::new(1));
        if cfg.bind == "-" {
            let (_tx_in, rx_in) = mpsc::channel(1024);
            let (tx_out, _rx_out) = mpsc::channel(1024);
            return Ok(Self {
                _cfg: cfg,
                inbound: rx_in,
                outbound: tx_out,
                _peers: Arc::new(Mutex::new(HashMap::new())),
                _peer_id: PeerId([0u8; 32]),
                session_id,
                next_sequence,
                active_peers: Arc::new(AtomicU64::new(0)),
            });
        }

        let listener = TcpListener::bind(&cfg.bind).await?;
        let (tx_in, rx_in) = mpsc::channel(1024);
        let (tx_out, mut rx_out) = mpsc::channel(1024);
        let peers: Arc<Mutex<HashMap<String, mpsc::Sender<Envelope>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let limiter = InboundLimiter::default();
        let counts = InboundCounts::default();
        let replay = ReplayProtector::default();
        let peer_id =
            PeerId(seed_prng().map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?);
        let active_peers = Arc::new(AtomicU64::new(0));
        let local_lattice_public = cfg.lattice_public.clone();
        let local_lattice_secret = cfg.lattice_secret.clone();
        
        // Remove PSK fallback, use lattice exclusively.
        let outbound_seed =
            seed_prng().map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        let cover_seed =
            seed_prng().map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        for peer in &cfg.peers {
            let seed =
                seed_prng().map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
            spawn_peer_writer(
                peer.clone(),
                peers.clone(),
                cfg.pad_bytes,
                peer_id,
                seed,
                local_lattice_public.clone(),
                local_lattice_secret.clone(),
                session_id,
                next_sequence.clone(),
                active_peers.clone(),
            )?;
        }

        tokio::spawn({
            let peers = peers.clone();
            let limiter = limiter.clone();
            let counts = counts.clone();
            let replay = replay.clone();
            async move {
                loop {
                    match listener.accept().await {
                        Ok((stream, addr)) => {
                            if !counts.try_add(addr.ip()) {
                                continue;
                            }
                            let tx = tx_in.clone();
                            let limiter = limiter.clone();
                            let counts = counts.clone();
                            let replay = replay.clone();
                            let pub_key = local_lattice_public.clone();
                            let sec_key = local_lattice_secret.clone();
                            let pad_bytes = cfg.pad_bytes;
                            tokio::spawn(async move {
                                let _ = handle_inbound(stream, addr.ip(), tx, limiter, replay, pub_key, sec_key, pad_bytes).await;
                                counts.remove(addr.ip());
                            });
                        }
                        Err(_) => break,
                    }
                    // keep peers warm
                    let _ = peers;
                }
            }
        });

        let peers_clone = peers.clone();
        tokio::spawn(async move {
            let mut prng = Prng::new(outbound_seed);
            while let Some(env) = rx_out.recv().await {
                let _ = send_to_peers(&peers_clone, &env, &mut prng).await;
            }
        });

        let cfg_cover = cfg.clone();
        let peers_cover = peers.clone();
        let cover_session_id = session_id;
        let cover_sequence = next_sequence.clone();
        tokio::spawn(async move {
            let mut prng = Prng::new(cover_seed);
            loop {
                sleep(Duration::from_millis(cfg_cover.cover_interval_ms)).await;
                let mut junk = vec![0u8; cfg_cover.pad_bytes.max(COVER_TRAFFIC_MIN_BYTES)];
                prng.fill_bytes(&mut junk);
                let env = Envelope {
                    msg: Message::Cover(junk.clone()),
                    session_id: cover_session_id,
                    sequence: cover_sequence.fetch_add(1, Ordering::Relaxed),
                    padding: Vec::new(),
                };
                let _ = send_to_peers(&peers_cover, &env, &mut prng).await;
            }
        });

        Ok(Self {
            _cfg: cfg,
            inbound: rx_in,
            outbound: tx_out,
            _peers: peers,
            _peer_id: peer_id,
            session_id,
            next_sequence,
            active_peers,
        })
    }

    pub async fn send(&self, msg: Message) {
        let env = Envelope {
            msg,
            session_id: self.session_id,
            sequence: self.next_sequence.fetch_add(1, Ordering::Relaxed),
            padding: Vec::new(),
        };
        let _ = self.outbound.send(env).await;
    }

    pub fn active_peer_count(&self) -> usize {
        self.active_peers.load(Ordering::Relaxed) as usize
    }

    pub fn sender(&self) -> NetworkSender {
        NetworkSender {
            outbound: self.outbound.clone(),
            session_id: self.session_id,
            next_sequence: self.next_sequence.clone(),
        }
    }
}

impl NetworkSender {
    pub async fn send(&self, msg: Message) {
        let env = Envelope {
            msg,
            session_id: self.session_id,
            sequence: self.next_sequence.fetch_add(1, Ordering::Relaxed),
            padding: Vec::new(),
        };
        let _ = self.outbound.send(env).await;
    }
}

async fn handle_inbound(
    mut stream: TcpStream,
    ip: IpAddr,
    tx: mpsc::Sender<Envelope>,
    limiter: InboundLimiter,
    replay: ReplayProtector,
    local_lattice_public: Option<Vec<u8>>,
    local_lattice_secret: Option<Vec<u8>>,
    pad_bytes: usize,
) -> std::io::Result<()> {
    let mut window_start = std::time::Instant::now();
    let mut count = 0u32;
    let mut session_key: Option<[u8; 32]> = None;
    let mut handshaked = false;
    let mut prng = Prng::new(seed_prng().unwrap_or([0u8; 32]));
    loop {
        if window_start.elapsed() >= Duration::from_secs(1) {
            window_start = std::time::Instant::now();
            count = 0;
        }
        if count >= MAX_INBOUND_MSG_PER_SEC {
            break;
        }
        if !limiter.allow(ip, MAX_INBOUND_MSG_PER_SEC, now_ms()) {
            break;
        }
        let mut len_buf = [0u8; 4];
        if stream.read_exact(&mut len_buf).await.is_err() {
            eprintln!("[p2p] read_exact len_buf failed from {}", ip);
            break;
        }
        let len = u32::from_le_bytes(len_buf) as usize;
        if len == 0 || len > MAX_MESSAGE_BYTES {
            eprintln!("[p2p] invalid message length {} from {}", len, ip);
            break;
        }
        let mut buf = vec![0u8; len];
        if stream.read_exact(&mut buf).await.is_err() {
            eprintln!("[p2p] read_exact message failed from {}", ip);
            break;
        }
        if let Some(env) = decode_envelope(&buf, session_key) {
            if !replay.allow(env.session_id, env.sequence, now_ms()) {
                break;
            }
            match &env.msg {
                Message::Handshake {
                    peer_id, pow_nonce, lattice_public, lattice_ephemeral, ..
                } => {
                    if !check_pow(*peer_id, *pow_nonce) {
                        break;
                    }
                    if lattice_ephemeral.is_none() {
                        let hello = Envelope {
                            msg: Message::Handshake {
                                peer_id: *peer_id,
                                tip: 0,
                                pow_nonce: *pow_nonce,
                                lattice_ephemeral: None,
                                lattice_public: local_lattice_public.clone(),
                            },
                            session_id: env.session_id,
                            sequence: 0,
                            padding: Vec::new(),
                        };
                        if let Some(payload) = encode_envelope(&hello, pad_bytes, &mut prng, None) {
                            if stream.write_all(&payload).await.is_err() {
                                break;
                            }
                        }
                    } else if !handshaked {
                        if let (Some(eph_bytes), Some(sec_bytes)) = (lattice_ephemeral, &local_lattice_secret) {
                            if let (Ok(peer_eph_poly), Ok(loc_sec_poly)) = (
                                knox_lattice::poly::Poly::from_bytes(eph_bytes),
                                knox_lattice::poly::Poly::from_bytes(sec_bytes)
                            ) {
                                let loc_sec = knox_lattice::ring_sig::LatticeSecretKey { s: loc_sec_poly };
                                let peer_eph = knox_lattice::ring_sig::LatticePublicKey { p: peer_eph_poly };
                                let one_time_sec = knox_lattice::stealth::recover_one_time_secret(&loc_sec, &loc_sec, &peer_eph);
                                let one_time_pub = knox_lattice::ring_sig::public_from_secret(&one_time_sec);
                                let tag = blake3::hash(&one_time_pub.p.to_bytes());
                                let mut sk = [0u8; 32];
                                sk.copy_from_slice(tag.as_bytes());
                                session_key = Some(sk);
                                handshaked = true;
                                eprintln!("[p2p] Accepted handshake from {}", ip);
                            } else {
                                break;
                            }
                        }
                    }
                }
                Message::Ping(_) | Message::Pong(_) => {}
                _ if !handshaked => {
                    eprintln!("[p2p] Message before handshake from {}", ip);
                    break;
                }
                _ => {}
            }
            let _ = tx.send(env).await;
        } else {
            eprintln!("[p2p] decode_envelope failed from {}", ip);
            break;
        }
        count = count.saturating_add(1);
    }
    Ok(())
}

async fn send_to_peers(
    peers: &Arc<Mutex<HashMap<String, mpsc::Sender<Envelope>>>>,
    env: &Envelope,
    prng: &mut Prng,
) -> std::io::Result<()> {
    let delay = relay_delay_ms(env.msg.clone(), prng);
    if delay > 0 {
        sleep(Duration::from_millis(delay)).await;
    }
    let senders = {
        if let Ok(map) = peers.lock() {
            map.values().cloned().collect::<Vec<_>>()
        } else {
            Vec::new()
        }
    };
    for tx in senders {
        let _ = tx.send(env.clone()).await;
    }
    Ok(())
}

fn relay_delay_ms(msg: Message, prng: &mut Prng) -> u64 {
    match msg {
        Message::Ping(_) | Message::Pong(_) | Message::Handshake { .. } => 0,
        _ => {
            if P2P_RELAY_DELAY_MAX_MS <= P2P_RELAY_DELAY_MIN_MS {
                return P2P_RELAY_DELAY_MIN_MS;
            }
            let mut bytes = [0u8; 8];
            prng.fill_bytes(&mut bytes);
            let span = P2P_RELAY_DELAY_MAX_MS - P2P_RELAY_DELAY_MIN_MS;
            P2P_RELAY_DELAY_MIN_MS + (u64::from_le_bytes(bytes) % (span + 1))
        }
    }
}

fn spawn_peer_writer(
    peer: String,
    peers: Arc<Mutex<HashMap<String, mpsc::Sender<Envelope>>>>,
    pad_bytes: usize,
    peer_id: PeerId,
    seed: [u8; 32],
    local_lattice_public: Option<Vec<u8>>,
    local_lattice_secret: Option<Vec<u8>>,
    session_id: [u8; 16],
    next_sequence: Arc<AtomicU64>,
    active_peers: Arc<AtomicU64>,
) -> std::io::Result<()> {
    let (tx, mut rx) = mpsc::channel::<Envelope>(PEER_QUEUE_SIZE);
    if let Ok(mut map) = peers.lock() {
        map.insert(peer.clone(), tx);
    }

    tokio::spawn(async move {
        let mut backoff = Duration::from_millis(500);
        let mut prng = Prng::new(seed);
        loop {
            match TcpStream::connect(&peer).await {
                Ok(mut stream) => {
                    backoff = Duration::from_millis(500);
                    let mut nonce_seed = [0u8; 8];
                    prng.fill_bytes(&mut nonce_seed);
                    let Some(pow_nonce) = tokio::task::spawn_blocking(move || {
                        solve_pow(peer_id, u64::from_le_bytes(nonce_seed))
                    })
                    .await
                    .unwrap_or(None) else {
                        eprintln!("[p2p] Failed to solve PoW for target peer {}", peer);
                        sleep(backoff).await;
                        backoff = (backoff * 2).min(Duration::from_secs(10));
                        continue;
                    };
                    
                    let hello = Envelope {
                        msg: Message::Handshake {
                            peer_id,
                            tip: 0,
                            pow_nonce,
                            lattice_ephemeral: None,
                            lattice_public: local_lattice_public.clone(),
                        },
                        session_id,
                        sequence: next_sequence.fetch_add(1, Ordering::Relaxed),
                        padding: Vec::new(),
                    };
                    let Some(payload1) = encode_envelope(&hello, pad_bytes, &mut prng, None) else { continue; };
                    if stream.write_all(&payload1).await.is_err() { continue; }

                    let mut len_buf = [0u8; 4];
                    let read_len = tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut len_buf)).await;
                    if read_len.is_err() || read_len.unwrap().is_err() { continue; }
                    let len = u32::from_le_bytes(len_buf) as usize;
                    if len == 0 || len > MAX_MESSAGE_BYTES { continue; }
                    let mut buf = vec![0u8; len];
                    let read_buf = tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut buf)).await;
                    if read_buf.is_err() || read_buf.unwrap().is_err() { continue; }
                    
                    let mut peer_pub_bytes = None;
                    if let Some(env2) = decode_envelope(&buf, None) {
                        if let Message::Handshake { lattice_public: Some(p), .. } = env2.msg {
                            peer_pub_bytes = Some(p);
                        }
                    }
                    let Some(peer_pub_bytes) = peer_pub_bytes else { continue; };

                    let mut session_key = None;
                    let mut eph_pub_bytes = None;
                    if let Ok(peer_pub_poly) = knox_lattice::poly::Poly::from_bytes(&peer_pub_bytes) {
                        let peer_pub = knox_lattice::ring_sig::LatticePublicKey { p: peer_pub_poly };
                        let ephemeral_secret = knox_lattice::poly::Poly::random_short();
                        let stealth_out = knox_lattice::stealth::send_to_stealth_with_ephemeral(&peer_pub, &peer_pub, &ephemeral_secret);
                        eph_pub_bytes = Some(stealth_out.ephemeral_public.p.to_bytes());
                        let tag = blake3::hash(&stealth_out.one_time_public.p.to_bytes());
                        let mut sk = [0u8; 32];
                        sk.copy_from_slice(tag.as_bytes());
                        session_key = Some(sk);
                    } else {
                        continue;
                    }

                    let kex = Envelope {
                        msg: Message::Handshake {
                            peer_id,
                            tip: 0,
                            pow_nonce,
                            lattice_ephemeral: eph_pub_bytes,
                            lattice_public: local_lattice_public.clone(),
                        },
                        session_id,
                        sequence: next_sequence.fetch_add(1, Ordering::Relaxed),
                        padding: Vec::new(),
                    };
                    let Some(payload2) = encode_envelope(&kex, pad_bytes, &mut prng, None) else { continue; };
                    if stream.write_all(&payload2).await.is_err() { continue; }
                    eprintln!("[p2p] Connected to {}", peer);
                    active_peers.fetch_add(1, Ordering::Relaxed);
                    while let Some(env_to_send) = rx.recv().await {
                        if let Some(payload) = encode_envelope(&env_to_send, pad_bytes, &mut prng, session_key) {
                            if stream.write_all(&payload).await.is_err() {
                                break;
                            }
                        }
                    }
                    eprintln!("[p2p] Reconnecting to {}", peer);
                    active_peers.fetch_sub(1, Ordering::Relaxed);
                }
                Err(_) => {
                    sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_secs(10));
                }
            }
        }
    });
    Ok(())
}

fn encode_envelope(
    env: &Envelope,
    pad_to: usize,
    prng: &mut Prng,
    psk: Option<[u8; 32]>,
) -> Option<Vec<u8>> {
    let mut bytes = bincode::encode_to_vec(env, bincode::config::standard()).ok()?;
    if bytes.len() < pad_to {
        let pad_len = pad_to - bytes.len();
        let mut pad = vec![0u8; pad_len];
        prng.fill_bytes(&mut pad);
        bytes.extend_from_slice(&pad);
    }
    let framed = if let Some(psk_key) = psk {
        let cipher = XChaCha20Poly1305::new_from_slice(&psk_key).ok()?;
        let mut nonce = [0u8; 24];
        os_random_bytes(&mut nonce).ok()?;
        let ciphertext = cipher
            .encrypt(XNonce::from_slice(&nonce), bytes.as_ref())
            .ok()?;
        let mut f = Vec::with_capacity(1 + nonce.len() + ciphertext.len());
        f.push(FRAME_ENCRYPTED);
        f.extend_from_slice(&nonce);
        f.extend_from_slice(&ciphertext);
        f
    } else {
        let mut f = Vec::with_capacity(1 + bytes.len());
        f.push(FRAME_PLAINTEXT);
        f.extend_from_slice(&bytes);
        f
    };
    let mut out = Vec::with_capacity(4 + framed.len());
    out.extend_from_slice(&(framed.len() as u32).to_le_bytes());
    out.extend_from_slice(&framed);
    Some(out)
}

fn decode_envelope(frame: &[u8], psk: Option<[u8; 32]>) -> Option<Envelope> {
    if frame.is_empty() {
        return None;
    }
    let mode = frame[0];
    let payload = match (mode, psk) {
        (FRAME_PLAINTEXT, None) => frame[1..].to_vec(),
        (FRAME_PLAINTEXT, Some(_)) => return None,
        (FRAME_ENCRYPTED, Some(psk_key)) => {
            if frame.len() < 1 + 24 {
                return None;
            }
            let nonce = &frame[1..25];
            let ciphertext = &frame[25..];
            let cipher = XChaCha20Poly1305::new_from_slice(&psk_key).ok()?;
            cipher.decrypt(XNonce::from_slice(nonce), ciphertext).ok()?
        }
        (FRAME_ENCRYPTED, None) => return None,
        _ => return None,
    };
    bincode::decode_from_slice::<Envelope, _>(&payload, bincode::config::standard())
        .ok()
        .map(|(env, _)| env)
}

fn load_psk_from_keyring() -> Result<Option<[u8; 32]>, String> {
    let is_mainnet_locked =
        std::env::var("KNOX_MAINNET_LOCK").ok().as_deref() == Some("1");

    // Direct PSK via env var: KNOX_P2P_PSK=<64-hex-chars>
    // Forbidden in mainnet-lock mode (use OS keyring or file for validators).
    if !is_mainnet_locked {
        if let Ok(hex) = std::env::var("KNOX_P2P_PSK") {
            let hex = hex.trim();
            if !hex.is_empty() {
                return Ok(Some(parse_hex_32(hex).map_err(|e| {
                    format!("KNOX_P2P_PSK contains invalid content: {e}")
                })?));
            }
        }
    }

    // KNOX_P2P_ALLOW_PLAINTEXT is honoured in all build modes (including
    // release) as long as mainnet lock is not active.  This is required for
    // desktop wallet nodes that cannot store a PSK in the OS keyring yet.
    let allow_plain = !is_mainnet_locked
        && std::env::var("KNOX_P2P_ALLOW_PLAINTEXT")
            .ok()
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

    let service = std::env::var("KNOX_P2P_PSK_SERVICE").unwrap_or_else(|_| "knox-p2p".to_string());
    let account = std::env::var("KNOX_P2P_PSK_ACCOUNT").unwrap_or_else(|_| "mainnet".to_string());
    let secret = match read_keyring_secret(&service, &account) {
        Ok(v) => v,
        Err(keyring_err) => {
            // On headless Linux servers the GUI keyring daemon is unavailable.
            // Before giving up, check for a hardcoded file-based PSK at the
            // well-known path /etc/knox/p2p-psk.  The file fallback is
            // intentionally Linux-only — macOS and Windows keyring works fine
            // in server contexts and does not need this path.
            #[cfg(target_os = "linux")]
            {
                use std::os::unix::fs::PermissionsExt;

                const PSK_FILE: &str = "/etc/knox/p2p-psk";

                // Use symlink_metadata so we inspect the path itself, not a
                // target — a symlink must never be accepted.
                match std::fs::symlink_metadata(PSK_FILE) {
                    Err(io_err) if io_err.kind() == std::io::ErrorKind::NotFound => {
                        // File absent — fall through to the keyring error below.
                    }
                    Err(io_err) => {
                        return Err(format!(
                            "PSK file {PSK_FILE} could not be accessed: {io_err}"
                        ));
                    }
                    Ok(meta) => {
                        // Reject symlinks outright.
                        if meta.file_type().is_symlink() {
                            return Err(format!(
                                "PSK file {PSK_FILE} must be a regular file, not a symlink"
                            ));
                        }
                        if !meta.file_type().is_file() {
                            return Err(format!(
                                "PSK file {PSK_FILE} must be a regular file"
                            ));
                        }
                        // Enforce strict 0400 permissions so the key is never
                        // world- or group-readable.
                        let mode = meta.permissions().mode() & 0o777;
                        if mode != 0o400 {
                            return Err(format!(
                                "PSK file {PSK_FILE} has permissions {mode:04o}; \
                                 it must be mode 0400 (chmod 0400 {PSK_FILE})"
                            ));
                        }
                        // Read, trim, and parse the 64-character hex PSK.
                        let raw = std::fs::read_to_string(PSK_FILE).map_err(|io_err| {
                            format!("failed to read PSK file {PSK_FILE}: {io_err}")
                        })?;
                        let trimmed = raw.trim();
                        return Ok(Some(parse_hex_32(trimmed).map_err(|hex_err| {
                            format!("PSK file {PSK_FILE} contains invalid content: {hex_err}")
                        })?));
                    }
                }
            }

            if allow_plain {
                return Ok(None);
            }
            return Err(format!(
                "unable to read KNOX P2P PSK from OS keyring ({keyring_err}); \
                 install secret-tool and store PSK, or place 64-hex PSK in \
                 /etc/knox/p2p-psk with mode 0400"
            ));
        }
    };
    let trimmed = secret.trim();
    if trimmed.is_empty() {
        if allow_plain {
            return Ok(None);
        }
        return Err("empty keyring secret for KNOX P2P PSK".to_string());
    }
    Ok(Some(parse_hex_32(trimmed)?))
}

fn read_keyring_secret(service: &str, account: &str) -> Result<String, String> {
    #[cfg(target_os = "linux")]
    {
        let out = Command::new("secret-tool")
            .arg("lookup")
            .arg("service")
            .arg(service)
            .arg("account")
            .arg(account)
            .output()
            .map_err(|e| format!("secret-tool execution failed: {e}"))?;
        if !out.status.success() {
            return Err("secret-tool lookup returned non-zero status".to_string());
        }
        return Ok(String::from_utf8_lossy(&out.stdout).to_string());
    }
    #[cfg(target_os = "macos")]
    {
        let out = Command::new("security")
            .arg("find-generic-password")
            .arg("-s")
            .arg(service)
            .arg("-a")
            .arg(account)
            .arg("-w")
            .output()
            .map_err(|e| format!("security command failed: {e}"))?;
        if !out.status.success() {
            return Err("security keychain lookup returned non-zero status".to_string());
        }
        return Ok(String::from_utf8_lossy(&out.stdout).to_string());
    }
    #[cfg(target_os = "windows")]
    {
        let script = format!(
            "$pw=(Get-StoredCredential -Target '{service}:{account}').Password; if($pw){{Write-Output $pw}}"
        );
        let out = Command::new("powershell")
            .arg("-NoProfile")
            .arg("-Command")
            .arg(script)
            .output()
            .map_err(|e| format!("powershell execution failed: {e}"))?;
        if !out.status.success() {
            return Err("powershell keyring lookup returned non-zero status".to_string());
        }
        return Ok(String::from_utf8_lossy(&out.stdout).to_string());
    }
    #[allow(unreachable_code)]
    Err("OS keyring integration is not supported on this platform".to_string())
}

fn parse_hex_32(raw: &str) -> Result<[u8; 32], String> {
    if raw.len() != 64 {
        return Err("PSK must be exactly 64 hex characters".to_string());
    }
    let mut out = [0u8; 32];
    let bytes = raw.as_bytes();
    for i in 0..32 {
        let hi = from_hex(bytes[i * 2])?;
        let lo = from_hex(bytes[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn from_hex(c: u8) -> Result<u8, String> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err("PSK contains invalid hex character".to_string()),
    }
}

fn check_pow(peer_id: PeerId, nonce: u64) -> bool {
    leading_zero_bits(&ult7rock_pow_hash(peer_id, nonce)) >= HANDSHAKE_POW_BITS
}

fn solve_pow(peer_id: PeerId, start: u64) -> Option<u64> {
    let mut nonce = start;
    for _ in 0..MAX_POW_STEPS {
        if check_pow(peer_id, nonce) {
            return Some(nonce);
        }
        nonce = nonce.wrapping_add(1);
    }
    None
}

/// ULT7Rock lattice-based PoW hash for the P2P handshake.
///
/// Construction:
///   challenge = peer_id.0 (32 bytes) || nonce.to_le_bytes() (8 bytes)
///   a = hash_to_poly(challenge)                  -- public ring element
///   s = sample_cbd(b"ult7rock-p2p-s\0\0" || challenge) -- small ring element
///   b = a * s  (NTT-accelerated negacyclic mul in Z_q[x]/(x^N+1))
///   hash = BLAKE3(b"ult7rock-p2p-pow-v1" || b.coeffs as LE64 bytes)
///
/// Difficulty check: leading zero bits of hash >= HANDSHAKE_POW_BITS.
fn ult7rock_pow_hash(peer_id: PeerId, nonce: u64) -> [u8; 32] {
    use knox_lattice::{hash_to_poly, sample_cbd};

    // Build the 40-byte challenge seed.
    let mut challenge = [0u8; 40];
    challenge[..32].copy_from_slice(&peer_id.0);
    challenge[32..].copy_from_slice(&nonce.to_le_bytes());

    // a is a uniformly random ring element derived from the challenge.
    let a = hash_to_poly(&challenge);

    // s is a small-norm ring element.  Its seed is domain-separated from a's
    // seed by prepending a 16-byte tag so that the two samples are independent.
    let mut s_seed = [0u8; 56]; // 16-byte domain tag + 40-byte challenge
    s_seed[..16].copy_from_slice(b"ult7rock-p2p-s\0\0");
    s_seed[16..].copy_from_slice(&challenge);
    let s = sample_cbd(&s_seed);

    // b = a * s: NTT-accelerated negacyclic polynomial multiplication.
    let b = a.mul(&s);

    // Commit: BLAKE3 over the domain tag followed by each coefficient
    // serialised as a little-endian 64-bit value.
    let mut hasher = Hasher::new();
    hasher.update(b"ult7rock-p2p-pow-v1");
    for &coeff in b.coeffs() {
        hasher.update(&coeff.to_le_bytes());
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_bytes());
    out
}

fn leading_zero_bits(bytes: &[u8; 32]) -> u32 {
    let mut count = 0u32;
    for b in bytes {
        let z = b.leading_zeros();
        count += z;
        if z < 8 {
            break;
        }
    }
    count
}

fn now_ms() -> u64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    now.as_millis() as u64
}

impl InboundLimiter {
    fn allow(&self, ip: IpAddr, limit_per_sec: u32, now_ms: u64) -> bool {
        let Ok(mut map) = self.inner.lock() else {
            return false;
        };
        if map.len() > MAX_INBOUND_IP_STATE {
            map.retain(|_, state| {
                now_ms.saturating_sub(state.window_start_ms) <= INBOUND_STATE_TTL_MS
            });
            if map.len() > MAX_INBOUND_IP_STATE {
                let oldest_ip = map
                    .iter()
                    .min_by_key(|(_, state)| state.window_start_ms)
                    .map(|(ip, _)| *ip);
                if let Some(oldest_ip) = oldest_ip {
                    map.remove(&oldest_ip);
                }
            }
        }
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

impl ReplayProtector {
    fn allow(&self, session_id: [u8; 16], sequence: u64, now_ms: u64) -> bool {
        let Ok(mut map) = self.inner.lock() else {
            return false;
        };
        if map.len() > MAX_REPLAY_SESSIONS {
            map.retain(|_, state| now_ms.saturating_sub(state.seen_ms) <= REPLAY_TTL_MS);
            if map.len() > MAX_REPLAY_SESSIONS {
                let oldest = map
                    .iter()
                    .min_by_key(|(_, state)| state.seen_ms)
                    .map(|(session, _)| *session);
                if let Some(oldest) = oldest {
                    map.remove(&oldest);
                }
            }
        }
        if let Some(state) = map.get_mut(&session_id) {
            if sequence <= state.max_seq {
                return false;
            }
            state.max_seq = sequence;
            state.seen_ms = now_ms;
            return true;
        }
        map.insert(
            session_id,
            ReplayState {
                max_seq: sequence,
                seen_ms: now_ms,
            },
        );
        true
    }
}

impl InboundCounts {
    fn try_add(&self, ip: IpAddr) -> bool {
        let Ok(mut map) = self.inner.lock() else {
            return false;
        };
        let entry = map.entry(ip).or_insert(0);
        if *entry >= MAX_INBOUND_PER_IP {
            return false;
        }
        *entry += 1;
        true
    }

    fn remove(&self, ip: IpAddr) {
        let Ok(mut map) = self.inner.lock() else {
            return;
        };
        if let Some(count) = map.get_mut(&ip) {
            if *count > 1 {
                *count -= 1;
            } else {
                map.remove(&ip);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_delay_within_bounds_for_payload_messages() {
        let mut seed = [0u8; 32];
        seed[0] = 7;
        let mut prng = Prng::new(seed);
        for _ in 0..512 {
            let d = relay_delay_ms(&Message::Cover(vec![1, 2, 3]), &mut prng);
            assert!(d >= P2P_RELAY_DELAY_MIN_MS);
            assert!(d <= P2P_RELAY_DELAY_MAX_MS);
        }
    }

    #[test]
    fn relay_delay_zero_for_handshake_class() {
        let mut prng = Prng::new([9u8; 32]);
        assert_eq!(relay_delay_ms(&Message::Ping(1), &mut prng), 0);
        assert_eq!(relay_delay_ms(&Message::Pong(1), &mut prng), 0);
        assert_eq!(
            relay_delay_ms(
                &Message::Handshake {
                    peer_id: PeerId([0u8; 32]),
                    tip: 0,
                    pow_nonce: 0,
                },
                &mut prng
            ),
            0
        );
    }

    #[test]
    fn replay_protector_rejects_reuse_and_out_of_order() {
        let rp = ReplayProtector::default();
        let sid = [7u8; 16];
        assert!(rp.allow(sid, 1, 100));
        assert!(rp.allow(sid, 2, 101));
        assert!(!rp.allow(sid, 2, 102));
        assert!(!rp.allow(sid, 1, 103));
        assert!(rp.allow(sid, 3, 104));
    }
}
