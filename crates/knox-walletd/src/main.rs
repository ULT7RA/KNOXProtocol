use knox_types::DEFAULT_DECOY_COUNT;
use knox_wallet::{
    address_from_string, address_to_string, build_transaction, create_subaddress, create_wallet,
    create_wallet_from_node_key, create_wallet_from_node_key_bytes, fibonacci_wall,
    list_wallet_addresses, load_wallet, mark_submitted_transaction, network_telemetry,
    recent_blocks, save_wallet, submit_transaction, sync_wallet, wallet_balance, WalletState,
    upstream_tip,
};
use rustls_pemfile::{certs, private_key};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use std::sync::Mutex;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex as AsyncMutex;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;

const MAX_HTTP_BYTES: usize = 2 * 1024 * 1024;
const MAX_HTTP_REQ_PER_SEC: u32 = 20;
const MAX_HTTP_BODY_BYTES: usize = 512 * 1024;

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

#[derive(Clone)]
struct WalletdState {
    wallet_path: String,
    rpc_addr: String,
    wallet: WalletState,
}

#[derive(Clone, Default)]
struct RateLimiter {
    inner: Arc<Mutex<HashMap<IpAddr, RateState>>>,
}

#[derive(Clone, Copy)]
struct RateState {
    window_start_ms: u64,
    count: u32,
}

#[derive(Serialize)]
struct ApiResponse<T: Serialize> {
    ok: bool,
    result: Option<T>,
    error: Option<String>,
}

#[derive(Serialize)]
struct HealthResponse {
    status: String,
}

#[derive(Serialize)]
struct InfoResponse {
    address: String,
    balance: u64,
    last_height: u64,
    addresses: Vec<String>,
}

#[derive(Serialize)]
struct SendResponse {
    submitted: bool,
    txid: String,
}

#[derive(Deserialize)]
struct SendRequest {
    to: String,
    amount: Option<u64>,
    fee: Option<u64>,
    amount_coins: Option<String>,
    fee_coins: Option<String>,
    ring: Option<usize>,
}

#[derive(Deserialize)]
struct ImportRequest {
    node_key_path: String,
}

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let wallet_path = args.next().unwrap_or_else(|| "wallet.bin".to_string());
    let rpc_addr = args.next().unwrap_or_else(|| "127.0.0.1:9736".to_string());
    let bind_addr = args.next().unwrap_or_else(|| "127.0.0.1:9980".to_string());
    let mut import_node_key: Option<String> = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--import-node-key" => {
                import_node_key = args.next();
            }
            _ => {
                eprintln!("unknown arg: {arg}");
            }
        }
    }

    let wallet = if let Some(node_key) = import_node_key {
        match create_wallet_from_node_key(&node_key, &wallet_path) {
            Ok(w) => w,
            Err(e) => {
                eprintln!("wallet import error: {e}");
                std::process::exit(1);
            }
        }
    } else if Path::new(&wallet_path).exists() {
        match load_wallet(&wallet_path) {
            Ok(w) => w,
            Err(e) => {
                eprintln!("wallet load error: {e}");
                std::process::exit(1);
            }
        }
    } else {
        match create_wallet(&wallet_path) {
            Ok(w) => w,
            Err(e) => {
                eprintln!("wallet create error: {e}");
                std::process::exit(1);
            }
        }
    };

    let state = Arc::new(AsyncMutex::new(WalletdState {
        wallet_path,
        rpc_addr,
        wallet,
    }));

    let tls_config = match load_tls_config() {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("tls config error: {e}");
            std::process::exit(1);
        }
    };
    let allow_insecure = unsafe_overrides_enabled()
        && std::env::var("KNOX_WALLETD_ALLOW_INSECURE").ok().as_deref() == Some("1");
    let require_tls = !allow_insecure;
    if require_tls && tls_config.is_none() {
        eprintln!("TLS required (set KNOX_WALLETD_TLS_CERT/KNOX_WALLETD_TLS_KEY)");
        std::process::exit(1);
    }
    let token = match load_auth_token() {
        Some(t) if t.len() >= 24 => t,
        _ => {
            eprintln!("KNOX_WALLETD_TOKEN (or KNOX_WALLETD_TOKEN_FILE) is required (min 24 chars)");
            std::process::exit(1);
        }
    };
    let token = Arc::new(token);

    let listener = TcpListener::bind(&bind_addr).await.unwrap_or_else(|e| {
        eprintln!("bind error: {e}");
        std::process::exit(1);
    });
    let limiter = RateLimiter::default();

    eprintln!(
        "[StarForge-wallet] listening on {bind_addr}{}",
        if tls_config.is_some() {
            " (tls)"
        } else {
            " (plain, insecure)"
        }
    );
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let state = state.clone();
                let tls = tls_config.clone();
                let limiter = limiter.clone();
                let token = token.clone();
                tokio::spawn(async move {
                    if !limiter.allow(peer.ip(), MAX_HTTP_REQ_PER_SEC, now_ms()) {
                        return;
                    }
                    if let Some(cfg) = tls {
                        let acceptor = TlsAcceptor::from(cfg);
                        match acceptor.accept(stream).await {
                            Ok(tls_stream) => handle_client(tls_stream, state, token).await,
                            Err(_) => {}
                        }
                    } else {
                        handle_client(stream, state, token).await;
                    }
                });
            }
            Err(e) => {
                eprintln!("accept error: {e}");
            }
        }
    }
}

async fn handle_client<S>(mut stream: S, state: Arc<AsyncMutex<WalletdState>>, token: Arc<String>)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let req = match read_request(&mut stream).await {
        Ok(req) => req,
        Err(err) => {
            respond_error(&mut stream, 400, &err).await;
            return;
        }
    };

    if req.method == "OPTIONS" {
        respond_empty(&mut stream, 204).await;
        return;
    }

    if !is_authorized(&req, token.as_str()) {
        respond_error(&mut stream, 401, "unauthorized").await;
        return;
    }

    let (path_only, query) = split_path_query(&req.path);

    match (req.method.as_str(), path_only) {
        ("GET", "/health") => {
            respond_ok(
                &mut stream,
                HealthResponse {
                    status: "ok".to_string(),
                },
            )
            .await;
        }
        ("GET", "/info") | ("GET", "/address") | ("GET", "/balance") => {
            let state = state.lock().await;
            let addrs = list_wallet_addresses(&state.wallet)
                .into_iter()
                .map(|(_, a)| address_to_string(&a))
                .collect();
            let resp = InfoResponse {
                address: address_to_string(&state.wallet.address()),
                balance: wallet_balance(&state.wallet),
                last_height: state.wallet.last_height,
                addresses: addrs,
            };
            respond_ok(&mut stream, resp).await;
        }
        ("GET", "/addresses") => {
            let state = state.lock().await;
            let list: Vec<serde_json::Value> = list_wallet_addresses(&state.wallet)
                .into_iter()
                .map(|(index, addr)| {
                    serde_json::json!({
                        "index": index,
                        "address": address_to_string(&addr)
                    })
                })
                .collect();
            respond_ok(&mut stream, list).await;
        }
        ("POST", "/sync") => {
            let (wallet_path, rpc_addr, mut wallet) = {
                let state = state.lock().await;
                (
                    state.wallet_path.clone(),
                    state.rpc_addr.clone(),
                    state.wallet.clone(),
                )
            };
            let sync_result = tokio::task::spawn_blocking(
                move || -> Result<(WalletState, InfoResponse), String> {
                    sync_wallet(&mut wallet, &rpc_addr)?;
                    save_wallet(&wallet_path, &wallet)?;
                    let resp = InfoResponse {
                        address: address_to_string(&wallet.address()),
                        balance: wallet_balance(&wallet),
                        last_height: wallet.last_height,
                        addresses: list_wallet_addresses(&wallet)
                            .into_iter()
                            .map(|(_, a)| address_to_string(&a))
                            .collect(),
                    };
                    Ok((wallet, resp))
                },
            )
            .await;
            match sync_result {
                Ok(Ok((wallet, resp))) => {
                    let mut state = state.lock().await;
                    state.wallet = wallet;
                    respond_ok(&mut stream, resp).await;
                }
                Ok(Err(e)) => {
                    respond_error(&mut stream, 500, &e).await;
                }
                Err(e) => {
                    respond_error(&mut stream, 500, &format!("sync task failed: {e}")).await;
                }
            }
        }
        ("POST", "/new-address") => {
            let mut state = state.lock().await;
            let addr = match create_subaddress(&mut state.wallet) {
                Ok(v) => v,
                Err(e) => {
                    respond_error(&mut stream, 500, &e).await;
                    return;
                }
            };
            if let Err(e) = save_wallet(&state.wallet_path, &state.wallet) {
                respond_error(&mut stream, 500, &format!("save failed: {e}")).await;
                return;
            }
            respond_ok(
                &mut stream,
                serde_json::json!({
                    "address": address_to_string(&addr)
                }),
            )
            .await;
        }
        ("POST", "/send") => {
            let send_req: SendRequest = match serde_json::from_slice(&req.body) {
                Ok(v) => v,
                Err(e) => {
                    respond_error(&mut stream, 400, &format!("invalid json: {e}")).await;
                    return;
                }
            };
            let to = match address_from_string(&send_req.to) {
                Ok(v) => v,
                Err(e) => {
                    respond_error(&mut stream, 400, &format!("invalid address: {e}")).await;
                    return;
                }
            };
            let ring = send_req.ring.unwrap_or(DEFAULT_DECOY_COUNT);
            let amount = match parse_send_amount(send_req.amount, send_req.amount_coins.as_deref())
            {
                Ok(v) => v,
                Err(e) => {
                    respond_error(&mut stream, 400, &format!("invalid amount: {e}")).await;
                    return;
                }
            };
            let fee = match parse_send_amount(send_req.fee, send_req.fee_coins.as_deref()) {
                Ok(v) => v,
                Err(e) => {
                    respond_error(&mut stream, 400, &format!("invalid fee: {e}")).await;
                    return;
                }
            };
            let (wallet_path, rpc_addr, mut wallet) = {
                let state = state.lock().await;
                (
                    state.wallet_path.clone(),
                    state.rpc_addr.clone(),
                    state.wallet.clone(),
                )
            };
            let send_result =
                tokio::task::spawn_blocking(move || -> Result<(WalletState, String), String> {
                    let tx = build_transaction(&mut wallet, &rpc_addr, &to, amount, fee, ring)?;
                    match submit_transaction(&rpc_addr, &tx) {
                        Ok(true) => {
                            mark_submitted_transaction(&mut wallet, &tx);
                            save_wallet(&wallet_path, &wallet)?;
                            let tx_bytes = bincode::encode_to_vec(&tx, bincode::config::standard())
                                .map_err(|e| format!("tx encode error: {e}"))?;
                            Ok((wallet, hex(&knox_types::hash_bytes(&tx_bytes).0)))
                        }
                        Ok(false) => Err("transaction rejected".to_string()),
                        Err(e) => Err(e),
                    }
                })
                .await;
            match send_result {
                Ok(Ok((wallet, txid))) => {
                    let mut state = state.lock().await;
                    state.wallet = wallet;
                    let resp = SendResponse {
                        submitted: true,
                        txid,
                    };
                    respond_ok(&mut stream, resp).await;
                }
                Ok(Err(e)) => {
                    respond_error(&mut stream, 500, &e).await;
                }
                Err(e) => {
                    respond_error(&mut stream, 500, &format!("send task failed: {e}")).await;
                }
            }
        }
        ("POST", "/import-node-key") => {
            let import_req: ImportRequest = match serde_json::from_slice(&req.body) {
                Ok(v) => v,
                Err(e) => {
                    respond_error(&mut stream, 400, &format!("invalid json: {e}")).await;
                    return;
                }
            };
            let mut state = state.lock().await;
            if !import_path_allowed(&import_req.node_key_path, &state.wallet_path) {
                respond_error(&mut stream, 400, "node key path not allowed").await;
                return;
            }
            let key_bytes = match std::fs::read(&import_req.node_key_path) {
                Ok(v) => v,
                Err(e) => {
                    respond_error(&mut stream, 400, &format!("node key read failed: {e}")).await;
                    return;
                }
            };
            match create_wallet_from_node_key_bytes(&key_bytes, &state.wallet_path) {
                Ok(w) => state.wallet = w,
                Err(e) => {
                    respond_error(&mut stream, 500, &e).await;
                    return;
                }
            }
            let resp = InfoResponse {
                address: address_to_string(&state.wallet.address()),
                balance: wallet_balance(&state.wallet),
                last_height: state.wallet.last_height,
                addresses: list_wallet_addresses(&state.wallet)
                    .into_iter()
                    .map(|(_, a)| address_to_string(&a))
                    .collect(),
            };
            respond_ok(&mut stream, resp).await;
        }
        ("GET", "/network") => {
            let rpc_addr = {
                let state = state.lock().await;
                state.rpc_addr.clone()
            };
            match tokio::task::spawn_blocking(move || -> Result<serde_json::Value, String> {
                let t = network_telemetry(&rpc_addr)?;
                let recent = recent_blocks(&rpc_addr, 24).unwrap_or_default();
                let recent_json: Vec<serde_json::Value> = recent
                    .into_iter()
                    .map(|b| {
                        serde_json::json!({
                            "height": b.header.height,
                            "time": b.header.timestamp_ms,
                            "txs": b.txs.len(),
                            "status": "SEALED",
                            "meta": format!("{} tx", b.txs.len()),
                        })
                    })
                    .collect();
                Ok(serde_json::json!({
                    "tip_height": t.tip_height,
                    "tip_hash": hex(&t.tip_hash.0),
                    "total_hardening": t.total_hardening,
                    "active_miners_recent": t.active_miners_recent,
                    "current_difficulty_bits": t.current_difficulty_bits,
                    "tip_proposer_streak": t.tip_proposer_streak,
                    "next_streak_if_same_proposer": t.next_streak_if_same_proposer,
                    "streak_bonus_ppm": t.streak_bonus_ppm,
                    "surge_phase": t.surge_phase,
                    "surge_countdown_ms": t.surge_countdown_ms,
                    "surge_block_index": t.surge_block_index,
                    "surge_blocks_remaining": t.surge_blocks_remaining,
                    "recent_blocks": recent_json
                }))
            })
            .await
            {
                Ok(Ok(body)) => respond_ok(&mut stream, body).await,
                Ok(Err(e)) => respond_error(&mut stream, 500, &e).await,
                Err(e) => {
                    respond_error(&mut stream, 500, &format!("network task failed: {e}")).await
                }
            }
        }
        ("GET", "/upstream-tip") => {
            let rpc_addr = {
                let state = state.lock().await;
                state.rpc_addr.clone()
            };
            match tokio::task::spawn_blocking(move || upstream_tip(&rpc_addr)).await {
                Ok(Ok(tip_height)) => {
                    respond_ok(
                        &mut stream,
                        serde_json::json!({
                            "tip_height": tip_height
                        }),
                    )
                    .await;
                }
                Ok(Err(e)) => respond_error(&mut stream, 500, &e).await,
                Err(e) => {
                    respond_error(&mut stream, 500, &format!("upstream-tip task failed: {e}"))
                        .await
                }
            }
        }
        ("GET", "/fib-wall") => {
            let rpc_addr = {
                let state = state.lock().await;
                state.rpc_addr.clone()
            };
            let limit = query
                .get("limit")
                .and_then(|v| v.parse::<u32>().ok())
                .unwrap_or(128)
                .clamp(1, 2048);
            match tokio::task::spawn_blocking(move || fibonacci_wall(&rpc_addr, limit)).await {
                Ok(Ok(wall)) => {
                    let out: Vec<serde_json::Value> = wall
                        .into_iter()
                        .map(|entry| {
                            serde_json::json!({
                                "block_height": entry.block_height,
                                "timestamp_ms": entry.timestamp_ms,
                                "month_start_ms": entry.month_start_ms,
                                "label": entry.label,
                                "proposer": hex(&entry.proposer),
                            })
                        })
                        .collect();
                    respond_ok(&mut stream, out).await;
                }
                Ok(Err(e)) => respond_error(&mut stream, 500, &e).await,
                Err(e) => {
                    respond_error(&mut stream, 500, &format!("fib-wall task failed: {e}")).await
                }
            }
        }
        _ => {
            respond_error(&mut stream, 404, "not found").await;
        }
    }
}

struct HttpRequest {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

async fn read_request<S>(stream: &mut S) -> Result<HttpRequest, String>
where
    S: AsyncRead + Unpin,
{
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    loop {
        let n = stream.read(&mut tmp).await.map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.len() > MAX_HTTP_BYTES {
            return Err("request too large".to_string());
        }
        if find_header_end(&buf).is_some() {
            break;
        }
    }
    let header_end = find_header_end(&buf).ok_or_else(|| "invalid http request".to_string())?;
    let header_str = String::from_utf8_lossy(&buf[..header_end]);
    let mut lines = header_str.lines();
    let request_line = lines
        .next()
        .ok_or_else(|| "missing request line".to_string())?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("").to_string();

    let mut content_length = 0usize;
    let mut headers = HashMap::new();
    for line in lines {
        let lower = line.to_ascii_lowercase();
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
        }
        if lower.starts_with("content-length:") {
            if let Ok(n) = lower[15..].trim().parse::<usize>() {
                content_length = n;
            }
        }
    }
    if content_length > MAX_HTTP_BODY_BYTES {
        return Err("request body too large".to_string());
    }

    let mut body = Vec::new();
    let mut rest = buf[(header_end + 4)..].to_vec();
    if !rest.is_empty() {
        body.append(&mut rest);
    }
    if body.len() > MAX_HTTP_BODY_BYTES {
        return Err("request body too large".to_string());
    }
    while body.len() < content_length {
        let n = stream.read(&mut tmp).await.map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
        if body.len() > MAX_HTTP_BODY_BYTES {
            return Err("request body too large".to_string());
        }
    }

    Ok(HttpRequest {
        method,
        path,
        headers,
        body,
    })
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn split_path_query(path: &str) -> (&str, HashMap<String, String>) {
    let mut out = HashMap::new();
    let (p, q) = match path.split_once('?') {
        Some(v) => v,
        None => return (path, out),
    };
    for pair in q.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = match pair.split_once('=') {
            Some(v) => v,
            None => (pair, ""),
        };
        let key = k.trim().to_ascii_lowercase();
        if key.is_empty() {
            continue;
        }
        out.insert(key, v.trim().to_string());
    }
    (p, out)
}

async fn respond_ok<T: Serialize, S: AsyncWrite + Unpin>(stream: &mut S, payload: T) {
    let resp = ApiResponse {
        ok: true,
        result: Some(payload),
        error: None,
    };
    let body = serde_json::to_string(&resp).unwrap_or_else(|_| "{\"ok\":false}".to_string());
    respond_with_body(stream, 200, &body).await;
}

async fn respond_error<S: AsyncWrite + Unpin>(stream: &mut S, status: u16, msg: &str) {
    let resp: ApiResponse<()> = ApiResponse {
        ok: false,
        result: None,
        error: Some(msg.to_string()),
    };
    let body = serde_json::to_string(&resp).unwrap_or_else(|_| "{\"ok\":false}".to_string());
    respond_with_body(stream, status, &body).await;
}

async fn respond_empty<S: AsyncWrite + Unpin>(stream: &mut S, status: u16) {
    let _ = stream
        .write_all(format!("HTTP/1.1 {}\r\n{}\r\n", status_line(status), cors_headers()).as_bytes())
        .await;
}

async fn respond_with_body<S: AsyncWrite + Unpin>(stream: &mut S, status: u16, body: &str) {
    let headers = format!(
        "HTTP/1.1 {}\r\n{}Content-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\n\r\n",
        status_line(status),
        cors_headers(),
        body.as_bytes().len()
    );
    let _ = stream.write_all(headers.as_bytes()).await;
    let _ = stream.write_all(body.as_bytes()).await;
}

fn status_line(code: u16) -> String {
    match code {
        200 => "200 OK".to_string(),
        204 => "204 No Content".to_string(),
        400 => "400 Bad Request".to_string(),
        404 => "404 Not Found".to_string(),
        _ => format!("{}", code),
    }
}

fn cors_headers() -> String {
    if unsafe_overrides_enabled() && std::env::var("KNOX_WALLETD_CORS").ok().as_deref() == Some("1")
    {
        "Access-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type, Authorization, X-Auth-Token\r\n"
            .to_string()
    } else {
        "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type, Authorization, X-Auth-Token\r\n"
            .to_string()
    }
}

fn now_ms() -> u64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    now.as_millis() as u64
}

impl RateLimiter {
    fn allow(&self, ip: IpAddr, limit_per_sec: u32, now_ms: u64) -> bool {
        let Ok(mut map) = self.inner.lock() else {
            return false;
        };
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

fn load_auth_token() -> Option<String> {
    if let Ok(path) = std::env::var("KNOX_WALLETD_TOKEN_FILE") {
        let p = path.trim();
        if !p.is_empty() {
            if let Ok(v) = std::fs::read_to_string(p) {
                let t = v.trim().to_string();
                if !t.is_empty() {
                    return Some(t);
                }
            }
        }
    }
    match std::env::var("KNOX_WALLETD_TOKEN") {
        Ok(v) => {
            let t = v.trim().to_string();
            if t.is_empty() {
                None
            } else {
                Some(t)
            }
        }
        Err(_) => None,
    }
}

fn is_authorized(req: &HttpRequest, token: &str) -> bool {
    if let Some(value) = req.headers.get("authorization") {
        let parts: Vec<&str> = value.split_whitespace().collect();
        if parts.len() == 2 && parts[0].eq_ignore_ascii_case("bearer") && ct_eq(parts[1], token) {
            return true;
        }
    }
    if let Some(value) = req.headers.get("x-auth-token") {
        if ct_eq(value, token) {
            return true;
        }
    }
    false
}

fn ct_eq(a: &str, b: &str) -> bool {
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    let max_len = a_bytes.len().max(b_bytes.len());
    let mut diff = a_bytes.len() ^ b_bytes.len();
    for i in 0..max_len {
        let xa = if i < a_bytes.len() { a_bytes[i] } else { 0 };
        let xb = if i < b_bytes.len() { b_bytes[i] } else { 0 };
        diff |= (xa ^ xb) as usize;
    }
    diff == 0
}

fn import_path_allowed(node_key_path: &str, wallet_path: &str) -> bool {
    if unsafe_overrides_enabled()
        && std::env::var("KNOX_WALLETD_ALLOW_ANY_PATH").ok().as_deref() == Some("1")
    {
        return true;
    }
    let wallet_dir = match Path::new(wallet_path).parent() {
        Some(dir) => dir,
        None => return false,
    };
    let node_path = match Path::new(node_key_path).canonicalize() {
        Ok(p) => p,
        Err(_) => return false,
    };
    let node_meta = match std::fs::symlink_metadata(&node_path) {
        Ok(m) => m,
        Err(_) => return false,
    };
    if !node_meta.file_type().is_file() || node_meta.file_type().is_symlink() {
        return false;
    }
    let wallet_dir = match wallet_dir.canonicalize() {
        Ok(p) => p,
        Err(_) => return false,
    };
    let data_dir = wallet_dir.join("data");
    let data_dir = match data_dir.canonicalize() {
        Ok(p) => p,
        Err(_) => return false,
    };
    if !node_path.starts_with(&data_dir) {
        return false;
    }
    match node_path.file_name().and_then(|n| n.to_str()) {
        Some(name) => name.eq_ignore_ascii_case("node.key"),
        None => false,
    }
}

fn load_tls_config() -> Result<Option<Arc<ServerConfig>>, String> {
    let mut cert_path = std::env::var("KNOX_WALLETD_TLS_CERT")
        .ok()
        .filter(|v| !v.trim().is_empty());
    let mut key_path = std::env::var("KNOX_WALLETD_TLS_KEY")
        .ok()
        .filter(|v| !v.trim().is_empty());

    if cert_path.is_none() || key_path.is_none() {
        let mut candidates = Vec::new();
        if let Ok(cwd) = std::env::current_dir() {
            candidates.push(cwd.join("certs"));
        }
        if let Ok(exe) = std::env::current_exe() {
            if let Some(dir) = exe.parent() {
                candidates.push(dir.join("certs"));
            }
        }
        for base in candidates {
            let c = base.join("walletd.crt");
            let k = base.join("walletd.key");
            if c.exists() && k.exists() {
                cert_path = Some(c.to_string_lossy().to_string());
                key_path = Some(k.to_string_lossy().to_string());
                break;
            }
        }
    }

    let cert_path = match cert_path {
        Some(v) => v,
        None => return Ok(None),
    };
    let key_path = match key_path {
        Some(v) => v,
        None => {
            return Err("KNOX_WALLETD_TLS_CERT set but KNOX_WALLETD_TLS_KEY missing".to_string())
        }
    };

    let cert_file = File::open(&cert_path).map_err(|e| format!("read cert: {e}"))?;
    let mut cert_reader = BufReader::new(cert_file);
    let certs: Vec<CertificateDer<'static>> = certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("parse cert: {e}"))?;
    if certs.is_empty() {
        return Err("no certs found in KNOX_WALLETD_TLS_CERT".to_string());
    }

    let key_file = File::open(&key_path).map_err(|e| format!("read key: {e}"))?;
    let mut key_reader = BufReader::new(key_file);
    let key: Option<PrivateKeyDer<'static>> =
        private_key(&mut key_reader).map_err(|e| format!("parse key: {e}"))?;
    let key = match key {
        Some(k) => k,
        None => return Err("no private key found in KNOX_WALLETD_TLS_KEY".to_string()),
    };

    let cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("tls config: {e}"))?;
    Ok(Some(Arc::new(cfg)))
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

fn parse_send_amount(raw_atoms: Option<u64>, raw_coins: Option<&str>) -> Result<u64, String> {
    if let Some(v) = raw_atoms {
        return Ok(v);
    }
    let coins = raw_coins.ok_or_else(|| "missing value".to_string())?.trim();
    if coins.is_empty() {
        return Err("empty value".to_string());
    }
    if let Some(dot) = coins.find('.') {
        let int_part = &coins[..dot];
        let frac_part = &coins[(dot + 1)..];
        if frac_part.len() > 8 {
            return Err("too many decimal places (max 8)".to_string());
        }
        let whole = int_part
            .parse::<u64>()
            .map_err(|_| "invalid integer part".to_string())?;
        let mut frac = frac_part.to_string();
        while frac.len() < 8 {
            frac.push('0');
        }
        let frac_atoms = frac
            .parse::<u64>()
            .map_err(|_| "invalid fractional part".to_string())?;
        whole
            .checked_mul(knox_types::ATOMS_PER_COIN)
            .and_then(|v| v.checked_add(frac_atoms))
            .ok_or_else(|| "amount overflow".to_string())
    } else {
        let whole = coins
            .parse::<u64>()
            .map_err(|_| "invalid amount".to_string())?;
        whole
            .checked_mul(knox_types::ATOMS_PER_COIN)
            .ok_or_else(|| "amount overflow".to_string())
    }
}
