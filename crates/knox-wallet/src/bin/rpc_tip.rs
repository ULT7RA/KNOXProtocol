use std::io::{Read, Write};
use std::net::TcpStream;

fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn rpc_request(addr: &str, req: knox_types::WalletRequest) -> Result<knox_types::WalletResponse, String> {
    let req_bytes =
        bincode::encode_to_vec(req, bincode::config::standard()).map_err(|e| format!("encode: {e}"))?;
    let mut stream = TcpStream::connect(addr).map_err(|e| format!("connect {addr}: {e}"))?;
    stream
        .write_all(&(req_bytes.len() as u32).to_le_bytes())
        .map_err(|e| format!("write len: {e}"))?;
    stream
        .write_all(&req_bytes)
        .map_err(|e| format!("write body: {e}"))?;
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .map_err(|e| format!("read len: {e}"))?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len == 0 || len > 64 * 1024 * 1024 {
        return Err(format!("bad response len: {len}"));
    }
    let mut buf = vec![0u8; len];
    stream
        .read_exact(&mut buf)
        .map_err(|e| format!("read body: {e}"))?;
    let (resp, _): (knox_types::WalletResponse, usize) = bincode::decode_from_slice(
        &buf,
        bincode::config::standard().with_limit::<{ 64 * 1024 * 1024 }>(),
    )
    .map_err(|e| format!("decode: {e}"))?;
    Ok(resp)
}

fn main() {
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:9736".to_string());

    let tip = match rpc_request(&addr, knox_types::WalletRequest::GetTip) {
        Ok(knox_types::WalletResponse::Tip(h)) => h,
        Ok(other) => {
            eprintln!("unexpected tip response: {other:?}");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("tip rpc failed: {e}");
            std::process::exit(1);
        }
    };

    let block = match rpc_request(&addr, knox_types::WalletRequest::GetBlock(tip)) {
        Ok(knox_types::WalletResponse::Block(Some(b))) => b,
        Ok(knox_types::WalletResponse::Block(None)) => {
            eprintln!("tip block missing at height {tip}");
            std::process::exit(1);
        }
        Ok(other) => {
            eprintln!("unexpected block response: {other:?}");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("block rpc failed: {e}");
            std::process::exit(1);
        }
    };

    let header_bytes =
        bincode::encode_to_vec(&block.header, bincode::config::standard()).expect("encode header");
    let header_hash = knox_types::hash_bytes(&header_bytes);
    println!(
        "addr={} tip={} round={} txs={} prev={} head={}",
        addr,
        tip,
        block.header.round,
        block.txs.len(),
        to_hex(&block.header.prev.0),
        to_hex(&header_hash.0)
    );
}
