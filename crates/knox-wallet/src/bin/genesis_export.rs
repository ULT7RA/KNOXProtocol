/// Connects to a running knox-node RPC and exports the genesis block as hex.
/// Usage: genesis_export [rpc_addr]
/// Default addr: 127.0.0.1:9736
///
/// Setup: SSH tunnel to a VM first:
///   ssh -L 9736:127.0.0.1:9736 ubuntu@<VM_IP> -i ~/.ssh/knox_oracle -N -f
/// Then run this tool. The hex output is the canonical genesis block bytes.

use std::io::{Read, Write};
use std::net::TcpStream;

fn main() {
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:9736".to_string());

    eprintln!("connecting to {addr}");

    let req = knox_types::WalletRequest::GetBlock(0);
    let req_bytes = bincode::encode_to_vec(req, bincode::config::standard())
        .expect("encode request");

    let mut stream = TcpStream::connect(&addr).expect("connect to node RPC");
    stream
        .write_all(&(req_bytes.len() as u32).to_le_bytes())
        .expect("write len");
    stream.write_all(&req_bytes).expect("write request");

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).expect("read response len");
    let resp_len = u32::from_le_bytes(len_buf) as usize;
    eprintln!("response size: {} bytes", resp_len);

    let mut resp_buf = vec![0u8; resp_len];
    stream.read_exact(&mut resp_buf).expect("read response");

    let (resp, _): (knox_types::WalletResponse, usize) = bincode::decode_from_slice(
        &resp_buf,
        bincode::config::standard().with_limit::<{ 128 * 1024 * 1024 }>(),
    )
    .expect("decode response");

    match resp {
        knox_types::WalletResponse::Block(Some(block)) => {
            let block_bytes = bincode::encode_to_vec(&block, bincode::config::standard())
                .expect("encode block");
            eprintln!("genesis block: {} bytes", block_bytes.len());
            let out_path = std::env::args().nth(2).unwrap_or_else(|| "genesis.bin".to_string());
            std::fs::write(&out_path, &block_bytes).expect("write genesis.bin");
            eprintln!("written to {out_path}");
        }
        knox_types::WalletResponse::Block(None) => {
            eprintln!("node returned no genesis block (ledger empty?)");
            std::process::exit(1);
        }
        _ => {
            eprintln!("unexpected response variant");
            std::process::exit(1);
        }
    }
}
