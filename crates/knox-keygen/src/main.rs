use std::fs;

use knox_crypto::generate_keypair;
use knox_lattice::{
    consensus_public_from_secret, consensus_secret_from_seed, encode_consensus_public_key,
};
use knox_types::hash_bytes;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 3 && args[1] == "--blake3" {
        match fs::read(&args[2]) {
            Ok(bytes) => {
                println!("{}", hex(&hash_bytes(&bytes).0));
            }
            Err(e) => {
                eprintln!("error: failed to read {}: {e}", args[2]);
            }
        }
        return;
    }
    if args.len() == 3 && args[1] == "--consensus-public-from-secret" {
        match hex32(&args[2]) {
            Ok(seed) => {
                let secret = consensus_secret_from_seed(&seed);
                let public = consensus_public_from_secret(&secret);
                println!("{}", hex(&encode_consensus_public_key(&public)));
            }
            Err(e) => eprintln!("error: {e}"),
        }
        return;
    }
    let expose_secret = args.iter().any(|a| a == "--full-keypair");
    match generate_keypair() {
        Ok((sk, pk)) => {
            if expose_secret {
                println!("{}{}", hex(&sk.0), hex(&pk.0));
            } else {
                println!("{}", hex(&pk.0));
            }
        }
        Err(e) => {
            eprintln!("error: {e}");
        }
    }
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

fn hex32(s: &str) -> Result<[u8; 32], String> {
    let s = s.trim();
    if s.len() != 64 {
        return Err("secret must be 64 hex chars".to_string());
    }
    let bytes = s.as_bytes();
    let mut out = [0u8; 32];
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
        _ => Err("invalid hex char".to_string()),
    }
}
