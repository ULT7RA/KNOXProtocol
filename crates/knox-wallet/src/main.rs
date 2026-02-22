use knox_types::DEFAULT_DECOY_COUNT;
use knox_wallet::*;

fn main() {
    let mut args = std::env::args().skip(1);
    let cmd = args.next().unwrap_or_else(|| "help".to_string());

    match cmd.as_str() {
        "create" => {
            let path = args.next().unwrap_or_else(|| "wallet.bin".to_string());
            match create_wallet(&path) {
                Ok(state) => {
                    println!("Wallet created: {}", path);
                    println!("Address: {}", address_to_string(&state.address()));
                }
                Err(e) => eprintln!("error: {e}"),
            }
        }
        "address" => {
            let path = args.next().unwrap_or_else(|| "wallet.bin".to_string());
            match load_wallet(&path) {
                Ok(state) => println!("{}", address_to_string(&state.address())),
                Err(e) => eprintln!("error: {e}"),
            }
        }
        "addresses" => {
            let path = args.next().unwrap_or_else(|| "wallet.bin".to_string());
            match load_wallet(&path) {
                Ok(state) => {
                    for (idx, addr) in list_wallet_addresses(&state) {
                        println!("#{idx}: {}", address_to_string(&addr));
                    }
                }
                Err(e) => eprintln!("error: {e}"),
            }
        }
        "new-address" => {
            let path = args.next().unwrap_or_else(|| "wallet.bin".to_string());
            match load_wallet(&path) {
                Ok(mut state) => match create_subaddress(&mut state) {
                    Ok(addr) => {
                        if let Err(e) = save_wallet(&path, &state) {
                            eprintln!("error: {e}");
                            return;
                        }
                        println!("{}", address_to_string(&addr));
                    }
                    Err(e) => eprintln!("error: {e}"),
                },
                Err(e) => eprintln!("error: {e}"),
            }
        }
        "import-node-key" => {
            let node_key = args.next().unwrap_or_else(|| "data/node.key".to_string());
            let path = args.next().unwrap_or_else(|| "wallet.bin".to_string());
            match create_wallet_from_node_key(&node_key, &path) {
                Ok(state) => {
                    println!("Wallet created from node key: {}", path);
                    println!("Address: {}", address_to_string(&state.address()));
                }
                Err(e) => eprintln!("error: {e}"),
            }
        }
        "sync" => {
            let path = args.next().unwrap_or_else(|| "wallet.bin".to_string());
            let rpc = args.next().unwrap_or_else(|| "127.0.0.1:9736".to_string());
            match load_wallet(&path) {
                Ok(mut state) => {
                    if let Err(e) = sync_wallet(&mut state, &rpc) {
                        eprintln!("sync error: {e}");
                        return;
                    }
                    let _ = save_wallet(&path, &state);
                    let bal = wallet_balance(&state);
                    println!("Synced. Balance: {} ({})", format_atoms(bal), bal);
                }
                Err(e) => eprintln!("error: {e}"),
            }
        }
        "rescan" => {
            let path = args.next().unwrap_or_else(|| "wallet.bin".to_string());
            let rpc = args.next().unwrap_or_else(|| "127.0.0.1:9736".to_string());
            match load_wallet(&path) {
                Ok(mut state) => {
                    reset_scan_state(&mut state);
                    if let Err(e) = sync_wallet(&mut state, &rpc) {
                        eprintln!("rescan error: {e}");
                        return;
                    }
                    let _ = save_wallet(&path, &state);
                    let bal = wallet_balance(&state);
                    println!("Rescanned. Balance: {} ({})", format_atoms(bal), bal);
                }
                Err(e) => eprintln!("error: {e}"),
            }
        }
        "balance" => {
            let path = args.next().unwrap_or_else(|| "wallet.bin".to_string());
            match load_wallet(&path) {
                Ok(state) => {
                    let bal = wallet_balance(&state);
                    println!("Balance: {} ({})", format_atoms(bal), bal);
                }
                Err(e) => eprintln!("error: {e}"),
            }
        }
        "send" => {
            let path = args.next().unwrap_or_else(|| "wallet.bin".to_string());
            let rpc = args.next().unwrap_or_else(|| "127.0.0.1:9736".to_string());
            let to_addr = args.next().unwrap_or_default();
            let amount = match parse_amount_arg(&args.next().unwrap_or_else(|| "0".to_string())) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("invalid amount: {e}");
                    return;
                }
            };
            let fee = match parse_amount_arg(&args.next().unwrap_or_else(|| "0".to_string())) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("invalid fee: {e}");
                    return;
                }
            };
            let ring: usize = args
                .next()
                .unwrap_or_else(|| DEFAULT_DECOY_COUNT.to_string())
                .parse()
                .unwrap_or(DEFAULT_DECOY_COUNT);

            let to = match address_from_string(&to_addr) {
                Ok(a) => a,
                Err(e) => {
                    eprintln!("invalid address: {e}");
                    return;
                }
            };
            let mut state = match load_wallet(&path) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("error: {e}");
                    return;
                }
            };
            if sync_wallet(&mut state, &rpc).is_err() {
                eprintln!("sync failed");
                return;
            }
            let tx = match build_transaction(&mut state, &rpc, &to, amount, fee, ring) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("build error: {e}");
                    return;
                }
            };
            match submit_transaction(&rpc, &tx) {
                Ok(true) => {
                    mark_submitted_transaction(&mut state, &tx);
                    println!("submitted");
                }
                Ok(false) => println!("rejected"),
                Err(e) => eprintln!("submit error: {e}"),
            }
            let _ = save_wallet(&path, &state);
        }
        _ => {
            eprintln!("Usage:");
            eprintln!("  knox-wallet-cli create <wallet.bin>");
            eprintln!("  knox-wallet-cli address <wallet.bin>");
            eprintln!("  knox-wallet-cli addresses <wallet.bin>");
            eprintln!("  knox-wallet-cli new-address <wallet.bin>");
            eprintln!("  knox-wallet-cli import-node-key <node.key> <wallet.bin>");
            eprintln!("  knox-wallet-cli sync <wallet.bin> <rpc_addr>");
            eprintln!("  knox-wallet-cli balance <wallet.bin>");
            eprintln!("  knox-wallet-cli rescan <wallet.bin> <rpc_addr>");
            eprintln!("  knox-wallet-cli send <wallet.bin> <rpc_addr> <address> <amount_coins> <fee_coins> [ring]");
            eprintln!("  amount/fee accept decimal coin units (8 decimals max), e.g. 1, 0.01");
        }
    }
}

fn parse_amount_arg(s: &str) -> Result<u64, String> {
    let raw = s.trim();
    if raw.is_empty() {
        return Err("empty amount".to_string());
    }
    if let Some(dot) = raw.find('.') {
        let int_part = &raw[..dot];
        let frac_part = &raw[(dot + 1)..];
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
        let whole = raw
            .parse::<u64>()
            .map_err(|_| "invalid amount".to_string())?;
        whole
            .checked_mul(knox_types::ATOMS_PER_COIN)
            .ok_or_else(|| "amount overflow".to_string())
    }
}

fn format_atoms(atoms: u64) -> String {
    let whole = atoms / knox_types::ATOMS_PER_COIN;
    let frac = atoms % knox_types::ATOMS_PER_COIN;
    format!("{whole}.{:08} KNOX", frac)
}
