use eframe::egui;
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

fn log_path() -> PathBuf {
    let mut root = if let Ok(appdata) = std::env::var("APPDATA") {
        PathBuf::from(appdata).join("knox-wallet-gui")
    } else if let Ok(xdg_state) = std::env::var("XDG_STATE_HOME") {
        PathBuf::from(xdg_state).join("knox-wallet-gui")
    } else if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home)
            .join(".local")
            .join("state")
            .join("knox-wallet-gui")
    } else {
        std::env::temp_dir().join("knox-wallet-gui")
    };
    let _ = fs::create_dir_all(&root);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&root, fs::Permissions::from_mode(0o700));
    }
    root.push("main.log");
    root
}

fn log_line(msg: &str) {
    let path = log_path();
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&path) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
        }
        let _ = writeln!(file, "{msg}");
    }
}
use knox_wallet::{
    address_from_string, address_to_string, build_transaction, create_wallet, load_wallet,
    submit_transaction, sync_wallet, wallet_balance, WalletState,
};

struct WalletApp {
    wallet_path: String,
    rpc_addr: String,
    status: String,
    address: String,
    balance: u64,
    send_to: String,
    send_amount: String,
    send_fee: String,
    send_confirmed: bool,
    state: Option<WalletState>,
}

impl Default for WalletApp {
    fn default() -> Self {
        Self {
            wallet_path: "wallet.bin".to_string(),
            rpc_addr: "127.0.0.1:9736".to_string(),
            status: String::new(),
            address: String::new(),
            balance: 0,
            send_to: String::new(),
            send_amount: "0".to_string(),
            send_fee: "0".to_string(),
            send_confirmed: false,
            state: None,
        }
    }
}

impl eframe::App for WalletApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("KNOX WALLET");
            ui.separator();
            ui.horizontal(|ui| {
                ui.label("Wallet file:");
                ui.text_edit_singleline(&mut self.wallet_path);
                if ui.button("Create").clicked() {
                    match create_wallet(&self.wallet_path) {
                        Ok(state) => {
                            self.address = address_to_string(&state.address());
                            self.balance = wallet_balance(&state);
                            self.state = Some(state);
                            self.status = "wallet created".to_string();
                        }
                        Err(e) => self.status = format!("create error: {e}"),
                    }
                }
                if ui.button("Load").clicked() {
                    match load_wallet(&self.wallet_path) {
                        Ok(state) => {
                            self.address = address_to_string(&state.address());
                            self.balance = wallet_balance(&state);
                            self.state = Some(state);
                            self.status = "wallet loaded".to_string();
                        }
                        Err(e) => self.status = format!("load error: {e}"),
                    }
                }
            });

            ui.horizontal(|ui| {
                ui.label("RPC:");
                ui.text_edit_singleline(&mut self.rpc_addr);
                if ui.button("Sync").clicked() {
                    if let Some(state) = &mut self.state {
                        match sync_wallet(state, &self.rpc_addr) {
                            Ok(()) => {
                                self.balance = wallet_balance(state);
                                let _ = knox_wallet::save_wallet(&self.wallet_path, state);
                                self.status = "synced".to_string();
                            }
                            Err(e) => self.status = format!("sync error: {e}"),
                        }
                    }
                }
            });

            ui.separator();
            ui.label(format!("Address: {}", self.address));
            ui.label(format!("Balance: {}", self.balance));
            ui.separator();

            ui.label("Send");
            ui.horizontal(|ui| {
                ui.label("To:");
                ui.text_edit_singleline(&mut self.send_to);
            });
            ui.horizontal(|ui| {
                ui.label("Amount:");
                ui.text_edit_singleline(&mut self.send_amount);
                ui.label("Fee:");
                ui.text_edit_singleline(&mut self.send_fee);
            });
            ui.checkbox(&mut self.send_confirmed, "I confirm this transfer");
            if ui.button("Send").clicked() {
                if let Some(state) = &mut self.state {
                    if !self.send_confirmed {
                        self.status = "confirm transfer checkbox before send".to_string();
                        return;
                    }
                    let addr = match address_from_string(&self.send_to) {
                        Ok(a) => a,
                        Err(e) => {
                            self.status = format!("address error: {e}");
                            return;
                        }
                    };
                    let amount: u64 = match self.send_amount.trim().parse() {
                        Ok(v) if v > 0 => v,
                        Ok(_) => {
                            self.status = "amount must be > 0".to_string();
                            return;
                        }
                        Err(_) => {
                            self.status = "amount must be an unsigned integer".to_string();
                            return;
                        }
                    };
                    let fee: u64 = match self.send_fee.trim().parse() {
                        Ok(v) => v,
                        Err(_) => {
                            self.status = "fee must be an unsigned integer".to_string();
                            return;
                        }
                    };
                    if sync_wallet(state, &self.rpc_addr).is_err() {
                        self.status = "sync failed".to_string();
                        return;
                    }
                    match build_transaction(
                        state,
                        &self.rpc_addr,
                        &addr,
                        amount,
                        fee,
                        knox_types::DEFAULT_DECOY_COUNT,
                    ) {
                        Ok(tx) => match submit_transaction(&self.rpc_addr, &tx) {
                            Ok(true) => {
                                let _ = knox_wallet::save_wallet(&self.wallet_path, state);
                                self.status = "submitted".to_string();
                                self.send_confirmed = false;
                            }
                            Ok(false) => self.status = "rejected".to_string(),
                            Err(e) => self.status = format!("submit error: {e}"),
                        },
                        Err(e) => self.status = format!("build error: {e}"),
                    }
                }
            }

            ui.separator();
            ui.label(format!("Status: {}", self.status));
        });
    }
}

fn main() -> Result<(), eframe::Error> {
    log_line("[knox-wallet-gui] start");
    std::panic::set_hook(Box::new(|info| {
        log_line(&format!("[knox-wallet-gui] panic: {info}"));
    }));
    let options = eframe::NativeOptions::default();
    log_line("[knox-wallet-gui] launching window");
    let res = eframe::run_native(
        "KNOX WALLET",
        options,
        Box::new(|_cc| Box::new(WalletApp::default())),
    );
    log_line("[knox-wallet-gui] run_native returned");
    res
}
