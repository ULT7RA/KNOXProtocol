fn main() {
    eprintln!("[knox-smoke] start");

    #[cfg(feature = "types")]
    {
        let _ = knox_types::Hash32::ZERO;
    }

    #[cfg(feature = "crypto")]
    {
        let _ = knox_crypto::hash_bytes(b"knox-smoke", b"crypto");
    }

    #[cfg(feature = "consensus")]
    {
        let _ = knox_consensus::ConsensusConfig {
            epoch_length: 1,
            committee_size: 1,
            max_round_ms: 1,
        };
    }

    #[cfg(feature = "ledger")]
    {
        let _ = knox_ledger::Ledger::open("./tmp-smoke");
    }

    #[cfg(feature = "p2p")]
    {
        let _ = knox_p2p::NetworkConfig {
            bind: "-".to_string(),
            peers: Vec::new(),
            max_peers: 1,
            pad_bytes: 0,
            cover_interval_ms: 1000,
        };
    }

    #[cfg(feature = "core")]
    {
        let _ = knox_core::NodeConfig {
            data_dir: "./tmp-smoke".to_string(),
            network: knox_p2p::NetworkConfig {
                bind: "-".to_string(),
                peers: Vec::new(),
                max_peers: 1,
                pad_bytes: 0,
                cover_interval_ms: 1000,
            },
            consensus: knox_consensus::ConsensusConfig {
                epoch_length: 1,
                committee_size: 1,
                max_round_ms: 1,
            },
            validators: knox_consensus::ValidatorSet {
                validators: Vec::new(),
            },
            consensus_keypair: None,
            rpc_bind: "-".to_string(),
            miner_address: knox_types::Address {
                view: [0u8; 32],
                spend: [0u8; 32],
                lattice_spend_pub: Vec::new(),
            },
            treasury_address: knox_types::Address {
                view: [0u8; 32],
                spend: [0u8; 32],
                lattice_spend_pub: Vec::new(),
            },
            dev_address: knox_types::Address {
                view: [0u8; 32],
                spend: [0u8; 32],
                lattice_spend_pub: Vec::new(),
            },
            premine_address: knox_types::Address {
                view: [0u8; 32],
                spend: [0u8; 32],
                lattice_spend_pub: Vec::new(),
            },
            mining_enabled: false,
            mining_profile: Default::default(),
            diamond_authenticators: Vec::new(),
            diamond_auth_quorum: 0,
            diamond_auth_endpoints: Vec::new(),
        };
    }

    #[cfg(feature = "tokio")]
    {
        let _ = tokio::runtime::Builder::new_current_thread();
    }

    eprintln!("[knox-smoke] ok");
}
