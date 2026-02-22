use knox_lattice::{
    commit_value, mine_block_proof, prove_range_u64, CommitmentOpening, LatticeCommitmentKey, Poly,
};
use knox_types::{BlockHeader, Hash32};
use std::time::Instant;

fn main() {
    let key = LatticeCommitmentKey::derive();
    let opening = CommitmentOpening {
        value: 123_456_789,
        randomness: Poly::sample_short(b"bench", b"open"),
    };

    let t0 = Instant::now();
    for _ in 0..32 {
        let _ = commit_value(&key, opening.value, &opening.randomness);
    }
    println!("commit x32: {:?}", t0.elapsed());

    let commitment = commit_value(&key, opening.value, &opening.randomness);
    let t1 = Instant::now();
    for _ in 0..8 {
        let _ = prove_range_u64(&key, &commitment, &opening).expect("range proof");
    }
    println!("range prove x8: {:?}", t1.elapsed());

    let header = BlockHeader {
        version: 1,
        height: 1,
        round: 0,
        prev: Hash32::ZERO,
        tx_root: Hash32::ZERO,
        slash_root: Hash32::ZERO,
        state_root: Hash32::ZERO,
        timestamp_ms: 0,
        proposer: [0u8; 32],
        qc: None,
    };
    let t2 = Instant::now();
    let _ = mine_block_proof(&header, 1);
    println!("mine one proof: {:?}", t2.elapsed());
}
