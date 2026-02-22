use knox_lattice::{
    commit_value, prove_range_u64, verify_range_u64, CommitmentOpening, LatticeCommitmentKey, Poly,
};

#[test]
fn range_proof_verifies_u64_commitment() {
    let key = LatticeCommitmentKey::derive();
    let opening = CommitmentOpening {
        value: 123_456,
        randomness: Poly::sample_short(b"range", b"open"),
    };
    let commitment = commit_value(&key, opening.value, &opening.randomness);
    let proof = prove_range_u64(&key, &commitment, &opening).expect("prove range");
    assert!(verify_range_u64(&key, &commitment, &proof));
}
