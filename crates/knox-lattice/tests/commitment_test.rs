use knox_lattice::{commit_value, verify_opening, CommitmentOpening, LatticeCommitmentKey, Poly};

#[test]
fn commitment_opening_verifies() {
    let key = LatticeCommitmentKey::derive();
    let opening = CommitmentOpening {
        value: 4242,
        randomness: Poly::sample_short(b"commitment", b"open"),
    };
    let c = commit_value(&key, opening.value, &opening.randomness);
    assert!(verify_opening(&key, &c, &opening));
}
