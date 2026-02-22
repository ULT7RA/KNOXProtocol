use knox_lattice::{
    build_address, commit_value, keygen, prove_range_u64, scan_with_view_key, send_to_stealth,
    sign_ring, verify_range_u64, verify_ring, CommitmentOpening, LatticeCommitmentKey, Poly,
};

#[test]
fn lattice_flow_sign_prove_and_scan() {
    let key = LatticeCommitmentKey::derive();
    let opening = CommitmentOpening {
        value: 512,
        randomness: Poly::sample_short(b"integration", b"open"),
    };
    let commitment = commit_value(&key, opening.value, &opening.randomness);
    let range = prove_range_u64(&key, &commitment, &opening).expect("prove range");
    assert!(verify_range_u64(&key, &commitment, &range));

    let mut ring = Vec::new();
    let mut secrets = Vec::new();
    for _ in 0..4 {
        let (sk, pk) = keygen();
        secrets.push(sk);
        ring.push(pk);
    }
    let sig = sign_ring(b"integration-msg", &ring, 1, &secrets[1]).expect("sign");
    assert!(verify_ring(b"integration-msg", &ring, &sig));

    let addr = build_address(secrets[2].clone(), secrets[3].clone());
    let out = send_to_stealth(&addr.view_public, &addr.spend_public);
    assert!(scan_with_view_key(
        &addr.view_secret,
        &addr.spend_public,
        &out
    ));
}
