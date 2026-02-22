use knox_lattice::{keygen, sign_ring, verify_ring};

#[test]
fn ring_signature_round_trip() {
    let mut ring = Vec::new();
    let mut secrets = Vec::new();
    for _ in 0..6 {
        let (sk, pk) = keygen();
        secrets.push(sk);
        ring.push(pk);
    }
    let msg = b"knox-lattice-ring-integration";
    let sig = sign_ring(msg, &ring, 2, &secrets[2]).expect("sign ring");
    assert!(verify_ring(msg, &ring, &sig));
    assert!(!verify_ring(b"tampered", &ring, &sig));
}
