use knox_lattice::{decrypt_amount_with_level, encrypt_amount_with_level, tx_hardening_level};

#[test]
fn transaction_encryption_round_trip() {
    let shared = [11u8; 32];
    let blind = [22u8; 32];
    let amount = 777u64;
    let level = tx_hardening_level(200);
    let (enc_amount, enc_blind) = encrypt_amount_with_level(&shared, amount, &blind, level);
    let (got_amount, got_blind) = decrypt_amount_with_level(&shared, enc_amount, enc_blind, level);
    assert_eq!(got_amount, amount);
    assert_eq!(got_blind, blind);
}
