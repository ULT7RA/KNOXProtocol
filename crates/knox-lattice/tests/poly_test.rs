use knox_lattice::Poly;

#[test]
fn poly_add_and_mul_are_stable() {
    let a = Poly::sample_short(b"poly", b"a");
    let b = Poly::sample_short(b"poly", b"b");
    let c = Poly::sample_short(b"poly", b"c");

    let lhs = a.mul(&b.add(&c));
    let rhs = a.mul(&b).add(&a.mul(&c));
    assert_eq!(lhs, rhs);
}
