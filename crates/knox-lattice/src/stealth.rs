use crate::poly::Poly;
use crate::ring_sig::{
    hash_to_poly, public_from_secret, ring_generator, LatticePublicKey, LatticeSecretKey,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LatticeAddressKeys {
    pub view_secret: LatticeSecretKey,
    pub view_public: LatticePublicKey,
    pub spend_secret: LatticeSecretKey,
    pub spend_public: LatticePublicKey,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LatticeStealthOutput {
    pub one_time_public: LatticePublicKey,
    pub ephemeral_public: LatticePublicKey,
}

pub fn build_address(
    view_secret: LatticeSecretKey,
    spend_secret: LatticeSecretKey,
) -> LatticeAddressKeys {
    let view_public = public_from_secret(&view_secret);
    let spend_public = public_from_secret(&spend_secret);
    LatticeAddressKeys {
        view_secret,
        view_public,
        spend_secret,
        spend_public,
    }
}

pub fn send_to_stealth(
    view_public: &LatticePublicKey,
    spend_public: &LatticePublicKey,
) -> LatticeStealthOutput {
    let ephemeral_secret = Poly::random_short();
    send_to_stealth_with_ephemeral(view_public, spend_public, &ephemeral_secret)
}

pub fn send_to_stealth_with_ephemeral(
    view_public: &LatticePublicKey,
    spend_public: &LatticePublicKey,
    ephemeral_secret: &Poly,
) -> LatticeStealthOutput {
    // Lattice key exchange shared secret: s = (A*view_sk)*r = (A*r)*view_sk
    let shared_sender = view_public.p.mul(ephemeral_secret);
    let tweak_secret = hash_to_poly(b"knox-lattice-stealth-tweak", &shared_sender.to_bytes());
    let tweak_public = ring_generator().mul(&tweak_secret);
    let one_time_public = LatticePublicKey {
        p: spend_public.p.add(&tweak_public),
    };
    let ephemeral_public = LatticePublicKey {
        p: ring_generator().mul(ephemeral_secret),
    };
    LatticeStealthOutput {
        one_time_public,
        ephemeral_public,
    }
}

pub fn recover_one_time_secret(
    view_secret: &LatticeSecretKey,
    spend_secret: &LatticeSecretKey,
    ephemeral_public: &LatticePublicKey,
) -> LatticeSecretKey {
    let shared_receiver = ephemeral_public.p.mul(&view_secret.s);
    let tweak_secret = hash_to_poly(b"knox-lattice-stealth-tweak", &shared_receiver.to_bytes());
    LatticeSecretKey {
        s: spend_secret.s.add(&tweak_secret),
    }
}

pub fn scan_with_view_key(
    view_secret: &LatticeSecretKey,
    spend_public: &LatticePublicKey,
    output: &LatticeStealthOutput,
) -> bool {
    let shared_receiver = output.ephemeral_public.p.mul(&view_secret.s);
    let tweak_secret = hash_to_poly(b"knox-lattice-stealth-tweak", &shared_receiver.to_bytes());
    let tweak_public = ring_generator().mul(&tweak_secret);
    let expected = LatticePublicKey {
        p: spend_public.p.add(&tweak_public),
    };
    expected == output.one_time_public
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stealth_output_is_scannable_and_recoverable() {
        let keys = build_address(
            LatticeSecretKey {
                s: Poly::sample_short(b"test", b"view"),
            },
            LatticeSecretKey {
                s: Poly::sample_short(b"test", b"spend"),
            },
        );
        let eph = Poly::sample_short(b"test", b"ephemeral");
        let out = send_to_stealth_with_ephemeral(&keys.view_public, &keys.spend_public, &eph);

        assert!(scan_with_view_key(
            &keys.view_secret,
            &keys.spend_public,
            &out
        ));

        let one_time_secret =
            recover_one_time_secret(&keys.view_secret, &keys.spend_secret, &out.ephemeral_public);
        let one_time_public = public_from_secret(&one_time_secret);
        assert_eq!(one_time_public, out.one_time_public);
    }
}
