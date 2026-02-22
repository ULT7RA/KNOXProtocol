use std::collections::HashSet;

use crate::ring_sig::{
    key_image, key_image_id, LatticeKeyImage, LatticePublicKey, LatticeSecretKey,
};

pub fn derive_key_image(secret: &LatticeSecretKey, public: &LatticePublicKey) -> LatticeKeyImage {
    key_image(secret, public)
}

pub fn derive_key_image_id(image: &LatticeKeyImage) -> [u8; 32] {
    key_image_id(image)
}

#[derive(Default, Clone, Debug)]
pub struct KeyImageSet {
    seen: HashSet<[u8; 32]>,
}

impl KeyImageSet {
    pub fn contains(&self, image: &LatticeKeyImage) -> bool {
        self.seen.contains(&derive_key_image_id(image))
    }

    pub fn insert(&mut self, image: &LatticeKeyImage) -> bool {
        self.seen.insert(derive_key_image_id(image))
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}
