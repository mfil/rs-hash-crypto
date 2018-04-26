use utils::{wots_sign_raw, wots_verify_raw};

use rand::Rng;
use rand::OsRng;

pub struct MTPubKey {
    hash: [u8; 32]
}

pub struct MTPrivKey {
    uses: u32,
    max_uses: u32,
    seed: [u8; 32],
}

enum NodePosition {
    Left,
    Right,
}

struct AuthNode {
    position: NodePosition,
    value: [u8; 32],
}

pub struct MTSignature {
    wots_pubkey: [[u8; 32]; 34],
    auth_path: Vec<AuthNode>,
}

impl MTPubKey {
    pub fn verify(&self, message: &[u8], signature: &MTSignature) -> bool {
        false
    }
}

pub fn mt_key_gen(max_uses: u32) -> (MTPubKey, MTPrivKey) {
    let mut priv_key = MTPrivKey {
        uses: 0,
        max_uses: max_uses,
        seed: [0; 32],
    };
    let mut rng = OsRng::new().unwrap();
    rng.fill_bytes(&mut priv_key.seed);

    let mut pub_key = MTPubKey {
        hash: [0; 32],
    };

    (pub_key, priv_key)
}

#[cfg(test)]
mod test {
    use merkle_tree::MTPubKey;
    use merkle_tree::MTSignature;

    #[test]
    fn verify_returns_false_for_wrong_signature() {
        let pubkey = MTPubKey { hash: [0; 32] };
        let sig = MTSignature {
            wots_pubkey: [[0; 32]; 34],
            auth_path: Vec::new(),
        };

        assert!(! pubkey.verify("Hello world".as_bytes(), &sig));
    }
}
