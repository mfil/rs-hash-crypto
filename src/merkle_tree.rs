use utils::{wots_sign_raw, wots_verify_raw, gen_pubkey};

use openssl::sha::sha256;
use rand::Rng;
use rand::OsRng;

/* Naive implementation of the Merkle Tree signature scheme. */

/* The Merkle Tree scheme works as follows: When creating a key, select
 * a number of uses and create that many one-time signature keypairs.
 * Then, build a hash tree as follows: The leaf nodes are hashes of the
 * one-time public keys. A parent is the hash of its two children. The
 * hash at the root of the tree is the public key of the Merkle Tree
 * scheme.
 *
 * To sign a message, pick the next unused one-time key pair. The
 * signature consists of the one-time public key, the one-time signature
 * on the message, and an "authentication path" that contains the
 * sibling of the leaf node corresponding to the one-time key, the
 * sibling of its parent, the sibling of its parent's parent, etc.
 *
 * To verify a signature, check two things. If the authentication path
 * was created honestly, it should allow to recompute the root node of
 * the hash tree. The public key of the Merkle Tree scheme contains the
 * actual root. Check that these two values are equal. Then, use the
 * one-time public key to check that the one-time signature is valid.
 * If the signature passes these two checks, it is valid. */

/* Functions to help use a tree stored as an array.
 * The root is at index 0, the left child of index i is at 2 * i + 1 and
 * the right child at 2 * i + 2. */

fn parent_index(index: usize) -> usize {
    (index - 1)/2
}

fn lchild_index(index: usize) -> usize {
    2 * index + 1
}

fn rchild_index(index: usize) -> usize {
    2 * index + 2
}

fn sibling_index(index: usize) -> usize {
    if index % 2 == 0 {
        index - 1
    }
    else {
        index + 1
    }
}

fn position_of_index(index: usize) -> NodePosition {
    if index % 2 == 0 {
        NodePosition::Right
    }
    else {
        NodePosition::Left
    }
}

fn leaf_node_index(number: usize, tree_height: u32) -> usize {
    let leaves_start = 2usize.pow(tree_height) - 1;

    leaves_start + number
}

pub struct MTPubKey {
    hash: [u8; 32]
}

pub struct MTPrivKey {
    uses: u32,
    max_uses: u32,
    height: u32,
    seed: [u8; 32],
    tree: Vec<[u8; 32]>,
}

enum NodePosition {
    Left,
    Right
}

struct Node {
    position: NodePosition,
    value: [u8; 32],
}

pub struct MTSignature {
    wots_pubkey: [u8; 32*34],
    wots_signature: [u8; 32*34],
    auth_path: Vec<Node>,
}

impl MTPubKey {
    pub fn verify(&self, message: &[u8], signature: &MTSignature) -> bool {
        /* First, verify the authentication path. */

        let mut hash = sha256(&signature.wots_pubkey);
        let mut buffer = [0u8; 64];
        for node in &signature.auth_path {
            match &node.position {
                NodePosition::Left  => {
                    buffer[0..32].copy_from_slice(&node.value);
                    buffer[32..64].copy_from_slice(&hash);
                },
                NodePosition::Right => {
                    buffer[0..32].copy_from_slice(&hash);
                    buffer[32..64].copy_from_slice(&node.value);
                },
            }

            hash = sha256(&buffer);
        }

        hash == self.hash && wots_verify_raw(&signature.wots_pubkey, message,
                                             &signature.wots_signature)
    }
}

impl MTPrivKey {
    pub fn get_uses(&self) -> u32 {
        self.uses
    }

    pub fn get_max_uses(&self) -> u32 {
        self.max_uses
    }

    fn register_use(&mut self) {
        /* Advance the use counter. */

        self.uses += 1;

        /* Generate the seed for the next one-time key in a
         * forward-secure way. */

        let mut to_hash: [u8; 33] = [0; 33];
        to_hash[0..32].copy_from_slice(&self.seed);
        self.seed = sha256(&to_hash);
    }

    pub fn sign(&mut self, message: &[u8]) -> Result<MTSignature, &'static str> {
        if self.uses >= self.max_uses {
            return Err("This key can not be used anymore.");
        }

        let wots_privkey = self.get_next_wots_key();
        let mut index = leaf_node_index(self.uses as usize, self.height);
        self.register_use();

        let mut auth_path = Vec::<Node>::with_capacity(self.height as usize);

        while index > 0 {
            let sibling = sibling_index(index);
            auth_path.push(Node {
                position: position_of_index(sibling),
                value: self.tree[sibling]
            });

            /* Move to the parent node. */

            index = parent_index(index);
        }

        Ok(MTSignature {
            wots_pubkey: gen_pubkey(&wots_privkey),
            wots_signature: wots_sign_raw(&wots_privkey, message),
            auth_path: auth_path,
        })
    }

    fn get_next_wots_key(&self) -> [u8; 32*34] {
        /* The seed for the ith WOTS key is sha256(seed_{i-1} || 00000000).
         * The WOTS key is generated from its seed as
         * sha256(seed_i || 00000001), sha256(seed_i || 00000002), ... */

        let mut buffer: [u8; 33] = [0; 33];
        buffer[0..32].copy_from_slice(&self.seed);
        let mut wots_key: [u8; 32*34] = [0; 32*34];

        for i in 0..34 {
            buffer[32] += 1;
            wots_key[32*i..32*(i+1)].copy_from_slice(&sha256(&buffer));
        }

        wots_key
    }

    fn get_all_wots_keys(&self) -> Vec<[u8; 32*34]> {
        let mut wots_keys = vec![[0u8; 32*34]; self.max_uses as usize];

        let mut buffer: [u8; 33] = [0; 33];
        buffer[0..32].copy_from_slice(&self.seed);

        for i in 0..(self.max_uses as usize) {
            buffer[32] = 0;
            for j in 0..34 {
                buffer[32] += 1;
                wots_keys[i][32*j..32*(j+1)].copy_from_slice(&sha256(&buffer))
            }

            buffer[32] = 0;
            let next_seed = sha256(&buffer);
            buffer[0..32].copy_from_slice(&next_seed);
        }

        wots_keys
    }
}

pub fn mt_key_gen(max_uses: u32) -> (MTPubKey, MTPrivKey) {

    /* Round up max_uses to a power of 2 and determine the tree height. */

    let mut actual_max_uses: u32 = 1;
    let mut height: u32 = 0;
    while actual_max_uses < max_uses {
        actual_max_uses <<= 1;
        height += 1;
    }

    let tree_size: usize = 2usize.pow(height + 1) - 1;

    let mut priv_key = MTPrivKey {
        uses: 0,
        max_uses: actual_max_uses,
        height: height,
        seed: [0; 32],
        tree: vec![[0; 32]; tree_size]
    };

    let mut rng = OsRng::new().unwrap();
    rng.fill_bytes(&mut priv_key.seed);

    /* Calculate the full tree. Inefficient, but I want to get the naive
     * implementation to work before moving to more complicated stuff. */

    /* Fill in the leaf nodes. */

    let wots_keys = priv_key.get_all_wots_keys();

    for (i, key) in wots_keys.iter().enumerate() {
        let pubkey = gen_pubkey(key);
        let key_hash = sha256(&pubkey);
        priv_key.tree[leaf_node_index(i, height)].copy_from_slice(&key_hash);
    }

    /* Go backwards through the rest of the tree. */

    let mut buffer = [0u8; 64];
    for i in (0..leaf_node_index(0, height)).rev() {
        let lchild = lchild_index(i);
        let rchild = rchild_index(i);
        buffer[0..32].copy_from_slice(&priv_key.tree[lchild]);
        buffer[32..64].copy_from_slice(&priv_key.tree[rchild]);
        priv_key.tree[i].copy_from_slice(&sha256(&buffer));
    }

    let pub_key = MTPubKey {
        hash: priv_key.tree[0]
    };

    (pub_key, priv_key)
}

#[cfg(test)]
mod test {
    use merkle_tree::{MTPubKey, MTPrivKey, mt_key_gen};
    use merkle_tree::MTSignature;

    #[test]
    fn verify_returns_false_for_wrong_signature() {
        let pubkey = MTPubKey { hash: [0; 32] };
        let sig = MTSignature {
            wots_pubkey: [0; 32*34],
            wots_signature: [0; 32*34],
            auth_path: Vec::new(),
        };

        assert!(! pubkey.verify("Hello world".as_bytes(), &sig));
    }

    #[test]
    fn priv_key_max_uses_is_rounded_up_to_a_power_of_two() {
        let (_, priv_key) = mt_key_gen(1);
        assert_eq!(priv_key.get_max_uses(), 1);

        let (_, priv_key) = mt_key_gen(15);
        assert_eq!(priv_key.get_max_uses(), 16);

        let (_, priv_key) = mt_key_gen(23);
        assert_eq!(priv_key.get_max_uses(), 32);

        let (_, priv_key) = mt_key_gen(32);
        assert_eq!(priv_key.get_max_uses(), 32);

        let (_, priv_key) = mt_key_gen(50);
        assert_eq!(priv_key.get_max_uses(), 64);
    }

    #[test]
    fn priv_key_produces_the_right_number_of_signatures() {
        let (_, mut priv_key) = mt_key_gen(32);
        let message = "Hello, world!".as_bytes();

        for _ in 0..priv_key.max_uses {
            assert!(priv_key.sign(&message).is_ok());
        }

        assert!(priv_key.sign(&message).is_err());
    }

    #[test]
    fn successive_signatures_have_different_one_time_keys() {
        let (_, mut priv_key) = mt_key_gen(32);
        let message = "Hello, world!".as_bytes();

        let sig1 = priv_key.sign(&message).unwrap();
        let sig2 = priv_key.sign(&message).unwrap();

        assert!(&sig1.wots_pubkey[..] != &sig2.wots_pubkey[..]);
    }

    #[test]
    fn valid_signatures_are_verified_as_true() {
        let (pub_key, mut priv_key) = mt_key_gen(32);
        let message = "Hello, world!".as_bytes();

        for _ in 0..32 {
            let signature = priv_key.sign(message).unwrap();
            assert!(pub_key.verify(message, &signature));
        }
    }

    #[test]
    fn signatures_without_auth_paths_are_not_verified_as_true() {
        let (pub_key, mut priv_key) = mt_key_gen(32);
        let message = "Hello, world!".as_bytes();

        let mut signature = priv_key.sign(&message).unwrap();
        signature.auth_path = Vec::new();

        assert!(!pub_key.verify(&message, &signature));
    }
}
