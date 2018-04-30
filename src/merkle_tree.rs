use utils::{wots_sign_raw, wots_verify_raw, gen_pubkey};

use openssl::sha::sha256;
use rand::Rng;
use rand::OsRng;

pub struct MTPubKey {
    hash: [u8; 32]
}

pub struct MTPrivKey {
    uses: u32,
    max_uses: u32,
    height: u32,
    seed: [u8; 32],
    auth_path: Vec<Node>,
    stacks: Vec<Option<Stack>>,
}

struct Stack {
    height: u32,
    start_index: u32,
    index: u32,
    nodes: Vec<Node>,
}

struct Node {
    height: u32,
    value: [u8; 32],
}

impl Stack {
    fn is_complete(&self) -> bool {
        if let Some(first_node) = self.nodes.first() {
            first_node.height == self.height
        }
        else {
            false
        }
    }

    fn needs_push(&self) -> bool {
        let size = self.nodes.len();
        if size > 2 {
            self.nodes[size - 1].height != self.nodes[size - 2].height
        }
        else {
            true
        }
    }

    fn push(&mut self, node: Node) {
        self.nodes.push(node);
        self.index += 1;
    }

    fn hash(&mut self) {
        let mut to_hash: [u8; 64] = [0; 64];
        let node = self.nodes.pop().unwrap();
        to_hash[32..64].copy_from_slice(&node.value);

        let node = self.nodes.pop().unwrap();
        to_hash[0..32].copy_from_slice(&node.value);

        self.nodes.push(Node {
            height: node.height,
            value: sha256(&to_hash),
        });
    }

    fn pop(&mut self) -> Node {
        self.nodes.pop().unwrap()
    }
}

pub struct MTSignature {
    wots_pubkey: [u8; 32*34],
    wots_signature: [u8; 32*34],
    auth_path: Vec<Node>,
}

impl MTPubKey {
    pub fn verify(&self, message: &[u8], signature: &MTSignature) -> bool {
        wots_verify_raw(&signature.wots_pubkey, message,
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

        let wots_privkey = self.get_wots_key(self.uses);
        self.register_use();

        Ok(MTSignature {
            wots_pubkey: gen_pubkey(&wots_privkey),
            wots_signature: wots_sign_raw(&wots_privkey, message),
            auth_path: Vec::new(),
        })
    }

    fn get_wots_key(&self, key_index: u32) -> [u8; 32*34] {

        /* The WOTS keys are generated in a forward-secure manner, so
         * we cannot produce a previous key. */

        if key_index < self.uses {
            panic!("MTPrivKey cannot generate previously used WOTS keys.");
        }

        /* The seed for the ith WOTS key is sha256(seed_{i-1} || 00000000).
         * The WOTS key is generated from its seed as
         * sha256(seed_i || 00000001), sha256(seed_i || 00000002), ... */

        let mut buffer: [u8; 33] = [0; 33];
        buffer[0..32].copy_from_slice(&self.seed);

        for _ in self.uses..key_index {
            let next_key_seed = sha256(&buffer);
            buffer[0..32].copy_from_slice(&next_key_seed);
        }

        let mut wots_key: [u8; 32*34] = [0; 32*34];
        for i in 0..34 {
            buffer[32] += 1;
            wots_key[32*i..32*(i+1)].copy_from_slice(&sha256(&buffer));
        }

        wots_key
    }

    fn get_leaf_node(&self, node_index: u32) -> Node {
        Node {
            height: 0,
            value: sha256(&self.get_wots_key(node_index)),
        }
    }

    fn stack_init(&mut self, height: u32, start_index: u32) {
        self.stacks[height as usize] = Some(Stack {
            height: height,
            start_index: start_index,
            index: start_index,
            nodes: Vec::new(),
        });
    }

    fn stack_update(&mut self, height: u32, num_updates: u32) {
        if let Some(mut stack) = self.stacks[height as usize].take() {
            let mut update_count = 0;

            while !stack.is_complete() && update_count < num_updates {
                if stack.needs_push() {
                    let leaf = self.get_leaf_node(stack.index);
                    stack.push(leaf);
                }
                else {
                    stack.hash();
                }
            }
        }
    }

    fn tree_hash(&self) -> [u8; 32] {

        /* We can only calculate the tree hash when no keys have been
         * used yet. */

        if self.uses > 0 {
            panic!("Cannot generate the tree hash after the first use.");
        }

        /* Initialize the stack with the first two leaf nodes. */

        let mut stack = Vec::<Node>::new();
        stack.push(self.get_leaf_node(0));
        stack.push(self.get_leaf_node(1));
        let mut node_index = 2;

        while stack[0].height < self.height {
            
            /* If the last two elements of the stack have the same
             * height, hash them together. Otherwise, add another leaf
             * node. */

            let size = stack.len();
            if size > 1 && stack[size - 1].height == stack[size - 2].height {
                let last_node = stack.pop().unwrap();
                let second_to_last_node = stack.pop().unwrap();

                let mut hash_buffer: [u8; 64] = [0; 64];
                hash_buffer[0..32].copy_from_slice(&second_to_last_node.value);
                hash_buffer[32..64].copy_from_slice(&last_node.value);
                stack.push(Node {
                    height: last_node.height + 1,
                    value: sha256(&hash_buffer),
                });
            }
            else {
                stack.push(self.get_leaf_node(node_index));
                node_index += 1;
            }
        }

        stack[0].value
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

    let mut priv_key = MTPrivKey {
        uses: 0,
        max_uses: actual_max_uses,
        height: height,
        seed: [0; 32],
        auth_path: Vec::with_capacity(height as usize),
        stacks: Vec::with_capacity(height as usize),
    };

    let mut rng = OsRng::new().unwrap();
    rng.fill_bytes(&mut priv_key.seed);

    let pub_key = MTPubKey {
        hash: priv_key.tree_hash(),
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
