use super::utils::{gen_pubkey, wots_sign_raw, wots_verify_raw};

use std::iter::Iterator;

use openssl::sha::sha256;
use rand::{Rng,OsRng};

pub struct OTSPubKey {
    hashes: [[[u8; 32]; 256]; 2]
}

pub struct OTSPrivKey {
    used: bool,
    preimages: [[[u8; 32]; 256]; 2]
}

pub struct OTSig {
    preimages: [[u8; 32]; 256]
}

impl OTSPubKey {
    pub fn verify(&self, message: &[u8], signature: &OTSig) -> bool {
        let mut output = true;
        let message_hash = sha256(message);

        for (i, preimage) in signature.preimages.iter().enumerate() {
            /* Get the ith bit of the message hash. */

            let byte = message_hash[i/8];
            let bit = (byte >> (i % 8)) & 0x01;

            /* Get the target hash from the public key. */

            let hash = self.hashes[bit as usize][i as usize];

            /* Check if the preimage matches the hash. */

            if hash != sha256(preimage) {
                output = false;
            }
        }

        output
    }
}

impl OTSPrivKey {
    pub fn is_used(&self) -> bool {
        self.used
    }

    pub fn sign(&mut self, message: &[u8]) -> Result<OTSig, &'static str> {
        /* Check that the key has not been used. */

        if self.used {
            return Err("Which part of \"one-time\" did you not understand?");
        }
        self.used = true;

        let mut signature = OTSig {
            preimages: [[0; 32]; 256]
        };

        let message_hash = sha256(message);

        for i in 0..256 {
            /* Extract the ith bit of the message hash. */

            let byte = message_hash[i/8];
            let bit = (byte >> (i % 8)) & 0x01;

            /* Copy the appropriate preimage. */

            let preimage = &self.preimages[bit as usize][i as usize];
            signature.preimages[i].copy_from_slice(preimage);
        }

        Ok(signature)
    }
}

pub fn ots_key_gen() -> (OTSPubKey, OTSPrivKey) {
    let mut rng = OsRng::new().unwrap();
    let mut priv_key = OTSPrivKey {
        used: false,
        preimages: [[[0; 32]; 256]; 2]
    };
    let mut pub_key = OTSPubKey {
        hashes: [[[0; 32]; 256]; 2]
    };

    for i in 0..2 {
        for j in 0..256 {
            rng.fill_bytes(&mut priv_key.preimages[i][j]);
            pub_key.hashes[i][j] = sha256(&priv_key.preimages[i][j]);
        }
    }

    (pub_key, priv_key)
}

/* Winternitz one-time signatures with parameter w = 8. */

pub struct WOTSPubKey {
    key_bytes: [u8; 32*34]
}

pub struct WOTSPrivKey {
    used: bool,
    key_bytes: [u8; 32*34]
}

pub struct WOTSig {
    sig_bytes: [u8; 32*34]
}

impl WOTSPrivKey {
    pub fn is_used(&self) -> bool {
        self.used
    }

    pub fn sign(&mut self, message: &[u8]) -> Result<WOTSig, &'static str> {
        if self.used {
            return Err("I said one-time!");
        }
        self.used = true;

        let mut signature = WOTSig {
            sig_bytes: [0; 32*34]
        };
        signature.sig_bytes = wots_sign_raw(&self.key_bytes, message);

        Ok(signature)
    }
}

impl WOTSPubKey {
    pub fn verify(&self, message: &[u8], signature: &WOTSig) -> bool {
        wots_verify_raw(&self.key_bytes, message, &signature.sig_bytes)
    }
}

pub fn wots_key_gen() -> (WOTSPubKey, WOTSPrivKey) {
    let mut rng = OsRng::new().unwrap();
    let mut priv_key = WOTSPrivKey {
        used: false,
        key_bytes: [0; 32*34]
    };
    let mut pub_key = WOTSPubKey {
        key_bytes: [0; 32*34]
    };

    rng.fill_bytes(&mut priv_key.key_bytes);

    pub_key.key_bytes = gen_pubkey(&priv_key.key_bytes);

    (pub_key, priv_key)
}

#[cfg(test)]
mod test {
    use one_time_sig::{ots_key_gen,wots_key_gen};

    #[test]
    fn fresh_priv_key_is_unused() {
        let (_, priv_key) = ots_key_gen();
        assert!(! priv_key.is_used());
    }

    #[test]
    fn priv_key_can_sign_once() {
        let (_, mut priv_key) = ots_key_gen();
        let result = priv_key.sign(b"foo");
        assert!(result.is_ok());
    }

    #[test]
    fn priv_key_is_used_after_signing() {
        let (_, mut priv_key) = ots_key_gen();
        priv_key.sign(b"foo").unwrap();
        assert!(priv_key.is_used());
    }

    #[test]
    fn used_priv_key_cannot_sign_again() {
        let (_, mut priv_key) = ots_key_gen();
        priv_key.sign(b"foo").unwrap();
        assert!(priv_key.sign(b"foo").is_err())
    }

    #[test]
    fn pub_key_verifies_valid_signature() {
        let (pub_key, mut priv_key) = ots_key_gen();
        let message = b"foo";
        let signature = priv_key.sign(message).unwrap();
        assert!(pub_key.verify(message, &signature));
    }

    #[test]
    fn pub_key_does_not_verify_signature_for_different_message() {
        let (pub_key, mut priv_key) = ots_key_gen();
        let message1 = b"foo";
        let message2 = b"bar";
        let signature = priv_key.sign(message1).unwrap();
        assert!(! pub_key.verify(message2, &signature));
    }

    #[test]
    fn pub_key_does_not_verify_signature_from_different_key() {
        let (pub_key, _) = ots_key_gen();
        let (_, mut priv_key2) = ots_key_gen();
        let message = b"foo";
        let signature = priv_key2.sign(message).unwrap();
        assert!(! pub_key.verify(message, &signature));
    }

    #[test]
    fn fresh_wots_priv_key_is_unused() {
        let (_, priv_key) = wots_key_gen();
        assert!(! priv_key.is_used());
    }

    #[test]
    fn wots_priv_key_can_sign_once() {
        let (_, mut priv_key) = wots_key_gen();
        let result = priv_key.sign(b"foo");
        assert!(result.is_ok());
    }

    #[test]
    fn wots_priv_key_is_used_after_signing() {
        let (_, mut priv_key) = wots_key_gen();
        priv_key.sign(b"foo").unwrap();
        assert!(priv_key.is_used());
    }

    #[test]
    fn used_wots_priv_key_cannot_sign_again() {
        let (_, mut priv_key) = wots_key_gen();
        priv_key.sign(b"foo").unwrap();
        assert!(priv_key.sign(b"foo").is_err())
    }

    #[test]
    fn wots_pub_key_verifies_valid_signature() {
        let (pub_key, mut priv_key) = wots_key_gen();
        let message = b"foo";
        let signature = priv_key.sign(message).unwrap();
        assert!(pub_key.verify(message, &signature));
    }

    #[test]
    fn wots_pub_key_does_not_verify_signature_for_different_message() {
        let (pub_key, mut priv_key) = wots_key_gen();
        let message1 = b"foo";
        let message2 = b"bar";
        let signature = priv_key.sign(message1).unwrap();
        assert!(! pub_key.verify(message2, &signature));
    }

    #[test]
    fn wots_pub_key_does_not_verify_signature_from_different_key() {
        let (pub_key, _) = wots_key_gen();
        let (_, mut priv_key2) = wots_key_gen();
        let message = b"foo";
        let signature = priv_key2.sign(message).unwrap();
        assert!(! pub_key.verify(message, &signature));
    }
}
