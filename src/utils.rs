use openssl::sha::sha256;

#[inline]
fn gen_wots_checksum(message_hash: &mut [u8; 34]) {
    let mut checksum: u16 = 0;
    for &byte in &message_hash[0..32] {
        checksum += 256 - (byte as u16);
    }
    message_hash[32] = (checksum >> 8) as u8;
    message_hash[33] = checksum as u8;
}

#[inline]
fn iterated_sha256(preimage: &[u8; 32], iterations: u8) -> [u8; 32] {
    let mut hash: [u8; 32] = [0; 32];
    hash.copy_from_slice(preimage);
    for _ in 0..iterations {
        hash = sha256(&hash);
    }

    hash
}

pub fn gen_pubkey(key: &[[u8; 32]; 34]) -> [[u8; 32]; 34] {
    let mut pubkey: [[u8; 32]; 34] = [[0; 32]; 34];
    for (preimage, hash) in key.iter().zip(pubkey.iter_mut()) {
        *hash = iterated_sha256(preimage, 255)
    }

    pubkey
}

pub fn wots_sign_raw(key: &[[u8; 32]; 34], message: &[u8]) -> [[u8; 32]; 34] {
    let mut message_hash: [u8; 34] = [0; 34];
    message_hash[0..32].copy_from_slice(&sha256(message));
    gen_wots_checksum(&mut message_hash);
    let mut signature: [[u8; 32]; 34] = [[0; 32]; 34];

    for (byte, preimage, hash) in izip!(message_hash.iter(), key.iter(),
                                        signature.iter_mut()) {
        *hash = iterated_sha256(preimage, 255 - *byte);
    }

    signature
}

pub fn wots_verify_raw(pubkey: &[[u8; 32]; 34], message: &[u8],
        signature: &[[u8; 32]; 34]) -> bool {

    let mut message_hash: [u8; 34] = [0; 34];
    message_hash[0..32].copy_from_slice(&sha256(message));
    gen_wots_checksum(&mut message_hash);

    let mut output = true;

    for (byte, sig_hash, pub_hash) in izip!(message_hash.iter(),
                                            signature.iter(),
                                            pubkey.iter()) {
        let hash = iterated_sha256(sig_hash, *byte);
        if hash != *pub_hash {
            output = false
        }
    }

    output
}
