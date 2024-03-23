use std::convert::identity as id;
use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use rand::Rng;

use crate::set_two::challenge_nine::pad_pkcs7;

pub type Iv = Vec<u8>;
#[derive(Debug, PartialEq)]
pub enum EncryptionType {
    Ecb,
    Cbc,
}

// Generate a random AES secret key (16 random bytes)
pub fn random_aes_key() -> Vec<u8> {
    rand::random::<[u8; 16]>().to_vec()
}

/// Encrypt input with key with AES in CBC mode
pub fn aes_cbc_enc(input: &[u8], key: &[u8]) -> (Iv, Vec<u8>) {
    let input = pad_pkcs7(input, 16);
    let iv = random_aes_key();

    let mut out = vec![];
    for (idx, block) in input.chunks(16).enumerate() {
        let prev = if idx == 0 {
            &iv
        } else {
            &out[idx - 1]
        };

        let xored = block
            .iter()
            .zip(prev.iter())
            .map(|(x, y)| x ^ y)
            .collect::<Vec<u8>>();

        let mut out_block = GenericArray::default();
        let aes = aes::Aes128Enc::new_from_slice(key).unwrap();
        aes.encrypt_block_b2b(GenericArray::from_slice(&xored), &mut out_block);

        out.push(out_block.to_vec());
    }

    (iv, out.into_iter().flatten().collect())
}

/// Encrypt input with key with AES in ECB mode
pub fn aes_ecb_enc(input: &[u8], key: &[u8]) -> Vec<u8> {
    let input = pad_pkcs7(input, 16);
    let blocks = input.clone();
    let blocks = blocks.chunks(16);

    blocks.flat_map(|block| {
        let aes = aes::Aes128Enc::new_from_slice(key).unwrap();
        // this function takes ownership of aes
        let mut out = GenericArray::default();
        aes.encrypt_block_b2b(GenericArray::from_slice(block), &mut out);

        out.to_vec()
    }).collect()
}

pub fn encrypt_randomly(data: &[u8]) -> (EncryptionType, Vec<u8>) {
    let key = random_aes_key();

    // Pad plaintext with oracle
    let mut final_plaintext = Vec::new();
    let oracle_size = rand::thread_rng().gen_range(5..=10);
    let oracle = (0..oracle_size).map(|_| rand::random()).collect::<Vec<u8>>();
    final_plaintext.extend(oracle.clone());
    final_plaintext.extend(data);
    final_plaintext.extend(oracle);

    if rand::random() {
        (EncryptionType::Cbc, aes_cbc_enc(&final_plaintext, &key).1)
    } else {
        (EncryptionType::Ecb, aes_ecb_enc(&final_plaintext, &key))
    }
}

/// Identifies whether a given block of encrypted data was encrypted in
/// ECB or CBC mode.
/// The given input MUST have been computed from an input containing a
/// repeating pattern _at least_ three blocks' width.
pub fn guess_ecb_or_cbc(input: &[u8]) -> EncryptionType {
    // Guess by getting windows into input from the beginning and from a 
    // one block offset. If, at any index (to account for the random amount
    // of padding), a 16 byte run is identical, it's very likely ECB.
    let ecb = input
        .windows(16)
        .zip(input.windows(16).skip(16))
        .map(|(l, r)| l == r)
        .any(id);

    if ecb {
        EncryptionType::Ecb
    } else {
        EncryptionType::Cbc
    }
}

#[cfg(test)]
mod tests {
    use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};

    use crate::set_one::challenge_seven::aes_ecb_dec;

    use super::*;

    #[test]
    fn test_guessing() {
        let input = b"000000000000000000000000000000000000000000000000";

        // make sure we get cbc and ecb guesses :)
        for _ in 0..20 {
            let (method, encrypted) = encrypt_randomly(input);
            let guess = guess_ecb_or_cbc(&encrypted);

            assert_eq!(method, guess);
        }
    }

    #[test]
    fn test_aes_ecb_enc() {
        let input = b"Test string! Test string! Test string! Test string!";
        let key = b"YELLOW SUBMARINE";

        let enc = aes_ecb_enc(input, key);
        let dec = aes_ecb_dec(&enc, key).unwrap();

        // hacky
        let match_ = String::from_utf8_lossy(input).to_string();
        assert!(String::from_utf8_lossy(&dec).contains(&match_));
    }

    #[test]
    fn test_aes_cbc_enc() {
        let input = b"Test string! Test string! Test string! Test string!";
        let key = b"YELLOW SUBMARINE";

        let (iv, enc) = aes_cbc_enc(input, key);
        assert!(enc.len() % 16 == 0, "output len somehow not a multiple of 16");

        let aes = cbc::Decryptor::<aes::Aes128>::new_from_slices(key, &iv)
            .expect("Couldn't create cbc instance from key/iv (bad length)");

        let res = aes.decrypt_padded_vec_mut::<Pkcs7>(&enc)
            .expect("aes_cbc_enc applied incorrect padding");
        let res = String::from_utf8_lossy(&res);

        let match_ = String::from_utf8_lossy(input).to_string();
        assert!(res.contains(&match_));
    }
}
