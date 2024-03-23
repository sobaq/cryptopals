use std::{collections::VecDeque, sync::OnceLock};
use rand::{RngCore, SeedableRng};

use crate::set_one::challenge_six::base64_decode;
use super::challenge_eleven::aes_ecb_enc;

const SECRET_INPUT: &str = include_str!("../../vendor/challenge-twelve.txt");

fn known_unknown_key() -> Vec<u8> {
    // Always generate the same key by seeding an RNG (poorly).
    // The output quality doesn't really matter, as long as the key isn't
    // trivially apparent.
    let mut rng = rand::rngs::StdRng::from_seed([0x69u8; 32]);
    let mut key = [0u8; 16];
    rng.fill_bytes(&mut key[..]);

    Vec::from(key)
}

// This is our black-box function that accepts input and returns some kind of
// output encrypted with a block cipher in ECB mode.
// Obivously, as an implementation detail, this is AES-128.
fn encrypt(input: &[u8]) -> Vec<u8> {
    static SECRET: OnceLock<Vec<u8>> = OnceLock::new();
    let secret_input = SECRET.get_or_init(|| { base64_decode(SECRET_INPUT) });

    let key = known_unknown_key();

    let mut plaintext = input.to_vec();
    plaintext.extend(secret_input);

    aes_ecb_enc(&plaintext, &key)
}

fn extract_block(ctx: &[u8], block_size: usize, block: usize) -> Vec<u8> {
    let dist = ctx.len() % block_size;
    let mut input = ctx.to_vec();
    input.extend(std::iter::repeat(0x00)
            .take(dist - 1)
            .collect::<Vec<u8>>());
    let zeroes = std::iter::repeat(0x00).take(block_size).collect::<Vec<u8>>();

    let block_start = ctx.len();
    let block_end = block_start + block_size;

    (0..block_size)
        .rev()
        .map(|idx| {
            let target = &encrypt(&zeroes[..idx])[block_start..block_end];
            let byte = (0x00..=0xFF)
                .find(|byte| {
                    input.push(*byte);
                    let guess = &encrypt(&input)[block_start..block_end];
                    input.pop();

                    target == guess
                })
                .unwrap();

            input.drain(..1);
            input.push(byte);
            byte
        })
        .collect()
}

/// Identify the cipher's block size by encrypting increasingly longer
/// plaintexts until the output grows.
fn identify_block_size() -> usize {
    let mut input = vec![];

    let empty = encrypt(&input);

    loop {
        input.push(b'a');
        let new = encrypt(&input);

        if new.len() != empty.len() {
            return new.len() - empty.len()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::set_two::challenge_eleven::{guess_ecb_or_cbc, EncryptionType};

    #[test]
    fn example() {
        let raw_secret = base64_decode(SECRET_INPUT);

        let block_size = identify_block_size();
        assert_eq!(block_size, 16);

        let crib = std::iter::repeat(0x00).take(block_size * 3).collect::<Vec<u8>>();
        assert_eq!(guess_ecb_or_cbc(&encrypt(&crib)), EncryptionType::Ecb);

        let blocks = encrypt(b"").len() / block_size;
        let mut res = Vec::new();
        for block in 0..blocks {
            res.extend(extract_block(&res, block_size, block));
            println!("{:?}", String::from_utf8_lossy(&res));
        }
        // let res = (0..blocks)
        //     .map(|x| extract_block(block_size, x))
        //     .inspect(|x| println!("{:?}", String::from_utf8_lossy(x)))
        //     .flatten()
        //     .collect::<Vec<u8>>();

        let decrypted = String::from_utf8_lossy(&res);
        let expected = String::from_utf8_lossy(&raw_secret);

        assert_eq!(decrypted, expected);
    }
}
