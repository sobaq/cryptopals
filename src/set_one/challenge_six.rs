use eyre::{ContextCompat, Result};
use itertools::Itertools;
use std::fmt::Write;

use super::challenge_three::brute_force_single_byte_xor;

const MIN_KEYSIZE: usize = 2;
const MAX_KEYSIZE: usize = 40;

const BASE64_CHARS: [char; 64] = [
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q',
    'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
    'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y',
    'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/',
];

pub fn hamming_distance(lhs: &[u8], rhs: &[u8]) -> usize {
    let lhs = bitstring(lhs);
    let rhs = bitstring(rhs);

    lhs.bytes()
        .zip(rhs.bytes())
        .map(|(x, y)| (x != y) as usize)
        .sum()
}

fn determine_keysize(input: &[u8]) -> Option<usize> {
    // For each keysize
    (MIN_KEYSIZE..=MAX_KEYSIZE)
        // Figure out the average hamming distance between every group of two
        // blocks.
        .map(|keysize| {
            let chunks = input
                .chunks(keysize)
                .array_chunks::<2>()
                .map(|[c1, c2]| hamming_distance(c1, c2) as f64 / keysize as f64);
            let len = chunks.len() as f64;
            (keysize, chunks.sum::<f64>() / len)
        })
        // Return the lowest average distance
        .sorted_by(|(_, x), (_, y)| x.partial_cmp(y).unwrap())
        .next()
        .map(|x| x.0)
}

// [[a, b, c], [d, e, f], [g, h, i]] -> [[a, d, g], [b, e, h], [c, f, i]]
fn transpose_ciphertext(ciphertext: &[u8], keysize: usize) -> Vec<Vec<u8>> {
    let blocks = ciphertext.chunks(keysize);

    let mut transposed_blocks = Vec::new();
    for block_idx in 0..keysize {
        let mut transposed_block = Vec::new();
        for block in blocks.clone() {
            if block.len() > block_idx {
                transposed_block.push(block[block_idx]);
            }
        }

        transposed_blocks.push(transposed_block);
    }

    transposed_blocks
}

/// Returns (keysize, key)
pub fn brute_force_repeating_key_xor(input: &[u8]) -> Result<(usize, String)> {
    let keysize = determine_keysize(input).context("Couldn't determine keysize")?;

    let blocks = transpose_ciphertext(input, keysize);
    
    let key = blocks
        .iter()
        .map(|block| {
            let xor_guesses = brute_force_single_byte_xor(block)?;
            let (_, key_part, _) = xor_guesses.first().context("couldn't guess key part")?;

            Ok(*key_part)
        })
        .collect::<Result<Vec<u8>>>()?;
    let key = String::from_utf8(key)?;

    Ok((keysize, key))
}

pub fn base64_decode(input: &str) -> Vec<u8> {
    let padding_len = input.chars().filter(|x| x == &'=').count();
    let input = input.replace('\n', "");

    let mut o = input
        .chars()
        .array_chunks::<4>()
        .flat_map(|[one, two, three, four]| {
            let n = (b64_idx(one) << 18) + (b64_idx(two) << 12) +
                    (b64_idx(three) << 6) + b64_idx(four);
            
            [((n >> 16) & 255) as u8, ((n >> 8) & 255) as u8, (n & 255) as u8]
        })
        .collect::<Vec<u8>>();

    o.truncate(o.len() - padding_len);
    o
}

fn bitstring(inp: &[u8]) -> String {
    inp.iter().fold(String::new(), |mut w, i| {
        // note the padding
        let _ = write!(w, "{i:0>8b}");
        w
    })
}

// i dislike this
fn b64_idx(x: char) -> usize {
    if x == '=' { return 0; }
    BASE64_CHARS.iter().position(|y| y == &x).unwrap()
}

#[cfg(test)]
mod tests {
    #![allow(deprecated)]
    use super::*;

    const EXAMPLE_INPUT: &str = include_str!("../../vendor/challenge-six.txt");

    #[test]
    fn distance_example() {
        assert_eq!(hamming_distance(b"this is a test", b"wokka wokka!!!"), 37);
    }

    #[test]
    fn test_base64_decode() {
        let dec_input = base64_decode(EXAMPLE_INPUT);

        assert_eq!(
            base64::decode(EXAMPLE_INPUT.replace('\n', ""))
                .expect("base64 crate can't decode input"),
            dec_input);
    }

    #[test]
    fn example() {
        let dec_input = base64_decode(EXAMPLE_INPUT);
        let res = brute_force_repeating_key_xor(&dec_input)
            .expect("couldn't determine key")
            .1;

        assert_eq!(&res, "Terminator X: Bring the noise");
    }
}
