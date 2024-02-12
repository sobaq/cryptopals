use eyre::{ensure, Result};
use std::fmt::Write;

use super::challenge_one::decode_hex;

pub fn fixed_xor(key: &[u8], input: &[u8]) -> Result<String> {
    ensure!(key.len() == input.len(), "key != input len");
    let key = decode_hex(key)?;
    let input = decode_hex(input)?;

    let xored_bytes = key
        .into_iter()
        .zip(input.iter())
        .map(|(x, y)| x ^ y)
        .collect::<Vec<u8>>();
    
    Ok(encode_hex(&xored_bytes))
}

pub fn encode_hex(input: &[u8]) -> String {
    input.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:X}");
        out
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example() {
        let r = fixed_xor(
            b"1c0111001f010100061a024b53535009181c",
            b"686974207468652062756c6c277320657965"
        ).expect("couldn't xor");

        assert_eq!(r.to_ascii_lowercase(), "746865206b696420646f6e277420706c6179")
    }

    #[test]
    fn different_lengths() {
        assert!(fixed_xor(b"ABC", b"AB").is_err())
    }
}
