use eyre::{eyre, ensure, Result};
use itertools::*;

const BASE64_CHARS: [char; 64] = [
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q',
    'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
    'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y',
    'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/',
];

// This is a piece of work
pub fn hex_to_base64(input: &str) -> Result<String> {
    ensure!(input.len() % 2 == 0, "input not a multiple of 2");

    let input_bytes = input.bytes().collect::<Vec<u8>>();
    let raw_bytes = decode_hex(&input_bytes)?.into_iter().chunks(3);
    let raw_bytes = raw_bytes.into_iter();

    let mut base64 = raw_bytes
        .map(|mut chunk| {
            let one = chunk.next().unwrap_or(0);
            let two = chunk.next().unwrap_or(0);
            let three = chunk.next().unwrap_or(0);
            let n = ((one as usize) << 16) + ((two as usize) << 8) + three as usize;

            Ok([
                BASE64_CHARS[(n >> 18) & 63],
                BASE64_CHARS[(n >> 12) & 63],
                BASE64_CHARS[(n >>  6) & 63],
                BASE64_CHARS[n         & 63],
            ])
        })
        
        // flatten iter of arrays of chars into a string
        .try_fold(String::new(), |mut acc, result: Result<_, eyre::Error>| {
            acc.extend(result?);
            Ok::<String, eyre::Error>(acc)
        })?;
    
    base64.truncate((((input.len() / 2) * 4) + 2) / 3);
    Ok(base64)
}

pub fn decode_hex(input: &[u8]) -> Result<Vec<u8>> {
    input
        .iter()
        .array_chunks::<2>()
        .map(|[hi, lo]|
            Ok::<_, eyre::Error>((dec_nibble(*hi)? << 4) | dec_nibble(*lo)?)
        )
        .collect()
}

fn dec_nibble(n: u8) -> Result<u8> {
    Ok(match (n as char).to_ascii_uppercase() {
        '0' => 0, '1' => 1, '2' => 2,  '3' => 3,  '4' => 4,  '5' => 5,  '6' => 6, '7' => 7,
        '8' => 8, '9' => 9, 'A' => 10, 'B' => 11, 'C' => 12, 'D' => 13, 'E' => 14,
        'F' => 15, _ => return Err(eyre!("hex nibble out of range")),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn example_case() {
        let i = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let o = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
        
        assert_eq!(hex_to_base64(i).expect("couldn't decode"), o);
    }

    #[test]
    fn padding() {
        assert_eq!(hex_to_base64("0169").expect("couldn't decode"), "AWk");
    }

    #[test]
    fn invalid() {
        assert!(hex_to_base64("ABABABGA").is_err())
    }
}
