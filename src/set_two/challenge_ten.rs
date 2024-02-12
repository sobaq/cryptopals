use aes::cipher::{generic_array::GenericArray, BlockDecrypt, KeyInit};
use eyre::Result;

pub fn decode_aes_cbc(
    ciphertext: &[u8],
    key: &[u8]
) -> Result<Vec<u8>>
{
    let aes = aes::Aes128Dec::new(key.into());
    let ciphertext_blocks = ciphertext.chunks(16).map(|x| x.to_vec()).collect::<Vec<Vec<u8>>>();
    
    let mut result = (1..ciphertext_blocks.len())
        .flat_map(|block_num| {
            let prev = &ciphertext_blocks[block_num - 1];
            let curr = &ciphertext_blocks[block_num];
    
            // Decrypt in place
            let mut dec = GenericArray::clone_from_slice(curr);
            aes.decrypt_block(&mut dec);

            dec
                .iter()
                .zip(prev.iter())
                .map(|(x, y)| x ^ y)
                .collect::<Vec<u8>>()
        })
        .skip(1)
        .collect::<Vec<u8>>();
    let bytes = result.len();
    
    // Potentially trim padding
    let padding_count = *result.last().expect("result vec is empty") as usize;
    if padding_count < 16
    && result[bytes - padding_count..]
        .iter()
        .all(|x| (*x as usize) == padding_count)
    {
        result.truncate(bytes - padding_count);
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::set_one::challenge_six::base64_decode;

    const ENC_INPUT: &str = include_str!("../../vendor/challenge-ten.txt");
    const ENC_OUTPUT: &str = include_str!("../../vendor/challenge-ten-dec.txt");

    #[test]
    fn example() {
        let inp = ENC_INPUT.replace('\n', "");
        let input = base64_decode(&inp);

        let out = decode_aes_cbc(&input, b"YELLOW SUBMARINE")
            .expect("couldn't decode message");
        let out = String::from_utf8_lossy(&out);
        
        assert!(out == ENC_OUTPUT);
    }
}
