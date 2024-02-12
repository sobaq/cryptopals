use itertools::Itertools;

pub fn is_aes_cbc(ciphertext: &[u8]) -> bool {
    let chunked = ciphertext.chunks(16);

    chunked.len() != chunked.unique().collect::<Vec<_>>().len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::set_one::challenge_one::decode_hex;

    #[test]
    fn example() {
        let raw = include_str!("../../vendor/challenge-eight.txt")
            .split('\n');

        assert!(
            raw
                .flat_map(|x| decode_hex(&x.bytes().collect::<Vec<u8>>()))
                .map(|x| is_aes_cbc(&x))
                .any(|x| x),
            "couldn't detect an aes message");
    }
}
