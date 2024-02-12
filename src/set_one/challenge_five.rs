/// Encrypts 'input' with repeating XOR key 'key'.
pub fn repeating_key_xor_encrypt(input: &str, key: &str) -> Vec<u8> {
    input
        .bytes()
        .zip(key.bytes().cycle())
        .map(|(x, y)| x ^ y)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::set_one::challenge_one::decode_hex;

    #[test]
    fn example() {
        let input = "\
Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal";

        let expected_output = decode_hex(b"\
0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272\
a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f\
").expect("couldn't decode expected output str");

        assert_eq!(repeating_key_xor_encrypt(input, "ICE"), expected_output);
    }
}
