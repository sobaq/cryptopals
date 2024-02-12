use itertools::Itertools;

use crate::set_one::challenge_three::brute_force_single_byte_xor;

use super::challenge_one::decode_hex;

/// Returns the top 5 plaintext contenders from all inputs
/// using decode_single_byte_xor from challenge three
pub fn detect_single_byte_xor(inputs: &[&[u8]]) -> Vec<(String, u8, f64)> {
    inputs
        .iter()
        .flat_map(|inp| brute_force_single_byte_xor(&decode_hex(inp).unwrap()))
        .flatten()
        .sorted_by(|(_, _, x), (_, _, y)| x.partial_cmp(y).unwrap())
        .take(5)
        .collect::<Vec<(String, u8, f64)>>()
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE_INPUT: &str = include_str!("../../vendor/challenge-four.txt");

    #[test]
    fn example() {
        let inp = EXAMPLE_INPUT
            .split('\n')
            .map(|x| x.bytes().collect())
            .collect::<Vec<Vec<u8>>>();
        let inp = inp.iter().map(|x| &x[0..x.len()]).collect::<Vec<&[u8]>>();

        let expected = "Now that the party is jumping\n";
        let out = detect_single_byte_xor(&inp);

        assert!(out.iter().any(|(x, _, _)| x == expected));
    }
}
