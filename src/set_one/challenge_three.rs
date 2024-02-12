use eyre::Result;

const LETTER_FREQUENCIES: [(char, f64); 26] = [
    ('a', 0.082),  ('b', 0.015),   ('c', 0.028), ('d', 0.043),  ('e', 0.127),
    ('f', 0.022),  ('g', 0.020),   ('h', 0.061), ('i', 0.070),  ('j', 0.0015),
    ('k', 0.0077), ('l', 0.040),   ('m', 0.024), ('n', 0.067),  ('o', 0.075),
    ('p', 0.019),  ('q', 0.00095), ('r', 0.060), ('s', 0.063),  ('t', 0.091),
    ('u', 0.028),  ('v', 0.0098),  ('w', 0.024), ('x', 0.0015), ('y', 0.020),
    ('z', 0.00074),
];

// returns the top 5 closest matches by chi2 test
pub fn brute_force_single_byte_xor(input: &[u8]) -> Result<Vec<(String, u8, f64)>> {
    let mut out = Vec::new();
    for i in 0..255 {
        let decoded = input
            .iter()
            .map(|x| (x ^ i) as char)
            .collect::<Vec<char>>();

        if !decoded.is_empty() {
            let s = chi2(&decoded);
            out.push((decoded, i, s));
        }
    }

    out.sort_by(|(_, _, x), (_, _, y)| x.partial_cmp(y).unwrap());
    Ok(out
        .into_iter()
        .take(5)
        .map(|(bytes, i, score)| (bytes.into_iter().collect(), i, score))
        .collect())
}

/// Naive https://en.wikipedia.org/wiki/Chi-squared_test implementation
pub fn chi2(input: &[char]) -> f64 {
    let len = input.len() as f64;

    let mut sum = 0.;
    for (letter, freq) in LETTER_FREQUENCIES {
        let expected_freq = freq * len;
        let actual_freq = input.iter().filter(|c| **c == letter).count() as f64;
        let diff = actual_freq - expected_freq;

        sum += (diff.powf(2.)) / len;
    }

    sum
}

#[cfg(test)]
mod tests {
    use crate::set_one::challenge_one::decode_hex;

    use super::*;

    #[test]
    fn example() {
        let dec = decode_hex(
            b"1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
            .expect("couldn't decode hex input");
        let res = brute_force_single_byte_xor(&dec).unwrap();
        let expected = String::from("Cooking MC's like a pound of bacon");

        assert!(res.into_iter().any(|(s, _, _)| s == expected));
    }
}
