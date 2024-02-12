use std::iter;

/// Pads `input` to a multiple of `block_size`
pub fn pad_pkcs7(input: &[u8], block_size: usize) -> Vec<u8> {
    let mut t = input.to_vec();
    t.extend(iter::repeat(4).take(block_size % input.len()));
    t
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example() {
        let r = pad_pkcs7(b"YELLOW SUBMARINE", 20);

        assert_eq!(&r, b"YELLOW SUBMARINE\x04\x04\x04\x04");
    }

    #[test]
    fn no_padding_if_unneeded() {
        let inp = b"this is a test string";

        assert!(pad_pkcs7(inp, inp.len()).len() == inp.len());
    }
}
