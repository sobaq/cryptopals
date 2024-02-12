use std::iter;

/// Pads `input` to a multiple of `block_size`
pub fn pad_pkcs7(input: &[u8], block_size: usize) -> Vec<u8> {
    let mut t = input.to_vec();
    let req = block_size - input.len() % block_size;
    t.extend(iter::repeat(req as u8).take(req));
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
    fn block_sized_input() {
        let inp = b"0123456789ABCDEF";
        let out = b"0123456789ABCDEF\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10";

        assert_eq!(pad_pkcs7(inp, inp.len()), out);
    }

    #[test]
    fn ten_chars() {
        let r = pad_pkcs7(b"1234567890", 20);

        assert_eq!(r, b"1234567890\x0A\x0A\x0A\x0A\x0A\x0A\x0A\x0A\x0A\x0A");
    }
}
