use eyre::{eyre, Result};
use aes::cipher::{BlockDecryptMut, block_padding::Pkcs7, KeyInit};

type Aes128EcbDec = ecb::Decryptor<aes::Aes128>;

pub fn aes_ecb_dec(input: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    // The challenge says:
    //  Easiest way: use OpenSSL::Cipher and give it AES-128-ECB as the cipher. 
    // Which I guess means "don't write this yourself"
    // So rustcrypto it is.
    let out = Aes128EcbDec::new(key.into())
        .decrypt_padded_vec_mut::<Pkcs7>(input)
        .map_err(|e| eyre!(e))?;

    Ok(out)
}

#[cfg(test)]
mod tests {
    use crate::set_one::challenge_six::base64_decode;

    use super::*;

    #[test]
    fn example() {
        let key = b"YELLOW SUBMARINE";
        let inp = include_str!("../../vendor/challenge-seven.txt")
            .replace('\n', "");
        let decoded = base64_decode(&inp);

        let out = aes_ecb_dec(&decoded, key)
            .expect("couldn't decrypt example aes message");
        let out = String::from_utf8_lossy(&out);

        // Lazy solution
        assert!(out.contains("I'm back and I'm ringin' the bell"));
        assert!(out.contains("I'm an effect and that you can bet"));
        assert!(out.contains("Play that funky music, white boy Come on"));
    }
}
