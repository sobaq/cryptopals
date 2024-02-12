use aes::cipher::{generic_array::GenericArray, KeyInit};
use rand::Rng;

// Generate a random AES secret key (16 random bytes)
pub fn random_aes_key() -> Vec<u8> {
    rand::random::<[u8; 16]>().to_vec()
}

// pub fn encrypt_random_data(data: &[u8]) -> Vec<u8> {
//     let key = GenericArray::clone_from_slice(&random_aes_key());
//     let aes = aes::Aes128Dec::new(&key);

//     let mut final_plaintext = Vec::new();

//     let oracle_size = rand::thread_rng().gen_range(5..=10);
//     let mut oracle = Vec::<u8>::new();
//     rand::thread_rng().fill(&mut oracle[0..oracle_size]);

//     if rand::random() {
//         aes_cbc_dec()
//     } else {

//     }

//     todo!()
// }
