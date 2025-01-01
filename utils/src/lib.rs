use std::{collections::HashSet, fs};
use base64::{engine::general_purpose, Engine};
use openssl::{error::ErrorStack, symm::{Cipher, Crypter, Mode}};
use rand::{distributions::Standard, thread_rng, Rng};

// Always operate on raw bytes, never on encoded strings. Only use hex and base64 for pretty-printing.

const LETTER_FREQ: [f64; 27] = [
    0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015, // A-G
    0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749, // H-N
    0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758, // O-U
    0.00978, 0.02360, 0.00150, 0.01974, 0.00074, 0.19181, // V-Z & space char
];

pub const BLOCK_SIZE: usize = 16;

pub fn hex_to_bytes(hex: &str) -> Vec<u8>{
    hex::decode(hex).unwrap()
}

pub fn bytes_to_hex(bytes: &[u8]) -> String{
    hex::encode(bytes)
}

pub fn bytes_to_b64(bytes: &[u8]) -> String{
    general_purpose::STANDARD.encode(bytes)
}

pub fn b64_to_bytes(b64: &str) -> Vec<u8>{
    general_purpose::STANDARD.decode(b64).unwrap()
}

pub fn bytes_to_plaintext(bytes: &Vec<u8>) -> String {
    String::from_utf8(bytes.to_vec()).unwrap()
}

pub fn open_file_to_string(path: &str) -> String {
    fs::read_to_string(path).unwrap().split('\n').collect::<Vec<_>>().join("")
}

pub fn fixed_xor(bytes_1: &Vec<u8>, bytes_2: &Vec<u8>) -> Vec<u8> {
    if bytes_1.len() != bytes_2.len() {
        panic!("Lengths are not equal");
    }

    bytes_1
        .iter()
        .zip(bytes_2.iter())
        .map(|(&b1, &b2)| b1 ^ b2)
        .collect::<Vec<u8>>()
}

pub fn count_freq_score(plaintext: &str) -> f64 {
    // better score => closer to english
    let mut counts = vec![0_u32; 27];
    let mut score = 0_f64;

    plaintext.chars().for_each(|c| match c {
        'a'..='z' => {
            counts[c as usize - 'a' as usize] += 1;
        }
        'A'..='Z' => {
            counts[c as usize - 'A' as usize] += 1;
        }
        ' ' => counts[26] += 1,
        _ => {}
    });

    for i in 0..27 {
        score += (counts[i] as f64) * LETTER_FREQ[i];
    }
    score
}

pub fn break_single_char_xor(bytes: &Vec<u8>) -> (f64, u8, String) {
    //(score, key, plaintext)
    let mut best_candidate: (f64, u8, String) = (0_f64, 0_u8, "".to_owned());

    for temp_key in 0..=255 {
        let plaintext_bytes: Vec<u8> = bytes.iter().map(|&b| b ^ temp_key).collect();
        let plaintext = String::from_utf8_lossy(&plaintext_bytes);
        let temp_score = count_freq_score(&plaintext);

        if temp_score > best_candidate.0 {
            best_candidate.0 = temp_score;
            best_candidate.1 = temp_key;
            best_candidate.2 = plaintext.to_string();
        }
    }
    best_candidate
}

pub fn repeat_key(size: usize, key: &str) -> Vec<u8> {    
    key.chars()
        .cycle()
        .take(size)
        .collect::<String>()
        .into_bytes()
}

pub fn edit_distance(bytes_1: &Vec<u8>, bytes_2: &Vec<u8>) -> u32 {
    if bytes_1.len() != bytes_2.len() {
        panic!("Lengths are not equal");
    }

    fixed_xor(bytes_1, bytes_2)
        .iter()
        .map(|b| b.count_ones())
        .sum()
}

pub fn guess_keysize(data: &[u8]) -> usize {
    //returns the keysize with the smallest normalized distance
    let mut distances = Vec::new();
    
    for keysize in 2..=40 {
        let blocks: Vec<&[u8]> = data.chunks(keysize).take(4).collect();
        let mut total_distance = 0;
        let mut pairs = 0;
        for i in 0..blocks.len() {
            for j in i+1..blocks.len() {
                total_distance += edit_distance(&blocks[i].to_vec(), &blocks[j].to_vec());
                pairs +=1;
            }
        }
        let normalized_distance = total_distance as f64 / (pairs * keysize) as f64;
        distances.push((keysize, normalized_distance));
    }
    distances.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());
    distances[0].0
}

pub fn transpose_blocks(blocks: Vec<&[u8]>) -> Vec<Vec<u8>> {
    let mut transposed: Vec<Vec<u8>> = vec![Vec::new(); blocks[0].len()];

    for block in blocks {
        for (i, &byte) in block.iter().enumerate() {
            transposed[i].push(byte);
        }
    }
    transposed
}

pub fn break_repeating_key_xor(keysize: usize, ciphertext_bytes: Vec<u8>) -> (Vec<u8>, String){

    let cipher_blocks: Vec<&[u8]> = ciphertext_bytes.chunks(keysize).collect();
    let transposed_blocks = transpose_blocks(cipher_blocks);
    let mut key_bytes = Vec::new();

    for block in transposed_blocks {
        let (_score, key_byte, _plaintext) = break_single_char_xor(&block);
        key_bytes.push(key_byte);
    }

    let repeated_key = repeat_key(ciphertext_bytes.len(), &bytes_to_plaintext(&key_bytes).as_str());
    let plaintext = bytes_to_plaintext(&fixed_xor(&ciphertext_bytes, &repeated_key));

    (key_bytes, plaintext)
}

pub fn cipher(t: Cipher, mode: Mode, key: &[u8], iv: Option<&[u8]>, data: &[u8], pad: bool) -> Result<Vec<u8>, ErrorStack> {
    let mut crypter = Crypter::new(t, mode, key, iv).unwrap();
    crypter.pad(pad); // Disable padding explicitly

    let mut ciphertext = vec![0; data.len() + t.block_size()];
    let count = crypter.update(data, &mut ciphertext).unwrap();
    let rest = crypter.finalize(&mut ciphertext[count..]).unwrap();

    ciphertext.truncate(count + rest); // Truncate to the actual ciphertext size
    
    Ok(ciphertext)
}

pub fn aes_ecb_128_decrypt(key_bytes: &[u8], ciphertext_bytes: &[u8]) -> Vec<u8> {
    cipher(Cipher::aes_128_ecb(), Mode::Decrypt, key_bytes, None, &ciphertext_bytes, false).unwrap()
}

pub fn aes_ecb_128_encrypt(key_bytes: &[u8], plaintext_bytes: &[u8]) -> Vec<u8> {
    cipher(Cipher::aes_128_ecb(), Mode::Encrypt, key_bytes, None, &plaintext_bytes, false).unwrap()
}

pub fn detect_aes_ecb(ciphertext_bytes: &[u8]) -> usize {
    let blocks = ciphertext_bytes.chunks(BLOCK_SIZE);
    let unique_blocks: HashSet<&[u8]> = HashSet::from_iter(blocks.clone());
    blocks.len() - unique_blocks.len()
}

pub fn pkcs7_padding(block_size: usize, plaintext_bytes: &[u8]) -> Vec<u8> {
    if block_size == 0 {
        panic!("Block size cannot be zero");
    }
    let padding_size = block_size - (plaintext_bytes.len() % block_size);
    let pad = vec![padding_size as u8; padding_size];
    [plaintext_bytes, &pad].concat()
}

pub fn remove_pkcs7_padding(plaintext_bytes: &[u8]) -> Vec<u8> {
    if plaintext_bytes.is_empty() {
        panic!("Cannot remove padding from an empty plaintext.");
    }
    let padding_size = *plaintext_bytes.last().unwrap() as usize;
    if padding_size == 0 || padding_size > plaintext_bytes.len() {
        panic!("Invalid PKCS#7 padding size.");
    }
    for &byte in &plaintext_bytes[plaintext_bytes.len() - padding_size..] {
        if byte as usize != padding_size {
            panic!("Invalid PKCS#7 padding.");
        }
    }

    plaintext_bytes[..plaintext_bytes.len() - padding_size].to_vec()
}

pub fn aes_cbc_128_encrypt(key_bytes: &[u8], iv: &[u8], plaintext_bytes: &[u8]) -> Vec<u8> {
    let padded = pkcs7_padding(BLOCK_SIZE, plaintext_bytes);
    let mut padded_blocks = Vec::new();
    for chunk in padded.chunks(BLOCK_SIZE){
        padded_blocks.push(chunk.to_vec());
    }

    let mut ciphertext: Vec<u8> = Vec::with_capacity(padded.len());
    let mut next_iv = iv.to_vec();

    for block in padded_blocks {
        let ciphertext_block = aes_ecb_128_encrypt(key_bytes, &fixed_xor(&next_iv, &block));
        next_iv = ciphertext_block.clone();
        ciphertext.extend_from_slice(&ciphertext_block);
    }

    ciphertext
}

pub fn aes_cbc_128_decrypt(key_bytes: &[u8], iv: &[u8], ciphertext_bytes: &[u8]) -> Vec<u8> {
    let mut ciphertext_blocks = Vec::new();
    for chunk in ciphertext_bytes.chunks(BLOCK_SIZE){
        ciphertext_blocks.push(chunk.to_vec());
    }

    let mut plaintext: Vec<u8> = Vec::new();
    let mut next_iv = iv.to_vec();

    for block in ciphertext_blocks {
        let mut plaintext_block = aes_ecb_128_decrypt(key_bytes, &block.to_vec());
        plaintext_block = fixed_xor(&next_iv, &plaintext_block);
        next_iv = block;
        plaintext.extend_from_slice(&plaintext_block);
    }

    remove_pkcs7_padding(&plaintext)
}

pub fn generate_random_bytes(size: usize)-> Vec<u8>{
    thread_rng().sample_iter(Standard).take(size).collect()
}

pub fn aes_encryption_oracle(plaintext_bytes: &[u8]) -> (Vec<u8>, String) {
    let mut rng = thread_rng();
    let key_bytes = generate_random_bytes(BLOCK_SIZE);
    let prepend = generate_random_bytes(rng.gen_range(5..=10));
    let append = generate_random_bytes(rng.gen_range(5..=10));

    let modified_plaintext_bytes = [prepend, plaintext_bytes.to_vec(), append].concat();

    let padded_plaintext_bytes = pkcs7_padding(BLOCK_SIZE, &modified_plaintext_bytes);

    if rng.gen_bool(0.5){
        (aes_ecb_128_encrypt(&key_bytes, &padded_plaintext_bytes), "ECB".to_string())
    } else  {
        let iv = generate_random_bytes(BLOCK_SIZE);
        (aes_cbc_128_encrypt(&key_bytes, &iv, &padded_plaintext_bytes), "CBC".to_string())
    }
}

pub fn detect_aes_mode(ciphertext_bytes: &[u8]) -> String {
    let repeated_blocks = detect_aes_ecb(&ciphertext_bytes);
    if repeated_blocks > 0 {
        "ECB".to_string()
    } else {
        "CBC".to_string()
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_edit_distance(){
        let test_s1 = "this is a test";
        let test_s2 = "wokka wokka!!!";
        let result = edit_distance(&test_s1.as_bytes().to_vec(), &test_s2.as_bytes().to_vec());
        // println!(" Test String 1 = {:#?}\n Test String 2 = {}\n Expected Hamming Distance = 37\n Actual Hamming Distance = {:#?}\n", test_s1, test_s2, result);
        assert_eq!(37, result);
    }

    #[test]
    fn test_detect_aes_ecb(){
        let ciphertext = "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a";
        let expected_blocks = 3;
        let repeated_blocks = detect_aes_ecb(&hex_to_bytes(&ciphertext));
        assert_eq!(repeated_blocks, expected_blocks);
    }

    #[test]
    fn test_pkcs7_padding() {
        let test_size_1 = 16;
        let test_size_2 =32;
        let test_1 = "YELLOW SUB";
        let test_2 = "YELLOW SUBMARINE";

        //Padding
        let expected_output_1 = "YELLOW SUB\x06\x06\x06\x06\x06\x06";
        let expected_output_2 = "YELLOW SUBMARINE\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10";
        assert_eq!(expected_output_1, bytes_to_plaintext(&pkcs7_padding(test_size_1, test_1.as_bytes())));
        assert_eq!(expected_output_2, bytes_to_plaintext(&pkcs7_padding(test_size_2, test_2.as_bytes())));
        
        //Remove Padding
        let expected_output_3 = "YELLOW SUB";
        let expected_output_4 = "YELLOW SUBMARINE";
        assert_eq!(expected_output_3, bytes_to_plaintext(&remove_pkcs7_padding(expected_output_1.as_bytes())));
        assert_eq!(expected_output_4, bytes_to_plaintext(&remove_pkcs7_padding(expected_output_2.as_bytes())));
    }

    #[test]
    fn test_aes_ecb_mode() {
        let input_plaintext = "YELLOW SUBMARINE";
        let key = "YELLOW SUBMARINE";

        let output_ciphertext = aes_ecb_128_encrypt(key.as_bytes(), input_plaintext.as_bytes());
        let output_plaintext = aes_ecb_128_decrypt(key.as_bytes(), &output_ciphertext);

        assert_eq!(input_plaintext, bytes_to_plaintext(&output_plaintext));
    }
    
    #[test]
    fn test_aes_cbc_mode() {
        let input_plaintext = "This is the test string";
        let key = "YELLOW SUBMARINE";
        let iv = vec![0_u8; BLOCK_SIZE];

        let output_ciphertext = aes_cbc_128_encrypt(key.as_bytes(), &iv,input_plaintext.as_bytes());
        let output_plaintext = aes_cbc_128_decrypt(key.as_bytes(), &iv, &output_ciphertext);

        let result_plaintext = bytes_to_plaintext(&output_plaintext);

        assert_eq!(input_plaintext, result_plaintext);
    }


    #[test]
    fn test_detect_aes_mode(){
        let plaintext_bytes = b"000000000000000000000000000000000000000000000000";
        let (ciphertext_bytes, actual_mode) = aes_encryption_oracle(plaintext_bytes);
        let detected_mode = detect_aes_mode(&ciphertext_bytes);

        println!(" Actual Mode = {}\n Detected Mode = {}\n", actual_mode, detected_mode);

        assert_eq!(actual_mode, detected_mode);
    }
}