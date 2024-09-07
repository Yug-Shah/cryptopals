mod utils;
use crate::utils::*;
use std::fs::File;
use std::io::{BufRead, BufReader};

pub fn challenge_1() {
    let input_hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let expected_b64 = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

    let bytes = hex_to_bytes(input_hex);
    let plaintext = bytes_to_plaintext(&bytes);

    let result_b64 = bytes_to_b64(&hex_to_bytes(input_hex));
    assert_eq!(result_b64, expected_b64);

    // convert b64 back to hex
    let result_hex = bytes_to_hex(&b64_to_bytes(&result_b64));
    assert_eq!(result_hex, input_hex);

    println!("Challenge 1 completed");
    println!(" Hex = {}\n Plaintext = {:#?}\n b64 = {}\n", input_hex, plaintext, result_b64);
}

pub fn challenge_2() {
    let input_hex_1 = "1c0111001f010100061a024b53535009181c";
    let input_hex_2 = "686974207468652062756c6c277320657965";
    let expected_hex_3 = "746865206b696420646f6e277420706c6179";

    let bytes_1 = hex_to_bytes(input_hex_1);
    let plaintext_1 = bytes_to_plaintext(&bytes_1);

    let bytes_2 = hex_to_bytes(input_hex_2);
    let plaintext_2 = bytes_to_plaintext(&bytes_2);

    let bytes_3 = fixed_xor(&bytes_1, &bytes_2);
    let plaintext_3 = bytes_to_plaintext(&bytes_3);
    let result_hex_3 = bytes_to_hex(&bytes_3);
    assert_eq!(result_hex_3, expected_hex_3);

    println!("Challenge 2 completed");
    println!(" Hex1 = {}\t Raw = {:#?}\n Hex2 = {}\t Raw = {}\n XOR = {}\t Raw = {}\n", input_hex_1, plaintext_1, input_hex_2, plaintext_2, result_hex_3, plaintext_3);
    
}

pub fn challenge_3() {
    let input_hex = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let expected_key = b'X';

    let bytes = hex_to_bytes(input_hex);
    let plaintext = bytes_to_plaintext(&bytes);

    let candidate = break_single_char_xor(&bytes);
    assert_eq!(candidate.1, expected_key);

    println!("Challenge 3 completed");
    println!(" Hex = {}\t Raw = {:#?}\n Key = {}\t Plaintext = {}\n", input_hex, plaintext, candidate.1 as char, candidate.2);
}

pub fn challenge_4() {
    let path = "set1/src/data/challenge4.txt";
    let expected_key = b'5';
    let file_reader = BufReader::new(File::open(path).expect("Error in opening the file"));

    //(score, key, plaintext, hex)
    let mut best_candidate = (0_f64, 0_u8, "".to_owned(), "".to_owned());
    
    for line in file_reader.lines().flatten() {
        let candidate = break_single_char_xor(&hex_to_bytes(&line));
        if candidate.0 > best_candidate.0 {
            best_candidate.0 = candidate.0;
            best_candidate.1 = candidate.1;
            best_candidate.2 = candidate.2;
            best_candidate.3 = line;
        }
    }

    let hex = best_candidate.3.as_str();
    let bytes = hex_to_bytes(hex);
    let plaintext = bytes_to_plaintext(&bytes);
    assert_eq!(best_candidate.1, expected_key);

    println!("Challenge 4 completed");
    println!(" Hex = {}\t Raw = {:#?}\n Key = {}\t Plaintext = {:#?}\n", hex, plaintext, best_candidate.1 as char, best_candidate.2);
}

pub fn challenge_5() {
    let plaintext = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
    let key = "ICE";
    let expected_ciphertext = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";

    let plaintext_bytes = plaintext.to_string().into_bytes();
    let repeated_key = repeat_key(plaintext.len(), key);

    let ciphertext_bytes = fixed_xor(&repeated_key, &plaintext_bytes);
    let ciphertext = bytes_to_hex(&ciphertext_bytes);
    assert_eq!(ciphertext, expected_ciphertext);

    println!("Challenge 5 completed");
    println!(" Plaintext = {:#?}\n Key = {}\n Ciphertext = {:#?}\n", plaintext, key, ciphertext);
}

pub fn challenge_6() {
    let path = "set1/src/data/challenge6.txt";
    let expected_key = "Terminator X: Bring the noise";
    let ciphertext_bytes = b64_to_bytes(&open_file_to_string(path));


    let keysize = guess_keysize(&ciphertext_bytes);
    let (key_bytes, _plaintext) = break_repeating_key_xor(keysize, ciphertext_bytes);

    let key = bytes_to_plaintext(&key_bytes);
    assert_eq!(key, expected_key);

    println!("Challenge 6 completed");
    println!(" Key = {}\n", key);
    // println!(" Plaintext = \n{}", plaintext);
}

pub fn challenge_7() {
    let path = "set1/src/data/challenge7.txt";
    let ciphertext_bytes = b64_to_bytes(&open_file_to_string(path));
    // The start of the plaintext is the following line.
    let expected_plaintext = "I'm back and I'm ringin' the bell ";

    let key = "YELLOW SUBMARINE";
    let key_bytes = key.as_bytes();

    let plaintext_bytes = decrypt_aes_ecb_128(key_bytes, &ciphertext_bytes).unwrap();
    let plaintext = bytes_to_plaintext(&plaintext_bytes);
    assert!(plaintext.contains(expected_plaintext));

    println!("Challenge 7 completed\n");
    // Plaintext is long, uncomment below to print
    // println!(" Plaintext = \n{}", plaintext);
}

pub fn challenge_8() {
    let path = "set1/src/data/challenge8.txt";
    let file_reader = BufReader::new(File::open(path).expect("Error in opening the file"));
    let expected_ciphertext = "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a";

    for (i, line) in file_reader.lines().enumerate() {
        let ciphertext_bytes = hex_to_bytes(&line.unwrap().trim());
        let repeated_blocks = detect_aes_ecb(&ciphertext_bytes);

        if repeated_blocks > 0 {
            assert_eq!(i, 132);
            assert_eq!(bytes_to_hex(&ciphertext_bytes), expected_ciphertext);
            println!("Challenge 8 completed");
            println!(" Line {} contains repeated blocks and is possibly encrypted using AES in ECB mode", i + 1);
            println!(" Ciphertext = {}", bytes_to_hex(&ciphertext_bytes));
        }
    }
}

fn main(){
    println!("Set 1\n");

    challenge_1();
    challenge_2();
    challenge_3();
    challenge_4();
    challenge_5();
    challenge_6();
    challenge_7();
    challenge_8();
}