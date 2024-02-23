use base64::prelude::*;
use hex;
use std::fs::File;
use std::io::{BufRead, BufReader};

const LETTER_FREQ: [f64; 27] = [
    0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015, // A-G
    0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749, // H-N
    0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758, // O-U
    0.00978, 0.02360, 0.00150, 0.01974, 0.00074, 0.19181, // V-Z & space char
];

fn count_freq_score(plaintext: &str) -> f64 {
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

pub fn get_raw_data(hex: &str) -> String {
    std::str::from_utf8(&(hex::decode(hex).unwrap()))
        .expect("Error in input")
        .to_string()
}

pub fn hex_to_base64(hex: &str) -> String {
    BASE64_STANDARD.encode(hex::decode(hex).unwrap())
}

pub fn fixed_xor(hex1: &str, hex2: &str) -> String {
    let byte1 = hex::decode(hex1).unwrap();
    let byte2 = hex::decode(hex2).unwrap();
    hex::encode(
        byte1
            .iter()
            .zip(byte2.iter())
            .map(|(&b1, &b2)| b1 ^ b2)
            .collect::<Vec<u8>>(),
    )
}

pub fn crack_single_xor(hex1: &str) -> (String, u8) {
    let secret_bytes = hex::decode(hex1).unwrap();
    let mut key: u8 = 0;
    let mut result: String = String::new();
    let mut best_score = 0_f64;

    for k in 0..=255 {
        let plaintext_bytes: Vec<u8> = secret_bytes.iter().map(|&b| b ^ k).collect();
        let plaintext = String::from_utf8_lossy(&plaintext_bytes);
        let score = count_freq_score(&plaintext);

        if score > best_score {
            best_score = score;
            result = plaintext.to_string();
            key = k;
        }
    }
    (result, key)
}

pub fn detect_single_xor(path: &str) -> (String, String, u8) {
    let file = File::open(path).expect("Error in opening the file");
    let buffered = BufReader::new(file).lines();
    let mut best_score = 0_f64;
    let mut result: String = String::new();
    let mut key: u8 = 0;
    let mut hex: String = String::new();

    for line in buffered.flatten() {
        let (temp, k) = crack_single_xor(line.as_str());
        let score = count_freq_score(&temp);
        if score > best_score {
            best_score = score;
            result = temp;
            result.pop();
            key = k;
            hex = line;
        }
    }
    (hex, result, key)
}

pub fn repeating_key_xor(plaintext: &str, key: &str) -> String {
    // let cipher_text: String = String::new();
    let key_string = key
        .chars()
        .cycle()
        .take(plaintext.len())
        .collect::<String>();
    let key_bytes = key_string.into_bytes();
    let plaintext_bytes = plaintext.to_string().into_bytes();

    hex::encode(
        plaintext_bytes
            .iter()
            .zip(key_bytes.iter())
            .map(|(&b1, &b2)| b1 ^ b2)
            .collect::<Vec<u8>>(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_raw_data() {
        let hex = "54686973207465737420636f6d706c65746564207375636365737366756c6c792e";
        let result = get_raw_data(hex);
        assert_eq!(result, "This test completed successfully.");
    }

    #[test]
    fn test_count_freq_score() {
        let text1 = "abcdefghijklmnopqrstuvwxyz ";
        let text2 = "The quick brown fox jumps over the lazy dog";
        let text3 = "";
        assert_eq!(count_freq_score(text1), 1.1917999999999997);
        assert_eq!(count_freq_score(text2), 3.2526699999999997);
        assert_eq!(count_freq_score(text3), 0_f64);
    }

    #[test]
    fn test_challenge_1() {
        let hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let raw_data = get_raw_data(hex);
        let result = hex_to_base64(hex);
        assert_eq!(
            result,
            "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
        );
        assert_eq!(raw_data, "I'm killing your brain like a poisonous mushroom");
    }

    #[test]
    fn test_challenge_2() {
        let hex1 = "1c0111001f010100061a024b53535009181c";
        let hex2 = "686974207468652062756c6c277320657965";
        let result = fixed_xor(hex1, hex2);
        let raw_data_1 = get_raw_data(hex1);
        let raw_data_2 = get_raw_data(hex2);
        let raw_data_3 = get_raw_data(&result);
        assert_eq!(result, "746865206b696420646f6e277420706c6179");
        assert_eq!(
            raw_data_1,
            "\u{1c}\u{1}\u{11}\0\u{1f}\u{1}\u{1}\0\u{6}\u{1a}\u{2}KSSP\t\u{18}\u{1c}"
        );
        assert_eq!(raw_data_2, "hit the bull's eye");
        assert_eq!(raw_data_3, "the kid don't play");
    }

    #[test]
    fn test_challenge_3() {
        let hex = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
        let (result, key) = crack_single_xor(hex);
        assert_eq!(result, "Cooking MC's like a pound of bacon");
        assert_eq!(key, b'X');
    }

    #[test]
    fn test_challenge_4() {
        let file_path = "./data/challenge4.txt";
        let (hex, result, key) = detect_single_xor(file_path);
        assert_eq!(
            hex,
            "7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f"
        );
        assert_eq!(key, b'5');
        assert_eq!(result, "Now that the party is jumping");
    }

    #[test]
    fn test_challenge_5() {
        let plaintext: &str =
            "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
        let key: &str = "ICE";
        let result = repeating_key_xor(plaintext, key);
        assert_eq!(result.as_str(), "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f");
    }
}
