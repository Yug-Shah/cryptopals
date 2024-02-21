use base64::prelude::*;
use hex;


pub fn hex_to_base64(hex: &str) -> String {
    BASE64_STANDARD.encode(hex::decode(hex).unwrap())
}

pub fn fixed_xor(hex1: &str, hex2: &str) -> String{
    let byte1 = hex::decode(hex1).unwrap();
    let byte2 = hex::decode(hex2).unwrap();
    
    hex::encode(byte1.iter()
        .zip(byte2.iter())
        .map(|(&b1, &b2)| b1 ^ b2)
        .collect::<Vec<u8>>())
}