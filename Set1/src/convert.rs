extern crate rustc_serialize as serialize;
use serialize::base64::{self, ToBase64};
use serialize::hex::FromHex;

pub fn hex_to_base64(hex: String) -> String {
    hex.from_hex().unwrap().as_slice().to_base64(base64::STANDARD)
}