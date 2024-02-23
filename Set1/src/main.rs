mod functions;

fn main(){

    //challenge1
    let hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let raw_data = functions::get_raw_data(hex);
    let result = functions::hex_to_base64(hex);
    println!("\nSet 1, Challenge 1\n Hex = {}\n Raw = {:#?}\n B64 = {}\n", hex, raw_data, result);

    //challenge2
    let hex1 = "1c0111001f010100061a024b53535009181c";
    let hex2 = "686974207468652062756c6c277320657965";
    let raw_data_1 = functions::get_raw_data(hex1);
    let raw_data_2 = functions::get_raw_data(hex2);
    let result = functions::fixed_xor(hex1, hex2);
    let raw_data_3 = functions::get_raw_data(&result);
    println!("\nSet 1, Challenge 2\n Hex1 = {}\t Raw = {:#?}\n Hex2 = {}\t Raw = {}\n XOR = {}\t Raw = {}\n", hex1, raw_data_1, hex2, raw_data_2, result, raw_data_3);


    //challenge 3
    let hex = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let (result, key) = functions::crack_xor(hex);
    let raw_data = functions::get_raw_data(hex);
    println!("\nSet 1, Challenge 3\n Hex = {}\t Raw = {:#?}\n Key = {}\t Plaintext = {}\n", hex, raw_data, key as char, result);

    //challenge 4
    let path = "./data/challenge4.txt";
    let (hex, result, key) = functions::detect_xor(path);
    let raw_data = functions::get_raw_data(&hex);
    println!("\nSet 1, Challenge 4\n Hex = {}\t Raw = {:#?}\n Key = {}\t Plaintext = {:#?}\n", hex, raw_data, key as char, result);

}