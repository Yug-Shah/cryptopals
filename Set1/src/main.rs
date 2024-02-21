mod functions;

fn main(){
    let mut input1;
    let mut input2;
    let mut result;

    //challenge1
    input1 = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    result = functions::hex_to_base64(input1);
    if result == "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t" {
        println!("Challenge 1, completed.");
    }

    //challenge2
    input1 = "1c0111001f010100061a024b53535009181c";
    input2 = "686974207468652062756c6c277320657965";
    result = functions::fixed_xor(input1, input2);
    if result == "746865206b696420646f6e277420706c6179" {
        println!("Challenge 2, completed.");
    }
}