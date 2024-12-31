use utils::*;

pub fn challenge_9() {
    let block_size = 20;
    let input = "YELLOW SUBMARINE";
    let expected_output = "YELLOW SUBMARINE\x04\x04\x04\x04".as_bytes();

    let padded_bytes = pkcs7_padding(block_size, input.as_bytes());
    assert_eq!(expected_output, padded_bytes);
    println!("Challenge 9 completed");
    println!(" Before Padding = {}\t After Padding = {:?}\n ", input, bytes_to_plaintext(&padded_bytes));
}

pub fn challenge_10() {
    let iv = vec![0_u8; BLOCK_SIZE];
    let key_bytes = "YELLOW SUBMARINE".as_bytes();

    let path = "set2/src/data/challenge10.txt";
    let ciphertext_bytes = b64_to_bytes(&open_file_to_string(path));

    let decrypted_bytes = aes_cbc_128_decrypt(key_bytes, &iv, &ciphertext_bytes);
    let plaintext = bytes_to_plaintext(&decrypted_bytes);

    //Testing for a known string in the plaintext
    assert_eq!(plaintext.contains("Play that funky music"), true);

    println!("Challenge 10 completed\n");
    // Plaintext is long, uncomment below to print
    // print!("Plaintext = {}\n", bytes_to_plaintext(&decrypted_bytes));

}

fn main(){
    println!("Set 2\n");

    challenge_9();
    challenge_10();
}
