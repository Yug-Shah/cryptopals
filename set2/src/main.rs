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


fn main(){
    println!("Set 2\n");

    challenge_9();
}
