use openssl::hash::{hash, DigestBytes, MessageDigest};

pub fn xor(s1: &mut [u8], s2: &[u8]) {
    s1.copy_from_slice(&s1.iter().zip(s2).map(|(x, y)| x ^ y).collect::<Vec<u8>>());
}

fn to_vec(input: DigestBytes) -> Vec<u8> {
    input.iter().cloned().collect()
}

pub fn sha3_256(input: &[u8]) -> Vec<u8> {
    to_vec(hash(MessageDigest::sha3_256(), input).unwrap())
}

pub fn sha2_256(input: &[u8]) -> Vec<u8> {
    to_vec(hash(MessageDigest::sha256(), input).unwrap())
}

pub fn sha3_512(input: &[u8]) -> Vec<u8> {
    to_vec(hash(MessageDigest::sha3_512(), input).unwrap())
}
