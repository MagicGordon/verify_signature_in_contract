use std::convert::TryFrom;
use std::str::FromStr;

use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::collections::{LazyOption, LookupMap, UnorderedMap, UnorderedSet};
use near_sdk::json_types::{I64, U64, U128};
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::{
    assert_one_yocto, env, ext_contract, log, near_bindgen, AccountId, Balance, BorshStorageKey,
    Duration, Gas, PanicOnDefault, Promise, Timestamp,
};

mod signature;
mod errors;

pub use signature::*;
pub use errors::*;

#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize, Default)]
pub struct Contract {}

#[near_bindgen]
impl Contract {
    pub fn verify(&self, data: String, signature: String, public_key: String) {
        let pk = PublicKey::from_str(public_key.as_str()).unwrap();
        let sig_from_str = Signature::from_str(signature.as_str()).unwrap();
        assert!(sig_from_str.verify(data.as_bytes(), &pk), "Invalid signature");
    }
}

#[test]
fn aa() {
    //near call dev-1706579460742-30579031695962 verify '{"data":"hello", "signature":"ed25519:3jHCr9EnN2UVH7zs8FPSJnXmRyAgMZN5Vvv6P91W6d4rp9Rk1ibmLM2FaCjLuJyfFy2PqfHFKWAP3tEPforBG156", "public_key":"ed25519:BVKkTH18XYpnnQkug9Ge4h1BpVu65bv9Nmzd1XY5WNLL"}' --accountId dev-1706579460742-30579031695962
    let pk = PublicKey::from_str("ed25519:BVKkTH18XYpnnQkug9Ge4h1BpVu65bv9Nmzd1XY5WNLL").unwrap();
    println!("{:?}", pk); 

    let sk = SecretKey::from_str("ed25519:378QybwFAxgo5QPm6zYRmuG6KCYW7tr5QhzFhUw5RNF1NSgJYPPrYm8ckTiEg3hmYxZsMitDvXa3PzrrAJBrz4ex").unwrap();
    let sig = sk.sign("hello".as_bytes());
    println!("{:?}", sk.public_key());
    
    println!("{:?}", sig);

    let sig_from_str = Signature::from_str("ed25519:3jHCr9EnN2UVH7zs8FPSJnXmRyAgMZN5Vvv6P91W6d4rp9Rk1ibmLM2FaCjLuJyfFy2PqfHFKWAP3tEPforBG156").unwrap();
    assert!(sig.verify("hello".as_bytes(), &pk));
    assert!(sig_from_str.verify("hello".as_bytes(), &pk));
}