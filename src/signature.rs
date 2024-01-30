use std::{convert::TryInto, fmt::{Display, Debug, Formatter}, str::FromStr};

use ed25519_dalek::{Signer, Verifier};

#[derive(Debug, Copy, Clone)]
pub enum KeyType {
    ED25519 = 0,
    SECP256K1 = 1,
}

impl Display for KeyType {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(
            f,
            "{}",
            match self {
                KeyType::ED25519 => "ed25519",
                KeyType::SECP256K1 => "secp256k1",
            },
        )
    }
}

impl FromStr for KeyType {
    type Err = crate::errors::ParseKeyTypeError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let lowercase_key_type = value.to_ascii_lowercase();
        match lowercase_key_type.as_str() {
            "ed25519" => Ok(KeyType::ED25519),
            "secp256k1" => Ok(KeyType::SECP256K1),
            _ => Err(Self::Err::UnknownKeyType { unknown_key_type: lowercase_key_type }),
        }
    }
}

#[derive(Clone)]
pub struct ED25519PublicKey(pub [u8; ed25519_dalek::PUBLIC_KEY_LENGTH]);


#[derive(Clone)]
pub struct Secp256K1PublicKey([u8; 64]);

/// Public key container supporting different curves.
#[derive(Clone)]
pub enum PublicKey {
    /// 256 bit elliptic curve based public-key.
    ED25519(ED25519PublicKey),
    /// 512 bit elliptic curve based public-key used in Bitcoin's public-key cryptography.
    SECP256K1(Secp256K1PublicKey),
}

impl Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "{}", String::from(self))
    }
}

impl Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "{}", String::from(self))
    }
}

impl From<&PublicKey> for String {
    fn from(public_key: &PublicKey) -> Self {
        match public_key {
            PublicKey::ED25519(public_key) => {
                format!("{}:{}", KeyType::ED25519, bs58::encode(&public_key.0).into_string())
            }
            PublicKey::SECP256K1(public_key) => format!(
                "{}:{}",
                KeyType::SECP256K1,
                bs58::encode(&public_key.0.to_vec()).into_string()
            ),
        }
    }
}

impl FromStr for PublicKey {
    type Err = crate::errors::ParseKeyError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (key_type, key_data) = split_key_type_data(value)?;
        match key_type {
            KeyType::ED25519 => {
                let mut array = [0; ed25519_dalek::PUBLIC_KEY_LENGTH];
                let length = bs58::decode(key_data)
                    .into(&mut array)
                    .map_err(|err| Self::Err::InvalidData { error_message: err.to_string() })?;
                if length != ed25519_dalek::PUBLIC_KEY_LENGTH {
                    return Err(Self::Err::InvalidLength {
                        expected_length: ed25519_dalek::PUBLIC_KEY_LENGTH,
                        received_length: length,
                    });
                }
                Ok(PublicKey::ED25519(ED25519PublicKey(array)))
            }
            KeyType::SECP256K1 => {
                let mut array = [0; 64];
                let length = bs58::decode(key_data)
                    .into(&mut array[..])
                    .map_err(|err| Self::Err::InvalidData { error_message: err.to_string() })?;
                if length != 64 {
                    return Err(Self::Err::InvalidLength {
                        expected_length: 64,
                        received_length: length,
                    });
                }
                Ok(PublicKey::SECP256K1(Secp256K1PublicKey(array)))
            }
        }
    }
}

fn split_key_type_data(value: &str) -> Result<(KeyType, &str), crate::errors::ParseKeyTypeError> {
    if let Some(idx) = value.find(':') {
        let (prefix, key_data) = value.split_at(idx);
        Ok((KeyType::from_str(prefix)?, &key_data[1..]))
    } else {
        // If there is no prefix then we Default to ED25519.
        Ok((KeyType::ED25519, value))
    }
}



const SECP256K1_SIGNATURE_LENGTH: usize = 65;

#[derive(Clone, Hash)]
pub struct Secp256K1Signature([u8; SECP256K1_SIGNATURE_LENGTH]);

#[derive(Clone)]
pub enum Signature {
    ED25519(ed25519_dalek::Signature),
    SECP256K1(Secp256K1Signature),
}

impl Signature {
    pub fn verify(&self, data: &[u8], public_key: &PublicKey) -> bool {
        match (&self, public_key) {
            (Signature::ED25519(signature), PublicKey::ED25519(public_key)) => {
                match ed25519_dalek::PublicKey::from_bytes(&public_key.0) {
                    Err(_) => false,
                    Ok(public_key) => public_key.verify(data, signature).is_ok(),
                }
            }
            (Signature::SECP256K1(_signature), PublicKey::SECP256K1(_public_key)) => {
                // let rsig = secp256k1::ecdsa::RecoverableSignature::from_compact(
                //     &signature.0[0..64],
                //     secp256k1::ecdsa::RecoveryId::from_i32(i32::from(signature.0[64])).unwrap(),
                // )
                // .unwrap();
                // let sig = rsig.to_standard();
                // let pdata: [u8; 65] = {
                //     // code borrowed from https://github.com/openethereum/openethereum/blob/98b7c07171cd320f32877dfa5aa528f585dc9a72/ethkey/src/signature.rs#L210
                //     let mut temp = [4u8; 65];
                //     temp[1..65].copy_from_slice(&public_key.0);
                //     temp
                // };
                // SECP256K1
                //     .verify_ecdsa(
                //         &secp256k1::Message::from_slice(data).expect("32 bytes"),
                //         &sig,
                //         &secp256k1::PublicKey::from_slice(&pdata).unwrap(),
                //     )
                //     .is_ok()
                true
            }
            _ => false,
        }
    }

    pub fn key_type(&self) -> KeyType {
        match self {
            Signature::ED25519(_) => KeyType::ED25519,
            Signature::SECP256K1(_) => KeyType::SECP256K1,
        }
    }
}

impl Display for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        let data = match self {
            Signature::ED25519(signature) => {
                bs58::encode(&signature.to_bytes().to_vec()).into_string()
            }
            Signature::SECP256K1(signature) => bs58::encode(&signature.0[..]).into_string(),
        };
        write!(f, "{}", format!("{}:{}", self.key_type(), data))
    }
}

impl Debug for Signature {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "{}", self)
    }
}

impl near_sdk::serde::Serialize for Signature {
    fn serialize<S>(
        &self,
        serializer: S,
    ) -> Result<<S as near_sdk::serde::Serializer>::Ok, <S as near_sdk::serde::Serializer>::Error>
    where
        S: near_sdk::serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl FromStr for Signature {
    type Err = crate::errors::ParseSignatureError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (sig_type, sig_data) = split_key_type_data(value)?;
        match sig_type {
            KeyType::ED25519 => {
                let mut array = [0; ed25519_dalek::SIGNATURE_LENGTH];
                let length = bs58::decode(sig_data)
                    .into(&mut array[..])
                    .map_err(|err| Self::Err::InvalidData { error_message: err.to_string() })?;
                if length != ed25519_dalek::SIGNATURE_LENGTH {
                    return Err(Self::Err::InvalidLength {
                        expected_length: ed25519_dalek::SIGNATURE_LENGTH,
                        received_length: length,
                    });
                }
                Ok(Signature::ED25519(
                    ed25519_dalek::Signature::from_bytes(&array)
                        .map_err(|err| Self::Err::InvalidData { error_message: err.to_string() })?,
                ))
            }
            KeyType::SECP256K1 => {
                // let mut array = [0; 65];
                // let length = bs58::decode(sig_data)
                //     .into(&mut array[..])
                //     .map_err(|err| Self::Err::InvalidData { error_message: err.to_string() })?;
                // if length != 65 {
                //     return Err(Self::Err::InvalidLength {
                //         expected_length: 65,
                //         received_length: length,
                //     });
                // }
                // Ok(Signature::SECP256K1(Secp256K1Signature(array)))
                unimplemented!()
            }
        }
    }
}




#[derive(Clone)]
pub struct ED25519SecretKey(pub [u8; ed25519_dalek::KEYPAIR_LENGTH]);

impl std::fmt::Debug for ED25519SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(
            f,
            "{}",
            bs58::encode(&self.0[..ed25519_dalek::SECRET_KEY_LENGTH].to_vec()).into_string()
        )
    }
}


#[derive(Clone, Debug)]
pub enum SecretKey {
    ED25519(ED25519SecretKey),
}

impl SecretKey {
    pub fn key_type(&self) -> KeyType {
        match self {
            SecretKey::ED25519(_) => KeyType::ED25519,
        }
    }

    pub fn sign(&self, data: &[u8]) -> Signature {
        match &self {
            SecretKey::ED25519(secret_key) => {
                let keypair = ed25519_dalek::Keypair::from_bytes(&secret_key.0).unwrap();
                Signature::ED25519(keypair.sign(data))
            }

            // SecretKey::SECP256K1(secret_key) => {
            //     let signature = SECP256K1.sign_ecdsa_recoverable(
            //         &secp256k1::Message::from_slice(data).expect("32 bytes"),
            //         secret_key,
            //     );
            //     let (rec_id, data) = signature.serialize_compact();
            //     let mut buf = [0; 65];
            //     buf[0..64].copy_from_slice(&data[0..64]);
            //     buf[64] = rec_id.to_i32() as u8;
            //     Signature::SECP256K1(Secp256K1Signature(buf))
            // }
        }
    }

    pub fn public_key(&self) -> PublicKey {
        match &self {
            SecretKey::ED25519(secret_key) => PublicKey::ED25519(ED25519PublicKey(
                secret_key.0[ed25519_dalek::SECRET_KEY_LENGTH..].try_into().unwrap(),
            )),
            // SecretKey::SECP256K1(secret_key) => {
            //     let pk = secp256k1::PublicKey::from_secret_key(&SECP256K1, secret_key);
            //     let serialized = pk.serialize_uncompressed();
            //     let mut public_key = Secp256K1PublicKey([0; 64]);
            //     public_key.0.copy_from_slice(&serialized[1..65]);
            //     PublicKey::SECP256K1(public_key)
            // }
        }
    }
}

impl std::fmt::Display for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        let data = match self {
            SecretKey::ED25519(secret_key) => bs58::encode(&secret_key.0[..]).into_string(),
        };
        write!(f, "{}:{}", self.key_type(), data)
    }
}

impl FromStr for SecretKey {
    type Err = crate::errors::ParseKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (key_type, key_data) = split_key_type_data(s)?;
        match key_type {
            KeyType::ED25519 => {
                let mut array = [0; ed25519_dalek::KEYPAIR_LENGTH];
                let length = bs58::decode(key_data)
                    .into(&mut array[..])
                    .map_err(|err| Self::Err::InvalidData { error_message: err.to_string() })?;
                if length != ed25519_dalek::KEYPAIR_LENGTH {
                    return Err(Self::Err::InvalidLength {
                        expected_length: ed25519_dalek::KEYPAIR_LENGTH,
                        received_length: length,
                    });
                }
                Ok(Self::ED25519(ED25519SecretKey(array)))
            }
            KeyType::SECP256K1 => {
                // let mut array = [0; secp256k1::constants::SECRET_KEY_SIZE];
                // let length = bs58::decode(key_data)
                //     .into(&mut array[..])
                //     .map_err(|err| Self::Err::InvalidData { error_message: err.to_string() })?;
                // if length != secp256k1::constants::SECRET_KEY_SIZE {
                //     return Err(Self::Err::InvalidLength {
                //         expected_length: secp256k1::constants::SECRET_KEY_SIZE,
                //         received_length: length,
                //     });
                // }
                // Ok(Self::SECP256K1(
                //     secp256k1::SecretKey::from_slice(&array)
                //         .map_err(|err| Self::Err::InvalidData { error_message: err.to_string() })?,
                // ))
                unimplemented!()
            }
        }
    }
}