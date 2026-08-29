use std::string::String;

use crate::log::{trace, info};
use crate::msgs::codec::Codec;
use crate::msgs::handshake::{ClientHelloPayload, PresharedKeyBinder};

use alloc::vec;
use alloc::vec::Vec;
#[cfg(not(feature = "ring"))]
use aws_lc_rs::digest::{SHA256, digest};
use crate::crypto::SecureRandom;
#[cfg(feature = "ring")]
use ring::digest::{SHA256, digest};

// use aes_gcm to support 512bits long nonce (not supported by ring)
use aes_gcm::{
    AeadInPlace, // Or `Aes128Gcm`
    AesGcm,
    KeyInit,
    aead::consts::U32,
    aes::Aes256,
};

pub(crate) mod server;

pub use server::JlsServerConfig;

#[derive(Clone, Debug)]
/// JLS Configuration
pub struct JlsClientConfig {
    /// enable JLS
    pub enable: bool,
    /// user password of a JLS peer
    pub user: JlsUser,
}

/// JLS User information
/// user_iv is generally used as username
#[derive(Clone, Debug, PartialEq)]
pub struct JlsUser {
    /// user password of a JLS peer
    pub user_pwd: String,
    /// user iv for a JLS peer
    pub user_iv: String,
}

const TLS13_DOWNGRADE_SENTINEL_TLS12: [u8; 8] = *b"DOWNGRD\x01";
const TLS13_DOWNGRADE_SENTINEL_TLS11_OR_BELOW: [u8; 8] = *b"DOWNGRD\x00";
const TLS13_HELLO_RETRY_REQUEST_SUFFIX: [u8; 8] = [0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C];
const ILLEGAL_FAKE_RANDOM_SUFFIX: [&[u8; 8]; 3] = [
    &TLS13_DOWNGRADE_SENTINEL_TLS12,
    &TLS13_DOWNGRADE_SENTINEL_TLS11_OR_BELOW,
    &TLS13_HELLO_RETRY_REQUEST_SUFFIX,
];

impl JlsUser {
    /// Create a new JlsUser
    pub fn new(user_pwd: &str, user_iv: &str) -> JlsUser {
        JlsUser {
            user_pwd: String::from(user_pwd),
            user_iv: String::from(user_iv),
        }
    }

    /// Build a fake random from a true random with given auth_data
    pub fn build_fake_random(&self, random: &[u8; 16], auth_data: &[u8]) -> [u8; 32] {
        let mut iv = self.user_iv.as_bytes().to_vec();
        iv.extend_from_slice(auth_data);
        let mut pwd = self.user_pwd.as_bytes().to_vec();
        pwd.extend_from_slice(auth_data);

        trace!("generate ch iv: {:?}", iv);
        trace!("generate pwd: {:?}", pwd);

        let iv = digest(&SHA256, iv.as_ref());
        let pwd = digest(&SHA256, pwd.as_ref());

        let cipher = AesGcm::<Aes256, U32>::new(pwd.as_ref().into());

        let mut buffer = Vec::<u8>::from(random.as_slice());
        cipher
            .encrypt_in_place(iv.as_ref().into(), b"", &mut buffer)
            .unwrap();

        buffer.try_into().unwrap()
    }
    /// Build a fake random from a true random with given auth_data, retry if illegal fake random generated
    /// If secure_random fails to generate random, use the given random to build fake random
    pub fn build_server_fake_random(&self, random: &[u8; 16], secure_random: &dyn SecureRandom, auth_data: &[u8]) -> [u8; 32] {
        loop {
            let mut fake_random = [0u8; 32];
            match secure_random.fill(&mut fake_random) {
                Ok(()) => {
                    let fake_random = self.build_fake_random(fake_random[16..32].try_into().unwrap(), auth_data);
                    if !is_illegal_fake_random(&fake_random) {
                        return fake_random;
                    }
                    info!("illegal fake random generated, retrying...");
                }
                Err(_) => {
                    let fake_random = self.build_fake_random(random, auth_data);
                    return fake_random;
                },
            }
        }
    }

    /// Check if it's a valid fake random
    pub fn check_fake_random(&self, fake_random: &[u8; 32], auth_data: &[u8]) -> bool {
        let mut iv = self.user_iv.as_bytes().to_vec();
        iv.extend_from_slice(auth_data);
        let mut pwd = self.user_pwd.as_bytes().to_vec();
        pwd.extend_from_slice(auth_data);

        trace!("check ch iv: {:?}", iv);
        trace!("check pwd: {:?}", pwd);

        let iv = digest(&SHA256, iv.as_ref());
        let pwd = digest(&SHA256, pwd.as_ref());

        let cipher = AesGcm::<Aes256, U32>::new(pwd.as_ref().into());

        let mut buffer = Vec::from(fake_random.as_ref());

        let is_valid = cipher
            .decrypt_in_place(iv.as_ref().into(), b"", &mut buffer)
            .is_ok();
        is_valid
    }
}

impl Default for JlsUser {
    fn default() -> JlsUser {
        JlsUser {
            user_pwd: "3070111071563328618171495819203123318".into(),
            user_iv: "3070111071563328618171495819203123318".into(),
        }
    }
}

impl JlsClientConfig {
    /// Create a new JlsConfig
    pub fn new(user_pwd: &str, user_iv: &str) -> JlsClientConfig {
        JlsClientConfig {
            enable: true,
            user: JlsUser::new(user_pwd, user_iv),
        }
    }
    /// enable JLS
    pub fn enable(mut self, enable: bool) -> Self {
        self.enable = enable;
        self
    }
    /// Set JLS user
    pub fn set_user(mut self, user_pwd: String, user_iv: String) -> Self {
        self.user = JlsUser::new(&user_pwd, &user_iv);
        self
    }
}
impl Default for JlsClientConfig {
    fn default() -> JlsClientConfig {
        JlsClientConfig {
            enable: false,
            user: JlsUser::default(),
        }
    }
}

pub(crate) fn is_illegal_fake_random(random: &[u8; 32]) -> bool {
    let suffix: &[u8; 8] = &random[24..32].try_into().unwrap();
    ILLEGAL_FAKE_RANDOM_SUFFIX.contains(&suffix)
}

// fill zero in the psk binders field.
pub(crate) fn set_zero_psk_binders(chp: &ClientHelloPayload, msg: &mut [u8]) {
    if let Some(psk) = chp.preshared_key_offer.as_ref() {
        let mut psk = psk.clone();
        for bind in psk.binders.iter_mut() {
            let len = bind.as_ref().len();
            *bind = PresharedKeyBinder::from(vec![0; len]);
        }
        let mut psk_bytes = Vec::new();
        psk.binders.encode(&mut psk_bytes);
        let len = msg.len();
        msg[len - psk_bytes.len()..].copy_from_slice(&psk_bytes);
        trace!("set zero psk binders: {:?}", msg);
    }
}

/// Jls State
#[derive(Clone, Debug, Default)]
pub enum JlsState {
    /// JLS authentication success
    AuthSuccess(JlsUser),
    /// JLS authentication failed with upstream addr
    AuthFailed(Option<String>),
    /// JLS authentication not yet happened
    #[default]
    NotAuthed,
    /// JLS is not enabled
    Disabled,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn illegal_fake_random() {
        let mut random = [0u8; 32];
        random[24..32].copy_from_slice(&TLS13_DOWNGRADE_SENTINEL_TLS12);
        assert!(is_illegal_fake_random(&random));


        assert!(!is_illegal_fake_random(&[0u8; 32]));
    }
}
