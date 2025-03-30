
use std::string::String;

use crate::log::trace;
use crate::msgs::handshake::{ClientExtension, ClientHelloPayload};

#[cfg(feature = "ring")]
use ring::digest::{digest, SHA256};
#[cfg(not(feature = "ring"))]
use aws_lc_rs::digest::{digest, SHA256};
use alloc::vec::Vec;
use alloc::vec;

// use aes_gcm to support 512bits long nonce (not supported by ring)
use aes_gcm::{
    aead::consts::U32,
    aes::Aes256,
    AeadInPlace, // Or `Aes128Gcm`
    AesGcm,
    KeyInit,
};

pub(crate) mod server;

#[derive(Clone,Debug)]
/// JLS Configuration
pub struct JlsConfig {
    /// user password of a JLS peer
    pub user_pwd: String,
    /// user iv for a JLS peer
    pub user_iv: String,
}

impl Default for JlsConfig {
    fn default() -> JlsConfig {
        JlsConfig {
            user_pwd: "3070111071563328618171495819203123318".into(),
            user_iv: "3070111071563328618171495819203123318".into(),
        }
    }
}

impl JlsConfig {
    /// Create a new JlsConfig
    pub fn new(user_pwd: &str, user_iv: &str) -> JlsConfig {
        JlsConfig {
            user_pwd: String::from(user_pwd),
            user_iv: String::from(user_iv),
        }
    }

    /// Build a fake random from a true random with given keyshare
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

// fill zero in the psk binders field.
pub(crate) fn set_zero_psk_binders(chp: &mut ClientHelloPayload) {
    let last_extension = chp.extensions.last_mut();
    if let Some(ClientExtension::PresharedKey(ref mut offer)) = last_extension {
        for ii in 0..offer.binders.len() {
            let len = offer.binders[ii].as_ref().len();
            offer.binders[0] = vec![0u8; len].into();
        }
    }
}

