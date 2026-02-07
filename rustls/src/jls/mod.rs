use std::string::String;

use crate::log::trace;
use crate::msgs::handshake::{ClientExtension, ClientHelloPayload};

use alloc::vec;
use alloc::vec::Vec;
#[cfg(not(feature = "ring"))]
use aws_lc_rs::digest::{SHA256, digest};
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
#[derive(Clone, Debug)]
pub struct JlsUser {
    /// user password of a JLS peer
    pub user_pwd: String,
    /// user iv for a JLS peer
    pub user_iv: String,
}

impl JlsUser {
    /// Create a new JlsUser
    pub fn new(user_pwd: &str, user_iv: &str) -> JlsUser {
        JlsUser {
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
}
impl Default for JlsClientConfig {
    fn default() -> JlsClientConfig {
        JlsClientConfig {
            enable: false,
            user: JlsUser::default(),
        }
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

/// Jls State
#[derive(Clone, Debug, PartialEq, Default)]
pub enum JlsState {
    /// JLS authentication success
    AuthSuccess,
    /// JLS authentication failed
    AuthFailed,
    /// JLS authentication not yet happened
    #[default]
    NotAuthed,
    /// JLS is not enabled
    Disabled,
}
