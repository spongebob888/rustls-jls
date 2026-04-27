use std::string::String;

use crate::log::trace;
use crate::msgs::codec::Codec;
use crate::msgs::handshake::{ClientHelloPayload, PresharedKeyBinder};

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
#[derive(Clone, Debug, PartialEq)]
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
    pub fn build_fake_random(
        &self,
        random: &[u8; 16],
        auth_data: &[u8],
    ) -> Result<[u8; 32], &'static str> {
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

        let out: [u8; 32] = buffer.try_into().unwrap();

        let suffix = &out[24..32];
        if suffix == [0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01]
            || suffix == [0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x00]
            || suffix == [0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C]
        {
            return Err("forbidden fake_random suffix");
        }

        Ok(out)
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

fn zero_psk_binders_extension(
    msg: &mut [u8],
    ext_start: usize,
    ext_end: usize,
) -> Result<(), &'static str> {
    let mut pos = ext_start;

    // PreSharedKeyExtension.client_hello:
    //
    // struct {
    //     PskIdentity identities<7..2^16-1>;
    //     PskBinderEntry binders<33..2^16-1>;
    // } OfferedPsks;
    //
    // identities vector:
    // uint16 identities_len;
    // repeated:
    //   opaque identity<1..2^16-1>;  // uint16 len + bytes
    //   uint32 obfuscated_ticket_age;

    let identities_len = read_u16_from_range(msg, &mut pos, ext_end)? as usize;
    let identities_end = pos
        .checked_add(identities_len)
        .ok_or("psk identities length overflow")?;

    if identities_end > ext_end {
        return Err("psk identities exceed extension");
    }

    // We don't need to parse every identity semantically, but doing so gives
    // better validation and lands exactly at binders.
    while pos < identities_end {
        let identity_len = read_u16_from_range(msg, &mut pos, identities_end)? as usize;
        skip_range(msg, &mut pos, identity_len, identities_end)?;

        // obfuscated_ticket_age: uint32
        skip_range(msg, &mut pos, 4, identities_end)?;
    }

    if pos != identities_end {
        return Err("psk identities parse mismatch");
    }

    // binders vector
    let binders_len = read_u16_from_range(msg, &mut pos, ext_end)? as usize;
    let binders_end = pos
        .checked_add(binders_len)
        .ok_or("psk binders length overflow")?;

    if binders_end != ext_end {
        return Err("psk binders do not reach end of psk extension");
    }

    // repeated PskBinderEntry:
    // opaque binder<32..255>; // uint8 len + bytes
    while pos < binders_end {
        let binder_len = read_u8_from_range(msg, &mut pos, binders_end)? as usize;
        if binder_len == 0 {
            return Err("empty psk binder");
        }

        if pos
            .checked_add(binder_len)
            .ok_or("psk binder length overflow")?
            > binders_end
        {
            return Err("psk binder exceeds binders vector");
        }

        msg[pos..pos + binder_len].fill(0);
        pos += binder_len;
    }

    if pos != binders_end {
        return Err("psk binders parse mismatch");
    }

    Ok(())
}

fn read_u24(buf: &[u8]) -> Result<usize, &'static str> {
    if buf.len() < 3 {
        return Err("buffer too short for u24");
    }

    Ok(((buf[0] as usize) << 16) | ((buf[1] as usize) << 8) | (buf[2] as usize))
}

fn read_u8(buf: &[u8], pos: &mut usize) -> Result<u8, &'static str> {
    if *pos >= buf.len() {
        return Err("buffer too short for u8");
    }

    let v = buf[*pos];
    *pos += 1;
    Ok(v)
}

fn read_u16_from_pos(buf: &[u8], pos: &mut usize) -> Result<u16, &'static str> {
    if pos
        .checked_add(2)
        .ok_or("u16 position overflow")?
        > buf.len()
    {
        return Err("buffer too short for u16");
    }

    let v = u16::from_be_bytes([buf[*pos], buf[*pos + 1]]);
    *pos += 2;
    Ok(v)
}

fn read_u8_from_range(buf: &[u8], pos: &mut usize, end: usize) -> Result<u8, &'static str> {
    if *pos >= end || *pos >= buf.len() {
        return Err("range too short for u8");
    }

    let v = buf[*pos];
    *pos += 1;
    Ok(v)
}

fn read_u16_from_range(buf: &[u8], pos: &mut usize, end: usize) -> Result<u16, &'static str> {
    if pos
        .checked_add(2)
        .ok_or("u16 range position overflow")?
        > end
        || pos
            .checked_add(2)
            .ok_or("u16 buffer position overflow")?
            > buf.len()
    {
        return Err("range too short for u16");
    }

    let v = u16::from_be_bytes([buf[*pos], buf[*pos + 1]]);
    *pos += 2;
    Ok(v)
}

fn skip(buf: &[u8], pos: &mut usize, len: usize) -> Result<(), &'static str> {
    if pos
        .checked_add(len)
        .ok_or("skip overflow")?
        > buf.len()
    {
        return Err("buffer too short while skipping");
    }

    *pos += len;
    Ok(())
}

fn skip_range(buf: &[u8], pos: &mut usize, len: usize, end: usize) -> Result<(), &'static str> {
    let new_pos = pos
        .checked_add(len)
        .ok_or("skip range overflow")?;

    if new_pos > end || new_pos > buf.len() {
        return Err("range too short while skipping");
    }

    *pos = new_pos;
    Ok(())
}

/// Fill zero in the PSK binders field directly from encoded ClientHello bytes.
///
/// This function intentionally does not rely on `ClientHelloPayload`,
/// because `parsed` may be inconsistent with the original encoded bytes.
///
/// `msg` is expected to be the encoded Handshake ClientHello body with
/// handshake header included:
///
/// ```text
/// struct {
///     HandshakeType msg_type;    // 1 byte
///     uint24 length;             // 3 bytes
///     ClientHello body;
/// } Handshake;
/// ```
///
/// For TLS 1.3 ClientHello:
///
/// ```text
/// ClientHello {
///     ProtocolVersion legacy_version;
///     Random random;
///     opaque legacy_session_id<0..32>;
///     CipherSuite cipher_suites<2..2^16-2>;
///     opaque legacy_compression_methods<1..2^8-1>;
///     Extension extensions<8..2^16-1>;
/// }
/// ```
///
/// We find extension type 41, `pre_shared_key`, and zero only its binders.
pub(crate) fn set_zero_psk_binders_from_encoded(msg: &mut [u8]) -> Result<(), &'static str> {
    const HANDSHAKE_HEADER_LEN: usize = 4;
    const CLIENT_HELLO_TYPE: u8 = 1;
    const EXT_PRE_SHARED_KEY: u16 = 41;

    if msg.len() < HANDSHAKE_HEADER_LEN {
        return Err("clienthello too short for handshake header");
    }

    if msg[0] != CLIENT_HELLO_TYPE {
        return Err("handshake message is not clienthello");
    }

    let hs_len = read_u24(&msg[1..4])?;
    if hs_len + HANDSHAKE_HEADER_LEN != msg.len() {
        return Err("clienthello handshake length mismatch");
    }

    let mut pos = HANDSHAKE_HEADER_LEN;

    // legacy_version: 2
    skip(msg, &mut pos, 2)?;

    // random: 32
    skip(msg, &mut pos, 32)?;

    // legacy_session_id: opaque <0..32>, uint8 length
    let session_id_len = read_u8(msg, &mut pos)? as usize;
    skip(msg, &mut pos, session_id_len)?;

    // cipher_suites: vector uint16 length, then that many bytes
    let cipher_suites_len = read_u16_from_pos(msg, &mut pos)? as usize;
    if cipher_suites_len % 2 != 0 {
        return Err("invalid cipher_suites length");
    }
    skip(msg, &mut pos, cipher_suites_len)?;

    // legacy_compression_methods: vector uint8 length
    let compression_methods_len = read_u8(msg, &mut pos)? as usize;
    skip(msg, &mut pos, compression_methods_len)?;

    // extensions: vector uint16 length
    if pos == msg.len() {
        // No extensions; therefore no PSK binders.
        return Ok(());
    }

    let extensions_len = read_u16_from_pos(msg, &mut pos)? as usize;
    let extensions_end = pos
        .checked_add(extensions_len)
        .ok_or("extensions length overflow")?;

    if extensions_end != msg.len() {
        return Err("extensions length does not reach end of clienthello");
    }

    while pos < extensions_end {
        let ext_type = read_u16_from_pos(msg, &mut pos)?;
        let ext_len = read_u16_from_pos(msg, &mut pos)? as usize;

        let ext_start = pos;
        let ext_end = ext_start
            .checked_add(ext_len)
            .ok_or("extension length overflow")?;

        if ext_end > extensions_end {
            return Err("extension length exceeds extensions block");
        }

        if ext_type == EXT_PRE_SHARED_KEY {
            zero_psk_binders_extension(msg, ext_start, ext_end)?;
            return Ok(());
        }

        pos = ext_end;
    }

    Ok(())
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
