use crate::log::{debug, error};

use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::vec::Vec;

use crate::{
    Error, HandshakeType,
    common_state::{Context, State},
    msgs::{
        codec::Codec,
        handshake::{
            ClientHelloPayload, ConvertServerNameList, HandshakeMessagePayload, HandshakePayload,
            Random,
        },
        message::Message,
    },
};

use super::{ServerConnectionData, hs::ServerContext};

/// Return true if jls authentication passed
pub(super) fn handle_client_hello_tls13(
    cx: &mut ServerContext<'_>,
    client_hello: &ClientHelloPayload,
) -> bool {
    let mut client_hello_clone = ClientHelloPayload {
        client_version: client_hello.client_version.clone(),
        random: Random([0u8; 32]),
        session_id: client_hello.session_id.clone(),
        cipher_suites: client_hello.cipher_suites.clone(),
        compression_methods: client_hello.compression_methods.clone(),
        extensions: client_hello.extensions.clone(),
    };
    // PSK binders involves the calucaltion of hash of clienthello contradicting
    // with fake random generaton. Must be set zero before checking.
    crate::jls::set_zero_psk_binders(&mut client_hello_clone);
    let ch_hs = HandshakeMessagePayload {
        typ: HandshakeType::ClientHello,
        payload: HandshakePayload::ClientHello(client_hello_clone),
    };
    let mut buf = Vec::<u8>::new();
    ch_hs.encode(&mut buf);

    let server_name = client_hello
        .sni_extension()
        .map_or(None, |x| x.single_hostname());

    let server_name = server_name.map(|x| x.as_ref().to_string());
    let config = &cx.data.jls_conn;
    let valid_name = config.check_server_name(server_name.as_deref());

    let random = &client_hello.random.0;

    if config
        .inner
        .check_fake_random(random, &buf)
        && valid_name
    {
        debug!("JLS client authenticated");
        cx.common.jls_authed = Some(true);
        return true;
    } else {
        if valid_name {
            debug!("JLS client authentication failed: wrong pwd/iv");
        } else {
            debug!("JLS client authentication failed: wrong server name");
        }

        cx.common.jls_authed = Some(false);
        let upstream_addr = config.upstream_addr.clone();
        if upstream_addr.is_none() {
            error!("[jls] No upstream addr provided");
        }
        return false;
    }
}

// JLS Forward
pub(super) struct ExpectForward {}
impl ExpectForward {}

impl State<ServerConnectionData> for ExpectForward {
    fn handle<'m>(
        self: Box<Self>,
        _: &mut Context<'_, ServerConnectionData>,
        message: Message<'m>,
    ) -> Result<Box<dyn State<ServerConnectionData> + 'm>, Error>
    where
        Self: 'm,
    {
        Err(crate::check::inappropriate_message(&message.payload, &[]))
    }

    fn into_owned(self: Box<Self>) -> Box<dyn State<ServerConnectionData> + 'static> {
        self
    }
}
