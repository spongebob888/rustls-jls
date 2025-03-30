use crate::log::{debug, error};

use alloc::vec::Vec;
use alloc::string::ToString;
use alloc::boxed::Box;

use crate::{
    common_state::{Context, State}, conn::ConnectionRandoms, jls::server::JlsForwardConn, msgs::{
        codec::Codec,
        handshake::{
            ClientHelloPayload, ConvertServerNameList, HandshakeMessagePayload, HandshakePayload,
            Random,
        },
        message::Message,
    }, Error, HandshakeType, JlsServerConfig
};

use super::{
    hs::ServerContext,
    ServerConnectionData,
};

/// Return true if jls authentication passed
pub(super) fn handle_client_hello_tls13(
    config: &JlsServerConfig,
    cx: &mut ServerContext<'_>,
    client_hello: &ClientHelloPayload,
    _: &Message<'_>,
    randoms: &mut ConnectionRandoms,
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

    let server_name = client_hello.sni_extension()
        .map_or(None, |x| x.single_hostname());

    let server_name = server_name.map(|x| x.as_ref().to_string());
    let valid_name = config.check_server_name(server_name.as_deref());


    if config.inner.check_fake_random(&randoms.client, &buf) && valid_name {
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
        if let Some(addr) = upstream_addr {
            cx.data.jls_conn = Some(JlsForwardConn {
                upstream_addr: Some(addr),
            });
        } else {
            error!("[jls] No upstream addr provided");
        }
        // End handshaking, start forward traffic
        cx.common.may_send_application_data = true;
        cx.common.may_receive_application_data = true;

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
        Self: 'm {
        Err(crate::check::inappropriate_message(&message.payload, &[]))
    }
    
    fn into_owned(self: Box<Self>) -> Box<dyn State<ServerConnectionData> + 'static> {
        self
    }
}
