use crate::{
    jls::{JlsServerConfig, JlsState},
    log::{debug, error}, msgs::message::MessagePayload,
};

use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::vec::Vec;

use crate::{
    Error, HandshakeType,
    common_state::{Context, State},
    msgs::{
        codec::Codec,
        handshake::{
            ClientHelloPayload, HandshakeMessagePayload, HandshakePayload,
            Random,
        },
        message::Message,
    },
};

use super::{ServerConnectionData, hs::ServerContext};

/// Return true if jls authentication passed
pub(super) fn handle_client_hello_tls13(
    cx: &mut ServerContext<'_>,
    client_hello: &Message<'_>,
) -> bool {

    let (mut encoded,  parsed) = match &client_hello.payload {
            MessagePayload::Handshake {
        parsed: _parsed,
        encoded: _encoded,
    } => {
        let ch = if let HandshakeMessagePayload(HandshakePayload::ClientHello(ch)) = _parsed {
            ch
        } else {
            unreachable!()
        };
        (_encoded.bytes().to_vec(), ch)
    }
    _ => unreachable!()
    };
    let config = &cx.data.jls_conn;
    if !config.enable {
        debug!("JLS disabled");
        return false;
    }
    // Fix fill random to be zero
    encoded[6..6+32].fill(0);

    // PSK binders involves the calucaltion of hash of clienthello contradicting
    // with fake random generaton. Must be set zero before checking.
    crate::jls::set_zero_psk_binders(parsed, &mut encoded);
    // let ch_hs = HandshakeMessagePayload (
    //     HandshakePayload::ClientHello(client_hello_clone),
    // );


    let server_name = parsed
        .server_name.as_ref()
        .map_or(None, |x| match x {
            crate::msgs::handshake::ServerNamePayload::SingleDnsName(x) => Some(x),
            crate::msgs::handshake::ServerNamePayload::IpAddress => None,
            crate::msgs::handshake::ServerNamePayload::Invalid => None,
        });

    let server_name = server_name.map(|x| x.as_ref().to_string());
    let valid_name = config.check_server_name(server_name.as_deref());

    let random = &parsed.random.0;

    let jls_chosen = config
        .users
        .iter()
        .find(|x| x.check_fake_random(random, &encoded));
    if jls_chosen.is_some() && valid_name {
        debug!("JLS client authenticated");
        cx.common.jls_authed = JlsState::AuthSuccess;
        cx.common.jls_chosen_user = jls_chosen.cloned();
        return true;
    } else {
        if valid_name {
            debug!("JLS client authentication failed: wrong pwd/iv");
        } else {
            debug!("JLS client authentication failed: wrong server name");
        }

        cx.common.jls_authed = JlsState::AuthFailed;
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
