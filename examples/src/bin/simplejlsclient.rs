/// This is the simplest possible client using rustls that does something useful:
/// it accepts the default configuration, loads some root certs, and then connects
/// to google.com and issues a basic HTTP request.  The response is printed to stdout.
///
/// It makes use of rustls::Stream to treat the underlying TLS connection as a basic
/// bi-directional stream -- the underlying IO is performed transparently.
///
/// Note that `unwrap()` is used to deal with networking errors; this is not something
/// that is sensible outside of example code.
use std::sync::Arc;

use std::io::{Read, Write};
use std::net::TcpStream;

use rustls::{RootCertStore, JlsConfig};

fn main() {
    env_logger::init();
    let root_store = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.into(),
    };
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    config.jls_config = JlsConfig::new("3070111071563328618171495819203123318",
    "3070111071563328618171495819203123318");
    let server_name = "www.visa.cn".try_into().unwrap();
    let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();
    let mut sock = TcpStream::connect("127.0.0.1:4443").unwrap();
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);
    tls.write_all(
        concat!(
            "GET / HTTP/1.1\r\n",
            "Host: www.visa.cn\r\n",
            "Connection: close\r\n",
            "Accept-Encoding: identity\r\n",
            "\r\n"
        )
        .as_bytes(),
    )
    .unwrap();
    let ciphersuite = tls
        .conn
        .negotiated_cipher_suite()
        .unwrap();
    writeln!(
        &mut std::io::stderr(),
        "Current ciphersuite: {:?}",
        ciphersuite.suite()
    )
    .unwrap();
    let mut plaintext = Vec::new();
    tls.read_to_end(&mut plaintext).unwrap();
    //stdout().write_all(&plaintext).unwrap();
}
