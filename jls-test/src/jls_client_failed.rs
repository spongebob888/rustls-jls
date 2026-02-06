use core::time;
use std::fmt::format;
use std::i32::MAX;
use std::io::{Error, ErrorKind, Read, Write, stdout};
use std::net::TcpStream;
use std::sync::Arc;
use std::thread::{self, sleep};

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ClientConfig, JlsConfig, JlsServerConfig, RootCertStore};
use rustls_raw::client;
use rustls_raw::server::{Acceptor, ServerConfig};

fn client_unknown_ca_rtt(mut config: ClientConfig, port: u16) {
    // Allow using SSLKEYLOGFILE.
    config.key_log = Arc::new(rustls::KeyLogFile::new());
    config.jls_config = JlsConfig::new("123", "123");
    //config.jls_config = JlsConfig::new("123", "123");

    let server_name = "localhost".try_into().unwrap();
    let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();
    let mut sock = TcpStream::connect(format!("localhost:{}", port)).unwrap();
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);

    let test_vector = b"test";
    let ret = tls.write_all(test_vector);
    assert!(tls.conn.is_jls() == Some(false));
    assert!(ret.is_err());
    return;
}

fn client_true_ca_rtt(mut config: ClientConfig, port: u16) {
    // Allow using SSLKEYLOGFILE.
    config.key_log = Arc::new(rustls::KeyLogFile::new());
    config.jls_config = JlsConfig::new("123", "123");

    let server_name = "localhost".try_into().unwrap();
    let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();
    let mut sock = TcpStream::connect(format!("localhost:{}", port)).unwrap();
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);

    let test_vector = b"test";
    tls.write_all(test_vector).unwrap();
    assert!(tls.conn.is_jls() == Some(false));
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
    let mut plaintext = [0; 100];
    let len = tls.read(&mut plaintext).unwrap();
    assert!(plaintext[..len] == *test_vector);
    log::info!("client read:{:?}", plaintext);
    stdout().write_all(&plaintext).unwrap();

    tls.flush().unwrap();
}

use std::env;
use std::error::Error as StdError;

use std::net::TcpListener;

use rustls::pki_types::pem::PemObject;

fn server_upstream(mut config: ServerConfig, port: u16) {
    //config.jls_config = JlsServerConfig::new("123", "123", "localhost::5443");

    let listener = TcpListener::bind(format!("127.0.0.1:{}", port)).unwrap();
    let cfg = Arc::new(config);

    for n in 1..2 {
        let (mut stream, _) = listener.accept().unwrap();
        let cfg = cfg.clone();
        thread::spawn(move || {
            let mut conn = rustls_raw::ServerConnection::new(cfg).unwrap();

            let mut buf = [0; 64];
            let mut len = 0;
            loop {
                thread::sleep(time::Duration::from_millis(100));
                assert!(conn.complete_io(&mut stream).is_err());
                return ();
            }
        });
    }

    ()
}

fn server_upstream_true_ca(mut config: ServerConfig, port: u16) {
    //config.jls_config = JlsServerConfig::new("123", "123", "localhost::5443");

    let listener = TcpListener::bind(format!("127.0.0.1:{}", port)).unwrap();
    let cfg = Arc::new(config);

    for n in 1..2 {
        let (mut stream, _) = listener.accept().unwrap();
        let cfg = cfg.clone();
        thread::spawn(move || {
            let mut conn = rustls_raw::ServerConnection::new(cfg).unwrap();

            let mut buf = [0; 64];
            let mut len = 0;
            loop {
                thread::sleep(time::Duration::from_millis(100));
                conn.complete_io(&mut stream).unwrap();
                match conn.reader().read(&mut buf) {
                    Err(e) => {
                        if e.kind() != ErrorKind::WouldBlock {
                            panic!("{}", e);
                        }
                    }
                    Ok(l) => {
                        len = l;
                        break;
                    }
                }
            }
            log::info!(
                "Received message from client: {:?}",
                String::from_utf8(buf[..len].to_vec())
            );

            conn.writer()
                .write_all(&buf[..len])
                .unwrap();

            conn.complete_io(&mut stream).unwrap();
        });
    }

    ()
}

struct TestPki {
    server_cert_der: CertificateDer<'static>,
    server_key_der: PrivateKeyDer<'static>,
    ca_cert: CertificateDer<'static>,
}
impl TestPki {
    fn new() -> Self {
        let alg = &rcgen::PKCS_ECDSA_P256_SHA256;
        let mut ca_params = rcgen::CertificateParams::new(Vec::new()).unwrap();
        ca_params
            .distinguished_name
            .push(rcgen::DnType::OrganizationName, "Provider Server Example");
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Example CA");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        let ca_key = rcgen::KeyPair::generate_for(alg).unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        // Create a server end entity cert issued by the CA.
        let mut server_ee_params =
            rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        server_ee_params.is_ca = rcgen::IsCa::NoCa;
        server_ee_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let server_key = rcgen::KeyPair::generate_for(alg).unwrap();
        let server_cert = server_ee_params
            .signed_by(&server_key, &ca_cert, &ca_key)
            .unwrap();
        Self {
            server_cert_der: server_cert.into(),
            // TODO(XXX): update below once https://github.com/rustls/rcgen/issues/260 is resolved.
            server_key_der: PrivatePkcs8KeyDer::from(server_key.serialize_der()).into(),
            ca_cert: ca_cert.into(),
        }
    }
    fn server_config(self) -> ServerConfig {
        let mut server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![self.server_cert_der.clone()], self.server_key_der)
            .unwrap();
        server_config.max_early_data_size = std::u32::MAX;

        server_config.key_log = Arc::new(rustls_raw::KeyLogFile::new());

        server_config
    }
    fn client_config(&self) -> ClientConfig {
        let mut rt = RootCertStore::empty();
        rt.add_parsable_certificates(vec![self.ca_cert.clone()]);
        let mut cfg = ClientConfig::builder()
            .with_root_certificates(rt)
            .with_no_client_auth();
        cfg.enable_early_data = true;
        cfg
    }
}

#[test]
fn test_unknow_ca_tls_server() {
    let pki = TestPki::new();
    let cfg_ca = pki.client_config();
    let client_config = ClientConfig::builder()
        .with_root_certificates(RootCertStore::empty())
        .with_no_client_auth();
    let server_up = thread::spawn(|| server_upstream(pki.server_config(), 4444));

    thread::sleep(time::Duration::from_millis(100));
    client_unknown_ca_rtt(client_config.clone(), 4444);
    server_up.join().unwrap();
}

#[test]
fn test_known_ca_tls_server() {
    let pki = TestPki::new();
    let cfg_ca = pki.client_config();
    let server_up = thread::spawn(|| server_upstream_true_ca(pki.server_config(), 4447));

    thread::sleep(time::Duration::from_millis(100));
    client_true_ca_rtt(cfg_ca.clone(), 4447);
    server_up.join().unwrap();
}
