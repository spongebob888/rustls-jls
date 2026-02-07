use core::time;
use std::fmt::format;
use std::i32::MAX;
use std::io::{Error, ErrorKind, Read, Write, stdout};
use std::net::TcpStream;
use std::sync::Arc;
use std::thread::{self, sleep};

use rustls::jls::JlsState;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::Acceptor;
use rustls::{
    ClientConfig, RootCertStore, ServerConfig, jls::JlsClientConfig, jls::JlsServerConfig,
};

fn client_one_rtt(mut config: ClientConfig, port: u16) {
    // Allow using SSLKEYLOGFILE.
    config.key_log = Arc::new(rustls::KeyLogFile::new());
    config.jls_config = JlsClientConfig::new("123", "123");

    let server_name = "localhost".try_into().unwrap();
    let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();
    let mut sock = TcpStream::connect(format!("localhost:{}", port)).unwrap();
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);

    let test_vector = b"test";
    tls.write_all(test_vector).unwrap();
    assert!(tls.conn.jls_state() == rustls::jls::JlsState::AuthSuccess);
    assert!(tls.conn.is_early_data_accepted() == false);
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

fn client_zero_rtt(mut config: ClientConfig, port: u16) {
    // Allow using SSLKEYLOGFILE.
    config.key_log = Arc::new(rustls::KeyLogFile::new());
    config.jls_config = JlsClientConfig::new("123", "123");

    let server_name = "localhost".try_into().unwrap();
    let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();
    let mut sock = TcpStream::connect(format!("localhost:{}", port)).unwrap();
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);

    let test_vector = b"test";
    tls.write_all(test_vector).unwrap();
    assert!(tls.conn.jls_state() == JlsState::AuthSuccess);
    assert!(tls.conn.is_early_data_accepted() == true);
    let ciphersuite = tls
        .conn
        .negotiated_cipher_suite()
        .unwrap();

    let mut plaintext = [0; 100];
    let len = tls.read(&mut plaintext).unwrap();
    assert!(plaintext[..len] == *test_vector);
    log::info!("client read:{:?}", plaintext);
    stdout().write_all(&plaintext).unwrap();

    tls.flush().unwrap();
}

fn client_wrong_passwd(mut config: ClientConfig, port: u16) {
    // Allow using SSLKEYLOGFILE.
    config.key_log = Arc::new(rustls::KeyLogFile::new());
    config.jls_config = JlsClientConfig::new("1238", "123");

    let server_name = "localhost".try_into().unwrap();
    let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();
    let mut sock = TcpStream::connect(format!("localhost:{}", port)).unwrap();
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);

    let test_vector = b"test";
    tls.write_all(test_vector).unwrap();
    assert!(tls.conn.jls_state() == JlsState::AuthFailed);
    assert!(tls.conn.is_early_data_accepted() == false);
    return;
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

fn server_upstream(mut config: ServerConfig, port: u16, iter: u32, jls: bool) {
    //config.jls_config = JlsServerConfig::new("123", "123", "localhost::5443");

    let listener = TcpListener::bind(format!("127.0.0.1:{}", port)).unwrap();
    config.jls_config =
        JlsServerConfig::new("123".into(), "1".into(), Some("localhost:443".into()), None)
            .add_user("123".into(), "123".into())
            .into();
    let mut cfg = Arc::new(config);

    for n in 0..iter {
        let (mut stream, _) = listener.accept().unwrap();
        let cfg = cfg.clone();
        thread::spawn(move || {
            let mut conn = rustls::ServerConnection::new(cfg).unwrap();

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
                assert!((conn.jls_state() == JlsState::AuthSuccess) == jls);
                assert!(conn.jls_chosen_user().unwrap().user_iv == "123");
            }
            log::info!(
                "Received message `from client: {:?}",
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

        server_config.key_log = Arc::new(rustls::KeyLogFile::new());

        server_config
    }
    fn client_config(&self) -> ClientConfig {
        let mut rt = RootCertStore::empty();
        //rt.add_parsable_certificates(vec![self.ca_cert.clone()]);
        let mut cfg = ClientConfig::builder()
            .with_root_certificates(rt)
            .with_no_client_auth();
        cfg.enable_early_data = true;
        cfg
    }
}

#[test]
fn test_true_jls_server() {
    let _ = env_logger::try_init();
    let pki = TestPki::new();
    let client_config = pki.client_config();
    let server_up = thread::spawn(|| server_upstream(pki.server_config(), 4443, 3, true));

    thread::sleep(time::Duration::from_millis(100));
    client_one_rtt(client_config.clone(), 4443);
    let cfg = client_config.clone();
    let client_jls = thread::spawn(move || {
        client_zero_rtt(cfg, 4443);
        log::info!("zero-rtt check passed");
    });
    client_zero_rtt(client_config, 4443);

    server_up.join().unwrap();
    client_jls.join().unwrap();
}

#[test]
fn test_false_jls_server() {
    let _ = env_logger::try_init();
    let pki = TestPki::new();
    let mut client_config = pki.client_config();
    //client_config.jls_config.user_pwd = "123".into();
    let server_up = thread::spawn(|| server_upstream(pki.server_config(), 4445, 1, false));

    thread::sleep(time::Duration::from_millis(100));
    let client_jls = thread::spawn(move || {
        client_wrong_passwd(client_config.clone(), 4445);
    });

    let _ = server_up.join();

    thread::sleep(time::Duration::from_millis(2000));
}
