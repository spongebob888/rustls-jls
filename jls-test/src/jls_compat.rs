//! JLS protocol compatibility tests.
//!
//! These tests validate that the current (local) JLS implementation in
//! `../rustls` is wire-compatible with the reference release
//! `v/0.23.25-1.0.2` (pulled in as the `rustls_ref` crate).
//!
//! Two directions are exercised:
//!   * local JLS client  <-> reference JLS server
//!   * reference JLS client <-> local JLS server
//!
//! In both cases a successful JLS authentication is expected, proving the two
//! versions speak the same JLS handshake on the wire.

use core::time;
use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;

use rcgen::Issuer;

/// Shared JLS credentials used by both peers. `pwd` and `iv` are deliberately
/// different so an accidental swap of the two would be caught.
const JLS_PWD: &str = "jls-compat-pwd";
const JLS_IV: &str = "jls-compat-iv";
/// The upstream address the server is configured to masquerade as. The SNI the
/// client sends (`localhost`) must match its host part for JLS to succeed.
const UPSTREAM_ADDR: &str = "localhost:443";
const SERVER_NAME: &str = "localhost";

/// Self-signed PKI shared between the two peers, kept as raw DER so it can be
/// fed into either crate's (possibly differing) `pki_types` version.
struct TestPki {
    server_cert_der: Vec<u8>,
    server_key_der: Vec<u8>,
    ca_cert_der: Vec<u8>,
}

impl TestPki {
    fn new() -> Self {
        let alg = &rcgen::PKCS_ECDSA_P256_SHA256;
        let mut ca_params = rcgen::CertificateParams::new(Vec::new()).unwrap();
        ca_params
            .distinguished_name
            .push(rcgen::DnType::OrganizationName, "JLS Compat Test");
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
        let issuer = Issuer::from_params(&ca_params, &ca_key);

        // Create a server end entity cert issued by the CA.
        let mut server_ee_params =
            rcgen::CertificateParams::new(vec![SERVER_NAME.to_string()]).unwrap();
        server_ee_params.is_ca = rcgen::IsCa::NoCa;
        server_ee_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let server_key = rcgen::KeyPair::generate_for(alg).unwrap();
        let server_cert = server_ee_params
            .signed_by(&server_key, &issuer)
            .unwrap();

        Self {
            server_cert_der: server_cert.der().as_ref().to_vec(),
            server_key_der: server_key.serialize_der(),
            ca_cert_der: ca_cert.der().as_ref().to_vec(),
        }
    }
}

// ---------------------------------------------------------------------------
// Local (current) rustls config builders
// ---------------------------------------------------------------------------

fn local_client_config(ca_der: &[u8]) -> rustls::ClientConfig {
    use rustls::pki_types::CertificateDer;

    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from(ca_der.to_vec()))
        .unwrap();
    let mut cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.key_log = Arc::new(rustls::KeyLogFile::new());
    cfg.jls_config = rustls::jls::JlsClientConfig::new(JLS_PWD, JLS_IV);
    cfg
}

fn local_server_config(cert_der: &[u8], key_der: &[u8]) -> rustls::ServerConfig {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

    let mut cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(cert_der.to_vec())],
            PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key_der.to_vec())),
        )
        .unwrap();
    cfg.key_log = Arc::new(rustls::KeyLogFile::new());
    cfg.jls_config = rustls::jls::JlsServerConfig::new(
        JLS_PWD.into(),
        JLS_IV.into(),
        Some(UPSTREAM_ADDR.into()),
        None,
    )
    .into();
    cfg
}

// ---------------------------------------------------------------------------
// Reference (v/0.23.25-1.0.2) rustls config builders
// ---------------------------------------------------------------------------

fn ref_client_config(ca_der: &[u8]) -> rustls_ref::ClientConfig {
    use rustls_ref::pki_types::CertificateDer;

    let mut roots = rustls_ref::RootCertStore::empty();
    roots
        .add(CertificateDer::from(ca_der.to_vec()))
        .unwrap();
    let mut cfg = rustls_ref::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.key_log = Arc::new(rustls_ref::KeyLogFile::new());
    cfg.jls_config = rustls_ref::JlsConfig::new(JLS_PWD, JLS_IV);
    cfg
}

fn ref_server_config(cert_der: &[u8], key_der: &[u8]) -> rustls_ref::ServerConfig {
    use rustls_ref::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

    let mut cfg = rustls_ref::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(cert_der.to_vec())],
            PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key_der.to_vec())),
        )
        .unwrap();
    cfg.key_log = Arc::new(rustls_ref::KeyLogFile::new());
    // The reference server config is stored inline (not behind an `Arc`).
    cfg.jls_config = rustls_ref::JlsServerConfig::new(JLS_PWD, JLS_IV, UPSTREAM_ADDR);
    cfg
}

// ---------------------------------------------------------------------------
// Servers
// ---------------------------------------------------------------------------

const ECHO_MSG: &[u8] = b"jls-protocol-compat";

/// Run a single-connection local (current) JLS server that echoes one message
/// back and asserts JLS authentication succeeded.
fn run_local_server(cfg: rustls::ServerConfig, port: u16) {
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port)).unwrap();
    let cfg = Arc::new(cfg);
    let (mut stream, _) = listener.accept().unwrap();
    let mut conn = rustls::ServerConnection::new(cfg).unwrap();

    let mut buf = [0u8; 64];
    let len = loop {
        thread::sleep(time::Duration::from_millis(50));
        conn.complete_io(&mut stream).unwrap();
        match conn.reader().read(&mut buf) {
            Err(e) if e.kind() == ErrorKind::WouldBlock => continue,
            Err(e) => panic!("local server read error: {e}"),
            Ok(l) => break l,
        }
    };

    assert!(
        matches!(conn.jls_state(), rustls::jls::JlsState::AuthSuccess(_)),
        "local server expected JLS AuthSuccess, got {:?}",
        conn.jls_state()
    );
    assert_eq!(conn.jls_chosen_user().unwrap().user_pwd, JLS_PWD);

    conn.writer()
        .write_all(&buf[..len])
        .unwrap();
    conn.complete_io(&mut stream).unwrap();
}

/// Run a single-connection reference (v/0.23.25-1.0.2) JLS server that echoes
/// one message back and asserts JLS authentication succeeded.
fn run_ref_server(cfg: rustls_ref::ServerConfig, port: u16) {
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port)).unwrap();
    let cfg = Arc::new(cfg);
    let (mut stream, _) = listener.accept().unwrap();
    let mut conn = rustls_ref::ServerConnection::new(cfg).unwrap();

    let mut buf = [0u8; 64];
    let len = loop {
        thread::sleep(time::Duration::from_millis(50));
        conn.complete_io(&mut stream).unwrap();
        match conn.reader().read(&mut buf) {
            Err(e) if e.kind() == ErrorKind::WouldBlock => continue,
            Err(e) => panic!("reference server read error: {e}"),
            Ok(l) => break l,
        }
    };

    assert_eq!(
        conn.is_jls(),
        Some(true),
        "reference server expected JLS authentication to succeed"
    );

    conn.writer()
        .write_all(&buf[..len])
        .unwrap();
    conn.complete_io(&mut stream).unwrap();
}

// ---------------------------------------------------------------------------
// Clients
// ---------------------------------------------------------------------------

/// Local (current) JLS client: connect, send a message, expect it echoed back
/// and JLS authentication to succeed.
fn run_local_client(cfg: rustls::ClientConfig, port: u16) {
    let server_name = SERVER_NAME.try_into().unwrap();
    let mut conn = rustls::ClientConnection::new(Arc::new(cfg), server_name).unwrap();
    let mut sock = TcpStream::connect(format!("localhost:{}", port)).unwrap();
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);

    tls.write_all(ECHO_MSG).unwrap();
    assert!(
        matches!(tls.conn.jls_state(), rustls::jls::JlsState::AuthSuccess(_)),
        "local client expected JLS AuthSuccess, got {:?}",
        tls.conn.jls_state()
    );

    let mut plaintext = [0u8; 64];
    let len = tls.read(&mut plaintext).unwrap();
    assert_eq!(&plaintext[..len], ECHO_MSG);
}

/// Reference (v/0.23.25-1.0.2) JLS client: connect, send a message, expect it
/// echoed back and JLS authentication to succeed.
fn run_ref_client(cfg: rustls_ref::ClientConfig, port: u16) {
    let server_name = SERVER_NAME.try_into().unwrap();
    let mut conn = rustls_ref::ClientConnection::new(Arc::new(cfg), server_name).unwrap();
    let mut sock = TcpStream::connect(format!("localhost:{}", port)).unwrap();
    let mut tls = rustls_ref::Stream::new(&mut conn, &mut sock);

    tls.write_all(ECHO_MSG).unwrap();
    assert_eq!(
        tls.conn.is_jls(),
        Some(true),
        "reference client expected JLS authentication to succeed"
    );

    let mut plaintext = [0u8; 64];
    let len = tls.read(&mut plaintext).unwrap();
    assert_eq!(&plaintext[..len], ECHO_MSG);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Local JLS client must successfully authenticate against a reference
/// `v/0.23.25-1.0.2` JLS server.
#[test]
fn compat_local_client_ref_server() {
    let _ = env_logger::try_init();
    let pki = TestPki::new();
    let port = 14443;

    let server_cfg = ref_server_config(&pki.server_cert_der, &pki.server_key_der);
    let server = thread::spawn(move || run_ref_server(server_cfg, port));

    thread::sleep(time::Duration::from_millis(200));
    let client_cfg = local_client_config(&pki.ca_cert_der);
    run_local_client(client_cfg, port);

    server.join().unwrap();
}

/// Reference `v/0.23.25-1.0.2` JLS client must successfully authenticate
/// against the local JLS server.
#[test]
fn compat_ref_client_local_server() {
    let _ = env_logger::try_init();
    let pki = TestPki::new();
    let port = 14444;

    let server_cfg = local_server_config(&pki.server_cert_der, &pki.server_key_der);
    let server = thread::spawn(move || run_local_server(server_cfg, port));

    thread::sleep(time::Duration::from_millis(200));
    let client_cfg = ref_client_config(&pki.ca_cert_der);
    run_ref_client(client_cfg, port);

    server.join().unwrap();
}
