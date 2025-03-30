use std::sync::Arc;

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;

use rustls::pki_types::ServerName;
use rustls::{RootCertStore};

fn start_connection(config: &Arc<rustls::ClientConfig>, domain_name: &str, ip:&str) {
    let server_name = ServerName::try_from(domain_name)
        .expect("invalid DNS name")
        .to_owned();
    let mut conn = rustls::ClientConnection::new(Arc::clone(config), server_name).unwrap();
    let mut sock = TcpStream::connect(format!("{}", ip)).unwrap();
    sock.set_nodelay(true).unwrap();
    let request = format!(
        "GET / HTTP/1.1\r\n\
         Host: {}\r\n\
         Connection: close\r\n\
         Accept-Encoding: identity\r\n\
         \r\n",
        domain_name
    );

    // If early data is available with this server, then early_data()
    // will yield Some(WriteEarlyData) and WriteEarlyData implements
    // io::Write.  Use this to send the request.
    if let Some(mut early_data) = conn.early_data() {
        early_data
            .write_all(request.as_bytes())
            .unwrap();
        println!("  * 0-RTT request sent");
    }

    let mut stream = rustls::Stream::new(&mut conn, &mut sock);

    // Complete handshake.
    stream.flush().unwrap();

    // If we didn't send early data, or the server didn't accept it,
    // then send the request as normal.
    if !stream.conn.is_early_data_accepted() {
        stream
            .write_all(request.as_bytes())
            .unwrap();
        println!("  * Normal request sent");
    } else {
        println!("  * 0-RTT data accepted");
    }

    let mut first_response_line = String::new();
    BufReader::new(stream)
        .read_line(&mut first_response_line)
        .unwrap();
    println!("  * Server response: {:?}", first_response_line);
}

fn main() {
    env_logger::init();
    let root_store = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.into(),
    };

    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    // Enable early data.
    config.enable_early_data = true;
    let config = Arc::new(config);

    // Do two connections. The first will be a normal request, the
    // second will use early data if the server supports it.

    println!("* Sending first request:");
    start_connection(&config, "codepen.io","104.17.14.48:443");
    println!("* Sending second request:");
    start_connection(&config, "codepen.io","104.16.176.44:443");

}
