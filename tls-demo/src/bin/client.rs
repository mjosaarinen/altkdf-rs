//! Deck TLS 1.3 demo **client** (draft-sullivan-tls-xof-ciphers-00).
//!
//! Connects to `127.0.0.1:<port>` (default 4443), completes a TLS 1.3 handshake
//! on a deck cipher suite, sends a line and prints the echo, then prints an
//! exported keying-material value (draft §5.6). Honors `SSLKEYLOGFILE`.
//!
//! Usage: `SSLKEYLOGFILE=keys.log cargo run -p tls-demo --bin deck-client -- [port]`

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

use rustls::pki_types::ServerName;
use rustls::{ClientConnection, KeyLogFile, Stream};
use tls_demo::demo_client_config;

fn main() {
    let port: u16 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(4443);

    let config = Arc::new(demo_client_config(Arc::new(KeyLogFile::new())));
    let server_name = ServerName::try_from("localhost").unwrap();
    let mut sock = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    let mut conn = ClientConnection::new(config, server_name).expect("client conn");

    let msg = b"hello from deck-client\n";
    {
        let mut tls = Stream::new(&mut conn, &mut sock);
        tls.write_all(msg).expect("write");
        tls.flush().expect("flush");
        let mut buf = [0u8; 4096];
        let n = tls.read(&mut buf).expect("read");
        print!("server echoed: {}", String::from_utf8_lossy(&buf[..n]));
    }

    if let Some(cs) = conn.negotiated_cipher_suite() {
        println!("suite: {:#06x}", u16::from(cs.suite()));
    }
    if let Some(g) = conn.negotiated_key_exchange_group() {
        println!("group: {:?}", g.name());
    }
    println!(
        "alpn:  {:?}",
        conn.alpn_protocol()
            .map(|a| String::from_utf8_lossy(a).into_owned()),
    );

    // Exported keying material (draft §5.6): keyed by the exporter master secret.
    let exported = conn
        .export_keying_material([0u8; 32], b"deck-demo exporter", Some(b"context"))
        .expect("export_keying_material");
    println!("exporter: {}", hex(&exported));
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
