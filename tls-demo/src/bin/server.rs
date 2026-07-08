//! Deck TLS 1.3 demo **server** (draft-sullivan-tls-xof-ciphers-00, Stage 5).
//!
//! Listens on `127.0.0.1:<port>` (default 4443), completes a TLS 1.3 handshake
//! on a deck cipher suite (`0xFF01..=0xFF05`), and echoes one line per
//! connection. Honors `SSLKEYLOGFILE` (NSS key-log format), so a captured
//! session can be decrypted in Wireshark.
//!
//! Usage: `SSLKEYLOGFILE=keys.log cargo run -p tls-demo --bin deck-server -- [port]`

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;

use rustls::{KeyLogFile, ServerConnection, Stream};
use tls_demo::{demo_server_config, self_signed_cert};

fn main() {
    let port: u16 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(4443);

    let (certs, key) = self_signed_cert();
    let config = Arc::new(demo_server_config(certs, key, Arc::new(KeyLogFile::new())));

    let listener = TcpListener::bind(("127.0.0.1", port)).expect("bind");
    println!(
        "deck-server: listening on {} (set SSLKEYLOGFILE to capture keys)",
        listener.local_addr().expect("local_addr"),
    );

    for stream in listener.incoming() {
        let mut sock = match stream {
            Ok(s) => s,
            Err(e) => {
                eprintln!("accept error: {e}");
                continue;
            }
        };
        let mut conn = match ServerConnection::new(config.clone()) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("server conn error: {e}");
                continue;
            }
        };

        // Echo one message, driving the handshake on first I/O.
        let mut line = Vec::new();
        {
            let mut tls = Stream::new(&mut conn, &mut sock);
            let mut buf = [0u8; 4096];
            match tls.read(&mut buf) {
                Ok(n) if n > 0 => {
                    line.extend_from_slice(&buf[..n]);
                    let _ = tls.write_all(&buf[..n]).and_then(|()| tls.flush());
                }
                Ok(_) => {}
                Err(e) => eprintln!("io error: {e}"),
            }
        }

        report(&conn);
        println!(
            "  echoed {} bytes: {:?}",
            line.len(),
            String::from_utf8_lossy(&line).trim_end(),
        );
    }
}

fn report(conn: &ServerConnection) {
    if let Some(cs) = conn.negotiated_cipher_suite() {
        println!("  suite: {:#06x}", u16::from(cs.suite()));
    }
    if let Some(g) = conn.negotiated_key_exchange_group() {
        println!("  group: {:?}", g.name());
    }
    if let Some(alpn) = conn.alpn_protocol() {
        println!("  alpn:  {:?}", String::from_utf8_lossy(alpn));
    }
}
