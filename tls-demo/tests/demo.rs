//! Stage 5 wire verification: a live deck TLS 1.3 handshake over a **real TCP
//! loopback** (not the in-memory transport of the Stage 4 test), exercising ALPN,
//! a two-way echo across a record boundary, a live KeyUpdate (draft §5.4), the
//! exporter (draft §5.6), and a key-log cross-check that both peers derived
//! identical deck secrets (draft §2.1, §5.3, §7.3).

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;

use rustls::pki_types::ServerName;
use rustls::{ClientConnection, ServerConnection, Stream};
use tls_demo::{
    demo_client_config, demo_server_config, self_signed_cert, CapturingKeyLog, DEMO_ALPN,
};

const MSG1: &[u8] = b"deck-demo round 1: hello over a real socket";
const EXP_LABEL: &[u8] = b"EXPERIMENTAL deck-demo exporter";
const EXP_CONTEXT: &[u8] = b"stage-5 context";

/// Round-2 payload length: larger than one 16 KB TLS record, so it crosses a
/// record boundary. The payload is sent *after* a KeyUpdate.
const BIG_LEN: usize = 20_000;

/// A `BIG_LEN`-byte payload for round 2.
fn big_msg() -> Vec<u8> {
    (0..BIG_LEN as u32).map(|i| i as u8).collect()
}

/// The five NSS labels both peers must log with identical 64-octet secrets.
const CROSS_CHECK_LABELS: [&str; 5] = [
    "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
    "SERVER_HANDSHAKE_TRAFFIC_SECRET",
    "CLIENT_TRAFFIC_SECRET_0",
    "SERVER_TRAFFIC_SECRET_0",
    "EXPORTER_SECRET",
];

struct PeerReport {
    suite: u16,
    alpn: Option<Vec<u8>>,
    exporter: [u8; 32],
}

/// Server side: read exactly `len` plaintext bytes and echo them back.
fn echo_exact(conn: &mut ServerConnection, sock: &mut TcpStream, len: usize) {
    let mut tls = Stream::new(conn, sock);
    let mut buf = vec![0u8; len];
    tls.read_exact(&mut buf).expect("server read_exact");
    tls.write_all(&buf).expect("server write");
    tls.flush().expect("server flush");
}

/// Client side: send `msg`, then read exactly `msg.len()` echoed bytes back.
fn send_recv(conn: &mut ClientConnection, sock: &mut TcpStream, msg: &[u8]) -> Vec<u8> {
    let mut tls = Stream::new(conn, sock);
    tls.write_all(msg).expect("client write");
    tls.flush().expect("client flush");
    let mut buf = vec![0u8; msg.len()];
    tls.read_exact(&mut buf).expect("client read_exact");
    buf
}

#[test]
fn live_socket_handshake_keyupdate_exporter_and_keylog_crosscheck() {
    let (certs, key) = self_signed_cert();
    let server_klog = CapturingKeyLog::new();
    let client_klog = CapturingKeyLog::new();

    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
    let port = listener.local_addr().unwrap().port();

    // ---- server thread ----
    let server_config = Arc::new(demo_server_config(certs, key, server_klog.clone()));
    let server = thread::spawn(move || -> PeerReport {
        let (mut sock, _) = listener.accept().expect("accept");
        let mut conn = ServerConnection::new(server_config).expect("server conn");

        echo_exact(&mut conn, &mut sock, MSG1.len()); // round 1
        echo_exact(&mut conn, &mut sock, BIG_LEN); // round 2 (post-KeyUpdate)

        let exporter = conn
            .export_keying_material([0u8; 32], EXP_LABEL, Some(EXP_CONTEXT))
            .expect("server export");
        PeerReport {
            suite: conn
                .negotiated_cipher_suite()
                .map(|c| u16::from(c.suite()))
                .unwrap(),
            alpn: conn.alpn_protocol().map(<[u8]>::to_vec),
            exporter,
        }
    });

    // ---- client (main thread) ----
    let client_config = Arc::new(demo_client_config(client_klog.clone()));
    let mut sock = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    let mut conn = ClientConnection::new(client_config, ServerName::try_from("localhost").unwrap())
        .expect("client conn");

    // Round 1 echo.
    assert_eq!(send_recv(&mut conn, &mut sock, MSG1), MSG1, "round 1 echo");

    // Live KeyUpdate (draft §5.4), then round 2 across a record boundary.
    conn.refresh_traffic_keys().expect("key update");
    let big = big_msg();
    assert_eq!(
        send_recv(&mut conn, &mut sock, &big),
        big,
        "round 2 echo after KeyUpdate",
    );

    let client_exporter = conn
        .export_keying_material([0u8; 32], EXP_LABEL, Some(EXP_CONTEXT))
        .expect("client export");
    let client_suite = conn
        .negotiated_cipher_suite()
        .map(|c| u16::from(c.suite()))
        .unwrap();
    let client_alpn = conn.alpn_protocol().map(<[u8]>::to_vec);

    let server_report = server.join().expect("server thread");

    // --- negotiation agreement ---
    assert_eq!(client_suite, server_report.suite, "same negotiated suite");
    assert!(
        (0xFF01..=0xFF05).contains(&client_suite),
        "negotiated a deck suite, got {client_suite:#06x}",
    );
    assert_eq!(client_alpn.as_deref(), Some(DEMO_ALPN), "client ALPN");
    assert_eq!(
        server_report.alpn.as_deref(),
        Some(DEMO_ALPN),
        "server ALPN"
    );

    // --- exporter agreement (draft §5.6) ---
    assert_eq!(
        client_exporter, server_report.exporter,
        "both peers derive the same exported keying material",
    );

    // --- key-log cross-check: both peers logged identical 64-octet deck secrets ---
    for label in CROSS_CHECK_LABELS {
        let c = client_klog
            .secret_for(label)
            .unwrap_or_else(|| panic!("client did not log {label}"));
        let s = server_klog
            .secret_for(label)
            .unwrap_or_else(|| panic!("server did not log {label}"));
        assert_eq!(c, s, "client and server logged the same {label}");
        assert_eq!(c.len(), 64, "{label} is a 64-octet deck secret (SecretLen)");
    }

    // Same connection: client_random agrees across both logs.
    let cr_client = client_klog.lines()[0].client_random.clone();
    let cr_server = server_klog.lines()[0].client_random.clone();
    assert_eq!(cr_client, cr_server, "same client_random in both key logs");
    assert_eq!(cr_client.len(), 32);
}
