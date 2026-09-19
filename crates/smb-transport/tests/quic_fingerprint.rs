//! Pinning checked against a real QUIC handshake.
//!
//! The unit tests cover parsing; what matters here is the part that only shows
//! up on the wire: that a pinned fingerprint lets a self-signed certificate
//! through, and that the wrong one stops it.

#![cfg(feature = "quic")]

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use smb_transport::{QuicCertValidationOptions, QuicConfig};
use smb_transport::{QuicTransport, SmbTransport};

/// A self-signed server on loopback, and the fingerprint of the certificate it
/// presents.
struct TestServer {
    address: SocketAddr,
    fingerprint: String,
    _endpoint: quinn::Endpoint,
}

fn start_server() -> TestServer {
    let generated =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string(), "127.0.0.1".to_string()])
            .expect("a self-signed certificate");

    let certificate = generated.cert.der().clone();
    let fingerprint =
        smb_transport::fingerprint_to_string(&smb_transport::fingerprint_of(&certificate));

    let key = rustls::pki_types::PrivateKeyDer::try_from(generated.signing_key.serialize_der())
        .expect("the generated key");

    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certificate], key)
        .expect("a usable certificate and key");
    tls.alpn_protocols = vec![b"smb".to_vec()];

    let server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls).expect("a QUIC server config"),
    ));

    let endpoint = quinn::Endpoint::server(
        server_config,
        SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
    )
    .expect("a bound endpoint");
    let address = endpoint.local_addr().expect("a local address");

    // Accept in the background; the handshake is all these tests look at.
    let accepting = endpoint.clone();
    tokio::spawn(async move {
        while let Some(incoming) = accepting.accept().await {
            tokio::spawn(async move {
                let _ = incoming.await;
            });
        }
    });

    TestServer {
        address,
        fingerprint,
        _endpoint: endpoint,
    }
}

async fn connect_with(
    fingerprints: Vec<String>,
    server: &TestServer,
) -> Result<(), smb_transport::TransportError> {
    let config = QuicConfig {
        local_address: None,
        cert_validation: QuicCertValidationOptions::PinnedFingerprints(fingerprints),
    };
    let mut transport = QuicTransport::new(&config, Duration::from_secs(10))?;
    transport.connect("localhost", server.address).await
}

#[tokio::test]
async fn a_pinned_fingerprint_accepts_a_self_signed_certificate() {
    let server = start_server();
    connect_with(vec![server.fingerprint.clone()], &server)
        .await
        .expect("the pinned certificate should be accepted");
}

/// The whole point: a certificate that is not the pinned one is refused, even
/// though it is otherwise a perfectly well-formed certificate.
#[tokio::test]
async fn a_different_fingerprint_is_refused() {
    let server = start_server();
    let wrong = "sha256:".to_string() + &"00".repeat(32);

    let result = connect_with(vec![wrong], &server).await;
    assert!(
        result.is_err(),
        "an unpinned certificate should not be accepted"
    );
}

/// Several pins are allowed, so a server can be rotated without a flag day.
#[tokio::test]
async fn any_of_several_pins_may_match() {
    let server = start_server();
    let pins = vec![
        "sha256:".to_string() + &"11".repeat(32),
        server.fingerprint.clone(),
    ];
    connect_with(pins, &server)
        .await
        .expect("a matching pin anywhere in the list should be accepted");
}

#[tokio::test]
async fn a_malformed_fingerprint_is_reported_before_connecting() {
    let server = start_server();
    let result = connect_with(vec!["not-a-fingerprint".to_string()], &server).await;
    let message = result.expect_err("a malformed pin is an error").to_string();
    assert!(
        message.contains("fingerprint"),
        "the error should name the problem, got: {message}"
    );
}
