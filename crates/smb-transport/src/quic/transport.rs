//! QUIC transport implementation for SMB.
//!
//! This module uses the [quinn](https://docs.rs/quinn/latest/quinn/) crate to implement the QUIC transport protocol for SMB.
//! Therefore, it should only be used when async features are enabled.

// quic => async
#[cfg(all(not(feature = "async"), feature = "quic"))]
compile_error!(
    "QUIC transport requires the async feature to be enabled. \
    Please enable the async feature in your Cargo.toml."
);

use std::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};

use rustls::crypto::CryptoProvider;

use super::error::*;
use crate::{
    QuicConfig, TransportError,
    traits::{SmbTransport, SmbTransportRead, SmbTransportWrite},
};
use futures_core::future::BoxFuture;
use futures_util::FutureExt;
use quinn::{Endpoint, crypto::rustls::QuicClientConfig};
use rustls::pki_types::CertificateDer;
use rustls_platform_verifier::ConfigVerifierExt;
use tokio::select;

pub struct QuicTransport {
    recv_stream: Option<quinn::RecvStream>,
    send_stream: Option<quinn::SendStream>,

    remote_address: Option<SocketAddr>,

    endpoint: Endpoint,
    timeout: Duration,
}

const LOCALHOST_V4: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0));

static CRYPTO_PROVIDER_INSTALLED: AtomicBool = AtomicBool::new(false);

impl QuicTransport {
    pub fn new(quic_config: &QuicConfig, timeout: Duration) -> crate::error::Result<Self> {
        Self::_init_crypto_provider();

        let client_addr = quic_config.local_address.unwrap_or(LOCALHOST_V4);
        let mut endpoint = Endpoint::client(client_addr)?;
        endpoint.set_default_client_config(Self::make_client_config(quic_config)?);
        Ok(Self {
            recv_stream: None,
            send_stream: None,
            remote_address: None,
            endpoint,
            timeout,
        })
    }

    fn _init_crypto_provider() {
        if CRYPTO_PROVIDER_INSTALLED.swap(true, std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        // A process-level provider can only be installed once, and something
        // else may have got there first: any other library using rustls
        // installs one, and rustls itself installs the crate-feature default
        // the first time a config is built. That is not an error - it just
        // means there is already a provider to use - so the result is ignored
        // rather than unwrapped.
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    fn make_client_config(quic_config: &QuicConfig) -> Result<quinn::ClientConfig> {
        // Pinning replaces the whole verifier rather than adding a root, so it
        // is built separately from the two trust-store based options.
        if let super::config::QuicCertValidationOptions::PinnedFingerprints(fingerprints) =
            &quic_config.cert_validation
        {
            return Self::make_pinned_client_config(fingerprints);
        }

        let mut quic_client_config = match &quic_config.cert_validation {
            super::config::QuicCertValidationOptions::PlatformVerifier => {
                rustls::ClientConfig::with_platform_verifier()?
            }
            // Handled above: pinning replaces the verifier entirely.
            super::config::QuicCertValidationOptions::PinnedFingerprints(_) => {
                unreachable!("pinned fingerprints take the dedicated path above")
            }
            super::config::QuicCertValidationOptions::CustomRootCerts(items) => {
                let mut roots = rustls::RootCertStore::empty();
                for cert in items {
                    match std::fs::read(cert) {
                        Ok(cert) => {
                            roots.add(CertificateDer::from(cert))?;
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => {
                            log::info!("local server certificate not found");
                        }
                        Err(e) => {
                            log::error!("failed to open local server certificate: {e}");
                        }
                    }
                }
                rustls::ClientConfig::builder()
                    .with_root_certificates(roots)
                    .with_no_client_auth()
            }
        };
        quic_client_config.alpn_protocols = vec![b"smb".to_vec()];
        Ok(quinn::ClientConfig::new(Arc::new(
            QuicClientConfig::try_from(quic_client_config)?,
        )))
    }

    /// A client config that trusts exactly the pinned certificates.
    fn make_pinned_client_config(fingerprints: &[String]) -> Result<quinn::ClientConfig> {
        let parsed = fingerprints
            .iter()
            .map(|f| super::fingerprint::parse(f))
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(QuicError::InvalidFingerprint)?;

        if parsed.is_empty() {
            return Err(QuicError::InvalidFingerprint(
                "no fingerprints were given to pin".to_string(),
            ));
        }

        // The process-wide default is installed by `_init_crypto_provider`.
        let provider = CryptoProvider::get_default()
            .cloned()
            .unwrap_or_else(|| Arc::new(rustls::crypto::ring::default_provider()));

        let verifier = super::fingerprint::PinnedFingerprintVerifier::new(parsed, provider.clone());

        let mut quic_client_config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth();
        quic_client_config.alpn_protocols = vec![b"smb".to_vec()];

        Ok(quinn::ClientConfig::new(Arc::new(
            QuicClientConfig::try_from(quic_client_config)?,
        )))
    }

    async fn inner_connect(
        &mut self,
        server_name: &str,
        server_address: SocketAddr,
    ) -> crate::error::Result<()> {
        let connection = self
            .endpoint
            .connect(server_address, server_name)
            .map_err(QuicError::from)?
            .await
            .map_err(|e| match e {
                quinn::ConnectionError::TimedOut => {
                    log::error!("Connection timed out after {:?}", self.timeout);
                    crate::TransportError::Timeout(self.timeout)
                }
                _ => {
                    log::error!("Failed to connect to {server_name} at {server_address}: {e}");
                    QuicError::ConnectionError(e).into()
                }
            })?;
        let remote_address = connection.remote_address();
        let (send, recv) = connection.open_bi().await.map_err(|e| {
            log::error!("Failed to open bidirectional stream: {e}");
            QuicError::ConnectionError(e)
        })?;

        self.send_stream = Some(send);
        self.recv_stream = Some(recv);
        self.remote_address = Some(remote_address);
        Ok(())
    }

    pub fn can_read(&self) -> bool {
        self.recv_stream.is_some()
    }

    pub fn can_write(&self) -> bool {
        self.send_stream.is_some()
    }

    async fn send_raw(&mut self, buf: &[u8]) -> Result<()> {
        let send_stream = self.send_stream.as_mut().ok_or(QuicError::NotConnected)?;
        send_stream.write_all(buf).await?;
        Ok(())
    }

    async fn receive_exact(&mut self, out_buf: &mut [u8]) -> Result<()> {
        let recv_stream = self.recv_stream.as_mut().ok_or(QuicError::NotConnected)?;
        recv_stream.read_exact(out_buf).await?;
        Ok(())
    }
}

impl SmbTransport for QuicTransport {
    fn connect<'a>(
        &'a mut self,
        server_name: &'a str,
        server_address: SocketAddr,
    ) -> BoxFuture<'a, crate::error::Result<()>> {
        let timeout = self.timeout;
        async move {
            select! {
                res = self.inner_connect(server_name, server_address) => {
                    res
                },
                _ = tokio::time::sleep(timeout) => {
                    log::debug!("QUIC Connection timed out after {:?}", timeout);
                    Err(crate::TransportError::Timeout(timeout))
                }
            }
        }
        .boxed()
    }

    fn split(
        mut self: Box<Self>,
    ) -> crate::error::Result<(Box<dyn SmbTransportRead>, Box<dyn SmbTransportWrite>)> {
        if !self.can_read() || !self.can_write() {
            return Err(crate::TransportError::NotConnected);
        }
        let (recv_stream, send_stream) = (
            self.recv_stream.take().unwrap(),
            self.send_stream.take().unwrap(),
        );

        // TODO: Is this actually needed?
        let endpoint_clone = self.endpoint.clone();

        Ok((
            Box::new(Self {
                recv_stream: Some(recv_stream),
                send_stream: None,
                remote_address: self.remote_address,
                endpoint: self.endpoint,
                timeout: self.timeout,
            }),
            Box::new(Self {
                recv_stream: None,
                send_stream: Some(send_stream),
                remote_address: self.remote_address,
                endpoint: endpoint_clone,
                timeout: self.timeout,
            }),
        ))
    }

    fn default_port(&self) -> u16 {
        443
    }

    fn remote_address(&self) -> crate::error::Result<SocketAddr> {
        self.remote_address.ok_or(TransportError::NotConnected)
    }
}

impl SmbTransportWrite for QuicTransport {
    #[cfg(feature = "async")]
    fn send_raw<'a>(&'a mut self, buf: &'a [u8]) -> BoxFuture<'a, crate::error::Result<()>> {
        async { Ok(self.send_raw(buf).await?) }.boxed()
    }
    #[cfg(not(feature = "async"))]
    fn send_raw(&mut self, buf: &[u8]) -> Result<()> {
        unimplemented!("QUIC transport requires async feature to be enabled");
    }
}

impl SmbTransportRead for QuicTransport {
    #[cfg(feature = "async")]
    fn receive_exact<'a>(
        &'a mut self,
        out_buf: &'a mut [u8],
    ) -> BoxFuture<'a, crate::error::Result<()>> {
        async { Ok(self.receive_exact(out_buf).await?) }.boxed()
    }
    #[cfg(not(feature = "async"))]
    fn receive_exact(&mut self, out_buf: &mut [u8]) -> Result<Vec<u8>> {
        unimplemented!("QUIC transport requires async feature to be enabled");
    }
}
