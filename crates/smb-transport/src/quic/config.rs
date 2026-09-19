use std::net::SocketAddr;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub enum QuicCertValidationOptions {
    /// Use the default platform verifier for the certificate.
    /// See `quinn::ClientConfig::with_platform_verifier`.
    /// This is the default option.
    #[default]
    PlatformVerifier,
    /// Use a store with the provided root certificates.
    CustomRootCerts(Vec<String>),
    /// Accept the server's certificate only if its SHA-256 fingerprint is one
    /// of these, ignoring the chain and the server name.
    ///
    /// For a server whose certificate cannot chain to a public CA but whose
    /// identity is known in advance - a self-signed certificate on an internal
    /// file server, say. Unlike [`QuicCertValidationOptions::CustomRootCerts`]
    /// nothing has to be copied to the client: a fingerprint is short enough to
    /// pass along by hand.
    ///
    /// Fingerprints are hex, over the certificate's DER encoding, as
    /// `openssl x509 -fingerprint -sha256` prints them. An optional `sha256:`
    /// prefix and `:` separators are accepted.
    PinnedFingerprints(Vec<String>),
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct QuicConfig {
    pub local_address: Option<SocketAddr>,
    pub cert_validation: QuicCertValidationOptions,
}
