//! Certificate pinning by SHA-256 fingerprint.
//!
//! Pinning a fingerprint is useful wherever the server's certificate cannot be
//! chained to a public CA but its identity is known ahead of time: a self-signed
//! certificate on an internal file server, or a short-lived share whose operator
//! reads the fingerprint out over another channel.
//!
//! It is stronger than trust-on-first-use, which accepts whatever it sees the
//! first time, and unlike [`super::config::QuicCertValidationOptions::CustomRootCerts`]
//! it needs no file to be copied to the client - a fingerprint is short enough
//! to paste into a command line or read aloud.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as TlsError, SignatureScheme};
use sha2::{Digest, Sha256};

/// A SHA-256 certificate fingerprint.
pub(crate) const FINGERPRINT_LEN: usize = 32;

/// Parse a SHA-256 fingerprint written as hex.
///
/// Permissive about how it is written, because these get copied by hand: an
/// optional `sha256:` prefix is accepted, as are `:` and `-` separators,
/// whitespace, and either case. What it will not accept is the wrong length,
/// which is the mistake worth catching.
pub(crate) fn parse(fingerprint: &str) -> Result<[u8; FINGERPRINT_LEN], String> {
    let trimmed = fingerprint.trim();
    let body = trimmed
        .strip_prefix("sha256:")
        .or_else(|| trimmed.strip_prefix("SHA256:"))
        .unwrap_or(trimmed);

    let hex: String = body
        .chars()
        .filter(|c| !matches!(c, ':' | '-' | ' ' | '\t'))
        .collect();

    if hex.len() != FINGERPRINT_LEN * 2 {
        return Err(format!(
            "a SHA-256 fingerprint is {} hex characters, got {} in {fingerprint:?}",
            FINGERPRINT_LEN * 2,
            hex.len()
        ));
    }

    let mut out = [0u8; FINGERPRINT_LEN];
    for (index, byte) in out.iter_mut().enumerate() {
        let pair = &hex[index * 2..index * 2 + 2];
        *byte = u8::from_str_radix(pair, 16)
            .map_err(|_| format!("{pair:?} in {fingerprint:?} is not hexadecimal"))?;
    }
    Ok(out)
}

/// The SHA-256 fingerprint of a certificate, over its DER encoding - the same
/// bytes `openssl x509 -fingerprint -sha256` hashes.
pub fn fingerprint_of(certificate: &CertificateDer<'_>) -> [u8; FINGERPRINT_LEN] {
    let digest = Sha256::digest(certificate.as_ref());
    let mut out = [0u8; FINGERPRINT_LEN];
    out.copy_from_slice(digest.as_slice());
    out
}

/// Render a fingerprint the way this module parses it back.
pub fn fingerprint_to_string(fingerprint: &[u8; FINGERPRINT_LEN]) -> String {
    let mut out = String::with_capacity(FINGERPRINT_LEN * 2 + 7);
    out.push_str("sha256:");
    for byte in fingerprint {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Accepts a server certificate only if its fingerprint is one of the pinned
/// set.
///
/// The certificate chain and the server name are deliberately not checked: the
/// point of pinning one exact certificate is that there is no chain to validate
/// and the name is whatever the operator chose. The handshake signature *is*
/// still verified, which is what proves the peer holds the matching private key
/// rather than merely having a copy of a public certificate.
#[derive(Debug)]
pub(crate) struct PinnedFingerprintVerifier {
    fingerprints: Vec<[u8; FINGERPRINT_LEN]>,
    provider: Arc<CryptoProvider>,
}

impl PinnedFingerprintVerifier {
    pub(crate) fn new(
        fingerprints: Vec<[u8; FINGERPRINT_LEN]>,
        provider: Arc<CryptoProvider>,
    ) -> Self {
        Self {
            fingerprints,
            provider,
        }
    }
}

impl ServerCertVerifier for PinnedFingerprintVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        let actual = fingerprint_of(end_entity);

        // Both sides of this comparison are public, so the constant-time walk is
        // habit rather than necessity; it costs 32 iterations.
        let matched = self.fingerprints.iter().any(|expected| {
            expected
                .iter()
                .zip(actual.iter())
                .fold(0u8, |acc, (a, b)| acc | (a ^ b))
                == 0
        });

        if matched {
            Ok(ServerCertVerified::assertion())
        } else {
            log::error!(
                "server certificate fingerprint {} is not pinned",
                fingerprint_to_string(&actual)
            );
            Err(TlsError::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXPECTED: [u8; FINGERPRINT_LEN] = [
        0x8e, 0xc2, 0x7e, 0x4c, 0x0e, 0xc7, 0x83, 0xbf, 0x4f, 0xa1, 0x2f, 0xc6, 0x96, 0x38, 0x29,
        0x4f, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
        0xee, 0xff,
    ];

    fn canonical() -> String {
        EXPECTED.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn parses_the_spellings_people_actually_paste() {
        let hex = canonical();
        assert_eq!(parse(&hex).unwrap(), EXPECTED);
        assert_eq!(parse(&hex.to_uppercase()).unwrap(), EXPECTED);
        assert_eq!(parse(&format!("sha256:{hex}")).unwrap(), EXPECTED);
        assert_eq!(parse(&format!("SHA256:{hex}")).unwrap(), EXPECTED);
        assert_eq!(parse(&format!("  {hex}  ")).unwrap(), EXPECTED);

        // Colon-separated, the way openssl prints it.
        let colons = EXPECTED
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":");
        assert_eq!(parse(&colons).unwrap(), EXPECTED);
    }

    #[test]
    fn round_trips_through_its_own_rendering() {
        assert_eq!(parse(&fingerprint_to_string(&EXPECTED)).unwrap(), EXPECTED);
    }

    /// A truncated fingerprint would silently pin fewer bits, so length is
    /// checked rather than padded.
    #[test]
    fn rejects_the_wrong_length() {
        let hex = canonical();
        assert!(parse(&hex[..62]).is_err());
        assert!(parse(&format!("{hex}00")).is_err());
        assert!(parse("").is_err());
    }

    #[test]
    fn rejects_non_hexadecimal() {
        let bad = "z".repeat(64);
        assert!(parse(&bad).is_err());
    }

    #[test]
    fn hashes_the_der_bytes() {
        let certificate = CertificateDer::from(vec![1, 2, 3, 4]);
        let expected = Sha256::digest([1, 2, 3, 4]);
        assert_eq!(fingerprint_of(&certificate).as_slice(), expected.as_slice());
    }
}
