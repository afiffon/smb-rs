use thiserror::Error;

#[derive(Error, Debug)]
pub enum QuicError {
    #[error("QUIC not connected")]
    NotConnected,
    #[error("QUIC start connect error: {0}")]
    ConnectError(#[from] quinn::ConnectError),
    #[error("QUIC connection error: {0}")]
    ConnectionError(#[from] quinn::ConnectionError),
    #[error("QUIC write error: {0}")]
    WriteError(#[from] quinn::WriteError),
    #[error("QUIC read error: {0}")]
    ReadError(#[from] quinn::ReadExactError),
    #[error("QUIC IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("TLS error: {0}")]
    TlsError(#[from] rustls::Error),
    #[error("invalid certificate fingerprint: {0}")]
    InvalidFingerprint(String),
    #[error("No cipher suites found")]
    NoCipherSuitesFound(#[from] quinn::crypto::rustls::NoInitialCipherSuite),
}

pub type Result<T> = std::result::Result<T, QuicError>;
