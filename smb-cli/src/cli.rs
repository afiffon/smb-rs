use crate::{copy::CopyCmd, info::InfoCmd, security::SecurityCmd, watch::WatchCmd};
use clap::{Parser, Subcommand, ValueEnum};
use smb::connection::MultiChannelConfig;
use smb::transport::config::*;
use smb::{
    ClientConfig, ConnectionConfig,
    connection::{AuthMethodsConfig, EncryptionMode},
};
use smb::{Dialect, Guid};

#[derive(Parser)]
#[command(version, about, long_about = None)]
pub struct Cli {
    #[arg(long)]
    pub port: Option<u16>,
    #[arg(short, long)]
    pub timeout: Option<u16>,

    #[arg(long)]
    pub negotiate_smb2_only: bool,
    /// Disables DFS referral resolution.
    #[arg(long)]
    pub no_dfs: bool,

    /// Configures multi-channel support.
    #[arg(long, default_value_t = MultiChannelMode::default())]
    pub multichannel: MultiChannelMode,

    #[cfg(feature = "rdma")]
    #[arg(long)]
    pub rdma_type: Option<RdmaType>,

    /// Opts-in to use SMB compression if the server supports it.
    #[arg(long)]
    pub compress: bool,

    /// Disables NTLM authentication.
    #[arg(long)]
    pub no_ntlm: bool,
    /// Disables Kerberos authentication.
    #[arg(long)]
    pub no_kerberos: bool,

    /// Selects a transport protocol to use.
    #[arg(long)]
    pub use_transport: Option<CliUseTransport>,

    #[arg(short, long)]
    pub username: String,
    #[arg(short, long)]
    pub password: String,

    /// Disables message signing.
    /// This may should only be used when logging in with a guest user.
    #[arg(long)]
    pub disable_message_signing: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(ValueEnum, Copy, Clone, Debug)]
pub enum CliUseTransport {
    Default,
    #[cfg(feature = "netbios-transport")]
    Netbios,
    #[cfg(feature = "quic")]
    Quic,
    #[cfg(feature = "rdma")]
    Rdma,
}

/// Describes the SMB multi-channel mode to use.
#[derive(ValueEnum, Copy, Clone, Debug, Default)]
pub enum MultiChannelMode {
    /// Do not use multichannel, even if the server and client support it.
    #[default]
    None,

    #[cfg(feature = "rdma")]
    /// Create additional server connections and multichannel
    /// only if the server supports RDMA and the client has RDMA-capable NICs.
    RdmaOnly,

    /// Try using multichannel if the server supports it,
    /// and multiple NICs are available on the server.
    Always,
}

impl From<MultiChannelMode> for MultiChannelConfig {
    fn from(mode: MultiChannelMode) -> Self {
        match mode {
            MultiChannelMode::None => MultiChannelConfig::Disabled,
            #[cfg(feature = "rdma")]
            MultiChannelMode::RdmaOnly => MultiChannelConfig::RdmaOnly,
            MultiChannelMode::Always => MultiChannelConfig::Always,
        }
    }
}

impl std::fmt::Display for MultiChannelMode {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            MultiChannelMode::None => write!(f, "none"),
            #[cfg(feature = "rdma")]
            MultiChannelMode::RdmaOnly => write!(f, "rdma-only"),
            MultiChannelMode::Always => write!(f, "always"),
        }
    }
}

#[derive(ValueEnum, Copy, Clone, Debug)]
#[cfg(feature = "rdma")]
pub enum RdmaType {
    /// InfiniBand
    Infiniband,
    /// RDMA over Converged Ethernet (RoCE)
    Roce,
    /// Internet Wide Area RDMA Protocol (iWARP)
    Iwarp,
}

#[cfg(feature = "rdma")]
impl From<RdmaType> for smb::transport::RdmaType {
    fn from(rdma_type: RdmaType) -> smb::transport::RdmaType {
        match rdma_type {
            RdmaType::Infiniband => smb::transport::RdmaType::InfiniBand,
            RdmaType::Roce => smb::transport::RdmaType::RoCE,
            RdmaType::Iwarp => smb::transport::RdmaType::IWarp,
        }
    }
}

impl Cli {
    pub fn make_smb_client_config(&self) -> Result<ClientConfig, &'static str> {
        Ok(ClientConfig {
            dfs: !self.no_dfs,
            #[cfg(feature = "rdma")]
            rdma_type: self.rdma_type.map(|x| x.into()),
            client_guid: Guid::generate(),
            connection: ConnectionConfig {
                max_dialect: Some(Dialect::MAX),
                encryption_mode: EncryptionMode::Allowed,
                timeout: self
                    .timeout
                    .map(|t| std::time::Duration::from_secs(t.into())),
                smb2_only_negotiate: self.negotiate_smb2_only,
                transport: match self
                    .use_transport
                    .as_ref()
                    .unwrap_or(&CliUseTransport::Default)
                {
                    #[cfg(feature = "quic")]
                    CliUseTransport::Quic => TransportConfig::Quic(QuicConfig {
                        local_address: None,
                        cert_validation: QuicCertValidationOptions::PlatformVerifier,
                    }),
                    #[cfg(feature = "rdma")]
                    CliUseTransport::Rdma => TransportConfig::Rdma(RdmaConfig {
                        rdma_type: self
                            .rdma_type
                            .map(|x| x.into())
                            .ok_or("RDMA type must be specified when using RDMA transport")?,
                    }),
                    #[cfg(feature = "netbios-transport")]
                    CliUseTransport::Netbios => TransportConfig::NetBios,
                    CliUseTransport::Default => TransportConfig::Tcp,
                },
                port: self.port,
                auth_methods: AuthMethodsConfig {
                    ntlm: !self.no_ntlm,
                    kerberos: !self.no_kerberos,
                },
                allow_unsigned_guest_access: self.disable_message_signing,
                compression_enabled: self.compress,
                multichannel: self.multichannel.into(),
                ..Default::default()
            },
        })
    }
}

#[derive(Subcommand)]
pub enum Commands {
    /// Copies files to/from a share.
    Copy(CopyCmd),
    /// Retrieves information about a share or a path.
    Info(InfoCmd),
    /// Configures object security
    Security(SecurityCmd),
    /// Watches for changes in a directory.
    Watch(WatchCmd),
}
