use std::sync::Arc;

use crate::Error;
use crate::connection::AuthMethodsConfig;
use crate::connection::connection_info::ConnectionInfo;
use maybe_async::*;
use sspi::{
    AcquireCredentialsHandleResult, AuthIdentity, AuthIdentityBuffers, BufferType,
    ClientRequestFlags, CredentialUse, DataRepresentation, InitializeSecurityContextResult,
    Negotiate, Ntlm, SecurityBuffer, Sspi, ntlm::NtlmConfig,
};
use sspi::{CredentialsBuffers, NegotiateConfig, SspiImpl, Username};

/// Wraps either a raw NTLM SSP or the SPNEGO `Negotiate` SSP.
///
/// `Negotiate` is required when Kerberos may be selected. For NTLM-only flows we use
/// `Ntlm` directly: sspi >= 0.18.8 wraps NTLM in SPNEGO via `Negotiate`, and Samba (at
/// least the test image) rejects the resulting AUTHENTICATE — see sspi-rs#600.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
enum Ssp {
    Ntlm {
        ssp: Ntlm,
        cred_handle: AcquireCredentialsHandleResult<Option<AuthIdentityBuffers>>,
    },
    Negotiate {
        ssp: Box<Negotiate>,
        cred_handle: AcquireCredentialsHandleResult<Option<CredentialsBuffers>>,
    },
}

#[derive(Debug)]
pub struct Authenticator {
    server_hostname: String,
    user_name: Username,

    ssp: Ssp,
    current_state: Option<InitializeSecurityContextResult>,
}

impl Authenticator {
    pub fn build(
        identity: AuthIdentity,
        conn_info: &Arc<ConnectionInfo>,
    ) -> crate::Result<Authenticator> {
        let client_computer_name = conn_info
            .config
            .client_name
            .as_ref()
            .unwrap_or(&String::from("smb-rs"))
            .clone();
        let user_name = identity.username.clone();

        let use_negotiate = cfg!(feature = "kerberos") && conn_info.config.auth_methods.kerberos;
        let ssp = if use_negotiate {
            let mut negotiate_ssp = Negotiate::new_client(NegotiateConfig::new(
                Box::new(NtlmConfig::new(client_computer_name.clone())),
                Some(Self::get_available_ssp_pkgs(&conn_info.config.auth_methods)),
                client_computer_name,
            ))?;
            let cred_handle = negotiate_ssp
                .acquire_credentials_handle()
                .with_credential_use(CredentialUse::Outbound)
                .with_auth_data(&sspi::Credentials::AuthIdentity(identity))
                .execute(&mut negotiate_ssp)?;
            Ssp::Negotiate {
                ssp: Box::new(negotiate_ssp),
                cred_handle,
            }
        } else {
            let mut ntlm_ssp = Ntlm::with_config(NtlmConfig::new(client_computer_name));
            let cred_handle = ntlm_ssp
                .acquire_credentials_handle()
                .with_credential_use(CredentialUse::Outbound)
                .with_auth_data(&identity)
                .execute(&mut ntlm_ssp)?;
            Ssp::Ntlm {
                ssp: ntlm_ssp,
                cred_handle,
            }
        };

        Ok(Authenticator {
            server_hostname: conn_info.server_name.clone(),
            ssp,
            current_state: None,
            user_name,
        })
    }

    pub fn user_name(&self) -> &Username {
        &self.user_name
    }

    pub fn is_authenticated(&self) -> crate::Result<bool> {
        if self.current_state.is_none() {
            return Ok(false);
        }
        Ok(self.current_state.as_ref().unwrap().status == sspi::SecurityStatus::Ok)
    }

    pub fn session_key(&self) -> crate::Result<[u8; 16]> {
        let key_info = match &self.ssp {
            Ssp::Ntlm { ssp, .. } => ssp.query_context_session_key()?,
            Ssp::Negotiate { ssp, .. } => ssp.query_context_session_key()?,
        };
        let k = &key_info.session_key.as_ref()[..16];
        Ok(k.try_into().unwrap())
    }

    fn make_sspi_target_name(server_fqdn: &str) -> String {
        format!("cifs/{server_fqdn}")
    }

    fn get_context_requirements() -> ClientRequestFlags {
        ClientRequestFlags::DELEGATE
            | ClientRequestFlags::MUTUAL_AUTH
            | ClientRequestFlags::INTEGRITY
            | ClientRequestFlags::FRAGMENT_TO_FIT
            | ClientRequestFlags::USE_SESSION_KEY
    }

    const SSPI_REQ_DATA_REPRESENTATION: DataRepresentation = DataRepresentation::Native;

    #[maybe_async]
    pub async fn next(&mut self, gss_token: &[u8]) -> crate::Result<Vec<u8>> {
        if self.is_authenticated()? {
            return Err(Error::InvalidState("Authentication already done.".into()));
        }

        if self.current_state.is_some()
            && self.current_state.as_ref().unwrap().status != sspi::SecurityStatus::ContinueNeeded
        {
            return Err(Error::InvalidState(
                "NTLM GSS session is not in a state to process next token.".into(),
            ));
        }

        let mut output_buffer = vec![SecurityBuffer::new(Vec::new(), BufferType::Token)];
        let mut input_buffers =
            vec![SecurityBuffer::new(gss_token.to_owned(), BufferType::Token)];
        let target_name = Self::make_sspi_target_name(&self.server_hostname);

        let result = match &mut self.ssp {
            Ssp::Ntlm { ssp, cred_handle } => {
                let mut builder = ssp
                    .initialize_security_context()
                    .with_credentials_handle(&mut cred_handle.credentials_handle)
                    .with_context_requirements(Self::get_context_requirements())
                    .with_target_data_representation(Self::SSPI_REQ_DATA_REPRESENTATION)
                    .with_output(&mut output_buffer)
                    .with_input(&mut input_buffers);
                // The NTLM generator never suspends — it has no network calls — so
                // `resolve_to_result` completes synchronously.
                ssp.initialize_security_context_impl(&mut builder)?
                    .resolve_to_result()?
            }
            Ssp::Negotiate { ssp, cred_handle } => {
                let mut builder = ssp
                    .initialize_security_context()
                    .with_credentials_handle(&mut cred_handle.credentials_handle)
                    .with_context_requirements(Self::get_context_requirements())
                    .with_target_data_representation(Self::SSPI_REQ_DATA_REPRESENTATION)
                    .with_output(&mut output_buffer)
                    .with_input(&mut input_buffers);
                if cfg!(feature = "kerberos") {
                    builder = builder.with_target_name(&target_name);
                }
                let mut generator = ssp.initialize_security_context_impl(&mut builder)?;
                // Kerberos requires a network client to be set up.
                // We avoid compiling with the network client if kerberos is not enabled,
                // so be sure to avoid using it in that case.
                #[cfg(feature = "kerberos")]
                {
                    use super::sspi_network_client::ReqwestNetworkClient;
                    #[cfg(feature = "async")]
                    {
                        Self::_resolve_with_async_client(
                            &mut generator,
                            &mut ReqwestNetworkClient::new(),
                        )
                        .await?
                    }
                    #[cfg(not(feature = "async"))]
                    {
                        generator.resolve_with_client(&ReqwestNetworkClient {})?
                    }
                }
                #[cfg(not(feature = "kerberos"))]
                {
                    generator.resolve_to_result()?
                }
            }
        };

        self.current_state = Some(result);

        let output_buffer = output_buffer
            .pop()
            .ok_or_else(|| Error::InvalidState("SSPI output buffer is empty.".to_string()))?
            .buffer;

        Ok(output_buffer)
    }

    /// This method, despite being very similar to [`sspi::generator::Generator::resolve_with_async_client`],
    /// adds the `Send` bound to the network client, which is required for our async code.
    ///
    /// See [<https://github.com/Devolutions/sspi-rs/issues/526>] for more details.
    #[cfg(all(feature = "kerberos", feature = "async"))]
    async fn _resolve_with_async_client(
        generator: &mut sspi::generator::GeneratorInitSecurityContext<'_>, // Generator returned from `sspi-rs`.
        network_client: &mut super::sspi_network_client::ReqwestNetworkClient, // Your custom network client.
    ) -> sspi::Result<InitializeSecurityContextResult> {
        let mut state = generator.start();

        use sspi::generator::GeneratorState::*;
        loop {
            match state {
                Suspended(ref request) => {
                    state = generator.resume(network_client.send(request).await);
                }
                Completed(client_state) => {
                    return client_state;
                }
            }
        }
    }

    fn get_available_ssp_pkgs(config: &AuthMethodsConfig) -> String {
        let krb_pku2u_config = if cfg!(feature = "kerberos") && config.kerberos {
            "kerberos,!pku2u"
        } else {
            "!kerberos,!pku2u"
        };
        let ntlm_config = if config.ntlm { "ntlm" } else { "!ntlm" };
        format!("{ntlm_config},{krb_pku2u_config}")
    }
}
