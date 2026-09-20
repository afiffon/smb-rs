use std::sync::Arc;

use crate::Error;
use crate::connection::AuthMethodsConfig;
use crate::connection::connection_info::ConnectionInfo;
use maybe_async::maybe_async;
use sspi::{
    AcquireCredentialsHandleResult, AuthIdentity, BufferType, ClientRequestFlags, CredentialUse,
    DataRepresentation, InitializeSecurityContextResult, Negotiate, SecurityBuffer, Sspi,
    ntlm::NtlmConfig,
};
use sspi::{CredentialsBuffers, NegotiateConfig, SspiImpl, Username};

#[derive(Debug)]
pub struct Authenticator {
    server_hostname: String,
    user_name: Username,

    ssp: Negotiate,
    cred_handle: AcquireCredentialsHandleResult<Option<CredentialsBuffers>>,
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
        let mut negotiate_ssp = Negotiate::new_client(NegotiateConfig::new(
            Box::new(NtlmConfig::default()),
            Some(Self::get_available_ssp_pkgs(&conn_info.config.auth_methods)),
            client_computer_name,
        ))?;
        let user_name = identity.username.clone();

        let cred_handle = negotiate_ssp
            .acquire_credentials_handle()
            .with_credential_use(CredentialUse::Outbound)
            .with_auth_data(&sspi::Credentials::AuthIdentity(identity.clone()))
            .execute(&mut negotiate_ssp)?;

        Ok(Authenticator {
            server_hostname: conn_info.server_name.clone(),
            ssp: negotiate_ssp,
            cred_handle,
            current_state: None,
            user_name,
        })
    }

    pub fn user_name(&self) -> &Username {
        &self.user_name
    }

    pub fn is_authenticated(&self) -> crate::Result<bool> {
        match self.current_state.as_ref().map(|state| state.status) {
            None | Some(sspi::SecurityStatus::ContinueNeeded) => Ok(false),
            Some(sspi::SecurityStatus::Ok) => Ok(true),
            Some(status) => Err(Error::InvalidState(format!(
                "Unexpected SSPI authentication status: {status:?}."
            ))),
        }
    }

    pub fn has_session_key(&self) -> crate::Result<bool> {
        match self.ssp.query_context_session_key() {
            Ok(key) if key.session_key.as_ref().len() >= 16 => Ok(true),
            Ok(_) => Err(Error::InvalidState(
                "SSPI session key is shorter than 16 bytes.".into(),
            )),
            Err(error) if error.error_type == sspi::ErrorKind::OutOfSequence => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    pub fn session_key(&self) -> crate::Result<[u8; 16]> {
        // Use the first 16 bytes of the session key.
        let key_info = self.ssp.query_context_session_key()?;
        let k = key_info.session_key.as_ref().get(..16).ok_or_else(|| {
            Error::InvalidState("SSPI session key is shorter than 16 bytes.".into())
        })?;
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

        let mut output_buffer = vec![SecurityBuffer::new(Vec::new(), BufferType::Token)];
        let target_name = Self::make_sspi_target_name(&self.server_hostname);
        let mut builder = self
            .ssp
            .initialize_security_context()
            .with_credentials_handle(&mut self.cred_handle.credentials_handle)
            .with_context_requirements(Self::get_context_requirements())
            .with_target_data_representation(Self::SSPI_REQ_DATA_REPRESENTATION)
            .with_output(&mut output_buffer);

        if cfg!(feature = "kerberos") {
            builder = builder.with_target_name(&target_name)
        }

        let mut input_buffers = vec![];
        input_buffers.push(SecurityBuffer::new(gss_token.to_owned(), BufferType::Token));
        builder = builder.with_input(&mut input_buffers);

        let result = {
            let mut generator = self.ssp.initialize_security_context_impl(&mut builder)?;
            // Kerberos requires a network client to be set up.
            // We avoid compiling with the network client if kerberos is not enabled,
            // so be sure to avoid using it in that case.
            // while default, sync network client is supported in sspi,
            // an implementation of the async one had to be added in this module.
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
        };

        log::debug!("SSPI authentication step: {:?}", result.status);
        self.current_state = Some(result);
        // Reject unsupported SSPI statuses before an output token can be sent.
        self.is_authenticated()?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use sspi::{Credentials, ErrorKind, SecurityStatus, ServerRequestFlags};

    // Exercise the real SSPI client/server state machines with the same request
    // flags as SMB, without requiring a Samba server or storing captured tokens.
    #[maybe_async::maybe_async]
    async fn check_final_spnego_token(corrupt_mic: bool, omit_mic: bool) {
        let identity = AuthIdentity {
            username: Username::parse("test_user@example.com").unwrap(),
            password: "test_password".to_string().into(),
        };
        let config = || {
            NegotiateConfig::new(
                Box::new(NtlmConfig::default()),
                Some("ntlm,!kerberos,!pku2u".into()),
                "smb-rs".into(),
            )
        };
        let credentials = Credentials::AuthIdentity(identity.clone());
        let mut ssp = Negotiate::new_client(config()).unwrap();
        let cred_handle = ssp
            .acquire_credentials_handle()
            .with_credential_use(CredentialUse::Outbound)
            .with_auth_data(&credentials)
            .execute(&mut ssp)
            .unwrap();
        let mut client = Authenticator {
            server_hostname: "127.0.0.1".into(),
            user_name: identity.username.clone(),
            ssp,
            cred_handle,
            current_state: None,
        };
        let mut server = Negotiate::new_server(config(), vec![identity]).unwrap();
        let mut server_credentials = server
            .acquire_credentials_handle()
            .with_credential_use(CredentialUse::Inbound)
            .with_auth_data(&credentials)
            .execute(&mut server)
            .unwrap();
        let mut server_step = |token: Vec<u8>| {
            let mut input = [SecurityBuffer::new(token, BufferType::Token)];
            let mut output = [SecurityBuffer::new(Vec::new(), BufferType::Token)];
            let builder = server
                .accept_security_context()
                .with_credentials_handle(&mut server_credentials.credentials_handle)
                .with_context_requirements(ServerRequestFlags::empty())
                .with_target_data_representation(DataRepresentation::Native)
                .with_input(&mut input)
                .with_output(&mut output);
            let result = server
                .accept_security_context_impl(builder)
                .unwrap()
                .resolve_to_result()
                .unwrap();
            (result.status, std::mem::take(&mut output[0].buffer))
        };

        let negotiate = client.next(&[]).await.unwrap();
        assert!(!client.has_session_key().unwrap());
        assert!(!client.is_authenticated().unwrap());
        let (status, challenge) = server_step(negotiate);
        assert_eq!(status, SecurityStatus::ContinueNeeded);

        let authenticate = client.next(&challenge).await.unwrap();
        assert!(!authenticate.is_empty());
        assert!(client.has_session_key().unwrap());
        assert!(!client.is_authenticated().unwrap());
        assert_eq!(
            client.current_state.as_ref().unwrap().status,
            SecurityStatus::ContinueNeeded
        );
        let key_before_final_token = client.session_key().unwrap();
        let (status, mut final_token) = server_step(authenticate);
        assert_eq!(status, SecurityStatus::Ok);
        assert!(!final_token.is_empty());

        if corrupt_mic {
            // The final field is the MIC OCTET STRING; change its last byte,
            // preserving the DER structure so this tests signature verification.
            *final_token.last_mut().unwrap() ^= 1;
        } else if omit_mic {
            // NegTokenResp containing only negState = accept-completed.
            final_token = vec![0xa1, 7, 0x30, 5, 0xa0, 3, 0x0a, 1, 0];
        }
        let result = client.next(&final_token).await;
        if corrupt_mic {
            assert!(
                matches!(result, Err(Error::SspiError(error)) if error.error_type == ErrorKind::MessageAltered)
            );
            assert!(!client.is_authenticated().unwrap());
        } else {
            assert!(result.unwrap().is_empty());
            assert_eq!(client.is_authenticated().unwrap(), !omit_mic);
            assert_eq!(client.session_key().unwrap(), key_before_final_token);
        }
    }

    #[maybe_async::test(not(feature = "async"), async(feature = "async", tokio::test))]
    async fn session_key_precedes_spnego_completion() {
        check_final_spnego_token(false, false).await;
    }

    #[maybe_async::test(not(feature = "async"), async(feature = "async", tokio::test))]
    async fn final_spnego_mic_is_verified() {
        check_final_spnego_token(true, false).await;
    }

    #[maybe_async::test(not(feature = "async"), async(feature = "async", tokio::test))]
    async fn missing_final_spnego_mic_does_not_complete_authentication() {
        check_final_spnego_token(false, true).await;
    }
}
