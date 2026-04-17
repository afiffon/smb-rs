use std::sync::Arc;

use crate::Error;
use crate::connection::connection_info::ConnectionInfo;
use maybe_async::*;
use sspi::{
    AcquireCredentialsHandleResult, AuthIdentity, AuthIdentityBuffers, BufferType,
    ClientRequestFlags, CredentialUse, DataRepresentation, InitializeSecurityContextResult,
    SecurityBuffer, Sspi, SspiImpl,
    ntlm::{Ntlm, NtlmConfig},
};
use sspi::Username;

/// SMB session authenticator using NTLM SSP directly.
///
/// Previous versions used sspi-rs's `Negotiate` SSP, which wraps NTLM in
/// an additional GSS-API / NegoEx framing layer that Windows 10's SMB server
/// rejects with `STATUS_INVALID_PARAMETER`.  By driving the `Ntlm` SSP
/// directly we get clean NTLM tokens that our `spnego` module wraps in the
/// standard SPNEGO envelope expected by SMB2.
#[derive(Debug)]
pub struct Authenticator {
    server_hostname: String,
    user_name: Username,

    ssp: Ntlm,
    cred_handle: AcquireCredentialsHandleResult<Option<AuthIdentityBuffers>>,
    current_state: Option<InitializeSecurityContextResult>,
    first_token_sent: bool,
}

impl Authenticator {
    pub fn build(
        identity: AuthIdentity,
        conn_info: &Arc<ConnectionInfo>,
    ) -> crate::Result<Authenticator> {
        let mut ntlm_ssp = Ntlm::with_config(NtlmConfig::default());
        let user_name = identity.username.clone();

        let cred_handle = ntlm_ssp
            .acquire_credentials_handle()
            .with_credential_use(CredentialUse::Outbound)
            .with_auth_data(&identity)
            .execute(&mut ntlm_ssp)?;

        Ok(Authenticator {
            server_hostname: conn_info.server_name.clone(),
            ssp: ntlm_ssp,
            cred_handle,
            current_state: None,
            user_name,
            first_token_sent: false,
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
        let key_info = self.ssp.query_context_session_key()?;
        let k = &key_info.session_key.as_ref()[..16];
        Ok(k.try_into().unwrap())
    }

    fn get_context_requirements() -> ClientRequestFlags {
        ClientRequestFlags::INTEGRITY
            | ClientRequestFlags::REPLAY_DETECT
            | ClientRequestFlags::SEQUENCE_DETECT
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

        // Ntlm SSP 只接受原始 NTLM token，需要先从 SPNEGO 中提取
        let sspi_input = if gss_token.is_empty() {
            gss_token.to_owned()
        } else {
            super::spnego::unwrap_response(gss_token)?
        };

        let mut output_buffer = vec![SecurityBuffer::new(Vec::new(), BufferType::Token)];
        let mut builder = self
            .ssp
            .initialize_security_context()
            .with_credentials_handle(&mut self.cred_handle.credentials_handle)
            .with_context_requirements(Self::get_context_requirements())
            .with_target_data_representation(Self::SSPI_REQ_DATA_REPRESENTATION)
            .with_output(&mut output_buffer);

        let target_name = format!("cifs/{}", self.server_hostname);
        builder = builder.with_target_name(&target_name);

        let mut input_buffers = vec![];
        input_buffers.push(SecurityBuffer::new(sspi_input, BufferType::Token));
        builder = builder.with_input(&mut input_buffers);

        let result = {
            let mut generator = self.ssp.initialize_security_context_impl(&mut builder)?;
            generator.resolve_to_result()?
        };

        self.current_state = Some(result);

        let raw_token = output_buffer
            .pop()
            .ok_or_else(|| Error::InvalidState("SSPI output buffer is empty.".to_string()))?
            .buffer;

        log::debug!(
            "NTLM SSP output: {} bytes, starts_with_ntlmssp={}",
            raw_token.len(),
            super::spnego::is_raw_ntlm(&raw_token)
        );

        // Ntlm SSP 直接输出原始 NTLM token，需要我们手动做 SPNEGO 封装
        if !self.first_token_sent {
            self.first_token_sent = true;
            let wrapped = super::spnego::wrap_init(&raw_token);
            log::debug!(
                "SPNEGO: NTLM Type-1 ({} bytes) -> NegTokenInit ({} bytes)",
                raw_token.len(),
                wrapped.len()
            );
            Ok(wrapped)
        } else {
            let wrapped = super::spnego::wrap_response(&raw_token);
            log::debug!(
                "SPNEGO: NTLM Type-3 ({} bytes) -> NegTokenResp ({} bytes)",
                raw_token.len(),
                wrapped.len()
            );
            Ok(wrapped)
        }
    }
}
