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

fn rc4_crypt(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut s: Vec<u8> = (0..=255).collect();
    let mut j: usize = 0;
    for i in 0..256 {
        j = (j + s[i] as usize + key[i % key.len()] as usize) & 0xff;
        s.swap(i, j);
    }
    let mut i: usize = 0;
    j = 0;
    data.iter()
        .map(|&b| {
            i = (i + 1) & 0xff;
            j = (j + s[i] as usize) & 0xff;
            s.swap(i, j);
            b ^ s[(s[i] as usize + s[j] as usize) & 0xff]
        })
        .collect()
}

/// Extract the NegotiateFlags field from a raw NTLM AUTHENTICATE_MESSAGE (Type-3).
///
/// Layout per [MS-NLMP] 2.2.1.3:
///   Signature(8) + MessageType(4) + LmChallengeResponseFields(8) +
///   NtChallengeResponseFields(8) + DomainNameFields(8) + UserNameFields(8) +
///   WorkstationFields(8) + EncryptedRandomSessionKeyFields(8) = 60 bytes
/// followed by 4 bytes of NegotiateFlags (little-endian).
fn extract_ntlm_type3_negotiate_flags(ntlm_msg: &[u8]) -> Option<u32> {
    if ntlm_msg.len() < 64 {
        return None;
    }
    if &ntlm_msg[..8] != b"NTLMSSP\0" {
        return None;
    }
    if u32::from_le_bytes(ntlm_msg[8..12].try_into().ok()?) != 3 {
        return None;
    }
    Some(u32::from_le_bytes(ntlm_msg[60..64].try_into().ok()?))
}

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
        // This authenticator drives the NTLM SSP directly (see module docs).
        // It does not implement Kerberos — the previous `Negotiate` SSP path
        // that used to cover Kerberos produced NegoEx framing Windows SMB
        // servers reject, so it was removed.  To avoid silently downgrading a
        // user who explicitly asked for Kerberos, fail fast here when the
        // connection config requests it.
        let auth_methods = &conn_info.config.auth_methods;
        if auth_methods.kerberos && !auth_methods.ntlm {
            return Err(Error::UnsupportedAuthenticationMechanism(
                "Kerberos-only authentication is not supported by this build; \
                 enable NTLM (auth_methods.ntlm = true) or use a build with \
                 Kerberos support".into(),
            ));
        }
        if auth_methods.kerberos {
            log::warn!(
                "AuthMethodsConfig.kerberos = true but this build only \
                 implements NTLM; falling back to NTLM. Set kerberos = false \
                 to silence this warning."
            );
        }

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

    /// Compute the SPNEGO mechListMIC manually.
    ///
    /// Implements the MIC computation described in [MS-SPNG] §3.1.5.1 +
    /// [MS-NLMP] §3.4.4.1:
    ///   1. Derive ClientSigningKey and ClientSealingKey from ExportedSessionKey.
    ///   2. Digest = HMAC-MD5(ClientSigningKey, seq_num_le || mechTypeList).
    ///   3. If NTLMSSP_NEGOTIATE_KEY_EXCH was negotiated:
    ///         Checksum = RC4(ClientSealingKey, Digest[0:8])
    ///      Otherwise:
    ///         Checksum = Digest[0:8]  (NTLMv2 + ESS without key exchange).
    ///   4. MIC = version(1u32_le) || Checksum || seq_num_le.
    ///
    /// `ntlm_negotiate_flags` MUST be the NegotiateFlags value actually sent on
    /// the wire in the AUTHENTICATE_MESSAGE (Type-3); otherwise server-side
    /// verification will fail.
    pub fn compute_mech_list_mic(
        &mut self,
        mech_list: &[u8],
        ntlm_negotiate_flags: u32,
    ) -> crate::Result<Vec<u8>> {
        use hmac::{Hmac, KeyInit, Mac};
        use md5::Md5;

        /// [MS-NLMP] 2.2.2.5 : NTLMSSP_NEGOTIATE_KEY_EXCH
        const NTLMSSP_NEGOTIATE_KEY_EXCH: u32 = 0x4000_0000;

        let session_key = self.session_key()?;

        // Derive ClientSigningKey = MD5(ExportedSessionKey || CLIENT_SIGN_MAGIC)
        let client_sign_magic = b"session key to client-to-server signing key magic constant\x00";
        let signing_key: [u8; 16] = {
            let mut hasher = <Md5 as md5::Digest>::new();
            md5::Digest::update(&mut hasher, &session_key);
            md5::Digest::update(&mut hasher, client_sign_magic.as_slice());
            md5::Digest::finalize(hasher).into()
        };

        // Derive ClientSealingKey = MD5(ExportedSessionKey || CLIENT_SEAL_MAGIC)
        let client_seal_magic = b"session key to client-to-server sealing key magic constant\x00";
        let sealing_key: [u8; 16] = {
            let mut hasher = <Md5 as md5::Digest>::new();
            md5::Digest::update(&mut hasher, &session_key);
            md5::Digest::update(&mut hasher, client_seal_magic.as_slice());
            md5::Digest::finalize(hasher).into()
        };

        if cfg!(feature = "__debug-dump-keys") {
            log::debug!(
                "MIC keys: signing={:02x?}, sealing={:02x?}",
                signing_key,
                sealing_key
            );
        }

        // Digest = HMAC-MD5(ClientSigningKey, seq_num(0) || mechTypeList)
        let seq_num: u32 = 0;
        let mut mac =
            Hmac::<Md5>::new_from_slice(&signing_key).expect("HMAC-MD5 key length is valid");
        mac.update(&seq_num.to_le_bytes());
        mac.update(mech_list);
        let digest: [u8; 16] = mac.finalize().into_bytes().into();

        // Checksum = RC4(ClientSealingKey, Digest[0:8]) iff KEY_EXCH was negotiated;
        // otherwise the checksum is just digest[0..8].
        let key_exch_enabled = ntlm_negotiate_flags & NTLMSSP_NEGOTIATE_KEY_EXCH != 0;
        let checksum: Vec<u8> = if key_exch_enabled {
            rc4_crypt(&sealing_key, &digest[..8])
        } else {
            digest[..8].to_vec()
        };

        // MIC = version(1) || checksum || seq_num
        let mut mic = Vec::with_capacity(16);
        mic.extend_from_slice(&1u32.to_le_bytes()); // version
        mic.extend_from_slice(&checksum); // 8 bytes
        mic.extend_from_slice(&seq_num.to_le_bytes()); // seq_num
        assert_eq!(mic.len(), 16);

        log::trace!(
            "mechListMIC: key_exch={}, mic={:02x?}",
            key_exch_enabled,
            &mic
        );

        Ok(mic)
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

        // Ntlm SSP only accepts raw NTLM tokens, so unwrap the SPNEGO envelope first.
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

        log::trace!(
            "NTLM SSP output: {} bytes, starts_with_ntlmssp={}",
            raw_token.len(),
            super::spnego::is_raw_ntlm(&raw_token)
        );

        // Ntlm SSP emits raw NTLM tokens; we wrap them into SPNEGO manually.
        if !self.first_token_sent {
            self.first_token_sent = true;
            let wrapped = super::spnego::wrap_init(&raw_token);
            log::trace!(
                "SPNEGO: NTLM Type-1 ({} bytes) -> NegTokenInit ({} bytes)",
                raw_token.len(),
                wrapped.len()
            );
            Ok(wrapped)
        } else if self.is_authenticated()? {
            // NTLM exchange is complete; include a mechListMIC in the Type-3
            // NegTokenResp. The MIC algorithm depends on the NegotiateFlags
            // actually sent on the wire in Type-3 (notably the KEY_EXCH bit),
            // so we parse the real flags from raw_token instead of assuming.
            let ntlm_flags = extract_ntlm_type3_negotiate_flags(&raw_token).ok_or_else(|| {
                Error::InvalidState("Failed to parse NegotiateFlags from NTLM Type-3".into())
            })?;
            log::trace!("NTLM Type-3 NegotiateFlags: 0x{:08x}", ntlm_flags);
            let mic = self.compute_mech_list_mic(super::spnego::MECH_TYPE_LIST_BYTES, ntlm_flags)?;
            let wrapped = super::spnego::wrap_response_with_mic(&raw_token, &mic);
            log::trace!(
                "SPNEGO: NTLM Type-3 ({} bytes) + MIC -> NegTokenResp ({} bytes)",
                raw_token.len(),
                wrapped.len()
            );
            Ok(wrapped)
        } else {
            let wrapped = super::spnego::wrap_response(&raw_token);
            log::trace!(
                "SPNEGO: NTLM Type-3 ({} bytes) -> NegTokenResp ({} bytes)",
                raw_token.len(),
                wrapped.len()
            );
            Ok(wrapped)
        }
    }
}
