use crate::session::authenticator::Authenticator;

use super::*;

enum SetupState {
    Initial {
        preauth_hash: PreauthHashState,
    },
    InProgress {
        preauth_hash: PreauthHashState,
        session: Arc<RwLock<SessionAndChannel>>,
        handler: ChannelMessageHandler,
        /// Token returned by the previous setup response and consumed by SSPI
        /// to produce the next request.
        input_token: Vec<u8>,
    },
    Complete {
        session: Arc<RwLock<SessionAndChannel>>,
        flags: SessionFlags,
    },
}

/// Session setup processor.
///
/// This is an internal structure.
/// Internal state relies on the invariants of the in-crate implementations of T.
/// Responses from the server must be validated before they update that state.
pub(crate) struct SessionSetup<'a, T>
where
    T: SessionSetupProperties,
{
    state: SetupState,

    authenticator: Authenticator,
    upstream: &'a ChannelUpstream,
    conn_info: &'a Arc<ConnectionInfo>,

    new_channel_id: u32,

    _phantom: std::marker::PhantomData<T>,
}

#[maybe_async]
impl<'a, T> SessionSetup<'a, T>
where
    T: SessionSetupProperties,
{
    pub async fn new(
        identity: sspi::AuthIdentity,
        upstream: &'a ChannelUpstream,
        conn_info: &'a Arc<ConnectionInfo>,
        new_channel_id: u32,
        primary_session: Option<&Arc<RwLock<SessionAndChannel>>>,
    ) -> crate::Result<Self> {
        let authenticator = Authenticator::build(identity, conn_info)?;

        let mut setup = Self {
            state: SetupState::Initial {
                preauth_hash: conn_info.preauth_hash.clone(),
            },
            authenticator,
            upstream,
            conn_info,
            new_channel_id,
            _phantom: std::marker::PhantomData,
        };

        if let Some(primary_session) = primary_session {
            let primary_session = primary_session.read().await?;

            let session = primary_session.session.clone();

            let channel = primary_session
                .channel
                .as_ref()
                .expect("A properly initialized session is expected in session setup.")
                .clone();
            #[cfg(feature = "ksmbd-multichannel-compat")]
            let channel = channel.with_binding(true);

            setup.set_session(session).await?;
            setup.session()?.write().await?.channel = Some(channel);
        }

        Ok(setup)
    }

    /// Common session setup logic.
    ///
    /// This function sets up a session against a connection, and it is somewhat abstract.
    /// by calling impl functions, this function's behavior is modified to support both new sessions and binding to existing sessions.
    pub(crate) async fn setup(&mut self) -> crate::Result<Arc<RwLock<SessionAndChannel>>> {
        log::debug!(
            "Setting up session for user {}.",
            self.authenticator.user_name().inner()
        );

        let result = self
            ._setup_loop()
            .await
            .map_err(Error::normalize_authentication_error);
        match result {
            Ok(()) => self.completed_session(),
            Err(e) => {
                log::error!("Failed to setup session: {}", e);
                if let Err(ce) = T::error_cleanup(self).await {
                    log::error!("Failed to cleanup after setup error: {}", ce);
                }
                Err(e)
            }
        }
    }

    /// *DO NOT OVERLOAD*
    ///
    /// Performs the session setup negotiation.
    ///
    /// This function loops until the authentication is complete, requesting GSS tokens
    /// and passing them to the server.
    async fn _setup_loop(&mut self) -> crate::Result<()> {
        loop {
            // Generate the next client token and determine the only valid SMB reply.
            let input_token = self.take_input_token()?;
            let token = self.authenticator.next(&input_token).await?;
            if token.is_empty() {
                return Err(Error::InvalidState(
                    "SSPI produced no token for a session setup request.".into(),
                ));
            }

            let expected_status = self.expected_setup_status()?;

            let request = self.send_setup_request(token).await?;
            if expected_status == Status::Success {
                // The final request completes the preauthentication transcript used
                // to derive the key that validates the response.
                self.finish_preauth_hash()?;
            }

            let response = self
                .receive_setup_response(request.msg_id, expected_status)
                .await?;
            if self.process_setup_response(response).await? {
                break;
            }
        }

        log::trace!("setup success, finishing up.");
        T::on_setup_success(self).await?;
        Ok(())
    }

    /// A key commits us to the final exchange: the preauthentication hash has
    /// been finalized and cannot accept another challenge/response round.
    fn expected_setup_status(&self) -> crate::Result<Status> {
        match (
            self.authenticator.authentication_completed()?,
            self.authenticator.has_session_key()?,
        ) {
            (_, true) => Ok(Status::Success),
            (false, false) => Ok(Status::MoreProcessingRequired),
            (true, false) => Err(Error::InvalidState(
                "SSPI completed authentication without a session key.".into(),
            )),
        }
    }

    /// Validates and applies one setup response. Final responses are authenticated
    /// here before their channel is installed; challenge responses advance the
    /// preauthentication transcript and provide the next SSPI input token.
    async fn process_setup_response(
        &mut self,
        mut response: IncomingMessage,
    ) -> crate::Result<bool> {
        let session_id = response.message.header.session_id;
        if session_id == 0 {
            return Err(Error::InvalidMessage(
                "Session setup response has no session ID.".into(),
            ));
        }
        if self
            .handler()
            .is_some_and(|handler| handler.session_id() != session_id)
        {
            return Err(Error::InvalidMessage(
                "Session setup response has a mismatched session ID.".into(),
            ));
        }

        if response.message.header.status == Status::MoreProcessingRequired as u32 {
            self.verify_challenge_response(&mut response).await?;
            if matches!(self.state, SetupState::Initial { .. }) {
                log::trace!("Creating session state with id {session_id}.");
                self.set_session(T::init_session(self, session_id).await?)
                    .await?;
            }
            self.next_preauth_hash(&response.raw)?;
            self.set_input_token(response.message.content.to_sessionsetup()?.buffer)?;
            return Ok(false);
        }

        let (session_flags, response_token) = {
            let setup_response = response.message.content.as_sessionsetup()?;
            (setup_response.session_flags, setup_response.buffer.clone())
        };

        // A successful SMB reply may carry the final SPNEGO token. In
        // particular, a Kerberos AP-REP can establish the acceptor subkey used
        // to verify this response, so SSPI must consume it first.
        self.complete_authentication(&response_token).await?;

        let channel = self.build_channel()?;
        self.verify_setup_response(
            &mut response,
            &channel,
            session_flags.is_guest_or_null_session(),
        )?;

        // A one-round Kerberos exchange has no session state until the signed
        // response has supplied and authenticated the server-assigned ID.
        if matches!(self.state, SetupState::Initial { .. }) {
            self.set_session(T::init_session(self, session_id).await?)
                .await?;
        }
        self.install_channel(channel).await?;
        self.complete_state(session_flags)?;

        Ok(true)
    }

    async fn complete_authentication(&mut self, response_token: &[u8]) -> crate::Result<()> {
        if !self.authenticator.authentication_completed()? {
            let output = self.authenticator.next(response_token).await?;
            if !output.is_empty() {
                return Err(Error::InvalidState(
                    "SSPI produced another token after SMB session setup succeeded.".into(),
                ));
            }
        }

        if !self.authenticator.authentication_completed()? {
            return Err(Error::InvalidState(
                "SMB session setup succeeded before SSPI authentication completed.".into(),
            ));
        }

        Ok(())
    }

    async fn verify_challenge_response(&self, response: &mut IncomingMessage) -> crate::Result<()> {
        let (session, channel) = {
            let SetupState::InProgress {
                session: session_state,
                ..
            } = &self.state
            else {
                return Ok(());
            };
            let session_state = session_state.read().await?;
            let Some(channel) = session_state.channel.clone() else {
                return Ok(());
            };
            (session_state.session.clone(), channel)
        };

        let unsigned_allowed = session.read().await?.allow_unsigned()?;

        self.verify_setup_response(response, &channel, unsigned_allowed)
    }

    fn verify_setup_response(
        &self,
        response: &mut IncomingMessage,
        channel: &ChannelInfo,
        unsigned_allowed: bool,
    ) -> crate::Result<()> {
        if response.form.encrypted {
            return Ok(());
        }

        let signed = response.message.header.flags.signed()
            || Self::is_unsigned_binding_compat_response(response, channel);
        if !signed {
            if unsigned_allowed {
                return Ok(());
            }
            return Err(Error::InvalidMessage("Expected a signed message!".into()));
        }

        let mut signer = channel.signer()?.clone();
        crate::connection::transformer::Transformer::verify_incoming_signature(
            &mut response.message,
            &response.raw,
            &mut response.form,
            &mut signer,
        )
    }

    fn is_unsigned_binding_compat_response(
        _response: &IncomingMessage,
        _channel: &ChannelInfo,
    ) -> bool {
        // ksmbd has a subtle, but irritating bug, where it does not set the "signed" flag
        // for responses during multi channel session setups. To resolve this, we check if the
        // current channel is defined as "binding-only" channel. The feature `ksmbd-multichannel-compat`
        // must also be enabled, or else this code will not be compiled.
        // This behavior is actually against the spec - MS-SMB2 3.2.4.1.1:
        // > "If the client signs the request, it MUST set the SMB2_FLAGS_SIGNED bit in the Flags field of the SMB2 header."
        #[cfg(feature = "ksmbd-multichannel-compat")]
        {
            return _response.message.header.signature != 0 && _channel.is_binding();
        }

        #[cfg(not(feature = "ksmbd-multichannel-compat"))]
        false
    }

    async fn set_session(&mut self, session: Arc<RwLock<SessionInfo>>) -> crate::Result<()> {
        let preauth_hash = match &self.state {
            SetupState::Initial { preauth_hash } => preauth_hash.clone(),
            _ => {
                return Err(Error::InvalidState(
                    "Session setup already has a registered session.".into(),
                ));
            }
        };
        let session_id = session.read().await?.id();
        let result = SessionAndChannel::new(session_id, session);
        let session = Arc::new(RwLock::new(result));

        let setup_handler = ChannelMessageHandler::make_for_setup(&session, self.upstream).await?;

        self.upstream
            .worker()
            .ok_or_else(|| Error::InvalidState("Worker not available!".to_string()))?
            .session_started(&session)
            .await?;

        self.state = SetupState::InProgress {
            preauth_hash,
            session,
            handler: setup_handler,
            input_token: Vec::new(),
        };

        Ok(())
    }

    async fn receive_setup_response(
        &mut self,
        for_msg_id: u64,
        expected_status: Status,
    ) -> crate::Result<IncomingMessage> {
        let expected_statuses = [expected_status];
        let roptions = ReceiveOptions::new()
            .with_status(&expected_statuses)
            .with_cmd(Some(smb_msg::Command::SessionSetup))
            .with_msg_id_filter(for_msg_id);

        log::trace!("setup loop: receiving unvalidated response with upstream handler");
        self.upstream.handler.recvo(roptions).await
    }

    async fn send_setup_request(&mut self, buf: Vec<u8>) -> crate::Result<SendMessageResult> {
        // Include each request before deriving the keys that validate its response.
        let request = T::make_request(self, buf).await?;

        let send_result = if let Some(handler) = self.handler() {
            log::trace!("setup loop: sending with channel handler");
            handler.sendo(request).await?
        } else {
            log::trace!("setup loop: sending with upstream handler");
            self.upstream.sendo(request).await?
        };

        let raw = send_result.raw.as_ref().ok_or_else(|| {
            Error::InvalidState("Session setup request did not retain its raw data.".into())
        })?;
        self.next_preauth_hash(raw)?;
        Ok(send_result)
    }

    fn build_channel(&self) -> crate::Result<ChannelInfo> {
        let channel = ChannelInfo::new(
            self.new_channel_id,
            &self.session_key()?,
            &self.preauth_hash_value()?,
            self.conn_info,
        )?;
        #[cfg(feature = "ksmbd-multichannel-compat")]
        let channel = channel.with_binding(T::is_binding());
        Ok(channel)
    }

    async fn install_channel(&mut self, channel: ChannelInfo) -> crate::Result<()> {
        T::on_session_key_exchanged(self).await?;
        log::trace!("Session keys are set.");
        let mut session_lock = self.session()?.write().await?;
        session_lock.set_channel(channel);

        log::trace!("Channel for current setup has been initialized");
        Ok(())
    }

    fn session_key(&self) -> crate::Result<KeyToDerive> {
        self.authenticator.session_key()
    }

    fn preauth_hash_value(&self) -> crate::Result<Option<PreauthHashValue>> {
        Ok(self.preauth_hash()?.unwrap_final_hash().copied())
    }

    fn next_preauth_hash(&mut self, data: &IoVec) -> crate::Result<()> {
        let hash = self.preauth_hash_mut()?;
        *hash = hash.clone().next(data);
        Ok(())
    }

    fn finish_preauth_hash(&mut self) -> crate::Result<()> {
        let hash = self.preauth_hash_mut()?;
        *hash = hash.clone().finish();
        Ok(())
    }

    fn preauth_hash(&self) -> crate::Result<&PreauthHashState> {
        match &self.state {
            SetupState::Initial { preauth_hash } | SetupState::InProgress { preauth_hash, .. } => {
                Ok(preauth_hash)
            }
            SetupState::Complete { .. } => Err(Error::InvalidState(
                "Session setup authentication is already complete.".into(),
            )),
        }
    }

    fn preauth_hash_mut(&mut self) -> crate::Result<&mut PreauthHashState> {
        match &mut self.state {
            SetupState::Initial { preauth_hash } | SetupState::InProgress { preauth_hash, .. } => {
                Ok(preauth_hash)
            }
            SetupState::Complete { .. } => Err(Error::InvalidState(
                "Session setup authentication is already complete.".into(),
            )),
        }
    }

    fn take_input_token(&mut self) -> crate::Result<Vec<u8>> {
        match &mut self.state {
            SetupState::Initial { .. } => Ok(Vec::new()),
            SetupState::InProgress { input_token, .. } => Ok(std::mem::take(input_token)),
            SetupState::Complete { .. } => Err(Error::InvalidState(
                "Session setup authentication is already complete.".into(),
            )),
        }
    }

    fn set_input_token(&mut self, token: Vec<u8>) -> crate::Result<()> {
        match &mut self.state {
            SetupState::InProgress { input_token, .. } => {
                *input_token = token;
                Ok(())
            }
            _ => Err(Error::InvalidState(
                "Cannot store an authentication token outside setup progress.".into(),
            )),
        }
    }

    fn handler(&self) -> Option<&ChannelMessageHandler> {
        match &self.state {
            SetupState::InProgress { handler, .. } => Some(handler),
            _ => None,
        }
    }

    fn session(&self) -> crate::Result<&Arc<RwLock<SessionAndChannel>>> {
        self.registered_session()
            .ok_or_else(|| Error::InvalidState("Session setup has no registered session.".into()))
    }

    fn registered_session(&self) -> Option<&Arc<RwLock<SessionAndChannel>>> {
        match &self.state {
            SetupState::InProgress { session, .. } | SetupState::Complete { session, .. } => {
                Some(session)
            }
            SetupState::Initial { .. } => None,
        }
    }

    fn complete_state(&mut self, flags: SessionFlags) -> crate::Result<()> {
        let session = match &self.state {
            SetupState::InProgress { session, .. } => session.clone(),
            _ => {
                return Err(Error::InvalidState(
                    "Cannot complete session setup before registering a session.".into(),
                ));
            }
        };
        self.state = SetupState::Complete { session, flags };
        Ok(())
    }

    fn completed_session(&self) -> crate::Result<Arc<RwLock<SessionAndChannel>>> {
        match &self.state {
            SetupState::Complete { session, .. } => Ok(session.clone()),
            _ => Err(Error::InvalidState(
                "Session setup did not reach the complete state.".into(),
            )),
        }
    }

    fn completed_flags(&self) -> crate::Result<SessionFlags> {
        match &self.state {
            SetupState::Complete { flags, .. } => Ok(*flags),
            _ => Err(Error::InvalidState(
                "Session setup did not reach the complete state.".into(),
            )),
        }
    }

    pub fn upstream(&self) -> &'a ChannelUpstream {
        self.upstream
    }

    pub fn conn_info(&self) -> &'a Arc<ConnectionInfo> {
        self.conn_info
    }
}

#[maybe_async(AFIT)]
pub(crate) trait SessionSetupProperties {
    #[cfg(feature = "ksmbd-multichannel-compat")]
    fn is_binding() -> bool {
        false
    }

    /// This function is called when setup error is encountered, to perform any necessary cleanup.
    async fn error_cleanup<T>(setup: &mut SessionSetup<'_, T>) -> crate::Result<()>
    where
        T: SessionSetupProperties;

    fn _make_default_request(buffer: Vec<u8>, dfs: bool) -> OutgoingMessage {
        OutgoingMessage::new(
            SessionSetupRequest::new(
                buffer,
                SessionSecurityMode::new().with_signing_enabled(true),
                SetupRequestFlags::new(),
                NegotiateCapabilities::new().with_dfs(dfs),
            )
            .into(),
        )
        .with_return_raw_data(true)
    }

    async fn make_request<T>(
        _setup: &mut SessionSetup<'_, T>,
        buffer: Vec<u8>,
    ) -> crate::Result<OutgoingMessage>
    where
        T: SessionSetupProperties,
    {
        let has_dfs = _setup.conn_info().negotiation.caps.dfs();
        Ok(Self::_make_default_request(buffer, has_dfs))
    }

    async fn init_session<T>(
        _setup: &'_ SessionSetup<'_, T>,
        _session_id: u64,
    ) -> crate::Result<Arc<RwLock<SessionInfo>>>
    where
        T: SessionSetupProperties;

    async fn on_session_key_exchanged<T>(_setup: &mut SessionSetup<'_, T>) -> crate::Result<()>
    where
        T: SessionSetupProperties,
    {
        // Default implementation does nothing.
        Ok(())
    }

    async fn on_setup_success<T>(_setup: &mut SessionSetup<'_, T>) -> crate::Result<()>
    where
        T: SessionSetupProperties;
}

pub(crate) struct SmbSessionBind;

#[maybe_async(AFIT)]
impl SessionSetupProperties for SmbSessionBind {
    #[cfg(feature = "ksmbd-multichannel-compat")]
    fn is_binding() -> bool {
        true
    }

    async fn make_request<T>(
        _setup: &mut SessionSetup<'_, T>,
        buffer: Vec<u8>,
    ) -> crate::Result<OutgoingMessage>
    where
        T: SessionSetupProperties,
    {
        // TODO: what about DFS in previous session?
        let has_dfs = _setup.conn_info().negotiation.caps.dfs();
        let mut request = Self::_make_default_request(buffer, has_dfs);
        request
            .message
            .content
            .as_mut_sessionsetup()
            .unwrap()
            .flags
            .set_binding(true);
        Ok(request)
    }

    async fn error_cleanup<T>(setup: &mut SessionSetup<'_, T>) -> crate::Result<()>
    where
        T: SessionSetupProperties,
    {
        let Some(session) = setup.registered_session().cloned() else {
            log::warn!("No session to cleanup in binding.");
            return Ok(());
        };
        setup
            .upstream
            .worker()
            .ok_or_else(|| Error::InvalidState("Worker not available!".to_string()))?
            .session_ended(&session)
            .await
    }

    async fn init_session<T>(
        _setup: &SessionSetup<'_, T>,
        _session_id: u64,
    ) -> crate::Result<Arc<RwLock<SessionInfo>>>
    where
        T: SessionSetupProperties,
    {
        panic!("(Primary) Session should be provided in construction, rather than during setup!");
    }

    async fn on_setup_success<T>(_setup: &mut SessionSetup<'_, T>) -> crate::Result<()>
    where
        T: SessionSetupProperties,
    {
        Ok(())
    }
}

pub(crate) struct SmbSessionNew;

#[maybe_async(AFIT)]
impl SessionSetupProperties for SmbSessionNew {
    async fn error_cleanup<T>(setup: &mut SessionSetup<'_, T>) -> crate::Result<()>
    where
        T: SessionSetupProperties,
    {
        let Some(session) = setup.registered_session().cloned() else {
            log::trace!("No session to cleanup in setup.");
            return Ok(());
        };

        log::trace!("Invalidating session before cleanup.");
        {
            let session_lock = session.read().await?;
            session_lock.session.write().await?.invalidate();
        }

        setup
            .upstream
            .worker()
            .ok_or_else(|| Error::InvalidState("Worker not available!".to_string()))?
            .session_ended(&session)
            .await
    }

    async fn on_session_key_exchanged<T>(setup: &mut SessionSetup<'_, T>) -> crate::Result<()>
    where
        T: SessionSetupProperties,
    {
        // Only on new sessions we need to initialize the session state with the keys.
        log::trace!("Session keys exchanged. Setting up session state.");
        setup.session()?.read().await?.session.write().await?.setup(
            &setup.session_key()?,
            &setup.preauth_hash_value()?,
            setup.conn_info,
        )
    }

    async fn on_setup_success<T>(setup: &mut SessionSetup<'_, T>) -> crate::Result<()>
    where
        T: SessionSetupProperties,
    {
        log::trace!("Session setup successful");
        let result = setup.session()?.read().await?;
        let mut session = result.session.write().await?;
        session.ready(setup.completed_flags()?, setup.conn_info)
    }

    async fn init_session<T>(
        _setup: &SessionSetup<'_, T>,
        session_id: u64,
    ) -> crate::Result<Arc<RwLock<SessionInfo>>>
    where
        T: SessionSetupProperties,
    {
        let session_info = SessionInfo::new(session_id);
        let session_info = Arc::new(RwLock::new(session_info));

        Ok(session_info)
    }
}
