use crate::session::authenticator::Authenticator;

use super::*;

/// Session setup processor.
///
/// This is an internal structure.
/// It is assume that T is properly implemented and tested in-crate,
/// and so, the wide use of unwrap() is acceptable.
pub(crate) struct SessionSetup<'a, T>
where
    T: SessionSetupProperties,
{
    last_setup_response: Option<SessionSetupResponse>,
    flags: Option<SessionFlags>,

    handler: Option<ChannelMessageHandler>,

    /// should always be set; this is Option to allow moving it out during setup,
    /// when it is being updated.
    preauth_hash: Option<PreauthHashState>,

    result: Option<Arc<RwLock<SessionAndChannel>>>,

    authenticator: Authenticator,
    upstream: &'a ChannelUpstream,
    conn_info: &'a Arc<ConnectionInfo>,

    // A place to store the current setup channel, until it is set into the info.
    channel: Option<ChannelInfo>,
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

        let mut result = Self {
            last_setup_response: None,
            flags: None,
            result: None,
            handler: None,
            preauth_hash: Some(conn_info.preauth_hash.clone()),
            authenticator,
            upstream,
            conn_info,
            channel: None,
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

            result.set_session(session).await?;
            result
                .result
                .as_ref()
                .expect("Should have been set up by set_session()")
                .write()
                .await?
                .channel = Some(channel);
        }

        Ok(result)
    }

    /// Common session setup logic.
    ///
    /// This function sets up a session against a connection, and it is somewhat abstract.
    /// by calling impl functions, this function's behavior is modified to support both new sessions and binding to existing sessions.
    pub(crate) async fn setup(&mut self) -> crate::Result<Arc<RwLock<SessionAndChannel>>> {
        log::debug!(
            "Setting up session for user {} (@{}).",
            self.authenticator.user_name().account_name(),
            self.authenticator.user_name().domain_name().unwrap_or("")
        );

        let result = self._setup_loop().await;
        match result {
            Ok(()) => Ok(self.result.take().unwrap()),
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
    ///
    /// Preauth hash policy (MS-SMB2 §3.2.5.3 / §3.2.4.2.3):
    ///   - Each outgoing request is chained into the hash.
    ///   - Each intermediate response (MORE_PROCESSING_REQUIRED) is chained.
    ///   - The final SUCCESS response is NOT included.
    ///   - `make_channel()` (key derivation) runs once the authentication is
    ///     complete and the preauth hash is finalized.
    async fn _setup_loop(&mut self) -> crate::Result<()> {
        let mut server_needs_more = true;
        const MAX_ROUNDS: usize = 8;
        let mut round = 0;

        while server_needs_more {
            round += 1;
            if round > MAX_ROUNDS {
                return Err(Error::InvalidState(
                    "Too many session setup rounds".to_string(),
                ));
            }

            let next_buf = match self.last_setup_response.as_ref() {
                Some(response) => self.authenticator.next(&response.buffer).await?,
                None => self.authenticator.next(&[]).await?,
            };
            let is_auth_done = self.authenticator.is_authenticated()?;

            let request = self.send_setup_request(next_buf).await?;

            // MS-SMB2 §3.2.5.3 : the signing key is derived from SessionKey and the
            // preauth hash covering every message up to and including the final
            // client request, and excludes the final SUCCESS response.
            //
            // If NTLM is done on this round (i.e. we just sent Type-3+MIC) the server
            // will answer with a signed SUCCESS.  The transformer verifies signatures
            // against the session's channel, so the channel (signing keys) MUST be
            // derived BEFORE we try to receive that response - otherwise the
            // transformer rejects the message with "Message is required to be signed,
            // but no channel is set up!".
            //
            // We can do this safely here because the preauth hash already reflects
            // every message up to the just-sent Type-3 request, which is exactly the
            // input MS-SMB2 mandates.  `self.result` exists only after the first round
            // has learned the session_id from Type-2, so gating on it keeps round 1
            // untouched.
            let channel_already_built = match self.result.as_ref() {
                Some(s) => s.read().await?.channel.is_some(),
                None => false,
            };
            if is_auth_done && self.result.is_some() && !channel_already_built {
                self.preauth_hash = self.preauth_hash.take().unwrap().finish().into();
                self.make_channel().await?;
            }

            let response = self.receive_setup_response(request.msg_id).await?;
            let response_status = response.message.header.status().ok();
            let message_form = response.form;
            let session_id = response.message.header.session_id;
            let session_setup_response = response.message.content.to_sessionsetup()?;

            if self.result.is_none() {
                log::trace!("Creating session state with id {session_id}.");
                self.set_session(T::init_session(self, session_id).await?)
                    .await?;
            }

            server_needs_more = response_status == Some(Status::MoreProcessingRequired);

            if is_auth_done {
                if server_needs_more {
                    // Server returned MORE_PROCESSING_REQUIRED even though NTLM
                    // authentication is already complete on our side.  This
                    // typically means the SPNEGO `mechListMIC` we embedded in
                    // Type-3 was missing or incorrect, so the server is asking
                    // for another round our state machine cannot produce.
                    //
                    // Per MS-SMB2 §3.2.5.3, accepting this response as "final"
                    // would leave the client using a session the server has
                    // not actually acknowledged as complete.  Rather than
                    // silently continuing with a half-negotiated session, fail
                    // fast so the caller can diagnose and fix the underlying
                    // mechListMIC or SPNEGO flow.
                    return Err(Error::InvalidState(format!(
                        "NTLM auth completed locally but server still returned \
                         STATUS_MORE_PROCESSING_REQUIRED; refusing to finalize \
                         a session the server has not accepted \
                         (likely a bad Type-3 mechListMIC). round={round}"
                    )));
                }

                // preauth_hash has already been finalized right after
                // send_setup_request, and make_channel() was invoked before
                // receive; this block only performs final validation.
                if self.preauth_hash.as_ref().unwrap().is_in_progress() {
                    // Defensive fallback: if the early-finalize branch above did
                    // not fire (e.g. on a legacy code path), finalize here.
                    self.preauth_hash = self.preauth_hash.take().unwrap().finish().into();
                    self.make_channel().await?;
                }

                if !server_needs_more
                    && !session_setup_response
                        .session_flags
                        .is_guest_or_null_session()
                    && !message_form.signed_or_encrypted()
                {
                    return Err(Error::InvalidMessage(
                        "Expected a signed message!".to_string(),
                    ));
                }

                server_needs_more = false;
            } else {
                // Intermediate response: chain into preauth hash and continue.
                self.next_preauth_hash(&response.raw);
            }

            self.flags = Some(session_setup_response.session_flags);
            self.last_setup_response = Some(session_setup_response);
        }

        self.flags.ok_or(Error::InvalidState(
            "Failed to complete authentication properly.".to_string(),
        ))?;

        log::trace!("setup success, finishing up.");
        T::on_setup_success(self).await?;

        Ok(())
    }

    async fn set_session(&mut self, session: Arc<RwLock<SessionInfo>>) -> crate::Result<()> {
        let session_id = session.read().await?.id();
        let result = SessionAndChannel::new(session_id, session);
        let session = Arc::new(RwLock::new(result));

        let setup_handler = ChannelMessageHandler::make_for_setup(&session, self.upstream).await?;
        self.handler = Some(setup_handler);

        self.upstream
            .worker()
            .ok_or_else(|| Error::InvalidState("Worker not available!".to_string()))
            .unwrap()
            .session_started(&session)
            .await?;

        self.result = Some(session);

        Ok(())
    }

    async fn receive_setup_response(&mut self, for_msg_id: u64) -> crate::Result<IncomingMessage> {
        let is_auth_done = self.authenticator.is_authenticated()?;

        // After the NTLM exchange completes, some servers send an additional
        // STATUS_MORE_PROCESSING_REQUIRED with a final SPNEGO accept token
        // (e.g. mechListMIC verification) before STATUS_SUCCESS.  Accept both
        // statuses so the session setup can proceed.
        let expected_status: &[Status] = if is_auth_done {
            &[Status::Success, Status::MoreProcessingRequired]
        } else {
            &[Status::MoreProcessingRequired]
        };

        let roptions = ReceiveOptions::new()
            .with_status(expected_status)
            .with_msg_id_filter(for_msg_id);

        let channel_set_up = self.result.is_some()
            && self
                .result
                .as_ref()
                .unwrap()
                .read()
                .await?
                .channel
                .is_some();
        // Skip security validation when the channel (signing keys) is not
        // yet available.  This covers both the initial rounds (auth not done)
        // AND extra SPNEGO rounds after NTLM completes but before
        // make_channel() derives the session key.
        let skip_security_validation = !channel_set_up;
        if let Some(handler) = &self.handler {
            log::trace!(
                "setup loop: receiving with channel handler; skip_security_validation={skip_security_validation}"
            );
            handler
                .recvo_internal(roptions, skip_security_validation)
                .await
        } else {
            log::trace!("setup loop: receiving with upstream handler");
            self.upstream.handler.recvo(roptions).await
        }
    }

    async fn send_setup_request(&mut self, buf: Vec<u8>) -> crate::Result<SendMessageResult> {
        // We'd like to update preauth hash with the last request before accept.
        // therefore we update it here for the PREVIOUS repsponse, assuming that we get an empty request when done.
        let request = T::make_request(self, buf).await?;

        let send_result = if let Some(handler) = self.handler.as_ref() {
            log::trace!("setup loop: sending with channel handler");
            handler.sendo(request).await?
        } else {
            log::trace!("setup loop: sending with upstream handler");
            self.upstream.sendo(request).await?
        };

        self.next_preauth_hash(send_result.raw.as_ref().unwrap());
        Ok(send_result)
    }

    /// Initializes the channel that is resulted from the current session setup.
    /// - Calls `T::on_session_key_exchanged` before setting up the channel.
    /// - Sets `self.channel` to the instantiated channel.
    /// - Calls `T::on_channel_set_up` after setting up the channel.
    async fn make_channel(&mut self) -> crate::Result<()> {
        T::on_session_key_exchanged(self).await?;
        log::trace!("Session keys are set.");

        let session_key = self.session_key()?;
        let preauth_hash_val = self.preauth_hash_value();
        if cfg!(feature = "__debug-dump-keys") {
            log::debug!(
                "make_channel: session_key={:02x?}, preauth_hash(first 16)={:02x?}",
                session_key,
                preauth_hash_val.as_ref().map(|h| &h[..16])
            );
        }

        let channel_info = ChannelInfo::new(
            self.new_channel_id,
            &session_key,
            &preauth_hash_val,
            self.conn_info,
        )?;

        self.channel = Some(channel_info);

        let mut session_lock = self.result.as_ref().unwrap().write().await?;
        session_lock.set_channel(self.channel.take().unwrap());

        log::trace!("Channel for current setup has been initialized");
        Ok(())
    }

    fn session_key(&self) -> crate::Result<KeyToDerive> {
        self.authenticator.session_key()
    }

    fn preauth_hash_value(&self) -> Option<PreauthHashValue> {
        self.preauth_hash
            .as_ref()
            .unwrap()
            .unwrap_final_hash()
            .copied()
    }

    fn next_preauth_hash(&mut self, data: &IoVec) -> &PreauthHashState {
        if let Some(ref mut hash) = self.preauth_hash {
            if hash.is_in_progress() {
                log::trace!(
                    "preauth hash: chaining {} bytes ({} segments)",
                    data.total_size(),
                    data.len()
                );
                *hash = hash.clone().next(data);
                if cfg!(feature = "__debug-dump-keys") {
                    if let &mut PreauthHashState::InProgress(ref h) = hash {
                        log::debug!("preauth hash (updated): {:02x?}", &h[..16]);
                    }
                }
            }
        }
        self.preauth_hash.as_ref().unwrap()
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
        if setup.result.is_none() {
            log::warn!("No session to cleanup in binding.");
            return Ok(());
        }
        setup
            .upstream
            .worker()
            .ok_or_else(|| Error::InvalidState("Worker not available!".to_string()))?
            .session_ended(setup.result.as_ref().unwrap())
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
        if setup.result.is_none() {
            log::trace!("No session to cleanup in setup.");
            return Ok(());
        }

        log::trace!("Invalidating session before cleanup.");
        let session = setup.result.as_ref().unwrap();
        {
            let session_lock = session.read().await?;
            session_lock.session.write().await?.invalidate();
        }

        setup
            .upstream
            .worker()
            .ok_or_else(|| Error::InvalidState("Worker not available!".to_string()))?
            .session_ended(setup.result.as_ref().unwrap())
            .await
    }

    async fn on_session_key_exchanged<T>(setup: &mut SessionSetup<'_, T>) -> crate::Result<()>
    where
        T: SessionSetupProperties,
    {
        // Only on new sessions we need to initialize the session state with the keys.
        log::trace!("Session keys exchanged. Setting up session state.");
        setup
            .result
            .as_ref()
            .unwrap()
            .read()
            .await?
            .session
            .write()
            .await?
            .setup(
                &setup.session_key()?,
                &setup.preauth_hash_value(),
                setup.conn_info,
            )
    }

    async fn on_setup_success<T>(setup: &mut SessionSetup<'_, T>) -> crate::Result<()>
    where
        T: SessionSetupProperties,
    {
        log::trace!("Session setup successful");
        let result = setup.result.as_ref().unwrap().read().await?;
        let mut session = result.session.write().await?;
        session.ready(setup.flags.unwrap(), setup.conn_info)
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
