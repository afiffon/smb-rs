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

/// Once the key is available, the request finishes the preauthentication hash
/// and installs the channel. Another challenge cannot be processed after that.
fn expected_setup_status(authenticated: bool, has_session_key: bool) -> crate::Result<Status> {
    match (authenticated, has_session_key) {
        (_, true) => Ok(Status::Success),
        (false, false) => Ok(Status::MoreProcessingRequired),
        (true, false) => Err(Error::InvalidState(
            "SSPI completed authentication without a session key.".into(),
        )),
    }
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
            "Setting up session for user {}.",
            self.authenticator.user_name().inner()
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
    async fn _setup_loop(&mut self) -> crate::Result<()> {
        loop {
            // Generate the next client token and determine the only valid SMB reply.
            let token = match self.last_setup_response.as_ref() {
                Some(response) => self.authenticator.next(&response.buffer).await?,
                None => self.authenticator.next(&[]).await?,
            };
            let expected_status = expected_setup_status(
                self.authenticator.is_authenticated()?,
                self.authenticator.has_session_key()?,
            )?;
            if token.is_empty() {
                return Err(Error::InvalidState(
                    "SSPI produced no token for a session setup request.".into(),
                ));
            }

            // The final response is signed. Install keys after hashing the request,
            // even if SSPI still needs that response's SPNEGO MIC to complete.
            let is_final_exchange = expected_status == Status::Success;
            if is_final_exchange && self.result.is_none() {
                return Err(Error::InvalidState(
                    "Session keys became available before a session ID was assigned.".into(),
                ));
            }
            let request = self.send_setup_request(token).await?;
            if is_final_exchange {
                self.preauth_hash = self.preauth_hash.take().unwrap().finish().into();
                self.make_channel().await?;
            }

            let response = self
                .receive_setup_response(request.msg_id, expected_status)
                .await?;
            let session_id = response.message.header.session_id;
            if session_id == 0
                || self
                    .handler
                    .as_ref()
                    .is_some_and(|handler| handler.session_id() != session_id)
            {
                return Err(Error::InvalidMessage(
                    "Session setup response has a missing or mismatched session ID.".into(),
                ));
            }
            let session_setup_response = response.message.content.to_sessionsetup()?;

            if !is_final_exchange {
                // Only challenge responses extend the preauthentication transcript.
                if self.result.is_none() {
                    log::trace!("Creating session state with id {session_id}.");
                    self.set_session(T::init_session(self, session_id).await?)
                        .await?;
                }
                self.next_preauth_hash(&response.raw);
                self.last_setup_response = Some(session_setup_response);
                continue;
            }

            // Success requires both SMB signature validation and SSPI completion.
            if !session_setup_response
                .session_flags
                .is_guest_or_null_session()
                && !response.form.signed_or_encrypted()
            {
                return Err(Error::InvalidMessage("Expected a signed message!".into()));
            }
            self.complete_authentication(&session_setup_response.buffer)
                .await?;
            self.flags = Some(session_setup_response.session_flags);
            break;
        }

        log::trace!("setup success, finishing up.");
        T::on_setup_success(self).await?;
        Ok(())
    }

    async fn complete_authentication(&mut self, token: &[u8]) -> crate::Result<()> {
        let session_key = self.authenticator.session_key()?;
        // A successful SMB reply may carry the last SPNEGO token. Consume it
        // locally; sending another setup request would restart a completed exchange.
        if !self.authenticator.is_authenticated()? {
            let output = self.authenticator.next(token).await?;
            if !output.is_empty() {
                return Err(Error::InvalidState(
                    "SSPI produced another token after SMB session setup succeeded.".into(),
                ));
            }
        }
        if !self.authenticator.is_authenticated()? {
            return Err(Error::InvalidState(
                "SMB session setup succeeded before SSPI authentication completed.".into(),
            ));
        }
        if self.authenticator.session_key()? != session_key {
            return Err(Error::InvalidState(
                "SSPI changed the session key after the channel was installed.".into(),
            ));
        }
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

    async fn receive_setup_response(
        &mut self,
        for_msg_id: u64,
        expected_status: Status,
    ) -> crate::Result<IncomingMessage> {
        let expected_statuses = [expected_status];
        let roptions = ReceiveOptions::new()
            .with_status(&expected_statuses)
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
        let skip_security_validation =
            expected_status == Status::MoreProcessingRequired && !channel_set_up;
        if let Some(handler) = &self.handler {
            log::trace!(
                "setup loop: receiving with channel handler; skip_security_validation={skip_security_validation}"
            );
            handler
                .recvo_internal(roptions, skip_security_validation)
                .await
        } else {
            if !skip_security_validation {
                return Err(Error::InvalidState(
                    "Cannot validate session setup success without a channel handler.".into(),
                ));
            }
            log::trace!("setup loop: receiving with upstream handler");
            self.upstream.handler.recvo(roptions).await
        }
    }

    async fn send_setup_request(&mut self, buf: Vec<u8>) -> crate::Result<SendMessageResult> {
        // Include each request before deriving the keys that validate its response.
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

        let channel_info = ChannelInfo::new(
            self.new_channel_id,
            &self.session_key()?,
            &self.preauth_hash_value(),
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
            *hash = hash.clone().next(data);
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

#[cfg(test)]
mod tests {
    use super::expected_setup_status;
    use smb_msg::Status;

    #[test]
    fn setup_requires_a_key_for_success() {
        assert_eq!(
            expected_setup_status(false, false).unwrap(),
            Status::MoreProcessingRequired
        );
        assert!(expected_setup_status(true, false).is_err());
    }

    #[test]
    fn setup_requires_success_after_key_exchange() {
        assert_eq!(expected_setup_status(false, true).unwrap(), Status::Success);
        assert_eq!(expected_setup_status(true, true).unwrap(), Status::Success);
    }
}
