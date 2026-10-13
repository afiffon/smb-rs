//! A basic create file test.

mod common;
use std::str::FromStr;
use std::time::Duration;

use common::{
    TestConstants, TestEnv, TestServer, default_connection_config, make_server_connection_for,
};
use serial_test::serial;
use smb::{Client, ClientConfig, UncPath};
use smb::{ConnectionConfig, FileCreateArgs};
use smb_fscc::FileDispositionInformation;
use smb_transport::{TransportConfig, TransportError};

#[maybe_async::maybe_async]
async fn _do_minimal_connection_test(
    server: TestServer,
    conn_config: Option<ConnectionConfig>,
    share: Option<&str>,
) -> smb::Result<()> {
    let (client, share_path) = make_server_connection_for(
        server,
        share.unwrap_or(TestConstants::DEFAULT_SHARE),
        conn_config,
    )
    .await?;

    exercise_share(&client, &share_path).await
}

#[maybe_async::maybe_async]
async fn exercise_share(client: &Client, share_path: &UncPath) -> smb::Result<()> {
    // Create a file
    let file = client
        .create_file(
            &share_path.clone().with_path("basic.txt"),
            &FileCreateArgs::make_create_new(Default::default(), Default::default()),
        )
        .await?
        .unwrap_file();

    file.set_info(FileDispositionInformation::default()).await?;

    file.close().await?;
    Ok(())
}

#[maybe_async::maybe_async]
async fn _test_basic_integration(
    server: TestServer,
    transport: TransportConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let conn_config = ConnectionConfig {
        transport,
        ..Default::default()
    };
    Ok(_do_minimal_connection_test(server, Some(conn_config), None).await?)
}

#[test_log::test(maybe_async::test(
    not(feature = "async"),
    async(feature = "async", tokio::test(flavor = "multi_thread"))
))]
#[serial]
async fn test_basic_guest() -> smb::Result<()> {
    with_temp_env!(
        [
            (TestEnv::USER, Some(TestEnv::GUEST_USER.to_string())),
            (TestEnv::PASSWORD, Some(TestEnv::GUEST_PASSWORD.to_string())),
        ],
        _do_minimal_connection_test(
            TestServer::Workgroup,
            ConnectionConfig {
                allow_unsigned_guest_access: true,
                ..Default::default()
            }
            .into(),
            Some(TestConstants::PUBLIC_GUEST_SHARE)
        )
    )
}

#[test_log::test(maybe_async::test(
    not(feature = "async"),
    async(feature = "async", tokio::test(flavor = "multi_thread"))
))]
#[serial]
async fn test_basic_guest_domain_rejected() -> smb::Result<()> {
    let result = with_temp_env!(
        [
            (TestEnv::USER, Some(TestEnv::GUEST_USER.to_string())),
            (TestEnv::PASSWORD, Some(TestEnv::GUEST_PASSWORD.to_string())),
        ],
        _do_minimal_connection_test(
            TestServer::Domain,
            Some(ConnectionConfig {
                allow_unsigned_guest_access: true,
                ..Default::default()
            }),
            Some(TestConstants::PUBLIC_GUEST_SHARE)
        )
    );
    assert!(matches!(result, Err(smb::Error::LogonFailure { .. })));
    Ok(())
}

#[test_log::test(maybe_async::test(
    not(feature = "async"),
    async(feature = "async", tokio::test(flavor = "multi_thread"))
))]
#[serial]
async fn test_basic_null_session_domain() -> smb::Result<()> {
    let server = TestServer::Domain.address();
    let share_path = UncPath::new(&server)?.with_share(TestConstants::PUBLIC_GUEST_SHARE)?;
    let client = Client::new(ClientConfig {
        connection: ConnectionConfig {
            allow_unsigned_guest_access: true,
            ..default_connection_config()
        },
        ..Default::default()
    });
    client.share_connect_null(&share_path).await?;
    exercise_share(&client, &share_path).await
}

#[test_log::test(maybe_async::test(
    not(feature = "async"),
    async(feature = "async", tokio::test(flavor = "multi_thread"))
))]
#[serial]
async fn test_basic_auth_fail() -> smb::Result<()> {
    with_temp_env!(
        [(
            TestEnv::PASSWORD,
            Some(TestEnv::DEFAULT_PASSWORD.to_string() + "1")
        ),],
        do_test_basic_auth_fail(TestServer::Workgroup)
    )
}

#[test_log::test(maybe_async::test(
    not(feature = "async"),
    async(feature = "async", tokio::test(flavor = "multi_thread"))
))]
#[serial]
async fn test_basic_auth_fail_domain() -> smb::Result<()> {
    with_temp_env!(
        [(
            TestEnv::PASSWORD,
            Some(TestEnv::DEFAULT_PASSWORD.to_string() + "1")
        ),],
        do_test_basic_auth_fail(TestServer::Domain)
    )
}

#[maybe_async::maybe_async]
async fn do_test_basic_auth_fail(server: TestServer) -> smb::Result<()> {
    let res = _do_minimal_connection_test(server, None, None)
        .await
        .unwrap_err();
    assert!(
        matches!(res, smb::Error::LogonFailure { .. }),
        "expected logon failure, got {res:?}"
    );
    smb::Result::Ok(())
}

#[cfg(feature = "kerberos")]
#[test_log::test(maybe_async::test(
    not(feature = "async"),
    async(feature = "async", tokio::test(flavor = "multi_thread"))
))]
#[serial]
async fn test_basic_kerberos_auth_fail() -> smb::Result<()> {
    with_temp_env!(
        [
            (TestEnv::USER, Some(TestEnv::KERBEROS_USER.to_string())),
            (
                TestEnv::PASSWORD,
                Some(TestEnv::DEFAULT_PASSWORD.to_string() + "1")
            ),
        ],
        do_test_basic_kerberos_auth_fail()
    )
}

#[cfg(feature = "kerberos")]
#[maybe_async::maybe_async]
async fn do_test_basic_kerberos_auth_fail() -> smb::Result<()> {
    let res = _do_minimal_connection_test(
        TestServer::Kerberos,
        Some(ConnectionConfig {
            auth_methods: smb::connection::AuthMethodsConfig {
                kerberos: true,
                ntlm: false,
            },
            ..default_connection_config()
        }),
        Some(TestConstants::KERBEROS_SHARE),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(res, smb::Error::LogonFailure { .. }),
        "expected logon failure, got {res:?}"
    );
    Ok(())
}

#[cfg(feature = "kerberos")]
#[test_log::test(maybe_async::test(
    not(feature = "async"),
    async(feature = "async", tokio::test(flavor = "multi_thread"))
))]
#[serial]
async fn test_basic_kerberos() -> Result<(), Box<dyn std::error::Error>> {
    with_temp_env!(
        [(TestEnv::USER, Some(TestEnv::KERBEROS_USER.to_string())),],
        _do_minimal_connection_test(
            TestServer::Kerberos,
            Some(ConnectionConfig {
                auth_methods: smb::connection::AuthMethodsConfig {
                    kerberos: true,
                    ntlm: false,
                },
                ..default_connection_config()
            }),
            Some(TestConstants::KERBEROS_SHARE)
        )
    )?;
    Ok(())
}

#[maybe_async::maybe_async]
async fn _test_connection_timeout_fail(
    transport_config: TransportConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::time::Instant;

    const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
    let client = Client::new(ClientConfig {
        connection: ConnectionConfig {
            timeout: Some(CONNECT_TIMEOUT),
            transport: transport_config,
            ..Default::default()
        },
        ..Default::default()
    });

    const UNRESPONSIVE_SMB_HOST: &str = "8.8.8.8"; // unless Google decides they like Microsoft...
    let time_before = Instant::now();
    let share_connect_result = client
        .share_connect(
            &UncPath::from_str(&format!("\\\\{}\\share", UNRESPONSIVE_SMB_HOST)).unwrap(),
            "user",
            "password".to_string(),
        )
        .await
        .map(|_| ());
    let time_after = Instant::now();

    if !matches!(
        share_connect_result,
        Err(smb::Error::TransportError(TransportError::Timeout(
            CONNECT_TIMEOUT
        )))
    ) {
        return Err(format!(
            "Expected OperationTimeout error, got {:?}!",
            share_connect_result
        )
        .into());
    }

    let delta_timeout = time_after.duration_since(time_before);
    let connect_timeout_with_margins_max = CONNECT_TIMEOUT + Duration::from_millis(100);
    let connect_timeout_with_margins_min = CONNECT_TIMEOUT - Duration::from_millis(5);
    if delta_timeout < connect_timeout_with_margins_min
        || delta_timeout > connect_timeout_with_margins_max
    {
        return Err(format!(
            "Expected timeout to be at least {:?}, but it was {:?}!",
            connect_timeout_with_margins_max, delta_timeout
        )
        .into());
    }

    Ok(())
}

/// Generates tests for different transport configurations.
macro_rules! test_transport {
    (
        $($transport_config:ty: $config_value:tt)+
    ) => {
            $(
                pastey::paste!{
#[test_log::test(maybe_async::test(
    not(feature = "async"),
    async(feature = "async", tokio::test(flavor = "multi_thread"))
))]
#[serial]
async fn [<test_basic_integration_ $transport_config:lower>]() -> Result<(), Box<dyn std::error::Error>> {
    _test_basic_integration(TestServer::Workgroup, TransportConfig::$config_value).await
}

#[test_log::test(maybe_async::test(
    not(feature = "async"),
    async(feature = "async", tokio::test(flavor = "multi_thread"))
))]
#[serial]
async fn [<test_basic_integration_domain_ $transport_config:lower>]() -> Result<(), Box<dyn std::error::Error>> {
    _test_basic_integration(TestServer::Domain, TransportConfig::$config_value).await
}

#[test_log::test(maybe_async::test(
    not(feature = "async"),
    async(feature = "async", tokio::test(flavor = "multi_thread"))
))]
#[serial]
async fn [<test_connection_timeout_fail_ $transport_config:lower>]() -> Result<(), Box<dyn std::error::Error>> {
    _test_connection_timeout_fail(TransportConfig::$config_value).await
}

            }
        )+
    };

    // Sugary XxxTransport::XxxTransport syntax
    (
        $($transport_config:ty,)+
    ) => {
        test_transport!($($transport_config: $transport_config)+);
    }
}

test_transport!(Tcp,);

#[cfg(feature = "netbios-transport")]
test_transport!(NetBios,);

#[cfg(feature = "test-quic")]
test_transport!(Quic,);

#[cfg(feature = "test-rdma")]
test_transport!(Rdma,);
