use std::net::{IpAddr, Ipv6Addr, SocketAddr, ToSocketAddrs};

pub struct TransportUtils;
use crate::TransportError;

impl TransportUtils {
    /// Parses a string endpoint into a [SocketAddr]. If no port is specified, port 0 is used.
    /// Returns [TransportError::InvalidAddress] if the address is invalid or cannot be resolved.
    ///
    /// Accepts `host`, `host:port`, an IPv4 or IPv6 literal with or without a port, and a
    /// bracketed IPv6 literal. Note that a bare IPv6 literal cannot carry a port, because the
    /// colons are ambiguous - `[::1]:445` is the way to give one.
    pub fn parse_socket_address(endpoint: &str) -> super::error::Result<SocketAddr> {
        let invalid = || TransportError::InvalidAddress(endpoint.to_string());

        // A complete socket address: `1.2.3.4:445` or `[::1]:445`.
        if let Ok(address) = endpoint.parse::<SocketAddr>() {
            return Ok(address);
        }

        // A bare IP literal with no port: `1.2.3.4` or `::1`.
        if let Ok(ip) = endpoint.parse::<IpAddr>() {
            return Ok(SocketAddr::new(ip, 0));
        }

        // A bracketed IPv6 literal with no port: `[::1]`.
        if let Some(inner) = endpoint.strip_prefix('[').and_then(|r| r.strip_suffix(']')) {
            return inner
                .parse::<Ipv6Addr>()
                .map(|ip| SocketAddr::new(IpAddr::V6(ip), 0))
                .map_err(|_| invalid());
        }

        // Anything else is a host name, with or without a port. Only a trailing
        // `:digits` counts as a port, so a name is never split on the wrong colon.
        let has_port = endpoint.rsplit_once(':').is_some_and(|(host, port)| {
            !host.is_empty() && !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit())
        });
        let endpoint = if has_port {
            endpoint.to_owned()
        } else {
            format!("{endpoint}:0")
        };

        endpoint
            .to_socket_addrs()
            .map_err(|_| invalid())?
            .next()
            .ok_or_else(invalid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4, SocketAddrV6};

    fn parse(endpoint: &str) -> SocketAddr {
        TransportUtils::parse_socket_address(endpoint)
            .unwrap_or_else(|e| panic!("{endpoint:?} should parse: {e}"))
    }

    #[test]
    fn parses_ipv4_with_and_without_a_port() {
        assert_eq!(
            parse("1.2.3.4:445"),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 445))
        );
        assert_eq!(
            parse("1.2.3.4"),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 0))
        );
    }

    #[test]
    fn parses_ipv6_in_every_spelling() {
        let loopback = Ipv6Addr::LOCALHOST;

        // Bracketed, with a port: the only form that can carry one.
        assert_eq!(
            parse("[::1]:445"),
            SocketAddr::V6(SocketAddrV6::new(loopback, 445, 0, 0))
        );
        // Bracketed, without a port.
        assert_eq!(
            parse("[::1]"),
            SocketAddr::V6(SocketAddrV6::new(loopback, 0, 0, 0))
        );
        // Bare. Previously this was split on the last colon and read as host
        // "::" with port 1.
        assert_eq!(
            parse("::1"),
            SocketAddr::V6(SocketAddrV6::new(loopback, 0, 0, 0))
        );
        assert_eq!(
            parse("2001:db8::1"),
            SocketAddr::V6(SocketAddrV6::new("2001:db8::1".parse().unwrap(), 0, 0, 0))
        );
        // A full-length literal, whose last group is all digits and so looks
        // most like a port.
        assert_eq!(
            parse("2001:db8:0:0:0:0:0:1"),
            SocketAddr::V6(SocketAddrV6::new("2001:db8::1".parse().unwrap(), 0, 0, 0))
        );
    }

    #[test]
    fn parses_host_names() {
        assert_eq!(parse("localhost:445").port(), 445);
        assert_eq!(parse("localhost").port(), 0);
    }

    #[test]
    fn rejects_malformed_endpoints() {
        for endpoint in ["[::1", "[not-an-address]", "[::1]:notaport"] {
            assert!(
                TransportUtils::parse_socket_address(endpoint).is_err(),
                "{endpoint:?} should be rejected"
            );
        }
    }
}
