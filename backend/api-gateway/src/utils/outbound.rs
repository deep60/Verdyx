//! Outbound request policy for URLs that users control (web intel targets,
//! webhook destinations).
//!
//! Checking the hostname text is not enough: a public name can resolve to an
//! internal address, a Docker service name has no dots, and a redirect can
//! point anywhere. This module enforces the policy at three points:
//!
//! 1. [`validate_outbound_url`] rejects bad schemes, userinfo, internal names
//!    and non-public IP literals before any request is made.
//! 2. [`PublicOnlyResolver`] is installed as the client's DNS resolver, so every
//!    connection (including redirects and later requests) only reaches public
//!    addresses. A DNS answer that mixes public and internal addresses is
//!    rejected outright.
//! 3. [`safe_redirect_policy`] re-runs the URL check on every redirect target,
//!    which covers IP literals that never go through DNS.
//!
//! The address rules mirror the analysis engine's `url_policy` module.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use reqwest::Url;
use url::Host;

/// Reject URLs that must never be fetched on a user's behalf.
pub fn validate_outbound_url(url: &Url) -> Result<(), String> {
    match url.scheme() {
        "http" | "https" => {}
        other => return Err(format!("scheme {other} is not allowed")),
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("URLs with userinfo are not allowed".into());
    }
    match url.port_or_known_default() {
        Some(0) | None => return Err("invalid port".into()),
        Some(_) => {}
    }
    match url.host() {
        Some(Host::Ipv4(v4)) if !is_public_ip(IpAddr::V4(v4)) => {
            Err(format!("{v4} is not a public address"))
        }
        Some(Host::Ipv6(v6)) if !is_public_ip(IpAddr::V6(v6)) => {
            Err(format!("{v6} is not a public address"))
        }
        Some(Host::Domain(domain)) if is_blocked_hostname(domain) => {
            Err(format!("host {domain} is not a public destination"))
        }
        Some(_) => Ok(()),
        None => Err("missing host".into()),
    }
}

/// Resolve `host` and return its addresses only if every one is public.
pub async fn resolve_public(host: &str, port: u16) -> Result<Vec<SocketAddr>, String> {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = host.parse::<IpAddr>() {
        return if is_public_ip(ip) {
            Ok(vec![SocketAddr::new(ip, port)])
        } else {
            Err(format!("{ip} is not a public address"))
        };
    }
    if is_blocked_hostname(host) {
        return Err(format!("host {host} is not a public destination"));
    }
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| format!("could not resolve {host}: {e}"))?
        .collect();
    check_all_public(host, addrs)
}

fn check_all_public(host: &str, addrs: Vec<SocketAddr>) -> Result<Vec<SocketAddr>, String> {
    if addrs.is_empty() {
        return Err(format!("{host} did not resolve"));
    }
    if let Some(bad) = addrs.iter().find(|a| !is_public_ip(a.ip())) {
        return Err(format!(
            "{host} resolves to non-public address {}",
            bad.ip()
        ));
    }
    Ok(addrs)
}

/// DNS resolver that refuses names resolving to any non-public address.
#[derive(Debug, Default, Clone)]
pub struct PublicOnlyResolver;

impl Resolve for PublicOnlyResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_string();
        Box::pin(async move {
            let addrs = resolve_public(&host, 0)
                .await
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;
            let iter: Addrs = Box::new(addrs.into_iter());
            Ok(iter)
        })
    }
}

/// Follow at most `max` redirects, and only to URLs that pass the policy.
pub fn safe_redirect_policy(max: usize) -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(move |attempt| {
        if attempt.previous().len() >= max {
            return attempt.stop();
        }
        match validate_outbound_url(attempt.url()) {
            Ok(()) => attempt.follow(),
            Err(_) => attempt.stop(),
        }
    })
}

/// Client builder for user-controlled destinations: public-only DNS, checked
/// redirects, and no environment proxy (a proxy would resolve names itself).
pub fn outbound_client_builder(max_redirects: usize) -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .dns_resolver(Arc::new(PublicOnlyResolver))
        .redirect(safe_redirect_policy(max_redirects))
        .no_proxy()
}

pub fn is_blocked_hostname(host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return true;
    }
    // Single-label names are Docker/Compose service names or LAN hosts
    // (e.g. `bounty-manager`, `redis`, `postgres`), never public sites.
    if !host.contains('.') {
        return true;
    }
    const EXACT: &[&str] = &[
        "localhost.localdomain",
        "metadata.google.internal",
        "metadata.google.com",
        "instance-data.ec2.internal",
        "kubernetes.default",
        "kubernetes.default.svc",
        "kubernetes.default.svc.cluster.local",
    ];
    if EXACT.contains(&host.as_str()) {
        return true;
    }
    const SUFFIXES: &[&str] = &[
        ".localhost",
        ".localdomain",
        ".local",
        ".internal",
        ".intranet",
        ".lan",
        ".home.arpa",
        ".invalid",
        ".ts.net",
        ".cluster.local",
    ];
    SUFFIXES.iter().any(|suffix| host.ends_with(suffix))
}

pub fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => {
            // IPv4-mapped/compatible addresses must get the IPv4 rules.
            if let Some(v4) = v6.to_ipv4() {
                return is_public_v4(v4);
            }
            is_public_v6(v6)
        }
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    if ip.is_unspecified()
        || ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_documentation()
    {
        return false;
    }
    // 0.0.0.0/8
    if a == 0 {
        return false;
    }
    // 100.64.0.0/10 carrier-grade NAT (also Tailscale).
    if a == 100 && (b & 0b1100_0000) == 0b0100_0000 {
        return false;
    }
    // 192.0.0.0/24 IETF protocol assignments.
    if a == 192 && b == 0 && c == 0 {
        return false;
    }
    // 198.18.0.0/15 benchmarking.
    if a == 198 && (b & 0xfe) == 18 {
        return false;
    }
    // 224.0.0.0/4 multicast and 240.0.0.0/4 reserved.
    a < 224
}

fn is_public_v6(ip: Ipv6Addr) -> bool {
    if ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() {
        return false;
    }
    let s = ip.segments();
    // fe80::/10 link-local, fec0::/10 site-local.
    if (s[0] & 0xffc0) == 0xfe80 || (s[0] & 0xffc0) == 0xfec0 {
        return false;
    }
    // fc00::/7 unique local (includes Tailscale fd7a:115c:a1e0::/48).
    if (s[0] & 0xfe00) == 0xfc00 {
        return false;
    }
    // 2001:db8::/32 and 3fff::/20 documentation.
    if (s[0] == 0x2001 && s[1] == 0x0db8) || (s[0] & 0xfff0) == 0x3ff0 {
        return false;
    }
    // 2001::/32 Teredo, 2001:2::/48 benchmarking.
    if s[0] == 0x2001 && (s[1] == 0 || (s[1] == 2 && s[2] == 0)) {
        return false;
    }
    // 100::/64 discard-only.
    if s[0] == 0x0100 && s[1] == 0 && s[2] == 0 && s[3] == 0 {
        return false;
    }
    // NAT64 prefixes can translate to internal IPv4.
    if s[0] == 0x0064 && s[1] == 0xff9b && (s[2] == 0 || s[2] == 1) {
        return false;
    }
    // 2002::/16 6to4 embeds an IPv4 address.
    if s[0] == 0x2002 {
        let embedded = Ipv4Addr::new(
            (s[1] >> 8) as u8,
            (s[1] & 0xff) as u8,
            (s[2] >> 8) as u8,
            (s[2] & 0xff) as u8,
        );
        if !is_public_v4(embedded) {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(u: &str) -> Result<(), String> {
        validate_outbound_url(&Url::parse(u).unwrap())
    }

    #[test]
    fn allows_ordinary_public_urls() {
        assert!(check("https://example.com/path").is_ok());
        assert!(check("http://www.example.co.uk:8080/").is_ok());
        assert!(check("https://8.8.8.8/").is_ok());
        assert!(check("https://[2606:4700:4700::1111]/").is_ok());
    }

    #[test]
    fn blocks_schemes_and_userinfo() {
        assert!(check("file:///etc/passwd").is_err());
        assert!(check("gopher://example.com/").is_err());
        assert!(check("https://user:pw@example.com/").is_err());
    }

    #[test]
    fn blocks_ranges_the_old_prefix_check_missed() {
        for u in [
            "http://172.17.0.1/",          // Docker bridge
            "http://172.31.255.255/",      // rest of 172.16/12
            "http://100.112.183.51:3310/", // Tailscale (CGNAT)
            "http://[fd7a:115c:a1e0::1]/", // Tailscale IPv6
            "http://[fe80::1]/",
            "http://[::ffff:127.0.0.1]/", // IPv4-mapped loopback
            "http://[::ffff:10.0.0.1]/",
            "http://0.0.0.0/",
            "http://0/",          // parses as 0.0.0.0
            "http://2130706433/", // decimal 127.0.0.1
            "http://0x7f000001/", // hex 127.0.0.1
            "http://127.1/",
            "http://169.254.169.254/latest/meta-data/",
        ] {
            assert!(check(u).is_err(), "{u} should be blocked");
        }
    }

    #[test]
    fn blocks_internal_hostnames() {
        for u in [
            "http://localhost/",
            "http://LOCALHOST./",
            "http://bounty-manager:8080/",
            "http://redis:6379/",
            "http://postgres/",
            "http://metadata.google.internal/",
            "http://foo.svc.cluster.local/",
            "http://verdyx-clamav.tail1234.ts.net/",
            "http://printer.lan/",
        ] {
            assert!(check(u).is_err(), "{u} should be blocked");
        }
    }

    #[test]
    fn mixed_dns_answers_are_rejected() {
        let addrs = vec![
            "93.184.216.34:443".parse().unwrap(),
            "10.0.0.5:443".parse().unwrap(),
        ];
        assert!(check_all_public("evil.example", addrs).is_err());
        assert!(check_all_public("none.example", vec![]).is_err());
        let ok = vec!["93.184.216.34:443".parse().unwrap()];
        assert!(check_all_public("example.com", ok).is_ok());
    }

    #[tokio::test]
    async fn resolve_public_rejects_loopback_names_and_literals() {
        assert!(resolve_public("localhost", 80).await.is_err());
        assert!(resolve_public("127.0.0.1", 80).await.is_err());
        assert!(resolve_public("[::1]", 80).await.is_err());
        assert!(resolve_public("8.8.8.8", 80).await.is_ok());
    }

    #[tokio::test]
    async fn client_refuses_to_connect_to_loopback() {
        // A real listener on loopback: the request must fail at DNS, not reach it.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let client = outbound_client_builder(3).build().unwrap();
        let err = client
            .get(format!("http://localhost:{port}/"))
            .send()
            .await
            .expect_err("loopback must be refused");
        assert!(err.is_connect() || err.is_request(), "{err}");
    }

    #[tokio::test]
    async fn redirect_to_internal_ip_is_not_followed() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        // The redirecting server itself is on loopback, so call the policy via a
        // plain client pointed at it, but with our redirect policy installed.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf).await;
                let _ = sock
                    .write_all(
                        b"HTTP/1.1 302 Found\r\nLocation: http://169.254.169.254/latest/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .await;
            }
        });
        let client = reqwest::Client::builder()
            .redirect(safe_redirect_policy(5))
            .no_proxy()
            .build()
            .unwrap();
        let resp = client
            .get(format!("http://127.0.0.1:{port}/"))
            .send()
            .await
            .unwrap();
        // The policy stopped, so we get the 302 itself rather than following it.
        assert_eq!(resp.status().as_u16(), 302);
    }
}
