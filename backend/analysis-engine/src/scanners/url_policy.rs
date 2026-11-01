//! Outbound-fetch policy for the URL scanner.
//!
//! A submitted URL must not be able to reach loopback, RFC1918, link-local,
//! or cloud-metadata addresses, including via redirects or DNS answers that
//! mix a public address with an internal one. TLS issuer and expiry are parsed
//! from a certificate the caller has already obtained; this module never
//! invents those fields.

use anyhow::{anyhow, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use url::{Host, Url};

pub(super) const FETCH_REFUSAL_PREFIX: &str = "refusing to fetch";
pub(super) const MAX_FETCH_BYTES: usize = 1024 * 1024;

pub(super) fn is_fetch_refusal(err: &str) -> bool {
    err.contains(FETCH_REFUSAL_PREFIX)
}

pub(super) fn refusal(url: &Url, reason: impl std::fmt::Display) -> anyhow::Error {
    anyhow!("{FETCH_REFUSAL_PREFIX} {url}: {reason}")
}

/// Allow only http(s) URLs whose host is not an internal name or non-public IP.
/// This does not resolve DNS; callers must also reject private answers.
pub(super) fn validate_url_policy(url: &Url) -> Result<()> {
    match url.scheme() {
        "http" | "https" => {}
        other => return Err(refusal(url, format!("scheme {other} is not allowed"))),
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(refusal(url, "URLs with userinfo are not allowed"));
    }
    if url.host_str().is_none() {
        return Err(refusal(url, "missing host"));
    }
    let port = url
        .port_or_known_default()
        .ok_or_else(|| refusal(url, "missing port"))?;
    if port == 0 {
        return Err(refusal(url, "port 0 is not allowed"));
    }

    match url.host() {
        Some(Host::Ipv4(v4)) if !is_public_v4(v4) => {
            Err(refusal(url, format!("{v4} is not a public address")))
        }
        Some(Host::Ipv6(v6)) if !is_public_ip(IpAddr::V6(v6)) => {
            Err(refusal(url, format!("{v6} is not a public address")))
        }
        Some(Host::Domain(domain)) if is_blocked_hostname(domain) => Err(refusal(
            url,
            format!("host {domain} is not a public destination"),
        )),
        Some(Host::Ipv4(_) | Host::Ipv6(_) | Host::Domain(_)) => Ok(()),
        None => Err(refusal(url, "missing host")),
    }
}

pub(super) fn is_blocked_hostname(host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return true;
    }
    const EXACT: &[&str] = &[
        "localhost",
        "localhost.localdomain",
        "metadata",
        "metadata.google.internal",
        "metadata.google.com",
        "metadata.internal",
        "instance-data",
        "instance-data.ec2.internal",
        "kubernetes",
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
    ];
    SUFFIXES.iter().any(|suffix| host.ends_with(suffix))
}

pub(super) fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => {
            // IPv4-mapped and IPv4-compatible addresses are a bypass if checked
            // only as IPv6. Apply the IPv4 policy to the embedded address.
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
    // 0.0.0.0/8 ("this network") — is_unspecified covers only 0.0.0.0.
    if a == 0 {
        return false;
    }
    // 100.64.0.0/10 carrier-grade NAT.
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
    if a >= 224 {
        return false;
    }
    true
}

fn is_public_v6(ip: Ipv6Addr) -> bool {
    if ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() {
        return false;
    }
    let s = ip.segments();
    // fe80::/10 link-local, fec0::/10 deprecated site-local.
    if (s[0] & 0xffc0) == 0xfe80 || (s[0] & 0xffc0) == 0xfec0 {
        return false;
    }
    // fc00::/7 unique local.
    if (s[0] & 0xfe00) == 0xfc00 {
        return false;
    }
    // 2001:db8::/32 and 3fff::/20 documentation.
    if s[0] == 0x2001 && s[1] == 0x0db8 || (s[0] & 0xfff0) == 0x3ff0 {
        return false;
    }
    // 2001::/32 Teredo tunneling.
    if s[0] == 0x2001 && s[1] == 0 {
        return false;
    }
    // 2001:2::/48 benchmarking.
    if s[0] == 0x2001 && s[1] == 2 && s[2] == 0 {
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
    // 2002::/16 6to4 embeds an IPv4 address in the next 32 bits.
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

/// Issuer and validity timestamps taken from a certificate that was already received.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ParsedCertificate {
    pub issuer: String,
    pub not_before: i64,
    pub not_after: i64,
}

/// Parsing failure is an error so the caller can leave issuer and expiry empty.
pub(super) fn parse_certificate(der: &[u8]) -> Result<ParsedCertificate> {
    let mut outer = Der::new(der);
    let mut certificate = Der::new(outer.expect(0x30)?);
    let mut tbs = Der::new(certificate.expect(0x30)?);
    if tbs.peek() == Some(0xa0) {
        let _ = tbs.read_tlv()?;
    }
    let _serial = tbs.expect(0x02)?;
    let _signature = tbs.expect(0x30)?;
    let issuer = format_name(tbs.expect(0x30)?)?;
    let mut validity = Der::new(tbs.expect(0x30)?);
    let not_before = read_time(&mut validity)?;
    let not_after = read_time(&mut validity)?;

    Ok(ParsedCertificate {
        issuer,
        not_before,
        not_after,
    })
}

struct Der<'a> {
    input: &'a [u8],
}

impl<'a> Der<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input }
    }

    fn peek(&self) -> Option<u8> {
        self.input.first().copied()
    }

    fn read_tlv(&mut self) -> Result<(u8, &'a [u8])> {
        let tag = self
            .input
            .first()
            .copied()
            .ok_or_else(|| anyhow!("truncated certificate"))?;
        self.input = &self.input[1..];
        let len = self.read_len()?;
        if self.input.len() < len {
            return Err(anyhow!("truncated certificate"));
        }
        let (body, rest) = self.input.split_at(len);
        self.input = rest;
        Ok((tag, body))
    }

    fn read_len(&mut self) -> Result<usize> {
        let first = self
            .input
            .first()
            .copied()
            .ok_or_else(|| anyhow!("truncated certificate length"))?;
        self.input = &self.input[1..];
        if first & 0x80 == 0 {
            return Ok(first as usize);
        }
        let nbytes = (first & 0x7f) as usize;
        if nbytes == 0 || nbytes > 4 || self.input.len() < nbytes {
            return Err(anyhow!("invalid certificate length"));
        }
        let mut len = 0usize;
        for byte in &self.input[..nbytes] {
            len = (len << 8) | *byte as usize;
        }
        self.input = &self.input[nbytes..];
        Ok(len)
    }

    fn expect(&mut self, tag: u8) -> Result<&'a [u8]> {
        let (got, body) = self.read_tlv()?;
        if got != tag {
            return Err(anyhow!("unexpected certificate field {got:#x}"));
        }
        Ok(body)
    }
}

fn format_name(name: &[u8]) -> Result<String> {
    let mut rdns = Der::new(name);
    let mut parts = Vec::new();
    while rdns.peek().is_some() {
        let rdn = rdns.expect(0x31)?;
        let mut set = Der::new(rdn);
        while set.peek().is_some() {
            let attr = set.expect(0x30)?;
            let mut pair = Der::new(attr);
            let oid = pair.expect(0x06)?;
            let (tag, value) = pair.read_tlv()?;
            let label = oid_label(oid).unwrap_or("OID");
            let text = decode_directory_string(tag, value)?;
            parts.push(format!("{label}={text}"));
        }
    }
    if parts.is_empty() {
        return Err(anyhow!("certificate issuer is empty"));
    }
    Ok(parts.join(", "))
}

fn oid_label(oid: &[u8]) -> Option<&'static str> {
    match oid {
        [0x55, 0x04, 0x03] => Some("CN"),
        [0x55, 0x04, 0x06] => Some("C"),
        [0x55, 0x04, 0x07] => Some("L"),
        [0x55, 0x04, 0x08] => Some("ST"),
        [0x55, 0x04, 0x0a] => Some("O"),
        [0x55, 0x04, 0x0b] => Some("OU"),
        [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01] => Some("emailAddress"),
        _ => None,
    }
}

fn decode_directory_string(tag: u8, value: &[u8]) -> Result<String> {
    match tag {
        0x0c | 0x13 | 0x16 | 0x14 | 0x1a => Ok(String::from_utf8_lossy(value).into_owned()),
        0x1e => decode_bmp_string(value),
        _ => Err(anyhow!("unsupported issuer string tag {tag:#x}")),
    }
}

fn decode_bmp_string(value: &[u8]) -> Result<String> {
    if !value.len().is_multiple_of(2) {
        return Err(anyhow!("invalid BMPString in certificate issuer"));
    }
    let units: Vec<u16> = value
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
        .collect();
    Ok(String::from_utf16_lossy(&units))
}

fn read_time(der: &mut Der<'_>) -> Result<i64> {
    let (tag, value) = der.read_tlv()?;
    let text = std::str::from_utf8(value).map_err(|_| anyhow!("certificate time is not ASCII"))?;
    let text = text.trim_end_matches('Z');
    let normalized = match tag {
        0x17 => {
            if text.len() < 10 {
                return Err(anyhow!("truncated certificate UTCTime"));
            }
            let year: i32 = text[..2]
                .parse()
                .map_err(|_| anyhow!("invalid certificate UTCTime"))?;
            let century = if year >= 50 { "19" } else { "20" };
            format!("{century}{text}")
        }
        0x18 => {
            if text.len() < 14 {
                return Err(anyhow!("truncated certificate GeneralizedTime"));
            }
            text.to_string()
        }
        _ => return Err(anyhow!("certificate validity is not a time")),
    };
    let digits: String = normalized.chars().take(14).collect();
    let naive = chrono::NaiveDateTime::parse_from_str(&digits, "%Y%m%d%H%M%S")
        .map_err(|_| anyhow!("certificate time {digits} is not a valid date"))?;
    Ok(naive.and_utc().timestamp())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_private_link_local_and_metadata_destinations() {
        let blocked = [
            "http://127.0.0.1/",
            "http://10.1.2.3/",
            "http://192.168.1.1/login",
            "http://172.16.0.1/",
            "http://169.254.169.254/latest/meta-data/",
            "http://0.0.0.0/",
            "http://100.64.0.1/",
            "http://[::1]/",
            "http://[fe80::1]/",
            "http://[fd00::1]/",
            "http://[::ffff:127.0.0.1]/",
            "http://[::ffff:169.254.169.254]/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://instance-data.ec2.internal/",
            "file:///etc/passwd",
            "gopher://example.com/",
            "http://user:pass@example.com/",
            "http://localhost/",
            "http://printer.local/",
        ];
        for raw in blocked {
            let url = Url::parse(raw).unwrap();
            assert!(
                validate_url_policy(&url).is_err(),
                "{raw} should be refused"
            );
        }
        assert!(validate_url_policy(&Url::parse("https://example.com/path").unwrap()).is_ok());
    }

    #[test]
    fn redirect_to_metadata_is_rejected_before_fetch() {
        let current = Url::parse("https://example.com/start").unwrap();
        let metadata = current
            .join("http://169.254.169.254/latest/meta-data/")
            .unwrap();
        assert!(validate_url_policy(&metadata).is_err());

        let scheme_relative = current
            .join("//metadata.google.internal/computeMetadata/v1/")
            .unwrap();
        assert!(validate_url_policy(&scheme_relative).is_err());

        let relative = current.join("/still-here").unwrap();
        assert!(validate_url_policy(&relative).is_ok());
        assert_eq!(relative.host_str(), Some("example.com"));
    }

    #[test]
    fn decimal_ip_obfuscation_is_treated_as_the_address_it_encodes() {
        let url = Url::parse("http://2130706433/").unwrap();
        assert_eq!(url.host_str(), Some("127.0.0.1"));
        assert!(validate_url_policy(&url).is_err());
    }

    #[test]
    fn public_addresses_are_allowed() {
        assert!(is_public_ip("1.1.1.1".parse().unwrap()));
        assert!(is_public_ip("8.8.8.8".parse().unwrap()));
        assert!(!is_public_ip("169.254.169.254".parse().unwrap()));
        assert!(!is_public_ip("::ffff:10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn certificate_facts_come_from_the_parsed_certificate() {
        fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
            let mut out = vec![tag];
            assert!(body.len() < 128);
            out.push(body.len() as u8);
            out.extend_from_slice(body);
            out
        }

        let cn_oid = [0x55, 0x04, 0x03];
        let issuer = tlv(
            0x30,
            &tlv(
                0x31,
                &tlv(0x30, &[tlv(0x06, &cn_oid), tlv(0x0c, b"Test CA")].concat()),
            ),
        );
        let validity = tlv(
            0x30,
            &[tlv(0x17, b"250101000000Z"), tlv(0x17, b"350101000000Z")].concat(),
        );
        let tbs = tlv(
            0x30,
            &[
                tlv(0x02, &[0x01]),
                tlv(0x30, &tlv(0x06, &cn_oid)),
                issuer,
                validity,
            ]
            .concat(),
        );
        let parsed = parse_certificate(&tlv(0x30, &tbs)).unwrap();
        assert_eq!(parsed.issuer, "CN=Test CA");
        assert!(parsed.not_after > parsed.not_before);
        assert_ne!(
            (parsed.not_after - chrono::Utc::now().timestamp()) / 86_400,
            90
        );
    }
}
