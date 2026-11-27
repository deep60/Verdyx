//! A small client for S3-compatible object storage: Amazon S3, Cloudflare
//! R2, Google Cloud Storage (with HMAC keys), Backblaze B2, Wasabi, MinIO and
//! the like. It lists a bucket and downloads objects, nothing else.
//!
//! Requests are signed with AWS Signature Version 4 here rather than through
//! the AWS SDK, so they can go through the webhook client
//! ([`crate::services::webhook_delivery::client_with_timeout`]): it connects
//! to public addresses only and doesn't follow redirects, so a team can't
//! point a "bucket" at Verdyx's own network.

use chrono::{DateTime, Utc};
use ring::hmac;
use sha2::{Digest, Sha256};

/// SHA-256 of an empty body: every request here is a GET.
const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// Where a bucket is and how to reach it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bucket {
    /// `https://host[:port]` for providers other than Amazon S3; `None` for
    /// Amazon S3 itself.
    pub endpoint: Option<url::Url>,
    pub region: String,
    pub name: String,
}

/// An access key pair.
#[derive(Clone)]
pub struct Keys {
    pub access_key_id: String,
    pub secret_access_key: String,
}

impl std::fmt::Debug for Keys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keys")
            .field("access_key_id", &self.access_key_id)
            .finish_non_exhaustive()
    }
}

/// One object in a listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Object {
    pub key: String,
    pub size: i64,
    pub etag: String,
    pub last_modified: Option<DateTime<Utc>>,
}

/// One page of a listing.
#[derive(Debug, Default)]
pub struct Page {
    pub objects: Vec<Object>,
    /// Pass back to get the next page; `None` on the last one.
    pub next: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum S3Error {
    /// The storage service refused: its HTTP status and error code.
    Refused { status: u16, code: String },
    /// Couldn't reach it, or the answer couldn't be read.
    Network(String),
    /// The object is larger than the limit.
    TooLarge,
}

impl S3Error {
    /// What to tell the person who set the connection up.
    pub fn explain(&self) -> String {
        match self {
            S3Error::Refused { status, code } => {
                let why = match code.as_str() {
                    "SignatureDoesNotMatch" => "the secret access key is wrong",
                    "InvalidAccessKeyId" => "the access key ID is wrong or was deleted",
                    "AccessDenied" | "AllAccessDisabled" => {
                        "the key isn't allowed to list or read this bucket"
                    }
                    "NoSuchBucket" => "there's no bucket by that name",
                    "PermanentRedirect"
                    | "AuthorizationHeaderMalformed"
                    | "IllegalLocationConstraintException" => "the bucket is in a different region",
                    "ExpiredToken" | "InvalidToken" => "the key has expired",
                    "RequestTimeTooSkewed" => "the storage service's clock disagrees with Verdyx's",
                    _ => "",
                };
                let code = if code.is_empty() {
                    "no error code"
                } else {
                    code
                };
                if why.is_empty() {
                    format!("the storage service answered {status} ({code})")
                } else {
                    format!("{why} (the storage service answered {status} {code})")
                }
            }
            S3Error::Network(e) => format!("couldn't reach the storage service: {e}"),
            S3Error::TooLarge => "the file is larger than the size limit".to_string(),
        }
    }
}

// ─── Checking what a team typed ──────────────────────────────────────────

/// A bucket name, or why not. Covers S3, R2 and GCS naming.
pub fn clean_bucket(raw: &str) -> Result<String, &'static str> {
    let b = raw.trim().to_string();
    let ok = (3..=63).contains(&b.len())
        && b.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '-' | '_'))
        && b.starts_with(|c: char| c.is_ascii_alphanumeric())
        && b.ends_with(|c: char| c.is_ascii_alphanumeric());
    if ok {
        Ok(b)
    } else {
        Err("enter the bucket's name: 3 to 63 lowercase letters, digits, dots, dashes or underscores")
    }
}

/// A region such as `eu-west-2` or `auto`, or why not.
pub fn clean_region(raw: &str) -> Result<String, &'static str> {
    let r = raw.trim().to_ascii_lowercase();
    if !r.is_empty() && r.len() <= 32 && r.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        Ok(r)
    } else {
        Err("enter the bucket's region, such as us-east-1 (or auto for R2)")
    }
}

/// A provider's endpoint, or why not: https, a public host, no path.
pub fn clean_endpoint(raw: &str) -> Result<url::Url, &'static str> {
    let raw = raw.trim().trim_end_matches('/');
    let with_scheme = if raw.contains("://") {
        raw.to_string()
    } else {
        format!("https://{raw}")
    };
    let url = crate::services::webhook_delivery::check_url(&with_scheme)?;
    if url.scheme() != "https" {
        return Err("the endpoint must use https");
    }
    if url.path() != "/" || url.query().is_some() || url.fragment().is_some() {
        return Err("enter only the endpoint's address, without a path or the bucket name");
    }
    Ok(url)
}

/// A key prefix to scan under ("" for the whole bucket), or why not.
pub fn clean_prefix(raw: &str) -> Result<String, &'static str> {
    let p = raw.trim().trim_start_matches('/').to_string();
    if p.len() > 512 || p.chars().any(|c| c.is_control()) {
        return Err("the folder (prefix) is too long or has control characters");
    }
    Ok(p)
}

// ─── Signing (AWS Signature Version 4) ───────────────────────────────────

/// RFC 3986 percent-encoding as SigV4 wants it: everything but the
/// unreserved characters, and `/` too unless `keep_slash`.
pub fn uri_encode(s: &str, keep_slash: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        let unreserved = b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~');
        if unreserved || (keep_slash && b == b'/') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), data)
        .as_ref()
        .to_vec()
}

/// The `Authorization` header for a request.
///
/// `path` is already URI-encoded. `headers` are every header to sign other
/// than `host`, `x-amz-content-sha256` and `x-amz-date`, which are always
/// signed. `amz_date` is `YYYYMMDDTHHMMSSZ`.
#[allow(clippy::too_many_arguments)]
pub fn authorization(
    keys: &Keys,
    region: &str,
    method: &str,
    host: &str,
    path: &str,
    query: &[(&str, &str)],
    headers: &[(&str, &str)],
    amz_date: &str,
) -> String {
    let mut q: Vec<(String, String)> = query
        .iter()
        .map(|(k, v)| (uri_encode(k, false), uri_encode(v, false)))
        .collect();
    q.sort();
    let canonical_query = q
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&");

    let mut h: Vec<(String, String)> = headers
        .iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), v.trim().to_string()))
        .chain([
            ("host".to_string(), host.to_string()),
            ("x-amz-content-sha256".to_string(), EMPTY_SHA256.to_string()),
            ("x-amz-date".to_string(), amz_date.to_string()),
        ])
        .collect();
    h.sort();
    let canonical_headers: String = h.iter().map(|(k, v)| format!("{k}:{v}\n")).collect();
    let signed_headers = h
        .iter()
        .map(|(k, _)| k.as_str())
        .collect::<Vec<_>>()
        .join(";");

    let canonical_request = format!(
        "{method}\n{path}\n{canonical_query}\n{canonical_headers}\n{signed_headers}\n{EMPTY_SHA256}"
    );
    let date = &amz_date[..8];
    let scope = format!("{date}/{region}/s3/aws4_request");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        hex::encode(Sha256::digest(canonical_request.as_bytes()))
    );
    let k_date = hmac_sha256(
        format!("AWS4{}", keys.secret_access_key).as_bytes(),
        date.as_bytes(),
    );
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, b"s3");
    let k_signing = hmac_sha256(&k_service, b"aws4_request");
    let signature = hex::encode(hmac_sha256(&k_signing, string_to_sign.as_bytes()));
    format!(
        "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={signature}",
        keys.access_key_id
    )
}

// ─── Requests ─────────────────────────────────────────────────────────────

impl Bucket {
    /// The host to connect to and the path of an object (`key` may be "").
    /// Amazon S3 is reached virtual-hosted style, except bucket names with
    /// dots, whose TLS certificate wouldn't match; other providers path style.
    pub fn locate(&self, key: &str) -> (String, String) {
        let key = uri_encode(key, true);
        match &self.endpoint {
            None if !self.name.contains('.') => (
                format!("{}.s3.{}.amazonaws.com", self.name, self.region),
                format!("/{key}"),
            ),
            None => (
                format!("s3.{}.amazonaws.com", self.region),
                format!("/{}/{key}", self.name),
            ),
            Some(url) => {
                let host = match url.port() {
                    Some(port) => format!("{}:{port}", url.host_str().unwrap_or_default()),
                    None => url.host_str().unwrap_or_default().to_string(),
                };
                (host, format!("/{}/{key}", self.name))
            }
        }
    }

    async fn get(
        &self,
        http: &reqwest::Client,
        keys: &Keys,
        key: &str,
        query: &[(&str, &str)],
    ) -> Result<reqwest::Response, S3Error> {
        let (host, path) = self.locate(key);
        let amz_date = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
        let auth = authorization(
            keys,
            &self.region,
            "GET",
            &host,
            &path,
            query,
            &[],
            &amz_date,
        );
        let qs = query
            .iter()
            .map(|(k, v)| format!("{}={}", uri_encode(k, false), uri_encode(v, false)))
            .collect::<Vec<_>>()
            .join("&");
        let url = if qs.is_empty() {
            format!("https://{host}{path}")
        } else {
            format!("https://{host}{path}?{qs}")
        };
        let response = http
            .get(&url)
            .header("x-amz-date", &amz_date)
            .header("x-amz-content-sha256", EMPTY_SHA256)
            .header("authorization", auth)
            .send()
            .await
            .map_err(|e| S3Error::Network(without_url(&e)))?;
        let status = response.status();
        if status.is_success() {
            return Ok(response);
        }
        let body = response.text().await.unwrap_or_default();
        Err(S3Error::Refused {
            status: status.as_u16(),
            code: error_code(&body),
        })
    }

    /// One page of objects under `prefix`, up to 1000.
    pub async fn list(
        &self,
        http: &reqwest::Client,
        keys: &Keys,
        prefix: &str,
        token: Option<&str>,
        max_keys: u16,
    ) -> Result<Page, S3Error> {
        let max = max_keys.clamp(1, 1000).to_string();
        let mut query: Vec<(&str, &str)> = vec![("list-type", "2"), ("max-keys", &max)];
        if !prefix.is_empty() {
            query.push(("prefix", prefix));
        }
        if let Some(t) = token {
            query.push(("continuation-token", t));
        }
        let body = self
            .get(http, keys, "", &query)
            .await?
            .text()
            .await
            .map_err(|e| S3Error::Network(without_url(&e)))?;
        parse_listing(&body).map_err(S3Error::Network)
    }

    /// An object's bytes, refusing anything over `max_bytes`.
    pub async fn download(
        &self,
        http: &reqwest::Client,
        keys: &Keys,
        key: &str,
        max_bytes: u64,
    ) -> Result<Vec<u8>, S3Error> {
        let mut response = self.get(http, keys, key, &[]).await?;
        if response.content_length().is_some_and(|n| n > max_bytes) {
            return Err(S3Error::TooLarge);
        }
        let mut data = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| S3Error::Network(without_url(&e)))?
        {
            if data.len() as u64 + chunk.len() as u64 > max_bytes {
                return Err(S3Error::TooLarge);
            }
            data.extend_from_slice(&chunk);
        }
        Ok(data)
    }
}

/// What went wrong with a request, without its URL, which may hold an
/// object key. The underlying cause is kept (a DNS or TLS error, say).
fn without_url(e: &reqwest::Error) -> String {
    let what = if e.is_timeout() {
        "timed out"
    } else if e.is_connect() {
        "couldn't connect"
    } else if e.is_body() || e.is_decode() {
        "the answer was cut off"
    } else {
        "the request failed"
    };
    let mut text = what.to_string();
    let mut source = std::error::Error::source(e);
    while let Some(s) = source {
        text = format!("{text}: {s}");
        source = s.source();
    }
    text
}

/// `<Error><Code>…</Code>` from an error body, or "".
pub fn error_code(body: &str) -> String {
    roxmltree::Document::parse(body)
        .ok()
        .and_then(|doc| {
            doc.descendants()
                .find(|n| n.tag_name().name() == "Code")
                .and_then(|n| n.text())
                .map(|t| t.trim().to_string())
        })
        .unwrap_or_default()
}

/// A `ListObjectsV2` answer.
pub fn parse_listing(body: &str) -> Result<Page, String> {
    let doc = roxmltree::Document::parse(body).map_err(|_| "the bucket listing wasn't XML")?;
    let root = doc.root_element();
    if root.tag_name().name() != "ListBucketResult" {
        return Err("the answer wasn't a bucket listing".to_string());
    }
    let child_text = |n: roxmltree::Node, name: &str| -> Option<String> {
        n.children()
            .find(|c| c.tag_name().name() == name)
            .and_then(|c| c.text())
            .map(str::to_string)
    };
    let objects = root
        .children()
        .filter(|n| n.tag_name().name() == "Contents")
        .filter_map(|n| {
            Some(Object {
                key: child_text(n, "Key")?,
                size: child_text(n, "Size")?.trim().parse().ok()?,
                etag: child_text(n, "ETag")
                    .unwrap_or_default()
                    .trim()
                    .trim_matches('"')
                    .to_string(),
                last_modified: child_text(n, "LastModified")
                    .and_then(|t| DateTime::parse_from_rfc3339(t.trim()).ok())
                    .map(|t| t.with_timezone(&Utc)),
            })
        })
        .collect();
    let truncated = child_text(root, "IsTruncated").is_some_and(|t| t.trim() == "true");
    let next = child_text(root, "NextContinuationToken").filter(|_| truncated);
    Ok(Page { objects, next })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// AWS's published example keys (from the Signature Version 4 docs).
    fn example_keys() -> Keys {
        Keys {
            access_key_id: "AKIAIOSFODNN7EXAMPLE".to_string(),
            secret_access_key: ["wJalrXUtnFEMI", "K7MDENG", "bPxRfiCYEXAMPLEKEY"].join("/"),
        }
    }

    #[test]
    fn signs_the_aws_documented_get_object_example() {
        let auth = authorization(
            &example_keys(),
            "us-east-1",
            "GET",
            "examplebucket.s3.amazonaws.com",
            "/test.txt",
            &[],
            &[("Range", "bytes=0-9")],
            "20130524T000000Z",
        );
        assert_eq!(
            auth,
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, \
             SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, \
             Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        );
    }

    #[test]
    fn signs_the_aws_documented_list_objects_example() {
        let auth = authorization(
            &example_keys(),
            "us-east-1",
            "GET",
            "examplebucket.s3.amazonaws.com",
            "/",
            &[("prefix", "J"), ("max-keys", "2")],
            &[],
            "20130524T000000Z",
        );
        assert!(
            auth.ends_with(
                "Signature=34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7"
            ),
            "{auth}"
        );
    }

    #[test]
    fn keys_are_encoded_once_with_slashes_kept() {
        assert_eq!(
            uri_encode("in box/Invoice 1+1=2 é.pdf", true),
            "in%20box/Invoice%201%2B1%3D2%20%C3%A9.pdf"
        );
        assert_eq!(uri_encode("a/b", false), "a%2Fb");
    }

    #[test]
    fn buckets_are_located_per_provider() {
        let aws = Bucket {
            endpoint: None,
            region: "eu-west-2".into(),
            name: "acme-uploads".into(),
        };
        assert_eq!(
            aws.locate("in/a b.exe"),
            (
                "acme-uploads.s3.eu-west-2.amazonaws.com".into(),
                "/in/a%20b.exe".into()
            )
        );
        let dotted = Bucket {
            name: "uploads.acme.com".into(),
            ..aws.clone()
        };
        assert_eq!(
            dotted.locate(""),
            (
                "s3.eu-west-2.amazonaws.com".into(),
                "/uploads.acme.com/".into()
            )
        );
        let r2 = Bucket {
            endpoint: Some(clean_endpoint("abc123.r2.cloudflarestorage.com").unwrap()),
            region: "auto".into(),
            name: "acme".into(),
        };
        assert_eq!(
            r2.locate("x"),
            ("abc123.r2.cloudflarestorage.com".into(), "/acme/x".into())
        );
    }

    #[test]
    fn endpoints_must_be_public_https_without_a_path() {
        assert!(clean_endpoint("https://storage.googleapis.com/").is_ok());
        assert!(clean_endpoint("http://storage.googleapis.com").is_err());
        assert!(clean_endpoint("https://127.0.0.1:9000").is_err());
        assert!(clean_endpoint("https://minio.internal").is_err());
        assert!(clean_endpoint("https://s3.example.com/my-bucket").is_err());
    }

    #[test]
    fn names_regions_and_prefixes_are_checked() {
        assert_eq!(clean_bucket(" acme-uploads ").unwrap(), "acme-uploads");
        assert!(clean_bucket("Acme").is_err());
        assert!(clean_bucket("ab").is_err());
        assert!(clean_bucket("-acme").is_err());
        assert_eq!(clean_region("EU-West-2").unwrap(), "eu-west-2");
        assert!(clean_region("eu west").is_err());
        assert_eq!(clean_prefix("/incoming/").unwrap(), "incoming/");
        assert!(clean_prefix("a\nb").is_err());
    }

    #[test]
    fn listings_and_errors_are_read() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>acme</Name><Prefix>in/</Prefix><KeyCount>2</KeyCount><MaxKeys>2</MaxKeys>
  <IsTruncated>true</IsTruncated>
  <Contents><Key>in/a&amp;b.exe</Key><LastModified>2026-11-20T10:00:00.000Z</LastModified>
    <ETag>&quot;9b2cf535f27731c974343645a3985328&quot;</ETag><Size>1024</Size>
    <StorageClass>STANDARD</StorageClass></Contents>
  <Contents><Key>in/</Key><LastModified>2026-11-20T09:00:00.000Z</LastModified>
    <ETag>"d41d8cd98f00b204e9800998ecf8427e"</ETag><Size>0</Size></Contents>
  <NextContinuationToken>1ueGcxLPRx1Tr/XYExHnhbYLgveDs2J/wm36Hy4vbOwM=</NextContinuationToken>
</ListBucketResult>"#;
        let page = parse_listing(xml).unwrap();
        assert_eq!(page.objects.len(), 2);
        assert_eq!(page.objects[0].key, "in/a&b.exe");
        assert_eq!(page.objects[0].etag, "9b2cf535f27731c974343645a3985328");
        assert_eq!(page.objects[0].size, 1024);
        assert!(page.objects[0].last_modified.is_some());
        assert_eq!(
            page.next.as_deref(),
            Some("1ueGcxLPRx1Tr/XYExHnhbYLgveDs2J/wm36Hy4vbOwM=")
        );

        let last = xml.replace("<IsTruncated>true", "<IsTruncated>false");
        assert!(parse_listing(&last).unwrap().next.is_none());
        assert!(parse_listing("<Error/>").is_err());

        let refused = "<?xml version=\"1.0\"?><Error><Code>SignatureDoesNotMatch</Code><Message>x</Message></Error>";
        let code = error_code(refused);
        assert_eq!(code, "SignatureDoesNotMatch");
        let msg = S3Error::Refused { status: 403, code }.explain();
        assert!(msg.starts_with("the secret access key is wrong"), "{msg}");
    }
}
