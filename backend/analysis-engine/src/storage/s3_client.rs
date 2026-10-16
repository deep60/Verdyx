// S3/MinIO client implementation
//! Complete S3/MinIO integration for file storage

use anyhow::{Context, Result};
use aws_config::{BehaviorVersion, Region};
use aws_sdk_s3::{
    config::{Credentials, SharedCredentialsProvider},
    primitives::ByteStream,
    Client, Config,
};
use sha2::{Digest, Sha256};
use std::env;
use tracing::{debug, info};

/// S3 client for file storage operations.
///
/// `STORAGE_BACKEND=local` stores objects on disk so the engine can run
/// without MinIO. Production should set `STORAGE_BACKEND=s3` and a real
/// S3 or R2 endpoint.
#[derive(Clone)]
pub struct S3Client {
    backend: StorageBackend,
}

#[derive(Clone)]
enum StorageBackend {
    S3 { client: Client, bucket: String },
    Local { root: std::path::PathBuf },
}

/// File metadata returned from S3/MinIO
#[derive(Debug, Clone)]
pub struct FileMetadata {
    pub key: String,
    pub size: i64,
    pub content_type: Option<String>,
    pub etag: Option<String>,
    pub last_modified: Option<chrono::DateTime<chrono::Utc>>,
    pub sha256_hash: String,
}

impl S3Client {
    /// Create a new S3 client configured for MinIO or AWS S3
    pub async fn new() -> Result<Self> {
        let backend_name = env::var("STORAGE_BACKEND").unwrap_or_else(|_| "s3".to_string());
        if backend_name.eq_ignore_ascii_case("local") {
            let root = env::var("UPLOAD_DIR").unwrap_or_else(|_| "./uploads".to_string());
            let root = std::path::PathBuf::from(root);
            std::fs::create_dir_all(&root).context("Failed to create local upload directory")?;
            info!("Using local file storage at {}", root.display());
            return Ok(Self {
                backend: StorageBackend::Local { root },
            });
        }

        let endpoint = env::var("S3_ENDPOINT").unwrap_or_else(|_| "http://minio:9000".to_string());
        let region = env::var("S3_REGION").unwrap_or_else(|_| "us-east-1".to_string());
        let bucket = env::var("S3_BUCKET").unwrap_or_else(|_| "verdyx-submissions".to_string());
        let access_key =
            shared::env::credential_or_dev_default("S3_ACCESS_KEY", "verdyx_admin")?;
        let secret_key =
            shared::env::credential_or_dev_default("S3_SECRET_KEY", "verdyx_secret_key_2024")?;

        info!(
            "Initializing S3 client with endpoint: {}, region: {}, bucket: {}",
            endpoint, region, bucket
        );

        // Create credentials
        let credentials = Credentials::new(access_key, secret_key, None, None, "verdyx");

        // Build S3 config
        let s3_config = Config::builder()
            .region(Region::new(region))
            .endpoint_url(endpoint)
            .credentials_provider(SharedCredentialsProvider::new(credentials))
            .force_path_style(true) // Required for MinIO
            .behavior_version(BehaviorVersion::latest())
            .build();

        let client = Client::from_conf(s3_config);

        // Ensure bucket exists
        let s3_client = Self {
            backend: StorageBackend::S3 { client, bucket },
        };
        s3_client.ensure_bucket_exists().await?;

        info!("S3 client initialized successfully");
        Ok(s3_client)
    }

    /// Ensure the bucket exists, create if it doesn't
    fn local_path(&self, key: &str) -> Result<std::path::PathBuf> {
        let StorageBackend::Local { root } = &self.backend else {
            return Err(anyhow::anyhow!("not local storage"));
        };
        let rel = key.trim_start_matches('/');
        if rel.contains("..") {
            return Err(anyhow::anyhow!("invalid storage key"));
        }
        Ok(root.join(rel))
    }

    async fn ensure_bucket_exists(&self) -> Result<()> {
        let StorageBackend::S3 { client, bucket } = &self.backend else {
            return Ok(());
        };
        match client.head_bucket().bucket(bucket).send().await {
            Ok(_) => {
                debug!("Bucket '{}' exists", bucket);
                Ok(())
            }
            Err(_) => {
                info!("Bucket '{}' doesn't exist, creating...", bucket);
                client
                    .create_bucket()
                    .bucket(bucket)
                    .send()
                    .await
                    .context("Failed to create bucket")?;
                info!("Bucket '{}' created successfully", bucket);
                Ok(())
            }
        }
    }

    /// Upload a file to S3/MinIO and return the SHA256 hash
    pub async fn upload_file(
        &self,
        key: &str,
        data: Vec<u8>,
        content_type: Option<String>,
    ) -> Result<String> {
        // Calculate SHA256 hash
        let mut hasher = Sha256::new();
        hasher.update(&data);
        let hash = hex::encode(hasher.finalize());

        debug!(
            "Uploading file: key={}, size={} bytes, hash={}",
            key,
            data.len(),
            hash
        );

        if let StorageBackend::Local { .. } = &self.backend {
            let path = self.local_path(key)?;
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(path, &data).with_context(|| format!("Failed to write {key}"))?;
            info!("File stored locally: key={}, hash={}", key, hash);
            return Ok(hash);
        }
        let StorageBackend::S3 { client, bucket } = &self.backend else {
            unreachable!();
        };

        // Create byte stream
        let body = ByteStream::from(data);

        // Build put object request
        let mut request = client.put_object().bucket(bucket).key(key).body(body);

        // Add content type if provided
        if let Some(ct) = content_type {
            request = request.content_type(ct);
        }

        // Add SHA256 hash as metadata
        request = request.metadata("sha256", &hash);

        // Execute upload
        request
            .send()
            .await
            .with_context(|| format!("Failed to upload file with key: {key}"))?;

        info!("File uploaded successfully: key={}, hash={}", key, hash);
        Ok(hash)
    }

    /// Download a file from S3/MinIO
    pub async fn download_file(&self, key: &str) -> Result<Vec<u8>> {
        debug!("Downloading file: key={}", key);

        if let StorageBackend::Local { .. } = &self.backend {
            let path = self.local_path(key)?;
            return std::fs::read(&path).with_context(|| format!("Failed to read {}", path.display()));
        }
        let StorageBackend::S3 { client, bucket } = &self.backend else {
            unreachable!();
        };

        let response = client
            .get_object()
            .bucket(bucket)
            .key(key)
            .send()
            .await
            .with_context(|| format!("Failed to download file with key: {key}"))?;

        let bytes = response
            .body
            .collect()
            .await
            .context("Failed to read file body")?
            .into_bytes()
            .to_vec();

        info!(
            "File downloaded successfully: key={}, size={} bytes",
            key,
            bytes.len()
        );
        Ok(bytes)
    }

    /// Delete a file from S3/MinIO
    pub async fn delete_file(&self, key: &str) -> Result<()> {
        debug!("Deleting file: key={}", key);

        if let StorageBackend::Local { .. } = &self.backend {
            let path = self.local_path(key)?;
            if path.exists() {
                std::fs::remove_file(path)?;
            }
            return Ok(());
        }
        let StorageBackend::S3 { client, bucket } = &self.backend else {
            unreachable!();
        };

        client
            .delete_object()
            .bucket(bucket)
            .key(key)
            .send()
            .await
            .with_context(|| format!("Failed to delete file with key: {key}"))?;

        info!("File deleted successfully: key={}", key);
        Ok(())
    }

    /// Get file metadata without downloading the entire file
    pub async fn get_file_metadata(&self, key: &str) -> Result<FileMetadata> {
        debug!("Getting metadata for file: key={}", key);

        if let StorageBackend::Local { .. } = &self.backend {
            let path = self.local_path(key)?;
            let meta = std::fs::metadata(&path)
                .with_context(|| format!("Failed to stat {}", path.display()))?;
            return Ok(FileMetadata {
                key: key.to_string(),
                size: meta.len() as i64,
                content_type: None,
                etag: None,
                last_modified: meta.modified().ok().map(chrono::DateTime::from),
                sha256_hash: "unknown".to_string(),
            });
        }
        let StorageBackend::S3 { client, bucket } = &self.backend else {
            unreachable!();
        };

        let response = client
            .head_object()
            .bucket(bucket)
            .key(key)
            .send()
            .await
            .with_context(|| format!("Failed to get metadata for file with key: {key}"))?;

        // Extract SHA256 from metadata
        let sha256_hash = response
            .metadata()
            .and_then(|m| m.get("sha256"))
            .cloned()
            .unwrap_or_else(|| "unknown".to_string());

        let metadata = FileMetadata {
            key: key.to_string(),
            size: response.content_length().unwrap_or(0),
            content_type: response.content_type().map(|s| s.to_string()),
            etag: response.e_tag().map(|s| s.to_string()),
            last_modified: response
                .last_modified()
                .and_then(|dt| chrono::DateTime::from_timestamp(dt.secs(), 0)),
            sha256_hash,
        };

        debug!("File metadata: {:?}", metadata);
        Ok(metadata)
    }

    /// List all files in the bucket with optional prefix
    pub async fn list_files(
        &self,
        prefix: Option<&str>,
        max_keys: Option<i32>,
    ) -> Result<Vec<String>> {
        debug!("Listing files with prefix: {:?}", prefix);

        if let StorageBackend::Local { root } = &self.backend {
            let mut keys = Vec::new();
            if root.exists() {
                for entry in std::fs::read_dir(root)? {
                    let entry = entry?;
                    if entry.file_type()?.is_file() {
                        if let Some(name) = entry.file_name().to_str() {
                            if prefix.is_none_or(|p| name.starts_with(p)) {
                                keys.push(name.to_string());
                            }
                        }
                    }
                }
            }
            return Ok(keys);
        }
        let StorageBackend::S3 { client, bucket } = &self.backend else {
            unreachable!();
        };
        let mut request = client.list_objects_v2().bucket(bucket);

        if let Some(p) = prefix {
            request = request.prefix(p);
        }

        if let Some(max) = max_keys {
            request = request.max_keys(max);
        }

        let response = request.send().await.context("Failed to list files")?;

        let keys: Vec<String> = response
            .contents()
            .iter()
            .filter_map(|obj| obj.key().map(|k| k.to_string()))
            .collect();

        info!("Listed {} files", keys.len());
        Ok(keys)
    }

    /// Check if a file exists in S3/MinIO
    pub async fn file_exists(&self, key: &str) -> bool {
        if let StorageBackend::Local { .. } = &self.backend {
            return self.local_path(key).map(|p| p.exists()).unwrap_or(false);
        }
        let StorageBackend::S3 { client, bucket } = &self.backend else {
            return false;
        };
        client
            .head_object()
            .bucket(bucket)
            .key(key)
            .send()
            .await
            .is_ok()
    }

    /// Generate a pre-signed URL for file download (valid for 1 hour)
    pub async fn generate_presigned_url(
        &self,
        key: &str,
        expires_in_secs: Option<u64>,
    ) -> Result<String> {
        if let StorageBackend::Local { .. } = &self.backend {
            return Ok(format!("file://{}", self.local_path(key)?.display()));
        }
        let StorageBackend::S3 { client, bucket } = &self.backend else {
            unreachable!();
        };
        let expires = std::time::Duration::from_secs(expires_in_secs.unwrap_or(3600));

        let presigned = client
            .get_object()
            .bucket(bucket)
            .key(key)
            .presigned(
                aws_sdk_s3::presigning::PresigningConfig::expires_in(expires)
                    .context("Failed to create presigning config")?,
            )
            .await
            .context("Failed to generate presigned URL")?;

        Ok(presigned.uri().to_string())
    }
}
