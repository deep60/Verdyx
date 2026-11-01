//! Minimal S3/MinIO uploader for user avatars.

use anyhow::{Context, Result};
use aws_config::{BehaviorVersion, Region};
use aws_sdk_s3::{
    config::{Credentials, SharedCredentialsProvider},
    primitives::ByteStream,
    Client, Config,
};
use std::env;
use tracing::info;

#[derive(Clone)]
pub struct AvatarStorage {
    client: Client,
    bucket: String,
    public_base_url: String,
}

impl AvatarStorage {
    /// Build from S3_* env vars (shared with the rest of the platform).
    pub async fn from_env() -> Result<Self> {
        let endpoint = env::var("S3_ENDPOINT").unwrap_or_else(|_| "http://minio:9000".to_string());
        let region = env::var("S3_REGION").unwrap_or_else(|_| "us-east-1".to_string());
        let bucket = env::var("S3_AVATAR_BUCKET")
            .or_else(|_| env::var("S3_BUCKET"))
            .unwrap_or_else(|_| "verdyx-avatars".to_string());
        let access_key = shared::env::credential_or_dev_default("S3_ACCESS_KEY", "verdyx_admin")?;
        let secret_key =
            shared::env::credential_or_dev_default("S3_SECRET_KEY", "verdyx_secret_key_2024")?;
        let public_base_url = env::var("S3_PUBLIC_URL").unwrap_or_else(|_| endpoint.clone());

        let credentials = Credentials::new(access_key, secret_key, None, None, "verdyx");
        let s3_config = Config::builder()
            .region(Region::new(region))
            .endpoint_url(&endpoint)
            .credentials_provider(SharedCredentialsProvider::new(credentials))
            .force_path_style(true)
            .behavior_version(BehaviorVersion::latest())
            .build();

        let client = Client::from_conf(s3_config);
        let storage = Self {
            client,
            bucket,
            public_base_url,
        };
        storage.ensure_bucket().await?;
        Ok(storage)
    }

    async fn ensure_bucket(&self) -> Result<()> {
        if self
            .client
            .head_bucket()
            .bucket(&self.bucket)
            .send()
            .await
            .is_err()
        {
            info!("Creating avatar bucket '{}'", self.bucket);
            self.client
                .create_bucket()
                .bucket(&self.bucket)
                .send()
                .await
                .context("Failed to create avatar bucket")?;
        }
        Ok(())
    }

    /// Upload avatar bytes and return the public URL.
    pub async fn upload_avatar(
        &self,
        key: &str,
        data: Vec<u8>,
        content_type: &str,
    ) -> Result<String> {
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .body(ByteStream::from(data))
            .content_type(content_type)
            .send()
            .await
            .context("Failed to upload avatar")?;

        Ok(format!(
            "{}/{}/{}",
            self.public_base_url.trim_end_matches('/'),
            self.bucket,
            key
        ))
    }
}
