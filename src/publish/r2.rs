//! R2 uploads.
//!
//! R2 speaks the S3 API, so this is the AWS SDK pointed at the account's R2
//! endpoint -- the same thing the Go agent does with `aws-sdk-go-v2`.
//!
//! **Every object goes up in a single PUT.** The agent compares each local
//! file's MD5 against the object's ETag to decide what to download, and a
//! multipart upload's ETag is not an MD5 -- it is a hash of part hashes with
//! a `-N` suffix. Uploading a certificate in parts would make the agent
//! re-download it forever.

use aws_sdk_s3::Client;
use aws_sdk_s3::config::{BehaviorVersion, Credentials, Region};
use aws_sdk_s3::primitives::ByteStream;
use std::path::Path;

use super::manifest::Keys;
use crate::config::{Config, Secrets};
use crate::error::{Error, Result};

pub struct R2 {
    client: Client,
    bucket: String,
    pub keys: Keys,
}

impl R2 {
    pub fn new(config: &Config, secrets: &Secrets) -> Result<Self> {
        if config.publish.bucket.is_empty() {
            return Err(Error::Config("publish.bucket is not set".to_owned()));
        }
        if config.publish.endpoint.is_empty() {
            return Err(Error::Config("publish.endpoint is not set".to_owned()));
        }
        if secrets.r2_access_key_id.is_empty() || secrets.r2_secret_access_key.is_empty() {
            return Err(Error::Config("R2 credentials are not set".to_owned()));
        }

        let credentials = Credentials::new(
            &secrets.r2_access_key_id,
            &secrets.r2_secret_access_key,
            None,
            None,
            "ais_domains",
        );

        let s3_config = aws_sdk_s3::Config::builder()
            .behavior_version(BehaviorVersion::latest())
            // R2 ignores the region but the SDK insists on one.
            .region(Region::new(config.publish.region.clone()))
            .endpoint_url(&config.publish.endpoint)
            .credentials_provider(credentials)
            .force_path_style(true)
            .build();

        Ok(Self {
            client: Client::from_conf(s3_config),
            bucket: config.publish.bucket.clone(),
            keys: Keys::new(&config.publish.prefix),
        })
    }

    pub async fn put_file(&self, key: &str, path: &Path) -> Result<()> {
        let body = ByteStream::from_path(path)
            .await
            .map_err(|e| Error::Publish(format!("reading {} for upload: {e}", path.display())))?;

        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .body(body)
            .send()
            .await
            .map_err(|e| Error::Publish(format!("uploading {key}: {e}")))?;

        Ok(())
    }

    pub async fn put_string(&self, key: &str, body: &str, content_type: &str) -> Result<()> {
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .content_type(content_type)
            .body(ByteStream::from(body.as_bytes().to_vec()))
            .send()
            .await
            .map_err(|e| Error::Publish(format!("uploading {key}: {e}")))?;

        Ok(())
    }

    pub async fn get_string(&self, key: &str) -> Result<Option<String>> {
        let response = match self.client.get_object().bucket(&self.bucket).key(key).send().await {
            Ok(response) => response,
            Err(err) => {
                let service_error = err.into_service_error();
                if service_error.is_no_such_key() {
                    return Ok(None);
                }
                return Err(Error::Publish(format!("reading {key}: {service_error}")));
            }
        };

        let bytes = response
            .body
            .collect()
            .await
            .map_err(|e| Error::Publish(format!("reading {key}: {e}")))?;

        Ok(Some(String::from_utf8_lossy(&bytes.into_bytes()).into_owned()))
    }

    /// Release ids currently in the bucket, oldest first.
    ///
    /// The ids sort chronologically because they are UTC timestamps, which is
    /// what makes pruning a simple "drop the front of the list".
    pub async fn list_release_ids(&self) -> Result<Vec<String>> {
        let prefix = self.keys.releases_prefix();
        let mut ids = Vec::new();
        let mut continuation = None;

        loop {
            let mut request = self
                .client
                .list_objects_v2()
                .bucket(&self.bucket)
                .prefix(&prefix)
                .delimiter("/");
            if let Some(token) = &continuation {
                request = request.continuation_token(token);
            }

            let response = request
                .send()
                .await
                .map_err(|e| Error::Publish(format!("listing {prefix}: {e}")))?;

            for common in response.common_prefixes() {
                if let Some(value) = common.prefix() {
                    if let Some(id) = value
                        .trim_end_matches('/')
                        .rsplit('/')
                        .next()
                        .filter(|id| !id.is_empty())
                    {
                        ids.push(id.to_owned());
                    }
                }
            }

            match response.next_continuation_token() {
                Some(token) => continuation = Some(token.to_owned()),
                None => break,
            }
        }

        ids.sort();
        Ok(ids)
    }

    /// Deletes every object under a release. Used for pruning, never for the
    /// release the `latest` pointer names.
    pub async fn delete_release(&self, release_id: &str) -> Result<usize> {
        let prefix = self.keys.release_prefix(release_id);
        let mut deleted = 0;
        let mut continuation = None;

        loop {
            let mut request =
                self.client.list_objects_v2().bucket(&self.bucket).prefix(&prefix);
            if let Some(token) = &continuation {
                request = request.continuation_token(token);
            }

            let response = request
                .send()
                .await
                .map_err(|e| Error::Publish(format!("listing {prefix}: {e}")))?;

            for object in response.contents() {
                if let Some(key) = object.key() {
                    self.client
                        .delete_object()
                        .bucket(&self.bucket)
                        .key(key)
                        .send()
                        .await
                        .map_err(|e| Error::Publish(format!("deleting {key}: {e}")))?;
                    deleted += 1;
                }
            }

            match response.next_continuation_token() {
                Some(token) => continuation = Some(token.to_owned()),
                None => break,
            }
        }

        Ok(deleted)
    }
}
