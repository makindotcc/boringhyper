use async_compression::tokio::bufread::GzipDecoder;
use async_trait::async_trait;
use boring::ssl::{SslConnector, SslMethod, SslVersion};
use futures::TryStreamExt;
use hyper::client::HttpConnector;
use hyper::http::request;
use hyper::{Body, Response};
use hyper_boring::HttpsConnector;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::fmt::{Display, Formatter};
use std::io::ErrorKind;
use tokio::io::AsyncReadExt;
use tokio_util::io::StreamReader;

pub type Client = hyper::Client<HttpsConnector<HttpConnector>>;

/*
 * Try to match it to be equal with real chrome build.
 * https://tools.scrapfly.io/api/fp/ja3?extended=1
 */
pub fn create_client() -> Client {
    // borrowed ;)
    // https://github.com/cloudflare/boring/blob/3059ba6e102599f8ae0a962223ca1e216bb61902/hyper-boring/src/test.rs#L63
    let mut connector = HttpConnector::new();
    connector.enforce_http(false);
    let mut ssl = SslConnector::builder(SslMethod::tls_client()).unwrap();
    ssl.set_grease_enabled(true);
    ssl.enable_ocsp_stapling();
    ssl.enable_signed_cert_timestamps();
    ssl.set_min_proto_version(Some(SslVersion::TLS1_2)).unwrap();
    ssl.set_max_proto_version(Some(SslVersion::TLS1_3)).unwrap();
    ssl.set_alpn_protos(b"\x02h2\x08http/1.1").unwrap();
    ssl.set_cipher_list(
        &[
            "TLS_AES_128_GCM_SHA256",
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
            "TLS_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_RSA_WITH_AES_128_CBC_SHA",
            "TLS_RSA_WITH_AES_256_CBC_SHA",
        ]
        .join(":"),
    )
    .unwrap();
    // also borrowed :)
    // https://github.com/4JX/reqwest-impersonate/blob/815e8695adf45253ac88ec2e53d44d22b0219ae8/src/browser/chrome/ver/v108.rs#L56
    ssl.set_sigalgs_list(
        &[
            "ecdsa_secp256r1_sha256",
            "rsa_pss_rsae_sha256",
            "rsa_pkcs1_sha256",
            "ecdsa_secp384r1_sha384",
            "rsa_pss_rsae_sha384",
            "rsa_pkcs1_sha384",
            "rsa_pss_rsae_sha512",
            "rsa_pkcs1_sha512",
        ]
        .join(":"),
    )
    .unwrap();
    let ssl = HttpsConnector::with_connector(connector, ssl).unwrap();
    hyper::Client::builder().build::<_, Body>(ssl)
}

pub trait ChromeHeadersExt {
    fn with_chrome_headers(self) -> Self;
}

impl ChromeHeadersExt for request::Builder {
    fn with_chrome_headers(self) -> Self {
        self
            .header("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
            .header("accept-encoding", "gzip") // chrome sends "gzip, deflate, br", but it works too? todo
            .header("accept-language", "pl")
            .header("cache-control", "max-age=0")
            .header("sec-fetch-dest", "document")
            .header("sec-fetch-mode", "navigate")
            .header("sec-fetch-site", "none")
            .header("sec-fetch-user", "?1")
            .header("upgrade-insecure-requests", "1")
            .header("user-agent", "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36")
    }
}

pub trait JsonBodyExt {
    fn json<T: Serialize>(json: &T) -> serde_json::Result<Body>;
}

impl JsonBodyExt for Body {
    fn json<T: Serialize>(json: &T) -> serde_json::Result<Body> {
        let bytes = serde_json::to_vec(json)?;
        Ok(Body::from(bytes))
    }
}

#[async_trait]
pub trait ReadBodyExt {
    async fn read_body(&mut self) -> Result<Vec<u8>>;

    async fn read_json<J: DeserializeOwned>(&mut self) -> Result<J>;
}

#[async_trait]
impl ReadBodyExt for Response<Body> {
    async fn read_body(&mut self) -> Result<Vec<u8>> {
        match self.headers().get("content-encoding") {
            None => Ok(hyper::body::to_bytes(self.body_mut())
                .await
                .map_err(Error::ReadUncompressed)?
                .to_vec()),
            Some(val) => match val.to_str() {
                Ok("gzip") => {
                    let stream_reader = StreamReader::new(
                        self.body_mut()
                            .map_err(|err| std::io::Error::new(ErrorKind::Other, err)),
                    );
                    let mut decoder = GzipDecoder::new(stream_reader);
                    let mut buf = Vec::new();
                    decoder
                        .read_to_end(&mut buf)
                        .await
                        .map_err(Error::ReadToEnd)?;
                    Ok(buf)
                }
                Ok(unsupported_encoding) => Err(Error::UnsupportedEncoding {
                    encoding: unsupported_encoding.to_string(),
                }),
                Err(err) => Err(Error::InvalidEncodingHeader(err)),
            },
        }
    }

    async fn read_json<J: DeserializeOwned>(&mut self) -> Result<J> {
        let body = self.read_body().await?;
        serde_json::from_slice(&body).map_err(Error::Deserialize)
    }
}

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    ReadToEnd(std::io::Error),
    ReadUncompressed(hyper::Error),
    Deserialize(serde_json::Error),
    UnsupportedEncoding { encoding: String },
    InvalidEncodingHeader(hyper::header::ToStrError),
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::ReadToEnd(err) => Some(err),
            Error::ReadUncompressed(err) => Some(err),
            Error::Deserialize(err) => Some(err),
            Error::UnsupportedEncoding { .. } => None,
            Error::InvalidEncodingHeader(err) => Some(err),
        }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::ReadToEnd(source) => write!(f, "Read to end: {}", source),
            Error::ReadUncompressed(source) => write!(f, "Read uncompressed: {}", source),
            Error::Deserialize(source) => write!(f, "Deserialize: {}", source),
            Error::UnsupportedEncoding { encoding } => {
                write!(f, "Unsupported content encoding: {}", encoding)
            }
            Error::InvalidEncodingHeader(err) => {
                write!(f, "Invalid content encoding header: {}", err)
            }
        }
    }
}
