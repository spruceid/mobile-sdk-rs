use std::{collections::HashMap, str::FromStr, sync::Arc};

use http::{HeaderMap, HeaderName, HeaderValue, Method};
use oid4vci::openidconnect::{HttpRequest as IHttpRequest, HttpResponse as IHttpResponse};
use url::Url;

#[derive(thiserror::Error, uniffi::Error, Debug)]
pub enum HttpClientError {
    #[error("failed to parse url")]
    UrlParse,

    #[error("failed to parse method")]
    MethodParse,

    #[error("failed to parse header")]
    HeaderParse,

    #[error("failed to parse header key: {key}")]
    HeaderKeyParse { key: String },

    #[error("failed to parse header value: {value}")]
    HeaderValueParse { value: String },

    #[error("failed to parse header entry: ({key}, {value})")]
    HeaderEntryParse { key: String, value: String },

    #[error("other error: {error}")]
    Other { error: String },
}

impl From<String> for HttpClientError {
    fn from(value: String) -> Self {
        Self::Other { error: value }
    }
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct HttpRequest {
    pub url: String,
    pub method: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

impl TryFrom<IHttpRequest> for HttpRequest {
    type Error = HttpClientError;

    fn try_from(
        IHttpRequest {
            url,
            method,
            headers,
            body,
        }: IHttpRequest,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            url: url.to_string(),
            method: method.to_string(),
            headers: headermap_to_hashmap(headers)?,
            body,
        })
    }
}

impl TryInto<IHttpRequest> for HttpRequest {
    type Error = HttpClientError;

    fn try_into(self) -> Result<IHttpRequest, Self::Error> {
        Ok(IHttpRequest {
            url: Url::from_str(&self.url).map_err(|_| HttpClientError::UrlParse)?,
            method: Method::from_str(&self.method).map_err(|_| HttpClientError::MethodParse)?,
            headers: hashmap_to_headermap(self.headers)?,
            body: self.body,
        })
    }
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct HttpResponse {
    pub status_code: u16,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

impl TryFrom<IHttpResponse> for HttpResponse {
    type Error = HttpClientError;

    fn try_from(
        IHttpResponse {
            status_code,
            headers,
            body,
        }: IHttpResponse,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            status_code: status_code.as_u16(),
            headers: headermap_to_hashmap(headers)?,
            body,
        })
    }
}

impl TryInto<IHttpResponse> for HttpResponse {
    type Error = HttpClientError;

    fn try_into(self) -> Result<IHttpResponse, Self::Error> {
        Ok(IHttpResponse {
            status_code: http::status::StatusCode::from_u16(self.status_code)
                .map_err(|_| "failed to parse status code".to_string())
                .map_err(HttpClientError::from)?,
            headers: hashmap_to_headermap(self.headers)?,
            body: self.body,
        })
    }
}

// TODO figure out how to use async_trait to have an async version of HttpClient
#[uniffi::export(with_foreign)]
pub trait HttpClient: Send + Sync {
    fn http_client(&self, request: HttpRequest) -> Result<HttpResponse, HttpClientError>;
}

pub(crate) fn wrap_http_client(
    client: Arc<dyn HttpClient>,
) -> impl Fn(IHttpRequest) -> Result<IHttpResponse, HttpClientError> {
    move |request| -> Result<IHttpResponse, HttpClientError> {
        client.http_client(request.try_into()?)?.try_into()
    }
}

fn headermap_to_hashmap(headers: HeaderMap) -> Result<HashMap<String, String>, HttpClientError> {
    headers
        .keys()
        .map(|k| {
            Ok((
                k.to_string(),
                headers
                    .get_all(k)
                    .iter()
                    .map(|v| v.to_str().map_err(|_| HttpClientError::HeaderParse))
                    .collect::<Result<Vec<_>, _>>()?
                    .join(","),
            ))
        })
        .collect()
}

fn hashmap_to_headermap(headers: HashMap<String, String>) -> Result<HeaderMap, HttpClientError> {
    headers
        .into_iter()
        .map(
            |(k, v)| match (HeaderName::from_str(&k), HeaderValue::from_str(&v)) {
                (Ok(k), Ok(v)) => Ok((k, v)),
                (Err(_), Ok(_)) => Err(HttpClientError::HeaderKeyParse { key: v }),
                (Ok(_), Err(_)) => Err(HttpClientError::HeaderValueParse { value: v }),
                (Err(_), Err(_)) => Err(HttpClientError::HeaderEntryParse { key: k, value: v }),
            },
        )
        .collect()
}
