use std::{collections::HashMap, str::FromStr, sync::Arc};

use oid4vci::openidconnect::{
    http::{HeaderMap, Method, Request, Response, StatusCode, Uri},
    HttpRequest as IHttpRequest, HttpResponse as IHttpResponse,
};

#[derive(thiserror::Error, uniffi::Error, Debug)]
pub enum HttpClientError {
    #[error("failed to build request")]
    RequestBuilder,

    #[error("failed to build response")]
    ResponseBuilder,

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

    fn try_from(req: IHttpRequest) -> Result<Self, Self::Error> {
        Ok(Self {
            url: req.uri().to_string(),
            method: req.method().to_string(),
            headers: headermap_to_hashmap(req.headers())?,
            body: req.body().clone(),
        })
    }
}

impl TryInto<IHttpRequest> for HttpRequest {
    type Error = HttpClientError;

    fn try_into(self) -> Result<IHttpRequest, Self::Error> {
        let mut request = Request::builder()
            .method(Method::from_str(&self.method).map_err(|_| HttpClientError::MethodParse)?)
            .uri(Uri::from_str(&self.url).map_err(|_| HttpClientError::UrlParse)?);

        for (k, v) in self.headers {
            request = request.header(k, v);
        }

        request
            .body(self.body)
            .map_err(|_| HttpClientError::RequestBuilder)
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

    fn try_from(res: IHttpResponse) -> Result<Self, Self::Error> {
        Ok(Self {
            status_code: res.status().as_u16(),
            headers: headermap_to_hashmap(res.headers())?,
            body: res.body().clone(),
        })
    }
}

impl TryInto<IHttpResponse> for HttpResponse {
    type Error = HttpClientError;

    fn try_into(self) -> Result<IHttpResponse, Self::Error> {
        let mut response = Response::builder().status(
            StatusCode::from_u16(self.status_code)
                .map_err(|_| "failed to parse status code".to_string())
                .map_err(HttpClientError::from)?,
        );

        for (k, v) in self.headers {
            response = response.header(k, v);
        }

        response
            .body(self.body)
            .map_err(|_| HttpClientError::ResponseBuilder)
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

fn headermap_to_hashmap(headers: &HeaderMap) -> Result<HashMap<String, String>, HttpClientError> {
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
