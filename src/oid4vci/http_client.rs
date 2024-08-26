use std::{collections::HashMap, future::Future, pin::Pin, str::FromStr, sync::Arc};

use async_trait::async_trait;
use either::Either;
use oid4vci::openidconnect::{
    http::{HeaderMap, Method, Request, Response, StatusCode, Uri},
    AsyncHttpClient as IAsyncHttpClient, HttpRequest as IHttpRequest,
    HttpResponse as IHttpResponse, SyncHttpClient as ISyncHttpClient,
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

#[uniffi::export(with_foreign)]
pub trait HttpClient: Send + Sync {
    fn http_client(&self, request: HttpRequest) -> Result<HttpResponse, HttpClientError>;
}

impl ISyncHttpClient for WrapArc<dyn HttpClient> {
    type Error = HttpClientError;

    fn call(&self, request: IHttpRequest) -> Result<IHttpResponse, Self::Error> {
        let request: HttpRequest = request.try_into()?;
        let response: HttpResponse = self.0.http_client(request)?;
        let response: IHttpResponse = response.try_into()?;
        Ok::<_, HttpClientError>(response)
    }
}

#[uniffi::export(with_foreign)]
#[async_trait]
pub trait AsyncHttpClient: Send + Sync {
    async fn http_client(&self, request: HttpRequest) -> Result<HttpResponse, HttpClientError>;
}

impl<'a, 'c> IAsyncHttpClient<'c> for WrapArc<dyn AsyncHttpClient + 'a> {
    type Error = HttpClientError;
    type Future = Pin<Box<dyn Future<Output = Result<IHttpResponse, HttpClientError>> + Send + 'c>>;

    fn call(&'c self, request: IHttpRequest) -> Self::Future {
        Box::pin(async move {
            let request: HttpRequest = request.try_into()?;
            let response: HttpResponse = self.0.http_client(request).await?;
            let response: IHttpResponse = response.try_into()?;
            Ok::<_, HttpClientError>(response)
        })
    }
}

#[derive(uniffi::Object)]
pub struct EitherHttpClient(
    pub(crate) Either<WrapArc<dyn HttpClient>, WrapArc<dyn AsyncHttpClient>>,
);

impl From<Arc<dyn HttpClient>> for EitherHttpClient {
    fn from(value: Arc<dyn HttpClient>) -> Self {
        Self(Either::Left(WrapArc::<_>(value)))
    }
}

impl From<Arc<dyn AsyncHttpClient>> for EitherHttpClient {
    fn from(value: Arc<dyn AsyncHttpClient>) -> Self {
        Self(Either::Right(WrapArc::<_>(value)))
    }
}

pub struct WrapArc<T: ?Sized>(Arc<T>);

#[uniffi::export]
fn oid4vci_create_sync_client(client: Arc<dyn HttpClient>) -> EitherHttpClient {
    client.into()
}

#[uniffi::export]
fn oid4vci_create_async_client(client: Arc<dyn AsyncHttpClient>) -> EitherHttpClient {
    client.into()
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
