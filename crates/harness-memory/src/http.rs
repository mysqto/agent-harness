//! The HTTP/1.1 exchange, over TCP or over a unix socket.
//!
//! hyper's connection API is used directly rather than a pooled, TLS-capable client. A memory call
//! is a single request under a deadline, so pooling buys little, and leaving TLS out keeps the
//! dependency tree small — transport security and key material belong in the sidecar, which is the
//! preferred path anyway.

use std::path::{Path, PathBuf};
use std::time::Duration;

use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::client::conn::http1;
use hyper::header::{CONTENT_TYPE, HOST};
use hyper::{Method, Request, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpStream, UnixStream};

use crate::{Error, Result};

/// How much of a failing response body is quoted back in an error.
const REASON_CHARS: usize = 200;

/// Where to send a request.
#[derive(Debug, Clone)]
pub(crate) enum Target {
    /// A direct connection to the service.
    Tcp(Endpoint),
    /// The local sidecar, which serves the same routes over a unix socket.
    Unix(PathBuf),
}

/// A parsed `base_url`: where to connect, and what to put in front of a route.
#[derive(Debug, Clone)]
pub(crate) struct Endpoint {
    /// `host:port`, used both to connect and as the `Host` header.
    authority: String,
    /// Path prefix, without a trailing slash.
    prefix: String,
}

impl Endpoint {
    /// Parses a `base_url`.
    ///
    /// Only `http://` is accepted: a client that silently downgraded, or that grew a TLS stack to
    /// avoid doing so, would both be worse than saying no and pointing at the sidecar. A bad URL is
    /// [`Error::Rejected`] rather than [`Error::Unavailable`] because retrying cannot fix it.
    pub(crate) fn parse(base_url: &str) -> Result<Self> {
        let rest = base_url.strip_prefix("http://").ok_or_else(|| {
            Error::Rejected(format!(
                "base_url must start with http://, got `{base_url}`; use a sidecar for TLS"
            ))
        })?;
        let (authority, path) = match rest.find('/') {
            Some(cut) => (&rest[..cut], &rest[cut..]),
            None => (rest, ""),
        };
        if authority.is_empty() {
            return Err(Error::Rejected(format!(
                "base_url has no host: `{base_url}`"
            )));
        }
        // A bracketed IPv6 literal must carry an explicit port; the ':' test cannot tell it apart
        // from a bare address otherwise.
        let authority = if authority.contains(':') {
            authority.to_owned()
        } else {
            format!("{authority}:80")
        };
        Ok(Self {
            authority,
            prefix: path.trim_end_matches('/').to_owned(),
        })
    }
}

/// A response, before its status has been judged.
pub(crate) struct Response {
    /// Status line.
    pub(crate) status: StatusCode,
    /// Body bytes, however the status turned out.
    pub(crate) body: Bytes,
}

impl Response {
    /// Returns the body, or classifies the status as an error.
    pub(crate) fn ok_body(self) -> Result<Bytes> {
        if self.status.is_success() {
            return Ok(self.body);
        }
        let reason = format!("{} {}", self.status.as_u16(), quote(&self.body));
        // Permanent and transient are kept apart deliberately. Treating a 4xx as retryable retries
        // for ever on a request that will never work; treating a 5xx as permanent throws away a
        // record that would have landed on the next attempt.
        if self.status == StatusCode::TOO_MANY_REQUESTS || self.status.is_server_error() {
            Err(Error::Unavailable(reason))
        } else if self.status.is_client_error() {
            Err(Error::Rejected(reason))
        } else {
            Err(Error::Transport(format!("unexpected status {reason}")))
        }
    }
}

/// Performs one request within `budget`.
///
/// An expired budget is [`Error::Unavailable`]: the store may well answer the next attempt, so the
/// caller should retry or degrade rather than treat the request as bad.
pub(crate) async fn request(
    target: &Target,
    method: Method,
    route: &str,
    body: Option<Vec<u8>>,
    budget: Duration,
) -> Result<Response> {
    tokio::time::timeout(budget, exchange(target, method, route, body))
        .await
        .map_err(|_| Error::Unavailable(format!("timed out after {}ms", budget.as_millis())))?
}

/// Connects and exchanges, picking the transport from the target.
async fn exchange(
    target: &Target,
    method: Method,
    route: &str,
    body: Option<Vec<u8>>,
) -> Result<Response> {
    match target {
        Target::Tcp(endpoint) => {
            let stream = TcpStream::connect(&endpoint.authority)
                .await
                .map_err(|err| {
                    Error::Transport(format!("connect {}: {err}", endpoint.authority))
                })?;
            let path = format!("{}{route}", endpoint.prefix);
            send(stream, &endpoint.authority, method, &path, body).await
        }
        Target::Unix(socket) => {
            let stream = connect_unix(socket).await?;
            // A unix peer has no authority of its own, but HTTP/1.1 requires the header.
            send(stream, "localhost", method, route, body).await
        }
    }
}

/// Connects to a unix socket, naming the path on failure — the usual cause is a missing sidecar.
pub(crate) async fn connect_unix(socket: &Path) -> Result<UnixStream> {
    UnixStream::connect(socket)
        .await
        .map_err(|err| Error::Transport(format!("connect {}: {err}", socket.display())))
}

/// Drives one request/response pair over an already-connected stream.
async fn send<S>(
    stream: S,
    host: &str,
    method: Method,
    path: &str,
    body: Option<Vec<u8>>,
) -> Result<Response>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let (mut sender, connection) = http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|err| Error::Transport(format!("handshake: {err}")))?;
    // The connection task owns the socket and finishes when the sender is dropped, so nothing
    // outlives this call.
    tokio::spawn(async move {
        let _ = connection.await;
    });

    let mut builder = Request::builder()
        .method(method)
        .header(HOST, host)
        .uri(path);
    let payload = match body {
        Some(bytes) => {
            builder = builder.header(CONTENT_TYPE, "application/json");
            Full::new(Bytes::from(bytes))
        }
        None => Full::default(),
    };
    let request = builder
        .body(payload)
        .map_err(|err| Error::Transport(format!("build request: {err}")))?;

    let response = sender
        .send_request(request)
        .await
        .map_err(|err| Error::Transport(format!("send: {err}")))?;
    let status = response.status();
    let body = response
        .into_body()
        .collect()
        .await
        .map_err(|err| Error::Transport(format!("read body: {err}")))?
        .to_bytes();
    Ok(Response { status, body })
}

/// Renders a body for an error message, bounded so a large error page cannot flood a log.
fn quote(body: &Bytes) -> String {
    String::from_utf8_lossy(body)
        .chars()
        .take(REASON_CHARS)
        .collect()
}

#[cfg(test)]
mod tests {
    use hyper::StatusCode;
    use hyper::body::Bytes;

    use super::{Endpoint, REASON_CHARS, Response, quote};
    use crate::Error;

    fn status(code: u16) -> Error {
        Response {
            status: StatusCode::from_u16(code).expect("valid status"),
            body: Bytes::from_static(b"why"),
        }
        .ok_body()
        .expect_err("non-success")
    }

    #[test]
    fn a_url_without_a_port_gets_the_default() {
        let endpoint = Endpoint::parse("http://memory.invalid").expect("parse");
        assert_eq!(endpoint.authority, "memory.invalid:80");
        assert_eq!(endpoint.prefix, "");
    }

    #[test]
    fn a_path_becomes_a_route_prefix() {
        let endpoint = Endpoint::parse("http://127.0.0.1:9/v1/").expect("parse");
        assert_eq!(endpoint.authority, "127.0.0.1:9");
        assert_eq!(endpoint.prefix, "/v1");
    }

    #[test]
    fn a_non_http_url_is_rejected_rather_than_downgraded() {
        for url in ["https://memory.invalid", "memory.invalid:80", "http://"] {
            assert!(
                matches!(Endpoint::parse(url), Err(Error::Rejected(_))),
                "{url}"
            );
        }
    }

    #[test]
    fn a_success_yields_the_body() {
        let body = Response {
            status: StatusCode::OK,
            body: Bytes::from_static(b"{}"),
        }
        .ok_body()
        .expect("success");
        assert_eq!(body, Bytes::from_static(b"{}"));
    }

    #[test]
    fn client_errors_are_permanent_and_server_errors_are_not() {
        assert!(matches!(status(400), Error::Rejected(_)));
        assert!(matches!(status(404), Error::Rejected(_)));
        assert!(matches!(status(429), Error::Unavailable(_)));
        assert!(matches!(status(500), Error::Unavailable(_)));
        assert!(matches!(status(503), Error::Unavailable(_)));
        // Nothing here follows redirects, so a 3xx is a protocol surprise rather than a verdict.
        assert!(matches!(status(302), Error::Transport(_)));
    }

    #[test]
    fn a_quoted_body_is_bounded() {
        let long = Bytes::from(vec![b'x'; REASON_CHARS * 2]);
        assert_eq!(quote(&long).len(), REASON_CHARS);
    }
}
