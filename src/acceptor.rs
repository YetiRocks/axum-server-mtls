use std::future::Future;
use std::io;
use std::pin::Pin;

use axum_server::accept::Accept;
use axum_server::tls_rustls::RustlsAcceptor;
use rustls_pki_types::CertificateDer;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::server::TlsStream;
use crate::PeerCertificates;

/// An [`Accept`] wrapper around [`RustlsAcceptor`] that extracts client
/// certificates from the TLS connection and injects them into every HTTP
/// request as an [`axum::Extension<PeerCertificates>`].
///
/// # Example
///
/// ```rust,no_run
/// use axum_server_mtls::MtlsAcceptor;
/// use axum_server::tls_rustls::{RustlsAcceptor, RustlsConfig};
///
/// # async fn example() {
/// let config = RustlsConfig::from_pem_file("cert.pem", "key.pem")
///     .await
///     .unwrap();
/// let acceptor = MtlsAcceptor::new(RustlsAcceptor::new(config));
///
/// axum_server::bind("0.0.0.0:3000".parse().unwrap())
///     .acceptor(acceptor)
///     .serve(axum::Router::new().into_make_service())
///     .await
///     .unwrap();
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct MtlsAcceptor<A = axum_server::accept::DefaultAcceptor> {
    inner: RustlsAcceptor<A>,
}

impl MtlsAcceptor {
    /// Create a new `MtlsAcceptor` wrapping a [`RustlsAcceptor`].
    pub fn new(inner: RustlsAcceptor) -> Self {
        Self { inner }
    }
}

impl<A> MtlsAcceptor<A> {
    /// Create from a `RustlsAcceptor` with a custom inner acceptor.
    pub fn from_rustls_acceptor(inner: RustlsAcceptor<A>) -> Self {
        Self { inner }
    }

    /// Access the inner `RustlsAcceptor`.
    pub fn inner(&self) -> &RustlsAcceptor<A> {
        &self.inner
    }
}

impl<I, S, A> Accept<I, S> for MtlsAcceptor<A>
where
    A: Accept<I, S> + Clone + Send + 'static,
    A::Stream: AsyncRead + AsyncWrite + Unpin + Send,
    A::Service: Send,
    A::Future: Send,
    I: Send + 'static,
    S: Send + 'static,
{
    // Stream is the TLS-wrapped stream from RustlsAcceptor
    type Stream = TlsStream<A::Stream>;

    // Service is the inner service wrapped with an Extension layer injecting PeerCertificates.
    // We use a concrete wrapper type to avoid complex associated type gymnastics.
    type Service = PeerCertService<A::Service>;

    type Future = Pin<Box<dyn Future<Output = io::Result<(Self::Stream, Self::Service)>> + Send>>;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        let inner = self.inner.clone();
        Box::pin(async move {
            // Delegate TLS handshake to RustlsAcceptor
            let (tls_stream, inner_service) = inner.accept(stream, service).await?;

            // Extract peer certificates from the completed TLS session.
            // get_ref() returns (&InnerStream, &ServerConnection).
            // ServerConnection::peer_certificates() returns Option<&[CertificateDer<'_>]>.
            let (_, server_conn) = tls_stream.get_ref();
            let peer_certs = match server_conn.peer_certificates() {
                Some(certs) if !certs.is_empty() => {
                    let owned: Vec<CertificateDer<'static>> =
                        certs.iter().map(|c| c.clone().into_owned()).collect();
                    PeerCertificates::new(owned)
                }
                _ => PeerCertificates::empty(),
            };

            Ok((tls_stream, PeerCertService::new(inner_service, peer_certs)))
        })
    }
}

/// A [`tower::Service`] wrapper that injects [`PeerCertificates`] into every request's extensions.
///
/// This is the `Service` type produced by [`MtlsAcceptor`]. You should not need to construct
/// this directly.
#[derive(Clone, Debug)]
pub struct PeerCertService<S> {
    inner: S,
    peer_certs: PeerCertificates,
}

impl<S> PeerCertService<S> {
    fn new(inner: S, peer_certs: PeerCertificates) -> Self {
        Self { inner, peer_certs }
    }
}

impl<S, B> tower_service::Service<http::Request<B>> for PeerCertService<S>
where
    S: tower_service::Service<http::Request<B>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: http::Request<B>) -> Self::Future {
        // Insert peer certificates into request extensions so handlers can extract them.
        req.extensions_mut().insert(self.peer_certs.clone());
        self.inner.call(req)
    }
}
