//! # axum-server-mtls
//!
//! mTLS client certificate extraction for [axum-server](https://crates.io/crates/axum-server).
//!
//! `axum-server` does not expose peer certificates after the TLS handshake
//! ([issue #162](https://github.com/programatik29/axum-server/issues/162)).
//! This crate fills that gap by wrapping `RustlsAcceptor` with a custom
//! `Accept` implementation that extracts the client certificate chain and
//! injects it into every HTTP request as an extension.
//!
//! ## Usage
//!
//! ```rust,no_run
//! use axum::{extract::Extension, routing::get, Router};
//! use axum_server_mtls::{MtlsAcceptor, PeerCertificates};
//! use axum_server::tls_rustls::{RustlsAcceptor, RustlsConfig};
//!
//! #[tokio::main]
//! async fn main() {
//!     let rustls_config = RustlsConfig::from_pem_file("cert.pem", "key.pem")
//!         .await
//!         .unwrap();
//!
//!     let app = Router::new().route("/", get(handler));
//!
//!     let acceptor = MtlsAcceptor::new(RustlsAcceptor::new(rustls_config));
//!
//!     let addr: std::net::SocketAddr = "0.0.0.0:3000".parse().unwrap();
//!     axum_server::bind(addr)
//!         .acceptor(acceptor)
//!         .serve(app.into_make_service())
//!         .await
//!         .unwrap();
//! }
//!
//! async fn handler(
//!     Extension(certs): Extension<PeerCertificates>,
//! ) -> String {
//!     match certs.leaf_cn() {
//!         Some(cn) => format!("Hello, {cn}!"),
//!         None => "No client certificate presented.".into(),
//!     }
//! }
//! ```
//!
//! ## How It Works
//!
//! 1. `MtlsAcceptor` delegates the TLS handshake to the inner `RustlsAcceptor`.
//! 2. After the handshake, it reads `ServerConnection::peer_certificates()`.
//! 3. It wraps the inner service with a `tower` `Extension` layer so that
//!    every request on that connection carries a [`PeerCertificates`] value.
//! 4. Handlers extract it via `Extension<PeerCertificates>`.
//!
//! The Rustls `ServerConfig` must be built with
//! [`with_client_cert_verifier`](rustls::ConfigBuilder::with_client_cert_verifier)
//! (optional or required) for clients to present certificates. If built with
//! `with_no_client_auth()`, `PeerCertificates` will always be empty.

mod acceptor;
mod certs;

pub use acceptor::MtlsAcceptor;
pub use certs::PeerCertificates;
