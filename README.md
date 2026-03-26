# axum-mtls-acceptor

mTLS client certificate extraction for [axum-server](https://crates.io/crates/axum-server).

`axum-server` does not expose peer certificates after the TLS handshake
([issue #162](https://github.com/programatik29/axum-server/issues/162)).
This crate fills that gap by wrapping `RustlsAcceptor` with a custom `Accept`
implementation that extracts the client certificate chain and injects it into
every HTTP request as an extension.

## Quick Start

```rust
use axum::{extract::Extension, routing::get, Router};
use axum_mtls_acceptor::{MtlsAcceptor, PeerCertificates};
use axum_server::tls_rustls::{RustlsAcceptor, RustlsConfig};

#[tokio::main]
async fn main() {
    // Build your RustlsConfig with client cert verification enabled.
    // See rustls docs for WebPkiClientVerifier setup.
    let rustls_config = RustlsConfig::from_pem_file("cert.pem", "key.pem")
        .await
        .unwrap();

    let app = Router::new().route("/", get(handler));

    // Wrap the RustlsAcceptor with MtlsAcceptor
    let acceptor = MtlsAcceptor::new(RustlsAcceptor::new(rustls_config));

    axum_server::bind("0.0.0.0:3000".parse().unwrap())
        .acceptor(acceptor)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn handler(Extension(certs): Extension<PeerCertificates>) -> String {
    match certs.leaf_cn() {
        Some(cn) => format!("Hello, {cn}!"),
        None => "No client certificate presented.".into(),
    }
}
```

## How It Works

1. `MtlsAcceptor` wraps `RustlsAcceptor` and implements `axum_server::accept::Accept`.
2. After the TLS handshake, it reads `ServerConnection::peer_certificates()`.
3. It wraps the connection's service so that every request carries a `PeerCertificates` value in its extensions.
4. Handlers extract it via `Extension<PeerCertificates>`.

## Enabling Client Certificate Verification

For clients to present certificates, the Rustls `ServerConfig` must be built with
a client cert verifier. `MtlsAcceptor` only *extracts* certificates that Rustls
has already verified — it does not perform verification itself.

```rust
use rustls::server::WebPkiClientVerifier;
use rustls::RootCertStore;
use std::sync::Arc;

// Load your client CA certificates
let mut roots = RootCertStore::empty();
// roots.add(...) your client CA certs

let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
    .allow_unauthenticated()  // optional: allow clients without certs too
    .build()
    .unwrap();

let config = rustls::ServerConfig::builder()
    .with_client_cert_verifier(verifier)
    .with_single_cert(server_certs, server_key)
    .unwrap();
```

Then pass this config to `RustlsConfig::from_config(Arc::new(config))`.

## `PeerCertificates` API

| Method | Returns | Description |
|--------|---------|-------------|
| `is_present()` | `bool` | Client presented at least one certificate |
| `is_empty()` | `bool` | No client certificate presented |
| `chain()` | `&[CertificateDer]` | Full DER-encoded cert chain, leaf first |
| `leaf()` | `Option<&CertificateDer>` | The client's own certificate |
| `leaf_cn()` | `Option<String>` | Common Name from the leaf cert's subject |
| `leaf_sans()` | `Vec<String>` | Subject Alternative Names (DNS, email, IP) |
| `leaf_serial_hex()` | `Option<String>` | Serial number as hex string |
| `leaf_not_after_unix()` | `Option<i64>` | Expiry as UNIX timestamp |

## Compatibility

| Dependency | Version |
|------------|---------|
| axum-server | 0.7.x |
| rustls | 0.23.x |
| tokio-rustls | 0.26.x |
| axum | 0.8.x (for `Extension` extractor) |

## What This Crate Does NOT Do

- **TLS verification** — that's Rustls' job. Configure `WebPkiClientVerifier` on your `ServerConfig`.
- **Identity mapping** — mapping CN/SANs to users/roles is application logic.
- **Certificate revocation** — use Rustls' CRL/OCSP support in the verifier.
- **Certificate management** — generating, storing, or rotating certs is out of scope.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT License](LICENSE-MIT) at your option.
