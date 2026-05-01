use rustls_pki_types::CertificateDer;
use x509_parser::prelude::*;

/// Client certificate chain extracted from the TLS connection.
///
/// Injected into every HTTP request on a connection as an `axum::Extension`.
/// If the client did not present a certificate, `chain` is empty.
///
/// # Extracting in handlers
///
/// ```rust,ignore
/// use axum::extract::Extension;
/// use axum_mtls_acceptor::PeerCertificates;
///
/// async fn handler(Extension(certs): Extension<PeerCertificates>) -> String {
///     if let Some(cn) = certs.leaf_cn() {
///         format!("Authenticated as: {cn}")
///     } else {
///         "Anonymous".into()
///     }
/// }
/// ```
#[derive(Clone, Debug)]
pub struct PeerCertificates {
    /// DER-encoded certificate chain, leaf first.
    ///
    /// Ordered as received in the TLS handshake: the client's own certificate
    /// is at index 0, followed by any intermediate CAs.
    chain: Vec<CertificateDer<'static>>,
}

impl PeerCertificates {
    /// Create from a certificate chain (leaf first). An empty slice is valid.
    pub fn new(chain: Vec<CertificateDer<'static>>) -> Self {
        Self { chain }
    }

    /// Create an empty instance (no client certificate presented).
    pub fn empty() -> Self {
        Self { chain: Vec::new() }
    }

    /// Returns `true` if the client presented at least one certificate.
    pub fn is_present(&self) -> bool {
        !self.chain.is_empty()
    }

    /// Returns `true` if no client certificate was presented.
    pub fn is_empty(&self) -> bool {
        self.chain.is_empty()
    }

    /// The full DER-encoded certificate chain, leaf first.
    pub fn chain(&self) -> &[CertificateDer<'static>] {
        &self.chain
    }

    /// The leaf (client) certificate, if present.
    pub fn leaf(&self) -> Option<&CertificateDer<'static>> {
        self.chain.first()
    }

    /// Extract the Common Name (CN) from the leaf certificate's subject.
    ///
    /// Returns `None` if no certificate is present or the CN cannot be parsed.
    pub fn leaf_cn(&self) -> Option<String> {
        let leaf = self.leaf()?;
        let (_, cert) = X509Certificate::from_der(leaf.as_ref()).ok()?;
        let cn = cert
            .subject()
            .iter_common_name()
            .next()
            .and_then(|cn| cn.as_str().ok().map(String::from));
        cn
    }

    /// Extract all Subject Alternative Names (SANs) from the leaf certificate.
    ///
    /// Returns DNS names, email addresses, and IP addresses as strings.
    /// Returns an empty vec if no certificate is present or SANs cannot be parsed.
    pub fn leaf_sans(&self) -> Vec<String> {
        let Some(leaf) = self.leaf() else {
            return Vec::new();
        };
        let Ok((_, cert)) = X509Certificate::from_der(leaf.as_ref()) else {
            return Vec::new();
        };

        let san_ext = match cert.subject_alternative_name() {
            Ok(Some(ext)) => ext,
            _ => return Vec::new(),
        };

        san_ext
            .value
            .general_names
            .iter()
            .filter_map(|name| match name {
                GeneralName::DNSName(dns) => Some(dns.to_string()),
                GeneralName::RFC822Name(email) => Some(email.to_string()),
                GeneralName::IPAddress(ip) => {
                    // x509-parser gives us raw bytes; convert to display form
                    match ip.len() {
                        4 => Some(format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])),
                        16 => {
                            let addr: std::net::Ipv6Addr = {
                                let mut octets = [0u8; 16];
                                octets.copy_from_slice(ip);
                                octets.into()
                            };
                            Some(addr.to_string())
                        }
                        _ => None,
                    }
                }
                _ => None,
            })
            .collect()
    }

    /// Extract the leaf certificate's serial number as a hex string.
    pub fn leaf_serial_hex(&self) -> Option<String> {
        let leaf = self.leaf()?;
        let (_, cert) = X509Certificate::from_der(leaf.as_ref()).ok()?;
        Some(cert.serial.to_str_radix(16))
    }

    /// Extract the leaf certificate's not-after (expiry) time as a UNIX timestamp.
    pub fn leaf_not_after_unix(&self) -> Option<i64> {
        let leaf = self.leaf()?;
        let (_, cert) = X509Certificate::from_der(leaf.as_ref()).ok()?;
        Some(cert.validity().not_after.timestamp())
    }
}

impl Default for PeerCertificates {
    fn default() -> Self {
        Self::empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_certs() {
        let certs = PeerCertificates::empty();
        assert!(certs.is_empty());
        assert!(!certs.is_present());
        assert!(certs.leaf().is_none());
        assert!(certs.leaf_cn().is_none());
        assert!(certs.leaf_sans().is_empty());
        assert!(certs.leaf_serial_hex().is_none());
        assert!(certs.leaf_not_after_unix().is_none());
    }
}
