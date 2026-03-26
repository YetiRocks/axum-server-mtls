use axum_mtls_acceptor::PeerCertificates;
use rcgen::{CertificateParams, KeyPair};

/// Generate a self-signed CA certificate and key.
fn generate_ca() -> (String, String, rcgen::CertifiedKey) {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Test CA");
    let key_pair = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key_pair).unwrap();
    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();
    (
        cert_pem.clone(),
        key_pem,
        rcgen::CertifiedKey { cert, key_pair },
    )
}

/// Generate a client certificate signed by the CA.
fn generate_client_cert(
    ca: &rcgen::CertifiedKey,
    cn: &str,
    sans: &[&str],
) -> (String, String, Vec<u8>) {
    let san_strings: Vec<String> = sans.iter().map(|s| s.to_string()).collect();
    let mut params = CertificateParams::new(san_strings).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, cn);
    params.is_ca = rcgen::IsCa::NoCa;
    let key_pair = KeyPair::generate().unwrap();
    let cert = params.signed_by(&key_pair, &ca.cert, &ca.key_pair).unwrap();
    let cert_pem = cert.pem();
    let cert_der = cert.der().to_vec();
    let key_pem = key_pair.serialize_pem();
    (cert_pem, key_pem, cert_der)
}

#[test]
fn peer_certificates_from_der() {
    let (_ca_pem, _ca_key, ca) = generate_ca();
    let (_cert_pem, _key_pem, cert_der) = generate_client_cert(&ca, "test-client", &["test.local"]);

    let der = rustls_pki_types::CertificateDer::from(cert_der);
    let certs = PeerCertificates::new(vec![der]);

    assert!(certs.is_present());
    assert!(!certs.is_empty());
    assert_eq!(certs.chain().len(), 1);
    assert_eq!(certs.leaf_cn().as_deref(), Some("test-client"));

    let sans = certs.leaf_sans();
    assert!(sans.contains(&"test.local".to_string()));

    assert!(certs.leaf_serial_hex().is_some());
    assert!(certs.leaf_not_after_unix().is_some());
}

#[test]
fn peer_certificates_multiple_sans() {
    let (_ca_pem, _ca_key, ca) = generate_ca();
    let (_cert_pem, _key_pem, cert_der) =
        generate_client_cert(&ca, "multi-san", &["a.example.com", "b.example.com"]);

    let der = rustls_pki_types::CertificateDer::from(cert_der);
    let certs = PeerCertificates::new(vec![der]);

    let sans = certs.leaf_sans();
    assert_eq!(sans.len(), 2);
    assert!(sans.contains(&"a.example.com".to_string()));
    assert!(sans.contains(&"b.example.com".to_string()));
}

#[test]
fn peer_certificates_empty() {
    let certs = PeerCertificates::empty();
    assert!(certs.is_empty());
    assert!(!certs.is_present());
    assert!(certs.leaf().is_none());
    assert!(certs.leaf_cn().is_none());
    assert!(certs.leaf_sans().is_empty());
    assert!(certs.leaf_serial_hex().is_none());
}

#[test]
fn peer_certificates_default_is_empty() {
    let certs = PeerCertificates::default();
    assert!(certs.is_empty());
}
