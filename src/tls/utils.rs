use openssl::sha::Sha256;
use rustls::server::WebPkiClientVerifier;
use rustls::RootCertStore;
use rustls::ServerConfig;
use rustls_pemfile::rsa_private_keys;
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::fs::File;
use std::io::{self, BufReader};
use std::sync::Arc;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use openssl::nid::Nid;
use openssl::x509::X509;
use tokio_rustls::server::TlsStream;

pub fn configure_server_tls(cert_path: &str, key_path: &str, ca_cert_path: &str) -> Arc<ServerConfig> {
    let certs = load_certs(cert_path).expect("Erreur load_certs");
    let ca_certs = load_certs(ca_cert_path).expect("Erreur load_certs pour CA");
    let key = load_private_key(key_path).expect("Erreur load_private_key");

    let mut client_auth_roots = RootCertStore::empty();
    for cert in ca_certs {
        client_auth_roots.add(cert).expect("Erreur ajout certificat CA");
    }

    let client_auth = WebPkiClientVerifier::builder(client_auth_roots.into())
        .build()
        .expect("Erreur création WebPkiClientVerifier");

    let config = ServerConfig::builder()
        .with_client_cert_verifier(client_auth)
        .with_single_cert(certs, key)
        .
        .expect("Erreur configuration serveur TLS");

    Arc::new(config)
}

fn load_certs(path: &str) -> io::Result<Vec<CertificateDer<'static>>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let certs: Vec<_> = certs(&mut reader).collect();
    let certs = certs.into_iter()
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid cert"))?;
    Ok(certs.into_iter()
        .map(CertificateDer::from)
        .collect())
}

fn load_private_key(path: &str) -> io::Result<PrivateKeyDer<'static>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let pkcs8_keys: Vec<_> = pkcs8_private_keys(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid PKCS#8 key"))?;
    
    if !pkcs8_keys.is_empty() {
        return Ok(PrivateKeyDer::from(pkcs8_keys[0].clone_key()));
    }
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    
    let pkcs1_keys: Vec<_> = rsa_private_keys(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid PKCS#1 key"))?;
    
    if !pkcs1_keys.is_empty() {
        return Ok(PrivateKeyDer::from(pkcs1_keys[0].clone_key()));
    }
    
    Err(io::Error::new(io::ErrorKind::InvalidInput, "no private key found"))
}

pub fn calculate_fingerprint(cert_bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();//NTM openssl
    hasher.update(cert_bytes);
    let result = hasher.finish();
    result.iter().map(|b| format!("{:02x}", b)).collect::<String>()
}

pub fn extract_client_certificate(tls_stream: &TlsStream<tokio::net::TcpStream>) -> Option<String> {
    if let Some(certs) = tls_stream.get_ref().1.peer_certificates() {
        if let Some(client_cert) = certs.first() {
           // println!("Client certificate: {:?}", client_cert.as_ref());
            let fingerprint = calculate_fingerprint(&client_cert.as_ref());
            println!("Fingerprint: {}", fingerprint);
            return Some(fingerprint);
        }
    }
    None
}

#[allow(dead_code)]
pub fn extract_client_subject(tls_stream: &TlsStream<tokio::net::TcpStream>) -> Option<String> {
    if let Some(certs) = tls_stream.get_ref().1.peer_certificates() {
        if let Some(client_cert) = certs.first() {
            let cert = X509::from_der(client_cert.as_ref()).ok()?;
            if let Some(subject) = cert.subject_name().entries_by_nid(Nid::COMMONNAME).next() {
                let subject_value = subject.data().as_utf8().ok()?;
                println!("Subject: {}", subject_value);
                return Some(subject_value.to_string());
            }
        }
    }
    None
}