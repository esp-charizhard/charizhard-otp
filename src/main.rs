

use hyper::StatusCode;
use openssl::nid::Nid;
use openssl::x509::X509;
use rustls::server::WebPkiClientVerifier;
use rustls::RootCertStore;
use serde_json::{from_reader, json, to_writer_pretty, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;
use std::collections::HashMap;
use std::error::Error;
use std::path::Path;
use std::sync::Arc;
use tokio::net::TcpListener;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, BufWriter};
use urlencoding::encode;
use serde::{Serialize, Deserialize};
use openssl::sha::Sha256;
use wireguard_keys::Privkey;

#[derive(Serialize, Deserialize, Debug,Clone)]
pub struct ClientData {
    address: String,
    port: String,
    privkey: String,
    pubkey: String,
    allowedip: String,
    allowedmask: String, 
}
type ClientMap = HashMap<String, ClientData>;


#[tokio::main]
async fn main() {
    let tls_config = configure_server_tls("temp_certif/server.crt","temp_certif/server.key","temp_certif/ca.crt");
    let acceptor =TlsAcceptor::from(tls_config.clone());
    let listener = TcpListener::bind("0.0.0.0:8443").await.unwrap();//TODO REPLACE DNS ?
    println!("Serveur HTTPS en écoute sur https://0.0.0.0:8443");
    loop {
        let (socket, _) = listener.accept().await.unwrap();
        if let Ok(mut tls_stream) = acceptor.accept(socket).await {
            println!("Connection mTLS ok ! ");
             
            if let Some((path, headers)) = get_route_path_and_headers(&mut tls_stream).await {
                match path.as_str() {
                    "/configwg" => {
                        if let Some(fingerprint) = extract_client_certificate(&tls_stream) {
                            //TODO MODIF BDD ?
                            let (status, response_body) = load_and_parse_json("example_json_config.json", &fingerprint).await;
                            let response_bytes = create_http_response(status, &response_body);

                            // if let Some(subject) = extract_client_subject(&tls_stream) {
                            //     println!("Le subject du certificat est : {}", subject);
                            // } else {
                            //     println!("Aucun certificat client ou subject non trouvé.");
                            // }//SI BESOIN

                            if let Err(e) = tls_stream.write_all(&response_bytes).await {
                                eprintln!("Erreur lors de l'envoi de la réponse : {}", e);
                            }
                        } else {
                            println!("Erreur lors de l'extraction du certificat du client");
                            let response_bytes = create_http_response(
                                StatusCode::FORBIDDEN,
                                "Erreur lors de l'extraction du certificat du client",
                            );
                            if let Err(e) = tls_stream.write_all(&response_bytes).await {
                                eprintln!("Erreur lors de l'envoi de la réponse : {}", e);
                            }
                        }
                    },
                    "/otp" => {
                        if let (Some(otp_value), Some(mail_value)) = (find_x_header(&headers, "otp"), find_x_header(&headers, "mail")) {
                            println!("Headers trouvés : otp = {}, mail = {}", otp_value, mail_value);
                            let ids = match list_ids_from_file(Path::new("otp.json")) {
                                Ok(ids) => ids,
                                Err(e) => {
                                    println!("Erreur : {}", e);
                                    vec![]
                                }
                            };
                            if is_string_in_id(&ids, &otp_value) {
                                match (get_attribute_value(Path::new("otp.json"), &otp_value, "mail"), get_attribute_value(Path::new("otp.json"), &otp_value, "is_set")) {
                                    (Ok(Some(mail_db_value)), Ok(Some(is_set_value))) if mail_db_value == mail_value && is_set_value == 0 => {
                                        println!("MAIL + OTP OK");
                                        if let Some(fingerprint) = extract_client_certificate(&tls_stream) {
                                        if let Err(e) = update_json_attribute(Path::new("otp.json"), &otp_value, "is_set", Value::from(fingerprint.clone())) {
                                            eprintln!("Erreur lors de la mise à jour du JSON : {}", e);
                                            let response_bytes = create_http_response(
                                                StatusCode::INTERNAL_SERVER_ERROR,
                                                "Erreur enrollement de l'otp",
                                            );
                                            if let Err(e) = tls_stream.write_all(&response_bytes).await {
                                                eprintln!("Erreur lors de l'envoi de la réponse : {}", e);
                                            }
                                        } else {
                                            println!("Mise à jour réussie !");
                                            
                                                let wg_config = generate_config(fingerprint);
                                                println!("wg_config : {:?}", wg_config);
                                                if let Err(e) = append_wg_config(Path::new("example_json_config.json"), wg_config) {
                                                    eprintln!("Erreur lors de l'écriture de la configuration WireGuard : {}", e);
                                                    let response_bytes = create_http_response(
                                                        StatusCode::INTERNAL_SERVER_ERROR,
                                                        "Erreur enrollement de l'otp",
                                                    );
                                                    if let Err(e) = tls_stream.write_all(&response_bytes).await {
                                                        eprintln!("Erreur lors de l'envoi de la réponse : {}", e);
                                                    }
                                                }
                                                let response_bytes = create_http_response(
                                                    StatusCode::OK,
                                                    "enrollement ok",
                                                );
                                                if let Err(e) = tls_stream.write_all(&response_bytes).await {
                                                    eprintln!("Erreur lors de l'envoi de la réponse : {}", e);
                                                }
                                             
                                        
                                        }
                                        
                                    }
                                }
                                    _ => {
                                        let response_bytes = create_http_response(
                                            StatusCode::FORBIDDEN,
                                            "Erreur recherche bdd",
                                        );
                                        if let Err(e) = tls_stream.write_all(&response_bytes).await {
                                            eprintln!("Erreur lors de l'envoi de la réponse : {}", e);
                                        }
                                    }
                                }
                            }
                            else {
                                println!("non trouvé dans le fichier JSON.");
                                let response_bytes = create_http_response(
                                    StatusCode::FORBIDDEN,
                                    "Erreur recherche bdd",
                                );
                                if let Err(e) = tls_stream.write_all(&response_bytes).await {
                                    eprintln!("Erreur lors de l'envoi de la réponse : {}", e);
                                }
                            }
                            let response_bytes = create_http_response(
                                StatusCode::NOT_IMPLEMENTED,
                                "NOT_IMPLEMENTED YET",
                            );
                            if let Err(e) = tls_stream.write_all(&response_bytes).await {
                                eprintln!("Erreur lors de l'envoi de la réponse : {}", e);
                            }
                        } else {
                            println!("Header 'otp' ou 'mail' non trouvé");
                            let response_bytes = create_http_response(
                                StatusCode::FORBIDDEN,
                                "header error",
                            );
                            if let Err(e) = tls_stream.write_all(&response_bytes).await {
                                eprintln!("Erreur lors de l'envoi de la réponse : {}", e);
                            }
                        }
                    }
                    "/reset" => {
                        if let Some(fingerprint) = extract_client_certificate(&tls_stream) {
                            let ids = match list_ids_from_file(Path::new("example_json_config.json")) {
                                Ok(ids) => ids,
                                Err(e) => {
                                    println!("Erreur : {}", e);
                                    vec![]
                                }
                            };
                            if is_string_in_id(&ids, &fingerprint) {
                                println!("trouvé dans le fichier JSON !");
                                if let Err(e) = remove_wg_config(Path::new("example_json_config.json"), &fingerprint) {
                                    println!("Erreur lors de la suppression de la config : {}", e);
                                    let response_bytes = create_http_response(
                                        StatusCode::INTERNAL_SERVER_ERROR,
                                        "Erreur suppression config",
                                    );
                                    if let Err(e) = tls_stream.write_all(&response_bytes).await {
                                        eprintln!("Erreur lors de l'envoi de la réponse : {}", e);
                                    }
                                }
                                let response_bytes = create_http_response(
                                    StatusCode::OK,
                                    "config wipe",
                                );
                                if let Err(e) = tls_stream.write_all(&response_bytes).await {
                                    eprintln!("Erreur lors de l'envoi de la réponse : {}", e);
                                }
                            } else {
                                println!("non trouvé dans le fichier JSON.");
                                let response_bytes = create_http_response(
                                    StatusCode::FORBIDDEN,
                                    "Erreur recherche bdd",
                                );
                                if let Err(e) = tls_stream.write_all(&response_bytes).await {
                                    eprintln!("Erreur lors de l'envoi de la réponse : {}", e);
                                }
                            }
                        }
                        else{
                            println!("Erreur lors de l'extraction du certificat du client");
                            let response_bytes = create_http_response(
                                StatusCode::FORBIDDEN,
                                "Erreur lors de l'extraction du certificat du client",
                            );
                            if let Err(e) = tls_stream.write_all(&response_bytes).await {
                                eprintln!("Erreur lors de l'envoi de la réponse : {}", e);
                            }
                        }
                    }
                    _ => {
                        let response_bytes = create_http_response(
                            StatusCode::NOT_FOUND,
                            "Route non trouvée",
                        );
                        if let Err(e) = tls_stream.write_all(&response_bytes).await {
                            eprintln!("Erreur lors de l'envoi de la réponse : {}", e);
                        }
                    }
            };            
        }
        else{
            println!("Connection mTLS failed!")
        }
    }
}
}
pub fn calculate_fingerprint(cert_bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();//NTM openssl
    hasher.update(cert_bytes);
    let result = hasher.finish();
    result.iter().map(|b| format!("{:02x}", b)).collect::<String>()
}

pub fn configure_server_tls(cert_path: &str,key_path: &str,ca_cert_path: &str) -> Arc<ServerConfig>{
    //println!("Configuring mTLS server");
    let certs = load_certs(cert_path).expect("Erreur load_certs");
    let ca_certs = load_certs(ca_cert_path).expect("Erreur load_certs pour CA");
    let key = load_private_key(key_path).expect("Erreur load_private_key");
    //println!("end load certifs/keys");
    let mut client_auth_roots = RootCertStore::empty();
    for cert in ca_certs {
       client_auth_roots.add(cert).expect("Erreur ajout certificat CA");
    }

    let client_auth = WebPkiClientVerifier::builder(client_auth_roots.into())
        .build()
        .expect("Erreur création WebPkiClientVerifier");
    
    let config = ServerConfig::builder()
       .with_client_cert_verifier(client_auth) //mTLS
       .with_single_cert(certs, key)
       .expect("Erreur configuration serveur TLS");
    //config.set_client_cert_verifier(rustls::client::ServerCertVerifier::from(ca_certs));
    Arc::new(config)
}

pub fn load_certs(path: &str) -> io::Result<Vec<CertificateDer<'static>>> {
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

pub fn load_private_key(path: &str) -> io::Result<PrivateKeyDer<'static>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let keys: Vec<_> = pkcs8_private_keys(&mut reader).collect();
    let keys = keys.into_iter()
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid key"))?;
    let keys = keys.into_iter()
        .map(PrivateKeyDer::from)
        .collect::<Vec<_>>();
    keys.into_iter()
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no private key found"))
}


fn extract_client_certificate(tls_stream: &TlsStream<tokio::net::TcpStream>) -> Option<String> {
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
fn extract_client_subject(tls_stream: &TlsStream<tokio::net::TcpStream>) -> Option<String> {
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

async fn load_and_parse_json(file_path: &str, id_client_x_value: &str) -> (StatusCode, String) {
    let file_result = async_fs::read_to_string(file_path).await;

    match file_result {
        Ok(contents) => {
            match parse_client_json(&contents, id_client_x_value) {
                Ok(client_data) => {
                    println!("Config trouvée : {:?}", client_data);
                    let encoded_data = create_urlencoded_data(&client_data);
                    //println!("Encoded: {}", encoded_data);
                    return (StatusCode::OK, encoded_data);
                }
                Err(e) => {
                    println!("Erreur lors du parsing : {}", e);
                    return (
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Cannot send you the config".to_string(),
                    );
                }
            }
        }
        Err(e) => {
            println!("Erreur lors de la récupération du contenu du fichier : {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Cannot send you the config".to_string(),
            );
        }
    }
}

pub fn parse_client_json(json_str: &str, client_id: &str) -> Result<ClientData, String> {
    let clients: ClientMap = match serde_json::from_str(json_str) {
        Ok(c) => c,
        Err(e) => return Err(format!("Erreur de format JSON : {}", e)),
    };
    match clients.get(client_id) {
        Some(client_data) => Ok(client_data.clone()), // Clone pour retourner une copie de ClientData
        None => Err(format!("Client ID '{}' non trouvé", client_id)),
    }
}

pub fn create_urlencoded_data(client_data: &ClientData) -> String {
    let mut data = HashMap::new();
    
    data.insert("address", &client_data.address);
    data.insert("port", &client_data.port);
    data.insert("privkey", &client_data.privkey);
    data.insert("public_key_server", &client_data.pubkey);
    data.insert("allowedip", &client_data.allowedip);
    data.insert("allowedmask", &client_data.allowedmask);

    let ordered_fields = vec![
        ("address", &client_data.address),
        ("port", &client_data.port),
        ("privkey", &client_data.privkey),
        ("pubkey", &client_data.pubkey),
        ("allowedip", &client_data.allowedip),
        ("allowedmask", &client_data.allowedmask),
    ];

    let encoded_data: String = ordered_fields
        .iter()
        .map(|(key, value)| format!("{}={}", encode(key), encode(value)))
        .collect::<Vec<String>>()
        .join("&");


    encoded_data
}

/// Extract the path from an HTTP request.
///
/// The function reads the request line by line and tries to extract the path from the first line.
/// If it fails, it returns "/" as the default path.
fn extract_path_from_request(request: &str) -> String {
    if let Some(path) = request.lines().next() {
        if let Some(path) = path.split_whitespace().nth(1) {
            return path.to_string();
        }
    }
    "/".to_string() // Par défaut, retourne la racine
}




async fn get_route_path_and_headers(tls_stream: &mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>) -> Option<(String, HashMap<String, String>)> {
    let mut request_data = Vec::new();
    let mut buffer = [0; 1024]; 
    loop {
        match tls_stream.read(&mut buffer).await {
            Ok(0) => break,
            Ok(n) => {
                request_data.extend_from_slice(&buffer[..n]);
                if request_data.windows(4).any(|window| window == b"\r\n\r\n") {
                    break; 
                }
            }
            Err(e) => {
                eprintln!("Erreur lors de la lecture de la requête : {}", e);
                return None; 
            }
        }
    }
    let request = match String::from_utf8(request_data) {
        Ok(request) => request,
        Err(e) => {
            eprintln!("Erreur lors de la conversion UTF-8 : {}", e);
            return None; 
        }
    };
    let path = extract_path_from_request(&request);
    println!("path : {}", path);
    let mut headers = HashMap::new();
    let mut in_headers = true;
    for line in request.lines() {

        if in_headers {
            if line.is_empty() {
                in_headers = false;
            } else {
                if let Some((key, value)) = parse_header(line) {
                    //println!("Header extrait: [{}] = [{}]", key, value);
                    headers.insert(key, value);
                } 
            }
        }
    }
    Some((path, headers))
}


pub fn create_http_response(status: StatusCode,body: &str,) -> Vec<u8> {
    let mut response = format!(
        "HTTP/1.1 {}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n", 
        status,
        body.len()
    );
    response.push_str("\r\n");
    response.push_str(body);
    response.into_bytes()
}

fn parse_header(header_line: &str) -> Option<(String, String)> {
    //println!("test parse header");
    if let Some(pos) = header_line.find(':') {
        let key = header_line[..pos].trim().to_string();
        let value = header_line[pos + 1..].trim().to_string();
        Some((key, value))
    } else {
        None
    }
}

fn is_string_in_id(ids: &Vec<String>, search_str: &str) -> bool {
    ids.iter().any(|id| id == search_str)
}


fn find_x_header(headers: &HashMap<String, String>, header_name: &str) -> Option<String> {
    headers.get(header_name).cloned()
}
fn list_ids_from_file(file_path: &Path) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let file = File::open(file_path)?;
    let reader = BufReader::new(file);
    let json_data: Value = serde_json::from_reader(reader)?;
    if let Value::Object(obj) = json_data {
        let ids: Vec<String> = obj.keys().map(|k| k.to_string()).collect();
        return Ok(ids);
    }
    Err("Le fichier JSON n'est pas un objet valide.".into())
}

fn get_attribute_value(file_path: &Path, id: &str, attribute: &str) -> Result<Option<Value>, Box<dyn Error>> {
    let file = File::open(file_path)?;
    let reader = BufReader::new(file);
    let json_data: Value = from_reader(reader)?;

    if let Some(entry) = json_data.get(id) {
        if let Some(value) = entry.get(attribute) {
            return Ok(Some(value.clone()));
        }
    }

    Ok(None) // L'attribut ou l'ID n'existe pas
}

fn update_json_attribute(file_path: &Path, id: &str, attribute: &str, new_value: Value) -> Result<(), Box<dyn Error>> {
    let file = File::open(file_path)?;
    let reader = BufReader::new(file);
    let mut json_data: Value = from_reader(reader)?;

    if let Some(entry) = json_data.get_mut(id) {
        if entry.get(attribute).is_some() {
            entry[attribute] = new_value;

            let file = OpenOptions::new().write(true).truncate(true).open(file_path)?;
            let writer = BufWriter::new(file);
            to_writer_pretty(writer, &json_data)?;

            return Ok(());
        }
    }

    Err("ID ou attribut non trouvé dans le fichier JSON.".into())
}

fn generate_config(fingerpint:String) -> serde_json::Value{
    let private_key = Privkey::generate();
    println!("Clé privée générée : {}", private_key.to_base64());
    json!({
        fingerpint: {
            "address": "1.1.1.1",//TODO Dynamic IP change for each client
            "port": "51820",
            "privkey": private_key,
            "pubkey": "nwkXWjc5q1NsGh6y9Y+1usPcbQzxYviNoqFG5Cl0tXI=",
            "allowedip": "10.200.200.200",
            "allowedmask": "255.255.255.254"
        }
    })
}

fn append_wg_config(file_path: &Path, config: Value) -> std::io::Result<()> {
    let mut data = if file_path.exists() {
        let file_content = fs::read_to_string(file_path)?;
        serde_json::from_str::<Value>(&file_content).unwrap_or(json!({}))
    } else {
        json!({})
    };
    if let Some(client_id) = config.as_object() {
        for (key, value) in client_id {
            data[key] = value.clone(); // Merging or updating values
        }
    }
    fs::write(file_path, serde_json::to_string_pretty(&config)?)
}

fn remove_wg_config(file_path: &Path, client_id: &str) -> std::io::Result<()> {
    let mut data = if file_path.exists() {
        let file_content = fs::read_to_string(file_path)?;
        serde_json::from_str::<Value>(&file_content).unwrap_or(json!({}))
    } else {
        json!({})
    };
    if data.is_object() {
        data.as_object_mut().unwrap().remove(client_id);
    }
    fs::write(file_path, serde_json::to_string_pretty(&data)?)
}