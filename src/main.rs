mod tls;
use tls::utils::{configure_server_tls,extract_client_certificate};
mod parsing;
use parsing::utils::{find_x_header, generate_wg_json, list_ids_from_file, load_and_parse_json, update_json_attribute};
use hyper::StatusCode;
mod routes;
use routes::utils::{create_http_response,get_route_path_and_headers, send_request_server};
mod wireguard;
use wireguard::utils::{append_wg_config,generate_config,remove_wg_config};
use serde_json::Value;
use tokio::io::AsyncWriteExt;
use tokio_rustls::TlsAcceptor;
use std::collections::HashMap;
use std::path::Path;
use tokio::net::TcpListener;
use tokio::time::{timeout, Duration};


const MAX_CONNECTIONS: usize = 10;

lazy_static::lazy_static! {
    static ref CONNECTION_SEM: tokio::sync::Semaphore = tokio::sync::Semaphore::new(MAX_CONNECTIONS);
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    //TODO MODIF how to get cert
    
    let tls_config = configure_server_tls("temp_certif/certif_charizhard.crt","temp_certif/key_charizhard.key","temp_certif/ca.crt");
    let acceptor =TlsAcceptor::from(tls_config.clone());
    let listener = TcpListener::bind("0.0.0.0:8443").await.unwrap();
    println!("Serveur HTTPS en écoute sur https://0.0.0.0:8443");
    loop {
        let permit = CONNECTION_SEM.acquire().await.unwrap();
        let (socket, _) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Erreur d'acceptation: {}", e);
                continue;
            }
        };
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let mut tls_stream = match timeout(Duration::from_secs(3), acceptor.accept(socket)).await {
                Ok(Ok(s)) => {
                    println!("Connexion mTLS réussie !");
                    s
                },
                Ok(Err(e)) => {
                    eprintln!("Échec TLS: {}", e);
                    return;
                }
                Err(_) => {
                    eprintln!("Timeout TLS !");
                    return;
                }
            };
            if let Some((path, headers)) = get_route_path_and_headers(&mut tls_stream).await {
                match path.as_str() {
                    "/configwg" => {
                        let _ = handle_configwg(&mut tls_stream).await;
                    },
                    "/otp" => {
                        let _ = handle_otp(&mut tls_stream,&headers).await;
                    }
                    "/reset" => {
                        let _ = handle_reset(&mut tls_stream).await;
                    }
                    _ => {
                        let response_bytes = create_http_response(
                            StatusCode::NOT_FOUND,
                            "Route non trouvée",
                        );
                        let _ = tls_stream.write_all(&response_bytes).await;
                    }
            };            
        }
        else{
            println!("Connection mTLS failed!")
        }
    }
    );
    } 
}



async fn handle_configwg(stream: &mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>) -> Result<(), Box<dyn std::error::Error>> {
    let fingerprint = extract_client_certificate(stream)
        .ok_or("Client certificate extraction failed")?;

    let (status, response_body) = load_and_parse_json("example_json_config.json", &fingerprint).await;
    let response_bytes = create_http_response(status, &response_body);

    stream.write_all(&response_bytes).await?;
    Ok(())
}

async fn handle_otp(stream: &mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>,headers: &HashMap<String, String>) -> Result<(), Box<dyn std::error::Error>> {
    let (otp_value, _mail_value) = match (find_x_header(&headers, "otp"), find_x_header(&headers, "mail")) {//TODO Remettre le mail_value
        (Some(o), Some(m)) => (o, m),
        _ => {
            send_error_response(stream, StatusCode::BAD_REQUEST, "Missing OTP or Mail header").await?;
            return Ok(()); 
        }
    };

    let ids = list_ids_from_file(Path::new("otp.json"))?;
    if !is_string_in_id(&ids, &otp_value) {
        send_error_response(stream, StatusCode::FORBIDDEN, "Invalid OTP").await?;
        return Ok(());
    }

    let fingerprint = extract_client_certificate(stream)
        .ok_or("Client certificate extraction failed")?;


    update_json_attribute(Path::new("otp.json"), &otp_value, "is_set", Value::from(fingerprint.clone()))?;
    
    let wg_config = generate_config(fingerprint.clone());
    append_wg_config(Path::new("example_json_config.json"), wg_config.clone())?;
    
    let json_to_send = generate_wg_json(&wg_config);
    send_request_server("http://wg-server:8081/add-peer", &json_to_send).await?;

    let (status, response_body) = load_and_parse_json("example_json_config.json", &fingerprint).await;
    let response_bytes = create_http_response(status, &response_body);
    stream.write_all(&response_bytes).await?;

    Ok(())
}


async fn send_error_response(stream: &mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>, status: StatusCode, message: &str) -> Result<(), std::io::Error> {
    let response = create_http_response(status, message);
    stream.write_all(&response).await
}

async fn handle_reset(tls_stream: &mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>) -> Result<(), Box<dyn std::error::Error>> {
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
                tls_stream.write_all(&response_bytes).await?;
            }
            let response_bytes = create_http_response(
                StatusCode::OK,
                "config wipe",
            );
            tls_stream.write_all(&response_bytes).await?;
        } else {
            println!("non trouvé dans le fichier JSON.");
            let response_bytes = create_http_response(
                StatusCode::FORBIDDEN,
                "Erreur recherche bdd",
            );
            tls_stream.write_all(&response_bytes).await?;
        }
    }
    else{
        
        println!("Erreur lors de l'extraction du certificat du client");
        let response_bytes = create_http_response(
            StatusCode::FORBIDDEN,
            "Erreur lors de l'extraction du certificat du client",
        );
        tls_stream.write_all(&response_bytes).await?;
    }
    Ok(())
}
fn is_string_in_id(ids: &Vec<String>, search_str: &str) -> bool {
    ids.iter().any(|id| id == search_str)
}



