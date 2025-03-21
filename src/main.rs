mod tls;
use tls::utils::{configure_server_tls,extract_client_certificate};
mod parsing;
use parsing::utils::{list_ids_from_file,load_and_parse_json,find_x_header,get_attribute_value,update_json_attribute};
use hyper::StatusCode;
mod routes;
use routes::utils::{create_http_response,get_route_path_and_headers};
mod wireguard;
use wireguard::utils::{append_wg_config,generate_config,remove_wg_config};
use serde_json::Value;
use tokio::io::AsyncWriteExt;
use tokio_rustls::TlsAcceptor;
use std::path::Path;
use tokio::net::TcpListener;





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



fn is_string_in_id(ids: &Vec<String>, search_str: &str) -> bool {
    ids.iter().any(|id| id == search_str)
}



