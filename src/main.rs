mod tls;
use chrono::Utc;
use mail::utils::send_email;
use tls::utils::{configure_server_tls, extract_client_certificate};
mod parsing;
use hyper::StatusCode;
use parsing::utils::{
    find_x_header, generate_wg_json, get_info_from_id_otp, init_db, insert_vpn_config, list_ids_from_db, list_mail_from_db, list_timestamp_from_db, load_and_parse_from_db, string_to_datetime, update_db_otp_value, write_db_otp_value
};
mod routes;
use routes::utils::{create_http_response, generate_otp, get_route_path_and_headers, send_request_server};
mod wireguard;
use std::collections::HashMap;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::time::{Duration, timeout};
use tokio_rustls::TlsAcceptor;
use wireguard::utils::{generate_config, remove_wg_config_db};
mod mail;
use std::env;
const MAX_CONNECTIONS: usize = 10;

lazy_static::lazy_static! {
    static ref CONNECTION_SEM: tokio::sync::Semaphore = tokio::sync::Semaphore::new(MAX_CONNECTIONS);
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv()?;
    let tls_config = configure_server_tls(
        "temp_certif/certif_charizhard.crt",
        "temp_certif/key_charizhard.key",
        "temp_certif/ca.crt",
    );
    


    let acceptor = TlsAcceptor::from(tls_config.clone());
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
            let mut tls_stream =
                match timeout(Duration::from_secs(20), acceptor.accept(socket)).await {
                    Ok(Ok(s)) => {
                        println!("Connexion mTLS réussie !");
                        s
                    }
                    Ok(Err(e)) => {
                        eprintln!("Échec TLS: {}", e);
                        // let response_bytes = create_http_response(StatusCode::INTERNAL_SERVER_ERROR, "Erreuyr");
                        // let _ = tls_stream.write_all(&response_bytes).await;
                        return;
                    }
                    Err(_) => {
                        eprintln!("Timeout TLS !");
                        return;
                    }
                };
            let database_url = env::var("DATABASE_URL").unwrap();
            let pool = init_db(&database_url).await.unwrap();
            match get_route_path_and_headers(&mut tls_stream).await {
                Some((path, headers)) => match path.as_str() {
                    "/configwg" => {
                        let _ = handle_configwg(&mut tls_stream,pool).await;
                    }
                    "/otp" => {
                        let _ = handle_otp(&mut tls_stream, &headers,pool).await;
                    }
                    "/gen_otp" => {
                        let _ = handle_gen_otp(&mut tls_stream, &headers,pool).await;
                    }
                    "/reset" => {
                        let _ = handle_reset(&mut tls_stream,pool).await;
                    }
                    _ => {
                        let response_bytes =
                            create_http_response(StatusCode::NOT_FOUND, "Route non trouvée");
                        let _ = tls_stream.write_all(&response_bytes).await;
                    }
                },
                None => {
                    eprintln!("Requête invalide : fermeture de la connexion");
                }
            }
        });
    }
}

async fn handle_configwg(
    stream: &mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>,pool:sqlx::PgPool
) -> Result<(), Box<dyn std::error::Error>> {
    let fingerprint =
        extract_client_certificate(stream).ok_or("Client certificate extraction failed")?;

    let (status, response_body) = load_and_parse_from_db(&pool,&fingerprint).await;
    let response_bytes = create_http_response(status, &response_body);

    stream.write_all(&response_bytes).await?;
    Ok(())
}

async fn handle_otp(
    stream: &mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    headers: &HashMap<String, String>,
    pool:sqlx::PgPool
) -> Result<(), Box<dyn std::error::Error>> {
    //println!("Handling OTP");
    let (otp_value, mail_value) = match (
        find_x_header(headers, "otp"),
        find_x_header(headers, "mail"),
    ) {
        //TODO Remettre le mail_value
        (Some(o), Some(m)) => (o, m),
        _ => {
            send_error_response(
                stream,
                StatusCode::BAD_REQUEST,
                "Missing OTP or Mail header",
            )
            .await?;
            return Ok(());
        }
    };
    //println!("Verif header ok");
    let ids = list_ids_from_db(&pool).await?;
    let mails = list_mail_from_db(&pool).await?;
    if !is_string_in_id(&ids, &otp_value) || !is_string_in_id(&mails, &mail_value) {
        send_error_response(stream, StatusCode::FORBIDDEN, "Invalid OTP/MAIL or already set").await?;
        return Ok(());
    }
    let valid_until=list_timestamp_from_db(&pool,&mail_value).await?;
    println!("valid_until: {:?}", valid_until);
    if Utc::now() > string_to_datetime(&valid_until[0]).await? {
        send_error_response(
            stream,
            StatusCode::FORBIDDEN,
            "otp expired",
        )
        .await?;
        return Ok(());
    }
    let fingerprint = extract_client_certificate(stream).ok_or("Client certificate extraction failed")?;
    if !get_info_from_id_otp(&pool, &otp_value).await?.is_none(){
        println!("You already got a config , sending u the right one");
        let (status, response_body) = load_and_parse_from_db(&pool,&fingerprint.clone()).await;
        let response_bytes = create_http_response(status, &response_body);
    
        stream.write_all(&response_bytes).await?;
    }
   

    update_db_otp_value(&pool, &otp_value, &fingerprint).await?;
    let wg_config = generate_config(fingerprint.clone());
    //println!("wg_config JSON: {}", wg_config);
    if let Err(e) = insert_vpn_config(&pool, wg_config.clone()).await {
        eprintln!("Erreur lors de l'insertion dans vpn_config: {}", e);
    }
    //println!("appended is_set from json");
    let json_to_send = generate_wg_json(&wg_config);
    //println!("JSON to send: {}", json_to_send);
    match send_request_server("https://charizhard-wg.duckdns.org:8081/add-peer", &json_to_send).await {
        Ok(_) => println!("Requête envoyée avec succès"),
        Err(e) => eprintln!("Erreur lors de l'envoi de la requête : {}", e),
    }
    let (status, response_body) = load_and_parse_from_db(&pool,&fingerprint).await;
    // let (status, response_body) =
    //     load_and_parse_json("example_json_config.json", &fingerprint).await;
    let response_bytes = create_http_response(status, &response_body);
    stream.write_all(&response_bytes).await?;

    Ok(())
}

async fn send_error_response(
    stream: &mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    status: StatusCode,
    message: &str,
) -> Result<(), std::io::Error> {
    let response = create_http_response(status, message);
    stream.write_all(&response).await
}

async fn handle_reset(
    tls_stream: &mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>, pool:sqlx::PgPool
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(fingerprint) = extract_client_certificate(tls_stream) {
        let ids = list_ids_from_db(&pool).await?;
        if is_string_in_id(&ids, &fingerprint) {
            println!("trouvé dans le fichier JSON !");
            match remove_wg_config_db(&pool, &fingerprint).await {
                Ok(_) => {
                    let response_bytes = create_http_response(StatusCode::OK, "Config wipe");
                    tls_stream.write_all(&response_bytes).await?;
                }
                Err(e) => {
                    eprintln!("Erreur lors de la suppression : {}", e);
                    let response_bytes = create_http_response(StatusCode::INTERNAL_SERVER_ERROR, "Cannot wipe the config");
                    tls_stream.write_all(&response_bytes).await?;
                }
            }
        } else {
            println!("non trouvé dans le fichier JSON.");
            let response_bytes =
                create_http_response(StatusCode::FORBIDDEN, "Erreur recherche bdd");
            tls_stream.write_all(&response_bytes).await?;
        }
    } else {
        println!("Erreur lors de l'extraction du certificat du client");
        let response_bytes = create_http_response(
            StatusCode::FORBIDDEN,
            "Erreur lors de l'extraction du certificat du client",
        );
        tls_stream.write_all(&response_bytes).await?;
    }
    Ok(())
}
fn is_string_in_id(ids: &[String], search_str: &str) -> bool {
    ids.iter().any(|id| id == search_str)
    
}



async fn handle_gen_otp(
    tls_stream: &mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    headers: &HashMap<String, String>,
    pool:sqlx::PgPool
) -> Result<(), Box<dyn std::error::Error>> {
    let mail_value = find_x_header(headers, "mail");
    println!("mail_value: {:?}",mail_value);
    let mails = list_mail_from_db(&pool).await?;
    if let Some(mail_value) = mail_value {
        if !is_string_in_id(&mails, mail_value.as_str()) {
            let response_bytes =
                create_http_response(StatusCode::FORBIDDEN, "Erreur recherche bdd");
            tls_stream.write_all(&response_bytes).await?;
        }
        println!("Generating OTP Value");
        let otp_value = generate_otp().await;
        println!("OTP Value: {:?}", otp_value);
        write_db_otp_value(&pool, &otp_value, &mail_value).await?;
        send_email(&mail_value, &otp_value).await?;
        let response_bytes = create_http_response(StatusCode::OK, "Sending MAIL , please check your inbox");
        tls_stream.write_all(&response_bytes).await?;
    }
    Ok(())
}