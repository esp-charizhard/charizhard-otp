use std::collections::HashMap;

use hyper::StatusCode;
use reqwest::Client;
use tokio::io::AsyncReadExt;

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

pub async fn get_route_path_and_headers(
    tls_stream: &mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
) -> Option<(String, HashMap<String, String>)> {
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
            } else if let Some((key, value)) = parse_header(line) {
                //println!("Header extrait: [{}] = [{}]", key, value);
                headers.insert(key, value);
            }
        }
    }
    Some((path, headers))
}

pub fn create_http_response(status: StatusCode, body: &str) -> Vec<u8> {
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

#[allow(unused)]
pub async fn send_request_server(endpoint: &str, json_data: &str) -> Result<(), reqwest::Error> {
    let client = Client::new();
    println!("{}", json_data);
    let response = client
        .post(endpoint)
        .header("Content-Type", "application/json")
        .body(json_data.to_string())
        .send()
        .await?;

    println!("Response status: {}", response.status());
    Ok(())
}
