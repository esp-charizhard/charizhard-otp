use std::{collections::HashMap, error::Error, fs::{File, OpenOptions}, io::{BufReader, BufWriter}, path::Path};

use hyper::StatusCode;
use serde::{Serialize, Deserialize};
use serde_json::{from_reader, to_writer_pretty, Value};
use urlencoding::encode;

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

pub async fn load_and_parse_json(file_path: &str, id_client_x_value: &str) -> (StatusCode, String) {
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

pub fn list_ids_from_file(file_path: &Path) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let file = File::open(file_path)?;
    let reader = BufReader::new(file);
    let json_data: Value = serde_json::from_reader(reader)?;
    if let Value::Object(obj) = json_data {
        let ids: Vec<String> = obj.keys().map(|k| k.to_string()).collect();
        return Ok(ids);
    }
    Err("Le fichier JSON n'est pas un objet valide.".into())
}

pub fn find_x_header(headers: &HashMap<String, String>, header_name: &str) -> Option<String> {
    headers.get(header_name).cloned()
}

pub fn get_attribute_value(file_path: &Path, id: &str, attribute: &str) -> Result<Option<Value>, Box<dyn Error>> {
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

pub fn update_json_attribute(file_path: &Path, id: &str, attribute: &str, new_value: Value) -> Result<(), Box<dyn Error>> {
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