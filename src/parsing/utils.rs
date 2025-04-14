use std::{
    cmp::Ordering, collections::HashMap, error::Error, fs::{File, OpenOptions}, io::{BufReader, BufWriter}, net::Ipv4Addr, path::Path
};

use hyper::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::{Value, from_reader, to_writer_pretty};
use sqlx::{PgPool,Row};
use urlencoding::encode;
use chrono::{DateTime, Duration, NaiveDateTime, ParseError, Utc,TimeZone,};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ClientData {
    pub(crate) address: String,
    pub(crate) port: String,
    pub(crate) privkey: String,
    pub(crate) pubkey: String,
    pub(crate) allowedip: String,
    pub(crate) allowedmask: String,
}
type ClientMap = HashMap<String, ClientData>;

#[derive(Serialize, Deserialize)]
struct WgConfigServer {
    public_key: String,
    allowed_ips: String,
}

#[allow(unused)]
fn mask_to_cidr(mask: &str) -> Option<u8> {
    mask.parse::<Ipv4Addr>().ok().map(|ip| {
        ip.octets()
            .iter()
            .fold(0, |acc, &b| acc + b.count_ones() as u8)
    })
}

#[allow(unused)]
fn format_allowed_ip(ip: &str, mask: &str) -> String {
    match mask_to_cidr(mask) {
        Some(cidr) => format!("{}/{}", ip, cidr),
        None => format!("{}/32", ip),
    }
}

#[allow(unused)]
pub fn generate_wg_json(wg_config: &Value) -> String {
    if let Some((_, inner_obj)) = wg_config.as_object().and_then(|obj| obj.iter().next()) {
        let public_key = inner_obj
            .get("pubkey")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let allowed_ip = inner_obj
            .get("allowedip")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let allowed_mask = inner_obj
            .get("allowedmask")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();

        let allowed_ips = if !allowed_ip.is_empty() && !allowed_mask.is_empty() {
            format_allowed_ip(&allowed_ip, &allowed_mask)
        } else {
            "".to_string()
        };

        let config = WgConfigServer {
            public_key,
            allowed_ips,
        };

        return serde_json::to_string_pretty(&config).unwrap_or_else(|_| "{}".to_string());
    }
    "{}".to_string()
}
#[allow(unused)]
pub async fn load_and_parse_json(file_path: &str, id_client_x_value: &str) -> (StatusCode, String) {
    let file_result = async_fs::read_to_string(file_path).await;

    match file_result {
        Ok(contents) => {
            match parse_client_json(&contents, id_client_x_value) {
                Ok(client_data) => {
                    println!("Config trouvée : {:?}", client_data);

                    let encoded_data = create_urlencoded_data(&client_data);

                    //println!("Encoded: {}", encoded_data);

                    (StatusCode::OK, encoded_data)
                }
                Err(e) => {
                    println!("Erreur lors du parsing : {}", e);

                    (
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Cannot send you the config".to_string(),
                    )
                }
            }
        }
        Err(e) => {
            println!(
                "Erreur lors de la récupération du contenu du fichier : {}",
                e
            );

            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Cannot send you the config".to_string(),
            )
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

    let ordered_fields = [
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

#[allow(unused)]
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

#[allow(dead_code)]
pub fn get_attribute_value(
    file_path: &Path,
    id: &str,
    attribute: &str,
) -> Result<Option<Value>, Box<dyn Error>> {
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
#[allow(dead_code)]
pub fn update_json_attribute(
    file_path: &Path,
    id: &str,
    attribute: &str,
    new_value: Value,
) -> Result<(), Box<dyn Error>> {
    println!(
        "Opening file '{}' to update attribute '{}' of ID '{}' to value '{:?}'",
        file_path.display(),
        attribute,
        id,
        new_value
    );

    let file = File::open(file_path)?;
    let reader = BufReader::new(file);
    let mut json_data: Value = from_reader(reader)?;

    println!("JSON data loaded from file: {:#?}", json_data);

    if let Some(entry) = json_data.get_mut(id) {
        println!("Entry found for ID '{}'", id);

        if entry.get(attribute).is_some() {
            println!(
                "Updating attribute '{}' to value '{:?}'",
                attribute, new_value
            );
            entry[attribute] = new_value;

            println!("Writing updated JSON data to file...");
            let file = OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(file_path)?;
            let writer = BufWriter::new(file);
            to_writer_pretty(writer, &json_data)?;

            println!("Updated JSON data written to file.");
            return Ok(());
        } else {
            println!("Attribute '{}' not found for ID '{}'", attribute, id);
        }
    } else {
        println!("ID '{}' not found in JSON data.", id);
    }

    Err("ID ou attribut non trouvé dans le fichier JSON.".into())
}


pub async fn init_db(db_url: &str) -> Result<PgPool, Box<dyn Error>> {
    let pool = PgPool::connect(db_url).await?;
    Ok(pool)
}

pub async fn list_ids_from_db(db_pool: &PgPool) -> Result<Vec<String>, Box<dyn Error>> {
    let rows = sqlx::query("SELECT id FROM users")
        .fetch_all(db_pool)
        .await?;
    let ids: Vec<String> = rows.into_iter().map(|row| row.get("id")).collect();
    
    Ok(ids)
}

pub async fn list_mail_from_db(db_pool: &PgPool) -> Result<Vec<String>, Box<dyn Error>> {
    let rows = sqlx::query("SELECT mail FROM users")
        .fetch_all(db_pool)
        .await?;
    let ids: Vec<String> = rows.into_iter().map(|row| row.get("mail")).collect();
    
    Ok(ids)
}
pub async fn list_timestamp_from_db(db_pool: &PgPool,user: &str) -> Result<Vec<String>, Box<dyn Error>> {
    let rows = sqlx::query("SELECT valid_until FROM users WHERE mail = $1")
        .bind(user)
        .fetch_all(db_pool)
        .await?;
    let ids: Vec<String> = rows.into_iter().map(|row| row.get("valid_until")).collect();
    
    Ok(ids)
}

pub async fn get_info_from_id_otp(db_pool: &PgPool, id: &str) -> Result<Option<String>, Box<dyn Error>> {
    let row = sqlx::query("SELECT is_set FROM users WHERE id = $1")
        .bind(id)
        .fetch_optional(db_pool)
        .await?;
    
        if let Some(r) = row {
            let is_set: Option<String> = r.try_get("is_set")?;
            Ok(is_set)
        } else {
            Ok(None)
        }
}



pub async fn update_db_otp_value(pool: &PgPool, id: &str, new_is_set_value: &str) -> Result<(), Box<dyn std::error::Error>> {
    let _ = sqlx::query("UPDATE users SET is_set = $1 WHERE id = $2")
        .bind(new_is_set_value)
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn write_db_otp_value(pool: &PgPool, id: &str, mail: &str) -> Result<(), Box<dyn std::error::Error>> {
    let otp_expiry = Utc::now() + Duration::minutes(5);
    let otp_expiry_str = otp_expiry.format("%Y-%m-%d %H:%M:%S").to_string();
    let _ = sqlx::query("UPDATE users SET id = $1, valid_until = $2 WHERE mail = $3")
        .bind(id)
        .bind(otp_expiry_str)
        .bind(mail)
        .execute(pool)
        .await?;
    Ok(())
}



pub async fn insert_vpn_config(pool: &PgPool, config: Value) -> Result<(), Box<dyn std::error::Error>> {
    if let Some((fingerprint, cfg)) = config.as_object().and_then(|obj| obj.iter().next()) {
        let address = cfg.get("address").and_then(|v| v.as_str()).unwrap_or_default();
        let port = cfg.get("port").and_then(|v| v.as_str()).unwrap_or_default();
        let privkey = cfg.get("privkey").and_then(|v| v.as_str()).unwrap_or_default();
        let pubkey = cfg.get("pubkey").and_then(|v| v.as_str()).unwrap_or_default();
        let allowedip = cfg.get("allowedip").and_then(|v| v.as_str()).unwrap_or_default();
        let allowedmask = cfg.get("allowedmask").and_then(|v| v.as_str()).unwrap_or_default();

        let _ = sqlx::query(
            "INSERT INTO wg_config (fingerprint, address, port, privkey, pubkey, allowedip, allowedmask)
             VALUES ($1, $2, $3, $4, $5, $6, $7)"
        )
        .bind(fingerprint)
        .bind(address)
        .bind(port)
        .bind(privkey)
        .bind(pubkey)
        .bind(allowedip)
        .bind(allowedmask)
        .execute(pool)
        .await?;
        
    }
    Ok(())
}


pub async fn load_and_parse_from_db(pool: &PgPool, id_client_x_value: &str) -> (StatusCode, String) {
    let row = sqlx::query("SELECT  address, port, privkey, pubkey, allowedip, allowedmask FROM wg_config WHERE fingerprint = $1")
    .bind(id_client_x_value)
    .fetch_optional(pool)
    .await;

    match row {
        Ok(Some(record)) => {
            let config = ClientData {
                address: record.get("address"),
                port: record.get("port"),
                privkey: record.get("privkey"),
                pubkey: record.get("pubkey"),
                allowedip: record.get("allowedip"),
                allowedmask: record.get("allowedmask"),
            };
            let encoded_data = create_urlencoded_data(&config);
            (StatusCode::OK, encoded_data)
        }
        Ok(None) => {
            println!("Aucun résultat pour l'ID fourni");
            (StatusCode::FORBIDDEN, "Cannot send you the config".to_string())
        }
        Err(e) => {
            println!("Erreur lors de la requête SQL : {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Database error".to_string())
        }
    }
    
}


pub async fn string_to_datetime(date_str: &str) -> Result<DateTime<Utc>, ParseError> {
    let naive_datetime = NaiveDateTime::parse_from_str(date_str, "%Y-%m-%d %H:%M:%S")?;
    let datetime_utc = Utc.from_utc_datetime(&naive_datetime);
    
    Ok(datetime_utc)
}
