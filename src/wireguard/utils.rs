
use std::{fs, path::Path};

use serde_json::{json, Value};
use wireguard_keys::Privkey;

pub fn generate_config(fingerpint:String) -> serde_json::Value{
    let private_key = Privkey::generate();
    println!("Clé privée générée : {}", private_key.to_base64());
    json!({
        fingerpint: {
            "address": "charizhard-wg.duckdns.org",//TODO Dynamic IP change for each client
            "port": "51820",
            "privkey": private_key,
            "pubkey": "nwkXWjc5q1NsGh6y9Y+1usPcbQzxYviNoqFG5Cl0tXI=",
            "allowedip": "192.168.200.2",
            "allowedmask": "255.255.255.255"
        }
    })
}

pub fn append_wg_config(file_path: &Path, config: Value) -> std::io::Result<()> {
    let mut data = if file_path.exists() {
        let file_content = fs::read_to_string(file_path)?;
        serde_json::from_str::<Value>(&file_content).unwrap_or(json!({}))
    } else {
        json!({})
    };
    if let Some(client_id) = config.as_object() {
        for (key, value) in client_id {
            data[key] = value.clone(); 
        }
    }
    fs::write(file_path, serde_json::to_string_pretty(&config)?)
}

pub fn remove_wg_config(file_path: &Path, client_id: &str) -> std::io::Result<()> {
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