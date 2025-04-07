use std::{fs, path::Path};

use serde_json::{Value, json};
use wireguard_keys::Privkey;

pub fn generate_config(fingerpint: String) -> serde_json::Value {
    let private_key = Privkey::generate();
    println!("Clé privée générée : {}", private_key.to_base64());
    json!({
        fingerpint: {
            "address": "54.82.126.191",//TODO Dynamic IP change for each client
            "port": "51820",
            "privkey": "kJ09fiJcmyEBIjPkAOEnP2xDXA5X2NrmlYql/duqnHI=",
            "pubkey": "nwkXWjc5q1NsGh6y9Y+1usPcbQzxYviNoqFG5Cl0tXI=",
            "allowedip": "192.168.200.2",
            "allowedmask": "255.255.255.255"
        }
    })
}

pub fn append_wg_config(file_path: &Path, config: Value) -> std::io::Result<()> {
    println!("Appending WireGuard configuration to file: {:?}", file_path);

    let mut data = if file_path.exists() {
        println!("File exists. Reading current content.");
        let file_content = fs::read_to_string(file_path)?;
        serde_json::from_str::<Value>(&file_content).unwrap_or_else(|_| {
            println!("Failed to parse existing file content. Using empty JSON object.");
            json!({})
        })
    } else {
        println!("File does not exist. Creating new JSON object.");
        json!({})
    };

    if let Some(client_id) = config.as_object() {
        println!("Appending new configuration data.");
        for (key, value) in client_id {
            println!("Adding key: {} with value: {:?}", key, value);
            data[key] = value.clone();
        }
    }

    println!("Writing updated configuration to file.");
    fs::write(file_path, serde_json::to_string_pretty(&data)?)
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
