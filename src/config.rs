use openssl::rsa::Rsa;
//use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Read;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ConfigurationFile {
    pub company: String,
    pub issuer_url: String,
    pub listening_address: String,
    pub username: String,
    pub password: String,
}

pub fn read_configuration() -> Result<ConfigurationFile, String> {
    let mut file = File::open("configuration.json").expect("cannot read configuration file");
    let mut content = String::new();

    if let Err(_) = file.read_to_string(&mut content) {
        return Err(String::from("cannot read file"));
    }

    let result: Result<ConfigurationFile, serde_json::Error> = serde_json::from_str(&content);
    match result {
        Ok(configuration) => Ok(configuration),
        Err(_) => Err(String::from("cannot parse your configuration file")),
    }
}

pub fn read_jwt_private_key() -> Result<Vec<u8>, String> {
    let mut file = File::open("private_rsa_key.der").unwrap();
    let mut private_key = Vec::new();

    match file.read_to_end(&mut private_key) {
        Ok(_) => Ok(private_key),
        Err(_) => Err(String::from("cannot read key!")),
    }
}

pub fn check_configuration() -> Result<(), String> {
    match read_jwt_private_key() {
        Ok(private_key) => match Rsa::private_key_from_der(&private_key) {
            Ok(_) => Ok(()),
            Err(_) => Err(String::from("cannot parse rsa key")),
        },
        Err(_) => Err(String::from("cannot find/read private key file")),
    }
}
