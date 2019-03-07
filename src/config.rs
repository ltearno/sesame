use openssl::rsa::Rsa;
use std::fs::File;
use std::io::Read;

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
