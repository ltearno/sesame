extern crate actix_web;
extern crate jsonwebtoken as jwt;
extern crate openssl;
#[macro_use]
extern crate serde_derive;
extern crate base64;

use actix_web::{http::ContentEncoding, server, App, HttpRequest, HttpResponse};
use jwt::{encode, Algorithm, Header};
use openssl::rsa::Rsa;
use std::fs::File;
use std::io::Read;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    company: String,
    exp: usize,
    role: String,
}

/**
 * certs endpoint should return something like this :HttpResponse

 {
    "keys": [
        {
            "kid": "118RDCse9jQdxQTgJKveyoHpZia8GJHTE9F2OJa53sw",
            "kty": "RSA",
            "alg": "RS256",
            "use": "sig",
            "n": "7KcL6wgbeJm4_E6K66Y5A9wP2Igmt1wfzkcZQ11HtVVAB3BGMsbHE37clWx0K4pW6ovbJcRxtHkuu6FMCch-WkIzqVr6e05haHO8pZpkXQH89a3t5dEeq9_e_W-yYKnmzlcAUVS8U3mBJMv7RQto0NBCmOBunoVmFbvCWOGj5FiSdS4xnSZIt1XmSTMVTiVeIUZGJ4M0oq53Hb7XFMPU7qB_GQRFh8dBXGjB9sMh7seq9sU39SDX5P-r4rDmIv6S_qbCCk6LNS9Q8zTVBkeavPi2Upu7zRV7PsScL3vxsVVXXe2PsaQewSNOZdwzCuT1FLELmyMaEHXZAlTdUcnhJQ",
            "e": "AQAB"
        }
    ]
}

 */

#[derive(Debug, Serialize, Deserialize)]
struct KeyDescription {
    kid: String,
    kty: String,
    alg: String,
    #[serde(rename = "use")]
    usee: String,
    n: String,
    e: String,
}

fn certs(_req: &HttpRequest) -> HttpResponse {
    let private_key = read_private_key().expect("cannot read key");

    let rsa_key = Rsa::private_key_from_der(&private_key).expect("cannot read RSA key");

    let encoded_modulus = base64::encode_config(&(rsa_key.n().to_vec()), base64::URL_SAFE_NO_PAD);
    let encoded_exponent = base64::encode_config(&(rsa_key.e().to_vec()), base64::URL_SAFE_NO_PAD);

    let value = KeyDescription {
        kid: String::from("toto"),
        kty: String::from("RSA"),
        alg: String::from("RSA256"),
        usee: String::from("sig"),
        n: encoded_modulus,
        e: encoded_exponent,
    };

    HttpResponse::Ok()
        .content_encoding(ContentEncoding::Auto)
        .content_type("application/json")
        .json(value)
}

fn read_private_key() -> Result<Vec<u8>, String> {
    let mut file = File::open("private_rsa_key.der").unwrap();
    let mut private_key = Vec::new();

    match file.read_to_end(&mut private_key) {
        Ok(_) => Ok(private_key),
        Err(_) => Err(String::from("cannot read key!")),
    }
}

fn index(_req: &HttpRequest) -> HttpResponse {
    let mut header = Header::default();
    header.kid = Some("blabla".to_owned());
    header.alg = Algorithm::RS256;

    let my_claims = Claims {
        sub: String::from("Tto"),
        company: String::from("LTE Consulting"),
        exp: 244555,
        role: String::from("{}"),
    };

    let private_key = read_private_key().expect("cannot read private key");

    let token = encode(&header, &my_claims, &private_key).expect("cannot generate JWT token");

    HttpResponse::Ok()
        .content_encoding(ContentEncoding::Auto)
        .content_type("application/json")
        .body(token)
}

fn main() {
    let private_key = read_private_key().expect("cannot read private key");

    let rsa_key = Rsa::private_key_from_der(&private_key).expect("cannot read RSA key");

    let encoded_modulus = base64::encode_config(&(rsa_key.n().to_vec()), base64::URL_SAFE_NO_PAD);
    let encoded_exponent = base64::encode_config(&(rsa_key.e().to_vec()), base64::URL_SAFE_NO_PAD);
    println!("n enc {:?}", encoded_modulus);
    println!("e enc {:?}", encoded_exponent);

    server::new(|| {
        App::new()
            .resource("/", |r| r.f(index))
            .resource("/certs", |r| r.f(certs))
    })
    .bind("127.0.0.1:8088")
    .unwrap()
    .run();
}
