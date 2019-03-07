extern crate actix_web;
extern crate jsonwebtoken as jwt;
extern crate openssl;
extern crate uuid;
#[macro_use]
extern crate serde_derive;
extern crate base64;

use actix_web::{
    http::header, http::ContentEncoding, http::Method, middleware, middleware::cors::Cors, server,
    App, HttpRequest, HttpResponse,
};
use jwt::{encode, Algorithm, Header};
use openssl::rsa::Rsa;
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use std::fs::File;
use std::io::Read;
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    jti: String,
    sub: String,
    company: String,
    exp: usize,
    role: String,
    roles: String,
    iss: String,
    aud: String,
    uuid: String,
}

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

#[derive(Debug, Serialize, Deserialize)]
struct ServerDescription {
    keys: Vec<KeyDescription>,
}

fn certs(_req: &HttpRequest) -> HttpResponse {
    let private_key = read_private_key().expect("cannot read key");

    let rsa_key = Rsa::private_key_from_der(&private_key).expect("cannot read RSA key");

    let encoded_modulus = base64::encode_config(&(rsa_key.n().to_vec()), base64::URL_SAFE_NO_PAD);
    let encoded_exponent = base64::encode_config(&(rsa_key.e().to_vec()), base64::URL_SAFE_NO_PAD);

    let key_description = KeyDescription {
        kid: String::from("toto"),
        kty: String::from("RSA"),
        alg: String::from("RSA256"),
        usee: String::from("sig"),
        n: encoded_modulus,
        e: encoded_exponent,
    };

    let body = ServerDescription {
        keys: vec![key_description],
    };

    HttpResponse::Ok()
        .content_encoding(ContentEncoding::Auto)
        .content_type("application/json")
        .json(body)
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
    header.kid = Some("toto".to_owned());
    header.alg = Algorithm::RS256;

    let my_claims = Claims {
        uuid: String::from("foolok"),
        jti: Uuid::new_v4().to_string(),
        sub: String::from("Tto"),
        company: String::from("LTE Consulting"),
        exp: 1552974457,
        role: String::from("{}"),

        roles: String::from("{}"),
        iss: String::from("https://authenticate-dev.idp.private.geoapi-airbusds.com/auth/realms/IDP"),
        aud: String::from("IDP"),
    };

    let private_key = read_private_key().expect("cannot read private key");

    let token = encode(&header, &my_claims, &private_key).expect("cannot generate JWT token");

    HttpResponse::Ok()
        .content_encoding(ContentEncoding::Auto)
        .content_type("application/json")
        .body(token)
}

fn main() {
    let private_key = read_private_key().expect("cannot find/read private key file");
    Rsa::private_key_from_der(&private_key).expect("cannot parse rsa key");

    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    builder
        .set_private_key_file("key.pem", SslFiletype::PEM)
        .expect("cannot read key for tls, create key.pem and cert.pem with this command : openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out cert.pem");
    builder.set_certificate_chain_file("cert.pem").unwrap();

    server::new(|| {
        App::new()
            .middleware(middleware::Logger::default())
            .configure(|app| {
                Cors::for_app(app)
                    .allowed_origin("*")
                    .allowed_methods(vec!["GET", "POST"])
                    .allowed_headers(vec![header::AUTHORIZATION, header::ACCEPT])
                    .allowed_header(header::CONTENT_TYPE)
                    .max_age(3600)
                    .resource("/", |r| r.f(index))
                    .resource("/certs", |r| r.f(certs))
                    .register()
            })
    })
    .bind_ssl("0.0.0.0:8443", builder)
    .unwrap()
    .run();
}
