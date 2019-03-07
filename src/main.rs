extern crate actix_web;
extern crate jsonwebtoken as jwt;
extern crate openssl;
extern crate uuid;
#[macro_use]
extern crate serde_derive;
extern crate base64;

mod basic_authenticator;
mod config;
mod model;

use config::*;
use model::*;

use actix_web::{
    http::header, http::ContentEncoding, http::StatusCode, middleware, middleware::cors::Cors,
    server, App, HttpRequest, HttpResponse,
};
use jwt::{encode, Algorithm, Header};
use openssl::rsa::Rsa;
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use uuid::Uuid;

fn certs(_req: &HttpRequest) -> HttpResponse {
    let private_key = read_jwt_private_key().expect("cannot read key");

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

fn index(_req: &HttpRequest) -> HttpResponse {
    let mut header = Header::default();
    header.kid = Some("toto".to_owned());
    header.alg = Algorithm::RS256;

    let authenticator = basic_authenticator::BasicAuthenticator {};

    if let Err(_) = authenticator.authenticate() {
        return HttpResponse::new(StatusCode::UNAUTHORIZED);
    }

    let my_claims = Claims {
        uuid: String::from("foolok"),
        jti: Uuid::new_v4().to_string(),
        sub: String::from("Tto"),
        company: String::from("LTE Consulting"),
        exp: 1552974457,
        role: String::from("{}"),

        roles: String::from("{}"),
        iss: String::from(
            "https://authenticate-dev.idp.private.geoapi-airbusds.com/auth/realms/IDP",
        ),
        aud: String::from("IDP"),
    };

    let private_key = read_jwt_private_key().expect("cannot read private key");

    let token = encode(&header, &my_claims, &private_key).expect("cannot generate JWT token");

    HttpResponse::Ok()
        .content_encoding(ContentEncoding::Auto)
        .content_type("application/json")
        .body(token)
}

fn main() {
    check_configuration().expect("configuration error");

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
