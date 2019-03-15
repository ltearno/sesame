extern crate actix_web;
extern crate jsonwebtoken as jwt;
extern crate openssl;
extern crate uuid;
#[macro_use]
extern crate serde_derive;
extern crate base64;
extern crate serde_json;

mod basic_authenticator;
mod config;
mod model;

use config::*;
use model::*;

use actix_web::FromRequest;
use actix_web::{
    http, http::header, http::ContentEncoding, http::StatusCode, middleware,
    middleware::cors::Cors, server, App, HttpRequest, HttpResponse, Path,
};
use jwt::{encode, Algorithm, Header};
use openssl::rsa::Rsa;
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use uuid::Uuid;

#[derive(Clone)]
struct ServerState<A: Authenticator> {
    configuration: ConfigurationFile,
    private_key: Vec<u8>,
    private_key_modulus: String,
    private_key_exponent: String,
    private_key_kid: String,
    authenticator: Box<A>,
}

fn certs<A: Authenticator>(_req: &HttpRequest<ServerState<A>>) -> HttpResponse {
    let key_description = KeyDescription {
        kty: String::from("RSA"),
        alg: String::from("RSA256"),
        usee: String::from("sig"),
        kid: _req.state().private_key_kid.to_owned(),
        n: _req.state().private_key_modulus.to_owned(),
        e: _req.state().private_key_exponent.to_owned(),
    };

    HttpResponse::Ok()
        .content_encoding(ContentEncoding::Auto)
        .content_type("application/json")
        .json(ServerDescription {
            keys: vec![key_description],
        })
}

fn index<A: Authenticator>(_req: &HttpRequest<ServerState<A>>) -> HttpResponse {
    let mut header = Header::default();
    header.kid = Some(_req.state().private_key_kid.to_owned());
    header.alg = Algorithm::RS256;

    let authenticator = &_req.state().authenticator;

    let user_uuid = match authenticator.authenticate(_req) {
        Err(_) => return HttpResponse::new(StatusCode::UNAUTHORIZED),
        Ok(user_uuid) => user_uuid,
    };

    let my_claims = Claims {
        uuid: user_uuid,
        jti: Uuid::new_v4().to_string(),
        sub: String::from("Tto"),
        company: _req.state().configuration.company.to_owned(),
        exp: 1552974457,
        role: String::from("{}"),
        roles: String::from("{}"),
        iss: _req.state().configuration.issuer_url.to_owned(),
        aud: String::from("IDP"),
    };

    let token =
        encode(&header, &my_claims, &_req.state().private_key).expect("cannot generate JWT token");

    HttpResponse::Ok()
        .content_encoding(ContentEncoding::Auto)
        .content_type("application/json")
        .body(token)
}

fn main() {
    let configuration = read_configuration().expect("error reading configuration");
    println!("{:?}", configuration);

    let private_key = read_jwt_private_key().expect("cannot read private key");

    let rsa_key = Rsa::private_key_from_der(&private_key).expect("cannot read RSA key");

    let private_key_modulus =
        base64::encode_config(&(rsa_key.n().to_vec()), base64::URL_SAFE_NO_PAD);
    let private_key_exponent =
        base64::encode_config(&(rsa_key.e().to_vec()), base64::URL_SAFE_NO_PAD);

    check_configuration().expect("configuration error");

    let server_state = ServerState {
        configuration,
        private_key,
        private_key_modulus,
        private_key_exponent,
        private_key_kid: Uuid::new_v4().to_string(),
        authenticator: Box::from(basic_authenticator::new_basic_authenticator()),
    };

    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    builder
        .set_private_key_file("key.pem", SslFiletype::PEM)
        .expect("cannot read key for tls, create key.pem and cert.pem with this command : openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out cert.pem");
    builder.set_certificate_chain_file("cert.pem").unwrap();

    server::new(move || {
        App::with_state(server_state.clone())
            .middleware(middleware::Logger::default())
            .configure(|app| {
                Cors::for_app(app)
                    .allowed_origin("*")
                    .allowed_methods(vec!["GET", "POST"])
                    .allowed_headers(vec![header::AUTHORIZATION, header::ACCEPT])
                    .allowed_header(header::CONTENT_TYPE)
                    .max_age(3600)
                    .resource("/", |r| r.f(index))
                    .resource("/certs", |r| r.method(http::Method::GET).f(certs))
                    .register()
            })
    })
    .bind_ssl("127.0.0.1:8443", builder)
    .unwrap()
    .run();
}
