extern crate actix_web;
extern crate futures;
extern crate jsonwebtoken as jwt;
extern crate openssl;
extern crate uuid;
#[macro_use]
extern crate serde_derive;
extern crate base64;
extern crate serde_json;
extern crate serde_urlencoded;

use futures::future::{ok, Future};
mod config;
mod model;
use std::time::SystemTime;

use config::*;
use model::*;

use actix_web::{
    http, http::header, http::ContentEncoding, middleware, middleware::cors::Cors, server, App,
    AsyncResponder, HttpMessage, HttpRequest, HttpResponse, Responder,
};
use jwt::{encode, Algorithm, Header};
use openssl::rsa::Rsa;
use openssl::sha::Sha512;
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use uuid::Uuid;

#[derive(Clone)]
struct ServerState {
    configuration: ConfigurationFile,
    private_key: Vec<u8>,
    private_key_modulus: String,
    private_key_exponent: String,
    private_key_kid: String,
}

fn certs(_req: &HttpRequest<ServerState>) -> HttpResponse {
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

#[derive(Deserialize)]
struct FormData {
    username: String,
    password: String,
    redirect_uri: String,
}

fn generate_jwt_token(
    user_uuid: &str,
    kid: &str,
    company: &str,
    issuer_url: &str,
    private_key: &Vec<u8>,
    token_duration_secs: u64,
) -> String {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("cannot measure time !")
        .as_secs();
    let expiration_time = now + token_duration_secs;

    let mut header = Header::default();
    header.kid = Some(kid.to_owned());
    header.alg = Algorithm::RS256;

    let my_claims = Claims {
        uuid: user_uuid.to_owned(),
        jti: Uuid::new_v4().to_string(),
        sub: String::from("Tto"),
        company: company.to_owned(),
        exp: expiration_time as usize,
        role: String::from("{}"),
        roles: String::from("{}"),
        iss: issuer_url.to_owned(),
        aud: String::from("IDP"),
    };

    encode(&header, &my_claims, private_key).expect("cannot generate JWT token")
}

fn login_form(
    req: &HttpRequest<ServerState>,
) -> Box<Future<Item = HttpResponse, Error = actix_web::Error>> {
    let state = req.state().clone();

    req.urlencoded::<FormData>()
        .then(move |r| match r {
            Err(_) => ok(HttpResponse::MovedPermanently()
                .header("Location", "")
                .finish()
                .into()),
            Ok(form) => {
                if form.username == state.configuration.username
                    && form.password == state.configuration.password
                {
                    let user_uuid = String::from(form.username);
                    let token = generate_jwt_token(
                        &user_uuid,
                        &state.private_key_kid,
                        &state.configuration.company,
                        &state.configuration.issuer_url,
                        &state.private_key,
                        state.configuration.token_duration_secs,
                    );

                    println!("generated user {} jwt token {}", user_uuid, token);

                    ok(HttpResponse::MovedPermanently()
                        .header("Location", form.redirect_uri + "#access_token=" + &token)
                        .finish()
                        .into())
                } else {
                    ok(HttpResponse::MovedPermanently()
                        .header("Location", "")
                        .finish()
                        .into())
                }
            }
        })
        .responder()
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

    let mut hasher = Sha512::new();
    hasher.update(&private_key);
    let private_key_kid = hasher.finish();

    let mut hasher = Sha512::new();
    hasher.update(&private_key_kid);
    let private_key_kid = hasher.finish();

    let mut hasher = Sha512::new();
    hasher.update(&private_key_kid);
    let private_key_kid = hasher.finish();

    let private_key_kid = base64::encode_config(&(private_key_kid.to_vec()), base64::STANDARD);

    check_configuration().expect("configuration error");

    println!("using KID {}", private_key_kid);

    let server_state = ServerState {
        configuration,
        private_key,
        private_key_modulus,
        private_key_exponent,
        private_key_kid,
    };

    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    builder
        .set_private_key_file("key.pem", SslFiletype::PEM)
        .expect("cannot read key for tls, create key.pem and cert.pem with this command : openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out cert.pem");
    builder.set_certificate_chain_file("cert.pem").unwrap();

    let server_state_clone = server_state.clone();
    server::new(move || {
        App::with_state(server_state.clone())
            .middleware(middleware::Logger::default())
            .configure(|app| {
                Cors::for_app(app)
                    //.allowed_origin("*")
                    .allowed_methods(vec!["GET", "POST"])
                    .allowed_headers(vec![header::AUTHORIZATION, header::ACCEPT])
                    .allowed_header(header::CONTENT_TYPE)
                    .max_age(3600)
                    .resource("/login", |r| {
                        r.method(http::Method::GET)
                            .f(|r| actix_web::fs::NamedFile::open("login.html").respond_to(r));
                        r.method(http::Method::POST).f(login_form);
                    })
                    .resource("/certs", |r| r.method(http::Method::GET).f(certs))
                    .register()
            })
    })
    .bind_ssl(&server_state_clone.configuration.listening_address, builder)
    .unwrap()
    .run();
}
