use crate::model::*;
use actix_web::{
    AsyncResponder, FromRequest, HttpMessage, HttpRequest, HttpResponse, Query, Result,
};
use futures::future::{ok, Future};
use serde_urlencoded;
use uuid::Uuid;

#[derive(Clone)]
pub struct BasicAuthenticator {
    db_file_path: String,
}

#[derive(Deserialize)]
pub struct AuthenticationRequest {
    username: String,
    password: String,
}

pub fn new_basic_authenticator() -> BasicAuthenticator {
    BasicAuthenticator {
        db_file_path: String::from("passwd"),
    }
}

#[derive(Deserialize)]
struct FormData {
    username: String,
    password: String,
}

impl Authenticator for BasicAuthenticator {
    fn authenticate<A>(&self, req: &HttpRequest<A>) -> Result<String, ()> {
        if req.content_type().to_lowercase() != "application/x-www-form-urlencoded" {
            return Ok(String::from("nope"));
        }

        let encoding = match req.encoding() {
            Ok(enc) => enc,
            Err(_) => return Err(()),
        };

        let rr = req
            .urlencoded::<FormData>()
            .from_err()
            .and_then(|params| {
                if params.username == "ltearno" && params.password == "toto" {
                    let user_uuid = Uuid::new_v4().to_string();
                    println!("welcome user {} {}", params.username, user_uuid);

                    Ok(user_uuid)
                } else {
                    Err(())
                };

                println!("USERNAME: {:?}", params.username);
                ok(HttpResponse::Ok().into())
            })
            .responder();
    }
}
