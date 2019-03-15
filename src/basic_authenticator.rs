use crate::model::*;
use actix_web::{Form, FromRequest, HttpRequest, Query, Result};
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

impl Authenticator for BasicAuthenticator {
    fn authenticate<A>(&self, req: &HttpRequest<A>) -> Result<String, ()> {
        match Query::<AuthenticationRequest>::extract(req) {
            Ok(params) => {
                if params.username == "ltearno" && params.password == "toto" {
                    let user_uuid = Uuid::new_v4().to_string();
                    println!("welcome user {} {}", params.username, user_uuid);

                    Ok(user_uuid)
                } else {
                    Err(())
                }
            }
            Err(_) => Ok(String::from("anonymous"))//Err(()),
        }
    }
}
