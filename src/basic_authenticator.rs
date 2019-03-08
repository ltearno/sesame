use crate::model::*;
use actix_web::{Form, Result};
use uuid::Uuid;

pub struct BasicAuthenticator {
    db_file_path: String,
}

#[derive(Deserialize)]
pub struct AuthenticationForm {
    username: String,
    password: String,
}

fn authenticate_form_process(form: Form<AuthenticationForm>) -> Result<String> {
    Ok(format!("Welcome {}!", form.username))
}

impl Authenticator for BasicAuthenticator {
    fn new() -> BasicAuthenticator {
        BasicAuthenticator {
            db_file_path: String::from("passwd"),
        }
    }

    fn authenticate(&self) -> Result<String, ()> {
        let user_uuid = Uuid::new_v4().to_string();
        println!("welcome user {}", user_uuid);

        Ok(user_uuid)
    }
}
