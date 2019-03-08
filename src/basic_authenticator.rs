use crate::model::*;
use uuid::Uuid;

pub struct BasicAuthenticator {}

impl Authenticator for BasicAuthenticator {
    fn authenticate(&self) -> Result<String, ()> {
        let user_uuid = Uuid::new_v4().to_string();
        println!("welcome user {}", user_uuid);

        Ok(user_uuid)
    }
}
