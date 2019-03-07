use crate::model::*;

pub struct BasicAuthenticator {}

impl Authenticator for BasicAuthenticator {
    fn authenticate(&self) -> Result<(), ()> {
        Ok(())
    }
}
