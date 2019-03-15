#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub jti: String,
    pub sub: String,
    pub company: String,
    pub exp: usize,
    pub role: String,
    pub roles: String,
    pub iss: String,
    pub aud: String,
    pub uuid: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyDescription {
    pub kid: String,
    pub kty: String,
    pub alg: String,
    #[serde(rename = "use")]
    pub usee: String,
    pub n: String,
    pub e: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerDescription {
    pub keys: Vec<KeyDescription>,
}
