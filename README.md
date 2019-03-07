# Sesame

This is the very first beginning of a cloud native open id connect identity provider (and broker).

## First iteration

- everything in configuration file (no admin ui or things like that)
- little web server to serve a login/password UI
- no database, all users are stored in memory from configuration

## Next iterations

- will do brokering with other SAML and OIDC identity providers
- will federate other user data sources (ldap, ...)
- key rotation
- hardened
- provide metrics (through Prometheus or something like that)
- ...

##

Generate a RSA 2018 bit key

    openssl genrsa -out private_rsa_key.pem 2048

Convert to DER encoding

    openssl rsa -in private_rsa_key.pem -outform DER -out private_rsa_key.der

Generate the corresponding public key

    openssl rsa -in private_rsa_key.der -inform DER -RSAPublicKey_out -outform DER -out public_key.der