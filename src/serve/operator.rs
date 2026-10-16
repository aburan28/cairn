//! Local operator controls need a credential even on loopback: a reverse
//! proxy can originate a loopback connection without forwarding any headers.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

pub(super) const ENV: &str = "CAIRN_SWARM_OPERATOR_TOKEN";
const DOMAIN: &[u8] = b"cairn/swarm/operator-token/v1";

pub(super) struct Token([u8; 32]);

impl Token {
    pub(super) fn from_env() -> Result<Option<Self>, String> {
        match std::env::var(ENV) {
            Ok(value) => Self::parse(&value).map(Some),
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(_) => Err(format!("{ENV} must contain 64 hexadecimal characters")),
        }
    }

    pub(super) fn parse(value: &str) -> Result<Self, String> {
        let raw = decode(value).ok_or_else(|| {
            format!("{ENV} must be a random 32-byte token encoded as 64 hexadecimal characters")
        })?;
        let mut mac = Hmac::<Sha256>::new_from_slice(DOMAIN).expect("HMAC accepts any key length");
        mac.update(&raw);
        // Store a verifier rather than the credential. HMAC's verify_slice
        // compares tags in constant time; ordinary string equality does not.
        Ok(Self(mac.finalize().into_bytes().into()))
    }

    fn accepts(&self, authorization: &str) -> bool {
        let Some(value) = authorization.strip_prefix("Bearer ").and_then(decode) else {
            return false;
        };
        let mut mac = Hmac::<Sha256>::new_from_slice(DOMAIN).expect("HMAC accepts any key length");
        mac.update(&value);
        mac.verify_slice(&self.0).is_ok()
    }
}

fn decode(value: &str) -> Option<Vec<u8>> {
    let value = value.trim();
    if value.len() != 64 {
        return None;
    }
    crate::hex::decode(value)
}

pub(super) fn authorized(
    token: &Result<Option<Token>, String>,
    authorization: Option<&str>,
) -> bool {
    match (token, authorization) {
        (Ok(Some(token)), Some(authorization)) => token.accepts(authorization),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn controls_are_disabled_without_a_token_and_require_the_exact_credential() {
        let secret = "7a".repeat(32);
        let token = Ok(Some(Token::parse(&secret).unwrap()));
        assert!(authorized(&token, Some(&format!("Bearer {secret}"))));
        for bad in [
            "",
            "Bearer ",
            "Basic abc",
            &format!("Bearer {}", "7b".repeat(32)),
            &format!("Bearer {secret} extra"),
        ] {
            assert!(!authorized(&token, Some(bad)));
        }
        assert!(!authorized(&token, None));
        assert!(!authorized(&Ok(None), Some(&format!("Bearer {secret}"))));
        for bad in ["", "abc", &"z".repeat(64)] {
            assert!(Token::parse(bad).is_err());
        }
    }
}
