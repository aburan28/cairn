//! Operator-selected network defaults, independent of the replicated log.
//!
//! A private installation must not contact public discovery infrastructure just
//! because a binary was built with a public seed list. This profile is not an
//! egress firewall: explicitly configured peers, DNS and executable jobs remain
//! the operator's responsibility.

use crate::fleet::PeerPolicy;
use crate::p2p::seeds::Source;

pub const NETWORK_ENV: &str = "CAIRN_NETWORK";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    Public,
    Private,
}

impl Profile {
    pub fn parse(setting: Option<&str>) -> Result<Self, String> {
        match setting.map(str::trim) {
            None | Some("") => Ok(Self::Public),
            Some(value) if value.eq_ignore_ascii_case("public") => Ok(Self::Public),
            Some(value) if value.eq_ignore_ascii_case("private") => Ok(Self::Private),
            Some(value) => Err(format!(
                "{NETWORK_ENV}={value:?}: expected public or private"
            )),
        }
    }

    pub fn from_env() -> Result<Self, String> {
        let profile = match std::env::var(NETWORK_ENV) {
            Ok(value) => Self::parse(Some(&value))?,
            Err(std::env::VarError::NotPresent) => Self::Public,
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err(format!("{NETWORK_ENV} is not valid Unicode"));
            }
        };
        profile.validate_auth(
            std::env::var(crate::google_auth::CLIENT_ID_ENV)
                .ok()
                .as_deref(),
        )?;
        Ok(profile)
    }

    pub fn is_private(self) -> bool {
        self == Self::Private
    }

    /// Refuse an external sign-in configuration rather than silently removing it.
    pub fn validate_auth(self, google_client: Option<&str>) -> Result<(), String> {
        if self.is_private() && google_client.is_some_and(|value| !value.trim().is_empty()) {
            return Err(format!(
                "{NETWORK_ENV}=private conflicts with {}; Google sign-in needs external \
                 endpoints. Remove that setting explicitly; fleet member authentication is unchanged",
                crate::google_auth::CLIENT_ID_ENV
            ));
        }
        Ok(())
    }

    pub fn seeds(self, setting: Option<&str>) -> Source {
        match Source::from_setting(setting) {
            Source::BuiltIn if self.is_private() => Source::Off,
            source => source,
        }
    }

    /// A private leader with no bootstrap peers is an intentionally isolated node.
    pub fn peers(self, setting: Option<&str>) -> Result<PeerPolicy, String> {
        let setting = match setting {
            None | Some("") if self.is_private() => "bootstrap",
            Some(value) if value.trim().is_empty() && self.is_private() => "bootstrap",
            Some(value) => value,
            None => "open",
        };
        let policy = PeerPolicy::parse(setting).map_err(|error| error.to_string())?;
        if self.is_private() && policy.is_open() {
            return Err(format!(
                "{NETWORK_ENV}=private refuses CAIRN_PEERS=open; use bootstrap or explicit peer ids"
            ));
        }
        Ok(policy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_profiles_fail_closed() {
        for value in ["privte", "off", "airgap", "0"] {
            assert!(Profile::parse(Some(value)).is_err());
        }
        assert_eq!(Profile::parse(None).unwrap(), Profile::Public);
        assert_eq!(Profile::parse(Some(" PRIVATE ")).unwrap(), Profile::Private);
    }

    #[test]
    fn private_discovery_is_explicit_and_peers_are_restricted() {
        assert_eq!(Profile::Private.seeds(None), Source::Off);
        assert_eq!(Profile::Private.seeds(Some(" ")), Source::Off);
        assert_eq!(Profile::Public.seeds(None), Source::BuiltIn);
        assert_eq!(
            Profile::Private.seeds(Some("/internal/seeds.json")),
            Source::File("/internal/seeds.json".into())
        );
        assert!(Profile::Private.peers(Some("open")).is_err());
        assert!(Profile::Private.peers(Some("garbage")).is_err());
        assert!(matches!(
            Profile::Private.peers(None).unwrap(),
            PeerPolicy::Allow { bootstrap: true, ids } if ids.is_empty()
        ));
        assert!(Profile::Public.peers(None).unwrap().is_open());
    }

    #[test]
    fn external_auth_is_refused_instead_of_silently_disabled() {
        assert!(Profile::Private.validate_auth(Some("client-id")).is_err());
        assert!(Profile::Private.validate_auth(None).is_ok());
        assert!(Profile::Public.validate_auth(Some("client-id")).is_ok());
    }
}
