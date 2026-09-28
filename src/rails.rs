//! Settlement rails are a branch point, not a currency.
//!
//! A log declares zero or more rails in genesis. With none declared, a deposit
//! is refused. That is the whole of "batteries not included": the type exists
//! so a deployment can name a rail later, and the default build has nothing
//! to call.

/// Why external value did not enter the log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RailError {
    /// No rail was declared, so there is nobody who can attest a deposit.
    NoRailDeclared,
}

impl std::fmt::Display for RailError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RailError::NoRailDeclared => f.write_str(
                "no settlement rail is declared on this log; deposits are refused \
                 until genesis names one",
            ),
        }
    }
}

/// A deposit against `rails`. Empty means the default build: refuse.
pub fn deposit(rails: &[String], external_ref: &str, units: u64) -> Result<(), RailError> {
    let _ = (external_ref, units);
    if rails.is_empty() {
        return Err(RailError::NoRailDeclared);
    }
    // A named rail still needs an attestor the log already trusts. This
    // function does not credit a balance; the audit is what would, once a
    // rail record exists in both implementations.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_log_refuses_a_deposit() {
        let err = deposit(&[], "tx-1", 10).unwrap_err();
        assert_eq!(err, RailError::NoRailDeclared);
        assert!(deposit(&["test-rail".into()], "tx-1", 10).is_ok());
    }
}
