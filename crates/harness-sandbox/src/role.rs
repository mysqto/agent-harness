//! Authorization, which is not signing.
//!
//! [`crate::Keyring::verify`] establishes *origin*: these bytes came from this agent. This module
//! answers the separate question of whether that agent may do what it asked. Both are required and
//! neither substitutes for the other — a verified signature that also granted permission would make
//! every key holder an operator, and a role check without a verified origin would authorise
//! whoever claimed the identity.
//!
//! Note what [`authorize`] does *not* take: a [`crate::Verified`]. It cannot be handed a signature
//! verdict, so no caller can accidentally treat one as permission.

use crate::{Error, Result};

/// What a caller is allowed to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// May read.
    Reader,
    /// May read, and write records attributed to itself.
    Writer,
    /// May read, write, and erase.
    Operator,
}

/// What a caller is asking to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Read records.
    Read,
    /// Write a record attributed to `agent`.
    Write {
        /// The identity the record claims. Compared against the caller's own.
        agent: String,
    },
    /// Erase records.
    Erase,
}

/// Decides whether `caller`, holding `role`, may perform `action`.
///
/// A writer may only write records attributed to itself: without that, a compromised agent could
/// write history in another agent's name, and every record after it would be evidence of nothing.
/// Erasure is operator-only because it is the one action that destroys the audit trail.
pub fn authorize(role: Role, caller: &str, action: &Action) -> Result<()> {
    match action {
        Action::Read => Ok(()),
        Action::Write { agent } => {
            if role == Role::Reader {
                return Err(Error::Denied(format!(
                    "{caller} holds reader and asked to write"
                )));
            }
            if agent == caller {
                Ok(())
            } else {
                Err(Error::Denied(format!(
                    "{caller} may not write a record attributed to {agent}"
                )))
            }
        }
        Action::Erase => {
            if role == Role::Operator {
                Ok(())
            } else {
                Err(Error::Denied(format!("{caller} may not erase records")))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Action, Role, authorize};
    use crate::{Keyring, Verified};

    /// A write attributed to `agent`.
    fn write(agent: &str) -> Action {
        Action::Write {
            agent: agent.to_owned(),
        }
    }

    #[test]
    fn a_verified_signature_is_not_permission() {
        // The point of keeping the two apart: the request provably came from alpha, and alpha still
        // may not write, because origin and authorization are different questions.
        let keyring = Keyring::provision("alpha").expect("provision");
        let mac = keyring.sign(b"record");
        assert_eq!(
            keyring.verify(b"record", &mac, 0).expect("verify"),
            Verified::Current
        );

        let denied = authorize(Role::Reader, "alpha", &write("alpha")).expect_err("reader writing");
        assert_eq!(
            denied.to_string(),
            "denied: alpha holds reader and asked to write"
        );
    }

    #[test]
    fn a_writer_may_only_write_as_itself() {
        assert!(authorize(Role::Writer, "alpha", &write("alpha")).is_ok());

        let forged = authorize(Role::Writer, "alpha", &write("beta")).expect_err("attribution");
        assert_eq!(
            forged.to_string(),
            "denied: alpha may not write a record attributed to beta"
        );
    }

    #[test]
    fn an_operator_may_not_write_as_somebody_else_either() {
        // Attribution is not a privilege level. An operator record still says who wrote it.
        assert!(authorize(Role::Operator, "ops", &write("alpha")).is_err());
        assert!(authorize(Role::Operator, "ops", &write("ops")).is_ok());
    }

    #[test]
    fn erasure_is_operator_only() {
        assert!(authorize(Role::Operator, "ops", &Action::Erase).is_ok());
        for role in [Role::Reader, Role::Writer] {
            let denied = authorize(role, "alpha", &Action::Erase).expect_err("erase");
            assert_eq!(denied.to_string(), "denied: alpha may not erase records");
        }
    }

    #[test]
    fn every_role_may_read() {
        for role in [Role::Reader, Role::Writer, Role::Operator] {
            assert!(authorize(role, "alpha", &Action::Read).is_ok(), "{role:?}");
        }
    }
}
