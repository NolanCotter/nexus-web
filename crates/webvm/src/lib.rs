//! WebVM: capability-gated sandbox stub.
//!
//! v0 executes no untrusted code. Interactive `App` components declare the
//! capabilities they want; the [`Broker`] grants or denies them against
//! policy. A WASM backend can implement [`Backend`] later.

use nexus_content::Capability;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Sandbox decision failures: denied capabilities, missing backends, limits.
#[derive(Debug, Error)]
pub enum VmError {
    /// Policy refused the capability (carries the reason).
    #[error("denied: {0}")]
    Denied(String),
    /// No backend implements this app (v0 has only [`NullBackend`]).
    #[error("not implemented: {0}")]
    NotImplemented(String),
    /// Granted, but a runtime budget (memory/steps) ran out.
    #[error("resource exhausted: {0}")]
    Exhausted(String),
}

/// A policy grant for one capability, recorded for audit.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Grant {
    /// Capability kind that was granted (e.g. `"storage"`).
    pub capability: String,
    /// Debug rendering of the granted request, for the audit log.
    pub scope: String,
}

/// What the [`Broker`] may grant. Empty `allow` denies everything.
#[derive(Debug, Clone, Default)]
pub struct Policy {
    /// Allowed capability kinds, e.g. ["storage", "notify"].
    /// Empty = deny everything.
    pub allow: Vec<String>,
    pub storage_max_kb: u32,
}

impl Policy {
    /// Maximum lockdown: grant nothing.
    pub fn deny_all() -> Self {
        Self {
            allow: vec![],
            storage_max_kb: 0,
        }
    }

    /// Permissive local-dev policy (storage/network/notify/audio, 1 MiB).
    /// Never use for untrusted content.
    pub fn allow_all_dev() -> Self {
        Self {
            allow: vec![
                "storage".into(),
                "network".into(),
                "notify".into(),
                "audio".into(),
            ],
            storage_max_kb: 1024,
        }
    }
}

fn kind_of(cap: &Capability) -> &'static str {
    match cap {
        Capability::Storage { .. } => "storage",
        Capability::Network { .. } => "network",
        Capability::Notify => "notify",
        Capability::Audio => "audio",
        Capability::Camera => "camera",
        Capability::Microphone => "microphone",
    }
}

/// Capability broker: checks page-requested capabilities against a
/// [`Policy`], records every decision in an audit log.
#[derive(Debug)]
pub struct Broker {
    policy: Policy,
    granted: Vec<Grant>,
    log: Vec<String>,
}

impl Broker {
    /// Broker enforcing `policy`, with empty grant set and audit log.
    pub fn new(policy: Policy) -> Self {
        Self {
            policy,
            granted: vec![],
            log: vec![],
        }
    }

    /// Check one capability against policy. Records an audit entry.
    pub fn check(&mut self, cap: &Capability) -> Result<Grant, VmError> {
        let kind = kind_of(cap).to_string();
        // Storage quota is enforced even when allowed.
        if let Capability::Storage { max_kb } = cap {
            if *max_kb > self.policy.storage_max_kb {
                self.log.push(format!("DENY {kind} quota {max_kb}"));
                return Err(VmError::Denied(format!(
                    "storage quota {max_kb}kb exceeds policy {}kb",
                    self.policy.storage_max_kb
                )));
            }
        }
        if !self.policy.allow.iter().any(|a| a == &kind) {
            self.log.push(format!("DENY {kind}"));
            return Err(VmError::Denied(format!("{kind} not granted")));
        }
        let grant = Grant {
            capability: kind.clone(),
            scope: format!("{cap:?}"),
        };
        self.log.push(format!("ALLOW {kind}"));
        self.granted.push(grant.clone());
        Ok(grant)
    }

    /// Check all capabilities a page requests.
    pub fn check_all(&mut self, caps: &[Capability]) -> Result<Vec<Grant>, VmError> {
        caps.iter().map(|c| self.check(c)).collect()
    }

    /// Drop all grants (audited). In-flight app handles must re-check.
    pub fn revoke_all(&mut self) {
        self.granted.clear();
        self.log.push("REVOKE ALL".to_string());
    }

    /// Ordered ALLOW/DENY/REVOKE audit entries.
    pub fn audit_log(&self) -> &[String] {
        &self.log
    }
}

/// Future execution backend (WASM). Stubbed for v0.
pub trait Backend: Send {
    /// Run `app_id` with `props`, returning its output text.
    fn run(&mut self, app_id: &str, props: &serde_json::Value) -> Result<String, VmError>;
}

/// Backend that implements nothing: every run fails with `NotImplemented`.
#[derive(Debug, Default)]
pub struct NullBackend;

impl Backend for NullBackend {
    fn run(&mut self, app_id: &str, _props: &serde_json::Value) -> Result<String, VmError> {
        Err(VmError::NotImplemented(format!(
            "no backend for app {app_id}"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deny_by_default() {
        let mut b = Broker::new(Policy::deny_all());
        let r = b.check(&Capability::Notify);
        assert!(matches!(r, Err(VmError::Denied(_))));
        assert!(b.audit_log().iter().any(|l| l.starts_with("DENY")));
    }

    #[test]
    fn allows_listed() {
        let mut b = Broker::new(Policy::allow_all_dev());
        assert!(b.check(&Capability::Notify).is_ok());
        assert!(b.check(&Capability::Camera).is_err());
    }

    #[test]
    fn enforces_storage_quota() {
        let mut b = Broker::new(Policy::allow_all_dev());
        assert!(b.check(&Capability::Storage { max_kb: 512 }).is_ok());
        assert!(b.check(&Capability::Storage { max_kb: 99999 }).is_err());
    }

    #[test]
    fn revoke_clears_grants() {
        let mut b = Broker::new(Policy::allow_all_dev());
        b.check(&Capability::Notify).unwrap();
        b.revoke_all();
        assert!(b.audit_log().iter().any(|l| l.contains("REVOKE")));
    }

    #[test]
    fn null_backend_errors() {
        let mut n = NullBackend;
        assert!(n.run("x", &serde_json::json!({})).is_err());
    }
}
