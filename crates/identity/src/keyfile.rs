//! Secret key file persistence (M3 hardening).
//!
//! Files store the raw 32-byte Ed25519 seed. On unix, writes are 0600 and
//! `load_secret_key` refuses files with group/other permission bits, so a
//! leaked world-readable key file fails loudly instead of silently loading.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

use super::{IdentityError, SiteIdentity};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

impl SiteIdentity {
    /// Generate a fresh identity and persist its secret to `path` (0600 on
    /// unix). Returns the identity.
    pub fn generate_key_file(path: &Path) -> Result<Self, IdentityError> {
        let id = Self::generate();
        id.save_secret_key(path)?;
        Ok(id)
    }

    /// Save the 32-byte secret seed. On unix the file is created and enforced
    /// at mode 0600 (owner read/write only).
    pub fn save_secret_key(&self, path: &Path) -> Result<(), IdentityError> {
        let signing = self
            .signing
            .as_ref()
            .ok_or_else(|| IdentityError::KeyFile("no secret key to save".into()))?;
        let mut opts = OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        opts.mode(0o600);
        let mut f = opts
            .open(path)
            .map_err(|e| IdentityError::KeyFile(e.to_string()))?;
        f.write_all(&signing.to_bytes())
            .and_then(|_| f.sync_all())
            .map_err(|e| IdentityError::KeyFile(e.to_string()))?;
        #[cfg(unix)]
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|e| IdentityError::KeyFile(e.to_string()))?;
        Ok(())
    }

    /// Load a 32-byte secret seed. On unix, rejects files whose permission
    /// bits grant group or other access (anything beyond 0600).
    pub fn load_secret_key(path: &Path) -> Result<Self, IdentityError> {
        #[cfg(unix)]
        {
            let meta = fs::metadata(path).map_err(|e| IdentityError::KeyFile(e.to_string()))?;
            let mode = meta.mode() & 0o777;
            if meta.is_file() && mode & 0o077 != 0 {
                return Err(IdentityError::InsecureKeyPerms(mode));
            }
        }
        let mut buf = Vec::new();
        File::open(path)
            .and_then(|mut f| f.read_to_end(&mut buf))
            .map_err(|e| IdentityError::KeyFile(e.to_string()))?;
        Self::from_secret_bytes(&buf).map_err(|e| IdentityError::KeyFile(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn tmp(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("nexus-id-{}-{}", std::process::id(), name))
    }

    #[test]
    fn save_load_roundtrip() {
        let path = tmp("roundtrip.key");
        let id = SiteIdentity::generate();
        id.save_secret_key(&path).unwrap();
        let loaded = SiteIdentity::load_secret_key(&path).unwrap();
        assert_eq!(loaded.site_id(), id.site_id());
        // Loaded key can sign and verify.
        let sr = loaded.sign_record("home", "b3:abc", 9_999_999_999).unwrap();
        loaded.verify_record(&sr, 1).unwrap();
        let _ = std::fs::remove_file(&path);
    }

    #[cfg(unix)]
    #[test]
    fn save_sets_0600_permissions() {
        let path = tmp("perms.key");
        let id = SiteIdentity::generate();
        id.save_secret_key(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let _ = std::fs::remove_file(&path);
    }

    #[cfg(unix)]
    #[test]
    fn load_rejects_world_readable_keyfile() {
        let path = tmp("worldread.key");
        let id = SiteIdentity::generate();
        id.save_secret_key(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            SiteIdentity::load_secret_key(&path),
            Err(IdentityError::InsecureKeyPerms(0o644))
        ));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_rejects_bad_length() {
        let path = tmp("badlen.key");
        std::fs::write(&path, b"way too short").unwrap();
        assert!(SiteIdentity::load_secret_key(&path).is_err());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn generate_key_file_persists() {
        let path = tmp("generate.key");
        let id = SiteIdentity::generate_key_file(&path).unwrap();
        assert_eq!(
            SiteIdentity::load_secret_key(&path).unwrap().site_id(),
            id.site_id()
        );
        let _ = std::fs::remove_file(&path);
    }
}
