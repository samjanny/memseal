//! # memseal
//!
//! Encrypt and store secrets in memory with password-based key derivation,
//! authenticated encryption, and automatic zeroization.
//!
//! ## Quick Start
//!
//! ```
//! use memseal::Vault;
//!
//! // Create a vault protected by a password (>= 8 bytes)
//! let mut vault = Vault::create(b"my-password-here").unwrap();
//!
//! // Store secrets
//! vault.store("api_key", b"sk-secret-12345").unwrap();
//! vault.store("db_url", b"postgres://user:pass@host/db").unwrap();
//!
//! // Export to bytes (for persistence or transmission)
//! let bytes = vault.export().unwrap();
//!
//! // Reopen with the same password
//! let reopened = Vault::open(b"my-password-here", &bytes).unwrap();
//! assert_eq!(
//!     reopened.retrieve("api_key").unwrap(),
//!     Some(b"sk-secret-12345".to_vec()),
//! );
//! ```
//!
//! ## File Persistence
//!
//! ```no_run
//! use memseal::Vault;
//! use std::path::Path;
//!
//! let mut vault = Vault::create(b"password1234")?;
//! vault.store("secret", b"value")?;
//!
//! // Save to disk
//! vault.save(Path::new("vault.seal"))?;
//!
//! // Load from disk
//! let loaded = Vault::load(Path::new("vault.seal"), b"password1234")?;
//! # Ok::<(), memseal::vault::vault_error::VaultError>(())
//! ```

#![deny(unsafe_code)]

pub mod constants;
pub mod crypto;
pub mod mem;
pub mod vault;

pub use vault::facade::Vault;
pub use vault::vault_error::VaultError;
