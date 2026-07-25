//! Library surface for `kd` (keydump).
//!
//! The CLI binary is a thin wrapper; integration tests and future tooling import
//! crypto / keychain / unlock / export from here.

pub mod cli;
pub mod crypto;
pub mod error;
pub mod export;
pub mod keychain;
pub mod unlock;
