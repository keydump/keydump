//! macOS file-based keychain (`kych` / `.keychain-db`) parser.

mod parse;
mod types;

pub use parse::KeychainFile;
pub use types::{PrivateKeyRecord, SymKeyBlob, X509Record};
