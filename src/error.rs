use thiserror::Error;

#[derive(Debug, Error)]
pub enum KdError {
    #[error("invalid keychain: {0}")]
    InvalidKeychain(String),

    #[error("wrong password or master key (DB blob decrypt failed)")]
    WrongCredential,

    #[error("table 0x{0:X} not found in keychain")]
    TableMissing(u32),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("unlock via securityd failed: {0}")]
    Securityd(String),

    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Msg(String),

    #[error("openssl: {0}")]
    Openssl(String),
}

impl From<openssl::error::ErrorStack> for KdError {
    fn from(e: openssl::error::ErrorStack) -> Self {
        KdError::Openssl(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, KdError>;
