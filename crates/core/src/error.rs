//! Interflow error types.

use thiserror::Error;

/// Carrier for the root-cause chain of semantic errors.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// The Interflow error type.
///
/// Two kinds of variants:
/// - **Typed source**: underlying errors converted via `#[from]`, with the
///   `source()` chain fully preserved;
/// - **Semantic variants** ([`InterflowError::Config`] etc.): carry a
///   human-readable `message` and an optional `#[source]` root cause. The
///   semantic category decides caller behavior — the supervisor treats only
///   [`InterflowError::Config`] as unrecoverable (see
///   [`InterflowError::is_fatal`]); everything else goes into backoff retry.
///
/// Build semantic variants with the same-named lowercase constructors
/// ([`InterflowError::config`] etc.); when wrapping an underlying error use
/// `.with_source(e)` to preserve the root-cause chain instead of flattening
/// `{e}` into the message.
#[derive(Error, Debug)]
pub enum InterflowError {
    /// IO error.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// HTTP construction error.
    #[error("HTTP error: {0}")]
    Http(#[from] http::Error),

    /// Hyper runtime error.
    #[error("Hyper error: {0}")]
    Hyper(#[from] hyper::Error),

    /// TOML parse error.
    #[error("TOML parse error: {0}")]
    Serialization(#[from] toml::de::Error),

    /// JSON serialization / deserialization error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Background task join error.
    #[error("task join error: {0}")]
    JoinError(#[from] tokio::task::JoinError),

    /// Configuration error (load / validate / assembly failure). Unrecoverable.
    #[error("configuration error: {message}")]
    Config {
        /// Human-readable description.
        message: String,
        /// Root cause, if any.
        #[source]
        source: Option<BoxError>,
    },

    /// Connection error (failure to establish / maintain the connection to the hub). Retryable.
    #[error("connection error: {message}")]
    Connection {
        /// Human-readable description.
        message: String,
        /// Root cause, if any.
        #[source]
        source: Option<BoxError>,
    },

    /// Protocol error (peer behavior violating protocol rules).
    #[error("protocol error: {message}")]
    Protocol {
        /// Human-readable description.
        message: String,
        /// Root cause, if any.
        #[source]
        source: Option<BoxError>,
    },

    /// Stream error (single-stream operation failure; does not escalate to a connection-level failure).
    #[error("stream error: {message}")]
    Stream {
        /// Human-readable description.
        message: String,
        /// Root cause, if any.
        #[source]
        source: Option<BoxError>,
    },

    /// Registration error (the hub rejected the agent's registration).
    #[error("registration error: {message}")]
    Registration {
        /// Human-readable description.
        message: String,
        /// Root cause, if any.
        #[source]
        source: Option<BoxError>,
    },
}

impl InterflowError {
    /// Builds a configuration error.
    pub fn config(message: impl Into<String>) -> Self {
        Self::Config {
            message: message.into(),
            source: None,
        }
    }

    /// Builds a connection error.
    pub fn connection(message: impl Into<String>) -> Self {
        Self::Connection {
            message: message.into(),
            source: None,
        }
    }

    /// Builds a protocol error.
    pub fn protocol(message: impl Into<String>) -> Self {
        Self::Protocol {
            message: message.into(),
            source: None,
        }
    }

    /// Builds a stream error.
    pub fn stream(message: impl Into<String>) -> Self {
        Self::Stream {
            message: message.into(),
            source: None,
        }
    }

    /// Builds a registration error.
    pub fn registration(message: impl Into<String>) -> Self {
        Self::Registration {
            message: message.into(),
            source: None,
        }
    }

    /// Attaches a root cause: preserves the `source()` chain so logs can expand the full causality.
    ///
    /// Only semantic variants accept a root cause; typed-source variants
    /// already carry one and are returned as-is.
    #[must_use]
    pub fn with_source(self, source: impl Into<BoxError>) -> Self {
        let source = Some(source.into());
        match self {
            Self::Config { message, .. } => Self::Config { message, source },
            Self::Connection { message, .. } => Self::Connection { message, source },
            Self::Protocol { message, .. } => Self::Protocol { message, source },
            Self::Stream { message, .. } => Self::Stream { message, source },
            Self::Registration { message, .. } => Self::Registration { message, source },
            other => other,
        }
    }

    /// Whether this is an unrecoverable error (the supervisor decides not to retry and exits directly based on this).
    pub const fn is_fatal(&self) -> bool {
        matches!(self, Self::Config { .. })
    }
}

/// The common Interflow Result alias.
pub type Result<T> = std::result::Result<T, InterflowError>;
