//! Interflow core tunnel primitives.
//!
//! HTTP/2 tunnel primitives shared by the ingress engine and
//! `interflow-mesh`: protocol frames, tunnel connections, the agent
//! registry, ACL, TLS, byte pumps, telemetry, and shared configuration.

#![deny(unsafe_code)]

pub mod config;
pub mod error;
pub mod fault;
pub mod protocol;
pub mod security;
pub mod telemetry;
pub mod tls;
pub mod tunnel;
