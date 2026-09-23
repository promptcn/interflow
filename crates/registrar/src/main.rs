//! `interflow-registrar` — enrollment administration and the independent
//! short-lived credential service.

use clap::{Parser, Subcommand};
use interflow_identity::PrincipalKind;
use interflow_identity::issuance::{LeafTtl, MIN_LEAF_TTL_SECONDS};
use interflow_registrar::server::{ServeOptions, serve};
use interflow_registrar::{
    ControlEndpoints, EnrollmentCodes, FileKeySource, KeySource, RegistrarService, RotationState,
};
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "interflow-registrar", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a one-time enrollment code (operator machine).
    Code {
        #[arg(long, default_value = "issuer")]
        issuer: PathBuf,
        #[arg(long)]
        realm: String,
        #[arg(long)]
        kind: String,
        #[arg(long)]
        node: String,
        #[arg(long)]
        workspace: Option<String>,
    },
    /// Consume a code locally and sign a CSR (testing).
    Enroll {
        #[arg(long, default_value = "issuer")]
        issuer: PathBuf,
        #[arg(long)]
        code: String,
        #[arg(long)]
        csr: PathBuf,
    },
    /// Issue the registrar endpoint's TLS certificate.
    Certificate {
        #[arg(long, default_value = "issuer")]
        issuer: PathBuf,
        #[arg(long)]
        realm: String,
        #[arg(long, default_value = "registrar")]
        node: String,
        #[arg(long)]
        endpoint: String,
        #[arg(long, default_value = "registrar.crt")]
        out_cert: PathBuf,
        #[arg(long, default_value = "registrar.key")]
        out_key: PathBuf,
    },
    /// Run the independent mTLS registrar service.
    Serve {
        #[arg(long, default_value = "issuer")]
        issuer: PathBuf,
        #[arg(long, default_value = "127.0.0.1:18666")]
        listen: SocketAddr,
        /// Public HTTPS endpoint clients use to reach this registrar.
        #[arg(long)]
        endpoint: String,
        #[arg(long, default_value = "registrar.crt")]
        tls_cert: PathBuf,
        #[arg(long, default_value = "registrar.key")]
        tls_key: PathBuf,
        #[arg(long, default_value = "24h", value_parser = parse_leaf_ttl)]
        leaf_ttl: LeafTtl,
        /// The deployment control endpoint; constrains renewed control SANs.
        #[arg(long)]
        control_endpoint: String,
        /// Site-to-site hub dial address (`<node>=<endpoint>`), constraining
        /// that hub node's renewed server-credential SAN. Repeatable.
        #[arg(long = "hub-endpoint", value_name = "NODE=ENDPOINT", value_parser = parse_hub_endpoint)]
        hub_endpoints: Vec<(String, String)>,
    },
}

/// Clap value parser: `<node>=<endpoint>` pairs for `--hub-endpoint`.
fn parse_hub_endpoint(entry: &str) -> Result<(String, String), String> {
    let (node, endpoint) = entry
        .split_once('=')
        .ok_or_else(|| format!("invalid --hub-endpoint {entry:?}: expected <node>=<endpoint>"))?;
    if node.is_empty() || endpoint.is_empty() {
        return Err(format!(
            "invalid --hub-endpoint {entry:?}: empty node or endpoint"
        ));
    }
    Ok((node.to_owned(), endpoint.to_owned()))
}

/// Clap value parser: `--leaf-ttl` with the production lower bound applied.
fn parse_leaf_ttl(text: &str) -> Result<LeafTtl, String> {
    let seconds = humantime::parse_duration(text)
        .map_err(|e| format!("invalid --leaf-ttl {text:?}: {e}"))?
        .as_secs();
    if seconds < MIN_LEAF_TTL_SECONDS {
        return Err("leaf TTL must be at least 1h in production".to_owned());
    }
    LeafTtl::from_seconds(i64::try_from(seconds.min(24 * 60 * 60)).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.command {
        Command::Code {
            issuer,
            realm,
            kind,
            node,
            workspace,
        } => {
            let kind = match kind.as_str() {
                "agent" => PrincipalKind::Agent,
                "ingress" => PrincipalKind::Ingress,
                other => return Err(format!("unknown kind {other:?} (agent|ingress)").into()),
            };
            let _source = FileKeySource::open(&issuer)?;
            let codes = EnrollmentCodes::open(issuer.join("enrollments.json"))?;
            let code = codes.create(&realm, kind, workspace.as_deref(), &node)?;
            println!("{}", serde_json::to_string_pretty(&code)?);
            Ok(())
        }
        Command::Enroll { issuer, code, csr } => {
            let source = FileKeySource::open(&issuer)?;
            let enrollments = EnrollmentCodes::open(issuer.join("enrollments.json"))?;
            let rotations = RotationState::open(issuer.join("rotation-state.json"))?;
            let service = RegistrarService::new(
                source,
                enrollments,
                rotations,
                LeafTtl::default_ttl(),
                ControlEndpoints::new("https://control.invalid"),
            );
            let csr_pem = std::fs::read_to_string(csr)?;
            let credential = service.enroll(&code, &csr_pem)?;
            println!("{}", serde_json::to_string_pretty(&credential)?);
            Ok(())
        }
        Command::Certificate {
            issuer,
            realm,
            node,
            endpoint,
            out_cert,
            out_key,
        } => {
            let source = FileKeySource::open(&issuer)?;
            let material = source
                .issuer_store()?
                .issue_control_endpoint(&realm, &node, &endpoint)?;
            std::fs::write(&out_cert, material.chain_pem)?;
            std::fs::write(&out_key, material.key_pem)?;
            println!(
                "registrar TLS certificate written to {}",
                out_cert.display()
            );
            Ok(())
        }
        Command::Serve {
            issuer,
            listen,
            endpoint,
            tls_cert,
            tls_key,
            leaf_ttl,
            control_endpoint,
            hub_endpoints,
        } => {
            serve(
                issuer,
                ServeOptions {
                    listen,
                    public_endpoint: endpoint,
                    tls_cert,
                    tls_key,
                    ttl: leaf_ttl,
                    control_endpoint,
                    hub_endpoints: hub_endpoints.into_iter().collect(),
                },
            )
            .await?;
            Ok(())
        }
    }
}
