//! Inner-TLS configuration assembly microbenchmark — the anchor for the
//! per-connection/per-stream rustls config path (verifier rebuild, anchor
//! store clone, client-auth material clone) and the post-handshake tenant
//! derivation (`TenantVerifier::derive`).
//!
//! The config cases call the factories repeatedly for the same expected
//! CN: before caching every call is a cold rebuild (the production shape
//! being optimized); with material-embedded caching the same calls become
//! cache hits — the numbers stay directly comparable.
//!
//! Run: `cargo bench -p interflow-core --bench inner_tls_config`

// Benchmark code conventionally uses unwrap/expect.
#![allow(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    missing_docs
)]

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use interflow_certs::{LoadedCa, Validity};
use interflow_core::tls::inner::{
    InnerTlsMaterial, inner_client_config, inner_quic_client_config, inner_server_config_unbound,
};
use interflow_core::tls::tenant::{TenantTrustRoot, TenantVerifier};
use rustls::pki_types::CertificateDer;

/// PEM material on disk for the inner plane: one CA, one client pair.
struct InnerMaterial {
    material: InnerTlsMaterial,
}

fn write(path: &std::path::Path, content: &str) {
    std::fs::write(path, content).unwrap();
}

/// Writes a key file with owner-only permissions (the loader's 0600
/// requirement).
fn write_secret(path: &std::path::Path, content: &str) {
    std::fs::write(path, content).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(path).unwrap().permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(path, perms).unwrap();
    }
}

fn inner_material() -> InnerMaterial {
    let dir = tempfile::tempdir().unwrap();
    let ca = LoadedCa::generate("bench", Validity::ca_default()).unwrap();
    let leaf = ca
        .build_client_cert("bench-agent", Validity::leaf_default())
        .unwrap();
    let ca_path = dir.path().join("ca.pem");
    let cert_path = dir.path().join("client.crt");
    let key_path = dir.path().join("client.key");
    write(&ca_path, ca.cert_pem());
    write(&cert_path, &leaf.cert_pem);
    write_secret(&key_path, &leaf.key_pem);
    // Leak the tempdir root: the material is fully loaded into memory, the
    // files only need to outlive `from_paths` (kept alive anyway — the
    // bench process is short-lived).
    std::mem::forget(dir);
    let material = InnerTlsMaterial::from_paths(
        &[ca_path.to_str().unwrap()],
        cert_path.to_str().unwrap(),
        key_path.to_str().unwrap(),
    )
    .unwrap();
    InnerMaterial { material }
}

fn bench_inner_configs(c: &mut Criterion) {
    let inner = inner_material();

    let mut group = c.benchmark_group("inner_tls_config");
    group.bench_function("inner_client_config", |b| {
        b.iter(|| {
            let config =
                inner_client_config(std::hint::black_box(&inner.material), "peer-agent").unwrap();
            std::hint::black_box(config);
        });
    });
    group.bench_function("inner_quic_client_config", |b| {
        b.iter(|| {
            let config =
                inner_quic_client_config(std::hint::black_box(&inner.material), "peer-agent")
                    .unwrap();
            std::hint::black_box(config);
        });
    });
    group.bench_function("inner_server_config_unbound", |b| {
        b.iter(|| {
            let config =
                inner_server_config_unbound(std::hint::black_box(&inner.material)).unwrap();
            std::hint::black_box(config);
        });
    });
    group.finish();
}

/// N tenant trust roots + one client chain issued by the CA at `issuer`
/// (0-based). The chain verifies against exactly one root.
fn tenant_setup(tenants: usize, issuer: usize) -> (TenantVerifier, Vec<CertificateDer<'static>>) {
    let mut roots = Vec::new();
    let mut issuer_ca = None;
    for i in 0..tenants {
        let ca = LoadedCa::generate(&format!("tenant-{i}"), Validity::ca_default()).unwrap();
        let root =
            TenantTrustRoot::from_pem(&format!("tenant-{i}"), false, ca.cert_pem().as_bytes())
                .unwrap();
        roots.push(root);
        if i == issuer {
            issuer_ca = Some(ca);
        }
    }
    let verifier = TenantVerifier::new(&roots).unwrap();
    let leaf = issuer_ca
        .unwrap()
        .build_client_cert("bench-agent", Validity::leaf_default())
        .unwrap();
    let chain: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut leaf.cert_pem.as_bytes())
        .collect::<Result<_, _>>()
        .unwrap();
    (verifier, chain)
}

fn bench_tenant_derive(c: &mut Criterion) {
    let mut group = c.benchmark_group("tenant_derive");
    for (tenants, issuer, label) in [
        (1usize, 0usize, "1 tenant"),
        (4, 0, "4 tenants (leaf of first)"),
        (4, 3, "4 tenants (leaf of last)"),
    ] {
        let (verifier, chain) = tenant_setup(tenants, issuer);
        group.bench_function(BenchmarkId::from_parameter(label), |b| {
            b.iter(|| {
                let identity = verifier.derive(std::hint::black_box(&chain));
                std::hint::black_box(identity);
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_inner_configs, bench_tenant_derive);
criterion_main!(benches);
