//! e2e: control API rule persistence (plan A) — the file is the source of truth.
//!
//! Covers:
//! - After `POST /ingress` returns 200, the file contains the new rule and the
//!   original comment is preserved;
//! - Process restart (same config file) → the rule is still present and the
//!   listener comes up, origin becomes `file`;
//! - `DELETE` is persisted to disk; a second delete returns 404; egress is
//!   symmetric;
//! - No Bearer → 401.

#![allow(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    missing_docs
)]

use interflow_mesh::agent::AgentClient;
use interflow_mesh::config::load_agent_config;
use interflow_testkit::{hub_config, pick_ephemeral_port, spawn_hub, wait_for_tcp};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const TOKEN: &str = "e2e-secret-token";

/// Temp dir (cleaned up on Drop).
struct TempDir(PathBuf);
impl TempDir {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "interflow-e2e-persist-{tag}-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("mkdir");
        Self(dir)
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Minimal HTTP/1.1 client (Connection: close semantics; returns (status, body)).
async fn http(
    addr: SocketAddr,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Option<&str>,
) -> (u16, String) {
    let mut stream = TcpStream::connect(addr).await.expect("connect control");
    let payload = body.unwrap_or("");
    let auth = token
        .map(|t| format!("Authorization: Bearer {t}\r\n"))
        .unwrap_or_default();
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: control\r\n{auth}Content-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{payload}",
        payload.len()
    );
    stream.write_all(req.as_bytes()).await.expect("write req");
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.expect("read resp");
    let text = String::from_utf8_lossy(&buf).into_owned();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .expect("status line");
    let body = text
        .split("\r\n\r\n")
        .nth(1)
        .unwrap_or_default()
        .to_string();
    (status, body)
}

/// Writes the initial config file and starts a file-backed agent; returns
/// (handle, control address, config path).
async fn start_file_agent(
    hub_port: u16,
    ctrl_port: u16,
    path: &std::path::Path,
) -> interflow_mesh::agent::AgentHandle {
    let toml = format!(
        "# e2e fixture top comment
config_version = 2

[agent]
id = \"persist-agent\"
hub_url = \"http://127.0.0.1:{hub_port}\"

[control]
enabled = true
listen_addr = \"127.0.0.1:{ctrl_port}\"
auth_token = \"{TOKEN}\"
"
    );
    std::fs::write(path, toml).expect("write config");
    let cfg = load_agent_config(path).expect("parse config");
    let handle = AgentClient::with_config_file(cfg, path)
        .expect("agent build")
        .start();
    wait_for_tcp(
        format!("127.0.0.1:{ctrl_port}").parse().unwrap(),
        Duration::from_secs(10),
    )
    .await
    .expect("control port up");
    handle
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn control_api_persists_rules_across_restart() {
    let hub_port = pick_ephemeral_port();
    let _hub = spawn_hub(hub_config(hub_port, vec![])).await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    let tmp = TempDir::new("restart");
    let cfg_path = tmp.0.join("agent.toml");
    let ctrl_port = pick_ephemeral_port();
    let ctrl: SocketAddr = format!("127.0.0.1:{ctrl_port}").parse().unwrap();
    // Listen port for the rule added via the API (pre-probed as free)
    let ingress_port = pick_ephemeral_port();

    // ---- First start ----
    let handle = start_file_agent(hub_port, ctrl_port, &cfg_path).await;

    // Missing auth → 401
    let (status, _) = http(ctrl, "GET", "/ingress", None, None).await;
    assert_eq!(status, 401);

    // POST /ingress → 200, the file contains the new rule and the comment is preserved
    let rule_json = format!(
        r#"{{"name":"api-added","listen_addr":"127.0.0.1:{ingress_port}","target_agent":"other"}}"#
    );
    let (status, body) = http(ctrl, "POST", "/ingress", Some(TOKEN), Some(&rule_json)).await;
    assert_eq!(status, 200, "POST /ingress body: {body}");
    let content = std::fs::read_to_string(&cfg_path).unwrap();
    assert!(
        content.contains("# e2e fixture top comment"),
        "comment should be preserved:\n{content}"
    );
    assert!(
        content.contains("api-added"),
        "file should contain the new rule:\n{content}"
    );

    // GET /ingress → the rule is listed, origin = api
    let (status, body) = http(ctrl, "GET", "/ingress", Some(TOKEN), None).await;
    assert_eq!(status, 200);
    let views: Vec<serde_json::Value> = serde_json::from_str(&body).expect("json");
    let view = views
        .iter()
        .find(|v| v["name"] == "api-added")
        .expect("api-added in list");
    assert_eq!(view["origin"], "api");
    assert_eq!(view["listen_addr"], format!("127.0.0.1:{ingress_port}"));

    // Graceful shutdown → restart with the same file
    handle.shutdown_graceful().await.expect("shutdown");
    tokio::time::sleep(Duration::from_millis(300)).await;

    let cfg2 = load_agent_config(&cfg_path).expect("rules should parse after restart");
    assert_eq!(
        cfg2.ingress.len(),
        1,
        "restart load should include the rule written by the API"
    );
    let handle2 = AgentClient::with_config_file(cfg2, &cfg_path)
        .expect("agent build 2")
        .start();
    wait_for_tcp(ctrl, Duration::from_secs(10))
        .await
        .expect("control up 2");

    // The rule is still present, origin = file (loaded from the file); the
    // listener actually comes up
    let (status, body) = http(ctrl, "GET", "/ingress", Some(TOKEN), None).await;
    assert_eq!(status, 200);
    let views: Vec<serde_json::Value> = serde_json::from_str(&body).expect("json 2");
    let view = views
        .iter()
        .find(|v| v["name"] == "api-added")
        .expect("api-added after restart");
    assert_eq!(view["origin"], "file");
    wait_for_tcp(
        format!("127.0.0.1:{ingress_port}").parse().unwrap(),
        Duration::from_secs(10),
    )
    .await
    .expect("ingress listener should come up after restart");

    // DELETE is persisted; a second delete returns 404
    let (status, body) = http(ctrl, "DELETE", "/ingress/api-added", Some(TOKEN), None).await;
    assert_eq!(status, 200, "DELETE body: {body}");
    assert!(
        !std::fs::read_to_string(&cfg_path)
            .unwrap()
            .contains("api-added")
    );
    let (status, _) = http(ctrl, "DELETE", "/ingress/api-added", Some(TOKEN), None).await;
    assert_eq!(status, 404, "repeated delete should return 404");
    let (status, _) = http(ctrl, "DELETE", "/ingress/ghost", Some(TOKEN), None).await;
    assert_eq!(status, 404);

    // ---- Symmetric verification for egress ----
    let (status, body) = http(
        ctrl,
        "POST",
        "/egress",
        Some(TOKEN),
        Some(r#"{"name":"eg1","target_addr":"127.0.0.1:14923"}"#),
    )
    .await;
    assert_eq!(status, 200, "POST /egress body: {body}");

    let (status, body) = http(ctrl, "GET", "/egress", Some(TOKEN), None).await;
    assert_eq!(status, 200);
    let views: Vec<serde_json::Value> = serde_json::from_str(&body).expect("egress json");
    assert!(
        views
            .iter()
            .any(|v| v["name"] == "eg1" && v["origin"] == "api")
    );

    let (status, _) = http(ctrl, "DELETE", "/egress/eg1", Some(TOKEN), None).await;
    assert_eq!(status, 200);
    assert!(!std::fs::read_to_string(&cfg_path).unwrap().contains("eg1"));
    let (status, _) = http(ctrl, "DELETE", "/egress/eg1", Some(TOKEN), None).await;
    assert_eq!(status, 404);

    handle2.shutdown_graceful().await.expect("shutdown 2");
}

/// POST with the same name = replace: the file entry is not duplicated, and
/// the port is updated.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn control_api_same_name_replaces() {
    let hub_port = pick_ephemeral_port();
    let _hub = spawn_hub(hub_config(hub_port, vec![])).await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    let tmp = TempDir::new("replace");
    let cfg_path = tmp.0.join("agent.toml");
    let ctrl_port = pick_ephemeral_port();
    let ctrl: SocketAddr = format!("127.0.0.1:{ctrl_port}").parse().unwrap();
    let handle = start_file_agent(hub_port, ctrl_port, &cfg_path).await;

    for port in [15100u16, 15101] {
        let rule =
            format!(r#"{{"name":"dup","listen_addr":"127.0.0.1:{port}","target_agent":"other"}}"#);
        let (status, body) = http(ctrl, "POST", "/ingress", Some(TOKEN), Some(&rule)).await;
        assert_eq!(status, 200, "body: {body}");
    }

    let cfg = load_agent_config(&cfg_path).unwrap();
    assert_eq!(cfg.ingress.len(), 1, "same-name replace should not append");
    assert_eq!(
        cfg.ingress[0].listen_addr.port(),
        15101,
        "new value should be used after replacement"
    );

    handle.shutdown_graceful().await.expect("shutdown");
}
