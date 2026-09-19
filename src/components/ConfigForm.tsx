import { useState } from "react";
import type { Transport } from "../api";

interface Props {
  disabled: boolean;
  ports: number[];
  setPorts: (ports: number[]) => void;
  hubUrl: string;
  setHubUrl: (v: string) => void;
  clientCert: string;
  setClientCert: (v: string) => void;
  clientKey: string;
  setClientKey: (v: string) => void;
  agentId: string;
  setAgentId: (v: string) => void;
  caPath: string;
  setCaPath: (v: string) => void;
  transport: Transport;
  setTransport: (v: Transport) => void;
  hubQuicAddr: string;
  setHubQuicAddr: (v: string) => void;
  profileLoaded: boolean;
  onGenerateAgentId: () => Promise<void>;
  onSaveProfile: () => Promise<void>;
}

export default function ConfigForm(p: Props) {
  const [newPort, setNewPort] = useState("");
  const [saved, setSaved] = useState(false);

  const addPort = () => {
    const port = Number.parseInt(newPort, 10);
    if (Number.isNaN(port) || port <= 0 || port > 65535 || p.ports.includes(port)) return;
    p.setPorts([...p.ports, port]);
    setNewPort("");
  };

  const pickFile = async (
    title: string,
    extensions: string[],
    onPicked: (path: string) => void
  ) => {
    const { open } = await import("@tauri-apps/plugin-dialog");
    const file = await open({
      title,
      filters: [{ name: "PEM file", extensions }],
    });
    if (typeof file === "string") onPicked(file);
  };

  const pickCa = () =>
    pickFile("Choose a CA certificate (PEM)", ["pem", "crt", "cer"], p.setCaPath);
  const pickClientCert = () =>
    pickFile("Choose a client certificate (PEM)", ["pem", "crt", "cer"], p.setClientCert);
  const pickClientKey = () =>
    pickFile("Choose a client key (PEM)", ["pem", "key"], p.setClientKey);

  return (
    <div className="form">
      <div className="row">
        <label>Local port</label>
        <div className="ports">
          {p.ports.map((port) => (
            <span key={port} className="port-chip">
              {port}
              {!p.disabled && (
                <button
                  className="chip-x"
                  onClick={() => p.setPorts(p.ports.filter((x) => x !== port))}
                  aria-label={`Remove port ${port}`}
                >
                  ×
                </button>
              )}
            </span>
          ))}
          {!p.disabled && (
            <>
              <input
                className="port-input"
                value={newPort}
                onChange={(e) => setNewPort(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && addPort()}
                placeholder="Port"
                inputMode="numeric"
              />
              <button onClick={addPort} disabled={newPort === ""}>
                Add
              </button>
            </>
          )}
        </div>
      </div>

      <div className="row">
        <label>Hub URL</label>
        <input
          disabled={p.disabled}
          value={p.hubUrl}
          onChange={(e) => p.setHubUrl(e.target.value)}
          placeholder="https://hub.example.com:6666"
        />
      </div>

      <div className="row">
        <label>Client cert</label>
        <input
          disabled={p.disabled}
          value={p.clientCert}
          onChange={(e) => p.setClientCert(e.target.value)}
          placeholder="mTLS identity, e.g. agents/<agent-id>.crt — CN must equal the Agent ID"
        />
        <button disabled={p.disabled} onClick={pickClientCert}>
          Browse
        </button>
      </div>

      <div className="row">
        <label>Client key</label>
        <input
          disabled={p.disabled}
          value={p.clientKey}
          onChange={(e) => p.setClientKey(e.target.value)}
          placeholder="e.g. agents/<agent-id>.key (must be 0600)"
        />
        <button disabled={p.disabled} onClick={pickClientKey}>
          Browse
        </button>
      </div>

      <div className="row">
        <label>Agent ID</label>
        <input
          disabled={p.disabled}
          value={p.agentId}
          onChange={(e) => p.setAgentId(e.target.value)}
          placeholder="Must match edge routes.toml"
          autoCapitalize="none"
          autoCorrect="off"
          spellCheck={false}
          autoComplete="off"
        />
        <button disabled={p.disabled} onClick={p.onGenerateAgentId}>
          Random
        </button>
      </div>

      <div className="row">
        <label>CA path</label>
        <input
          disabled={p.disabled}
          value={p.caPath}
          onChange={(e) => p.setCaPath(e.target.value)}
          placeholder="(optional) self-signed hub CA PEM"
        />
        <button disabled={p.disabled} onClick={pickCa}>
          Browse
        </button>
      </div>

      <div className="row">
        <label>Transport</label>
        <div className="transport-toggle">
          <button
            className={p.transport === "h2" ? "selected" : ""}
            disabled={p.disabled}
            onClick={() => p.setTransport("h2")}
            title="HTTP/2 long-lived streams — works wherever TCP egress is allowed"
          >
            h2
          </button>
          <button
            className={p.transport === "quic" ? "selected" : ""}
            disabled={p.disabled}
            onClick={() => p.setTransport("quic")}
            title="QUIC native streams — no TCP head-of-line blocking; needs UDP egress and TLS"
          >
            QUIC
          </button>
        </div>
      </div>

      {p.transport === "quic" && (
        <div className="row">
          <label>Hub QUIC address</label>
          <input
            disabled={p.disabled}
            value={p.hubQuicAddr}
            onChange={(e) => p.setHubQuicAddr(e.target.value)}
            placeholder="(optional) host:port — empty derives it from the hub URL"
          />
        </div>
      )}

      <div className="row">
        <label />
        <button
          disabled={p.disabled || !p.profileLoaded}
          onClick={async () => {
            await p.onSaveProfile();
            setSaved(true);
            setTimeout(() => setSaved(false), 1500);
          }}
        >
          {saved ? "Saved ✓" : "Save to profile"}
        </button>
      </div>
    </div>
  );
}
