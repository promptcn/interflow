import { useEffect, useState } from "react";
import { api, formatRemainingSecs, isRunning, leafPhaseClass, stateText, type LogLine, type NodeInfo, type Transport } from "../api";
import LogView from "./LogView";
import { KindBadge, SectionPanel, StateDot } from "./ui";

interface Props {
  node: NodeInfo;
  onBack: () => void;
  onChanged: () => Promise<void>;
  onError: (message: string) => void;
  // Log pane (moved in from the old split layout): the detail page owns its
  // placement, App still owns the buffer and the scope preference.
  logs: LogLine[];
  logScope: "node" | "machine";
  onLogScopeChange: (scope: "node" | "machine") => void;
  onClearLogs: () => void;
}

/// Strict loopback `<ip>:<port>` parse (127.x.x.x:port or [::1]:port) —
/// the same shape the engine's default-deny policy will dial; the backend
/// re-validates, this is the fail-fast hint.
function parseLoopbackAddr(value: string): string | null {
  const t = value.trim();
  let m = /^\[([0-9a-fA-F:]+)\]:(\d+)$/.exec(t);
  if (m) {
    if (m[1].toLowerCase() !== "::1") return null;
    const port = Number(m[2]);
    return port >= 1 && port <= 65535 ? `[::1]:${port}` : null;
  }
  m = /^(127\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)$/.exec(t);
  if (m) {
    const port = Number(m[2]);
    return port >= 1 && port <= 65535 ? `${m[1]}:${port}` : null;
  }
  return null;
}

/// The detail page: one node, one level below the overview cards. Sections
/// carry one concern each (status/actions, identity, preferences, pack
/// truth, logs) — the hierarchy the old single-form pane lacked. Only the
/// preferences section is editable, and only while stopped: what is shown
/// elsewhere is what runs.
export default function NodeDetail({
  node,
  onBack,
  onChanged,
  onError,
  logs,
  logScope,
  onLogScopeChange,
  onClearLogs,
}: Props) {
  const running = isRunning(node.state);
  const isAgent = node.kind === "expose_agent" || node.kind === "mesh_agent";
  const services = node.services ?? [];
  const reconnecting =
    typeof node.state === "object" && node.state !== null && "Reconnecting" in node.state;

  const [transport, setTransport] = useState<Transport>(node.transport ?? "h2");
  const [hubQuicAddr, setHubQuicAddr] = useState(node.hub_quic_addr ?? "");
  // Per-service address inputs: "" = no preference (pack default runs).
  const [addresses, setAddresses] = useState<Record<string, string>>({});
  const [savedFlash, setSavedFlash] = useState(false);

  // Current override state from the node snapshot (id → overridden address).
  const overrides: Record<string, string> = Object.fromEntries(
    services.filter((s) => s.overridden).map((s) => [s.id, s.effective_address]),
  );

  // Reset the form when switching nodes (the page is one component).
  useEffect(() => {
    setTransport(node.transport ?? "h2");
    setHubQuicAddr(node.hub_quic_addr ?? "");
    setAddresses(
      Object.fromEntries(
        (node.services ?? [])
          .filter((s) => s.overridden)
          .map((s) => [s.id, s.effective_address]),
      ),
    );
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [node.id, node.transport, node.hub_quic_addr, node.services]);

  const addressError = (id: string): string | null => {
    const value = (addresses[id] ?? "").trim();
    if (value === "") return null; // empty = default, always fine
    return parseLoopbackAddr(value) === null
      ? "Must be loopback <ip>:<port>, e.g. 127.0.0.1:5173"
      : null;
  };
  const anyAddressError = services.some((s) => addressError(s.id) !== null);

  const addressesDirty = services.some(
    (s) => (addresses[s.id] ?? "").trim() !== (overrides[s.id] ?? "").trim(),
  );

  const dirty =
    isAgent &&
    (transport !== (node.transport ?? "h2") ||
      hubQuicAddr.trim() !== (node.hub_quic_addr ?? "") ||
      addressesDirty);

  const savePrefs = async () => {
    try {
      await api.updateNodePrefs(node.id, {
        transport,
        hub_quic_addr: transport === "quic" && hubQuicAddr.trim() !== "" ? hubQuicAddr.trim() : null,
        service_addresses: services
          .filter((s) => (addresses[s.id] ?? "").trim() !== "")
          .map((s) => ({ id: s.id, address: addresses[s.id].trim() })),
      });
      await onChanged();
      setSavedFlash(true);
      setTimeout(() => setSavedFlash(false), 1500);
    } catch (e) {
      onError(`Preferences not saved: ${e}`);
    }
  };

  const start = async () => {
    try {
      await api.startNode(node.id);
      await onChanged();
    } catch (e) {
      onError(`Start failed: ${e}`);
    }
  };

  const stop = async () => {
    try {
      await api.stopNode(node.id);
      await onChanged();
    } catch (e) {
      onError(`Stop failed: ${e}`);
    }
  };

  const remove = async () => {
    try {
      await api.removeNode(node.id);
      onBack();
      await onChanged();
    } catch (e) {
      onError(`Remove failed: ${e}`);
    }
  };

  const hasMeshRules =
    node.kind === "mesh_agent" &&
    (node.mesh_ingress_rules.length > 0 || node.mesh_egress_rules.length > 0);

  return (
    <div className="detail-page">
      <div className="detail-topbar">
        <button className="back" onClick={onBack} title="Esc">
          ← All nodes
        </button>
        <StateDot state={node.state} size={12} />
        <h2>{node.name}</h2>
        <KindBadge kind={node.kind} />
      </div>

      <div className="detail-body">
        <SectionPanel
          title="Status"
          actions={
            <>
              <button className="primary" disabled={running} onClick={start}>
                Start
              </button>
              <button disabled={!running} onClick={stop}>
                Stop
              </button>
              <button
                className="danger"
                disabled={running}
                onClick={remove}
                title="the pack directory is untouched"
              >
                Remove
              </button>
            </>
          }
        >
          <span>{stateText(node.state)}</span>
          {reconnecting && (
            <span className="hint">
              Will reconnect automatically once the network recovers
            </span>
          )}
        </SectionPanel>

        <SectionPanel title="Identity">
          {node.principal && (
            <div className="row">
              <label>Identity</label>
              <input value={node.principal} readOnly />
            </div>
          )}
          <div className="row">
            <label>Credential Pack</label>
            <input value={node.pack_dir} readOnly title={node.pack_dir} />
          </div>
          {node.generation > 0 && (
            <div className="row">
              <label>Generation</label>
              <span className="hint">{node.generation}</span>
            </div>
          )}
          {node.credential && (
            <div className="row">
              <label>Credentials expire</label>
              <span
                className={`hint ${leafPhaseClass(node.credential)}`}
                title="When this node's leaf credentials stop working — rotate before then"
              >
                {node.credential.not_after} ·{" "}
                {formatRemainingSecs(node.credential.remaining_secs)} left
              </span>
            </div>
          )}
        </SectionPanel>

        {hasMeshRules && (
          <SectionPanel title="Mesh rules">
            {node.mesh_ingress_rules.length > 0 && (
              <div className="mesh-rule-group">
                <div className="mesh-rule-group-title hint">Ingress</div>
                {node.mesh_ingress_rules.map((rule) => (
                  <div className="mesh-rule" key={rule.name}>
                    <span className="mono">{rule.listen}</span>
                    <span className="mesh-rule-proto">{rule.protocol}</span>
                    <span>→ {rule.remote_addr}</span>
                    <span className="hint">at {rule.target_agent}</span>
                    <span className="mesh-rule-name hint" title={rule.name}>
                      {rule.name}
                    </span>
                  </div>
                ))}
              </div>
            )}
            {node.mesh_egress_rules.length > 0 && (
              <div className="mesh-rule-group">
                <div className="mesh-rule-group-title hint">Egress</div>
                {node.mesh_egress_rules.map((rule) => (
                  <div className="mesh-rule" key={rule.name}>
                    <span className="mesh-rule-proto">{rule.protocol}</span>
                    <span>{rule.target}</span>
                    <span className="mesh-rule-name hint" title={rule.name}>
                      {rule.name}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </SectionPanel>
        )}

        {isAgent && (
          <SectionPanel
            title="Runtime preferences"
            hint={running ? "stop the node to edit" : undefined}
          >
            <div className="row">
              <label>Transport</label>
              <div className="transport-toggle">
                <button
                  className={transport === "h2" ? "selected" : ""}
                  disabled={running}
                  onClick={() => setTransport("h2")}
                >
                  h2
                </button>
                <button
                  className={transport === "quic" ? "selected" : ""}
                  disabled={running}
                  onClick={() => setTransport("quic")}
                >
                  QUIC
                </button>
              </div>
            </div>
            {transport === "quic" && (
              <div className="row">
                <label>Hub QUIC address</label>
                <input
                  disabled={running}
                  value={hubQuicAddr}
                  onChange={(e) => setHubQuicAddr(e.target.value)}
                  placeholder="(optional) host:port — derived if empty"
                  autoCapitalize="none"
                  autoCorrect="off"
                  spellCheck={false}
                  autoComplete="off"
                />
              </div>
            )}
            {services.length > 0 && (
              <>
                <div className="row">
                  <label>Service addresses</label>
                  <span className="hint">empty = pack default</span>
                </div>
                {services.map((service) => {
                  const err = addressError(service.id);
                  return (
                    <div className="row" key={service.id}>
                      <label className="mono">{service.id}</label>
                      <div className="address-edit">
                        <input
                          className={err ? "invalid" : ""}
                          disabled={running}
                          value={addresses[service.id] ?? ""}
                          onChange={(e) =>
                            setAddresses((prev) => ({
                              ...prev,
                              [service.id]: e.target.value,
                            }))
                          }
                          placeholder={service.default_address}
                          title={
                            service.overridden
                              ? `Pack default: ${service.default_address}`
                              : undefined
                          }
                          autoCapitalize="none"
                          autoCorrect="off"
                          spellCheck={false}
                          autoComplete="off"
                        />
                        <button
                          className="link"
                          disabled={running || (addresses[service.id] ?? "") === ""}
                          onClick={() =>
                            setAddresses((prev) => ({ ...prev, [service.id]: "" }))
                          }
                          title="Revert to pack default"
                        >
                          reset
                        </button>
                      </div>
                      {err && <span className="field-error">{err}</span>}
                    </div>
                  );
                })}
              </>
            )}
            <div className="row">
              <label />
              <button disabled={running || !dirty || anyAddressError} onClick={savePrefs}>
                {savedFlash ? "Saved ✓" : "Save preferences"}
              </button>
            </div>
          </SectionPanel>
        )}

        <SectionPanel
          title="Logs"
          grow
          actions={
            <span className="log-scope-row">
              <button
                className={logScope === "node" ? "selected" : ""}
                onClick={() => onLogScopeChange("node")}
              >
                This node
              </button>
              <button
                className={logScope === "machine" ? "selected" : ""}
                onClick={() => onLogScopeChange("machine")}
              >
                This machine
              </button>
            </span>
          }
        >
          <LogView logs={logs} showNodeColumn={logScope === "machine"} onClear={onClearLogs} />
        </SectionPanel>
      </div>
    </div>
  );
}
