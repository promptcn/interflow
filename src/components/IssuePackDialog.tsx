import { useMemo, useState } from "react";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import { api, type DeployContextDto, type IssueNodeParams } from "../api";
import { Modal } from "./ui";

/// The issue wizard: one modal from "a new machine needs a pack" to a
/// sealed `.iflowpack` in Downloads. The user supplies exactly the two
/// security-relevant facts (node name, authorization scope); the manifest
/// append, validation, apply and sealing are orchestrated underneath
type Kind = IssueNodeParams["kind"];

const KINDS: { value: Kind; label: string; blurb: string }[] = [
  { value: "agent_mesh", label: "Mesh agent", blurb: "site-to-site endpoint (ingress/egress rules)" },
  { value: "agent_expose", label: "Expose agent", blurb: "dials local services into a public domain" },
  { value: "hub", label: "Hub", blurb: "the public relay (one per realm)" },
  { value: "ingress", label: "Ingress", blurb: "public entry point for expose routes" },
];

interface ServiceRow {
  id: string;
  address: string;
}
interface MeshIngressRow {
  name: string;
  listen: string;
  protocol: "tcp" | "udp";
  target_agent: string;
  remote_addr: string;
}
interface MeshEgressRow {
  name: string;
  protocol: "tcp" | "udp";
  target: string; // host:port, or ip/prefix when it contains "/"
}

interface Done {
  packDirName: string;
  filePath: string | null;
  passphrase: string | null;
}

const field = (
  value: string,
  onChange: (v: string) => void,
  placeholder: string,
  width?: string,
) => (
  <input
    style={width ? { width } : undefined}
    value={value}
    placeholder={placeholder}
    onChange={(e) => onChange(e.target.value)}
    autoCapitalize="none"
    autoCorrect="off"
    spellCheck={false}
    autoComplete="off"
  />
);

export default function IssuePackDialog({
  manifest,
  issuer,
  out,
  busy: faceBusy,
  recentContexts,
  onPickContext,
  onSay,
  onIssued,
  onComplete,
  onClose,
}: {
  manifest: string;
  issuer: string;
  out: string;
  busy: boolean;
  recentContexts: DeployContextDto[];
  onPickContext: (ctx: DeployContextDto) => void;
  onSay: (lines: string[]) => void;
  /// Feeds the rewritten manifest text back into the editor pane.
  onIssued: (manifestText: string) => void;
  /// Refreshes the pack grid after a successful apply.
  onComplete: () => void;
  onClose: () => void;
}) {
  const [kind, setKind] = useState<Kind>("agent_mesh");
  const [node, setNode] = useState("");
  const [workspace, setWorkspace] = useState("");
  const [services, setServices] = useState<ServiceRow[]>([{ id: "", address: "" }]);
  const [meshIngress, setMeshIngress] = useState<MeshIngressRow[]>([
    { name: "", listen: "", protocol: "tcp", target_agent: "", remote_addr: "" },
  ]);
  const [meshEgress, setMeshEgress] = useState<MeshEgressRow[]>([]);
  const [ingressWorkspaces, setIngressWorkspaces] = useState("default");
  const [hubEndpoint, setHubEndpoint] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState<Done | null>(null);
  const [copied, setCopied] = useState(false);

  const trimmed = node.trim();
  const ready =
    trimmed !== "" &&
    (kind === "hub" ? hubEndpoint.trim() !== "" : true) &&
    (kind === "ingress" ? ingressWorkspaces.trim() !== "" : true);

  const buildParams = (): IssueNodeParams => ({
    kind,
    node: trimmed,
    manifest: manifest.trim(),
    workspace: workspace.trim() === "" ? null : workspace.trim(),
    services:
      kind === "agent_expose"
        ? services.map((s) => ({ id: s.id.trim(), address: s.address.trim() }))
        : [],
    mesh_ingress:
      kind === "agent_mesh"
        ? meshIngress.map((r) => ({
            name: r.name.trim(),
            listen: r.listen.trim(),
            protocol: r.protocol,
            target_agent: r.target_agent.trim(),
            remote_addr: r.remote_addr.trim(),
          }))
        : [],
    mesh_egress:
      kind === "agent_mesh"
        ? meshEgress.map((r) => ({
            name: r.name.trim(),
            protocol: r.protocol,
            target: r.target.includes("/") ? null : r.target.trim(),
            target_cidr: r.target.includes("/") ? r.target.trim() : null,
          }))
        : [],
    ingress_workspaces:
      kind === "ingress"
        ? ingressWorkspaces
            .split(",")
            .map((w) => w.trim())
            .filter((w) => w !== "")
        : [],
    hub_endpoint: kind === "hub" ? hubEndpoint.trim() : null,
  });

  /// Informational preview of the appended TOML — the backend's toml_edit
  /// insert is the authority; this just shows the shape before committing.
  const preview = useMemo(() => {
    if (trimmed === "") return "";
    const lines: string[] = [];
    const ws = workspace.trim() === "" ? null : workspace.trim();
    if (kind === "agent_expose" || kind === "agent_mesh") {
      if (ws) lines.push(`[workspace.${ws}]  # auto-declared if new`);
      lines.push(`[agent.${trimmed}]`);
      if (ws) lines.push(`workspace = "${ws}"`);
      for (const s of services.filter((s) => s.id.trim() !== "")) {
        lines.push(``, `[[agent.${trimmed}.services]]`, `id = "${s.id.trim()}"`, `address = "${s.address.trim()}"`);
      }
      for (const r of meshIngress.filter((r) => r.name.trim() !== "")) {
        lines.push(
          ``,
          `[[agent.${trimmed}.mesh_ingress]]`,
          `name = "${r.name.trim()}"`,
          `listen = "${r.listen.trim()}"`,
          ...(r.protocol === "udp" ? [`protocol = "udp"`] : []),
          `target_agent = "${r.target_agent.trim()}"`,
          `remote_addr = "${r.remote_addr.trim()}"`,
        );
      }
      for (const r of meshEgress.filter((r) => r.name.trim() !== "")) {
        lines.push(
          ``,
          `[[agent.${trimmed}.mesh_egress]]`,
          `name = "${r.name.trim()}"`,
          ...(r.protocol === "udp" ? [`protocol = "udp"`] : []),
          r.target.includes("/")
            ? `target_cidr = "${r.target.trim()}"`
            : `target_addr = "${r.target.trim()}"`,
        );
      }
    } else if (kind === "hub") {
      lines.push(`[mesh.hub.${trimmed}]`, `endpoint = "${hubEndpoint.trim()}"`);
    } else {
      lines.push(`[ingress.${trimmed}]`, `workspaces = [${ingressWorkspaces.split(",").map((w) => `"${w.trim()}"`).join(", ")}]`);
    }
    return lines.join("\n");
  }, [kind, trimmed, workspace, services, meshIngress, meshEgress, hubEndpoint, ingressWorkspaces]);

  const run = async (download: boolean) => {
    setBusy(true);
    setError(null);
    try {
      const outcome = await api.deployAddNode(buildParams());
      onSay([`✔ ${trimmed} appended to ${manifest.trim()} → packs/${outcome.pack_dir_name}`]);
      onIssued(outcome.manifest_text);
      const lines = await api.deployApply(manifest.trim(), issuer.trim(), out.trim());
      onSay(lines);
      if (download) {
        const passphrase = await api.deployGeneratePassphrase();
        const sealed = await api.deploySealToDownloads(
          `${out.trim()}/packs/${outcome.pack_dir_name}`,
          passphrase,
        );
        onSay([`sealed → ${sealed.path}`]);
        setDone({ packDirName: outcome.pack_dir_name, filePath: sealed.path, passphrase });
      } else {
        setDone({ packDirName: outcome.pack_dir_name, filePath: null, passphrase: null });
      }
      onComplete();
    } catch (e) {
      const message = String(e);
      setError(message);
      onSay([`✘ ${message}`]);
    } finally {
      setBusy(false);
    }
  };

  const copyPassphrase = async () => {
    if (!done?.passphrase) return;
    try {
      await writeText(done.passphrase);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      // Clipboard denied — the passphrase stays visible for manual copy.
    }
  };

  const active = busy || faceBusy;

  return (
    <Modal onClose={active ? () => {} : onClose} wide>
      <h2>Issue a pack</h2>

      {done ? (
        <>
          <p className="confirm-message">
            {done.passphrase
              ? `${done.packDirName} is sealed and in your Downloads folder. The target machine's GUI asks for this passphrase on import:`
              : `${done.packDirName} is rendered under ${out.trim()}/packs/ — seal it from its pack card when you're ready.`}
          </p>
          {done.passphrase && (
            <div className="issue-passphrase">
              <code>{done.passphrase}</code>
              <button onClick={() => void copyPassphrase()}>{copied ? "Copied" : "Copy"}</button>
            </div>
          )}
          {done.filePath && <p className="hint">{done.filePath}</p>}
          <p className="hint">
            The manifest was rewritten non-destructively (comments kept; the previous copy is
            beside it as .bak).
          </p>
          <div className="dialog-actions">
            <button className="primary" onClick={onClose}>
              Done
            </button>
          </div>
        </>
      ) : (
        <>
          {recentContexts.length > 1 && (
            <div className="row">
              <label>Context</label>
              <select
                value={`${manifest}|${issuer}|${out}`}
                onChange={(e) => {
                  const picked = recentContexts.find(
                    (c) => `${c.manifest}|${c.issuer}|${c.out}` === e.target.value,
                  );
                  if (picked) onPickContext(picked);
                }}
              >
                {recentContexts.map((c) => (
                  <option key={`${c.manifest}|${c.issuer}|${c.out}`} value={`${c.manifest}|${c.issuer}|${c.out}`}>
                    {c.manifest} · {c.issuer}
                  </option>
                ))}
              </select>
            </div>
          )}

          <div className="issue-kinds">
            {KINDS.map((k) => (
              <button
                key={k.value}
                className={kind === k.value ? "selected" : ""}
                disabled={active}
                title={k.blurb}
                onClick={() => setKind(k.value)}
              >
                {k.label}
              </button>
            ))}
          </div>
          <p className="hint">{KINDS.find((k) => k.value === kind)?.blurb}</p>

          <div className="row">
            <label>Node name</label>
            {field(node, setNode, "home-win")}
          </div>

          {(kind === "agent_expose" || kind === "agent_mesh") && (
            <div className="row">
              <label>Workspace</label>
              {field(workspace, setWorkspace, "empty = the manifest's sole workspace / default")}
            </div>
          )}
          {kind === "hub" && (
            <div className="row">
              <label>Endpoint</label>
              {field(hubEndpoint, setHubEndpoint, "mesh.example.com:6666")}
            </div>
          )}
          {kind === "ingress" && (
            <div className="row">
              <label>Workspaces</label>
              {field(ingressWorkspaces, setIngressWorkspaces, "default")}
            </div>
          )}

          {kind === "agent_expose" && (
            <div className="rule-editor">
              <div className="rule-editor-head">
                <span>Services</span>
                <button disabled={active} onClick={() => setServices([...services, { id: "", address: "" }])}>
                  + service
                </button>
              </div>
              {services.map((s, i) => (
                <div className="rule-row" key={i}>
                  {field(s.id, (v) => setServices(services.map((r, j) => (j === i ? { ...r, id: v } : r))), "asr", "120px")}
                  {field(s.address, (v) => setServices(services.map((r, j) => (j === i ? { ...r, address: v } : r))), "127.0.0.1:8080")}
                  <button
                    className="rule-remove"
                    disabled={active}
                    onClick={() => setServices(services.filter((_, j) => j !== i))}
                  >
                    ×
                  </button>
                </div>
              ))}
            </div>
          )}

          {kind === "agent_mesh" && (
            <div className="rule-editor">
              <div className="rule-editor-head">
                <span>Mesh ingress — forward a local listener to a peer</span>
                <button
                  disabled={active}
                  onClick={() =>
                    setMeshIngress([...meshIngress, { name: "", listen: "", protocol: "tcp", target_agent: "", remote_addr: "" }])
                  }
                >
                  + rule
                </button>
              </div>
              {meshIngress.map((r, i) => {
                const patch = (p: Partial<MeshIngressRow>) =>
                  setMeshIngress(meshIngress.map((row, j) => (j === i ? { ...row, ...p } : row)));
                return (
                  <div className="rule-row" key={i}>
                    {field(r.name, (v) => patch({ name: v }), "ollama", "110px")}
                    {field(r.listen, (v) => patch({ listen: v }), "127.0.0.1:11434", "170px")}
                    <select value={r.protocol} disabled={active} onChange={(e) => patch({ protocol: e.target.value as "tcp" | "udp" })}>
                      <option value="tcp">tcp</option>
                      <option value="udp">udp</option>
                    </select>
                    {field(r.target_agent, (v) => patch({ target_agent: v }), "peer agent", "110px")}
                    {field(r.remote_addr, (v) => patch({ remote_addr: v }), "127.0.0.1:11434", "170px")}
                    <button
                      className="rule-remove"
                      disabled={active}
                      onClick={() => setMeshIngress(meshIngress.filter((_, j) => j !== i))}
                    >
                      ×
                    </button>
                  </div>
                );
              })}
              <div className="rule-editor-head">
                <span>Mesh egress — what this agent dials for peers</span>
                <button
                  disabled={active}
                  onClick={() => setMeshEgress([...meshEgress, { name: "", protocol: "tcp", target: "" }])}
                >
                  + rule
                </button>
              </div>
              {meshEgress.map((r, i) => {
                const patch = (p: Partial<MeshEgressRow>) =>
                  setMeshEgress(meshEgress.map((row, j) => (j === i ? { ...row, ...p } : row)));
                return (
                  <div className="rule-row" key={i}>
                    {field(r.name, (v) => patch({ name: v }), "loopback", "110px")}
                    <select value={r.protocol} disabled={active} onChange={(e) => patch({ protocol: e.target.value as "tcp" | "udp" })}>
                      <option value="tcp">tcp</option>
                      <option value="udp">udp</option>
                    </select>
                    {field(r.target, (v) => patch({ target: v }), "127.0.0.1:11434 or 127.0.0.0/8")}
                    <button
                      className="rule-remove"
                      disabled={active}
                      onClick={() => setMeshEgress(meshEgress.filter((_, j) => j !== i))}
                    >
                      ×
                    </button>
                  </div>
                );
              })}
              <p className="hint">
                The peer's egress must already authorize the remote address (protocol included);
                the validator refuses unmatched pairs.
              </p>
            </div>
          )}

          {preview !== "" && (
            <div className="issue-preview">
              <span className="hint">will append (non-destructive; comments kept)</span>
              <pre>{preview}</pre>
            </div>
          )}

          {error && <div className="dialog-error">{error}</div>}

          <div className="dialog-actions">
            <button disabled={active} onClick={onClose}>
              Cancel
            </button>
            <button disabled={active || !ready} onClick={() => void run(false)}>
              Issue only
            </button>
            <button className="primary" disabled={active || !ready} onClick={() => void run(true)}>
              {busy ? "…" : "Issue & download"}
            </button>
          </div>
        </>
      )}
    </Modal>
  );
}
