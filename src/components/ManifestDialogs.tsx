import { useState, type ReactNode } from "react";
import { Modal } from "./ui";
import type {
  HubDto,
  IngressNodeDto,
  IssueMeshEgressDto,
  IssueMeshIngressDto,
  IssueNodeKindDto,
  IssueServiceSpecDto,
  ManifestEgressRuleDto,
  ManifestIngressRuleDto,
  ManifestServiceDto,
  MeshProtocolDto,
  RouteDto,
} from "../api";

/// Modal editors for the manifest Form view — one per creation/editable
/// kind, each submitting its **complete desired state** through the
/// document model (`deployEditManifest`). Nothing here talks to the disk:
/// the caller owns the document, Save owns the file.

function field(
  value: string,
  set: (v: string) => void,
  placeholder: string,
  width?: string,
): ReactNode {
  return (
    <input
      style={width ? { width } : undefined}
      value={value}
      placeholder={placeholder}
      onChange={(e) => set(e.target.value)}
      autoCapitalize="none"
      autoCorrect="off"
      spellCheck={false}
      autoComplete="off"
    />
  );
}

function protocolSelect(
  value: MeshProtocolDto,
  set: (v: MeshProtocolDto) => void,
): ReactNode {
  return (
    <select value={value} onChange={(e) => set(e.target.value as MeshProtocolDto)}>
      <option value="tcp">tcp</option>
      <option value="udp">udp</option>
    </select>
  );
}

function DialogFrame({
  title,
  onClose,
  busy,
  onConfirm,
  confirmLabel = "Apply",
  children,
}: {
  title: string;
  onClose: () => void;
  busy: boolean;
  onConfirm: () => void;
  confirmLabel?: string;
  children: ReactNode;
}) {
  return (
    <Modal onClose={onClose} wide>
      <h2>{title}</h2>
      <div className="rule-editor" style={{ gap: 8 }}>
        {children}
      </div>
      <div className="dialog-actions">
        <button disabled={busy} onClick={onClose}>
          Cancel
        </button>
        <button className="primary" disabled={busy} onClick={onConfirm}>
          {confirmLabel}
        </button>
      </div>
    </Modal>
  );
}

/// One `[[agent.services]]` entry: id + dial address.
export function ServiceDialog({
  agent,
  initial,
  busy,
  onConfirm,
  onClose,
}: {
  agent: string;
  initial: ManifestServiceDto | null;
  busy: boolean;
  onConfirm: (edit: { id: string; address: string }) => void;
  onClose: () => void;
}) {
  const [id, setId] = useState(initial?.id ?? "");
  const [address, setAddress] = useState(initial?.address ?? "");
  return (
    <DialogFrame
      title={initial ? `Service ${initial.id} — ${agent}` : `New service — ${agent}`}
      onClose={onClose}
      busy={busy}
      onConfirm={() => onConfirm({ id: id.trim(), address: address.trim() })}
    >
      <div className="rule-row">
        {field(id, setId, "asr", "110px")}
        {field(address, setAddress, "127.0.0.1:8080")}
      </div>
      <p className="hint">id + the manifest-issued default dial address (strict ip:port).</p>
    </DialogFrame>
  );
}

/// One `[[agent.mesh_ingress]]` rule: forward a local loopback listener
/// through the hub to a peer.
export function MeshIngressRuleDialog({
  agent,
  initial,
  busy,
  onConfirm,
  onClose,
}: {
  agent: string;
  initial: ManifestIngressRuleDto | null;
  busy: boolean;
  onConfirm: (edit: {
    name: string;
    listen: string;
    protocol: MeshProtocolDto;
    target_agent: string;
    remote_addr: string;
    idle_timeout_secs: number | null;
  }) => void;
  onClose: () => void;
}) {
  const [name, setName] = useState(initial?.name ?? "");
  const [listen, setListen] = useState(initial?.listen ?? "");
  const [protocol, setProtocol] = useState<MeshProtocolDto>(initial?.protocol ?? "tcp");
  const [targetAgent, setTargetAgent] = useState(initial?.target_agent ?? "");
  const [remoteAddr, setRemoteAddr] = useState(initial?.remote_addr ?? "");
  const [idle, setIdle] = useState(
    initial?.idle_timeout_secs != null ? String(initial.idle_timeout_secs) : "",
  );
  const idleNum = idle.trim() === "" ? null : Number(idle.trim());
  return (
    <DialogFrame
      title={initial ? `Rule ${initial.name} — ${agent}` : `New mesh ingress rule — ${agent}`}
      onClose={onClose}
      busy={busy}
      onConfirm={() =>
        onConfirm({
          name: name.trim(),
          listen: listen.trim(),
          protocol,
          target_agent: targetAgent.trim(),
          remote_addr: remoteAddr.trim(),
          idle_timeout_secs:
            idleNum != null && Number.isFinite(idleNum) && idleNum > 0
              ? Math.floor(idleNum)
              : null,
        })
      }
    >
      <div className="rule-row">
        {field(name, setName, "ollama", "110px")}
        {field(listen, setListen, "listen 127.0.0.1:11434", "190px")}
        {protocolSelect(protocol, setProtocol)}
        {field(targetAgent, setTargetAgent, "→ agent", "110px")}
        {field(remoteAddr, setRemoteAddr, "remote 127.0.0.1:11434", "190px")}
      </div>
      <div className="rule-row">
        <label className="hint">idle timeout (s)</label>
        {field(idle, setIdle, "blank = default (tcp 300 / udp 60)", "220px")}
      </div>
      <p className="hint">
        The peer must offer the remote address (exact or inside an authorized range); the
        validator refuses unmatched pairs. Idle budget bounds: 1–86400.
      </p>
    </DialogFrame>
  );
}

/// One `[[agent.mesh_egress]]` rule: what this agent dials for peers — one
/// concrete address or an authorized range.
export function MeshEgressRuleDialog({
  agent,
  initial,
  busy,
  onConfirm,
  onClose,
}: {
  agent: string;
  initial: ManifestEgressRuleDto | null;
  busy: boolean;
  onConfirm: (edit: {
    name: string;
    protocol: MeshProtocolDto;
    target: string;
    udp_idle_timeout_secs: number | null;
  }) => void;
  onClose: () => void;
}) {
  const [name, setName] = useState(initial?.name ?? "");
  const [protocol, setProtocol] = useState<MeshProtocolDto>(initial?.protocol ?? "tcp");
  const [target, setTarget] = useState(initial?.target_addr ?? initial?.target_cidr ?? "");
  const [idle, setIdle] = useState(
    initial?.udp_idle_timeout_secs != null ? String(initial.udp_idle_timeout_secs) : "",
  );
  const idleNum = idle.trim() === "" ? null : Number(idle.trim());
  return (
    <DialogFrame
      title={initial ? `Rule ${initial.name} — ${agent}` : `New mesh egress rule — ${agent}`}
      onClose={onClose}
      busy={busy}
      onConfirm={() =>
        onConfirm({
          name: name.trim(),
          protocol,
          target: target.trim(),
          udp_idle_timeout_secs:
            idleNum != null && Number.isFinite(idleNum) && idleNum > 0
              ? Math.floor(idleNum)
              : null,
        })
      }
    >
      <div className="rule-row">
        {field(name, setName, "loopback-services", "160px")}
        {protocolSelect(protocol, setProtocol)}
        {field(target, setTarget, "127.0.0.1:8080 (one service) or 127.0.0.0/8 (a range)")}
      </div>
      <div className="rule-row">
        <label className="hint">udp idle timeout (s)</label>
        {field(idle, setIdle, "blank = default 60", "160px")}
      </div>
      <p className="hint">
        A `/` makes it a range authorization (any port) — a wider range grows the blast
        radius of this pack's leak; declare the narrowest that covers what you serve.
      </p>
    </DialogFrame>
  );
}

/// One `[[route]]`: public host → service identity.
export function RouteDialog({
  initial,
  busy,
  onConfirm,
  onClose,
}: {
  initial: RouteDto | null;
  busy: boolean;
  onConfirm: (edit: { host: string; service: string }) => void;
  onClose: () => void;
}) {
  const [host, setHost] = useState(initial?.host ?? "");
  const [service, setService] = useState(initial?.service ?? "");
  return (
    <DialogFrame
      title={initial ? `Route ${initial.host}` : "New route"}
      onClose={onClose}
      busy={busy}
      onConfirm={() => onConfirm({ host: host.trim(), service: service.trim() })}
    >
      <div className="rule-row">
        {field(host, setHost, "app.example.com", "220px")}
        <span className="hint">→</span>
        {field(service, setService, "workspace/agent/service")}
      </div>
      <p className="hint">
        The service reference is an identity, never an address; the control endpoint's
        host cannot double as a route host.
      </p>
    </DialogFrame>
  );
}

/// `[mesh.hub.<name>]` — create or edit (the name is the pack's identity:
/// renaming is remove + add).
export function HubDialog({
  initial,
  busy,
  onConfirm,
  onClose,
}: {
  initial: HubDto | null;
  busy: boolean;
  onConfirm: (edit: { name: string; endpoint: string; listen: string }) => void;
  onClose: () => void;
}) {
  const [name, setName] = useState(initial?.name ?? "");
  const [endpoint, setEndpoint] = useState(initial?.endpoint ?? "");
  const [listen, setListen] = useState(
    initial && initial.listen !== "0.0.0.0:6666" ? initial.listen : "",
  );
  return (
    <DialogFrame
      title={initial ? `Hub ${initial.name}` : "New mesh hub"}
      onClose={onClose}
      busy={busy}
      onConfirm={() =>
        onConfirm({ name: name.trim(), endpoint: endpoint.trim(), listen: listen.trim() })
      }
    >
      {initial ? (
        <div className="row">
          <label>Name</label>
          <input value={name} readOnly />
        </div>
      ) : (
        <div className="rule-row">
          {field(name, setName, "hub name", "140px")}
          {field(endpoint, setEndpoint, "endpoint mesh.example.com:6666")}
        </div>
      )}
      {initial && (
        <div className="rule-row">{field(endpoint, setEndpoint, "mesh.example.com:6666")}</div>
      )}
      <div className="rule-row">
        <label className="hint">listen</label>
        {field(listen, setListen, "blank = 0.0.0.0:6666", "220px")}
      </div>
      <p className="hint">
        The endpoint is the address agents dial and the SAN source of the hub's server
        credential — a hostname that resolves directly to this machine. v1 allows one
        hub per realm.
      </p>
    </DialogFrame>
  );
}

/// `[ingress.<node>]` — create or edit a public entry point.
export function IngressNodeDialog({
  initial,
  busy,
  onConfirm,
  onClose,
}: {
  initial: IngressNodeDto | null;
  busy: boolean;
  onConfirm: (edit: {
    node: string;
    workspaces: string[];
    listen: string;
    control_listen: string;
    edge_rate: number | null;
  }) => void;
  onClose: () => void;
}) {
  const [node, setNode] = useState(initial?.node ?? "");
  const [workspaces, setWorkspaces] = useState(initial?.workspaces.join(", ") ?? "");
  const [listen, setListen] = useState(
    initial && initial.listen !== "0.0.0.0:443" ? initial.listen : "",
  );
  const [controlListen, setControlListen] = useState(
    initial && initial.control_listen !== "127.0.0.1:16666" ? initial.control_listen : "",
  );
  const [edgeRate, setEdgeRate] = useState(
    initial?.edge_rate_per_ip_per_minute != null
      ? String(initial.edge_rate_per_ip_per_minute)
      : "",
  );
  const rateNum = edgeRate.trim() === "" ? null : Number(edgeRate.trim());
  return (
    <DialogFrame
      title={initial ? `Ingress ${initial.node}` : "New ingress node"}
      onClose={onClose}
      busy={busy}
      onConfirm={() =>
        onConfirm({
          node: node.trim(),
          workspaces: workspaces
            .split(",")
            .map((w) => w.trim())
            .filter((w) => w !== ""),
          listen: listen.trim(),
          control_listen: controlListen.trim(),
          edge_rate:
            rateNum != null && Number.isFinite(rateNum) && rateNum > 0
              ? Math.floor(rateNum)
              : null,
        })
      }
    >
      <div className="rule-row">
        {field(node, setNode, "edge", "120px")}
        {field(workspaces, setWorkspaces, "workspaces, comma-separated (default)")}
      </div>
      <div className="rule-row">
        <label className="hint">public listen</label>
        {field(listen, setListen, "blank = 0.0.0.0:443", "200px")}
        <label className="hint">control listen</label>
        {field(controlListen, setControlListen, "blank = 127.0.0.1:16666", "200px")}
      </div>
      <div className="rule-row">
        <label className="hint">per-IP new-conn/min</label>
        {field(edgeRate, setEdgeRate, "blank = engine default (fronted 600 / direct 30)", "260px")}
      </div>
    </DialogFrame>
  );
}

/// Whole-node creation inside the Form view — the issue wizard's node
/// fields minus its paths: the document being edited is the target, and
/// the role split (one pack, one role) is enforced by the same core.
export function CreateNodeDialog({
  busy,
  onConfirm,
  onClose,
}: {
  busy: boolean;
  onConfirm: (spec: {
    kind: IssueNodeKindDto;
    node: string;
    workspace: string;
    services: IssueServiceSpecDto[];
    mesh_ingress: IssueMeshIngressDto[];
    mesh_egress: IssueMeshEgressDto[];
    ingress_workspaces: string[];
    hub_endpoint: string;
  }) => void;
  onClose: () => void;
}) {
  const [kind, setKind] = useState<IssueNodeKindDto>("agent_mesh");
  const [node, setNode] = useState("");
  const [workspace, setWorkspace] = useState("");
  const [services, setServices] = useState<IssueServiceSpecDto[]>([]);
  const [meshIngress, setMeshIngress] = useState<IssueMeshIngressDto[]>([]);
  const [meshEgress, setMeshEgress] = useState<IssueMeshEgressDto[]>([]);
  const [ingressWorkspaces, setIngressWorkspaces] = useState("");
  const [hubEndpoint, setHubEndpoint] = useState("");

  const kinds: [IssueNodeKindDto, string][] = [
    ["agent_mesh", "Mesh agent"],
    ["agent_expose", "Expose agent"],
    ["hub", "Hub"],
    ["ingress", "Ingress"],
  ];

  return (
    <DialogFrame
      title="Add node to the manifest"
      onClose={onClose}
      busy={busy}
      confirmLabel="Add"
      onConfirm={() =>
        onConfirm({
          kind,
          node: node.trim(),
          workspace: workspace.trim(),
          services,
          mesh_ingress: meshIngress,
          mesh_egress: meshEgress,
          ingress_workspaces: ingressWorkspaces
            .split(",")
            .map((w) => w.trim())
            .filter((w) => w !== ""),
          hub_endpoint: hubEndpoint.trim(),
        })
      }
    >
      <div className="issue-kinds">
        {kinds.map(([value, label]) => (
          <button
            key={value}
            className={kind === value ? "selected" : ""}
            onClick={() => setKind(value)}
          >
            {label}
          </button>
        ))}
      </div>
      <div className="rule-row">
        {field(node, setNode, "node name", "140px")}
        {(kind === "agent_mesh" || kind === "agent_expose") &&
          field(workspace, setWorkspace, "workspace (blank = sole/default)")}
        {kind === "hub" && field(hubEndpoint, setHubEndpoint, "mesh.example.com:6666")}
        {kind === "ingress" &&
          field(ingressWorkspaces, setIngressWorkspaces, "workspaces, comma-separated")}
      </div>

      {kind === "agent_expose" && (
        <div className="rule-editor">
          <div className="rule-editor-head">
            <span>Services</span>
            <button onClick={() => setServices([...services, { id: "", address: "" }])}>
              + service
            </button>
          </div>
          {services.map((s, i) => (
            <div className="rule-row" key={i}>
              {field(
                s.id,
                (v) => setServices(services.map((r, j) => (j === i ? { ...r, id: v } : r))),
                "asr",
                "110px",
              )}
              {field(
                s.address,
                (v) => setServices(services.map((r, j) => (j === i ? { ...r, address: v } : r))),
                "127.0.0.1:8080",
              )}
              <button
                className="rule-remove"
                onClick={() => setServices(services.filter((_, j) => j !== i))}
              >
                ×
              </button>
            </div>
          ))}
        </div>
      )}

      {kind === "agent_mesh" && (
        <>
          <div className="rule-editor">
            <div className="rule-editor-head">
              <span>Mesh ingress — forward a local listener to a peer</span>
              <button
                onClick={() =>
                  setMeshIngress([
                    ...meshIngress,
                    { name: "", listen: "", protocol: "tcp", target_agent: "", remote_addr: "" },
                  ])
                }
              >
                + rule
              </button>
            </div>
            {meshIngress.map((r, i) => {
              const patch = (p: Partial<IssueMeshIngressDto>) =>
                setMeshIngress(meshIngress.map((row, j) => (j === i ? { ...row, ...p } : row)));
              return (
                <div className="rule-row" key={i}>
                  {field(r.name, (v) => patch({ name: v }), "ollama", "100px")}
                  {field(r.listen, (v) => patch({ listen: v }), "127.0.0.1:11434", "160px")}
                  {protocolSelect(r.protocol, (p) => patch({ protocol: p }))}
                  {field(r.target_agent, (v) => patch({ target_agent: v }), "→ agent", "100px")}
                  {field(r.remote_addr, (v) => patch({ remote_addr: v }), "127.0.0.1:11434", "160px")}
                  <button
                    className="rule-remove"
                    onClick={() => setMeshIngress(meshIngress.filter((_, j) => j !== i))}
                  >
                    ×
                  </button>
                </div>
              );
            })}
          </div>
          <div className="rule-editor">
            <div className="rule-editor-head">
              <span>Mesh egress — what this agent dials for peers</span>
              <button
                onClick={() =>
                  setMeshEgress([
                    ...meshEgress,
                    { name: "", protocol: "tcp", target: null, target_cidr: null },
                  ])
                }
              >
                + rule
              </button>
            </div>
            {meshEgress.map((r, i) => {
              const patch = (p: Partial<IssueMeshEgressDto>) =>
                setMeshEgress(meshEgress.map((row, j) => (j === i ? { ...row, ...p } : row)));
              return (
                <div className="rule-row" key={i}>
                  {field(r.name, (v) => patch({ name: v }), "loopback", "120px")}
                  {protocolSelect(r.protocol, (p) => patch({ protocol: p }))}
                  {field(
                    r.target ?? r.target_cidr ?? "",
                    (v) =>
                      patch(
                        v.includes("/")
                          ? { target: null, target_cidr: v }
                          : { target: v, target_cidr: null },
                      ),
                    "127.0.0.1:8080 or 127.0.0.0/8",
                  )}
                  <button
                    className="rule-remove"
                    onClick={() => setMeshEgress(meshEgress.filter((_, j) => j !== i))}
                  >
                    ×
                  </button>
                </div>
              );
            })}
            <p className="hint">
              The peer's egress must already authorize the remote address (protocol
              included); the validator refuses unmatched pairs.
            </p>
          </div>
        </>
      )}
      <p className="hint">
        An agent declares services <em>or</em> mesh rules — one pack, one role. The edit
        lands in the document (nothing is issued until Apply).
      </p>
    </DialogFrame>
  );
}
