import { useState, type ReactNode } from "react";
import { X } from "lucide-react";
import { useT } from "../i18n";
import {
  Button,
  DialogFooter,
  DialogTitle,
  Hint,
  InfoHint,
  Input,
  Modal,
  SegmentedControl,
  Select,
} from "./ui";
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
  widthClass?: string,
): ReactNode {
  return (
    <Input
      aria-label={placeholder}
      className={widthClass}
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
    <Select
      ariaLabel="protocol"
      value={value}
      onValueChange={(v) => set(v as MeshProtocolDto)}
      options={[
        { value: "tcp", label: "tcp" },
        { value: "udp", label: "udp" },
      ]}
      className="w-[92px]"
    />
  );
}

function DialogFrame({
  title,
  /// One-liner riding an ⓘ beside the title — the dialog-level
  /// explanation that used to be a permanent footer paragraph.
  hint,
  onClose,
  busy,
  onConfirm,
  confirmLabel,
  children,
}: {
  title: string;
  hint?: string;
  onClose: () => void;
  busy: boolean;
  onConfirm: () => void;
  confirmLabel?: string;
  children: ReactNode;
}) {
  const { t } = useT();
  return (
    <Modal onClose={onClose} wide>
      <DialogTitle>
        {title}
        {hint && <InfoHint text={hint} className="relative -top-px" />}
      </DialogTitle>
      <div className="flex flex-col gap-2 rounded-lg border border-dashed border-line p-2.5">
        {children}
      </div>
      <DialogFooter>
        <Button disabled={busy} onClick={onClose}>
          {t("common.cancel")}
        </Button>
        <Button variant="primary" disabled={busy} onClick={onConfirm}>
          {confirmLabel ?? t("common.apply")}
        </Button>
      </DialogFooter>
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
  const { t } = useT();
  return (
    <DialogFrame
      title={
        initial
          ? t("dialogs.serviceTitle", { id: initial.id, agent })
          : t("dialogs.newServiceTitle", { agent })
      }
      hint={t("dialogs.serviceHint")}
      onClose={onClose}
      busy={busy}
      onConfirm={() => onConfirm({ id: id.trim(), address: address.trim() })}
    >
      <div className="flex min-w-0 flex-wrap items-center gap-1.5">
        {field(id, setId, "asr", "w-[110px]")}
        {field(address, setAddress, "127.0.0.1:8080")}
      </div>
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
  const [protocol, setProtocol] = useState<MeshProtocolDto>(
    initial?.protocol ?? "tcp",
  );
  const [targetAgent, setTargetAgent] = useState(initial?.target_agent ?? "");
  const [remoteAddr, setRemoteAddr] = useState(initial?.remote_addr ?? "");
  const [idle, setIdle] = useState(
    initial?.idle_timeout_secs != null ? String(initial.idle_timeout_secs) : "",
  );
  const idleNum = idle.trim() === "" ? null : Number(idle.trim());
  const { t } = useT();
  return (
    <DialogFrame
      title={
        initial
          ? t("dialogs.ruleTitle", { name: initial.name, agent })
          : t("dialogs.newIngressRuleTitle", { agent })
      }
      hint={t("dialogs.ingressRuleHint")}
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
      <div className="flex min-w-0 flex-wrap items-center gap-1.5">
        {field(name, setName, "ollama", "w-[110px]")}
        {field(listen, setListen, t("dialogs.phListen"), "w-[190px]")}
        {protocolSelect(protocol, setProtocol)}
        {field(
          targetAgent,
          setTargetAgent,
          t("dialogs.phToAgent"),
          "w-[110px]",
        )}
        {field(remoteAddr, setRemoteAddr, t("dialogs.phRemote"), "w-[190px]")}
      </div>
      <div className="flex min-w-0 flex-wrap items-center gap-1.5">
        <label className="text-small text-fg-3">
          {t("dialogs.idleTimeoutLabel")}
        </label>
        {field(idle, setIdle, t("dialogs.idlePh"), "w-[220px]")}
      </div>
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
  const [protocol, setProtocol] = useState<MeshProtocolDto>(
    initial?.protocol ?? "tcp",
  );
  const [target, setTarget] = useState(
    initial?.target_addr ?? initial?.target_cidr ?? "",
  );
  const [idle, setIdle] = useState(
    initial?.udp_idle_timeout_secs != null
      ? String(initial.udp_idle_timeout_secs)
      : "",
  );
  const idleNum = idle.trim() === "" ? null : Number(idle.trim());
  const { t } = useT();
  return (
    <DialogFrame
      title={
        initial
          ? t("dialogs.ruleTitle", { name: initial.name, agent })
          : t("dialogs.newEgressRuleTitle", { agent })
      }
      hint={t("dialogs.egressRuleHint")}
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
      <div className="flex min-w-0 flex-wrap items-center gap-1.5">
        {field(name, setName, "loopback-services", "w-[160px]")}
        {protocolSelect(protocol, setProtocol)}
        {field(target, setTarget, t("dialogs.phEgressTarget"))}
      </div>
      <div className="flex min-w-0 flex-wrap items-center gap-1.5">
        <label className="text-small text-fg-3">
          {t("dialogs.udpIdleLabel")}
        </label>
        {field(idle, setIdle, t("dialogs.udpIdlePh"), "w-[160px]")}
      </div>
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
  const { t } = useT();
  return (
    <DialogFrame
      title={
        initial
          ? t("dialogs.routeTitle", { host: initial.host })
          : t("dialogs.newRouteTitle")
      }
      hint={t("dialogs.routeHint")}
      onClose={onClose}
      busy={busy}
      onConfirm={() =>
        onConfirm({ host: host.trim(), service: service.trim() })
      }
    >
      <div className="flex min-w-0 flex-wrap items-center gap-1.5">
        {field(host, setHost, "app.example.com", "w-[220px]")}
        <span className="text-small text-fg-3">→</span>
        {field(service, setService, "workspace/agent/service")}
      </div>
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
  onConfirm: (edit: {
    name: string;
    endpoint: string;
    listen: string;
    quic_listen: string;
  }) => void;
  onClose: () => void;
}) {
  const [name, setName] = useState(initial?.name ?? "");
  const [endpoint, setEndpoint] = useState(initial?.endpoint ?? "");
  const [listen, setListen] = useState(
    initial && initial.listen !== "0.0.0.0:6666" ? initial.listen : "",
  );
  const [quicListen, setQuicListen] = useState(initial?.quic_listen ?? "");
  const { t } = useT();
  return (
    <DialogFrame
      title={
        initial
          ? t("dialogs.hubTitle", { name: initial.name })
          : t("dialogs.newHubTitle")
      }
      hint={t("dialogs.hubHint")}
      onClose={onClose}
      busy={busy}
      onConfirm={() =>
        onConfirm({
          name: name.trim(),
          endpoint: endpoint.trim(),
          listen: listen.trim(),
          quic_listen: quicListen.trim(),
        })
      }
    >
      {initial ? (
        <div className="flex items-center gap-2">
          <label className="w-[140px] shrink-0 text-base text-fg-2">
            {t("dialogs.nameLabel")}
          </label>
          <Input value={name} readOnly />
        </div>
      ) : (
        <div className="flex min-w-0 flex-wrap items-center gap-1.5">
          {field(name, setName, t("dialogs.phHubName"), "w-[140px]")}
          {field(endpoint, setEndpoint, t("dialogs.phHubEndpoint"))}
        </div>
      )}
      {initial && (
        <div className="flex min-w-0 flex-wrap items-center gap-1.5">
          {field(endpoint, setEndpoint, "mesh.example.com:6666")}
        </div>
      )}
      <div className="flex min-w-0 flex-wrap items-center gap-1.5">
        <label className="text-small text-fg-3">
          {t("dialogs.listenLabel")}
        </label>
        {field(listen, setListen, t("dialogs.phBlankHubListen"), "w-[220px]")}
        <label className="text-small text-fg-3">
          {t("dialogs.quicListenLabel")}
        </label>
        {field(
          quicListen,
          setQuicListen,
          t("dialogs.phBlankQuicHub"),
          "w-[260px]",
        )}
      </div>
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
    quic_listen: string;
    edge_rate: number | null;
  }) => void;
  onClose: () => void;
}) {
  const [node, setNode] = useState(initial?.node ?? "");
  const [workspaces, setWorkspaces] = useState(
    initial?.workspaces.join(", ") ?? "",
  );
  const [listen, setListen] = useState(
    initial && initial.listen !== "0.0.0.0:443" ? initial.listen : "",
  );
  const [controlListen, setControlListen] = useState(
    initial && initial.control_listen !== "127.0.0.1:16666"
      ? initial.control_listen
      : "",
  );
  const [quicListen, setQuicListen] = useState(initial?.quic_listen ?? "");
  const [edgeRate, setEdgeRate] = useState(
    initial?.edge_rate_per_ip_per_minute != null
      ? String(initial.edge_rate_per_ip_per_minute)
      : "",
  );
  const rateNum = edgeRate.trim() === "" ? null : Number(edgeRate.trim());
  const { t } = useT();
  return (
    <DialogFrame
      title={
        initial
          ? t("dialogs.ingressTitle", { node: initial.node })
          : t("dialogs.newIngressTitle")
      }
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
          quic_listen: quicListen.trim(),
          edge_rate:
            rateNum != null && Number.isFinite(rateNum) && rateNum > 0
              ? Math.floor(rateNum)
              : null,
        })
      }
    >
      <div className="flex min-w-0 flex-wrap items-center gap-1.5">
        {field(node, setNode, "edge", "w-[120px]")}
        {field(workspaces, setWorkspaces, t("dialogs.phWorkspacesDefault"))}
      </div>
      <div className="flex min-w-0 flex-wrap items-center gap-1.5">
        <label className="text-small text-fg-3">
          {t("dialogs.publicListen")}
        </label>
        {field(listen, setListen, t("dialogs.phBlank443"), "w-[200px]")}
        <label className="text-small text-fg-3">
          {t("dialogs.controlListen")}
        </label>
        {field(
          controlListen,
          setControlListen,
          t("dialogs.phBlankControl"),
          "w-[200px]",
        )}
      </div>
      <div className="flex min-w-0 flex-wrap items-center gap-1.5">
        <label className="text-small text-fg-3">
          {t("dialogs.quicListenLabel")}
        </label>
        {field(
          quicListen,
          setQuicListen,
          t("dialogs.phBlankQuicIngress"),
          "w-[260px]",
        )}
      </div>
      <div className="flex min-w-0 flex-wrap items-center gap-1.5">
        <label className="text-small text-fg-3">{t("dialogs.rateLabel")}</label>
        {field(edgeRate, setEdgeRate, t("dialogs.phRate"), "w-[260px]")}
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
  const { t } = useT();

  const kinds: [IssueNodeKindDto, string][] = [
    ["agent_mesh", "Mesh agent"],
    ["agent_expose", "Expose agent"],
    ["hub", "Hub"],
    ["ingress", "Ingress"],
  ];

  return (
    <DialogFrame
      title={t("dialogs.addNodeTitle")}
      hint={t("dialogs.onePackOneRole")}
      onClose={onClose}
      busy={busy}
      confirmLabel={t("dialogs.addConfirm")}
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
      <SegmentedControl
        value={kind}
        options={kinds.map(([value, label]) => ({ value, label }))}
        onChange={setKind}
      />
      <div className="flex min-w-0 flex-wrap items-center gap-1.5">
        {field(node, setNode, t("dialogs.phNodeName"), "w-[140px]")}
        {(kind === "agent_mesh" || kind === "agent_expose") &&
          field(workspace, setWorkspace, t("dialogs.phWorkspace"))}
        {kind === "hub" &&
          field(hubEndpoint, setHubEndpoint, "mesh.example.com:6666")}
        {kind === "ingress" &&
          field(
            ingressWorkspaces,
            setIngressWorkspaces,
            t("dialogs.phWorkspaces"),
          )}
      </div>

      {kind === "agent_expose" && (
        <div className="flex flex-col gap-1 rounded-lg border border-dashed border-line p-2">
          <div className="flex items-center justify-between gap-2 text-small text-fg-3">
            <span>{t("issue.services")}</span>
            <Button
              size="sm"
              onClick={() =>
                setServices([...services, { id: "", address: "" }])
              }
            >
              {t("common.addService")}
            </Button>
          </div>
          {services.map((s, i) => (
            <div
              className="flex min-w-0 flex-wrap items-center gap-1.5"
              key={i}
            >
              {field(
                s.id,
                (v) =>
                  setServices(
                    services.map((r, j) => (j === i ? { ...r, id: v } : r)),
                  ),
                "asr",
                "110px",
              )}
              {field(
                s.address,
                (v) =>
                  setServices(
                    services.map((r, j) =>
                      j === i ? { ...r, address: v } : r,
                    ),
                  ),
                "127.0.0.1:8080",
              )}
              <Hint text={t("common.remove")}>
                <Button
                  variant="link"
                  size="icon-sm"
                  aria-label={t("common.remove")}
                  onClick={() =>
                    setServices(services.filter((_, j) => j !== i))
                  }
                  className="text-fg-3 hover:text-critical"
                >
                  <X className="size-3.5" />
                </Button>
              </Hint>
            </div>
          ))}
        </div>
      )}

      {kind === "agent_mesh" && (
        <>
          <div className="flex flex-col gap-1 rounded-lg border border-dashed border-line p-2">
            <div className="flex items-center justify-between gap-2 text-small text-fg-3">
              <span>{t("form.meshIngressTitle")}</span>
              <Button
                size="sm"
                onClick={() =>
                  setMeshIngress([
                    ...meshIngress,
                    {
                      name: "",
                      listen: "",
                      protocol: "tcp",
                      target_agent: "",
                      remote_addr: "",
                    },
                  ])
                }
              >
                {t("common.addRule")}
              </Button>
            </div>
            {meshIngress.map((r, i) => {
              const patch = (p: Partial<IssueMeshIngressDto>) =>
                setMeshIngress(
                  meshIngress.map((row, j) =>
                    j === i ? { ...row, ...p } : row,
                  ),
                );
              return (
                <div
                  className="flex min-w-0 flex-wrap items-center gap-1.5"
                  key={i}
                >
                  {field(
                    r.name,
                    (v) => patch({ name: v }),
                    "ollama",
                    "w-[100px]",
                  )}
                  {field(
                    r.listen,
                    (v) => patch({ listen: v }),
                    "127.0.0.1:11434",
                    "w-[160px]",
                  )}
                  {protocolSelect(r.protocol, (p) => patch({ protocol: p }))}
                  {field(
                    r.target_agent,
                    (v) => patch({ target_agent: v }),
                    t("dialogs.phToAgent"),
                    "w-[100px]",
                  )}
                  {field(
                    r.remote_addr,
                    (v) => patch({ remote_addr: v }),
                    "127.0.0.1:11434",
                    "w-[160px]",
                  )}
                  <Hint text={t("common.remove")}>
                    <Button
                      variant="link"
                      size="icon-sm"
                      aria-label={t("common.remove")}
                      onClick={() =>
                        setMeshIngress(meshIngress.filter((_, j) => j !== i))
                      }
                      className="text-fg-3 hover:text-critical"
                    >
                      <X className="size-3.5" />
                    </Button>
                  </Hint>
                </div>
              );
            })}
          </div>
          <div className="flex flex-col gap-1 rounded-lg border border-dashed border-line p-2">
            <div className="flex items-center justify-between gap-2 text-small text-fg-3">
              <Hint text={t("dialogs.peerAuthHint")}>
                <span>{t("form.meshEgressTitle")}</span>
              </Hint>
              <button
                className="sm"
                onClick={() =>
                  setMeshEgress([
                    ...meshEgress,
                    {
                      name: "",
                      protocol: "tcp",
                      target: null,
                      target_cidr: null,
                    },
                  ])
                }
              >
                {t("common.addRule")}
              </button>
            </div>
            {meshEgress.map((r, i) => {
              const patch = (p: Partial<IssueMeshEgressDto>) =>
                setMeshEgress(
                  meshEgress.map((row, j) =>
                    j === i ? { ...row, ...p } : row,
                  ),
                );
              return (
                <div
                  className="flex min-w-0 flex-wrap items-center gap-1.5"
                  key={i}
                >
                  {field(
                    r.name,
                    (v) => patch({ name: v }),
                    "loopback",
                    "w-[120px]",
                  )}
                  {protocolSelect(r.protocol, (p) => patch({ protocol: p }))}
                  {field(
                    r.target ?? r.target_cidr ?? "",
                    (v) =>
                      patch(
                        v.includes("/")
                          ? { target: null, target_cidr: v }
                          : { target: v, target_cidr: null },
                      ),
                    t("dialogs.phEgressTarget"),
                  )}
                  <Hint text={t("common.remove")}>
                    <Button
                      variant="link"
                      size="icon-sm"
                      aria-label={t("common.remove")}
                      onClick={() =>
                        setMeshEgress(meshEgress.filter((_, j) => j !== i))
                      }
                      className="text-fg-3 hover:text-critical"
                    >
                      <X className="size-3.5" />
                    </Button>
                  </Hint>
                </div>
              );
            })}
          </div>
        </>
      )}
    </DialogFrame>
  );
}
