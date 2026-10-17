import { useMemo, useState } from "react";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import { X } from "lucide-react";
import { api, type DeployContextDto, type IssueNodeParams } from "../api";
import { useT, type TFn } from "../i18n";
import RecentContextSelect from "./RecentContextSelect";
import {
  Button,
  DialogFooter,
  DialogTitle,
  Hint,
  Input,
  Modal,
  SegmentedControl,
  Select,
  useToast,
} from "./ui";

/// The issue wizard: one modal from "a new machine needs a pack" to a
/// sealed `.iflowpack` in Downloads. The user supplies exactly the two
/// security-relevant facts (node name, authorization scope); the manifest
/// append, validation, apply and sealing are orchestrated underneath
type Kind = IssueNodeParams["kind"];

/// Kind labels stay product vocabulary in both languages; the blurb
/// translates (same vocabulary as the node cards' kindBlurb).
const kinds = (t: TFn): { value: Kind; label: string; blurb: string }[] => [
  { value: "agent_mesh", label: "Mesh agent", blurb: t("issue.blurbMesh") },
  {
    value: "agent_expose",
    label: "Expose agent",
    blurb: t("issue.blurbExpose"),
  },
  { value: "hub", label: "Hub", blurb: t("issue.blurbHub") },
  { value: "ingress", label: "Ingress", blurb: t("kindBlurb.ingress") },
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
  widthClass?: string,
) => (
  <Input
    aria-label={placeholder}
    className={widthClass}
    value={value}
    placeholder={placeholder}
    onChange={(e) => onChange(e.target.value)}
    autoCapitalize="none"
    autoCorrect="off"
    spellCheck={false}
    autoComplete="off"
  />
);

const protocolSelect = (
  value: "tcp" | "udp",
  disabled: boolean,
  onChange: (v: "tcp" | "udp") => void,
) => (
  <Select
    ariaLabel="protocol"
    value={value}
    disabled={disabled}
    onValueChange={(v) => onChange(v as "tcp" | "udp")}
    options={[
      { value: "tcp", label: "tcp" },
      { value: "udp", label: "udp" },
    ]}
    className="w-[92px]"
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
  onAddHere,
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
  /// The done screen's "add on this machine now" entry (the new IA's
  /// dead-end fix): receives the rendered pack directory. Optional —
  /// absent hides the button.
  onAddHere?: (packDir: string) => void;
  onClose: () => void;
}) {
  const [kind, setKind] = useState<Kind>("agent_mesh");
  const [node, setNode] = useState("");
  const [workspace, setWorkspace] = useState("");
  const [services, setServices] = useState<ServiceRow[]>([
    { id: "", address: "" },
  ]);
  const [meshIngress, setMeshIngress] = useState<MeshIngressRow[]>([
    {
      name: "",
      listen: "",
      protocol: "tcp",
      target_agent: "",
      remote_addr: "",
    },
  ]);
  const [meshEgress, setMeshEgress] = useState<MeshEgressRow[]>([]);
  const [ingressWorkspaces, setIngressWorkspaces] = useState("default");
  const [hubEndpoint, setHubEndpoint] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState<Done | null>(null);
  const toast = useToast();
  const { t } = useT();
  const KINDS = kinds(t);

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
        lines.push(
          ``,
          `[[agent.${trimmed}.services]]`,
          `id = "${s.id.trim()}"`,
          `address = "${s.address.trim()}"`,
        );
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
      lines.push(
        `[ingress.${trimmed}]`,
        `workspaces = [${ingressWorkspaces
          .split(",")
          .map((w) => `"${w.trim()}"`)
          .join(", ")}]`,
      );
    }
    return lines.join("\n");
  }, [
    kind,
    trimmed,
    workspace,
    services,
    meshIngress,
    meshEgress,
    hubEndpoint,
    ingressWorkspaces,
  ]);

  const run = async (download: boolean) => {
    setBusy(true);
    setError(null);
    try {
      const outcome = await api.deployAddNode(buildParams());
      onSay([
        t("issue.appendedLine", {
          node: trimmed,
          manifest: manifest.trim(),
          pack: outcome.pack_dir_name,
        }),
      ]);
      onIssued(outcome.manifest_text);
      const report = await api.deployApply(
        manifest.trim(),
        issuer.trim(),
        out.trim(),
      );
      onSay(report.lines);
      if (download) {
        const passphrase = await api.deployGeneratePassphrase();
        const sealed = await api.deploySealToDownloads(
          `${out.trim()}/packs/${outcome.pack_dir_name}`,
          passphrase,
        );
        onSay([t("issue.sealedLine", { path: sealed.path })]);
        setDone({
          packDirName: outcome.pack_dir_name,
          filePath: sealed.path,
          passphrase,
        });
      } else {
        setDone({
          packDirName: outcome.pack_dir_name,
          filePath: null,
          passphrase: null,
        });
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
      toast.push(t("common.copied"));
    } catch {
      // Clipboard denied — the passphrase stays visible for manual copy.
    }
  };

  const active = busy || faceBusy;

  return (
    <Modal onClose={active ? () => {} : onClose} wide>
      <DialogTitle>{t("issue.title")}</DialogTitle>

      {done ? (
        <>
          <p className="m-0 text-base whitespace-pre-wrap text-fg-1">
            {done.passphrase
              ? t("issue.doneSealed", { name: done.packDirName })
              : t("issue.doneRendered", {
                  name: done.packDirName,
                  out: out.trim(),
                })}
          </p>
          {done.passphrase && (
            <div className="flex items-center gap-2">
              <code className="min-w-0 flex-1 rounded-lg border border-line bg-bg-3 p-2 font-mono text-base break-all text-fg-1">
                {done.passphrase}
              </code>
              <Button onClick={() => void copyPassphrase()}>
                {t("common.copy")}
              </Button>
            </div>
          )}
          {done.filePath && (
            <p className="m-0 text-small text-fg-3">{done.filePath}</p>
          )}
          <p className="m-0 text-small text-fg-3">
            {t("issue.manifestRewritten")}
          </p>
          <DialogFooter>
            {onAddHere && (
              <Button
                variant="secondary"
                onClick={() =>
                  onAddHere(`${out.trim()}/packs/${done.packDirName}`)
                }
              >
                {t("dep.node.addHere")}
              </Button>
            )}
            <Button variant="primary" onClick={onClose}>
              {t("common.done")}
            </Button>
          </DialogFooter>
        </>
      ) : (
        <>
          {recentContexts.length > 1 && (
            <div className="flex items-center gap-2">
              <span className="w-[140px] shrink-0 text-base text-fg-2">
                {t("issue.context")}
              </span>
              <RecentContextSelect
                contexts={recentContexts}
                current={{ manifest, issuer, out }}
                onPick={onPickContext}
              />
            </div>
          )}

          <SegmentedControl
            value={kind}
            options={KINDS.map((k) => ({
              value: k.value,
              label: k.label,
              title: k.blurb,
            }))}
            onChange={setKind}
            disabled={active}
          />

          <div className="flex items-center gap-2">
            <span className="w-[140px] shrink-0 text-base text-fg-2">
              {t("issue.nodeName")}
            </span>
            {field(node, setNode, "home-win")}
          </div>

          {(kind === "agent_expose" || kind === "agent_mesh") && (
            <div className="flex items-center gap-2">
              <span className="w-[140px] shrink-0 text-base text-fg-2">
                {t("issue.workspace")}
              </span>
              {field(workspace, setWorkspace, t("issue.workspacePh"))}
            </div>
          )}
          {kind === "hub" && (
            <div className="flex items-center gap-2">
              <span className="w-[140px] shrink-0 text-base text-fg-2">
                {t("issue.endpoint")}
              </span>
              {field(hubEndpoint, setHubEndpoint, "mesh.example.com:6666")}
            </div>
          )}
          {kind === "ingress" && (
            <div className="flex items-center gap-2">
              <span className="w-[140px] shrink-0 text-base text-fg-2">
                {t("issue.workspaces")}
              </span>
              {field(ingressWorkspaces, setIngressWorkspaces, "default")}
            </div>
          )}

          {kind === "agent_expose" && (
            <div className="flex flex-col gap-1 rounded-lg border border-dashed border-line p-2">
              <div className="flex items-center justify-between gap-2 text-small text-fg-3">
                <span>{t("issue.services")}</span>
                <Button
                  size="sm"
                  disabled={active}
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
                    "w-[120px]",
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
                      disabled={active}
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
            <div className="flex flex-col gap-1 rounded-lg border border-dashed border-line p-2">
              <div className="flex items-center justify-between gap-2 text-small text-fg-3">
                <span>{t("form.meshIngressTitle")}</span>
                <Button
                  size="sm"
                  disabled={active}
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
                const patch = (p: Partial<MeshIngressRow>) =>
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
                      "w-[110px]",
                    )}
                    {field(
                      r.listen,
                      (v) => patch({ listen: v }),
                      "127.0.0.1:11434",
                      "w-[170px]",
                    )}
                    {protocolSelect(r.protocol, active, (p) =>
                      patch({ protocol: p }),
                    )}
                    {field(
                      r.target_agent,
                      (v) => patch({ target_agent: v }),
                      t("issue.phPeerAgent"),
                      "w-[110px]",
                    )}
                    {field(
                      r.remote_addr,
                      (v) => patch({ remote_addr: v }),
                      "127.0.0.1:11434",
                      "w-[170px]",
                    )}
                    <Hint text={t("common.remove")}>
                      <Button
                        variant="link"
                        size="icon-sm"
                        disabled={active}
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
              <div className="flex items-center justify-between gap-2 text-small text-fg-3">
                <Hint text={t("dialogs.peerAuthHint")}>
                  <span>{t("form.meshEgressTitle")}</span>
                </Hint>
                <Button
                  size="sm"
                  disabled={active}
                  onClick={() =>
                    setMeshEgress([
                      ...meshEgress,
                      { name: "", protocol: "tcp", target: "" },
                    ])
                  }
                >
                  {t("common.addRule")}
                </Button>
              </div>
              {meshEgress.map((r, i) => {
                const patch = (p: Partial<MeshEgressRow>) =>
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
                      "w-[110px]",
                    )}
                    {protocolSelect(r.protocol, active, (p) =>
                      patch({ protocol: p }),
                    )}
                    {field(
                      r.target,
                      (v) => patch({ target: v }),
                      t("dialogs.phEgressTarget"),
                    )}
                    <Hint text={t("common.remove")}>
                      <Button
                        variant="link"
                        size="icon-sm"
                        disabled={active}
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
          )}

          {preview !== "" && (
            <div className="flex flex-col gap-1">
              <span className="text-small text-fg-3">
                {t("issue.willAppend")}
              </span>
              <pre className="m-0 overflow-x-auto rounded-lg border border-line bg-bg-3 p-2.5 font-mono text-small text-fg-2">
                {preview}
              </pre>
            </div>
          )}

          {error && (
            <div className="rounded-lg border border-critical/40 bg-critical/10 p-2.5 text-base whitespace-pre-wrap text-critical">
              {error}
            </div>
          )}

          <DialogFooter>
            <Button disabled={active} onClick={onClose}>
              {t("common.cancel")}
            </Button>
            <Button disabled={active || !ready} onClick={() => void run(false)}>
              {t("issue.issueOnly")}
            </Button>
            <Button
              variant="primary"
              disabled={active || !ready}
              onClick={() => void run(true)}
            >
              {busy ? "…" : t("issue.issueDownload")}
            </Button>
          </DialogFooter>
        </>
      )}
    </Modal>
  );
}
