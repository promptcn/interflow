import { useState } from "react";
import { ChevronDown, ChevronRight, X } from "lucide-react";
import { useT, type TFn } from "../i18n";
import { Badge, Button, ConfirmDialog, Field, Hint, Input, SectionPanel, Select } from "./ui";
import {
  CreateNodeDialog,
  HubDialog,
  IngressNodeDialog,
  MeshEgressRuleDialog,
  MeshIngressRuleDialog,
  RouteDialog,
  ServiceDialog,
} from "./ManifestDialogs";
import type {
  AgentRoleDto,
  EditActionDto,
  ManifestSummaryDto,
  PublicTlsModeDto,
  IdentityModeDto,
} from "../api";

/// The Form view — a projection of the manifest document. Every change is
/// one structured edit through the document model (`onEdit`); nothing here
/// holds a second copy of the document, and no edit touches the file
/// (Save owns the write). Scalar sections keep a local draft with an
/// explicit Apply; list content (rules, services, routes) edits through
/// dialogs, one complete desired state per submission.
///
/// Frequency layering (2026-10-08 deploy-legibility backlog): the sections
/// day-to-day operations touch (streams on agents, ingress, routes) render
/// first and open; the deploy-time-once sections (realm, identity tier,
/// public TLS, hub, workspaces) fold into one collapsed group below — the
/// schema's full vocabulary stays one click away without fronting the
/// form with fields an operator touches once per deployment.

type Edit = (action: EditActionDto) => Promise<boolean>;

export default function ManifestForm({
  summary,
  busy,
  onEdit,
}: {
  summary: ManifestSummaryDto;
  busy: boolean;
  onEdit: Edit;
}) {
  const { t } = useT();
  const [deployTimeOpen, setDeployTimeOpen] = useState(false);
  return (
    <div className="flex flex-col gap-2.5">
      <AgentsSection
        key={JSON.stringify(summary.agents)}
        agents={summary.agents}
        workspaces={summary.workspaces}
        busy={busy}
        onEdit={onEdit}
      />
      <IngressSection
        key={JSON.stringify(summary.ingress)}
        ingress={summary.ingress}
        workspaces={summary.workspaces}
        busy={busy}
        onEdit={onEdit}
      />
      <RoutesSection
        key={JSON.stringify(summary.routes)}
        routes={summary.routes}
        busy={busy}
        onEdit={onEdit}
      />
      <div className="flex flex-col gap-2.5">
        <Hint text={t("form.deployTimeTitle")}>
          <Button
            variant="link"
            size="sm"
            className="self-start text-small uppercase tracking-[0.05em] text-fg-3"
            onClick={() => setDeployTimeOpen((v) => !v)}
          >
            {deployTimeOpen ? (
              <ChevronDown className="size-4" />
            ) : (
              <ChevronRight className="size-4" />
            )}
            {t("form.deployTime")}
          </Button>
        </Hint>
        {deployTimeOpen && (
          <>
            <RealmSection
              key={JSON.stringify(summary.realm)}
              realm={summary.realm}
              busy={busy}
              onEdit={onEdit}
            />
            <IdentitySection
              key={JSON.stringify(summary.identity)}
              identity={summary.identity}
              busy={busy}
              onEdit={onEdit}
            />
            <PublicTlsSection
              key={JSON.stringify(summary.public_tls)}
              tls={summary.public_tls}
              busy={busy}
              onEdit={onEdit}
            />
            <HubSection
              key={JSON.stringify(summary.hubs)}
              hubs={summary.hubs}
              busy={busy}
              onEdit={onEdit}
            />
            <WorkspaceSection
              key={JSON.stringify(summary.workspaces)}
              workspaces={summary.workspaces}
              busy={busy}
              onEdit={onEdit}
            />
          </>
        )}
      </div>
    </div>
  );
}

/// One section's Apply button + the "this writes into the document, not
/// the file" reminder when a draft diverges.
function SectionApply({
  disabled,
  label,
  onClick,
}: {
  disabled: boolean;
  label?: string;
  onClick: () => void;
}) {
  const { t } = useT();
  return (
    <div className="flex items-center gap-2">
      <Button variant="primary" disabled={disabled} onClick={onClick}>
        {label ?? t("common.apply")}
      </Button>
      <span className="text-small text-fg-3">{t("form.editsLandHint")}</span>
    </div>
  );
}

function RealmSection({
  realm,
  busy,
  onEdit,
}: {
  realm: ManifestSummaryDto["realm"];
  busy: boolean;
  onEdit: Edit;
}) {
  const [id, setId] = useState(realm.id);
  const [endpoint, setEndpoint] = useState(realm.control_endpoint);
  const { t } = useT();
  const dirty = id !== realm.id || endpoint !== realm.control_endpoint;
  const input = (value: string, set: (v: string) => void, placeholder: string, fieldId: string) => (
    <Input
      id={fieldId}
      value={value}
      placeholder={placeholder}
      onChange={(e) => set(e.target.value)}
      autoCapitalize="none"
      autoCorrect="off"
      spellCheck={false}
      autoComplete="off"
    />
  );
  return (
    <SectionPanel title={t("form.realmTitle")} hint={t("form.realmHint")}>
      <Field label={t("form.id")}>{(fieldId) => input(id, setId, "promptcn-mesh", fieldId)}</Field>
      <Field label={t("form.controlEndpoint")}>
        {(fieldId) => input(endpoint, setEndpoint, t("form.controlEndpointPh"), fieldId)}
      </Field>
      <SectionApply
        disabled={busy || !dirty}
        onClick={() => void onEdit({ SetRealm: { id, control_endpoint: endpoint } })}
      />
    </SectionPanel>
  );
}

function IdentitySection({
  identity,
  busy,
  onEdit,
}: {
  identity: ManifestSummaryDto["identity"];
  busy: boolean;
  onEdit: Edit;
}) {
  const [mode, setMode] = useState<IdentityModeDto>(identity.mode);
  const [leafTtl, setLeafTtl] = useState(identity.leaf_ttl ?? "");
  const [registrar, setRegistrar] = useState(identity.registrar_endpoint);
  const { t } = useT();
  const dirty =
    mode !== identity.mode ||
    leafTtl !== (identity.leaf_ttl ?? "") ||
    registrar !== identity.registrar_endpoint;
  const bounds = identity.leaf_ttl_bounds;
  return (
    <SectionPanel title={t("form.identityTitle")} hint={t("form.identityHint")}>
      <Field label={t("form.mode")}>
        {(id) => (
          <Select
            id={id}
            value={mode}
            onValueChange={(v) => setMode(v as IdentityModeDto)}
            options={[
              { value: "registrar", label: t("form.modeRegistrar") },
              { value: "offline", label: t("form.modeOffline") },
            ]}
          />
        )}
      </Field>
      <Field label={t("form.leafTtl")}>
        {(id) => (
          <Input
            id={id}
            value={leafTtl}
            placeholder={t("form.leafTtlPh", {
              def: bounds.default,
              min: bounds.min,
              max: bounds.max,
            })}
            onChange={(e) => setLeafTtl(e.target.value)}
            autoCapitalize="none"
            autoCorrect="off"
            spellCheck={false}
            autoComplete="off"
          />
        )}
      </Field>
      <Field label={t("manifest.registrarEndpoint")}>
        {(id) => (
          <Input
            id={id}
            value={registrar}
            placeholder={mode === "registrar" ? t("form.registrarPh") : t("form.registrarPhOffline")}
            onChange={(e) => setRegistrar(e.target.value)}
            autoCapitalize="none"
            autoCorrect="off"
            spellCheck={false}
            autoComplete="off"
          />
        )}
      </Field>
      <SectionApply
        disabled={busy || !dirty}
        onClick={() =>
          void onEdit({
            SetIdentity: {
              mode,
              leaf_ttl: leafTtl.trim() === "" ? null : leafTtl,
              registrar_endpoint: registrar.trim() === "" ? null : registrar,
            },
          })
        }
      />
    </SectionPanel>
  );
}

function PublicTlsSection({
  tls,
  busy,
  onEdit,
}: {
  tls: ManifestSummaryDto["public_tls"];
  busy: boolean;
  onEdit: Edit;
}) {
  const [mode, setMode] = useState<PublicTlsModeDto>(tls.mode);
  const [email, setEmail] = useState(tls.email ?? "");
  const [directory, setDirectory] = useState(tls.directory ?? "");
  const { t } = useT();
  const dirty =
    mode !== tls.mode ||
    email !== (tls.email ?? "") ||
    directory !== (tls.directory ?? "");
  return (
    <SectionPanel title={t("form.publicTlsTitle")} hint={t("form.publicTlsHint")}>
      <Field label={t("form.mode")}>
        {(id) => (
          <Select
            id={id}
            value={mode}
            onValueChange={(v) => setMode(v as PublicTlsModeDto)}
            options={[
              { value: "acme", label: t("form.tlsAcme") },
              { value: "frontend-proxy", label: t("form.tlsFrontend") },
              { value: "manual", label: t("form.tlsManual") },
            ]}
          />
        )}
      </Field>
      {mode === "acme" && (
        <>
          <Field label={t("form.acmeEmail")}>
            {(id) => (
              <Input
                id={id}
                value={email}
                placeholder="ops@example.com"
                onChange={(e) => setEmail(e.target.value)}
                autoCapitalize="none"
                autoCorrect="off"
                spellCheck={false}
                autoComplete="off"
              />
            )}
          </Field>
          <Field label={t("form.acmeDirectory")}>
            {(id) => (
              <Input
                id={id}
                value={directory}
                placeholder={t("form.acmeDirectoryPh")}
                onChange={(e) => setDirectory(e.target.value)}
                autoCapitalize="none"
                autoCorrect="off"
                spellCheck={false}
                autoComplete="off"
              />
            )}
          </Field>
        </>
      )}
      <SectionApply
        disabled={busy || !dirty}
        onClick={() =>
          void onEdit({
            SetPublicTls: {
              mode,
              email: email.trim() === "" ? null : email,
              directory: directory.trim() === "" ? null : directory,
            },
          })
        }
      />
    </SectionPanel>
  );
}

function HubSection({
  hubs,
  busy,
  onEdit,
}: {
  hubs: ManifestSummaryDto["hubs"];
  busy: boolean;
  onEdit: Edit;
}) {
  const [dialog, setDialog] = useState<{ hub: ManifestSummaryDto["hubs"][number] | null } | null>(
    null,
  );
  const [removing, setRemoving] = useState<string | null>(null);
  const { t } = useT();
  return (
    <SectionPanel
      title={t("form.hubTitle")}
      hint={t("form.hubHint")}
      actions={
        hubs.length === 0 ? (
          <Button size="sm" disabled={busy} onClick={() => setDialog({ hub: null })}>
            {t("form.addHub")}
          </Button>
        ) : undefined
      }
    >
      {hubs.length === 0 && <p className="m-0 text-small text-fg-3">{t("form.noHub")}</p>}
      {hubs.map((hub) => (
        <div className="flex min-w-0 flex-wrap items-center gap-2" key={hub.name}>
          <span className="min-w-[90px] shrink-0 font-mono text-small">{hub.name}</span>
          <span className="font-mono text-small text-fg-2">{hub.endpoint}</span>
          <span className="text-small text-fg-3">listen {hub.listen}</span>
          {hub.quic_listen && <span className="text-small text-fg-3">· quic {hub.quic_listen}</span>}
          <span className="flex-1" />
          <Button size="sm" disabled={busy} onClick={() => setDialog({ hub })}>
            {t("common.edit")}
          </Button>
          <Button size="sm" variant="danger" disabled={busy} onClick={() => setRemoving(hub.name)}>
            {t("common.remove")}
          </Button>
        </div>
      ))}
      {dialog && (
        <HubDialog
          initial={dialog.hub}
          busy={busy}
          onClose={() => setDialog(null)}
          onConfirm={async (edit) => {
            const ok = await onEdit({
              UpsertHub: {
                name: edit.name,
                endpoint: edit.endpoint,
                listen: edit.listen || null,
                quic_listen: edit.quic_listen || null,
              },
            });
            if (ok) setDialog(null);
          }}
        />
      )}
      {removing !== null && (
        <ConfirmDialog
          title={t("form.hubRemoveTitle", { name: removing })}
          message={t("form.hubRemoveMessage")}
          confirmLabel={t("common.remove")}
          danger
          busy={busy}
          onConfirm={async () => {
            const ok = await onEdit({ RemoveHub: removing });
            if (ok) setRemoving(null);
          }}
          onClose={() => setRemoving(null)}
        />
      )}
    </SectionPanel>
  );
}

function WorkspaceSection({
  workspaces,
  busy,
  onEdit,
}: {
  workspaces: ManifestSummaryDto["workspaces"];
  busy: boolean;
  onEdit: Edit;
}) {
  const [name, setName] = useState("");
  const { t } = useT();
  return (
    <SectionPanel title={t("form.workspacesTitle")} hint={t("form.workspacesHint")}>
      <div className="flex flex-wrap items-center gap-1.5">
        {workspaces.map((ws) => (
          <span
            key={ws}
            className="inline-flex items-center gap-1 rounded-full border border-line px-2 py-px text-micro text-fg-2"
          >
            {ws}
            <Hint text={t("form.removeWsTitle")}>
              <Button
                variant="link"
                size="icon-sm"
                disabled={busy}
                aria-label={t("form.removeWsTitle")}
                onClick={() => void onEdit({ RemoveWorkspace: ws })}
                className="text-fg-3 hover:text-critical"
              >
                <X className="size-3.5" />
              </Button>
            </Hint>
          </span>
        ))}
        {workspaces.length === 0 && <span className="text-small text-fg-3">{t("form.noneDeclared")}</span>}
      </div>
      <div className="flex items-center gap-2">
        <Input
          aria-label={t("form.addWorkspace")}
          value={name}
          placeholder={t("form.newWorkspacePh")}
          onChange={(e) => setName(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && name.trim() !== "") {
              void onEdit({ UpsertWorkspace: name.trim() }).then((ok) => {
                if (ok) setName("");
              });
            }
          }}
          autoCapitalize="none"
          autoCorrect="off"
          spellCheck={false}
          autoComplete="off"
          className="max-w-[280px]"
        />
        <Button
          size="sm"
          disabled={busy || name.trim() === ""}
          onClick={() =>
            void onEdit({ UpsertWorkspace: name.trim() }).then((ok) => {
              if (ok) setName("");
            })
          }
        >
          {t("form.addWorkspace")}
        </Button>
      </div>
    </SectionPanel>
  );
}

const roleLabel = (role: AgentRoleDto, t: TFn): string => {
  switch (role) {
    case "expose":
      return t("form.roleExpose");
    case "mesh":
      return t("form.roleMesh");
    case "mixed":
      return t("form.roleMixed");
    case "empty":
      return t("form.roleEmpty");
  }
};

function AgentsSection({
  agents,
  workspaces,
  busy,
  onEdit,
}: {
  agents: ManifestSummaryDto["agents"];
  workspaces: string[];
  busy: boolean;
  onEdit: Edit;
}) {
  const [creating, setCreating] = useState(false);
  const [removing, setRemoving] = useState<string | null>(null);
  const [serviceDialog, setServiceDialog] = useState<{ agent: string; service: ManifestSummaryDto["agents"][number]["services"][number] | null } | null>(null);
  const [ingressDialog, setIngressDialog] = useState<{ agent: string; rule: ManifestSummaryDto["agents"][number]["mesh_ingress"][number] | null } | null>(null);
  const [egressDialog, setEgressDialog] = useState<{ agent: string; rule: ManifestSummaryDto["agents"][number]["mesh_egress"][number] | null } | null>(null);
  const { t } = useT();
  return (
    <SectionPanel
      title={t("form.agentsTitle")}
      hint={t("form.agentsHint")}
      actions={
        <Button disabled={busy} onClick={() => setCreating(true)}>
          {t("form.addNode")}
        </Button>
      }
    >
      {agents.map((agent) => (
        <div className="flex flex-col gap-1.5 rounded-lg border border-line bg-bg-3/60 p-2" key={agent.node}>
          <div className="flex min-w-0 flex-wrap items-center gap-2">
            <span className="min-w-[90px] shrink-0 font-mono text-small">{agent.node}</span>
            <Badge tone={agent.role === "mesh" || agent.role === "expose" ? "accent" : "critical"}>
              {roleLabel(agent.role, t)}
            </Badge>
            <Select
              value={agent.workspace}
              disabled={busy || workspaces.length < 2}
              title={
                workspaces.length < 2 ? t("form.singleWorkspaceTitle") : t("form.retargetWorkspaceTitle")
              }
              onValueChange={(ws) =>
                void onEdit({ SetAgentWorkspace: { agent: agent.node, workspace: ws } })
              }
              options={workspaces.map((ws) => ({ value: ws, label: ws }))}
              className="w-[140px]"
            />
            <Select
              value={agent.transport ?? "h2"}
              disabled={busy}
              title={t("form.transportTitle")}
              onValueChange={(v) =>
                void onEdit({
                  SetAgentTransport: {
                    agent: agent.node,
                    transport: v === "quic" ? "quic" : null,
                  },
                })
              }
              options={[
                { value: "h2", label: "h2" },
                { value: "quic", label: "quic" },
              ]}
              className="w-[110px]"
            />
            <span className="flex-1" />
            <Button size="sm" variant="danger" disabled={busy} onClick={() => setRemoving(agent.node)}>
              {t("common.remove")}
            </Button>
          </div>

          {(agent.role === "expose" || agent.role === "mixed") && (
            <div className="flex flex-col gap-1 rounded-lg border border-dashed border-line p-2">
              <div className="flex items-center justify-between gap-2 text-small text-fg-3">
                <span>{t("form.servicesExpose")}</span>
                <Button
                  size="sm"
                  disabled={busy}
                  onClick={() => setServiceDialog({ agent: agent.node, service: null })}
                >
                  {t("common.addService")}
                </Button>
              </div>
              {agent.services.map((s) => (
                <div className="flex min-w-0 flex-wrap items-center gap-2" key={s.id}>
                  <span className="min-w-[90px] shrink-0 font-mono text-small">{s.id}</span>
                  <span className="font-mono text-small text-fg-2">{s.address}</span>
                  <span className="flex-1" />
                  <Button size="sm" disabled={busy} onClick={() => setServiceDialog({ agent: agent.node, service: s })}>
                    {t("common.edit")}
                  </Button>
                  <Hint text={t("common.remove")}>
                    <Button
                      variant="link"
                      size="icon-sm"
                      disabled={busy}
                      aria-label={t("common.remove")}
                      onClick={() => void onEdit({ RemoveService: { agent: agent.node, id: s.id } })}
                      className="text-fg-3 hover:text-critical"
                    >
                      <X className="size-3.5" />
                    </Button>
                  </Hint>
                </div>
              ))}
            </div>
          )}

          {(agent.role === "mesh" || agent.role === "mixed") && (
            <>
              <div className="flex flex-col gap-1 rounded-lg border border-dashed border-line p-2">
                <div className="flex items-center justify-between gap-2 text-small text-fg-3">
                  <span>{t("form.meshIngressTitle")}</span>
                  <Button
                    size="sm"
                    disabled={busy}
                    onClick={() => setIngressDialog({ agent: agent.node, rule: null })}
                  >
                    {t("common.addRule")}
                  </Button>
                </div>
                {agent.mesh_ingress.map((r) => (
                  <div className="flex min-w-0 flex-wrap items-center gap-2" key={r.name}>
                    <span className="min-w-[90px] shrink-0 font-mono text-small">{r.name}</span>
                    <span className="font-mono text-small text-fg-2">{r.listen}</span>
                    <span className="text-small text-fg-3">{r.protocol === "udp" ? "udp" : "tcp"}</span>
                    <span className="font-mono text-small text-fg-2">
                      → {r.target_agent} @ {r.remote_addr}
                    </span>
                    {r.idle_timeout_secs != null && (
                      <span className="text-small text-fg-3">idle {r.idle_timeout_secs}s</span>
                    )}
                    <span className="flex-1" />
                    <Button size="sm" disabled={busy} onClick={() => setIngressDialog({ agent: agent.node, rule: r })}>
                      {t("common.edit")}
                    </Button>
                    <Hint text={t("common.remove")}>
                      <Button
                        variant="link"
                        size="icon-sm"
                        disabled={busy}
                        aria-label={t("common.remove")}
                        onClick={() =>
                          void onEdit({ RemoveMeshIngress: { agent: agent.node, name: r.name } })
                        }
                        className="text-fg-3 hover:text-critical"
                      >
                        <X className="size-3.5" />
                      </Button>
                    </Hint>
                  </div>
                ))}
              </div>
              <div className="flex flex-col gap-1 rounded-lg border border-dashed border-line p-2">
                <div className="flex items-center justify-between gap-2 text-small text-fg-3">
                  <span>{t("form.meshEgressTitle")}</span>
                  <Button
                    size="sm"
                    disabled={busy}
                    onClick={() => setEgressDialog({ agent: agent.node, rule: null })}
                  >
                    {t("common.addRule")}
                  </Button>
                </div>
                {agent.mesh_egress.map((r) => (
                  <div className="flex min-w-0 flex-wrap items-center gap-2" key={r.name}>
                    <span className="min-w-[90px] shrink-0 font-mono text-small">{r.name}</span>
                    <span className="text-small text-fg-3">{r.protocol === "udp" ? "udp" : "tcp"}</span>
                    <span className="font-mono text-small text-fg-2">
                      {r.target_addr ?? r.target_cidr}
                      {r.target_cidr ? t("form.rangeSuffix") : ""}
                    </span>
                    {r.udp_idle_timeout_secs != null && (
                      <span className="text-small text-fg-3">udp idle {r.udp_idle_timeout_secs}s</span>
                    )}
                    <span className="flex-1" />
                    <Button size="sm" disabled={busy} onClick={() => setEgressDialog({ agent: agent.node, rule: r })}>
                      {t("common.edit")}
                    </Button>
                    <Hint text={t("common.remove")}>
                      <Button
                        variant="link"
                        size="icon-sm"
                        disabled={busy}
                        aria-label={t("common.remove")}
                        onClick={() =>
                          void onEdit({ RemoveMeshEgress: { agent: agent.node, name: r.name } })
                        }
                        className="text-fg-3 hover:text-critical"
                      >
                        <X className="size-3.5" />
                      </Button>
                    </Hint>
                  </div>
                ))}
              </div>
            </>
          )}
        </div>
      ))}
      {agents.length === 0 && <p className="m-0 text-small text-fg-3">{t("form.noAgents")}</p>}

      {creating && (
        <CreateNodeDialog
          busy={busy}
          onClose={() => setCreating(false)}
          onConfirm={async (spec) => {
            const ok = await onEdit({
              CreateNode: {
                kind: spec.kind,
                node: spec.node,
                workspace: spec.workspace === "" ? null : spec.workspace,
                services: spec.services.filter((s) => s.id !== "" && s.address !== ""),
                mesh_ingress: spec.mesh_ingress.filter((r) => r.name !== ""),
                mesh_egress: spec.mesh_egress.filter((r) => r.name !== ""),
                ingress_workspaces: spec.ingress_workspaces,
                hub_endpoint: spec.hub_endpoint === "" ? null : spec.hub_endpoint,
              },
            });
            if (ok) setCreating(false);
          }}
        />
      )}
      {removing !== null && (
        <ConfirmDialog
          title={t("form.agentRemoveTitle", { name: removing })}
          message={t("form.agentRemoveMessage")}
          confirmLabel={t("common.remove")}
          danger
          busy={busy}
          onConfirm={async () => {
            const ok = await onEdit({ RemoveAgent: removing });
            if (ok) setRemoving(null);
          }}
          onClose={() => setRemoving(null)}
        />
      )}
      {serviceDialog && (
        <ServiceDialog
          agent={serviceDialog.agent}
          initial={serviceDialog.service}
          busy={busy}
          onClose={() => setServiceDialog(null)}
          onConfirm={async (edit) => {
            const ok = await onEdit({
              UpsertService: { agent: serviceDialog.agent, id: edit.id, address: edit.address },
            });
            if (ok) setServiceDialog(null);
          }}
        />
      )}
      {ingressDialog && (
        <MeshIngressRuleDialog
          agent={ingressDialog.agent}
          initial={ingressDialog.rule}
          busy={busy}
          onClose={() => setIngressDialog(null)}
          onConfirm={async (edit) => {
            const ok = await onEdit({
              UpsertMeshIngress: {
                agent: ingressDialog.agent,
                name: edit.name,
                listen: edit.listen,
                protocol: edit.protocol,
                target_agent: edit.target_agent,
                remote_addr: edit.remote_addr,
                idle_timeout_secs: edit.idle_timeout_secs,
              },
            });
            if (ok) setIngressDialog(null);
          }}
        />
      )}
      {egressDialog && (
        <MeshEgressRuleDialog
          agent={egressDialog.agent}
          initial={egressDialog.rule}
          busy={busy}
          onClose={() => setEgressDialog(null)}
          onConfirm={async (edit) => {
            const isRange = edit.target.includes("/");
            const ok = await onEdit({
              UpsertMeshEgress: {
                agent: egressDialog.agent,
                name: edit.name,
                protocol: edit.protocol,
                target_addr: !isRange && edit.target !== "" ? edit.target : null,
                target_cidr: isRange ? edit.target : null,
                udp_idle_timeout_secs: edit.udp_idle_timeout_secs,
              },
            });
            if (ok) setEgressDialog(null);
          }}
        />
      )}
    </SectionPanel>
  );
}

function IngressSection({
  ingress,
  workspaces,
  busy,
  onEdit,
}: {
  ingress: ManifestSummaryDto["ingress"];
  workspaces: string[];
  busy: boolean;
  onEdit: Edit;
}) {
  const [dialog, setDialog] = useState<{ node: ManifestSummaryDto["ingress"][number] | null } | null>(null);
  const [removing, setRemoving] = useState<string | null>(null);
  const { t } = useT();
  return (
    <SectionPanel
      title={t("form.ingressTitle")}
      hint={t("form.ingressHint")}
      actions={
        <Button size="sm" disabled={busy} onClick={() => setDialog({ node: null })}>
          {t("form.addIngress")}
        </Button>
      }
    >
      {ingress.length === 0 && <p className="m-0 text-small text-fg-3">{t("form.noIngress")}</p>}
      {ingress.map((node) => (
        <div className="flex min-w-0 flex-wrap items-center gap-2" key={node.node}>
          <span className="min-w-[90px] shrink-0 font-mono text-small">{node.node}</span>
          <span className="font-mono text-small text-fg-2">{node.workspaces.join(", ")}</span>
          <span className="text-small text-fg-3">
            {node.listen}
            {node.quic_listen != null ? ` · quic ${node.quic_listen}` : ""}
            {node.edge_rate_per_ip_per_minute != null
              ? ` · ${t("form.perIpRate", { n: node.edge_rate_per_ip_per_minute })}`
              : ""}
          </span>
          <span className="flex-1" />
          <Button size="sm" disabled={busy} onClick={() => setDialog({ node })}>
            {t("common.edit")}
          </Button>
          <Button size="sm" variant="danger" disabled={busy} onClick={() => setRemoving(node.node)}>
            {t("common.remove")}
          </Button>
        </div>
      ))}
      {workspaces.length === 0 && (
        <p className="m-0 text-small text-fg-3">{t("form.declareWorkspaceFirst")}</p>
      )}
      {dialog && (
        <IngressNodeDialog
          initial={dialog.node}
          busy={busy}
          onClose={() => setDialog(null)}
          onConfirm={async (edit) => {
            const ok = await onEdit({
              UpsertIngress: {
                node: edit.node,
                workspaces: edit.workspaces,
                listen: edit.listen === "" ? null : edit.listen,
                control_listen: edit.control_listen === "" ? null : edit.control_listen,
                quic_listen: edit.quic_listen === "" ? null : edit.quic_listen,
                edge_rate_per_ip_per_minute: edit.edge_rate,
              },
            });
            if (ok) setDialog(null);
          }}
        />
      )}
      {removing !== null && (
        <ConfirmDialog
          title={t("form.ingressRemoveTitle", { name: removing })}
          message={t("form.ingressRemoveMessage")}
          confirmLabel={t("common.remove")}
          danger
          busy={busy}
          onConfirm={async () => {
            const ok = await onEdit({ RemoveIngress: removing });
            if (ok) setRemoving(null);
          }}
          onClose={() => setRemoving(null)}
        />
      )}
    </SectionPanel>
  );
}

function RoutesSection({
  routes,
  busy,
  onEdit,
}: {
  routes: ManifestSummaryDto["routes"];
  busy: boolean;
  onEdit: Edit;
}) {
  const [dialog, setDialog] = useState<{ route: ManifestSummaryDto["routes"][number] | null } | null>(null);
  const { t } = useT();
  return (
    <SectionPanel
      title={t("form.routesTitle")}
      hint={t("form.routesHint")}
      actions={
        <Button size="sm" disabled={busy} onClick={() => setDialog({ route: null })}>
          {t("form.addRoute")}
        </Button>
      }
    >
      {routes.map((route) => (
        <div className="flex min-w-0 flex-wrap items-center gap-2" key={route.host}>
          <span className="min-w-[90px] shrink-0 font-mono text-small">{route.host}</span>
          <span className="text-small text-fg-3">→</span>
          <span className="font-mono text-small text-fg-2">{route.service}</span>
          <span className="flex-1" />
          <Button size="sm" disabled={busy} onClick={() => setDialog({ route })}>
            {t("common.edit")}
          </Button>
          <Hint text={t("common.remove")}>
            <Button
              variant="link"
              size="icon-sm"
              disabled={busy}
              aria-label={t("common.remove")}
              onClick={() => void onEdit({ RemoveRoute: { host: route.host } })}
              className="text-fg-3 hover:text-critical"
            >
              <X className="size-3.5" />
            </Button>
          </Hint>
        </div>
      ))}
      {routes.length === 0 && <p className="m-0 text-small text-fg-3">{t("form.noRoutes")}</p>}
      {dialog && (
        <RouteDialog
          initial={dialog.route}
          busy={busy}
          onClose={() => setDialog(null)}
          onConfirm={async (edit) => {
            const ok = await onEdit({ UpsertRoute: { host: edit.host, service: edit.service } });
            if (ok) setDialog(null);
          }}
        />
      )}
    </SectionPanel>
  );
}
