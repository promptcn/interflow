import { useState } from "react";
import { ConfirmDialog, SectionPanel } from "./ui";
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
  return (
    <div className="manifest-form">
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
      <HubSection key={JSON.stringify(summary.hubs)} hubs={summary.hubs} busy={busy} onEdit={onEdit} />
      <WorkspaceSection
        key={JSON.stringify(summary.workspaces)}
        workspaces={summary.workspaces}
        busy={busy}
        onEdit={onEdit}
      />
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
    </div>
  );
}

/// One section's Apply button + the "this writes into the document, not
/// the file" reminder when a draft diverges.
function SectionApply({
  disabled,
  label = "Apply",
  onClick,
}: {
  disabled: boolean;
  label?: string;
  onClick: () => void;
}) {
  return (
    <div className="row form-actions">
      <button className="primary" disabled={disabled} onClick={onClick}>
        {label}
      </button>
      <span className="hint">edits land in the document — Save writes the file</span>
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
  const dirty = id !== realm.id || endpoint !== realm.control_endpoint;
  const input = (value: string, set: (v: string) => void, placeholder: string) => (
    <input
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
    <SectionPanel title="Realm" hint="one independent trust domain — the identity inside principal URIs">
      <div className="row">
        <label>Id</label>
        {input(id, setId, "promptcn-mesh")}
      </div>
      <div className="row">
        <label>Control endpoint</label>
        {input(endpoint, setEndpoint, "blank = site-to-site only (agents dial the mesh hub)")}
      </div>
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
  const dirty =
    mode !== identity.mode ||
    leafTtl !== (identity.leaf_ttl ?? "") ||
    registrar !== identity.registrar_endpoint;
  const bounds = identity.leaf_ttl_bounds;
  return (
    <SectionPanel title="Identity tier" hint="one decision: credential lifetime + how it renews">
      <div className="row">
        <label>Mode</label>
        <select
          value={mode}
          onChange={(e) => setMode(e.target.value as IdentityModeDto)}
        >
          <option value="registrar">
            registrar — short leaves, automatic renewal
          </option>
          <option value="offline">
            offline — long leaves, manual rotate
          </option>
        </select>
      </div>
      <div className="row">
        <label>Leaf TTL</label>
        <input
          value={leafTtl}
          placeholder={`blank = default (${bounds.default}); ${bounds.min}–${bounds.max}`}
          onChange={(e) => setLeafTtl(e.target.value)}
          autoCapitalize="none"
          autoCorrect="off"
          spellCheck={false}
          autoComplete="off"
        />
      </div>
      <div className="row">
        <label>Registrar endpoint</label>
        <input
          value={registrar}
          placeholder={mode === "registrar" ? "https://registrar.example.com (required)" : "blank — offline tier has none"}
          onChange={(e) => setRegistrar(e.target.value)}
          autoCapitalize="none"
          autoCorrect="off"
          spellCheck={false}
          autoComplete="off"
        />
      </div>
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
  const dirty =
    mode !== tls.mode ||
    email !== (tls.email ?? "") ||
    directory !== (tls.directory ?? "");
  return (
    <SectionPanel title="Public TLS" hint="how the ingress terminates public HTTPS">
      <div className="row">
        <label>Mode</label>
        <select value={mode} onChange={(e) => setMode(e.target.value as PublicTlsModeDto)}>
          <option value="acme">acme — automatic</option>
          <option value="frontend-proxy">frontend-proxy — nginx/LB terminates</option>
          <option value="manual">manual — expert</option>
        </select>
      </div>
      {mode === "acme" && (
        <>
          <div className="row">
            <label>ACME email</label>
            <input
              value={email}
              placeholder="ops@example.com"
              onChange={(e) => setEmail(e.target.value)}
              autoCapitalize="none"
              autoCorrect="off"
              spellCheck={false}
              autoComplete="off"
            />
          </div>
          <div className="row">
            <label>ACME directory</label>
            <input
              value={directory}
              placeholder="blank = Let's Encrypt production"
              onChange={(e) => setDirectory(e.target.value)}
              autoCapitalize="none"
              autoCorrect="off"
              spellCheck={false}
              autoComplete="off"
            />
          </div>
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
  return (
    <SectionPanel
      title="Mesh hub"
      hint="the public relay site-to-site agents dial (v1: one per realm)"
      actions={
        hubs.length === 0 ? (
          <button disabled={busy} onClick={() => setDialog({ hub: null })}>
            + hub
          </button>
        ) : undefined
      }
    >
      {hubs.length === 0 && (
        <p className="hint">
          No hub — add one before (or while) declaring mesh agents; a hub without agents
          shows as an issue until the first one arrives.
        </p>
      )}
      {hubs.map((hub) => (
        <div className="rule-row" key={hub.name}>
          <span className="mono summary-key">{hub.name}</span>
          <span className="mono">{hub.endpoint}</span>
          <span className="hint">listen {hub.listen}</span>
          <span style={{ flex: 1 }} />
          <button disabled={busy} onClick={() => setDialog({ hub })}>
            Edit
          </button>
          <button className="danger" disabled={busy} onClick={() => setRemoving(hub.name)}>
            Remove
          </button>
        </div>
      ))}
      {dialog && (
        <HubDialog
          initial={dialog.hub}
          busy={busy}
          onClose={() => setDialog(null)}
          onConfirm={async (edit) => {
            const ok = await onEdit({
              UpsertHub: { name: edit.name, endpoint: edit.endpoint, listen: edit.listen || null },
            });
            if (ok) setDialog(null);
          }}
        />
      )}
      {removing !== null && (
        <ConfirmDialog
          title={`Remove hub ${removing}?`}
          message="The hub leaves the manifest; agents keep their rules until you remove those too (a hub-less mesh shows as an issue)."
          confirmLabel="Remove"
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
  return (
    <SectionPanel title="Workspaces" hint="isolation and authorization namespaces">
      <div className="chip-row">
        {workspaces.map((ws) => (
          <span className="ws-chip" key={ws}>
            {ws}
            <button
              disabled={busy}
              title="remove (rejected while anything still references it)"
              onClick={() => void onEdit({ RemoveWorkspace: ws })}
            >
              ×
            </button>
          </span>
        ))}
        {workspaces.length === 0 && <span className="hint">none declared</span>}
      </div>
      <div className="row">
        <input
          value={name}
          placeholder="new workspace name"
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
        />
        <button
          disabled={busy || name.trim() === ""}
          onClick={() =>
            void onEdit({ UpsertWorkspace: name.trim() }).then((ok) => {
              if (ok) setName("");
            })
          }
        >
          + workspace
        </button>
      </div>
    </SectionPanel>
  );
}

const ROLE_LABEL: Record<AgentRoleDto, string> = {
  expose: "expose role",
  mesh: "mesh role",
  mixed: "mixed (rejected)",
  empty: "no role (rejected)",
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
  return (
    <SectionPanel
      title="Agents"
      hint="one pack, one role: services or mesh rules — never both"
      actions={
        <button disabled={busy} onClick={() => setCreating(true)}>
          + node
        </button>
      }
    >
      {agents.map((agent) => (
        <div className="agent-card" key={agent.node}>
          <div className="rule-row">
            <span className="mono summary-key">{agent.node}</span>
            <span className={`kind-badge role-${agent.role}`}>{ROLE_LABEL[agent.role]}</span>
            <select
              value={agent.workspace}
              disabled={busy || workspaces.length < 2}
              title={
                workspaces.length < 2 ? "the manifest has a single workspace" : "retarget the workspace"
              }
              onChange={(e) => void onEdit({ SetAgentWorkspace: { agent: agent.node, workspace: e.target.value } })}
            >
              {workspaces.map((ws) => (
                <option key={ws} value={ws}>
                  {ws}
                </option>
              ))}
            </select>
            <span style={{ flex: 1 }} />
            <button className="danger" disabled={busy} onClick={() => setRemoving(agent.node)}>
              Remove
            </button>
          </div>

          {(agent.role === "expose" || agent.role === "mixed") && (
            <div className="rule-editor">
              <div className="rule-editor-head">
                <span>Services — expose to public routes</span>
                <button
                  disabled={busy}
                  onClick={() => setServiceDialog({ agent: agent.node, service: null })}
                >
                  + service
                </button>
              </div>
              {agent.services.map((s) => (
                <div className="rule-row" key={s.id}>
                  <span className="mono summary-key">{s.id}</span>
                  <span className="mono">{s.address}</span>
                  <span style={{ flex: 1 }} />
                  <button disabled={busy} onClick={() => setServiceDialog({ agent: agent.node, service: s })}>
                    Edit
                  </button>
                  <button
                    className="rule-remove"
                    disabled={busy}
                    onClick={() => void onEdit({ RemoveService: { agent: agent.node, id: s.id } })}
                  >
                    ×
                  </button>
                </div>
              ))}
            </div>
          )}

          {(agent.role === "mesh" || agent.role === "mixed") && (
            <>
              <div className="rule-editor">
                <div className="rule-editor-head">
                  <span>Mesh ingress — forward a local listener to a peer</span>
                  <button
                    disabled={busy}
                    onClick={() => setIngressDialog({ agent: agent.node, rule: null })}
                  >
                    + rule
                  </button>
                </div>
                {agent.mesh_ingress.map((r) => (
                  <div className="rule-row" key={r.name}>
                    <span className="mono summary-key">{r.name}</span>
                    <span className="mono">{r.listen}</span>
                    <span className="hint">{r.protocol === "udp" ? "udp" : "tcp"}</span>
                    <span className="mono">
                      → {r.target_agent} @ {r.remote_addr}
                    </span>
                    {r.idle_timeout_secs != null && (
                      <span className="hint">idle {r.idle_timeout_secs}s</span>
                    )}
                    <span style={{ flex: 1 }} />
                    <button disabled={busy} onClick={() => setIngressDialog({ agent: agent.node, rule: r })}>
                      Edit
                    </button>
                    <button
                      className="rule-remove"
                      disabled={busy}
                      onClick={() =>
                        void onEdit({ RemoveMeshIngress: { agent: agent.node, name: r.name } })
                      }
                    >
                      ×
                    </button>
                  </div>
                ))}
              </div>
              <div className="rule-editor">
                <div className="rule-editor-head">
                  <span>Mesh egress — what this agent dials for peers</span>
                  <button
                    disabled={busy}
                    onClick={() => setEgressDialog({ agent: agent.node, rule: null })}
                  >
                    + rule
                  </button>
                </div>
                {agent.mesh_egress.map((r) => (
                  <div className="rule-row" key={r.name}>
                    <span className="mono summary-key">{r.name}</span>
                    <span className="hint">{r.protocol === "udp" ? "udp" : "tcp"}</span>
                    <span className="mono">
                      {r.target_addr ?? r.target_cidr}
                      {r.target_cidr ? " (range)" : ""}
                    </span>
                    {r.udp_idle_timeout_secs != null && (
                      <span className="hint">udp idle {r.udp_idle_timeout_secs}s</span>
                    )}
                    <span style={{ flex: 1 }} />
                    <button disabled={busy} onClick={() => setEgressDialog({ agent: agent.node, rule: r })}>
                      Edit
                    </button>
                    <button
                      className="rule-remove"
                      disabled={busy}
                      onClick={() =>
                        void onEdit({ RemoveMeshEgress: { agent: agent.node, name: r.name } })
                      }
                    >
                      ×
                    </button>
                  </div>
                ))}
              </div>
            </>
          )}
        </div>
      ))}
      {agents.length === 0 && (
        <p className="hint">
          No agents — the manifest needs at least one (a fresh mesh skeleton shows this
          as an issue until the first node arrives).
        </p>
      )}

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
          title={`Remove agent ${removing}?`}
          message="The agent and all its rules leave the manifest. Peers targeting it will show pairing issues until their rules are updated too."
          confirmLabel="Remove"
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
  return (
    <SectionPanel
      title="Ingress nodes"
      hint="public entry points for expose routes"
      actions={
        <button disabled={busy} onClick={() => setDialog({ node: null })}>
          + ingress
        </button>
      }
    >
      {ingress.length === 0 && (
        <p className="hint">
          No ingress — this realm is site-to-site only (a hub serves as the entry).
        </p>
      )}
      {ingress.map((node) => (
        <div className="rule-row" key={node.node}>
          <span className="mono summary-key">{node.node}</span>
          <span className="mono">{node.workspaces.join(", ")}</span>
          <span className="hint">
            {node.listen}
            {node.edge_rate_per_ip_per_minute != null
              ? ` · ${node.edge_rate_per_ip_per_minute}/min per IP`
              : ""}
          </span>
          <span style={{ flex: 1 }} />
          <button disabled={busy} onClick={() => setDialog({ node })}>
            Edit
          </button>
          <button className="danger" disabled={busy} onClick={() => setRemoving(node.node)}>
            Remove
          </button>
        </div>
      ))}
      {workspaces.length === 0 && (
        <p className="hint">Declare a workspace first — an ingress serves workspaces.</p>
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
                edge_rate_per_ip_per_minute: edit.edge_rate,
              },
            });
            if (ok) setDialog(null);
          }}
        />
      )}
      {removing !== null && (
        <ConfirmDialog
          title={`Remove ingress ${removing}?`}
          message="The ingress leaves the manifest; its routes must go too (or the document shows issues)."
          confirmLabel="Remove"
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
  return (
    <SectionPanel
      title="Routes"
      hint="public hostname → service identity (workspace/agent/service)"
      actions={
        <button disabled={busy} onClick={() => setDialog({ route: null })}>
          + route
        </button>
      }
    >
      {routes.map((route) => (
        <div className="rule-row" key={route.host}>
          <span className="mono summary-key">{route.host}</span>
          <span className="hint">→</span>
          <span className="mono">{route.service}</span>
          <span style={{ flex: 1 }} />
          <button disabled={busy} onClick={() => setDialog({ route })}>
            Edit
          </button>
          <button
            className="rule-remove"
            disabled={busy}
            onClick={() => void onEdit({ RemoveRoute: { host: route.host } })}
          >
            ×
          </button>
        </div>
      ))}
      {routes.length === 0 && <p className="hint">no routes (required once an ingress exists)</p>}
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
