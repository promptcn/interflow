import { useState } from "react";
import { MoreVertical } from "lucide-react";
import { api } from "../api";
import { useT } from "../i18n";
import { RouteDialog, ServiceDialog } from "../components/ManifestDialogs";
import {
  Button,
  ConfirmDialog,
  EmptyState,
  Field,
  Input,
  Menu,
  MenuContent,
  MenuItem,
  MenuSeparator,
  MenuTrigger,
  Modal,
  SectionPanel,
  Table,
  TBody,
  Td,
  Th,
  THead,
  Tr,
  useToast,
} from "../components/ui";
import { DialogFooter, DialogTitle } from "../components/ui/dialog";
import type { RouteDto } from "../api";
import { useDeployment } from "./DeploymentContext";

interface Props {
  onOpenNode: (id: string) => void;
}

/// 服务: the expose face's two tables — public routes (host → service
/// identity, hot since the engine channel) and per-node services (the
/// declared default × this machine's effective address, editable LIVE for
/// local nodes — the Phase-1.3 channel). Row actions speak the area's
/// shared language (2026-10-16 streams row language): the primary op
/// inline, the rest behind the ⋯ menu; every successful edit refreshes
/// the composed fleet at once (the saved document shows immediately,
/// honestly 待发布 until publish converges it).
export default function ServicesView({ onOpenNode }: Props) {
  const { t } = useT();
  const { fleet, busy, applyEdit, refresh, nodesChanged, say } = useDeployment();
  const [routeEdit, setRouteEdit] = useState<{
    initial: RouteDto | null;
  } | null>(null);
  const [routeDelete, setRouteDelete] = useState<RouteDto | null>(null);
  const [serviceAdd, setServiceAdd] = useState<string | null>(null);
  const [serviceEdit, setServiceEdit] = useState<{
    agent: string;
    id: string;
  } | null>(null);
  const [serviceDelete, setServiceDelete] = useState<{
    agent: string;
    id: string;
  } | null>(null);
  const [addressEdit, setAddressEdit] = useState<{
    nodeId: string;
    node: string;
    service: string;
    current: string;
  } | null>(null);
  const toast = useToast();

  if (fleet === null) return null;

  const routes = fleet.summary.routes;
  const services = fleet.services;

  const editRoute = async (host: string, service: string) => {
    const error = await applyEdit({ UpsertRoute: { host, service } });
    if (error !== null) say([`✘ ${error}`]);
    else void refresh(true);
  };

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-3 overflow-auto">
      <SectionPanel
        title={t("dep.services.routes")}
        actions={
          <Button
            size="sm"
            disabled={busy}
            onClick={() => setRouteEdit({ initial: null })}
          >
            {t("dep.services.routeAdd")}
          </Button>
        }
      >
        {routes.length === 0 ? (
          <EmptyState>{t("dep.services.empty")}</EmptyState>
        ) : (
          <div className="overflow-x-auto">
            <Table>
              <THead>
                <Tr>
                  <Th>{t("dep.services.col.host")}</Th>
                  <Th>{t("dep.services.col.service")}</Th>
                  <Th />
                </Tr>
              </THead>
              <TBody>
                {routes.map((r) => (
                  <Tr key={r.host}>
                    <Td>
                      <span className="font-mono text-small">{r.host}</span>
                    </Td>
                    <Td>
                      <span className="font-mono text-small text-fg-2">
                        {r.service}
                      </span>
                    </Td>
                    <Td className="whitespace-nowrap">
                      <span className="flex items-center justify-end gap-1">
                        <Button
                          size="sm"
                          variant="secondary"
                          disabled={busy}
                          onClick={() => setRouteEdit({ initial: r })}
                        >
                          {t("common.edit")}
                        </Button>
                        <Menu>
                          <MenuTrigger asChild>
                            <Button
                              size="icon-sm"
                              variant="secondary"
                              disabled={busy}
                              aria-label={t("common.more")}
                              title={t("common.more")}
                            >
                              <MoreVertical className="size-4" />
                            </Button>
                          </MenuTrigger>
                          <MenuContent>
                            <MenuItem danger onSelect={() => setRouteDelete(r)}>
                              {t("dep.services.delete")}
                            </MenuItem>
                          </MenuContent>
                        </Menu>
                      </span>
                    </Td>
                  </Tr>
                ))}
              </TBody>
            </Table>
          </div>
        )}
      </SectionPanel>

      <SectionPanel title={t("dep.services.node")}>
        {services.length === 0 ? (
          <EmptyState>{t("dep.services.empty")}</EmptyState>
        ) : (
          <div className="overflow-x-auto">
            <Table>
              <THead>
                <Tr>
                  <Th>{t("dep.services.col.node")}</Th>
                  <Th>{t("dep.services.col.service")}</Th>
                  <Th>{t("dep.services.col.address")}</Th>
                  <Th>{t("dep.services.col.default")}</Th>
                  <Th />
                </Tr>
              </THead>
              <TBody>
                {services.map((s) => (
                  <Tr key={`${s.agent}/${s.id}`}>
                    <Td className="whitespace-nowrap">
                      {s.local_node_id ? (
                        <Button
                          size="sm"
                          variant="link"
                          onClick={() => onOpenNode(s.local_node_id!)}
                        >
                          {s.agent}
                        </Button>
                      ) : (
                        <span className="text-fg-2">{s.agent}</span>
                      )}
                    </Td>
                    <Td className="whitespace-nowrap">
                      <span className="font-medium">{s.id}</span>
                    </Td>
                    <Td className="whitespace-nowrap">
                      {s.effective_address !== null ? (
                        <span
                          className={`font-mono text-small ${s.overridden ? "text-accent" : "text-fg-2"}`}
                          title={
                            s.overridden
                              ? t("dep.services.overridden")
                              : undefined
                          }
                        >
                          {s.effective_address}
                          {s.overridden && " ✱"}
                        </span>
                      ) : (
                        <span className="text-small text-fg-3">
                          {t("dep.services.notHere")}
                        </span>
                      )}
                    </Td>
                    <Td className="whitespace-nowrap">
                      <span className="font-mono text-small text-fg-3">
                        {s.default_address}
                      </span>
                    </Td>
                    <Td className="whitespace-nowrap">
                      <span className="flex items-center justify-end gap-1">
                        {s.local_node_id && s.effective_address !== null && (
                          <Button
                            size="sm"
                            variant="secondary"
                            onClick={() =>
                              setAddressEdit({
                                nodeId: s.local_node_id!,
                                node: s.agent,
                                service: s.id,
                                current: s.effective_address!,
                              })
                            }
                          >
                            {t("common.edit")}
                          </Button>
                        )}
                        <Menu>
                          <MenuTrigger asChild>
                            <Button
                              size="icon-sm"
                              variant="secondary"
                              disabled={busy}
                              aria-label={t("common.more")}
                              title={t("common.more")}
                            >
                              <MoreVertical className="size-4" />
                            </Button>
                          </MenuTrigger>
                          <MenuContent>
                            <MenuItem
                              onSelect={() =>
                                setServiceEdit({ agent: s.agent, id: s.id })
                              }
                            >
                              {t("dep.services.editDefault")}
                            </MenuItem>
                            <MenuSeparator />
                            <MenuItem
                              danger
                              onSelect={() =>
                                setServiceDelete({ agent: s.agent, id: s.id })
                              }
                            >
                              {t("dep.services.delete")}
                            </MenuItem>
                          </MenuContent>
                        </Menu>
                      </span>
                    </Td>
                  </Tr>
                ))}
              </TBody>
            </Table>
          </div>
        )}
        <div className="mt-2 flex flex-wrap gap-2">
          {/* Only agents that may carry services — the form face rejects
              them elsewhere (one pack, one role), so the buttons must
              not offer a mesh agent the schema forbids. */}
          {Array.from(
            new Set(
              fleet.summary.agents
                .filter((a) => a.role === "expose" || a.role === "mixed")
                .map((a) => a.node),
            ),
          ).map((agent) => (
            <Button
              key={agent}
              size="sm"
              variant="secondary"
              disabled={busy}
              onClick={() => setServiceAdd(agent)}
            >
              + {agent}
            </Button>
          ))}
        </div>
      </SectionPanel>

      {routeEdit !== null && (
        <RouteDialog
          initial={routeEdit.initial}
          busy={busy}
          onClose={() => setRouteEdit(null)}
          onConfirm={async (edit) => {
            await editRoute(edit.host, edit.service);
            setRouteEdit(null);
          }}
        />
      )}

      {routeDelete !== null && (
        <ConfirmDialog
          title={t("dep.services.deleteRouteTitle", { name: routeDelete.host })}
          message={t("dep.services.deleteRouteBody")}
          confirmLabel={t("dep.streams.delete")}
          danger
          busy={busy}
          onConfirm={async () => {
            await applyEdit({ RemoveRoute: { host: routeDelete.host } });
            setRouteDelete(null);
            void refresh(true);
          }}
          onClose={() => setRouteDelete(null)}
        />
      )}

      {(serviceAdd !== null || serviceEdit !== null) && (
        <ServiceDialog
          agent={serviceAdd ?? serviceEdit!.agent}
          initial={null}
          busy={busy}
          onClose={() => {
            setServiceAdd(null);
            setServiceEdit(null);
          }}
          onConfirm={async (edit) => {
            const error = await applyEdit({
              UpsertService: {
                agent: serviceAdd ?? serviceEdit!.agent,
                id: edit.id,
                address: edit.address,
              },
            });
            if (error === null) {
              setServiceAdd(null);
              setServiceEdit(null);
              void refresh(true);
            }
          }}
        />
      )}

      {serviceDelete !== null && (
        <ConfirmDialog
          title={t("dep.services.deleteServiceTitle", {
            name: serviceDelete.id,
          })}
          message={t("dep.services.deleteServiceBody")}
          confirmLabel={t("dep.streams.delete")}
          danger
          busy={busy}
          onConfirm={async () => {
            await applyEdit({
              RemoveService: {
                agent: serviceDelete.agent,
                id: serviceDelete.id,
              },
            });
            setServiceDelete(null);
            void refresh(true);
          }}
          onClose={() => setServiceDelete(null)}
        />
      )}

      {addressEdit !== null && (
        <AddressDialog
          node={addressEdit.node}
          service={addressEdit.service}
          current={addressEdit.current}
          onClose={() => setAddressEdit(null)}
          onSaved={async (next) => {
            // Whole-prefs save: the node's other preferences (transport,
            // hub QUIC) must ride along unchanged — read, patch the one
            // service, save.
            try {
              const nodes = await api.listNodes();
              const node = nodes.find((n) => n.id === addressEdit.nodeId);
              const others =
                node?.services
                  .filter(
                    (sv) => sv.id !== addressEdit.service && sv.overridden,
                  )
                  .map((sv) => ({
                    id: sv.id,
                    address: sv.effective_address,
                  })) ?? [];
              await api.updateNodePrefs(addressEdit.nodeId, {
                transport: node?.transport ?? null,
                hub_quic_addr: node?.hub_quic_addr ?? null,
                service_addresses: next
                  ? [...others, { id: addressEdit.service, address: next }]
                  : others,
              });
              toast.push(t("dep.services.addressLive"));
              nodesChanged();
            } catch (e) {
              say([`✘ ${String(e)}`]);
            }
          }}
        />
      )}
    </div>
  );
}

/// The live address editor: where THIS machine dials the service. Saving
/// applies live (the Phase-1.3 channel) — no restart, the next connection
/// uses the new target. Empty = the signed default.
function AddressDialog({
  node,
  service,
  current,
  onClose,
  onSaved,
}: {
  node: string;
  service: string;
  current: string;
  onClose: () => void;
  onSaved: (next: string | null) => Promise<void>;
}) {
  const { t } = useT();
  const [value, setValue] = useState(current);
  const [working, setWorking] = useState(false);
  return (
    <Modal onClose={onClose}>
      <DialogTitle>
        {t("dep.services.addressTitle", { service: `${node}/${service}` })}
      </DialogTitle>
      <div className="flex flex-col gap-2">
        <Field label={t("dep.services.col.address")}>
          {(id) => (
            <Input
              id={id}
              value={value}
              placeholder="127.0.0.1:3000"
              onChange={(e) => setValue(e.target.value)}
              autoFocus
            />
          )}
        </Field>
        <p className="m-0 text-small text-fg-3">
          {t("dep.services.addressLive")}
        </p>
      </div>
      <DialogFooter>
        <Button variant="secondary" size="sm" onClick={onClose}>
          {t("common.cancel")}
        </Button>
        <Button
          size="sm"
          disabled={working}
          onClick={async () => {
            setWorking(true);
            await onSaved(value.trim() === "" ? null : value.trim());
            setWorking(false);
            onClose();
          }}
        >
          {t("common.apply")}
        </Button>
      </DialogFooter>
    </Modal>
  );
}
