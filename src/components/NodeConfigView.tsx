import { useEffect, useState } from "react";
import { api, isRunning, type NodeInfo, type Transport } from "../api";
import { useT } from "../i18n";
import { parseLoopbackAddr } from "../lib/net";
import { cn } from "../lib/utils";
import {
  Badge,
  Button,
  Field,
  Hint,
  InfoRow,
  Input,
  SectionPanel,
  SegmentedControl,
  useToast,
} from "./ui";

// One rule/proposal row: listen → remote (mono data) + proto pill + the
// trailing named attribution. Egress rows carry a bare target (no arrow).
// `listenClass`/`listenTitle` carry the live listener state onto the listen
// address (green-by-default; critical when nothing is serving the rule).
const RuleRow = ({
  listen,
  listenClass,
  listenTitle,
  proto,
  remote,
  target,
  at,
  name,
  nameClass,
  nameTitle,
}: {
  listen?: string;
  listenClass?: string;
  listenTitle?: string;
  proto: string;
  remote?: string;
  target?: string;
  at?: string;
  name: string;
  nameClass?: string;
  nameTitle?: string;
}) => (
  <div className="flex flex-wrap items-baseline gap-2.5 text-base">
    {listen && (
      <Hint text={listenTitle ?? listen}>
        <span className={cn("font-mono text-small", listenClass)}>{listen}</span>
      </Hint>
    )}
    <Badge className="uppercase">{proto}</Badge>
    {remote && <span>→ {remote}</span>}
    {target && <span>{target}</span>}
    {at && <span className="text-small text-fg-3">{at}</span>}
    <Hint text={nameTitle ?? name}>
      <span className={cn("ml-auto text-small text-fg-3", nameClass)}>{name}</span>
    </Hint>
  </div>
);

/// The detail page's low-frequency view: what the node IS and what this
/// machine prefers — pack-signed identity truth, the full rule lists, the
/// stream-proposal receipts, and the only editable form (2026-10-09
/// frequency layering). Look-up and edit share the layer because they are
/// the same visit: nothing here needs to be seen unbidden, so it stays out
/// of the monitoring view's way.
export default function NodeConfigView({
  node,
  onChanged,
  onError,
}: {
  node: NodeInfo;
  onChanged: () => Promise<void>;
  onError: (message: string) => void;
}) {
  const { t } = useT();
  const toast = useToast();
  const running = isRunning(node.state);
  const isAgent = node.kind === "expose_agent" || node.kind === "mesh_agent";
  const services = node.services ?? [];
  const hasMeshRules =
    node.kind === "mesh_agent" &&
    (node.mesh_ingress_rules.length > 0 || node.mesh_egress_rules.length > 0);

  // The toggle shows the *effective* transport: local preference, else the
  // pack's signed manifest default, else h2. Saving always writes the local
  // preference (untouched = inherited).
  const [transport, setTransport] = useState<Transport>(
    node.transport ?? node.pack_transport ?? "h2",
  );
  const [hubQuicAddr, setHubQuicAddr] = useState(node.hub_quic_addr ?? "");
  // Per-service address inputs: "" = no preference (pack default runs).
  const [addresses, setAddresses] = useState<Record<string, string>>({});

  // Current override state from the node snapshot (id → overridden address).
  const overrides: Record<string, string> = Object.fromEntries(
    services.filter((s) => s.overridden).map((s) => [s.id, s.effective_address]),
  );

  // Reset the form when switching nodes (the views stay mounted, so the
  // reset must key on the node identity, not on remounting).
  useEffect(() => {
    setTransport(node.transport ?? node.pack_transport ?? "h2");
    setHubQuicAddr(node.hub_quic_addr ?? "");
    setAddresses(
      Object.fromEntries(
        (node.services ?? [])
          .filter((s) => s.overridden)
          .map((s) => [s.id, s.effective_address]),
      ),
    );
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [node.id, node.transport, node.pack_transport, node.hub_quic_addr, node.services]);

  const addressError = (id: string): string | null => {
    const value = (addresses[id] ?? "").trim();
    if (value === "") return null; // empty = default, always fine
    return parseLoopbackAddr(value) === null ? t("nodeDetail.addrError") : null;
  };
  const anyAddressError = services.some((s) => addressError(s.id) !== null);

  const addressesDirty = services.some(
    (s) => (addresses[s.id] ?? "").trim() !== (overrides[s.id] ?? "").trim(),
  );

  const dirty =
    isAgent &&
    (transport !== (node.transport ?? node.pack_transport ?? "h2") ||
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
      toast.push(t("nodeDetail.saved"));
    } catch (e) {
      onError(t("nodeDetail.prefsNotSaved", { error: String(e) }));
    }
  };

  return (
    <>
      <SectionPanel title={t("nodeDetail.identity")}>
        {node.principal && (
          <InfoRow label={t("nodeDetail.identity")}>
            <Input value={node.principal} readOnly />
          </InfoRow>
        )}
        <InfoRow label={t("nodeDetail.credentialPack")}>
          <Hint text={node.pack_dir}>
            <Input value={node.pack_dir} readOnly />
          </Hint>
        </InfoRow>
        {node.generation > 0 && (
          <InfoRow label={t("nodeDetail.generation")}>
            <span className="text-small text-fg-2">{node.generation}</span>
          </InfoRow>
        )}
      </SectionPanel>

      {hasMeshRules && (
        <SectionPanel title={t("nodeDetail.meshRules")}>
          {node.mesh_ingress_rules.length > 0 && (
            <div className="flex flex-col gap-1">
              <div className="text-small font-semibold uppercase tracking-[0.05em] text-fg-3">
                Ingress
              </div>
              {node.mesh_ingress_rules.map((rule) => {
                // Join the live listener face by rule name (running mesh
                // agents): the pack's declared listen vs what is really
                // serving there — the declared address turns critical when
                // nothing binds it (the 2026-10-09 honesty axis), and the
                // tooltip carries the bound port pick or the bind error.
                const listener =
                  node.listeners?.find((l) => l.rule === rule.name) ?? null;
                const down = running && listener != null && listener.bound_addr == null;
                return (
                  <RuleRow
                    key={rule.name}
                    listen={rule.listen}
                    listenClass={down ? "text-critical" : undefined}
                    listenTitle={
                      listener?.bound_addr != null
                        ? t("nodeDetail.listenerBoundTitle")
                        : listener?.last_error ?? undefined
                    }
                    proto={rule.protocol}
                    remote={rule.remote_addr}
                    at={t("nodeDetail.atAgent", { agent: rule.target_agent })}
                    name={rule.name}
                  />
                );
              })}
            </div>
          )}
          {node.mesh_egress_rules.length > 0 && (
            <div className="flex flex-col gap-1">
              <div className="text-small font-semibold uppercase tracking-[0.05em] text-fg-3">
                Egress
              </div>
              {node.mesh_egress_rules.map((rule) => (
                <RuleRow key={rule.name} proto={rule.protocol} target={rule.target} name={rule.name} />
              ))}
            </div>
          )}
        </SectionPanel>
      )}

      {node.kind === "mesh_agent" && running && node.proposals && node.proposals.length > 0 && (
        <SectionPanel title={t("nodeDetail.requestedStreams")}>
          {node.proposals.map((p) => (
            <RuleRow
              key={p.id}
              listen={p.rule.listen}
              proto={p.rule.protocol}
              remote={p.rule.remote_addr}
              at={t("nodeDetail.atAgent", { agent: p.rule.target_agent })}
              name={
                p.status.status === "pending"
                  ? t("proposal.statusPending")
                  : p.status.status === "approved"
                    ? t("proposal.statusApproved", {
                        gen: String((p.status as { generation: number }).generation),
                      })
                    : t("proposal.statusRejected")
              }
              nameClass={p.status.status === "rejected" ? "text-critical" : undefined}
              nameTitle={
                p.status.status === "rejected"
                  ? t("nodeDetail.proposalRejectedTitle", {
                      reason: (p.status as { reason: string }).reason,
                    })
                  : undefined
              }
            />
          ))}
          {node.proposals.some((p) => p.status.status === "rejected") && (
            <div className="rounded-lg border border-critical/40 bg-critical/10 p-2.5 text-small whitespace-pre-wrap text-critical">
              {node.proposals
                .filter((p) => p.status.status === "rejected")
                .map((p) => `${p.rule.name}: ${(p.status as { reason: string }).reason}`)
                .join("\n")}
            </div>
          )}
        </SectionPanel>
      )}

      {isAgent && (
        <SectionPanel
          title={t("nodeDetail.runtimePrefs")}
          hint={running ? t("nodeDetail.stopToEdit") : undefined}
        >
          <InfoRow label={t("prefs.transport")}>
            <div className="flex flex-wrap items-center gap-2">
              {node.transport == null && node.pack_transport === "quic" && (
                <span className="text-small text-fg-3">{t("nodeDetail.quicInherited")}</span>
              )}
              <SegmentedControl
                value={transport}
                options={[
                  { value: "h2", label: "h2" },
                  { value: "quic", label: "QUIC" },
                ]}
                onChange={setTransport}
                disabled={running}
              />
            </div>
          </InfoRow>
          {transport === "quic" && (
            <Field label={t("prefs.hubQuicAddr")}>
              {(id) => (
                <Input
                  id={id}
                  disabled={running}
                  value={hubQuicAddr}
                  onChange={(e) => setHubQuicAddr(e.target.value)}
                  placeholder={
                    node.pack_hub_quic_addr
                      ? t("prefs.hubQuicDerived", { addr: node.pack_hub_quic_addr })
                      : t("prefs.hubQuicPlaceholder")
                  }
                  autoCapitalize="none"
                  autoCorrect="off"
                  spellCheck={false}
                  autoComplete="off"
                />
              )}
            </Field>
          )}
          {services.length > 0 && (
            <>
              <InfoRow label={t("nodeDetail.serviceAddresses")}>
                <span className="text-small text-fg-3">{t("nodeDetail.emptyDefault")}</span>
              </InfoRow>
              {services.map((service) => {
                const err = addressError(service.id);
                return (
                  <Field key={service.id} label={<span className="font-mono">{service.id}</span>}>
                    {(id) => (
                      <>
                        <div className="flex min-w-0 flex-1 items-center gap-1.5">
                          <Hint
                            text={
                              service.overridden
                                ? t("common.packDefaultTitle", { addr: service.default_address })
                                : service.default_address
                            }
                          >
                            <Input
                              id={id}
                              aria-invalid={err ? true : undefined}
                              disabled={running}
                              value={addresses[service.id] ?? ""}
                              onChange={(e) =>
                                setAddresses((prev) => ({
                                  ...prev,
                                  [service.id]: e.target.value,
                                }))
                              }
                              placeholder={service.default_address}
                              autoCapitalize="none"
                              autoCorrect="off"
                              spellCheck={false}
                              autoComplete="off"
                              className="flex-1"
                            />
                          </Hint>
                          <Button
                            variant="link"
                            size="sm"
                            disabled={running || (addresses[service.id] ?? "") === ""}
                            onClick={() =>
                              setAddresses((prev) => ({ ...prev, [service.id]: "" }))
                            }
                            title={t("nodeDetail.revertTitle")}
                          >
                            {t("common.reset")}
                          </Button>
                        </div>
                        {err && (
                          <span className="text-small whitespace-nowrap text-critical">{err}</span>
                        )}
                      </>
                    )}
                  </Field>
                );
              })}
            </>
          )}
          <InfoRow label="">
            <Button
              variant="primary"
              disabled={running || !dirty || anyAddressError}
              onClick={savePrefs}
            >
              {t("nodeDetail.savePrefs")}
            </Button>
          </InfoRow>
        </SectionPanel>
      )}
    </>
  );
}
