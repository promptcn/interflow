import { useState } from "react";
import { api, formatRemainingSecs, kindBlurb, leafPhase, type AddNodeParams, type PackInspection, type Transport } from "../api";
import { useT } from "../i18n";
import { cn } from "../lib/utils";
import { Button, DialogFooter, DialogTitle, Field, Input, KindBadge, Modal, SegmentedControl } from "./ui";

/// The add-a-node flow: pick a pack directory (or import a sealed
/// `.iflowpack`), inspect it through the same funnel the start path uses,
/// preview what it is, choose the few agent preferences, add. Unchanged by
/// the card-overview redesign — only its home moved out of the old sidebar.
export default function AddNodeDialog({
  onClose,
  onAdded,
}: {
  onClose: () => void;
  onAdded: (createdId: string) => Promise<void>;
}) {
  const [packDir, setPackDir] = useState("");
  const [inspection, setInspection] = useState<PackInspection | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  // Agent preferences (the only user-chosen runtime knobs; everything else
  // comes from the pack).
  const [transport, setTransport] = useState<Transport>("h2");
  const [hubQuicAddr, setHubQuicAddr] = useState("");
  // Sealed .iflowpack import: decrypt into the GUI-managed packs root, then
  // the same inspect → add flow as a directory.
  const [sealedPath, setSealedPath] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const { t } = useT();

  const isAgent =
    inspection?.kind === "expose_agent" || inspection?.kind === "mesh_agent";

  const pickPackDir = async () => {
    const { open } = await import("@tauri-apps/plugin-dialog");
    const dir = await open({
      title: t("addNode.choosePackDir"),
      directory: true,
    });
    if (typeof dir === "string") {
      setPackDir(dir);
      setInspection(null);
      setError(null);
    }
  };

  const pickSealed = async () => {
    const { open } = await import("@tauri-apps/plugin-dialog");
    const file = await open({
      title: t("addNode.chooseSealed"),
      filters: [{ name: t("addNode.sealedFilter"), extensions: ["iflowpack"] }],
    });
    if (typeof file === "string") {
      setSealedPath(file);
      setInspection(null);
      setError(null);
    }
  };

  const importSealed = async () => {
    setError(null);
    setInspection(null);
    setBusy(true);
    try {
      const imported = await api.deployInstallSealed(sealedPath.trim(), passphrase);
      setPackDir(imported.pack_dir);
      applyInspection(imported.inspection);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  const inspect = async () => {
    setError(null);
    setInspection(null);
    setBusy(true);
    try {
      applyInspection(await api.inspectPack(packDir.trim()));
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  /// Publish one inspection and start the transport control from the pack's
  /// signed default. The control is not rendered before this point, so the
  /// reset can never overwrite a user choice — it IS the initial value
  /// ((internal design notes):
  /// a hardcoded h2 start silently overrode packs signed `quic`).
  const applyInspection = (result: PackInspection) => {
    setInspection(result);
    setTransport(result.transport ?? "h2");
  };

  const add = async () => {
    setError(null);
    setBusy(true);
    try {
      // Only a choice that DIFFERS from the pack's signed default becomes a
      // persisted local preference; the default itself stores null so the
      /// pack stays authoritative across future re-issues.
      const packDefault = inspection?.transport ?? "h2";
      const params: AddNodeParams = {
        pack_dir: packDir.trim(),
        transport: isAgent && transport !== packDefault ? transport : null,
        hub_quic_addr: isAgent && transport === "quic" && hubQuicAddr.trim() !== "" ? hubQuicAddr.trim() : null,
      };
      const created = await api.addNode(params);
      await onAdded(created.id);
    } catch (e) {
      setError(String(e));
      setBusy(false);
    }
  };

  return (
    <Modal onClose={onClose}>
      <DialogTitle>{t("addNode.title")}</DialogTitle>
      <Field label={t("addNode.credentialPack")}>
        {(id) => (
          <div className="flex min-w-0 flex-1 items-center gap-2">
            <Input
              id={id}
              value={packDir}
              onChange={(e) => {
                setPackDir(e.target.value);
                setInspection(null);
              }}
              placeholder={t("addNode.packDirPlaceholder")}
              autoCapitalize="none"
              autoCorrect="off"
              spellCheck={false}
              autoComplete="off"
              className="flex-1"
            />
            <Button onClick={pickPackDir}>{t("common.browse")}</Button>
            <Button variant="primary" disabled={busy || packDir.trim() === ""} onClick={inspect}>
              {busy ? "…" : t("addNode.inspect")}
            </Button>
          </div>
        )}
      </Field>

      <div className="flex flex-col gap-2 border-t border-dashed border-line pt-3">
        <Field label={t("addNode.orImportSealed")}>
          {(id) => (
            <div className="flex min-w-0 flex-1 items-center gap-2">
              <Input
                id={id}
                value={sealedPath}
                onChange={(e) => {
                  setSealedPath(e.target.value);
                  setInspection(null);
                }}
                placeholder={t("addNode.sealedPlaceholder")}
                autoCapitalize="none"
                autoCorrect="off"
                spellCheck={false}
                autoComplete="off"
                className="flex-1"
              />
              <Button onClick={pickSealed}>{t("common.browse")}</Button>
            </div>
          )}
        </Field>
        {sealedPath.trim() !== "" && (
          <Field label={t("common.passphrase")}>
            {(id) => (
              <div className="flex min-w-0 flex-1 items-center gap-2">
                <Input
                  id={id}
                  type="password"
                  value={passphrase}
                  onChange={(e) => setPassphrase(e.target.value)}
                  autoComplete="off"
                  className="flex-1"
                />
                <Button
                  variant="primary"
                  disabled={busy || passphrase === ""}
                  onClick={importSealed}
                >
                  {busy ? "…" : t("addNode.import")}
                </Button>
              </div>
            )}
          </Field>
        )}
      </div>

      {inspection && (
        <div className="flex flex-col gap-2.5 rounded-lg border border-line bg-bg-3 p-3">
          <div className="flex items-center gap-2">
            <KindBadge kind={inspection.kind} />
            <strong>{inspection.name}</strong>
            <span className="text-small text-fg-3">— {kindBlurb(inspection.kind, t)}</span>
          </div>
          <dl className="m-0 grid grid-cols-[130px_1fr] gap-x-2.5 gap-y-1 text-base">
            <dt className="text-fg-3">{t("addNode.identity")}</dt>
            <dd className="m-0 break-all">{inspection.principal}</dd>
            <dt>
              {inspection.kind === "hub" || inspection.kind === "ingress"
                ? t("addNode.listensOn")
                : t("addNode.connectsTo")}
            </dt>
            <dd className="m-0 break-all">{inspection.listen ?? inspection.control_endpoint}</dd>
            {inspection.services.length > 0 && (
              <>
                <dt className="text-fg-3">{t("addNode.services")}</dt>
                <dd className="m-0 break-all">{inspection.services.join(", ")}</dd>
              </>
            )}
            {(inspection.mesh_ingress > 0 || inspection.mesh_egress > 0) && (
              <>
                <dt className="text-fg-3">{t("addNode.meshRules")}</dt>
                <dd className="m-0">
                  {t("nodeCard.meshRules", {
                    in: inspection.mesh_ingress,
                    out: inspection.mesh_egress,
                  })}
                </dd>
              </>
            )}
            {inspection.credential && (
              <>
                <dt className="text-fg-3">{t("addNode.credentialsExpire")}</dt>
                <dd
                  className={cn(
                    "m-0",
                    leafPhase(inspection.credential) === "warn" && "text-warn",
                    leafPhase(inspection.credential) === "critical" && "text-critical",
                  )}
                >
                  {inspection.credential.not_after} ·{" "}
                  {t("addNode.timeLeft", {
                    time: formatRemainingSecs(inspection.credential.remaining_secs),
                  })}
                </dd>
              </>
            )}
          </dl>

          {isAgent && (
            <div className="flex flex-col gap-2 border-t border-line pt-2.5">
              <div className="flex items-center gap-2">
                <span className="w-[140px] shrink-0 text-base text-fg-2">
                  {t("prefs.transport")}
                </span>
                <SegmentedControl
                  value={transport}
                  options={[
                    { value: "h2", label: "h2" },
                    { value: "quic", label: "QUIC" },
                  ]}
                  onChange={setTransport}
                />
                <span className="text-small text-fg-3" title={t("prefs.transportPersistTitle")}>
                  {t("prefs.packDefaultHint", { value: inspection.transport ?? "h2" })}
                </span>
              </div>
              {transport === "quic" && (
                <Field label={t("prefs.hubQuicAddr")}>
                  {(id) => (
                    <Input
                      id={id}
                      value={hubQuicAddr}
                      onChange={(e) => setHubQuicAddr(e.target.value)}
                      placeholder={t("prefs.hubQuicPlaceholder")}
                      autoCapitalize="none"
                      autoCorrect="off"
                      spellCheck={false}
                      autoComplete="off"
                    />
                  )}
                </Field>
              )}
            </div>
          )}
        </div>
      )}

      {error && (
        <div className="text-base whitespace-pre-wrap text-critical">{error}</div>
      )}

      <DialogFooter>
        <Button onClick={onClose}>{t("common.cancel")}</Button>
        <Button variant="primary" disabled={busy || !inspection} onClick={add}>
          {t("addNode.addButton")}
        </Button>
      </DialogFooter>
    </Modal>
  );
}
