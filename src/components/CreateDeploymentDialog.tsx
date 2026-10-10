import { useState } from "react";
import { api } from "../api";
import { useT } from "../i18n";
import TemplateBuilder from "./TemplateBuilder";
import { Button, DialogFooter, DialogTitle, Modal } from "./ui";

/// The create-deployment dialog (2026-10-09 first-run backlog): the
/// template builder's write half. Generate → native save dialog (the
/// per-OS default as the starting point) → the create command, which
/// refuses an existing file — the `interflow-cli setup` semantic, so a
/// live manifest is never silently replaced. On success the caller gets
/// the chosen path and the deployment loads; a refusal (or a cancelled
/// save dialog) stays inside the dialog.
export default function CreateDeploymentDialog({
  root,
  onClose,
  onCreated,
}: {
  /// The deployments root (`deploy_defaults`) — the save dialog starts at
  /// `<root>/<realm>/interflow.toml`; null while it loads (generation can
  /// still proceed, the dialog just starts elsewhere).
  root: string | null;
  onClose: () => void;
  /// The deployment was created at this path (issuer/out blank-fill and
  /// context remembering are the owner's job).
  onCreated: (path: string) => void;
}) {
  const { t } = useT();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const create = async (text: string, realm: string) => {
    setBusy(true);
    setError(null);
    try {
      const { save } = await import("@tauri-apps/plugin-dialog");
      const target = await save({
        title: t("manifest.saveToTitle"),
        defaultPath: root === null ? undefined : `${root}/${realm}/interflow.toml`,
      });
      if (typeof target !== "string") return; // cancelled — back to the form
      await api.deployCreateManifest(target, text);
      onCreated(target);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal onClose={busy ? () => {} : onClose}>
      <DialogTitle>{t("overview.createTitle")}</DialogTitle>
      <div className="flex flex-col gap-2.5">
        <p className="m-0 text-small text-fg-3">{t("overview.createHint")}</p>
        <div className="flex flex-wrap items-center gap-2">
          <TemplateBuilder onGenerated={(text, realm) => void create(text, realm)} />
        </div>
        {error && (
          <div className="rounded-lg border border-critical/40 bg-critical/10 p-2.5 text-base whitespace-pre-wrap text-critical">
            {error}
          </div>
        )}
      </div>
      <DialogFooter>
        <Button onClick={onClose} disabled={busy}>
          {t("common.cancel")}
        </Button>
      </DialogFooter>
    </Modal>
  );
}
