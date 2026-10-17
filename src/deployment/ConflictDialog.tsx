import { Button, Modal } from "../components/ui";
import { useT } from "../i18n";
import { useDeployment } from "./DeploymentContext";

/// The changed-on-disk guard's resolution surface: another writer (a
/// terminal CLI run, another editor window) saved the manifest while it
/// was open here. The disk's current version is shown verbatim; adopting
/// it is the only forward that cannot destroy the other writer's work —
/// re-apply local edits on top. There is deliberately no "overwrite"
/// button: silently discarding the other writer's edit is exactly the
/// lost-update this guard exists to prevent.
export default function ConflictDialog() {
  const { t } = useT();
  const dep = useDeployment();
  if (dep.conflict === null) return null;
  return (
    <Modal onClose={dep.keepLocalVersion} wide>
      <div className="flex flex-col gap-3">
        <h2 className="text-lg font-medium">{t("manifest.conflictTitle")}</h2>
        <p className="text-base text-fg-2">{t("manifest.conflictBody")}</p>
        <textarea
          readOnly
          value={dep.conflict.diskText}
          spellCheck={false}
          className="max-h-[40vh] min-h-[160px] resize-y rounded-lg border border-line bg-bg-3 p-2.5 font-mono text-small text-fg-1"
        />
        <div className="flex justify-end gap-2">
          <Button onClick={dep.keepLocalVersion}>{t("manifest.conflictKeep")}</Button>
          <Button variant="primary" onClick={dep.takeDiskVersion}>
            {t("manifest.conflictTakeDisk")}
          </Button>
        </div>
      </div>
    </Modal>
  );
}
