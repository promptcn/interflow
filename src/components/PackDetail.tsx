import { useState } from "react";
import { ArrowLeft } from "lucide-react";
import { type DeployPackDto } from "../api";
import { useT } from "../i18n";
import {
  Button,
  ConfirmDialog,
  Hint,
  InfoRow,
  Input,
  Kbd,
  KindBadge,
  PassphraseDialog,
  SectionPanel,
} from "./ui";

/// One issued pack, one level below the grid. Identity and generation state
/// up top; the lifecycle actions grouped by intent (distribute / maintain /
/// destructive) instead of the old five-button wall. Destructive and
/// secret-asking steps get real dialogs, not window.prompt/confirm.
export default function PackDetail({
  pack,
  busy,
  onBack,
  onUpdateLocal,
  onSeal,
  onCopyInstallCommand,
  onRotate,
  onRevoke,
}: {
  pack: DeployPackDto;
  busy: boolean;
  onBack: () => void;
  onUpdateLocal: () => void;
  onSeal: (pack: DeployPackDto, target: string, passphrase: string) => Promise<void>;
  onCopyInstallCommand: () => void;
  onRotate: () => void;
  onRevoke: () => void;
}) {
  // Seal flow: pick the target file, then ask for the passphrase in a real
  // dialog (the recipient enters the same one on import).
  const [sealTarget, setSealTarget] = useState<string | null>(null);
  const [revoking, setRevoking] = useState(false);
  const { t } = useT();

  const pickSealTarget = async () => {
    const { save } = await import("@tauri-apps/plugin-dialog");
    const target = await save({
      title: t("packDetail.sealAs", { name: pack.dir_name }),
      defaultPath: `${pack.dir_name}.iflowpack`,
    });
    if (typeof target === "string") setSealTarget(target);
  };

  // Same rule as the overview grid: a higher generation OR a different
  // content digest means the dist pack differs from what the local node
  // runs (a re-applied manifest re-renders the same generation with new
  // content).
  const updateAvailable =
    !!pack.local_node &&
    (pack.local_node.generation < pack.generation || pack.local_node.digest !== pack.digest);

  const updateTitle =
    updateAvailable && (pack.local_node?.generation ?? 0) >= pack.generation
      ? t("pack.updateTitleContent")
      : t("pack.updateTitle");

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-3 overflow-y-auto">
      <div className="flex flex-wrap items-center gap-2.5">
        <Button variant="link" size="sm" onClick={onBack}>
          <ArrowLeft className="size-4" />
          {t("packDetail.backPacks")}
          <Kbd>Esc</Kbd>
        </Button>
        <h2 className="m-0 text-xl font-semibold">{pack.dir_name}</h2>
        <KindBadge kind={pack.kind} />
      </div>

      <div className="flex min-h-0 flex-col gap-3">
        <SectionPanel
          title={t("packDetail.identity")}
          hint={t("packDetail.fromPath", { path: pack.path })}
        >
          <InfoRow label={t("packDetail.principal")}>
            <Hint text={pack.principal}>
              <Input value={pack.principal} readOnly />
            </Hint>
          </InfoRow>
          <InfoRow label={t("packDetail.generation")}>
            <span className="text-small text-fg-3">
              {t("pack.genExpires", { gen: pack.generation, expires: pack.expires })}
            </span>
          </InfoRow>
          {pack.local_node && (
            <InfoRow label={t("packDetail.localNode")}>
              <span className="text-small text-fg-3">{pack.local_node.name}</span>
            </InfoRow>
          )}
        </SectionPanel>

        {pack.local_node && (
          <SectionPanel title={t("packDetail.localNode")}>
            <div className="flex flex-wrap gap-2">
              <Hint text={updateTitle}>
                <Button
                  variant={updateAvailable ? "primary" : "secondary"}
                  disabled={busy}
                  onClick={onUpdateLocal}
                >
                  {updateAvailable
                    ? pack.local_node.generation < pack.generation
                      ? t("packDetail.updateToGen", {
                          name: pack.local_node.name,
                          gen: pack.generation,
                        })
                      : t("packDetail.updateName", { name: pack.local_node.name })
                    : t("packDetail.reinstallInto", { name: pack.local_node.name })}
                </Button>
              </Hint>
            </div>
          </SectionPanel>
        )}

        <SectionPanel title={t("packDetail.distribute")}>
          <div className="flex flex-wrap gap-2">
            <Button onClick={() => void pickSealTarget()}>{t("packDetail.sealButton")}</Button>
            <Button onClick={onCopyInstallCommand}>{t("packDetail.copyInstall")}</Button>
          </div>
        </SectionPanel>

        <SectionPanel title={t("packDetail.maintenance")}>
          <div className="flex flex-wrap gap-2">
            <Button disabled={busy} onClick={onRotate}>
              {t("packDetail.rotate")}
            </Button>
            <Button variant="danger" onClick={() => setRevoking(true)}>
              {t("packDetail.revoke")}
            </Button>
          </div>
        </SectionPanel>
      </div>

      {sealTarget !== null && (
        <PassphraseDialog
          title={t("packDetail.sealTitle", { name: pack.dir_name })}
          description={t("packDetail.sealDesc")}
          confirmLabel={t("packDetail.sealConfirm")}
          generate
          onClose={() => setSealTarget(null)}
          onConfirm={async (passphrase) => {
            const target = sealTarget;
            setSealTarget(null);
            await onSeal(pack, target, passphrase);
          }}
        />
      )}

      {revoking && (
        <ConfirmDialog
          title={t("packDetail.revokeTitle", { name: pack.dir_name })}
          message={t("packDetail.revokeMessage")}
          confirmLabel={t("packDetail.revokeConfirm")}
          danger
          onClose={() => setRevoking(false)}
          onConfirm={() => {
            setRevoking(false);
            onRevoke();
          }}
        />
      )}
    </div>
  );
}
