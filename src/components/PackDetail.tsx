import { useState } from "react";
import { ArrowLeft } from "lucide-react";
import { type DeployPackDto } from "../api";
import { useT } from "../i18n";
import {
  packDistributeSource,
  packUpdateAction,
  packUpdateSource,
  type PackIdentity,
} from "../lib/packStatus";
import {
  Badge,
  Button,
  ConfirmDialog,
  Hint,
  InfoRow,
  Input,
  KindBadge,
  PassphraseDialog,
  SectionPanel,
} from "./ui";

/// One identity, one level below the grid. The page speaks the identity's
/// whole truth: the current material up top, the local node's relation to
/// it, the distribution surface (the open window when there is one, else
/// the current material), and the lifecycle actions grouped by intent.
/// Destructive and secret-asking steps get real dialogs, not
/// window.prompt/confirm.
export default function PackDetail({
  identity,
  busy,
  onBack,
  onUpdateLocal,
  onSeal,
  onCopyInstallCommand,
  onRotate,
  onRevoke,
}: {
  identity: PackIdentity;
  busy: boolean;
  onBack: () => void;
  onUpdateLocal: (pack: DeployPackDto) => void;
  onSeal: (pack: DeployPackDto, target: string, passphrase: string) => Promise<void>;
  onCopyInstallCommand: (pack: DeployPackDto) => void;
  onRotate: (pack: DeployPackDto) => void;
  onRevoke: (pack: DeployPackDto) => void;
}) {
  // Seal flow: pick the target file, then ask for the passphrase in a real
  // dialog (the recipient enters the same one on import).
  const [sealTarget, setSealTarget] = useState<string | null>(null);
  const [revoking, setRevoking] = useState(false);
  const { t } = useT();

  const { current, window } = identity;
  const distribute = packDistributeSource(identity);
  const updateSource = packUpdateSource(identity);

  const pickSealTarget = async () => {
    const { save } = await import("@tauri-apps/plugin-dialog");
    const target = await save({
      title: t("packDetail.sealAs", { name: distribute.dir_name }),
      defaultPath: `${distribute.dir_name}.iflowpack`,
    });
    if (typeof target === "string") setSealTarget(target);
  };

  // Same rule as the overview grid (packUpdateAction): generations move
  // forward only — a lower generation is a downgrade and renders NO action
  // at all, not even the reinstall branch (that door was the bug's second
  // face: the button relabeled but still downgraded on click).
  const action = packUpdateAction(updateSource);

  const updateTitle =
    action === "content" ? t("pack.updateTitleContent") : t("pack.updateTitle");

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-3 overflow-y-auto">
      <div className="flex flex-wrap items-center gap-2.5">
        <Button variant="link" size="sm" onClick={onBack}>
          <ArrowLeft className="size-4" />
          {t("packDetail.backPacks")}
        </Button>
        <h2 className="m-0 text-xl font-semibold">{current.node}</h2>
        <KindBadge kind={current.kind} />
        {window && (
          <Hint text={current.local_node ? t("pack.windowUpdateTitle") : t("pack.windowDistributeTitle")}>
            <Badge tone="accent">
              {t(current.local_node ? "pack.windowUpdateBadge" : "pack.windowDistributeBadge", {
                gen: window.generation,
              })}
            </Badge>
          </Hint>
        )}
      </div>

      <div className="flex min-h-0 flex-col gap-3">
        <SectionPanel
          title={t("packDetail.identity")}
          hint={t("packDetail.fromPath", { path: current.path })}
        >
          <InfoRow label={t("packDetail.principal")}>
            <Hint text={identity.principal}>
              <Input value={identity.principal} readOnly />
            </Hint>
          </InfoRow>
          <InfoRow label={t("packDetail.generation")}>
            <span className="text-small text-fg-3">
              {t("pack.genExpires", { gen: current.generation, expires: current.expires })}
            </span>
          </InfoRow>
          {current.local_node && (
            <InfoRow label={t("packDetail.localNode")}>
              <span className="text-small text-fg-3">{current.local_node.name}</span>
            </InfoRow>
          )}
        </SectionPanel>

        {current.local_node && (
          <SectionPanel title={t("packDetail.localNode")}>
            {action === "downgrade" ? (
              <span className="text-small text-fg-3">
                {t("pack.downgradeHint", {
                  local: current.local_node.generation,
                  pack: updateSource.generation,
                })}
              </span>
            ) : (
              <div className="flex flex-wrap gap-2">
                <Hint text={updateTitle}>
                  <Button
                    variant={action === "reinstall" ? "secondary" : "primary"}
                    disabled={busy}
                    onClick={() => onUpdateLocal(updateSource)}
                  >
                    {action === "upgrade"
                      ? t("packDetail.updateToGen", {
                          name: current.local_node.name,
                          gen: updateSource.generation,
                        })
                      : action === "content"
                        ? t("packDetail.updateName", { name: current.local_node.name })
                        : t("packDetail.reinstallInto", { name: current.local_node.name })}
                  </Button>
                </Hint>
              </div>
            )}
          </SectionPanel>
        )}

        <SectionPanel title={t("packDetail.distribute")}>
          <InfoRow label={t("packDetail.distributeFrom")}>
            <Hint text={distribute.path}>
              <span className="truncate font-mono text-small text-fg-3">
                {distribute.dir_name} · gen {distribute.generation}
              </span>
            </Hint>
          </InfoRow>
          <div className="flex flex-wrap gap-2">
            <Button onClick={() => void pickSealTarget()}>{t("packDetail.sealButton")}</Button>
            <Button onClick={() => onCopyInstallCommand(distribute)}>
              {t("packDetail.copyInstall")}
            </Button>
          </div>
        </SectionPanel>

        <SectionPanel title={t("packDetail.maintenance")}>
          <div className="flex flex-wrap gap-2">
            <Button disabled={busy} onClick={() => onRotate(current)}>
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
          title={t("packDetail.sealTitle", { name: distribute.dir_name })}
          description={t("packDetail.sealDesc")}
          confirmLabel={t("packDetail.sealConfirm")}
          generate
          onClose={() => setSealTarget(null)}
          onConfirm={async (passphrase) => {
            const target = sealTarget;
            setSealTarget(null);
            await onSeal(distribute, target, passphrase);
          }}
        />
      )}

      {revoking && (
        <ConfirmDialog
          title={t("packDetail.revokeTitle", { name: current.node })}
          message={t("packDetail.revokeMessage")}
          confirmLabel={t("packDetail.revokeConfirm")}
          danger
          onClose={() => setRevoking(false)}
          onConfirm={() => {
            setRevoking(false);
            onRevoke(current);
          }}
        />
      )}
    </div>
  );
}
