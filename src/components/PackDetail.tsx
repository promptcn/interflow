import { useState } from "react";
import { type DeployPackDto } from "../api";
import { ConfirmDialog, KindBadge, PassphraseDialog, SectionPanel } from "./ui";

/// One issued pack, one level below the grid. Identity and generation state
/// up top; the lifecycle actions grouped by intent (distribute / maintain /
/// destructive) instead of the old five-button wall. Destructive and
/// secret-asking steps get real dialogs, not window.prompt/confirm.
export default function PackDetail({
  pack,
  out,
  busy,
  onBack,
  onUpdateLocal,
  onSeal,
  onCopyInstallCommand,
  onRotate,
  onRevoke,
}: {
  pack: DeployPackDto;
  out: string;
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

  const pickSealTarget = async () => {
    const { save } = await import("@tauri-apps/plugin-dialog");
    const target = await save({
      title: `Seal ${pack.dir_name} as .iflowpack`,
      defaultPath: `${pack.dir_name}.iflowpack`,
    });
    if (typeof target === "string") setSealTarget(target);
  };

  const updateAvailable = !!pack.local_node && pack.local_node.generation < pack.generation;

  return (
    <div className="detail-page">
      <div className="detail-topbar">
        <button className="back" onClick={onBack} title="Esc">
          ← Packs
        </button>
        <h2>{pack.dir_name}</h2>
        <KindBadge kind={pack.kind} />
      </div>

      <div className="detail-body">
        <SectionPanel title="Identity" hint={`from ${out}/packs/${pack.dir_name}`}>
          <div className="row">
            <label>Principal</label>
            <input value={pack.principal} readOnly title={pack.principal} />
          </div>
          <div className="row">
            <label>Generation</label>
            <span className="hint">gen {pack.generation} · expires {pack.expires}</span>
          </div>
          {pack.local_node && (
            <div className="row">
              <label>Local node</label>
              <span className="hint">{pack.local_node.name}</span>
            </div>
          )}
        </SectionPanel>

        {pack.local_node && (
          <SectionPanel title="Local node">
            <div className="actions">
              <button
                className={updateAvailable ? "primary" : ""}
                disabled={busy}
                onClick={onUpdateLocal}
                title="stop, swap the pack in place (state kept), restart"
              >
                {updateAvailable
                  ? `Update ${pack.local_node.name} to gen ${pack.generation}`
                  : `Reinstall into ${pack.local_node.name}`}
              </button>
            </div>
          </SectionPanel>
        )}

        <SectionPanel title="Distribute">
          <div className="actions">
            <button onClick={() => void pickSealTarget()}>Seal .iflowpack…</button>
            <button onClick={onCopyInstallCommand}>Copy install command</button>
          </div>
        </SectionPanel>

        <SectionPanel title="Maintenance">
          <div className="actions">
            <button disabled={busy} onClick={onRotate}>
              Rotate
            </button>
            <button className="danger" onClick={() => setRevoking(true)}>
              Revoke…
            </button>
          </div>
        </SectionPanel>
      </div>

      {sealTarget !== null && (
        <PassphraseDialog
          title={`Seal ${pack.dir_name}`}
          description="The recipient enters it on import."
          confirmLabel="Seal"
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
          title={`Revoke ${pack.dir_name}?`}
          message="Credentials stop being accepted everywhere (deny list + CRL). This cannot be undone."
          confirmLabel="Revoke"
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
