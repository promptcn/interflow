import { useCallback, useEffect, useMemo, useState } from "react";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import {
  api,
  type ApplyReportDto,
  type DeployContextDto,
  type DeployPackDto,
} from "../api";
import { SegmentedControl } from "../components/ui";
import { useT } from "../i18n";
import { rememberContext } from "../lib/deploySteps";
import { packIdentities } from "../lib/packStatus";
import IssuePackDialog from "../components/IssuePackDialog";
import ManifestEditor from "../components/ManifestEditor";
import PackDetail from "../components/PackDetail";
import PackOverview from "../components/PackOverview";
import { useDeployment } from "./DeploymentContext";

/// 高级: the escape hatch — the manifest document (Form/TOML, two
/// projections of one text) and the raw dist pack tree, where the engine's
/// own vocabulary (manifest / pack / generation / apply / seal) lives
/// freely. Structured edits from the other views land in the same document
/// this editor shows; Save stays the editor's own write path.
export default function AdvancedView({
  selectedPack,
  onSelectPack,
}: {
  selectedPack: string | null;
  onSelectPack: (principal: string | null) => void;
}) {
  const { t } = useT();
  const { deployment, text, savedText, setText, save, busy, say, nodesChanged } = useDeployment();
  const [packs, setPacks] = useState<DeployPackDto[]>([]);
  const [recentContexts, setRecentContexts] = useState<DeployContextDto[]>([]);
  const [issueOpen, setIssueOpen] = useState(false);
  const [subView, setSubView] = useState<"file" | "packs">("file");

  const refreshPacks = useCallback(async () => {
    if (deployment === null) return;
    try {
      setPacks(await api.deployListPacks(deployment.out_path));
    } catch (e) {
      say([`✘ ${String(e)}`]);
    }
  }, [deployment, say]);

  useEffect(() => {
    void refreshPacks();
  }, [refreshPacks]);

  // The identity model is the packs view's one truth — the overview grid
  // and the selected detail page read the same projection.
  const identities = useMemo(() => packIdentities(packs), [packs]);

  if (deployment === null) return null;

  const selected = identities.find((i) => i.principal === selectedPack) ?? null;

  const dirty = text !== null && text !== savedText;

  /// The document triple is fixed by the deployment folder; the recents
  /// list still rides the deploy prefs so the CLI-adjacent history stays.
  const triple: DeployContextDto = {
    manifest: deployment.manifest_path,
    issuer: deployment.issuer_path,
    out: deployment.out_path,
  };
  const remember = () => {
    const next = rememberContext(recentContexts, triple);
    if (next === recentContexts) return;
    setRecentContexts(next);
    api.deployPrefsSave(next).catch(() => {});
  };

  const updateLocalNode = async (pack: DeployPackDto) => {
    const local = pack.local_node;
    if (!local) return;
    try {
      const result = await api.deployUpdateNode(local.id, pack.path);
      say([
        `${pack.dir_name}: ${local.name} ${
          result.generation_from === result.generation_to
            ? t("deploy.updatedContent", {
                a: result.generation_from,
                b: result.generation_to,
              })
            : t("deploy.updatedGen", {
                from: result.generation_from,
                to: result.generation_to,
              })
        }${result.restarted ? t("deploy.restarted") : t("deploy.leftStopped")}`,
      ]);
      await Promise.all([refreshPacks(), nodesChanged()]);
    } catch (e) {
      say([`✘ ${String(e)}`]);
    }
  };

  const seal = async (pack: DeployPackDto, target: string, passphrase: string) => {
    try {
      await api.deploySealPack(pack.path, target, passphrase);
      say([t("deploy.sealedLine", { pack: pack.dir_name, target })]);
    } catch (e) {
      say([`✘ ${String(e)}`]);
    }
  };

  const copyInstallCommand = async (pack: DeployPackDto) => {
    const command = `sudo interflow-cli node install --pack ${pack.path}`;
    try {
      await writeText(command);
      say([t("deploy.copiedLine", { command })]);
    } catch {
      say([t("deploy.onServerLine", { command })]);
    }
  };

  const rotate = async (pack: DeployPackDto) => {
    const node = `${pack.kind === "hub" ? "hub" : pack.kind === "ingress" ? "ingress" : "agent"}/${pack.node}`;
    try {
      say(await api.deployRotate(deployment.manifest_path, deployment.issuer_path, node, pack.path));
      await Promise.all([refreshPacks(), nodesChanged()]);
    } catch (e) {
      say([`✘ ${String(e)}`]);
    }
  };

  const revoke = async (pack: DeployPackDto) => {
    try {
      say(await api.deployRevoke(deployment.issuer_path, pack.path, "key-compromise"));
      await Promise.all([refreshPacks(), nodesChanged()]);
    } catch (e) {
      say([`✘ ${String(e)}`]);
    }
  };

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-2.5">
      <SegmentedControl
        value={selected !== null ? "packs" : subView}
        options={[
          { value: "file", label: t("dep.advanced.file") },
          { value: "packs", label: t("deploy.packs") },
        ]}
        onChange={(v) => {
          setSubView(v);
          if (v === "file") onSelectPack(null);
        }}
      />
      {selected ? (
        <PackDetail
          identity={selected}
          busy={busy}
          onBack={() => onSelectPack(null)}
          onUpdateLocal={(pack) => void updateLocalNode(pack)}
          onSeal={seal}
          onCopyInstallCommand={(pack) => void copyInstallCommand(pack)}
          onRotate={(pack) => void rotate(pack)}
          onRevoke={(pack) => void revoke(pack)}
        />
      ) : (
        <>
          {subView === "file" && (
          <ManifestEditor
            compact
            manifest={deployment.manifest_path}
            issuer={deployment.issuer_path}
            out={deployment.out_path}
            placeholders={{}}
            text={text}
            busy={busy}
            dirty={dirty}
            recentContexts={recentContexts}
            onManifestChange={() => {}}
            onIssuerChange={() => {}}
            onOutChange={() => {}}
            onPickContext={() => {}}
            onTextChange={setText}
            onPickFile={async () => {}}
            onLoad={async () => {
              const loaded = await api.deployReadText(deployment.manifest_path);
              setText(loaded.text);
            }}
            onSave={async () => {
              if ((await save()) !== false) {
                say([t("deploy.savedLine", { path: deployment.manifest_path })]);
                remember();
              }
            }}
            onValidate={async () => {
              say(await api.deployValidate(deployment.manifest_path));
            }}
            onApply={async () => {
              // Advanced keeps the direct apply (engine vocabulary); the
              // other views' orchestration lives in the Publish button.
              if (dirty && text !== null) await save();
              const report: ApplyReportDto = await api.deployApply(
                deployment.manifest_path,
                deployment.issuer_path,
                deployment.out_path,
              );
              say(report.lines);
              await refreshPacks();
            }}
          />
          )}
          {subView === "packs" && (
          <PackOverview
            packs={packs}
            busy={busy}
            onRefresh={() => void refreshPacks()}
            onOpenPack={onSelectPack}
            onUpdateLocal={(pack) => void updateLocalNode(pack)}
            onIssuePack={() => setIssueOpen(true)}
          />
          )}
        </>
      )}

      {issueOpen && (
        <IssuePackDialog
          manifest={deployment.manifest_path}
          issuer={deployment.issuer_path}
          out={deployment.out_path}
          busy={busy}
          recentContexts={recentContexts}
          onPickContext={() => {}}
          onSay={say}
          onIssued={(next) => {
            setText(next);
            void save(next);
          }}
          onComplete={() => {
            void refreshPacks();
            nodesChanged();
          }}
          onClose={() => setIssueOpen(false)}
        />
      )}

    </div>
  );
}
