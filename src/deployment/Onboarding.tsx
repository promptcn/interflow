import { useEffect, useState } from "react";
import { api, type DeploymentDto } from "../api";
import { useT } from "../i18n";
import AddNodeDialog from "../components/AddNodeDialog";
import CreateDeploymentDialog from "../components/CreateDeploymentDialog";
import { Button, EmptyState, SectionPanel } from "../components/ui";
import { useDeployment } from "./DeploymentContext";

/// The true-new-operator state: the shell's whole content area ONLY where
/// zero deployments AND zero nodes exist — node-carrying machines never
/// see it (their node view is the shell; deployment guidance there was the
/// wrong-direction onboarding this gating fixes).
///
/// Three entries, two audiences: Open/Create speak to the OPERATOR (the
/// machine that holds the deployment tree), "Import a node pack" speaks to
/// a pure agent machine — a `.iflowpack` carries identity, hub endpoint
/// and transport on its own, so a node machine never needs the manifest
/// the other two entries assume. Creating a deployment is demoted behind
/// an Advanced fold: for a deployed-end machine it is exactly the
/// wrong-direction button, and it used to sit on the first screen.
export default function Onboarding({ onNodesChanged }: { onNodesChanged?: () => Promise<void> }) {
  const { t } = useT();
  const { openDeployment, openPickedManifest } = useDeployment();
  const [discovered, setDiscovered] = useState<DeploymentDto[]>([]);
  const [root, setRoot] = useState<string | null>(null);
  const [createOpen, setCreateOpen] = useState(false);
  const [importOpen, setImportOpen] = useState(false);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    void api.deploymentList().then(setDiscovered).catch(() => {});
    void api
      .deployDefaults()
      .then((d) => setRoot(d.root))
      .catch(() => {});
  }, []);

  const open = async (path: string) => {
    setBusy(true);
    await openDeployment(path);
    setBusy(false);
  };

  const choose = async () => {
    const { open } = await import("@tauri-apps/plugin-dialog");
    const picked = await open({
      title: t("dep.onboarding.open"),
      directory: true,
      defaultPath: root ?? undefined,
    });
    if (typeof picked === "string") await openPickedToFolder(picked);
  };

  /// A picked folder is opened directly (it names the deployment root);
  /// a picked FILE falls back to its folder (the deployment shape).
  const openPickedToFolder = async (picked: string) => {
    setBusy(true);
    await openDeployment(picked);
    setBusy(false);
  };

  return (
    <div className="flex min-h-0 flex-1 items-start justify-center overflow-auto pt-16">
      <div className="flex w-full max-w-lg flex-col gap-3">
        <EmptyState>
          <div className="flex flex-col gap-1.5">
            <span className="text-base font-semibold text-fg-1">{t("dep.onboarding.title")}</span>
            <span className="max-w-sm">{t("dep.onboarding.body")}</span>
          </div>
        </EmptyState>
        <div className="flex items-center justify-center gap-2.5">
          <Button disabled={busy} onClick={() => void choose()}>
            {t("dep.onboarding.open")}
          </Button>
          <Button
            variant="secondary"
            onClick={() => {
              setImportOpen(true);
            }}
          >
            {t("dep.onboarding.importPack")}
          </Button>
        </div>
        <p className="m-0 text-center text-micro text-fg-3">
          {t("dep.onboarding.importPackHint")}
        </p>
        {discovered.length > 0 && (
          <SectionPanel title={t("dep.onboarding.discovered")}>
            <div className="flex flex-col gap-1">
              {discovered.map((d) => (
                <button
                  key={d.root}
                  onClick={() => void open(d.root)}
                  className="flex cursor-pointer items-baseline justify-between rounded-lg px-2.5 py-1.5 text-left text-base transition-colors duration-150 outline-none hover:bg-bg-hover focus-visible:ring-[3px] focus-visible:ring-accent-tint"
                >
                  <span className="font-medium">{d.name}</span>
                  <span className="font-mono text-micro text-fg-3">{d.root}</span>
                </button>
              ))}
            </div>
          </SectionPanel>
        )}
        <details className="group px-1">
          <summary className="cursor-pointer list-none text-micro text-fg-3 outline-none transition-colors duration-150 hover:text-fg-2 focus-visible:ring-[3px] focus-visible:ring-accent-tint">
            {t("dep.onboarding.advanced")}
          </summary>
          <div className="pt-2">
            <Button
              variant="secondary"
              onClick={() => {
                setCreateOpen(true);
              }}
            >
              {t("dep.onboarding.create")}
            </Button>
            <p className="m-0 pt-1.5 text-micro text-fg-3">{t("dep.onboarding.createHint")}</p>
          </div>
        </details>
        {importOpen && (
          <AddNodeDialog
            onClose={() => setImportOpen(false)}
            onAdded={async () => {
              setImportOpen(false);
              // The refresh is the whole handoff: with a node on board the
              // shell flips out of onboarding on its own.
              await onNodesChanged?.();
            }}
          />
        )}
        {createOpen && (
          <CreateDeploymentDialog
            root={root}
            onClose={() => setCreateOpen(false)}
            onCreated={(path) => {
              setCreateOpen(false);
              void openPickedManifest(path);
            }}
          />
        )}
      </div>
    </div>
  );
}
