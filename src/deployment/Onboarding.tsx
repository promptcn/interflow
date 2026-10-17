import { useEffect, useState } from "react";
import { api, type DeploymentDto } from "../api";
import { useT } from "../i18n";
import CreateDeploymentDialog from "../components/CreateDeploymentDialog";
import { Button, EmptyState, SectionPanel } from "../components/ui";
import { useDeployment } from "./DeploymentContext";

/// The true-new-operator state: the shell's whole content area ONLY where
/// zero deployments AND zero nodes exist — node-carrying machines never
/// see it (their node view is the shell; deployment guidance there was the
/// wrong-direction onboarding this gating fixes). Open an existing
/// deployment (native picker or the discovered list) or create one from a
/// template — the two entries the old Nodes-face dead end never pointed
/// at (audit friction #1).
export default function Onboarding() {
  const { t } = useT();
  const { openDeployment, openPickedManifest } = useDeployment();
  const [discovered, setDiscovered] = useState<DeploymentDto[]>([]);
  const [root, setRoot] = useState<string | null>(null);
  const [createOpen, setCreateOpen] = useState(false);
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
          <Button variant="secondary" onClick={() => setCreateOpen(true)}>
            {t("dep.onboarding.create")}
          </Button>
        </div>
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
