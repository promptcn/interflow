import { useEffect, useState } from "react";
import { Lock } from "lucide-react";
import { api, type DeploymentDto } from "../api";
import { useT } from "../i18n";
import { createEntryVisible } from "../lib/shellFace";
import CreateDeploymentDialog from "../components/CreateDeploymentDialog";
import { Button, Modal } from "../components/ui";
import { DialogTitle } from "../components/ui/dialog";
import { InfoHint } from "../components/ui/tooltip";
import { useDeployment } from "./DeploymentContext";

/// The sidebar's scope picker (the realm-axis group's header,
/// 2026-10-15 nav re-axis): the switcher governs the WHOLE sidebar. Its
/// list is two kinds of realm context — discovered deployments
/// (writable: the manifest-editing scope) and 🔒 realms inferred from
/// this machine's packs (read-only: presence only, no deployment tree
/// behind them; a realm already covered by a discovered deployment
/// never double-lists). With no scope open the header stays a quiet
/// action (打开部署… — never a fault tone) while the group's body stays
/// collapsed, and on a node-carrying machine with no deployments found
/// the picker drops the create entry and its guidance copy — nodes are
/// the truth there, not a missing deployment.
export default function DeploymentSwitcher({
  collapsed = false,
  hasNodes = false,
  realms = [],
  realmScope = null,
  onPickDeployment,
  onPickRealm,
  onCloseScope,
}: {
  collapsed?: boolean;
  hasNodes?: boolean;
  /// This machine's inferred 🔒 realm candidates (pack principals of
  /// its mesh agents — the shell's `meshRealms(nodes)`).
  realms?: string[];
  /// The active 🔒 realm scope, if any (mutually exclusive with an open
  /// deployment).
  realmScope?: string | null;
  onPickDeployment: (root: string) => Promise<boolean>;
  onPickRealm: (name: string) => void;
  onCloseScope: () => Promise<void>;
}) {
  const { t } = useT();
  const { deployment } = useDeployment();
  const [open, setOpen] = useState(false);
  const [list, setList] = useState<DeploymentDto[]>([]);
  const [listLoaded, setListLoaded] = useState(false);
  const [root, setRoot] = useState<string | null>(null);
  const [createOpen, setCreateOpen] = useState(false);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!open) return;
    setListLoaded(false);
    void api
      .deploymentList()
      .then((l) => {
        setList(l);
        setListLoaded(true);
      })
      .catch(() => setListLoaded(true));
    void api
      .deployDefaults()
      .then((d) => setRoot(d.root))
      .catch(() => {});
  }, [open]);

  /// A discovered deployment already carries the realm's writable face —
  /// its realm never double-lists as a 🔒 entry.
  const lockedRealms = realms.filter((r) => !list.some((d) => d.name === r));

  /// The deployed-end form (nodes on board, no deployments found) speaks
  /// the neutral picker — open-only, no onboarding guidance.
  const nodeOnlyForm = listLoaded && list.length === 0 && hasNodes;

  const pick = async (path: string) => {
    setBusy(true);
    const ok = await onPickDeployment(path);
    setBusy(false);
    if (ok) setOpen(false);
  };

  const headerTitle = deployment
    ? `${deployment.name} — ${deployment.root}`
    : realmScope !== null
      ? `${realmScope} 🔒`
      : t("dep.switcher.open");

  return (
    <>
      <button
        onClick={() => setOpen(true)}
        title={headerTitle}
        className={`flex w-full cursor-pointer items-center rounded-lg border border-line bg-bg-2 py-2 text-left outline-none transition-colors duration-150 hover:bg-bg-hover focus-visible:ring-[3px] focus-visible:ring-accent-tint ${
          collapsed ? "justify-center px-0" : "gap-2 px-2.5"
        }`}
      >
        <span className="inline-block size-2 shrink-0 rounded-full bg-accent" />
        {!collapsed && (
          <>
            <span className="flex min-w-0 flex-1 items-center gap-1.5">
              <span className="truncate text-base font-medium">
                {deployment
                  ? deployment.name
                  : realmScope !== null
                    ? realmScope
                    : t("dep.switcher.open")}
              </span>
              {deployment === null && realmScope !== null && (
                <Lock
                  className="size-3.5 shrink-0 text-fg-3"
                  aria-label="read-only"
                />
              )}
            </span>
            <span className="text-small text-fg-3">▾</span>
          </>
        )}
      </button>

      {open && (
        <Modal onClose={() => setOpen(false)}>
          <DialogTitle>
            {t("dep.switcher.title")}
            {!nodeOnlyForm && (
              <InfoHint
                text={t("dep.switcher.hint")}
                className="relative -top-px"
              />
            )}
          </DialogTitle>
          <div className="flex max-h-[50vh] flex-col gap-1 overflow-auto">
            {list.map((d) => (
              <button
                key={d.root}
                disabled={busy}
                onClick={() => void pick(d.root)}
                className={`flex cursor-pointer items-baseline justify-between rounded-lg px-2.5 py-1.5 text-left outline-none transition-colors duration-150 hover:bg-bg-hover focus-visible:ring-[3px] focus-visible:ring-accent-tint ${
                  deployment?.root === d.root ? "bg-accent-tint" : ""
                }`}
              >
                <span className="text-base font-medium">{d.name}</span>
                <span className="font-mono text-micro text-fg-3">{d.root}</span>
              </button>
            ))}
            {list.length === 0 && (
              <p className="m-0 px-2.5 py-1.5 text-small text-fg-3">
                {t("dep.onboarding.discovered")} — ∅
              </p>
            )}
            {lockedRealms.length > 0 && (
              <>
                <span className="mt-2 px-2.5 text-small font-semibold uppercase tracking-[0.05em] text-fg-3">
                  {t("dep.switcher.realms")}
                </span>
                {lockedRealms.map((name) => (
                  <button
                    key={name}
                    disabled={busy}
                    title={t("dep.switcher.lockedHint")}
                    onClick={() => {
                      onPickRealm(name);
                      setOpen(false);
                    }}
                    className={`flex cursor-pointer items-center gap-2 rounded-lg px-2.5 py-1.5 text-left outline-none transition-colors duration-150 hover:bg-bg-hover focus-visible:ring-[3px] focus-visible:ring-accent-tint ${
                      deployment === null && realmScope === name
                        ? "bg-accent-tint"
                        : ""
                    }`}
                  >
                    <Lock className="size-3.5 shrink-0 text-fg-3" aria-hidden />
                    <span className="text-base font-medium">{name}</span>
                    <span className="ml-auto text-micro text-fg-3">
                      {t("dep.switcher.lockedShort")}
                    </span>
                  </button>
                ))}
              </>
            )}
          </div>
          <div className="mt-2 flex flex-wrap gap-2">
            <Button
              size="sm"
              variant="secondary"
              onClick={async () => {
                const { open } = await import("@tauri-apps/plugin-dialog");
                const picked = await open({
                  title: t("dep.onboarding.open"),
                  directory: true,
                  defaultPath: root ?? undefined,
                });
                if (typeof picked === "string") await pick(picked);
              }}
            >
              {t("dep.onboarding.open")}
            </Button>
            {createEntryVisible(list.length > 0, hasNodes) && (
              <Button
                size="sm"
                variant="secondary"
                onClick={() => setCreateOpen(true)}
              >
                {t("dep.onboarding.create")}
              </Button>
            )}
            {(deployment !== null || realmScope !== null) && (
              <Button
                size="sm"
                variant="link"
                onClick={async () => {
                  await onCloseScope();
                  setOpen(false);
                }}
              >
                {t("common.close")}
              </Button>
            )}
          </div>
        </Modal>
      )}

      {createOpen && (
        <CreateDeploymentDialog
          root={root}
          onClose={() => setCreateOpen(false)}
          onCreated={(path) => {
            setCreateOpen(false);
            void pick(path.replace(/\/[^/]*$/, ""));
          }}
        />
      )}
    </>
  );
}
