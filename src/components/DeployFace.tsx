import { useCallback, useEffect, useRef, useState } from "react";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import {
  api,
  type ApplyReportDto,
  type ControlProposalDto,
  type DeployContextDto,
  type DeployPackDto,
  type ManifestSummaryDto,
} from "../api";
import { ChevronDown, ChevronRight } from "lucide-react";
import { useT } from "../i18n";
import { rememberContext, withBlankSiblingsFilled } from "../lib/deploySteps";
import CreateDeploymentDialog from "./CreateDeploymentDialog";
import DeployOverview from "./DeployOverview";
import IssuePackDialog from "./IssuePackDialog";
import ManifestEditor from "./ManifestEditor";
import PackDetail from "./PackDetail";
import PackOverview from "./PackOverview";
import { Button, Hint, SegmentedControl } from "./ui";
import StreamDialog, { type StreamFields } from "./StreamDialog";

/// The deploy (operator) face, task-first (2026-10-08 deploy-legibility
/// backlog): the Overview lands — the deployment's shape (fleet table),
/// the task entries (add stream / adjust / apply / rotate), the derived
/// next steps, and the last apply's generation + convergence. Packs and
/// the full manifest editor stay one nav-click away (the schema-complete
/// form is the escape hatch, not the front door). The output strip at the
/// bottom is the face's single command-output surface, shared by all
/// views.
///
/// Navigation state (view, selected pack) lives in App so Esc and face
/// switches stay coherent; paths, manifest text, and the pack list live
/// here so switching views never loses editor state.
export type DeployView = "overview" | "packs" | "manifest";

interface Props {
  view: DeployView;
  selectedPack: string | null;
  onViewChange: (view: DeployView) => void;
  onSelectPack: (dirName: string | null) => void;
  onError: (message: string) => void;
  /// Local nodes can change under a deploy action (update/rotate/revoke) —
  /// the nodes face cards must re-read.
  onNodesChanged: () => Promise<void>;
}

export default function DeployFace({
  view,
  selectedPack,
  onViewChange,
  onSelectPack,
  onError,
  onNodesChanged,
}: Props) {
  const { t } = useT();
  // Paths start EMPTY on a fresh install — never a placeholder pointing at
  // a file nothing creates (the 2026-10-09 first-run bug: `~/interflow.toml`
  // surfaced as "fix the manifest's TOML syntax"). The remembered context
  // restores them on mount, and the per-OS defaults (`deploy_default_paths`)
  // back the placeholders and the create-deployment flow. Hand-typing `~`
  // works; the backend expands it.
  const [manifest, setManifest] = useState("");
  const [issuer, setIssuer] = useState("");
  const [out, setOut] = useState("");
  const [root, setRoot] = useState<string | null>(null);
  const [recentContexts, setRecentContexts] = useState<DeployContextDto[]>([]);
  const [prefsLoaded, setPrefsLoaded] = useState(false);
  const [issueOpen, setIssueOpen] = useState(false);
  const [createOpen, setCreateOpen] = useState(false);
  // The manifest text being edited (loaded/saved by path; the template
  // builder seeds it). `savedText` is what was last on disk — the gap
  // between the two is the editor's dirty state (Save or discard closes
  // it; Apply closes it by saving first: Apply means "make the saved
  // manifest live").
  const [text, setText] = useState<string | null>(null);
  const [savedText, setSavedText] = useState<string | null>(null);
  // The on-disk document's read model — the Overview's data (fleet table,
  // next steps). Re-read whenever the paths move and after every write
  // path (save / apply / issue wizard / stream wizard). Read and parse
  // failures are separate classes: a missing file is a load problem (pick
  // or create one), unparseable text is the editor's.
  const [diskSummary, setDiskSummary] = useState<ManifestSummaryDto | null>(null);
  const [diskParseError, setDiskParseError] = useState<string | null>(null);
  const [diskReadError, setDiskReadError] = useState<string | null>(null);
  // The last apply's structured outcome — the Overview's result card.
  const [lastApply, setLastApply] = useState<ApplyReportDto | null>(null);
  const [output, setOutput] = useState<string[]>([]);
  const [outputOpen, setOutputOpen] = useState(false);
  const [packs, setPacks] = useState<DeployPackDto[]>([]);
  const [busy, setBusy] = useState(false);
  // The add/adjust-stream wizard (undefined = closed; {} = add mode).
  const [streamEdit, setStreamEdit] = useState<
    { agent?: string; ruleName?: string } | undefined
  >(undefined);
  // The hub's proposal queue + a low-frequency refresher — the operator
  // sees "someone is waiting on you" without keeping the Overview open.
  const [proposals, setProposals] = useState<ControlProposalDto[] | null>(null);
  const [proposalsBusy, setProposalsBusy] = useState(false);
  const pendingProposals = (proposals ?? []).filter((p) => p.status.status === "pending");

  // Restore the last-used deployment context on mount (convenience only —
  // a failure keeps the empty paths), and fetch the deployments root that
  // backs the placeholders and the create flow (one deployment = one
  // realm-named folder under it).
  useEffect(() => {
    let cancelled = false;
    api
      .deployDefaults()
      .then((d) => {
        if (!cancelled) setRoot(d.root);
      })
      .catch(() => {
        // Placeholders stay absent; nothing functional depends on them.
      });
    void (async () => {
      try {
        const prefs = await api.deployPrefsLoad();
        if (!cancelled && prefs.recent.length > 0) {
          setRecentContexts(prefs.recent);
          setManifest(prefs.recent[0].manifest);
          setIssuer(prefs.recent[0].issuer);
          setOut(prefs.recent[0].out);
        }
      } catch {
        // Empty paths stand.
      } finally {
        if (!cancelled) setPrefsLoaded(true);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  /// A context is remembered only in use — a successful read, write, or
  /// an explicit pick. Typed-but-never-loaded paths never persist (the
  /// 2026-10-09 bug: the placeholder triple wrote itself into the recents
  /// on every launch and came back forever).
  const remember = (ctx?: DeployContextDto) => {
    const triple = ctx ?? { manifest: manifest.trim(), issuer: issuer.trim(), out: out.trim() };
    const next = rememberContext(recentContexts, triple);
    if (next === recentContexts) return;
    setRecentContexts(next);
    api.deployPrefsSave(next).catch(() => {});
  };
  // refreshDisk's effect keys on the manifest alone, so it reaches the
  // latest remember/sibling values through refs instead of stale closures.
  const rememberRef = useRef(remember);
  rememberRef.current = remember;
  const siblingsRef = useRef({ issuer, out });
  siblingsRef.current = { issuer, out };

  const pickContext = (ctx: DeployContextDto) => {
    setManifest(ctx.manifest);
    setIssuer(ctx.issuer);
    setOut(ctx.out);
    remember(ctx);
  };

  const say = (lines: string[]) => {
    setOutput((prev) => [...prev, ...lines]);
    setOutputOpen(true);
  };

  const pickFile = async (setter: (v: string) => void, directory: boolean, title: string) => {
    const { open } = await import("@tauri-apps/plugin-dialog");
    const picked = await open({ title, directory });
    if (typeof picked === "string") setter(picked);
  };

  /// The Overview's empty/missing-file entry: pick an existing manifest
  /// with the native dialog, starting from the deployments root. Loading,
  /// sibling fill, and remembering all ride the usual manifest-change
  /// refresh — this only moves the path.
  const chooseManifest = async () => {
    const { open } = await import("@tauri-apps/plugin-dialog");
    const picked = await open({
      title: t("manifest.chooseManifest"),
      directory: false,
      defaultPath: root ?? undefined,
    });
    if (typeof picked === "string") setManifest(picked);
  };

  /// Reads the manifest from disk into the overview's read model (and
  /// lazily into the editor, so opening the manifest view is instant).
  /// Read failure and parse failure land in separate slots — the Overview
  /// answers a missing file with "pick or create one", and a syntax error
  /// with the editor.
  const refreshDisk = useCallback(async () => {
    const path = manifest.trim();
    if (path === "") {
      setDiskSummary(null);
      setDiskParseError(null);
      setDiskReadError(null);
      return;
    }
    try {
      const loaded = await api.deployReadText(path);
      setDiskReadError(null);
      try {
        const summary = await api.deployParseManifest(loaded);
        setDiskSummary(summary);
        setDiskParseError(null);
      } catch (e) {
        setDiskSummary(null);
        setDiskParseError(String(e));
      }
      setText((prev) => prev ?? loaded);
      setSavedText((prev) => prev ?? loaded);
      // A manifest that reads is a context in use: blank issuer/out take
      // the manifest's own directory (the one-folder convention; typed
      // values are never overwritten) and the triple is remembered.
      const { issuer: curIssuer, out: curOut } = siblingsRef.current;
      const ctx = withBlankSiblingsFilled({ manifest: path, issuer: curIssuer, out: curOut });
      if (ctx.issuer !== curIssuer) setIssuer(ctx.issuer);
      if (ctx.out !== curOut) setOut(ctx.out);
      rememberRef.current(ctx);
    } catch (e) {
      setDiskSummary(null);
      setDiskParseError(null);
      setDiskReadError(String(e));
    }
  }, [manifest]);

  useEffect(() => {
    if (!prefsLoaded) return;
    void refreshDisk();
  }, [prefsLoaded, refreshDisk]);

  const refreshProposals = useCallback(async () => {
    if (manifest.trim() === "" || issuer.trim() === "") return;
    try {
      setProposals(await api.deployListProposals(manifest.trim(), issuer.trim()));
    } catch {
      // Unreachable hub / unreadable issuer — the queue simply reads as
      // unknown; the Overview's own hub state carries the reason.
    }
  }, [manifest, issuer]);

  useEffect(() => {
    if (!prefsLoaded) return;
    void refreshProposals();
    const timer = setInterval(() => void refreshProposals(), 60_000);
    return () => clearInterval(timer);
  }, [prefsLoaded, refreshProposals, lastApply]);

  /// Approve = the shared orchestration (manifest edit → apply → record);
  /// the report lands in the Overview's result card like a manual apply.
  const approveProposal = async (id: string) => {
    setProposalsBusy(true);
    try {
      const report = await api.deployApproveProposal(
        manifest.trim(),
        issuer.trim(),
        out.trim(),
        id,
      );
      say(report.lines);
      setLastApply(report);
      setPacks(await api.deployListPacks(out.trim()));
      await Promise.all([refreshDisk(), refreshProposals()]);
    } catch (e) {
      say([`✘ ${String(e)}`]);
    } finally {
      setProposalsBusy(false);
    }
  };

  const rejectProposal = async (id: string, reason: string) => {
    setProposalsBusy(true);
    try {
      await api.deployRejectProposal(manifest.trim(), issuer.trim(), id, reason);
      say([t("overview.rejectedLine", { id, reason })]);
      await refreshProposals();
    } catch (e) {
      say([`✘ ${String(e)}`]);
    } finally {
      setProposalsBusy(false);
    }
  };

  const loadManifest = async () => {
    setBusy(true);
    try {
      const loaded = await api.deployReadText(manifest.trim());
      setText(loaded);
      setSavedText(loaded);
      await refreshDisk();
    } catch (e) {
      onError(String(e));
    } finally {
      setBusy(false);
    }
  };

  const saveManifest = async () => {
    if (text === null) return;
    setBusy(true);
    try {
      await api.deployWriteText(manifest.trim(), text);
      setSavedText(text);
      say([t("deploy.savedLine", { path: manifest.trim() })]);
      remember();
      await refreshDisk();
    } catch (e) {
      onError(String(e));
    } finally {
      setBusy(false);
    }
  };

  const validate = async () => {
    setBusy(true);
    try {
      say(await api.deployValidate(manifest.trim()));
    } catch (e) {
      say([`✘ ${String(e)}`]);
    } finally {
      setBusy(false);
    }
  };

  const apply = async () => {
    setBusy(true);
    try {
      // Apply reads the file — unsaved editor state would silently miss the
      // very changes being applied for, so save first (a no-op when clean).
      if (text !== null && text !== savedText) {
        await api.deployWriteText(manifest.trim(), text);
        setSavedText(text);
        say([t("deploy.savedLine", { path: manifest.trim() })]);
      }
      const report = await api.deployApply(manifest.trim(), issuer.trim(), out.trim());
      say(report.lines);
      setLastApply(report);
      setPacks(await api.deployListPacks(out.trim()));
      remember();
      await refreshDisk();
      // The Overview carries the apply's result (generation + fleet
      // convergence) — landing there answers "what did that do" in place.
      onViewChange("overview");
    } catch (e) {
      say([`✘ ${String(e)}`]);
    } finally {
      setBusy(false);
    }
  };

  /// The add/adjust-stream wizard's submit: the same pure edit the form
  /// editor applies (dry-run previewed in the dialog), then Save & Apply —
  /// one path, no hand-written TOML, no CLI. Returns the error string for
  /// the dialog to surface, or null on success (the dialog closes).
  const submitStream = async (fields: StreamFields): Promise<string | null> => {
    try {
      const base = text ?? (await api.deployReadText(manifest.trim()));
      const result = await api.deployEditManifest(base, {
        UpsertMeshIngress: {
          agent: fields.agent,
          name: fields.name.trim(),
          listen: fields.listen.trim(),
          protocol: fields.protocol,
          target_agent: fields.target_agent,
          remote_addr: fields.remote_addr.trim(),
          idle_timeout_secs:
            fields.idle_timeout_secs.trim() === "" ? null : Number(fields.idle_timeout_secs),
        },
      });
      await api.deployWriteText(manifest.trim(), result.text);
      setText(result.text);
      setSavedText(result.text);
      await apply();
      return null;
    } catch (e) {
      return String(e);
    }
  };

  const refreshPacks = async () => {
    try {
      setPacks(await api.deployListPacks(out.trim()));
    } catch (e) {
      say([`✘ ${String(e)}`]);
    }
  };

  /// P1-2: update the local node that runs this pack's identity to this
  /// dist generation — stop → swap in place (state kept, previous backed
  /// up) → restore the start intent. One click replaces the old
  /// "change the pack directory / remove and re-add" dance.
  const updateLocalNode = async (pack: DeployPackDto) => {
    const local = pack.local_node;
    if (!local) return;
    setBusy(true);
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
      await Promise.all([refreshPacks(), onNodesChanged()]);
    } catch (e) {
      say([`✘ ${String(e)}`]);
    } finally {
      setBusy(false);
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
    setBusy(true);
    try {
      say(await api.deployRotate(manifest.trim(), issuer.trim(), node, pack.path));
      await Promise.all([refreshPacks(), onNodesChanged()]);
    } catch (e) {
      say([`✘ ${String(e)}`]);
    } finally {
      setBusy(false);
    }
  };

  const revoke = async (pack: DeployPackDto) => {
    try {
      say(await api.deployRevoke(issuer.trim(), pack.path, "key-compromise"));
      await Promise.all([refreshPacks(), onNodesChanged()]);
    } catch (e) {
      say([`✘ ${String(e)}`]);
    }
  };

  const selected = packs.find((p) => p.dir_name === selectedPack) ?? null;

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-2.5">
      <div className="flex items-center gap-2.5">
        <SegmentedControl
          value={view}
          options={[
            { value: "overview", label: t("deploy.overview") },
            { value: "packs", label: t("deploy.packs") },
            { value: "manifest", label: t("deploy.manifest") },
          ]}
          onChange={onViewChange}
        />
        {pendingProposals.length > 0 && (
          <Hint text={t("overview.proposalsHint")}>
            <button
              onClick={() => onViewChange("overview")}
              className="inline-flex min-h-control-sm cursor-pointer items-center rounded-full border border-warn/55 bg-warn/10 px-2.5 text-small font-medium text-warn transition-colors duration-150 outline-none hover:bg-warn/15 focus-visible:ring-[3px] focus-visible:ring-accent-tint"
            >
              {t("deploy.pendingProposals", { n: String(pendingProposals.length) })}
            </button>
          </Hint>
        )}
      </div>

      {view === "manifest" ? (
        <ManifestEditor
          manifest={manifest}
          issuer={issuer}
          out={out}
          placeholders={{
            manifest: root === null ? undefined : `${root}/<realm>/interflow.toml`,
            issuer: root === null ? undefined : `${root}/<realm>/issuer`,
            out: root === null ? undefined : `${root}/<realm>/dist`,
          }}
          text={text}
          busy={busy}
          dirty={text !== null && text !== savedText}
          recentContexts={recentContexts}
          onManifestChange={setManifest}
          onIssuerChange={setIssuer}
          onOutChange={setOut}
          onPickContext={pickContext}
          onTextChange={setText}
          onPickFile={pickFile}
          onLoad={loadManifest}
          onSave={saveManifest}
          onValidate={validate}
          onApply={apply}
        />
      ) : view === "overview" ? (
        <DeployOverview
          manifest={manifest}
          issuer={issuer}
          out={out}
          summary={diskSummary}
          parseError={diskParseError}
          readError={diskReadError}
          dirty={text !== null && text !== savedText}
          lastApply={lastApply}
          busy={busy}
          recentContexts={recentContexts}
          onPickContext={pickContext}
          onChooseManifest={() => void chooseManifest()}
          onCreateDeployment={() => setCreateOpen(true)}
          onAddStream={() => setStreamEdit({})}
          onAdjustStream={(agent, ruleName) => setStreamEdit({ agent, ruleName })}
          onApply={() => void apply()}
          onOpenManifest={() => onViewChange("manifest")}
          onOpenPacks={() => onViewChange("packs")}
          onIssueNode={() => setIssueOpen(true)}
          onSave={() => void saveManifest()}
          proposals={proposals}
          proposalsBusy={proposalsBusy}
          onApproveProposal={(id) => void approveProposal(id)}
          onRejectProposal={(id, reason) => void rejectProposal(id, reason)}
        />
      ) : selected ? (
        <PackDetail
          pack={selected}
          busy={busy}
          onBack={() => onSelectPack(null)}
          onUpdateLocal={() => void updateLocalNode(selected)}
          onSeal={seal}
          onCopyInstallCommand={() => void copyInstallCommand(selected)}
          onRotate={() => void rotate(selected)}
          onRevoke={() => void revoke(selected)}
        />
      ) : (
        <PackOverview
          packs={packs}
          out={out}
          busy={busy}
          onOutChange={setOut}
          onPickFile={pickFile}
          onRefresh={() => void refreshPacks()}
          onOpenPack={onSelectPack}
          onUpdateLocal={(pack) => void updateLocalNode(pack)}
          onIssuePack={() => setIssueOpen(true)}
        />
      )}

      {streamEdit !== undefined && diskSummary !== null && text !== null && (
        <StreamDialog
          summary={diskSummary}
          text={text}
          prefill={
            streamEdit.ruleName && streamEdit.agent
              ? { agent: streamEdit.agent, ruleName: streamEdit.ruleName }
              : undefined
          }
          busy={busy}
          onSubmit={submitStream}
          onClose={() => setStreamEdit(undefined)}
        />
      )}

      {createOpen && (
        <CreateDeploymentDialog
          root={root}
          onClose={() => setCreateOpen(false)}
          // Creating is just moving the path: the manifest-change refresh
          // loads the new file, blank-fills issuer/out from the defaults,
          // and remembers the context — one path, no special cases.
          onCreated={(path) => {
            setManifest(path);
            say([t("overview.createSaved", { path })]);
            setCreateOpen(false);
            // The Overview's ladder (declare the first node…) is the
            // follow-through — landing there answers "what now" in place.
            onViewChange("overview");
          }}
        />
      )}

      {issueOpen && (
        <IssuePackDialog
          manifest={manifest}
          issuer={issuer}
          out={out}
          busy={busy}
          recentContexts={recentContexts}
          onPickContext={pickContext}
          onSay={say}
          // `node add` writes the file itself; the editor mirrors the
          // outcome, so the on-disk and on-screen states stay one.
          onIssued={(t) => {
            setText(t);
            setSavedText(t);
            void refreshDisk();
          }}
          onComplete={() => void refreshPacks()}
          onClose={() => setIssueOpen(false)}
        />
      )}

      <div className="flex shrink-0 flex-col gap-1.5 border-t border-line pt-1.5">
        <Button
          size="sm"
          className="self-start"
          onClick={() => setOutputOpen((v) => !v)}
        >
          {outputOpen ? (
            <ChevronDown className="size-4" />
          ) : (
            <ChevronRight className="size-4" />
          )}
          {t("deploy.output")}
          {output.length > 0 ? ` (${output.length})` : ""}
        </Button>
        {outputOpen && (
          <pre className="m-0 max-h-[200px] overflow-auto rounded-lg border border-line bg-bg-3 p-2.5 font-mono text-micro whitespace-pre-wrap text-fg-2">
            {output.length === 0 ? t("deploy.outputPlaceholder") : output.join("\n")}
          </pre>
        )}
      </div>
    </div>
  );
}
