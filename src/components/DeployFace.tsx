import { useEffect, useState } from "react";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import { api, type DeployContextDto, type DeployPackDto } from "../api";
import IssuePackDialog from "./IssuePackDialog";
import ManifestEditor from "./ManifestEditor";
import PackDetail from "./PackDetail";
import PackOverview from "./PackOverview";

/// The deploy (operator) face: manifest → validate/apply → packs →
/// distribute/rotate/revoke. Two levels like the nodes face — the Packs
/// grid (the frequent layer) and the Manifest editor one click away, with
/// pack details a level below the grid. The output strip at the bottom is
/// the face's single command-output surface, shared by both views.
///
/// Navigation state (view, selected pack) lives in App so Esc and face
/// switches stay coherent; paths, manifest text, and the pack list live
/// here so switching views never loses editor state.
export type DeployView = "packs" | "manifest";

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
  // Paths (hand-typing `~` works; the backend expands it). Restored from
  // the remembered deployment contexts on mount — switching between the
  // expose and mesh faces is a pick, never retyped paths.
  const [manifest, setManifest] = useState("~/interflow.toml");
  const [issuer, setIssuer] = useState("~/interflow-issuer");
  const [out, setOut] = useState("~/interflow-dist");
  const [recentContexts, setRecentContexts] = useState<DeployContextDto[]>([]);
  const [prefsLoaded, setPrefsLoaded] = useState(false);
  const [issueOpen, setIssueOpen] = useState(false);
  // The manifest text being edited (loaded/saved by path; the template
  // builder seeds it). `savedText` is what was last on disk — the gap
  // between the two is the editor's dirty state (Save or discard closes
  // it; Apply closes it by saving first: Apply means "make the saved
  // manifest live").
  const [text, setText] = useState<string | null>(null);
  const [savedText, setSavedText] = useState<string | null>(null);
  const [output, setOutput] = useState<string[]>([]);
  const [outputOpen, setOutputOpen] = useState(false);
  const [packs, setPacks] = useState<DeployPackDto[]>([]);
  const [busy, setBusy] = useState(false);

  // Restore the last-used deployment context on mount (convenience only —
  // a failure keeps the defaults).
  useEffect(() => {
    let cancelled = false;
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
        // Defaults stand.
      } finally {
        if (!cancelled) setPrefsLoaded(true);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  // Debounced persistence: the current triple goes to the front of the
  // remembered list (deduped, capped by the backend's remember policy).
  useEffect(() => {
    if (!prefsLoaded) return;
    const timer = setTimeout(() => {
      const current = { manifest: manifest.trim(), issuer: issuer.trim(), out: out.trim() };
      if (current.manifest === "" || current.issuer === "" || current.out === "") return;
      const rest = recentContexts.filter(
        (c) =>
          c.manifest !== current.manifest ||
          c.issuer !== current.issuer ||
          c.out !== current.out,
      );
      const next = [current, ...rest].slice(0, 5);
      setRecentContexts(next);
      api.deployPrefsSave(next).catch(() => {});
    }, 800);
    return () => clearTimeout(timer);
    // recentContexts is intentionally excluded: the list update below runs
    // through this effect's own output, and every real change to it arrives
    // via a paths change anyway.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [manifest, issuer, out, prefsLoaded]);

  const pickContext = (ctx: DeployContextDto) => {
    setManifest(ctx.manifest);
    setIssuer(ctx.issuer);
    setOut(ctx.out);
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

  const loadManifest = async () => {
    setBusy(true);
    try {
      const loaded = await api.deployReadText(manifest.trim());
      setText(loaded);
      setSavedText(loaded);
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
      say([`saved ${manifest.trim()}`]);
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
        say([`saved ${manifest.trim()}`]);
      }
      say(await api.deployApply(manifest.trim(), issuer.trim(), out.trim()));
      setPacks(await api.deployListPacks(out.trim()));
      // Packs were just (re)issued — the grid is where the user continues.
      onViewChange("packs");
    } catch (e) {
      say([`✘ ${String(e)}`]);
    } finally {
      setBusy(false);
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
      const result = await api.deployUpdateNode(
        local.id,
        `${out.trim()}/packs/${pack.dir_name}`,
      );
      say([
        `${pack.dir_name}: ${local.name} updated gen ${result.generation_from} → ${result.generation_to}${result.restarted ? " (restarted)" : " (left stopped)"}`,
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
      await api.deploySealPack(`${out.trim()}/packs/${pack.dir_name}`, target, passphrase);
      say([`sealed ${pack.dir_name} → ${target}`]);
    } catch (e) {
      say([`✘ ${String(e)}`]);
    }
  };

  const copyInstallCommand = async (pack: DeployPackDto) => {
    const command = `sudo interflow node install --pack packs/${pack.dir_name}`;
    try {
      await writeText(command);
      say([`copied: ${command}`]);
    } catch {
      say([`on the target server: ${command}`]);
    }
  };

  const rotate = async (pack: DeployPackDto) => {
    const node = `${pack.kind === "hub" ? "hub" : pack.kind === "ingress" ? "ingress" : "agent"}/${pack.node}`;
    setBusy(true);
    try {
      say(
        await api.deployRotate(manifest.trim(), issuer.trim(), node, `${out.trim()}/packs/${pack.dir_name}`),
      );
      await Promise.all([refreshPacks(), onNodesChanged()]);
    } catch (e) {
      say([`✘ ${String(e)}`]);
    } finally {
      setBusy(false);
    }
  };

  const revoke = async (pack: DeployPackDto) => {
    try {
      say(
        await api.deployRevoke(
          issuer.trim(),
          `${out.trim()}/packs/${pack.dir_name}`,
          "operator-requested",
        ),
      );
      await Promise.all([refreshPacks(), onNodesChanged()]);
    } catch (e) {
      say([`✘ ${String(e)}`]);
    }
  };

  const selected = packs.find((p) => p.dir_name === selectedPack) ?? null;

  return (
    <div className="deploy-face">
      <div className="deploy-nav">
        <span className="deploy-nav-toggle">
          <button
            className={view === "packs" ? "selected" : ""}
            onClick={() => onViewChange("packs")}
          >
            Packs
          </button>
          <button
            className={view === "manifest" ? "selected" : ""}
            onClick={() => onViewChange("manifest")}
          >
            Manifest
          </button>
        </span>
      </div>

      {view === "manifest" ? (
        <ManifestEditor
          manifest={manifest}
          issuer={issuer}
          out={out}
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
      ) : selected ? (
        <PackDetail
          pack={selected}
          out={out}
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
          }}
          onComplete={() => void refreshPacks()}
          onClose={() => setIssueOpen(false)}
        />
      )}

      <div className="output-strip">
        <button className="output-strip-toggle" onClick={() => setOutputOpen((v) => !v)}>
          {outputOpen ? "▾" : "▸"} Output{output.length > 0 ? ` (${output.length})` : ""}
        </button>
        {outputOpen && (
          <pre className="deploy-output">
            {output.length === 0 ? "plan validate / apply output appears here" : output.join("\n")}
          </pre>
        )}
      </div>
    </div>
  );
}
