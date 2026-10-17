import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
  type ReactNode,
} from "react";
import {
  api,
  type ChangeStateDto,
  type ControlProposalDto,
  type DeploymentDto,
  type EditActionDto,
  type FleetDto,
  type PublishResultDto,
} from "../api";
import { useT } from "../i18n";

/// The changed-on-disk payload: what the disk holds now (the winning
/// writer's version) plus its freshness token.
export interface ConflictInfo {
  diskText: string;
  diskDigest: string;
}

/// The deployment-scoped state layer (2026-10-11 IA): ONE provider behind
/// the five views — which deployment is open, the document being edited,
/// the change classification (the status cluster's truth), the composed
/// fleet read model, the proposal queue, and the publish orchestration.
///
/// Discipline carried over from the old Deploy face:
/// - the manifest text IS the editor state; `savedText` is the disk truth
///   (the gap is the dirty bit);
/// - structured edits are pure `text → validated text` transforms; in the
///   new IA a structured edit SAVES immediately (the document is the UI's
///   state; Publish is the commit to the fleet) — the TOML escape hatch in
///   Advanced keeps its manual Save;
/// - publish = save + apply + converge the local fleet (hot or swapped),
///   and the result states its consequences plainly.

interface DeploymentState {
  deployment: DeploymentDto | null;
  loading: boolean;
  busy: boolean;
  text: string | null;
  savedText: string | null;
  fleet: FleetDto | null;
  changeState: ChangeStateDto | null;
  proposals: ControlProposalDto[] | null;
  lastPublish: PublishResultDto | null;
  output: string[];
  openDeployment: (root: string) => Promise<boolean>;
  closeDeployment: () => Promise<void>;
  openPickedManifest: (path: string) => Promise<boolean>;
  refresh: (includeHub?: boolean) => Promise<void>;
  setText: (text: string | null) => void;
  save: (text?: string) => Promise<boolean>;
  applyEdit: (action: EditActionDto) => Promise<string | null>;
  publish: () => Promise<void>;
  say: (lines: string[]) => void;
  /// A save met a changed-on-disk manifest (another writer won the race).
  /// Non-null renders the shell's conflict dialog.
  conflict: ConflictInfo | null;
  /// Adopt the disk version (text + saved truth + freshness token move).
  takeDiskVersion: () => void;
  /// Keep the local edits (unsaved; the next save re-races with a fresh
  /// read of what disk holds).
  keepLocalVersion: () => void;
  /** Node mutations elsewhere (update/rotate) invalidate the fleet join —
   * the views call this after touching nodes. */
  nodesChanged: () => void;
  registerNodesChanged: (fn: () => Promise<void>) => void;
}

const Ctx = createContext<DeploymentState | null>(null);

export function useDeployment(): DeploymentState {
  const value = useContext(Ctx);
  if (value === null) throw new Error("useDeployment outside DeploymentProvider");
  return value;
}

export function DeploymentProvider({
  onError,
  children,
}: {
  onError: (message: string) => void;
  children: ReactNode;
}) {
  const [deployment, setDeployment] = useState<DeploymentDto | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const { t } = useT();
  const [text, setText] = useState<string | null>(null);
  const [savedText, setSavedText] = useState<string | null>(null);
  /// The freshness token of `savedText` (sha256 of the bytes on disk) —
  /// every save hands it back for the changed-on-disk check.
  const [savedDigest, setSavedDigest] = useState<string | null>(null);
  const [conflict, setConflict] = useState<ConflictInfo | null>(null);
  const [fleet, setFleet] = useState<FleetDto | null>(null);
  const [changeState, setChangeState] = useState<ChangeStateDto | null>(null);
  const [proposals, setProposals] = useState<ControlProposalDto[] | null>(null);
  const [lastPublish, setLastPublish] = useState<PublishResultDto | null>(null);
  const [output, setOutput] = useState<string[]>([]);

  /// The error sink keeps a stable identity for the callbacks below — an
  /// inline arrow from the shell would re-create `load` and re-run the
  /// mount effect (a re-open loop) on every unrelated re-render.
  const onErrorRef = useRef(onError);
  onErrorRef.current = onError;
  const reportError = useCallback((message: string) => onErrorRef.current(message), []);

  const say = useCallback((lines: string[]) => {
    setOutput((prev) => [...prev, ...lines]);
  }, []);

  /// Loads the deployment document + the composed read model. Read failure
  /// and parse failure are separate classes (the onboarding/overview
  /// distinction); both land in the fleet call's error slots where they
  /// matter, and a hard read error leaves `text` null (the document is
  /// unavailable, not empty).
  const load = useCallback(
    async (dep: DeploymentDto, includeHub: boolean) => {
      try {
        const loaded = await api.deployReadText(dep.manifest_path);
        setText((prev) => prev ?? loaded.text);
        setSavedText((prev) => prev ?? loaded.text);
        setSavedDigest((prev) => prev ?? loaded.digest);
      } catch (e) {
        setText(null);
        setSavedText(null);
        setSavedDigest(null);
        reportError(String(e));
      }
      try {
        const composed = await api.fleetOverview(
          dep.manifest_path,
          dep.issuer_path,
          includeHub,
        );
        setFleet(composed);
        setChangeState(composed.change_state);
      } catch (e) {
        setFleet(null);
        reportError(String(e));
      }
    },
    [reportError],
  );

  /// Opens a deployment folder (validated by the backend; a non-deployment
  /// path returns the bilingual error). The document and fleet land in one
  /// pass; the previous deployment's state is cleared first so switching
  /// never shows a stale mix.
  const openDeployment = useCallback(
    async (root: string) => {
      setBusy(true);
      try {
        const dep = await api.deploymentSetCurrent(root);
        setDeployment(dep);
        setText(null);
        setSavedText(null);
        setSavedDigest(null);
        setConflict(null);
        setFleet(null);
        setChangeState(null);
        setLastPublish(null);
        setProposals(null);
        await load(dep, true);
        return true;
      } catch (e) {
        reportError(String(e));
        return false;
      } finally {
        setBusy(false);
      }
    },
    [load, reportError],
  );

  /// The onboarding escape hatch: a manifest picked outside the deployments
  /// root still opens (the folder becomes the deployment context if it
  /// carries one, else the read runs context-free with derived siblings).
  const openPickedManifest = useCallback(
    async (path: string) => {
      const folder = path.replace(/\/[^/]*$/, "");
      return openDeployment(folder);
    },
    [openDeployment],
  );

  const closeDeployment = useCallback(async () => {
    try {
      const prefs = await api.guiPrefsLoad();
      await api.guiPrefsSave({ ...prefs, current_deployment: null });
    } catch {
      // Preferring a broken close over a stuck one.
    }
    setDeployment(null);
    setText(null);
    setSavedText(null);
    setSavedDigest(null);
    setConflict(null);
    setFleet(null);
    setChangeState(null);
    setLastPublish(null);
  }, []);

  const refresh = useCallback(
    async (includeHub = true) => {
      if (deployment === null) return;
      try {
        const composed = await api.fleetOverview(
          deployment.manifest_path,
          deployment.issuer_path,
          includeHub,
        );
        setFleet(composed);
        setChangeState(composed.change_state);
      } catch (e) {
        reportError(String(e));
      }
    },
    [deployment, onError],
  );

  const save = useCallback(
    async (override?: string) => {
      const body = override ?? text;
      if (deployment === null || body === null) return false;
      try {
        const outcome = await api.deployWriteText(
          deployment.manifest_path,
          body,
          savedDigest,
        );
        if (outcome.kind === "conflict") {
          // The disk truth moved under us — record what won and surface
          // the reload-or-keep dialog instead of clobbering.
          setSavedText(outcome.text);
          setSavedDigest(outcome.digest);
          setConflict({ diskText: outcome.text, diskDigest: outcome.digest });
          return false;
        }
        setSavedText(body);
        setSavedDigest(outcome.digest);
        return true;
      } catch (e) {
        reportError(String(e));
        return false;
      }
    },
    [deployment, reportError, savedDigest, text],
  );

  /// One structured edit: pure transform → immediate save → the summary and
  /// change classification move with it (the status cluster re-lights).
  /// Returns the error string for the calling view, or null on success.
  const applyEdit = useCallback(
    async (action: EditActionDto): Promise<string | null> => {
      if (deployment === null) return "no deployment open";
      try {
        let baseText: string;
        let baseDigest: string | null;
        if (text !== null) {
          baseText = text;
          baseDigest = savedDigest;
        } else {
          const fresh = await api.deployReadText(deployment.manifest_path);
          baseText = fresh.text;
          baseDigest = fresh.digest;
        }
        const result = await api.deployEditManifest(baseText, action);
        const outcome = await api.deployWriteText(
          deployment.manifest_path,
          result.text,
          baseDigest,
        );
        if (outcome.kind === "conflict") {
          setSavedText(outcome.text);
          setSavedDigest(outcome.digest);
          setConflict({ diskText: outcome.text, diskDigest: outcome.digest });
          return t("manifest.conflictShort");
        }
        setText(result.text);
        setSavedText(result.text);
        setSavedDigest(outcome.digest);
        // The change classification follows the save (light call, no hub
        // dial) so the status cluster answers "what would publish do".
        try {
          setChangeState(
            await api.deployChangeState(deployment.manifest_path, deployment.issuer_path),
          );
        } catch {
          // Classification stays at its last reading; publish re-runs the
          // authoritative funnel regardless.
        }
        return null;
      } catch (e) {
        return String(e);
      }
    },
    [deployment, savedDigest, t, text],
  );

  /// The 发布 button's single entry: save (when dirty) → publish (the
  /// backend's save+apply+converge orchestration) → the fleet and the
  /// result card move in one pass.
  const publish = useCallback(async () => {
    if (deployment === null) return;
    setBusy(true);
    try {
      // Dirty documents save first, through the same changed-on-disk guard
      // as the manual Save — a conflict aborts the publish with the reload
      // dialog open (publishing over a document another writer just
      // changed is the lost-update in its costliest shape).
      const dirty = text !== null && text !== savedText;
      if (dirty && !(await save())) {
        say([`✘ ${t("manifest.conflictShort")}`]);
        return;
      }
      const result = await api.deploymentPublish(
        deployment.manifest_path,
        deployment.issuer_path,
        deployment.out_path,
        null,
      );
      setLastPublish(result);
      say(result.apply.lines);
      const dep = deployment;
      try {
        const composed = await api.fleetOverview(
          dep.manifest_path,
          dep.issuer_path,
          true,
        );
        setFleet(composed);
        setChangeState(composed.change_state);
      } catch {
        // The result card already carries the publish outcome.
      }
    } catch (e) {
      say([`✘ ${String(e)}`]);
      onError(String(e));
    } finally {
      setBusy(false);
    }
  }, [deployment, onError, save, savedText, say, t, text]);

  // Restore the remembered deployment on mount.
  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const current = await api.deploymentCurrent();
        if (!cancelled && current !== null) {
          setDeployment(current);
          await load(current, true);
        }
      } catch {
        // No deployment remembered (first run) — onboarding owns the shell.
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [load]);

  // The proposal queue: fetched with the fleet and on a low-frequency
  // refresher — the operator sees "someone is waiting" without keeping any
  // particular view open.
  const refreshProposals = useCallback(async () => {
    if (deployment === null) return;
    try {
      setProposals(
        await api.deployListProposals(deployment.manifest_path, deployment.issuer_path),
      );
    } catch {
      // Unreachable hub — the queue reads as unknown.
    }
  }, [deployment]);

  useEffect(() => {
    if (deployment === null) return;
    void refreshProposals();
    const timer = setInterval(() => void refreshProposals(), 60_000);
    return () => clearInterval(timer);
  }, [deployment, refreshProposals, lastPublish]);

  // The conflict dialog's two ways out (see ConflictDialog).
  const takeDiskVersion = useCallback(() => {
    if (conflict === null) return;
    setText(conflict.diskText);
    setSavedText(conflict.diskText);
    setSavedDigest(conflict.diskDigest);
    setConflict(null);
  }, [conflict]);
  const keepLocalVersion = useCallback(() => setConflict(null), []);

  // Node mutations from any view (update/rotate/add) invalidate the fleet
  // join — registered by the shell, invoked by the views.
  const nodesChangedRef = useRef<() => Promise<void>>(async () => {});
  const registerNodesChanged = useCallback((fn: () => Promise<void>) => {
    nodesChangedRef.current = fn;
  }, []);
  const nodesChanged = useCallback(() => {
    void nodesChangedRef.current();
    void refresh(true);
  }, [refresh]);

  const value: DeploymentState = {
    deployment,
    loading,
    busy,
    text,
    savedText,
    fleet,
    changeState,
    proposals,
    lastPublish,
    output,
    openDeployment,
    closeDeployment,
    openPickedManifest,
    refresh,
    setText,
    save,
    applyEdit,
    publish,
    say,
    conflict,
    takeDiskVersion,
    keepLocalVersion,
    nodesChanged,
    registerNodesChanged,
  };

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}
