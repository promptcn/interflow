import { useEffect, useRef, useState } from "react";
import { api, type DeployContextDto, type EditActionDto, type ManifestSummaryDto, type ManifestTemplateParams } from "../api";
import ManifestForm from "./ManifestForm";

/// The manifest page — one document, two views.
///
/// The editor's state IS the manifest text (`text`, owned by DeployFace);
/// the Form view is a projection of it (parsed + issues via the backend),
/// the TOML view is the text itself. Every form action is one pure
/// `text → validated text` transform (`deployEditManifest`) whose result
/// replaces both the text and the summary — there is never a second copy
/// of the document to keep in sync. Save is the only write to the file
/// (one `.bak` generation, atomic); nothing a form does touches the disk.
export default function ManifestEditor({
  manifest,
  issuer,
  out,
  text,
  busy,
  dirty,
  recentContexts,
  onManifestChange,
  onIssuerChange,
  onOutChange,
  onPickContext,
  onTextChange,
  onPickFile,
  onLoad,
  onSave,
  onValidate,
  onApply,
}: {
  manifest: string;
  issuer: string;
  out: string;
  text: string | null;
  busy: boolean;
  /// The editor text differs from what was last saved/loaded — Save (or
  /// discarding) is the way out; Apply auto-saves first.
  dirty: boolean;
  /// Remembered deployment contexts — one pick restores a whole triple
  /// (switching faces never mixes paths).
  recentContexts: DeployContextDto[];
  onManifestChange: (v: string) => void;
  onIssuerChange: (v: string) => void;
  onOutChange: (v: string) => void;
  onPickContext: (ctx: DeployContextDto) => void;
  onTextChange: (v: string | null) => void;
  onPickFile: (setter: (v: string) => void, directory: boolean, title: string) => void;
  onLoad: () => void;
  onSave: () => void;
  onValidate: () => void;
  onApply: () => void;
}) {
  const [view, setView] = useState<"form" | "toml">("form");
  const [summary, setSummary] = useState<ManifestSummaryDto | null>(null);
  const [parseError, setParseError] = useState<string | null>(null);
  const [editError, setEditError] = useState<string | null>(null);
  const [editBusy, setEditBusy] = useState(false);
  // A form edit already returned the next summary with the next text; the
  // reparse it would trigger is redundant (and would flash).
  const skipNextParse = useRef(false);

  // Live read model: reparse (debounced) whenever the text changes outside
  // a form edit — typing in the TOML view, Load, a template, a wizard
  // append. Shape failures are parse errors (no document to render);
  // semantic failures arrive as `summary.issues`.
  useEffect(() => {
    if (text === null) {
      setSummary(null);
      setParseError(null);
      return;
    }
    if (skipNextParse.current) {
      skipNextParse.current = false;
      return;
    }
    let active = true;
    const timer = setTimeout(() => {
      void api
        .deployParseManifest(text)
        .then((next) => {
          if (!active) return;
          setSummary(next);
          setParseError(null);
        })
        .catch((e) => {
          if (!active) return;
          setSummary(null);
          setParseError(String(e));
        });
    }, 250);
    return () => {
      active = false;
      clearTimeout(timer);
    };
  }, [text]);

  /// One structured edit: `text → validated text`. On success the document
  /// and its read model move together; on failure the banner carries the
  /// funnel's phrasing and the document is untouched (purity is the
  /// rollback).
  const applyAction = async (action: EditActionDto): Promise<boolean> => {
    if (text === null) return false;
    setEditBusy(true);
    setEditError(null);
    try {
      const result = await api.deployEditManifest(text, action);
      skipNextParse.current = true;
      onTextChange(result.text);
      setSummary(result.summary);
      setParseError(null);
      return true;
    } catch (e) {
      setEditError(String(e));
      return false;
    } finally {
      setEditBusy(false);
    }
  };

  const formBusy = busy || editBusy;

  const statusChip = () => {
    if (text === null) return null;
    if (parseError !== null) {
      return (
        <button className="valid-chip invalid" onClick={() => setView("toml")} title={parseError}>
          ✕ unparseable — fix in TOML
        </button>
      );
    }
    if (summary === null) return <span className="valid-chip">…</span>;
    if (summary.issues.length > 0) {
      return (
        <button
          className="valid-chip invalid"
          onClick={() => setView("form")}
          title={summary.issues.join("\n")}
        >
          ✕ {summary.issues.length} issue{summary.issues.length > 1 ? "s" : ""}
        </button>
      );
    }
    return <span className="valid-chip valid">✓ valid</span>;
  };

  return (
    <div className="manifest-page">
      <div className="manifest-paths">
        {recentContexts.length > 1 && (
          <div className="row">
            <label>Recent</label>
            <select
              value={`${manifest}|${issuer}|${out}`}
              onChange={(e) => {
                const picked = recentContexts.find(
                  (c) => `${c.manifest}|${c.issuer}|${c.out}` === e.target.value,
                );
                if (picked) onPickContext(picked);
              }}
            >
              {recentContexts.map((c) => (
                <option
                  key={`${c.manifest}|${c.issuer}|${c.out}`}
                  value={`${c.manifest}|${c.issuer}|${c.out}`}
                >
                  {c.manifest} · {c.issuer} · {c.out}
                </option>
              ))}
            </select>
          </div>
        )}
        <div className="row">
          <label>Manifest</label>
          <input
            value={manifest}
            onChange={(e) => onManifestChange(e.target.value)}
            autoCapitalize="none"
            autoCorrect="off"
            spellCheck={false}
            autoComplete="off"
          />
          <button onClick={() => onPickFile(onManifestChange, false, "Choose the manifest")}>
            …
          </button>
          <button disabled={busy} onClick={onLoad}>
            Load
          </button>
          <button disabled={busy || text === null} onClick={onSave}>
            Save{dirty ? " •" : ""}
          </button>
        </div>
        <div className="row">
          <label>Issuer</label>
          <input
            value={issuer}
            onChange={(e) => onIssuerChange(e.target.value)}
            autoCapitalize="none"
            autoCorrect="off"
            spellCheck={false}
            autoComplete="off"
          />
          <button onClick={() => onPickFile(onIssuerChange, true, "Choose the issuer directory")}>
            …
          </button>
        </div>
        <div className="row">
          <label>Output</label>
          <input
            value={out}
            onChange={(e) => onOutChange(e.target.value)}
            autoCapitalize="none"
            autoCorrect="off"
            spellCheck={false}
            autoComplete="off"
          />
          <button onClick={() => onPickFile(onOutChange, true, "Choose the dist directory")}>
            …
          </button>
        </div>
      </div>

      <div className="row manifest-toolbar">
        <span className="manifest-views">
          <button
            className={view === "form" ? "selected" : ""}
            disabled={text === null}
            onClick={() => setView("form")}
          >
            Form
          </button>
          <button
            className={view === "toml" ? "selected" : ""}
            disabled={text === null}
            onClick={() => setView("toml")}
          >
            TOML
          </button>
        </span>
        {statusChip()}
        {dirty && <span className="hint">unsaved — Save writes the file (with a .bak)</span>}
        <span style={{ flex: 1 }} />
        <TemplateBuilder onTemplate={onTextChange} />
      </div>

      {text === null ? (
        <p className="hint">load a manifest, or generate a template</p>
      ) : view === "toml" ? (
        <textarea
          className="manifest-editor"
          value={text}
          onChange={(e) => onTextChange(e.target.value)}
          spellCheck={false}
        />
      ) : parseError !== null ? (
        <div className="manifest-form">
          <div className="dialog-error">{parseError}</div>
          <p className="hint">
            The text does not parse — switch to the TOML view to fix it; the Form view
            returns as soon as it does.
          </p>
        </div>
      ) : summary !== null ? (
        <>
          {summary.issues.length > 0 && (
            <div className="dialog-error">{summary.issues.join("\n")}</div>
          )}
          {editError !== null && <div className="dialog-error">✕ {editError}</div>}
          <ManifestForm summary={summary} busy={formBusy} onEdit={applyAction} />
        </>
      ) : (
        <p className="hint">parsing…</p>
      )}
      <div className="row deploy-actions">
        <button disabled={busy} onClick={onValidate}>
          Validate
        </button>
        <button className="primary" disabled={busy || text === null} onClick={onApply}>
          Apply — issue packs
        </button>
      </div>
    </div>
  );
}

/// The starter-template builder — the GUI twin of `interflow setup`. Two
/// skeletons: the expose deployment (registrar tier, public routes) and
/// the site-to-site mesh (offline tier, one hub, no placeholder agents).
function TemplateBuilder({ onTemplate }: { onTemplate: (text: string) => void }) {
  const [open, setOpen] = useState<"expose" | "mesh" | null>(null);
  const [params, setParams] = useState<ManifestTemplateParams>({
    realm: "promptcn",
    control_endpoint: "tunnel.example.com:443",
    registrar_endpoint: "https://registrar.example.com",
    host: "app.example.com",
    agent: "desktop",
    service: "asr",
    service_address: "127.0.0.1:8080",
  });
  const [mesh, setMesh] = useState({ realm: "promptcn-mesh", hub_name: "central", hub_endpoint: "mesh.example.com:6666" });

  const field = (
    key: keyof ManifestTemplateParams,
    label: string,
    setter: (params: ManifestTemplateParams) => void,
  ) => (
    <div className="row" key={key}>
      <label>{label}</label>
      <input
        value={params[key]}
        onChange={(e) => setter({ ...params, [key]: e.target.value })}
        autoCapitalize="none"
        autoCorrect="off"
        spellCheck={false}
      />
    </div>
  );

  const generate = async () => {
    try {
      onTemplate(await api.deployManifestTemplate(params));
      setOpen(null);
    } catch (e) {
      // The builder only formats; a failure here is a GUI bug, surface it.
      console.error("template failed:", e);
    }
  };

  const generateMesh = async () => {
    try {
      onTemplate(await api.deployMeshTemplate(mesh));
      setOpen(null);
    } catch (e) {
      console.error("template failed:", e);
    }
  };

  if (open === null) {
    return (
      <>
        <button onClick={() => setOpen("expose")}>Expose template…</button>
        <button onClick={() => setOpen("mesh")}>Mesh template…</button>
      </>
    );
  }
  if (open === "mesh") {
    return (
      <div className="template-builder">
        <div className="row">
          <label>Realm</label>
          <input
            value={mesh.realm}
            onChange={(e) => setMesh({ ...mesh, realm: e.target.value })}
            autoCapitalize="none"
            autoCorrect="off"
            spellCheck={false}
          />
        </div>
        <div className="row">
          <label>Hub name</label>
          <input
            value={mesh.hub_name}
            onChange={(e) => setMesh({ ...mesh, hub_name: e.target.value })}
            autoCapitalize="none"
            autoCorrect="off"
            spellCheck={false}
          />
        </div>
        <div className="row">
          <label>Hub endpoint</label>
          <input
            value={mesh.hub_endpoint}
            onChange={(e) => setMesh({ ...mesh, hub_endpoint: e.target.value })}
            autoCapitalize="none"
            autoCorrect="off"
            spellCheck={false}
          />
        </div>
        <div className="row">
          <button onClick={() => setOpen(null)}>Cancel</button>
          <button className="primary" onClick={generateMesh}>
            Generate
          </button>
        </div>
      </div>
    );
  }
  return (
    <div className="template-builder">
      {field("realm", "Realm", setParams)}
      {field("control_endpoint", "Control endpoint", setParams)}
      {field("registrar_endpoint", "Registrar endpoint", setParams)}
      {field("host", "Public host", setParams)}
      {field("agent", "Agent node", setParams)}
      {field("service", "Service id", setParams)}
      {field("service_address", "Service address", setParams)}
      <div className="row">
        <button onClick={() => setOpen(null)}>Cancel</button>
        <button className="primary" onClick={generate}>
          Generate
        </button>
      </div>
    </div>
  );
}
