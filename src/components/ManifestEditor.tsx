import { useState } from "react";
import { api, type ManifestTemplateParams } from "../api";

/// The manifest page: paths, template builder, TOML editor, validate/apply.
/// Full width — the two-column layout it used to share with the pack wall
/// starved the editor, which is the one surface that wants every pixel.
export default function ManifestEditor({
  manifest,
  issuer,
  out,
  text,
  busy,
  onManifestChange,
  onIssuerChange,
  onOutChange,
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
  onManifestChange: (v: string) => void;
  onIssuerChange: (v: string) => void;
  onOutChange: (v: string) => void;
  onTextChange: (v: string | null) => void;
  onPickFile: (setter: (v: string) => void, directory: boolean, title: string) => void;
  onLoad: () => void;
  onSave: () => void;
  onValidate: () => void;
  onApply: () => void;
}) {
  return (
    <div className="manifest-page">
      <div className="manifest-paths">
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
            Save
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

      <TemplateBuilder onTemplate={onTextChange} />

      <textarea
        className="manifest-editor"
        value={text ?? "# load a manifest, or generate a template"}
        onChange={(e) => onTextChange(e.target.value)}
        readOnly={text === null}
        spellCheck={false}
      />
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

/// The starter-template builder — the GUI twin of `interflow setup`.
function TemplateBuilder({ onTemplate }: { onTemplate: (text: string) => void }) {
  const [open, setOpen] = useState(false);
  const [params, setParams] = useState<ManifestTemplateParams>({
    realm: "promptcn",
    control_endpoint: "tunnel.example.com:443",
    registrar_endpoint: "https://registrar.example.com",
    host: "app.example.com",
    agent: "desktop",
    service: "asr",
    service_address: "127.0.0.1:8080",
  });

  const field = (key: keyof ManifestTemplateParams, label: string) => (
    <div className="row" key={key}>
      <label>{label}</label>
      <input
        value={params[key]}
        onChange={(e) => setParams({ ...params, [key]: e.target.value })}
        autoCapitalize="none"
        autoCorrect="off"
        spellCheck={false}
      />
    </div>
  );

  const generate = async () => {
    try {
      onTemplate(await api.deployManifestTemplate(params));
      setOpen(false);
    } catch (e) {
      // The builder only formats; a failure here is a GUI bug, surface it.
      console.error("template failed:", e);
    }
  };

  if (!open) {
    return (
      <div className="row">
        <button onClick={() => setOpen(true)}>New deployment template…</button>
      </div>
    );
  }
  return (
    <div className="template-builder">
      {field("realm", "Realm")}
      {field("control_endpoint", "Control endpoint")}
      {field("registrar_endpoint", "Registrar endpoint")}
      {field("host", "Public host")}
      {field("agent", "Agent node")}
      {field("service", "Service id")}
      {field("service_address", "Service address")}
      <div className="row">
        <button onClick={() => setOpen(false)}>Cancel</button>
        <button className="primary" onClick={generate}>
          Generate
        </button>
      </div>
    </div>
  );
}
