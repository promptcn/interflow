import { useState } from "react";
import {
  api,
  kindBlurb,
  type AddNodeParams,
  type PackInspection,
  type Transport,
} from "../api";
import { KindBadge } from "./ui";

/// The add-a-node flow: pick a pack directory (or import a sealed
/// `.iflowpack`), inspect it through the same funnel the start path uses,
/// preview what it is, choose the few agent preferences, add. Unchanged by
/// the card-overview redesign — only its home moved out of the old sidebar.
export default function AddNodeDialog({
  onClose,
  onAdded,
}: {
  onClose: () => void;
  onAdded: (createdId: string) => Promise<void>;
}) {
  const [packDir, setPackDir] = useState("");
  const [inspection, setInspection] = useState<PackInspection | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  // Agent preferences (the only user-chosen runtime knobs; everything else
  // comes from the pack).
  const [transport, setTransport] = useState<Transport>("h2");
  const [hubQuicAddr, setHubQuicAddr] = useState("");
  // Sealed .iflowpack import: decrypt into the GUI-managed packs root, then
  // the same inspect → add flow as a directory.
  const [sealedPath, setSealedPath] = useState("");
  const [passphrase, setPassphrase] = useState("");

  const isAgent =
    inspection?.kind === "expose_agent" || inspection?.kind === "mesh_agent";

  const pickPackDir = async () => {
    const { open } = await import("@tauri-apps/plugin-dialog");
    const dir = await open({
      title: "Choose the Credential Pack directory",
      directory: true,
    });
    if (typeof dir === "string") {
      setPackDir(dir);
      setInspection(null);
      setError(null);
    }
  };

  const pickSealed = async () => {
    const { open } = await import("@tauri-apps/plugin-dialog");
    const file = await open({
      title: "Choose a sealed .iflowpack",
      filters: [{ name: "Interflow sealed pack", extensions: ["iflowpack"] }],
    });
    if (typeof file === "string") {
      setSealedPath(file);
      setInspection(null);
      setError(null);
    }
  };

  const importSealed = async () => {
    setError(null);
    setInspection(null);
    setBusy(true);
    try {
      const imported = await api.deployInstallSealed(sealedPath.trim(), passphrase);
      setPackDir(imported.pack_dir);
      setInspection(imported.inspection);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  const inspect = async () => {
    setError(null);
    setInspection(null);
    setBusy(true);
    try {
      setInspection(await api.inspectPack(packDir.trim()));
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  const add = async () => {
    setError(null);
    setBusy(true);
    try {
      const params: AddNodeParams = {
        pack_dir: packDir.trim(),
        transport: isAgent ? transport : null,
        hub_quic_addr: isAgent && transport === "quic" && hubQuicAddr.trim() !== "" ? hubQuicAddr.trim() : null,
      };
      const created = await api.addNode(params);
      await onAdded(created.id);
    } catch (e) {
      setError(String(e));
      setBusy(false);
    }
  };

  return (
    <div className="dialog-backdrop" onClick={(e) => e.target === e.currentTarget && onClose()}>
      <div className="dialog">
        <h2>Add a node</h2>
        <div className="row">
          <label>Credential Pack</label>
          <input
            value={packDir}
            onChange={(e) => {
              setPackDir(e.target.value);
              setInspection(null);
            }}
            placeholder="Credential Pack directory"
            autoCapitalize="none"
            autoCorrect="off"
            spellCheck={false}
            autoComplete="off"
          />
          <button onClick={pickPackDir}>Browse</button>
          <button disabled={busy || packDir.trim() === ""} onClick={inspect}>
            {busy ? "…" : "Inspect"}
          </button>
        </div>

        <div className="import-sealed">
          <div className="row">
            <label>…or import a sealed pack</label>
            <input
              value={sealedPath}
              onChange={(e) => {
                setSealedPath(e.target.value);
                setInspection(null);
              }}
              placeholder="path to a .iflowpack"
              autoCapitalize="none"
              autoCorrect="off"
              spellCheck={false}
              autoComplete="off"
            />
            <button onClick={pickSealed}>Browse</button>
          </div>
          {sealedPath.trim() !== "" && (
            <div className="row">
              <label>Passphrase</label>
              <input
                type="password"
                value={passphrase}
                onChange={(e) => setPassphrase(e.target.value)}
                autoComplete="off"
              />
              <button
                className="primary"
                disabled={busy || passphrase === ""}
                onClick={importSealed}
              >
                {busy ? "…" : "Import"}
              </button>
            </div>
          )}
        </div>

        {inspection && (
          <div className="inspection">
            <div className="inspection-title">
              <KindBadge kind={inspection.kind} />
              <strong>{inspection.name}</strong>
              <span className="hint">— {kindBlurb(inspection.kind)}</span>
            </div>
            <dl>
              <dt>Identity</dt>
              <dd>{inspection.principal}</dd>
              <dt>{inspection.kind === "hub" || inspection.kind === "ingress" ? "Listens on" : "Connects to"}</dt>
              <dd>{inspection.listen ?? inspection.control_endpoint}</dd>
              {inspection.services.length > 0 && (
                <>
                  <dt>Services</dt>
                  <dd>{inspection.services.join(", ")}</dd>
                </>
              )}
              {(inspection.mesh_ingress > 0 || inspection.mesh_egress > 0) && (
                <>
                  <dt>Mesh rules</dt>
                  <dd>
                    {inspection.mesh_ingress} ingress · {inspection.mesh_egress} egress
                  </dd>
                </>
              )}
            </dl>

            {isAgent && (
              <div className="prefs">
                <div className="row">
                  <label>Transport</label>
                  <div className="transport-toggle">
                    <button
                      className={transport === "h2" ? "selected" : ""}
                      onClick={() => setTransport("h2")}
                    >
                      h2
                    </button>
                    <button
                      className={transport === "quic" ? "selected" : ""}
                      onClick={() => setTransport("quic")}
                    >
                      QUIC
                    </button>
                  </div>
                </div>
                {transport === "quic" && (
                  <div className="row">
                    <label>Hub QUIC address</label>
                    <input
                      value={hubQuicAddr}
                      onChange={(e) => setHubQuicAddr(e.target.value)}
                      placeholder="(optional) host:port — derived if empty"
                      autoCapitalize="none"
                      autoCorrect="off"
                      spellCheck={false}
                      autoComplete="off"
                    />
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {error && <div className="dialog-error">{error}</div>}

        <div className="dialog-actions">
          <button onClick={onClose}>Cancel</button>
          <button className="primary" disabled={busy || !inspection} onClick={add}>
            Add node
          </button>
        </div>
      </div>
    </div>
  );
}
