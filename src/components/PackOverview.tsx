import { type DeployPackDto } from "../api";
import { KindBadge } from "./ui";

/// The deploy face's landing view: issued packs as cards. Same grammar as
/// the nodes overview — the card carries identity + generation state and at
/// most one contextual primary action; everything else is the detail page.
export default function PackOverview({
  packs,
  out,
  busy,
  onOutChange,
  onPickFile,
  onRefresh,
  onOpenPack,
  onUpdateLocal,
  onIssuePack,
}: {
  packs: DeployPackDto[];
  out: string;
  busy: boolean;
  onOutChange: (v: string) => void;
  onPickFile: (setter: (v: string) => void, directory: boolean, title: string) => void;
  onRefresh: () => void;
  onOpenPack: (dirName: string) => void;
  onUpdateLocal: (pack: DeployPackDto) => void;
  onIssuePack: () => void;
}) {
  /// "Update available" = the dist pack differs from what the local node
  /// runs. A higher generation OR a different content digest both count: a
  /// re-applied manifest re-renders the SAME generation with different
  /// content (e.g. an h2→QUIC transport switch), which only the digest
  /// catches.
  const updateAvailable = (pack: DeployPackDto) =>
    !!pack.local_node &&
    (pack.local_node.generation < pack.generation || pack.local_node.digest !== pack.digest);

  return (
    <div className="pack-overview">
      <div className="pack-toolbar">
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
          <button disabled={busy} onClick={onRefresh}>
            Refresh
          </button>
          <button className="primary" disabled={busy} onClick={onIssuePack} title="append a node to the manifest, apply, seal into Downloads">
            + Issue pack…
          </button>
        </div>
      </div>

      {packs.length === 0 && (
        <div className="empty-state">No packs yet — apply the manifest or Refresh.</div>
      )}

      <div className="card-grid">
        {packs.map((pack) => (
          <div
            key={pack.dir_name}
            className="node-card"
            role="button"
            tabIndex={0}
            title={pack.principal}
            onClick={() => onOpenPack(pack.dir_name)}
            onKeyDown={(e) => {
              if (e.key === "Enter") onOpenPack(pack.dir_name);
            }}
          >
            <div className="node-card-head">
              <strong className="node-card-name">{pack.dir_name}</strong>
              <KindBadge kind={pack.kind} />
            </div>
            <div className="node-card-summary">
              <div className="node-card-line" title={pack.principal}>
                {pack.principal}
              </div>
              <div className="node-card-line">
                gen {pack.generation} · expires {pack.expires}
              </div>
            </div>
            <div className="node-card-foot">
              {pack.local_node ? (
                <span className="node-card-state" title={pack.local_node.name}>
                  {pack.local_node.name} · gen {pack.local_node.generation}
                </span>
              ) : (
                <span className="node-card-state">not on this machine</span>
              )}
              {pack.local_node && updateAvailable(pack) && (
                <button
                  className="primary"
                  disabled={busy}
                  title={
                    pack.local_node.generation < pack.generation
                      ? "stop, swap the pack in place (state kept), restart"
                      : "same generation, different content — stop, swap the pack in place (state kept), restart"
                  }
                  onClick={(e) => {
                    e.stopPropagation();
                    onUpdateLocal(pack);
                  }}
                >
                  {pack.local_node.generation < pack.generation
                    ? `Update → gen ${pack.generation}`
                    : "Update"}
                </button>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
