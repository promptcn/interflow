import { useEffect, useRef, useState } from "react";
import { api, type DeployContextDto, type EditActionDto, type ManifestSummaryDto } from "../api";
import { useT } from "../i18n";
import ManifestForm from "./ManifestForm";
import RecentContextSelect from "./RecentContextSelect";
import TemplateBuilder from "./TemplateBuilder";
import { Badge, Button, Field, Hint, Input, SegmentedControl } from "./ui";

/// The manifest page — one document, two views.
///
/// The editor's state IS the manifest text (`text`, owned by the deployment
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
  placeholders,
  text,
  busy,
  dirty,
  recentContexts,
  compact = false,
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
  /// Per-OS default paths — the fields' placeholder hints (a hint, never a
  /// value: an empty field is honest, a fake default is the first-run bug).
  placeholders: { manifest?: string; issuer?: string; out?: string };
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
  /// Deployment-context mode: the path triple is fixed by the deployment
  /// folder, so the three path inputs, the recents picker, and the
  /// template builder collapse into one slim header line (path + Load +
  /// Save). Publish lives in the shell's status cluster — the bottom bar
  /// keeps Validate only.
  compact?: boolean;
}) {
  const { t } = useT();
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
        <Hint text={parseError}>
          <button onClick={() => setView("toml")} className="cursor-pointer">
            <Badge tone="critical">{t("manifest.unparseable")}</Badge>
          </button>
        </Hint>
      );
    }
    if (summary === null) return <Badge>…</Badge>;
    if (summary.issues.length > 0) {
      return (
        <Hint text={summary.issues.join("\n")}>
          <button onClick={() => setView("form")} className="cursor-pointer">
            <Badge tone="critical">
              {summary.issues.length > 1
                ? t("manifest.issuesCount", { n: summary.issues.length })
                : t("manifest.issueCount", { n: summary.issues.length })}
            </Badge>
          </button>
        </Hint>
      );
    }
    return <Badge tone="success">{t("manifest.valid")}</Badge>;
  };

  const pathRow = (
    label: string,
    value: string,
    placeholder: string | undefined,
    onChange: (v: string) => void,
    onBrowse: () => void,
    extra?: React.ReactNode,
  ) => (
    <Field label={label}>
      {(id) => (
        <div className="flex min-w-0 flex-1 items-center gap-2">
          <Input
            id={id}
            value={value}
            placeholder={placeholder}
            onChange={(e) => onChange(e.target.value)}
            autoCapitalize="none"
            autoCorrect="off"
            spellCheck={false}
            autoComplete="off"
            className="flex-1"
          />
          <Button onClick={onBrowse}>…</Button>
          {extra}
        </div>
      )}
    </Field>
  );

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-2.5 overflow-y-auto">
      {compact ? (
        <div className="flex min-w-0 items-center gap-2">
          <code
            className="min-w-0 flex-1 truncate rounded-lg border border-line bg-bg-3 px-2 py-1 font-mono text-small text-fg-2"
            title={`${manifest} · ${issuer} · ${out}`}
          >
            {manifest}
          </code>
          <Button disabled={busy} onClick={onLoad}>
            {t("manifest.load")}
          </Button>
          <Button disabled={busy || text === null} onClick={onSave}>
            {t("manifest.save")}
            {dirty ? " •" : ""}
          </Button>
        </div>
      ) : (
      <div className="flex flex-col gap-2">
        {recentContexts.length > 1 && (
          <div className="flex items-center gap-2">
            <span className="w-[140px] shrink-0 text-base text-fg-2">{t("manifest.recent")}</span>
            <RecentContextSelect
              contexts={recentContexts}
              current={{ manifest, issuer, out }}
              onPick={onPickContext}
            />
          </div>
        )}
        {pathRow(
          t("manifest.manifest"),
          manifest,
          placeholders.manifest,
          onManifestChange,
          () => onPickFile(onManifestChange, false, t("manifest.chooseManifest")),
          <>
            <Button disabled={busy} onClick={onLoad}>
              {t("manifest.load")}
            </Button>
            <Button disabled={busy || text === null} onClick={onSave}>
              {t("manifest.save")}
              {dirty ? " •" : ""}
            </Button>
          </>,
        )}
        {pathRow(t("manifest.issuer"), issuer, placeholders.issuer, onIssuerChange, () =>
          onPickFile(onIssuerChange, true, t("manifest.chooseIssuer")),
        )}
        {pathRow(t("manifest.output"), out, placeholders.out, onOutChange, () =>
          onPickFile(onOutChange, true, t("manifest.chooseDist")),
        )}
      </div>
      )}

      <div className="flex flex-wrap items-center gap-2">
        <SegmentedControl
          value={view}
          options={[
            { value: "form", label: t("manifest.form") },
            { value: "toml", label: t("manifest.toml") },
          ]}
          onChange={setView}
          disabled={text === null}
        />
        {statusChip()}
        {dirty && <span className="text-small text-warn">{t("manifest.unsavedHint")}</span>}
        <span className="flex-1" />
        {!compact && <TemplateBuilder onTemplate={onTextChange} />}
      </div>

      {text === null ? (
        <p className="text-small text-fg-3">{t("manifest.loadHint")}</p>
      ) : view === "toml" ? (
        <textarea
          value={text}
          onChange={(e) => onTextChange(e.target.value)}
          spellCheck={false}
          className="min-h-[320px] flex-none resize-y rounded-lg border border-line bg-bg-3 p-2.5 font-mono text-small text-fg-1 outline-none focus-visible:border-accent focus-visible:ring-[3px] focus-visible:ring-accent-tint"
        />
      ) : parseError !== null ? (
        <div className="flex flex-col gap-2.5">
          <div className="text-base whitespace-pre-wrap text-critical">{parseError}</div>
          <p className="text-small text-fg-3">{t("manifest.parseFail")}</p>
        </div>
      ) : summary !== null ? (
        <>
          {summary.issues.length > 0 && (
            <div className="rounded-lg border border-critical/40 bg-critical/10 p-2.5 text-base whitespace-pre-wrap text-critical">
              {summary.issues.join("\n")}
            </div>
          )}
          {editError !== null && (
            <div className="rounded-lg border border-critical/40 bg-critical/10 p-2.5 text-base whitespace-pre-wrap text-critical">
              {editError}
            </div>
          )}
          <ManifestForm summary={summary} busy={formBusy} onEdit={applyAction} />
        </>
      ) : (
        <p className="text-small text-fg-3">{t("manifest.parsing")}</p>
      )}
      <div className="flex justify-end gap-2">
        <Button disabled={busy} onClick={onValidate}>
          {t("manifest.validate")}
        </Button>
        {!compact && (
          <Button variant="primary" disabled={busy || text === null} onClick={onApply}>
            {t("manifest.applyButton")}
          </Button>
        )}
      </div>
    </div>
  );
}
