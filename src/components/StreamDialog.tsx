import { useEffect, useMemo, useState } from "react";
import { api, type ManifestSummaryDto } from "../api";
import { useT } from "../i18n";
import { parseLoopbackAddr } from "../lib/net";
import {
  Badge,
  Button,
  DialogFooter,
  DialogTitle,
  Drawer,
  Field,
  InfoHint,
  Input,
  Select,
} from "./ui";

/// The add/adjust-stream wizard (2026-10-08 deploy-legibility backlog):
/// the task-path answer to "give an agent one more stream". The form's
/// fields ARE the validator's fields, and the validator runs WHILE typing
/// — every change is a dry-run of the same pure `text → validated text`
/// edit the form editor applies (`deployEditManifest` on a scratch copy;
/// nothing is written until Save & Apply). The pairing error that used to
/// surface only at apply time (a `remote_addr` outside the target's
/// egress authorization) surfaces here, with the funnel's own phrasing.

export interface StreamFields {
  agent: string;
  name: string;
  listen: string;
  protocol: "tcp" | "udp";
  target_agent: string;
  remote_addr: string;
  idle_timeout_secs: string; // "" = default
}

export default function StreamDialog({
  summary,
  text,
  prefill,
  busy,
  onSubmit,
  onClose,
}: {
  summary: ManifestSummaryDto;
  /// The current manifest document (the dry-run base; never written here).
  text: string;
  /// Adjust mode: the agent + rule name being edited (undefined = add).
  prefill?: { agent: string; ruleName: string };
  busy: boolean;
  /// Submit = edit + validate + save (publishing is the shell's commit);
  /// resolves to an error string or null.
  onSubmit: (fields: StreamFields) => Promise<string | null>;
  onClose: () => void;
}) {
  const { t } = useT();
  const agents = summary.agents.map((a) => a.node);

  const initial: StreamFields = useMemo(() => {
    if (prefill) {
      const agent = summary.agents.find((a) => a.node === prefill.agent);
      const rule = agent?.mesh_ingress.find((r) => r.name === prefill.ruleName);
      if (agent && rule) {
        return {
          agent: agent.node,
          name: rule.name,
          listen: rule.listen,
          protocol: rule.protocol,
          target_agent: rule.target_agent,
          remote_addr: rule.remote_addr,
          idle_timeout_secs:
            rule.idle_timeout_secs == null
              ? ""
              : String(rule.idle_timeout_secs),
        };
      }
    }
    return {
      agent: agents[0] ?? "",
      name: "",
      listen: "",
      protocol: "tcp",
      target_agent: "",
      remote_addr: "",
      idle_timeout_secs: "",
    };
    // Seed once per dialog open.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [prefill?.agent, prefill?.ruleName]);

  const [fields, setFields] = useState<StreamFields>(initial);
  const [preview, setPreview] = useState<{
    state: "idle" | "checking" | "ok" | "error";
    message: string | null;
  }>({ state: "idle", message: null });
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const set = (patch: Partial<StreamFields>) =>
    setFields((prev) => ({ ...prev, ...patch }));

  const listenError =
    fields.listen.trim() === ""
      ? null
      : parseLoopbackAddr(fields.listen) === null
        ? t("stream.listenError")
        : null;
  const remoteError =
    fields.remote_addr.trim() === ""
      ? null
      : /^\[?[^\]]+\]?:\d+$/.test(fields.remote_addr.trim())
        ? null
        : t("stream.remoteError");
  const complete =
    fields.agent !== "" &&
    fields.name.trim() !== "" &&
    parseLoopbackAddr(fields.listen) !== null &&
    fields.target_agent !== "" &&
    !remoteError;

  // Live dry-run: the same edit Submit will make, applied to the current
  // document in memory. The funnel's verdict (including the ingress↔egress
  // pairing) is the preview; nothing touches the file.
  useEffect(() => {
    if (!complete) {
      setPreview({ state: "idle", message: null });
      return;
    }
    let cancelled = false;
    setPreview({ state: "checking", message: null });
    const timer = setTimeout(() => {
      void (async () => {
        try {
          const result = await api.deployEditManifest(text, {
            UpsertMeshIngress: {
              agent: fields.agent,
              name: fields.name.trim(),
              listen: parseLoopbackAddr(fields.listen) ?? fields.listen.trim(),
              protocol: fields.protocol,
              target_agent: fields.target_agent,
              remote_addr: fields.remote_addr.trim(),
              idle_timeout_secs:
                fields.idle_timeout_secs.trim() === ""
                  ? null
                  : Number(fields.idle_timeout_secs),
            },
          });
          const newIssues = result.summary.issues.filter(
            (issue) => !summary.issues.includes(issue),
          );
          if (cancelled) return;
          if (newIssues.length > 0) {
            setPreview({ state: "error", message: newIssues.join("\n") });
          } else {
            setPreview({ state: "ok", message: null });
          }
        } catch (e) {
          if (!cancelled) setPreview({ state: "error", message: String(e) });
        }
      })();
    }, 300);
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
    // The dry-run base moves with the document; fields drive re-runs.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [
    text,
    complete,
    fields.agent,
    fields.name,
    fields.listen,
    fields.protocol,
    fields.target_agent,
    fields.remote_addr,
    fields.idle_timeout_secs,
  ]);

  const submit = async () => {
    setSubmitting(true);
    setSubmitError(null);
    try {
      const error = await onSubmit(fields);
      if (error) setSubmitError(error);
      else onClose();
    } finally {
      setSubmitting(false);
    }
  };

  const targetOptions = agents.filter((a) => a !== fields.agent);

  return (
    <Drawer onClose={onClose} guard={submitting}>
      <DialogTitle>
        {prefill
          ? t("stream.adjustTitle", { name: prefill.ruleName })
          : t("stream.addTitle")}
        <InfoHint text={t("stream.semantics")} className="relative -top-px" />
      </DialogTitle>
      <Field label={t("stream.agent")}>
        {(id) => (
          <Select
            id={id}
            value={fields.agent}
            onValueChange={(v) => set({ agent: v })}
            options={agents.map((a) => ({ value: a, label: a }))}
            className="max-w-[280px]"
          />
        )}
      </Field>
      <Field label={t("stream.name")}>
        {(id) => (
          <Input
            id={id}
            className="font-mono"
            value={fields.name}
            onChange={(e) => set({ name: e.target.value })}
            placeholder="ollama"
            autoCapitalize="none"
            autoCorrect="off"
            spellCheck={false}
          />
        )}
      </Field>
      <Field label={t("stream.listen")}>
        {(id) => (
          <>
            <Input
              id={id}
              aria-invalid={listenError ? true : undefined}
              className="font-mono"
              value={fields.listen}
              onChange={(e) => set({ listen: e.target.value })}
              placeholder="127.0.0.1:11434"
              autoCapitalize="none"
              autoCorrect="off"
              spellCheck={false}
            />
            {listenError && (
              <span className="text-small whitespace-nowrap text-critical">
                {listenError}
              </span>
            )}
          </>
        )}
      </Field>
      <Field label={t("stream.protocol")}>
        {(id) => (
          <Select
            id={id}
            value={fields.protocol}
            onValueChange={(v) => set({ protocol: v as "tcp" | "udp" })}
            options={[
              { value: "tcp", label: "tcp" },
              { value: "udp", label: "udp" },
            ]}
            className="w-[110px]"
          />
        )}
      </Field>
      <Field label={t("stream.target")}>
        {(id) => (
          <div className="flex items-center gap-2">
            <Select
              id={id}
              value={fields.target_agent}
              placeholder="—"
              onValueChange={(v) => set({ target_agent: v })}
              options={targetOptions.map((a) => ({ value: a, label: a }))}
              className="max-w-[280px]"
            />
            {targetOptions.length === 0 && (
              <span className="text-small text-fg-3">
                {t("stream.noTargets")}
              </span>
            )}
          </div>
        )}
      </Field>
      <Field label={t("stream.remote")}>
        {(id) => (
          <>
            <Input
              id={id}
              aria-invalid={remoteError ? true : undefined}
              className="font-mono"
              value={fields.remote_addr}
              onChange={(e) => set({ remote_addr: e.target.value })}
              placeholder="127.0.0.1:11434"
              autoCapitalize="none"
              autoCorrect="off"
              spellCheck={false}
            />
            {remoteError && (
              <span className="text-small whitespace-nowrap text-critical">
                {remoteError}
              </span>
            )}
          </>
        )}
      </Field>
      <Field label={t("stream.idle")}>
        {(id) => (
          <Input
            id={id}
            className="font-mono"
            value={fields.idle_timeout_secs}
            onChange={(e) => set({ idle_timeout_secs: e.target.value })}
            placeholder={t("stream.idlePlaceholder")}
            autoCapitalize="none"
            autoCorrect="off"
            spellCheck={false}
          />
        )}
      </Field>

      <div className="flex flex-col gap-1">
        {preview.state === "checking" && (
          <span className="text-small text-fg-3">…</span>
        )}
        {preview.state === "ok" && (
          <Badge tone="success">{t("stream.previewOk")}</Badge>
        )}
        {preview.state === "error" && (
          <div className="rounded-lg border border-critical/40 bg-critical/10 p-2.5 text-base whitespace-pre-wrap text-critical">
            {t("stream.previewReject")}
            {"\n"}
            {preview.message}
          </div>
        )}
        {preview.state === "idle" && complete === false && (
          <span className="text-small text-fg-3">
            {t("stream.previewIncomplete")}
          </span>
        )}
      </div>
      {submitError && (
        <div className="rounded-lg border border-critical/40 bg-critical/10 p-2.5 text-base whitespace-pre-wrap text-critical">
          {submitError}
        </div>
      )}

      <DialogFooter>
        <Button onClick={onClose}>{t("common.cancel")}</Button>
        <Button
          variant="primary"
          disabled={
            busy || submitting || !complete || preview.state === "error"
          }
          onClick={() => void submit()}
        >
          {submitting ? "…" : t("dep.streams.save")}
        </Button>
      </DialogFooter>
    </Drawer>
  );
}
