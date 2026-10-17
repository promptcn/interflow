import { useMemo, useState } from "react";
import { api, type NodeInfo, type ProposalSubmitOutcomeDto } from "../api";
import { useT } from "../i18n";
import { parseLoopbackAddr } from "../lib/net";
import { cn } from "../lib/utils";
import {
  Button,
  DialogFooter,
  DialogTitle,
  Field,
  InfoHint,
  Input,
  Modal,
  Select,
} from "./ui";

/// The requester's "Request stream" form (the kube-CSR face): a node
/// asks ITS operator for one more mesh stream. The fields are the
/// validator's fields; the target dropdown lists the fleet's peers (the
/// peer-observability face's data). Submitting rides the agent's own
/// session — the mTLS identity is the requester, and the hub's funnel
/// answers immediately (queued / duplicate / denied with the validator's
/// own phrasing). The decision arrives later through the receipts face
/// ("Requested streams" in the node detail).

export default function ProposalDialog({
  node,
  onClose,
  onError,
}: {
  node: NodeInfo;
  onClose: () => void;
  onError: (message: string) => void;
}) {
  const { t } = useT();
  const peers = useMemo(
    () =>
      (node.peers?.peers ?? []).map((p) => p.agent.split("/").pop() ?? p.agent),
    [node.peers],
  );
  const [name, setName] = useState("");
  const [listen, setListen] = useState("");
  const [protocol, setProtocol] = useState<"tcp" | "udp">("tcp");
  const [target, setTarget] = useState("");
  const [remote, setRemote] = useState("");
  const [idle, setIdle] = useState("");
  const [busy, setBusy] = useState(false);
  const [outcome, setOutcome] = useState<ProposalSubmitOutcomeDto | null>(null);

  const listenError =
    listen.trim() === ""
      ? null
      : parseLoopbackAddr(listen) === null
        ? t("stream.listenError")
        : null;
  const complete =
    name.trim() !== "" &&
    parseLoopbackAddr(listen) !== null &&
    target !== "" &&
    remote.trim() !== "";

  const submit = async () => {
    setBusy(true);
    try {
      const result = await api.meshSubmitProposal(node.id, {
        name: name.trim(),
        listen: parseLoopbackAddr(listen) ?? listen.trim(),
        protocol,
        target_agent: target,
        remote_addr: remote.trim(),
        idle_timeout_secs: idle.trim() === "" ? null : Number(idle),
      });
      setOutcome(result);
      if (result.outcome === "denied") {
        // Surface the funnel's phrasing in the shared error channel too —
        // it is the actionable text.
        onError(result.reason);
      }
    } catch (e) {
      onError(String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal onClose={onClose} wide>
      <DialogTitle>
        {t("proposal.title")}
        <InfoHint
          text={`${t("stream.semantics")} ${t("proposal.decisionLands")}`}
          className="relative -top-px"
        />
      </DialogTitle>
      <Field label={t("stream.name")}>
        {(id) => (
          <Input
            id={id}
            className="font-mono"
            value={name}
            onChange={(e) => setName(e.target.value)}
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
              value={listen}
              onChange={(e) => setListen(e.target.value)}
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
            value={protocol}
            onValueChange={(v) => setProtocol(v as "tcp" | "udp")}
            options={[
              { value: "tcp", label: "tcp" },
              { value: "udp", label: "udp" },
            ]}
            className="w-[110px]"
          />
        )}
      </Field>
      <Field label={t("stream.target")}>
        {(id) =>
          peers.length > 0 ? (
            // peers list excludes self; free text is the fallback below
            <Select
              id={id}
              value={target}
              placeholder="—"
              onValueChange={setTarget}
              options={peers.map((p) => ({ value: p, label: p }))}
              className="max-w-[280px]"
            />
          ) : (
            <Input
              id={id}
              className="font-mono"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="home-win"
              autoCapitalize="none"
              autoCorrect="off"
              spellCheck={false}
            />
          )
        }
      </Field>
      <Field label={t("stream.remote")}>
        {(id) => (
          <Input
            id={id}
            className="font-mono"
            value={remote}
            onChange={(e) => setRemote(e.target.value)}
            placeholder="127.0.0.1:11434"
            autoCapitalize="none"
            autoCorrect="off"
            spellCheck={false}
          />
        )}
      </Field>
      <Field label={t("stream.idle")}>
        {(id) => (
          <Input
            id={id}
            className="font-mono"
            value={idle}
            onChange={(e) => setIdle(e.target.value)}
            placeholder={t("stream.idlePlaceholder")}
            autoCapitalize="none"
            autoCorrect="off"
            spellCheck={false}
          />
        )}
      </Field>

      {outcome && (
        <div
          className={cn(
            "text-base whitespace-pre-wrap",
            outcome.outcome === "denied"
              ? "rounded-lg border border-critical/40 bg-critical/10 p-2.5 text-critical"
              : "text-small text-fg-3",
          )}
        >
          {outcome.outcome === "queued" && t("proposal.queued")}
          {outcome.outcome === "duplicate" && t("proposal.duplicate")}
          {outcome.outcome === "denied" &&
            `${t("proposal.denied")}${outcome.reason}`}
        </div>
      )}

      <DialogFooter>
        <Button onClick={onClose}>{t("common.cancel")}</Button>
        <Button
          variant="primary"
          disabled={busy || !complete}
          onClick={() => void submit()}
        >
          {busy ? "…" : t("proposal.submit")}
        </Button>
      </DialogFooter>
    </Modal>
  );
}
