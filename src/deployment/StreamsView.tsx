import { useState } from "react";
import { MoreVertical } from "lucide-react";
import type { StreamDto } from "../api";
import { useT } from "../i18n";
import StreamDialog, { type StreamFields } from "../components/StreamDialog";
import StreamDrawer from "../components/StreamDrawer";
import { streamStatusKey, streamStatusWordKey } from "../lib/streamFaces";
import { cn } from "../lib/utils";
import {
  Badge,
  Button,
  ConfirmDialog,
  EmptyState,
  Field,
  Hint,
  Input,
  Menu,
  MenuContent,
  MenuItem,
  MenuSeparator,
  MenuTrigger,
  Modal,
  SectionPanel,
  StatusKeyDot,
  statusTextClass,
  Table,
  TBody,
  Td,
  Th,
  THead,
  Tr,
} from "../components/ui";
import { DialogFooter, DialogTitle } from "../components/ui/dialog";
import { useDeployment } from "./DeploymentContext";

interface Props {
  onOpenNode: (id: string) => void;
}

/// 流: mesh streams as first-class rows — one row IS the cross-machine
/// pairing (source listen ↔ target remote), status-led and flat — the
/// 2026-10-16 streams row language ruling
/// The row carries the scan-level truth only — status dot first, identity with the source
/// agent AS the link, one weighted route line (listen → target remote,
/// hierarchy by weight, no separator semantics) — and the row click
/// opens the drawer with the whole story. Actions: the frequent adjust
/// inline, the rare rename/delete behind the ⋯ menu. In-place adjust is
/// the wizard's paired editor + live dry-run; rename is the atomic
/// RenameMeshIngress edit; delete confirms.
export default function StreamsView({ onOpenNode }: Props) {
  const { t } = useT();
  const { fleet, text, busy, applyEdit, refresh } = useDeployment();
  const [adjust, setAdjust] = useState<{ agent: string; ruleName: string } | undefined>();
  const [adding, setAdding] = useState(false);
  const [renaming, setRenaming] = useState<{ agent: string; from: string } | null>(null);
  const [deleting, setDeleting] = useState<{ agent: string; name: string } | null>(null);
  const [detail, setDetail] = useState<{ agent: string; name: string } | null>(null);

  if (fleet === null) return null;

  const streams = fleet.streams;
  // Any pending edit lights the hint (the status cluster's definition —
  // this page's own edits are always policy edits, but the page must not
  // go quiet while an identity edit from 高级 waits).
  const unpublished =
    fleet.change_state.kind !== "applied" && fleet.change_state.kind !== "never_applied";
  // Selected by identity, re-derived per render: a refresh while the
  // drawer is open updates the sheet in place, and a deleted stream
  // closes it honestly.
  const detailStream =
    detail === null
      ? undefined
      : streams.find((s) => s.agent === detail.agent && s.name === detail.name);

  /// Adjust = the shared wizard (paired fields + live dry-run validation);
  /// its submit path in this IA saves the document and leaves publishing
  /// to the status cluster's button — the row's 未发布 story. Every
  /// successful edit refreshes the composed fleet at once: the saved
  /// document's row appears immediately, honestly 追赶中/未知 until
  /// publish converges it (the old table waited for a reopen to show its
  /// own edit).
  const submitAdjust = async (fields: StreamFields) => {
    const error = await submitFields(fields, applyEdit);
    if (error === null) void refresh(true);
    return error;
  };

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-3 overflow-auto">
      <SectionPanel
        title={t("dep.streams.title")}
        hint={unpublished ? t("dep.status.unpublished") : undefined}
        actions={
          <Button size="sm" disabled={busy || text === null} onClick={() => setAdding(true)}>
            {t("dep.streams.add")}
          </Button>
        }
      >
        {streams.length === 0 ? (
          <EmptyState>
            <div className="flex flex-col items-center gap-3">
              <p className="m-0">{t("dep.streams.empty")}</p>
              <Button
                size="sm"
                variant="primary"
                disabled={busy || text === null}
                onClick={() => setAdding(true)}
              >
                {t("dep.streams.add")}
              </Button>
            </div>
          </EmptyState>
        ) : (
          <div className="overflow-x-auto">
            <Table>
              <THead>
                <Tr>
                  <Th>{t("dep.streams.col.status")}</Th>
                  <Th>{t("dep.streams.col.name")}</Th>
                  <Th>{t("dep.streams.col.route")}</Th>
                  <Th />
                </Tr>
              </THead>
              <TBody>
                {streams.map((s) => (
                  <Tr
                    key={`${s.agent}/${s.name}`}
                    className="cursor-pointer"
                    onClick={() => setDetail({ agent: s.agent, name: s.name })}
                  >
                    <Td className="whitespace-nowrap">
                      <StreamStatusCell stream={s} />
                    </Td>
                    <Td className="whitespace-nowrap">
                      <div className="flex flex-col items-start">
                        <span className="font-medium">{s.name}</span>
                        {s.source_node_id ? (
                          <Button
                            size="sm"
                            variant="link"
                            title={t("dep.streams.openSourceNode")}
                            onClick={(e) => {
                              e.stopPropagation();
                              onOpenNode(s.source_node_id!);
                            }}
                          >
                            {s.agent}
                          </Button>
                        ) : (
                          <span className="text-small text-fg-3">{s.agent}</span>
                        )}
                      </div>
                    </Td>
                    <Td className="whitespace-nowrap">
                      <span className="flex items-center gap-2 font-mono text-small">
                        <Badge tone="neutral" className="uppercase">
                          {s.protocol}
                        </Badge>
                        <span className="text-fg-1">{s.listen}</span>
                        <span className="text-fg-3">→</span>
                        <span className="text-fg-2">{s.target_agent}</span>
                        <span className="text-fg-3">{s.remote_addr}</span>
                      </span>
                    </Td>
                    <Td className="whitespace-nowrap">
                      <span
                        className="flex items-center justify-end gap-1"
                        onClick={(e) => e.stopPropagation()}
                      >
                        <Button
                          size="sm"
                          variant="secondary"
                          disabled={busy}
                          onClick={() => setAdjust({ agent: s.agent, ruleName: s.name })}
                        >
                          {t("dep.streams.adjust")}
                        </Button>
                        <Menu>
                          <MenuTrigger asChild>
                            <Button
                              size="icon-sm"
                              variant="secondary"
                              disabled={busy}
                              aria-label={t("common.more")}
                              title={t("common.more")}
                            >
                              <MoreVertical className="size-4" />
                            </Button>
                          </MenuTrigger>
                          <MenuContent>
                            <MenuItem
                              onSelect={() => setRenaming({ agent: s.agent, from: s.name })}
                            >
                              {t("dep.streams.rename")}
                            </MenuItem>
                            <MenuSeparator />
                            <MenuItem
                              danger
                              onSelect={() => setDeleting({ agent: s.agent, name: s.name })}
                            >
                              {t("dep.streams.delete")}
                            </MenuItem>
                          </MenuContent>
                        </Menu>
                      </span>
                    </Td>
                  </Tr>
                ))}
              </TBody>
            </Table>
          </div>
        )}
      </SectionPanel>

      {detailStream !== undefined && (
        <StreamDrawer
          stream={detailStream}
          fleet={fleet}
          busy={busy}
          onClose={() => setDetail(null)}
          onAdjust={() => {
            setDetail(null);
            setAdjust({ agent: detailStream.agent, ruleName: detailStream.name });
          }}
          onRename={() => {
            setDetail(null);
            setRenaming({ agent: detailStream.agent, from: detailStream.name });
          }}
          onDelete={() => {
            setDetail(null);
            setDeleting({ agent: detailStream.agent, name: detailStream.name });
          }}
          onOpenNode={onOpenNode}
        />
      )}

      {(adding || adjust !== undefined) && text !== null && (
        <StreamDialog
          summary={fleet.summary}
          text={text}
          prefill={adjust}
          busy={busy}
          onSubmit={submitAdjust}
          onClose={() => {
            setAdding(false);
            setAdjust(undefined);
          }}
        />
      )}

      {renaming !== null && (
        <RenameDialog
          agent={renaming.agent}
          from={renaming.from}
          busy={busy}
          onConfirm={async (to) => {
            const error = await applyEdit({
              RenameMeshIngress: { agent: renaming.agent, from: renaming.from, to },
            });
            if (error === null) {
              setRenaming(null);
              void refresh(true);
            }
            return error;
          }}
          onClose={() => setRenaming(null)}
        />
      )}

      {deleting !== null && (
        <ConfirmDialog
          title={t("dep.streams.deleteTitle", { name: deleting.name })}
          message={t("dep.streams.deleteBody")}
          confirmLabel={t("dep.streams.delete")}
          danger
          busy={busy}
          onConfirm={async () => {
            await applyEdit({
              RemoveMeshIngress: { agent: deleting.agent, name: deleting.name },
            });
            setDeleting(null);
            void refresh(true);
          }}
          onClose={() => setDeleting(null)}
        />
      )}
    </div>
  );
}

/// The row's leading cell: dot + word. Down wraps the word in a Hint so
/// the bind failure is one hover away (gui.md's "挂了看原因"); the
/// drawer carries the same reason with room to breathe.
function StreamStatusCell({ stream }: { stream: StreamDto }) {
  const { t } = useT();
  const key = streamStatusKey(stream.status);
  const word = (
    <span
      className={cn(
        "text-small font-medium transition-colors duration-200",
        key === null ? "text-fg-3" : statusTextClass[key],
      )}
    >
      {t(streamStatusWordKey[stream.status])}
    </span>
  );
  return (
    <span className="flex items-center gap-1.5">
      <StatusKeyDot status={key} />
      {stream.last_error !== null ? <Hint text={stream.last_error}>{word}</Hint> : word}
    </span>
  );
}

/// The wizard's field shape (StreamFields) applied as one structured edit.
async function submitFields(
  fields: StreamFields,
  applyEdit: ReturnType<typeof useDeployment>["applyEdit"],
): Promise<string | null> {
  return applyEdit({
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
}

/// The atomic rename: one pure edit, position and comments preserved
/// (the Phase-1 engine contract — no upsert-plus-remove residue).
function RenameDialog({
  agent,
  from,
  busy,
  onConfirm,
  onClose,
}: {
  agent: string;
  from: string;
  busy: boolean;
  onConfirm: (to: string) => Promise<string | null>;
  onClose: () => void;
}) {
  const { t } = useT();
  const [to, setTo] = useState(from);
  const [error, setError] = useState<string | null>(null);
  const [working, setWorking] = useState(false);
  return (
    <Modal onClose={onClose}>
      <DialogTitle>{t("dep.streams.renameTitle")}</DialogTitle>
      <div className="flex flex-col gap-2">
        <Field label={`${t("dep.streams.renameFrom")} · ${agent}`}>
          {() => <Input value={from} readOnly />}
        </Field>
        <Field label={t("dep.streams.renameTo")}>
          {(id) => <Input id={id} value={to} onChange={(e) => setTo(e.target.value)} autoFocus />}
        </Field>
        {error && <p className="m-0 text-small text-critical">{error}</p>}
      </div>
      <DialogFooter>
        <Button variant="secondary" size="sm" onClick={onClose}>
          {t("common.cancel")}
        </Button>
        <Button
          size="sm"
          disabled={busy || working || to.trim() === "" || to === from}
          onClick={async () => {
            setWorking(true);
            setError(await onConfirm(to.trim()));
            setWorking(false);
          }}
        >
          {t("dep.streams.rename")}
        </Button>
      </DialogFooter>
    </Modal>
  );
}
