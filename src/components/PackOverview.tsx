import { type DeployPackDto } from "../api";
import { useT } from "../i18n";
import { Button, EmptyState, Field, Hint, Input, KindBadge } from "./ui";

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
  const { t } = useT();
  /// "Update available" = the dist pack differs from what the local node
  /// runs. A higher generation OR a different content digest both count: a
  /// re-applied manifest re-renders the SAME generation with different
  /// content (e.g. an h2→QUIC transport switch), which only the digest
  /// catches.
  const updateAvailable = (pack: DeployPackDto) =>
    !!pack.local_node &&
    (pack.local_node.generation < pack.generation || pack.local_node.digest !== pack.digest);

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-2.5 overflow-y-auto">
      <div className="flex items-center gap-2">
        <Field label={t("pack.output")}>
          {(id) => (
            <div className="flex min-w-0 flex-1 items-center gap-2">
              <Input
                id={id}
                value={out}
                onChange={(e) => onOutChange(e.target.value)}
                autoCapitalize="none"
                autoCorrect="off"
                spellCheck={false}
                autoComplete="off"
                className="max-w-[420px] flex-1"
              />
              <Button onClick={() => onPickFile(onOutChange, true, t("pack.chooseDist"))}>…</Button>
              <Button disabled={busy} onClick={onRefresh}>
                {t("pack.refresh")}
              </Button>
              <Hint text={t("pack.issuePackTitle")}>
                <Button variant="primary" disabled={busy} onClick={onIssuePack}>
                  {t("pack.issuePack")}
                </Button>
              </Hint>
            </div>
          )}
        </Field>
      </div>

      {packs.length === 0 && <EmptyState>{t("pack.noPacks")}</EmptyState>}

      <div className="grid grid-cols-[repeat(auto-fill,minmax(300px,1fr))] content-start gap-3">
        {packs.map((pack) => (
          <Hint key={pack.dir_name} text={pack.principal}>
            <div
              role="button"
              tabIndex={0}
              onClick={() => onOpenPack(pack.dir_name)}
              onKeyDown={(e) => {
                if (e.key === "Enter") onOpenPack(pack.dir_name);
              }}
              className="flex w-full cursor-pointer flex-col gap-2 rounded-xl border border-line bg-bg-2 p-3.5 text-left text-fg-1 outline-none transition-[border-color,box-shadow] duration-150 hover:border-line-strong hover:shadow-elevate-1 focus-visible:border-accent focus-visible:ring-[3px] focus-visible:ring-accent-tint"
            >
              <div className="flex items-center gap-2">
                <strong className="min-w-0 flex-1 truncate text-base font-semibold">
                  {pack.dir_name}
                </strong>
                <KindBadge kind={pack.kind} />
              </div>
              <div className="flex flex-col gap-0.5 font-mono text-small text-fg-2">
                <div className="truncate">{pack.principal}</div>
                <div className="truncate">
                  {t("pack.genExpires", { gen: pack.generation, expires: pack.expires })}
                </div>
              </div>
              <div className="mt-auto flex min-h-control items-center gap-2">
                {pack.local_node ? (
                  <Hint text={pack.local_node.name}>
                    <span className="min-w-0 flex-1 truncate text-start text-small text-fg-3">
                      {pack.local_node.name} · gen {pack.local_node.generation}
                    </span>
                  </Hint>
                ) : (
                  <span className="min-w-0 flex-1 truncate text-small text-fg-3">
                    {t("pack.notOnMachine")}
                  </span>
                )}
                {pack.local_node && updateAvailable(pack) && (
                  <Hint
                    text={
                      pack.local_node.generation < pack.generation
                        ? t("pack.updateTitle")
                        : t("pack.updateTitleContent")
                    }
                  >
                    <Button
                      size="sm"
                      variant="primary"
                      disabled={busy}
                      onClick={(e) => {
                        e.stopPropagation();
                        onUpdateLocal(pack);
                      }}
                    >
                      {pack.local_node.generation < pack.generation
                        ? t("pack.updateTo", { gen: pack.generation })
                        : t("pack.update")}
                    </Button>
                  </Hint>
                )}
              </div>
            </div>
          </Hint>
        ))}
      </div>
    </div>
  );
}
