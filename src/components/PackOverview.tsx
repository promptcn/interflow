import { type DeployPackDto } from "../api";
import { useT } from "../i18n";
import { principalRealm } from "../lib/shellFace";
import { packIdentities, packUpdateAction, packUpdateSource } from "../lib/packStatus";
import { Badge, Button, EmptyState, Hint, KindBadge } from "./ui";

/// The deploy face's landing view: one card per IDENTITY — the card is the
/// node the material belongs to, never the directory that happens to hold
/// it. Same grammar as the nodes overview (NodeCard): identity + kind +
/// generation state and at most one contextual primary action; the open
/// distribution window rides the card as a badge, and history (consumed or
/// superseded staging, archives) never surfaces — the filesystem stays its
/// archive. Everything else is the detail page.
export default function PackOverview({
  packs,
  busy,
  onRefresh,
  onOpenPack,
  onUpdateLocal,
  onIssuePack,
}: {
  packs: DeployPackDto[];
  busy: boolean;
  onRefresh: () => void;
  onOpenPack: (principal: string) => void;
  onUpdateLocal: (pack: DeployPackDto) => void;
  onIssuePack: () => void;
}) {
  const { t } = useT();
  const identities = packIdentities(packs);

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-2.5 overflow-y-auto">
      <div className="flex items-center justify-end gap-2">
        <Button disabled={busy} onClick={onRefresh}>
          {t("pack.refresh")}
        </Button>
        <Hint text={t("pack.issuePackTitle")}>
          <Button variant="primary" disabled={busy} onClick={onIssuePack}>
            {t("pack.issuePack")}
          </Button>
        </Hint>
      </div>

      {identities.length === 0 && <EmptyState>{t("pack.noPacks")}</EmptyState>}

      <div className="grid grid-cols-[repeat(auto-fill,minmax(300px,1fr))] content-start gap-3">
        {identities.map((identity) => {
          const { current, window } = identity;
          const realm = principalRealm(identity.principal);
          const source = packUpdateSource(identity);
          const action = packUpdateAction(source);
          const local = current.local_node;
          return (
            <Hint key={identity.principal} text={identity.principal}>
              <div
                role="button"
                tabIndex={0}
                onClick={() => onOpenPack(identity.principal)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") onOpenPack(identity.principal);
                }}
                className="flex w-full cursor-pointer flex-col gap-2 rounded-xl border border-line bg-bg-2 p-3.5 text-left text-fg-1 outline-none transition-[border-color,box-shadow] duration-150 hover:border-line-strong hover:shadow-elevate-1 focus-visible:border-accent focus-visible:ring-[3px] focus-visible:ring-accent-tint"
              >
                <div className="flex items-center gap-2">
                  <strong className="min-w-0 flex-1 truncate text-base font-semibold">
                    {current.node}
                  </strong>
                  {realm && <span className="shrink-0 font-mono text-micro text-fg-3">{realm}</span>}
                  <KindBadge kind={current.kind} />
                </div>
                <div className="flex flex-col gap-0.5 font-mono text-small text-fg-2">
                  <div className="truncate">{identity.principal}</div>
                  <div className="truncate">
                    {t("pack.genExpires", { gen: current.generation, expires: current.expires })}
                  </div>
                </div>
                {window && (
                  <Hint text={local ? t("pack.windowUpdateTitle") : t("pack.windowDistributeTitle")}>
                    <Badge tone="accent">
                      {t(local ? "pack.windowUpdateBadge" : "pack.windowDistributeBadge", {
                        gen: window.generation,
                      })}
                    </Badge>
                  </Hint>
                )}
                <div className="mt-auto flex min-h-control items-center gap-2">
                  {local ? (
                    <Hint text={local.name}>
                      <span className="min-w-0 flex-1 truncate text-start text-small text-fg-3">
                        {local.name} · gen {local.generation}
                      </span>
                    </Hint>
                  ) : (
                    <span className="min-w-0 flex-1 truncate text-small text-fg-3">
                      {t("pack.notOnMachine")}
                    </span>
                  )}
                  {local &&
                    (action === "upgrade" || action === "content") && (
                      <Hint
                        text={
                          action === "upgrade" ? t("pack.updateTitle") : t("pack.updateTitleContent")
                        }
                      >
                        <Button
                          size="sm"
                          variant="primary"
                          disabled={busy}
                          onClick={(e) => {
                            e.stopPropagation();
                            onUpdateLocal(source);
                          }}
                        >
                          {action === "upgrade"
                            ? t("pack.updateTo", { gen: source.generation })
                            : t("pack.update")}
                        </Button>
                      </Hint>
                    )}
                </div>
              </div>
            </Hint>
          );
        })}
      </div>
    </div>
  );
}
