import { useEffect, useRef } from "react";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import { LogLine } from "../api";
import { useT } from "../i18n";
import { cn } from "../lib/utils";
import { Button, useToast } from "./ui";

/// Level color — the same status vocabulary the dots speak. Static map,
/// unknown levels fall back to plain text.
const LEVEL_CLASS: Record<string, string> = {
  error: "text-critical",
  warn: "text-warn",
};

export default function LogView({
  logs,
  showNodeColumn,
  onClear,
}: {
  logs: LogLine[];
  showNodeColumn: boolean;
  onClear: () => void;
}) {
  const bottomRef = useRef<HTMLDivElement>(null);
  const toast = useToast();
  const { t } = useT();

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ block: "end" });
  }, [logs]);

  const copy = async () => {
    try {
      const text = logs
        .map((l) => `${l.ts} ${l.level} [${l.target}] ${l.message}`)
        .join("\n");
      await writeText(text);
      toast.push(t("common.copied"));
    } catch (e) {
      console.error("Failed to copy logs:", e);
    }
  };

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-1.5">
      <div className="flex justify-end gap-2">
        <Button size="sm" disabled={logs.length === 0} onClick={onClear}>
          {t("log.clear")}
        </Button>
        <Button size="sm" disabled={logs.length === 0} onClick={copy}>
          {t("log.copy")}
        </Button>
      </div>
      {/* Log contract:
          lines never wrap — the whole block scrolls horizontally and the
          columns stay aligned; auto-scroll follows the tail. */}
      <div className="min-h-0 flex-1 overflow-auto rounded-lg border border-line bg-bg-3 p-2.5 font-mono text-small">
        {logs.map((line, i) => (
          <div key={i} className="flex w-max min-w-full gap-2 py-px whitespace-pre">
            <span className="shrink-0 text-micro text-fg-3">{line.ts}</span>
            <span
              className={cn("w-[46px] shrink-0 font-semibold", LEVEL_CLASS[line.level.toLowerCase()] ?? "text-fg-1")}
            >
              {line.level}
            </span>
            {showNodeColumn && (
              <span className="w-[120px] shrink-0 overflow-hidden text-ellipsis text-fg-2">
                {line.node ?? "—"}
              </span>
            )}
            <span className="w-[210px] shrink-0 overflow-hidden text-ellipsis text-fg-3">
              {line.target}
            </span>
            <span className="flex-1 text-fg-1">{line.message}</span>
          </div>
        ))}
        <div ref={bottomRef} />
      </div>
    </div>
  );
}
