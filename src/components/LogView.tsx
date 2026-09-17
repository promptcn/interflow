import { useEffect, useRef, useState } from "react";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import { LogLine } from "../api";

export default function LogView({ logs }: { logs: LogLine[] }) {
  const bottomRef = useRef<HTMLDivElement>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ block: "end" });
  }, [logs]);

  const copy = async () => {
    try {
      const text = logs
        .map((l) => `${l.ts} ${l.level} [${l.target}] ${l.message}`)
        .join("\n");
      await writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch (e) {
      console.error("Failed to copy logs:", e);
    }
  };

  return (
    <div className="log-section">
      <div className="log-toolbar">
        <button disabled={logs.length === 0} onClick={copy}>
          {copied ? "Copied" : "Copy logs"}
        </button>
      </div>
      <div className="log-view">
        {logs.map((line, i) => (
          <div key={i} className={`log-line ${line.level.toLowerCase()}`}>
            <span className="log-ts">{line.ts}</span>
            <span className="log-level">{line.level}</span>
            <span className="log-target">{line.target}</span>
            <span className="log-msg">{line.message}</span>
          </div>
        ))}
        <div ref={bottomRef} />
      </div>
    </div>
  );
}
