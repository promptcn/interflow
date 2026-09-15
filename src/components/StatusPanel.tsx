import { TunnelState } from "../api";

export default function StatusPanel({
  state,
  text,
  color,
}: {
  state: TunnelState | null;
  text: string;
  color: string;
}) {
  return (
    <div className="status-panel">
      <span className="dot" style={{ background: color }} aria-label={text} />
      <span>{text}</span>
      {typeof state === "object" && state !== null && "Reconnecting" in state && (
        <span className="hint">Will reconnect automatically once the network recovers</span>
      )}
    </div>
  );
}
