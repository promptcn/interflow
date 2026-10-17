import type { DeployContextDto } from "../api";
import { useT } from "../i18n";
import { Select } from "./ui";

/// The remembered deployment-context picker — one widget that used to exist
/// as three near-identical native selects (the manifest editor, the issue
/// IssuePackDialog), each hand-parsing the same composite
/// `manifest|issuer|out` string.
export function contextKey(c: { manifest: string; issuer: string; out: string }): string {
  return `${c.manifest}|${c.issuer}|${c.out}`;
}

export default function RecentContextSelect({
  contexts,
  current,
  onPick,
  id,
}: {
  contexts: DeployContextDto[];
  current: { manifest: string; issuer: string; out: string };
  onPick: (ctx: DeployContextDto) => void;
  id?: string;
}) {
  const { t } = useT();
  if (contexts.length <= 1) return null;
  return (
    <Select
      id={id}
      ariaLabel={t("manifest.recent")}
      value={contextKey(current)}
      onValueChange={(key) => {
        const picked = contexts.find((c) => contextKey(c) === key);
        if (picked) onPick(picked);
      }}
      options={contexts.map((c) => ({
        value: contextKey(c),
        label: `${c.manifest} · ${c.issuer} · ${c.out}`,
      }))}
    />
  );
}
