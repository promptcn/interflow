import { useState } from "react";
import { api, type ManifestTemplateParams } from "../api";
import { useT } from "../i18n";
import { Button, Field, Input } from "./ui";

/// The starter-template builder — the GUI twin of `interflow-cli setup`. Two
/// skeletons: the expose deployment (registrar tier, public routes) and the
/// site-to-site mesh (offline tier, one hub, no placeholder agents).
///
/// Shared by the manifest editor's toolbar (generated text seeds the open
/// document; the editor's Save is the write path) and the create-deployment
/// dialog (generated text goes through the create command — a new file, a
/// fresh deployment). Extracted 2026-10-09 from ManifestEditor so the
/// Overview's first-run empty state can offer the same builder.
export default function TemplateBuilder({
  onTemplate,
  onGenerated,
}: {
  /// Seed mode (the editor toolbar): the text lands in the open document.
  onTemplate?: (text: string) => void;
  /// Create mode: the text plus the realm id are handed to the flow that
  /// writes a new file (the realm names the deployment's folder). Exactly
  /// one of the two is wired per call site.
  onGenerated?: (text: string, realm: string) => void;
}) {
  const { t } = useT();
  const [open, setOpen] = useState<"expose" | "mesh" | null>(null);
  const [params, setParams] = useState<ManifestTemplateParams>({
    realm: "promptcn",
    control_endpoint: "tunnel.example.com:443",
    registrar_endpoint: "https://registrar.example.com",
    host: "app.example.com",
    agent: "desktop",
    service: "asr",
    service_address: "127.0.0.1:8080",
  });
  const [mesh, setMesh] = useState({ realm: "promptcn-mesh", hub_name: "central", hub_endpoint: "mesh.example.com:6666" });

  const field = (
    key: keyof ManifestTemplateParams,
    label: string,
    setter: (params: ManifestTemplateParams) => void,
  ) => (
    <Field key={key} label={label}>
      {(id) => (
        <Input
          id={id}
          value={params[key]}
          onChange={(e) => setter({ ...params, [key]: e.target.value })}
          autoCapitalize="none"
          autoCorrect="off"
          spellCheck={false}
        />
      )}
    </Field>
  );

  const generate = async () => {
    try {
      const text = await api.deployManifestTemplate(params);
      if (onGenerated) onGenerated(text, params.realm);
      else onTemplate?.(text);
      setOpen(null);
    } catch (e) {
      // The builder only formats; a failure here is a GUI bug, surface it.
      console.error("template failed:", e);
    }
  };

  const generateMesh = async () => {
    try {
      const text = await api.deployMeshTemplate(mesh);
      if (onGenerated) onGenerated(text, mesh.realm);
      else onTemplate?.(text);
      setOpen(null);
    } catch (e) {
      console.error("template failed:", e);
    }
  };

  if (open === null) {
    return (
      <>
        <Button onClick={() => setOpen("expose")}>{t("manifest.exposeTemplate")}</Button>
        <Button onClick={() => setOpen("mesh")}>{t("manifest.meshTemplate")}</Button>
      </>
    );
  }
  if (open === "mesh") {
    return (
      <div className="flex flex-col gap-1.5 rounded-lg border border-dashed border-line p-2.5">
        <Field label={t("manifest.realm")}>
          {(id) => (
            <Input
              id={id}
              value={mesh.realm}
              onChange={(e) => setMesh({ ...mesh, realm: e.target.value })}
              autoCapitalize="none"
              autoCorrect="off"
              spellCheck={false}
            />
          )}
        </Field>
        <Field label={t("manifest.hubName")}>
          {(id) => (
            <Input
              id={id}
              value={mesh.hub_name}
              onChange={(e) => setMesh({ ...mesh, hub_name: e.target.value })}
              autoCapitalize="none"
              autoCorrect="off"
              spellCheck={false}
            />
          )}
        </Field>
        <Field label={t("manifest.hubEndpoint")}>
          {(id) => (
            <Input
              id={id}
              value={mesh.hub_endpoint}
              onChange={(e) => setMesh({ ...mesh, hub_endpoint: e.target.value })}
              autoCapitalize="none"
              autoCorrect="off"
              spellCheck={false}
            />
          )}
        </Field>
        <div className="flex gap-2">
          <Button onClick={() => setOpen(null)}>{t("common.cancel")}</Button>
          <Button variant="primary" onClick={generateMesh}>
            {t("common.generate")}
          </Button>
        </div>
      </div>
    );
  }
  return (
    <div className="flex flex-col gap-1.5 rounded-lg border border-dashed border-line p-2.5">
      {field("realm", t("manifest.realm"), setParams)}
      {field("control_endpoint", t("manifest.controlEndpoint"), setParams)}
      {field("registrar_endpoint", t("manifest.registrarEndpoint"), setParams)}
      {field("host", t("manifest.publicHost"), setParams)}
      {field("agent", t("manifest.agentNode"), setParams)}
      {field("service", t("manifest.serviceId"), setParams)}
      {field("service_address", t("manifest.serviceAddress"), setParams)}
      <div className="flex gap-2">
        <Button onClick={() => setOpen(null)}>{t("common.cancel")}</Button>
        <Button variant="primary" onClick={generate}>
          {t("common.generate")}
        </Button>
      </div>
    </div>
  );
}
