import { useEffect, useState } from "react";
import { api, onLogLine, onTunnelState, TunnelState, LogLine, Transport, stateText, stateColor, isRunning } from "./api";
import ConfigForm from "./components/ConfigForm";
import StatusPanel from "./components/StatusPanel";
import LogView from "./components/LogView";

export default function App() {
  const [state, setState] = useState<TunnelState | null>(null);
  const [logs, setLogs] = useState<LogLine[]>([]);
  const [ports, setPorts] = useState<number[]>([]);
  const [hubUrl, setHubUrl] = useState("");
  const [clientCert, setClientCert] = useState("");
  const [clientKey, setClientKey] = useState("");
  const [agentId, setAgentId] = useState("");
  const [caPath, setCaPath] = useState("");
  const [transport, setTransport] = useState<Transport>("h2");
  const [hubQuicAddr, setHubQuicAddr] = useState("");
  const [profileLoaded, setProfileLoaded] = useState(false);

  useEffect(() => {
    (async () => {
      try {
        const profile = await api.loadProfile();
        if (profile.hub_url) setHubUrl(profile.hub_url);
        if (profile.client_cert) setClientCert(profile.client_cert);
        if (profile.client_key) setClientKey(profile.client_key);
        if (profile.agent_id) setAgentId(profile.agent_id);
        if (profile.ca_path) setCaPath(profile.ca_path);
        if (profile.local_ports?.length) setPorts(profile.local_ports);
        if (profile.transport) setTransport(profile.transport);
        if (profile.hub_quic_addr) setHubQuicAddr(profile.hub_quic_addr);
      } finally {
        setProfileLoaded(true);
      }
      setState(await api.getState());
      setLogs(await api.getRecentLogs());
    })();

    const unsubs = [
      onTunnelState(setState),
      onLogLine((line) =>
        setLogs((prev) => {
          const next = [...prev, line];
          return next.length > 2000 ? next.slice(next.length - 2000) : next;
        })
      ),
    ];
    return () => {
      unsubs.forEach((u) => u.then((f) => f()));
    };
  }, []);

  const running = isRunning(state);
  const canStart =
    !running &&
    ports.length > 0 &&
    hubUrl.trim() !== "" &&
    clientCert.trim() !== "" &&
    clientKey.trim() !== "" &&
    agentId.trim() !== "";

  const start = async () => {
    try {
      await api.startTunnel({
        local_ports: ports,
        hub_url: hubUrl.trim(),
        client_cert: clientCert.trim(),
        client_key: clientKey.trim(),
        agent_id: agentId.trim(),
        ca_path: caPath.trim() === "" ? null : caPath.trim(),
        transport,
        hub_quic_addr: hubQuicAddr.trim() === "" ? null : hubQuicAddr.trim(),
      });
      // After a successful start, persist the ports to the profile so the GUI auto-fills them on next launch
      try {
        await api.saveProfile({
          hub_url: hubUrl.trim() || null,
          client_cert: clientCert.trim() || null,
          client_key: clientKey.trim() || null,
          agent_id: agentId.trim() || null,
          ca_path: caPath.trim() || null,
          local_ports: ports,
          transport,
          hub_quic_addr: hubQuicAddr.trim() || null,
        });
      } catch (e) {
        console.error("Failed to auto-save profile:", e);
      }
    } catch (e) {
      setLogs((prev) => [...prev, { ts: new Date().toISOString(), level: "ERROR", target: "gui", message: String(e) }]);
    }
  };

  const stop = async () => {
    try {
      await api.stopTunnel();
    } catch (e) {
      console.error(e);
    }
  };

  return (
    <div className="app">
      <StatusPanel state={state} text={stateText(state)} color={stateColor(state)} />
      <ConfigForm
        disabled={running}
        ports={ports}
        setPorts={setPorts}
        hubUrl={hubUrl}
        setHubUrl={setHubUrl}
        clientCert={clientCert}
        setClientCert={setClientCert}
        clientKey={clientKey}
        setClientKey={setClientKey}
        agentId={agentId}
        setAgentId={setAgentId}
        caPath={caPath}
        setCaPath={setCaPath}
        transport={transport}
        setTransport={setTransport}
        hubQuicAddr={hubQuicAddr}
        setHubQuicAddr={setHubQuicAddr}
        profileLoaded={profileLoaded}
        onGenerateAgentId={async () => setAgentId(await api.generateAgentId())}
        onSaveProfile={async () => {
          await api.saveProfile({
            hub_url: hubUrl.trim() || null,
            client_cert: clientCert.trim() || null,
            client_key: clientKey.trim() || null,
            agent_id: agentId.trim() || null,
            ca_path: caPath.trim() || null,
            local_ports: ports.length > 0 ? ports : null,
            transport,
            hub_quic_addr: hubQuicAddr.trim() || null,
          });
        }}
      />
      <div className="actions">
        <button className="primary" disabled={!canStart} onClick={start}>
          Start
        </button>
        <button disabled={!running} onClick={stop}>
          Stop
        </button>
      </div>
      <LogView
        logs={logs}
        onClear={async () => {
          // View first (instant feedback), then the backend buffer it
          // replays from on reload — the other order would let cleared
          // lines reappear after a webview reload.
          setLogs([]);
          try {
            await api.clearLogs();
          } catch (e) {
            console.error("Failed to clear logs:", e);
          }
        }}
      />
    </div>
  );
}
