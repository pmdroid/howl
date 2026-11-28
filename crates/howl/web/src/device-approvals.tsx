import { useEffect, useState } from "react";

type Device = { id: string; fingerprint: string };
type Membership = "unconfigured" | "legacy" | "founder" | "pending" | "approved" | "denied";
type Requests = { membership: Membership; local: Device; pending: Device[] };
type Api = <T>(action: string, fields?: Record<string, unknown>) => Promise<T>;

const membershipText = {
  pending: "Ask the founder to match this fingerprint and approve your device.",
  denied: "The founder denied this device’s request to join the network.",
  approved: "This device has access to the network. The founder handles new device requests.",
  legacy: "This device uses an enrollment without founder approvals.",
  unconfigured: "Sign in to the control plane to enroll this device.",
};

function Identity({ device }: { device: Device }) {
  return <dl className="device-identity">
    <dt>Fingerprint</dt>
    <dd className="fingerprint"><code>{device.fingerprint.match(/.{1,8}/g)?.map((part, index) =>
      <span key={index}>{part}</span>)}</code></dd>
    <dt>Device ID</dt>
    <dd className="device-id"><code>{device.id}</code></dd>
  </dl>;
}

export function DeviceApprovals({ api }: { api: Api }) {
  const [requests, setRequests] = useState<Requests>();
  const [revision, refresh] = useState(0);
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState("");
  const [decisionError, setDecisionError] = useState("");
  const [notice, setNotice] = useState("");

  useEffect(() => {
    if (busy) return;
    let active = true;
    let timer: number;
    async function load() {
      try {
        const data = await api<Requests>("device_requests");
        if (active) {
          setRequests(data);
          setLoadError("");
        }
      } catch (reason) {
        if (active) setLoadError(reason instanceof Error ? reason.message : "Could not load device requests.");
      } finally {
        if (active) {
          setLoading(false);
          timer = window.setTimeout(load, 10000);
        }
      }
    }
    void load();
    return () => { active = false; window.clearTimeout(timer); };
  }, [api, busy, revision]);

  async function decide(device: Device, action: "approve_device" | "deny_device") {
    setBusy(true);
    setNotice("");
    setDecisionError("");
    try {
      await api(action, { device: device.id, fingerprint: device.fingerprint });
      setRequests(current => current && { ...current, pending: current.pending.filter(item => item.id !== device.id) });
      setNotice(`Device ${device.id.slice(0, 12)}… ${action === "approve_device" ? "approved" : "denied"}.`);
    } catch (reason) {
      setDecisionError(reason instanceof Error ? reason.message : "Could not save this decision.");
    } finally {
      setLoading(true);
      setBusy(false);
      refresh(value => value + 1);
    }
  }

  return <>
    <header className="topbar"><span className="wordmark">Howl</span>
      <button type="button" disabled={busy || loading} onClick={() => { setLoading(true); refresh(value => value + 1); }}>
        {loading ? "Refreshing…" : "Refresh"}
      </button>
    </header>
    <main className="approvals">
      <h1>Device approvals</h1>
      {decisionError && <p className="error" role="alert">{decisionError}</p>}
      {loadError && <p className="error" role="alert">{loadError}</p>}
      <div role="status">{notice && <p className="notice">{notice}</p>}</div>
      {!requests && !loadError && <p role="status">Loading device requests…</p>}
      {requests && (requests.membership === "founder" ? <section>
        <h2>Pending requests{requests.pending.length > 0 && ` (${requests.pending.length})`}</h2>
        {requests.pending.length ? <>
          <p className="approval-help">Before approving, match the fingerprint with the one on the requesting device.</p>
          <ul className="device-requests">{requests.pending.map(device => <li key={device.id}>
            <Identity device={device} />
            <div className="device-actions" role="group" aria-label={`Decision for device ${device.id}`}>
              <button type="button" className="primary" disabled={busy || loading || !!loadError}
                onClick={() => void decide(device, "approve_device")}>Approve</button>
              <button type="button" className="pause" disabled={busy || loading || !!loadError}
                onClick={() => void decide(device, "deny_device")}>Deny</button>
            </div>
          </li>)}</ul>
        </> : <p className="approval-empty">No devices are waiting for approval.</p>}
      </section> : <section>
        <h2>{requests.membership === "pending" ? "Waiting for approval" : "This device"}</h2>
        <p className="approval-help">{membershipText[requests.membership]}</p>
        <Identity device={requests.local} />
      </section>)}
    </main>
  </>;
}
