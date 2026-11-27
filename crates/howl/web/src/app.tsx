import { useEffect, useState, type FormEvent, type ReactNode } from "react";
import { createRoot } from "react-dom/client";

type Device = { id: string; certificate: string; fingerprint: string };
type Channel = { id: string; members: string[]; manifest: string };
type Overview = { local: Device; peers: Device[]; channels: Channel[]; agents: { role: string; id: string }[] };
type Message = { message: string; sender: string; time: number; text: string; role: string | null };
type Work = { message: string; target: string; state: string; root: string | null; paused: boolean };
type Conversation = { messages: Message[]; work: Work[] };
type Receipt = { message: string };
type Delivery = { recipients: { device: string; attempts: number; acknowledged: boolean }[] };
type Repository = { commit: string; selection: string };

const fragment = window.location.hash.slice(1);
if (/^[a-f0-9]{64}$/.test(fragment)) sessionStorage.setItem("howl.session", fragment);
if (fragment) history.replaceState(null, "", window.location.pathname);
const session = sessionStorage.getItem("howl.session");

async function api<T>(action: string, fields: Record<string, unknown> = {}): Promise<T> {
  const response = await fetch("/api", {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${session}` },
    body: JSON.stringify({ action, ...fields }),
  });
  if (!response.ok) {
    const result = await response.json().catch(() => ({}));
    throw new Error(result.error ?? (response.status === 401
      ? "Open the current session link from your terminal."
      : `Request failed (${response.status}).`));
  }
  return response.json();
}

const short = (id: string) => id.slice(0, 12);
const words = (text: string) => text.trim().split(/[\s,]+/).filter(Boolean);
const lines = (text: string) => text.split("\n").map(line => line.trim()).filter(Boolean);
const input = (data: FormData, key: string) => String(data.get(key) ?? "");

function Field({ label, children }: { label: string; children: ReactNode }) {
  return <label>{label}{children}</label>;
}

function PeerSelect({ peers }: { peers: string[] }) {
  return <Field label="Peer device"><select name="peer" required defaultValue="">
    <option value="" disabled>Choose a device</option>
    {peers.map(peer => <option key={peer} value={peer}>{short(peer)}</option>)}
  </select></Field>;
}

function App() {
  const [overview, setOverview] = useState<Overview>();
  const [selected, setSelected] = useState("");
  const [conversation, setConversation] = useState<Conversation>();
  const [revision, refresh] = useState(0);
  const [matches, setMatches] = useState<string[]>();
  const [messageId, setMessageId] = useState("");
  const [delivery, setDelivery] = useState<Delivery>();
  const [repository, setRepository] = useState<Repository>();
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);
  const channel = overview?.channels.find(item => item.id === selected);
  const peers = channel?.members.filter(id => id !== overview?.local.id) ?? [];

  useEffect(() => {
    if (!session) return;
    let active = true;
    api<Overview>("overview").then(data => {
      if (active) {
        setOverview(data);
        setSelected(id => id || data.channels[0]?.id || "");
      }
    }).catch(reason => { if (active) setError(reason.message); });
    return () => { active = false; };
  }, [revision]);

  useEffect(() => {
    if (!selected) return;
    let active = true;
    let timer: number;
    async function update() {
      try {
        const data = await api<Conversation>("conversation", { channel: selected });
        if (active) {
          setConversation(data);
          timer = window.setTimeout(update, 5000);
        }
      } catch (reason) {
        if (active) setError(reason instanceof Error ? reason.message : "Could not load this channel.");
      }
    }
    void update();
    return () => { active = false; window.clearTimeout(timer); };
  }, [selected, revision]);

  async function run(action: () => Promise<void>) {
    setError("");
    setNotice("");
    setBusy(true);
    try { await action(); }
    catch (reason) { setError(reason instanceof Error ? reason.message : "Request failed."); }
    finally { setBusy(false); }
  }

  function form(action: (data: FormData, element: HTMLFormElement) => Promise<void>) {
    return (event: FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      const element = event.currentTarget;
      const data = new FormData(element);
      void run(() => action(data, element));
    };
  }

  function select(id: string) {
    if (selected === id) return;
    setSelected(id);
    setConversation(undefined);
    setMatches(undefined);
    setMessageId("");
    setDelivery(undefined);
    setRepository(undefined);
  }

  async function lookup(message: string) {
    setDelivery(undefined);
    setDelivery(await api<Delivery>("delivery", { channel: selected, message }));
  }

  async function send(data: FormData, element: HTMLFormElement, wake: boolean) {
    const receipt = await api<Receipt>(wake ? "wake" : "send", {
      channel: selected,
      peer: input(data, "peer"),
      route: input(data, "route").trim() || "-",
      text: input(data, "text"),
      ...(wake ? { target: input(data, "target"), lifetime: Number(input(data, "lifetime")) } : {}),
    });
    setMessageId(receipt.message);
    setNotice(wake ? "Wake queued." : "Message queued.");
    element.reset();
    await lookup(receipt.message);
  }

  if (!session) return <main className="locked"><h1>Howl</h1><p>Open the session link printed by <code>howl web</code>.</p></main>;

  return <>
    <header className="topbar">
      <a href="/" className="wordmark">Howl</a>
      <div className="top-actions">
        {overview && <span title={overview.local.id}>This device <code>{short(overview.local.id)}</code></span>}
        <button type="button" disabled={busy} onClick={() => refresh(value => value + 1)}>Refresh</button>
      </div>
    </header>
    <main className="layout">
      <aside className="sidebar">
        <h2>Channels</h2>
        <nav aria-label="Channels">
          {overview?.channels.map(item => <button key={item.id} className="channel" title={item.id}
            type="button" disabled={busy} aria-current={selected === item.id ? "page" : undefined}
            onClick={() => select(item.id)}>
            <code>{short(item.id)}</code><span>{item.members.length} {item.members.length === 1 ? "device" : "devices"}</span>
          </button>)}
        </nav>
        <details open={overview?.channels.length === 0 || undefined}>
          <summary>New conversation</summary>
          <form onSubmit={form(async data => {
            const item = await api<Channel>("create", { peers: words(input(data, "peers")) });
            select(item.id);
            refresh(value => value + 1);
            setNotice("Conversation created.");
          })}>
            <Field label="Trusted peer IDs (optional)"><textarea name="peers" rows={2} /></Field>
            <button disabled={busy}>Create conversation</button>
          </form>
        </details>
        <details>
          <summary>Join channel</summary>
          <form onSubmit={form(async (data, element) => {
            const item = await api<Channel>("join", { manifest: input(data, "manifest") });
            select(item.id);
            refresh(value => value + 1);
            setNotice("Channel joined.");
            element.reset();
          })}>
            <Field label="Signed channel manifest"><textarea name="manifest" rows={3} required /></Field>
            <button disabled={busy}>Join channel</button>
          </form>
        </details>
        <h2>Devices</h2>
        {overview?.peers.length === 0 && <p className="muted">No trusted peers yet.</p>}
        {overview?.peers.map(peer => <details key={peer.id}>
          <summary>{short(peer.id)}</summary><code className="digest" title="Fingerprint">{peer.fingerprint}</code>
        </details>)}
        <details>
          <summary>Pair device</summary>
          <form onSubmit={form(async (data, element) => {
            await api("pair", { certificate: input(data, "certificate"), fingerprint: input(data, "fingerprint") });
            refresh(value => value + 1);
            setNotice("Device paired.");
            element.reset();
          })}>
            <Field label="Peer certificate"><textarea name="certificate" rows={3} required /></Field>
            <Field label="Independently confirmed fingerprint"><input name="fingerprint" required /></Field>
            <button disabled={busy}>Trust device</button>
          </form>
        </details>
        {overview && <details>
          <summary>This device’s certificate</summary>
          <Field label="Device ID"><input readOnly value={overview.local.id} /></Field>
          <Field label="Fingerprint"><input readOnly value={overview.local.fingerprint} /></Field>
          <Field label="Certificate"><textarea rows={3} readOnly value={overview.local.certificate} /></Field>
        </details>}
      </aside>

      <section className="workspace">
        {error && <p role="alert" className="error">{error}</p>}
        {notice && <p role="status" className="notice">{notice}</p>}
        {!channel ? <div className="welcome"><h1>{overview ? "Conversations" : "Opening Howl"}</h1>
          {overview && <p>Create a conversation or join a channel using its signed manifest.</p>}
        </div> : <>
          <div className="conversation-header">
            <div><h1>Conversation</h1><code title={channel.id}>{short(channel.id)}</code></div>
            <details>
              <summary>Share manifest</summary>
              <Field label="Signed manifest"><textarea readOnly rows={3} value={channel.manifest} /></Field>
            </details>
          </div>

          <form className="search" onSubmit={form(async data => {
            setMatches((await api<{ matches: string[] }>("search", { channel: selected, query: input(data, "query") })).matches);
          })}>
            <Field label="Search chat"><input type="search" name="query" required /></Field>
            <button disabled={busy}>Search</button>
            {matches && <button type="button" onClick={() => setMatches(undefined)}>Clear</button>}
          </form>
          <div className="timeline">
            {matches ? (matches.length ? matches.map((text, index) => <p key={index}>{text}</p>) : <p className="muted">No matching messages.</p>) :
              (conversation?.messages.length ? conversation.messages.map(message =>
                <article className="message" key={`${message.sender}/${message.message}`}>
                  <div className="message-meta">
                    <strong title={message.sender}>{message.role ?? short(message.sender)}</strong>
                    <time dateTime={new Date(message.time * 1000).toISOString()}>{new Date(message.time * 1000).toLocaleString()}</time>
                  </div>
                  <p>{message.text}</p>
                </article>) : <p className="muted">{conversation ? "No messages in this channel." : "Loading messages…"}</p>)}
          </div>

          {peers.length > 0 && <form className="composer" key={channel.id} onSubmit={form((data, element) => send(data, element, false))}>
            <Field label="Message"><textarea name="text" rows={3} required /></Field>
            <div className="form-row"><PeerSelect peers={peers} /><Field label="Peer route (optional)"><input name="route" placeholder="IP:port" /></Field></div>
            <button className="primary" disabled={busy}>Send message</button>
          </form>}

          <section className="operations" key={selected}>
            {peers.length > 0 && <details>
              <summary>Wake an agent</summary>
              <form onSubmit={form((data, element) => send(data, element, true))}>
                <div className="form-row"><PeerSelect peers={peers} /><Field label="Peer route (optional)"><input name="route" placeholder="IP:port" /></Field></div>
                <div className="form-row">
                  <Field label="Target agent ID"><input name="target" required /></Field>
                  <Field label="Expires in (seconds)"><input name="lifetime" type="number" min={1} max={300} defaultValue={120} required /></Field>
                </div>
                <Field label="Wake request"><textarea name="text" required rows={3} /></Field>
                <button className="primary" disabled={busy}>Send wake</button>
              </form>
            </details>}
            <details>
              <summary>Agents and pause</summary>
              <ul className="agents">{overview?.agents.map(agent => <li key={agent.id}>
                <strong>{agent.role}</strong><code className="digest">{agent.id}</code>
              </li>)}</ul>
              {conversation?.work.length === 0 && <p className="muted">No wake requests received.</p>}
              <ul className="agents">{conversation?.work.map(work => <li key={work.message}>
                <div title={work.target}><code>{short(work.message)}</code> · {work.paused ? "paused" : work.state}</div>
                {work.root && !work.paused && work.state !== "expired" && <button className="pause" disabled={busy}
                  onClick={() => void run(async () => {
                    await api("pause", { channel: selected, root: work.root });
                    setNotice("Agent turn paused.");
                    refresh(value => value + 1);
                  })}>Pause conversation</button>}
              </li>)}</ul>
              {peers.length > 0 && <form onSubmit={form(async data => {
                await api("grant", { channel: selected, peer: input(data, "peer"), role: input(data, "role"), generation: Number(input(data, "generation")) });
                setNotice("Wake grant saved.");
              })}>
                <div className="form-row"><PeerSelect peers={peers} />
                  <Field label="Local agent"><select name="role"><option value="architect">Architect</option><option value="reviewer">Reviewer</option></select></Field>
                  <Field label="Grant generation"><input name="generation" type="number" min={1} defaultValue={1} required /></Field>
                </div>
                <button disabled={busy}>Grant wake permission</button>
              </form>}
            </details>
            <details open={Boolean(delivery) || undefined}>
              <summary>Delivery status</summary>
              <form onSubmit={form(() => lookup(messageId))}>
                <Field label="Outgoing message ID"><input value={messageId} onChange={event => setMessageId(event.target.value)} required /></Field>
                <button disabled={busy}>Check delivery</button>
              </form>
              {delivery && (delivery.recipients.length
                ? <ul className="agents">{delivery.recipients.map(item => <li key={item.device} title={item.device}>
                  <code>{short(item.device)}</code> · {item.acknowledged ? "Delivered" : "Queued"} · {item.attempts} attempts
                </li>)}</ul> : <p className="muted">No outgoing message with this ID.</p>)}
            </details>
            <details>
              <summary>Repository selection</summary>
              <form onSubmit={form(async data => {
                setRepository(undefined);
                setRepository(await api<Repository>("repository", {
                  repository: input(data, "repository"), commit: input(data, "commit"), paths: lines(input(data, "paths")),
                }));
              })}>
                <Field label="Local repository path"><input name="repository" required /></Field>
                <Field label="Commit or ref"><input name="commit" defaultValue="HEAD" required /></Field>
                <Field label="Included files, one relative path per line"><textarea name="paths" rows={3} required /></Field>
                <button disabled={busy}>Select repository files</button>
              </form>
              {repository && <dl>
                <dt>Commit</dt><dd><code className="digest">{repository.commit}</code></dd>
                <dt>Selection digest</dt><dd><code className="digest">{repository.selection}</code></dd>
              </dl>}
            </details>
          </section>
        </>}
      </section>
    </main>
  </>;
}

createRoot(document.getElementById("root")!).render(<App />);
