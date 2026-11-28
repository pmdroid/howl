import type { MeshPath } from "../native-discovery.ts";
import {
  type DeviceIdentity,
  deviceName,
  element,
  fillIdentity,
  resumeKey,
} from "./device-identity.js";

type Connection = MeshPath & { name: string };
type Mesh = {
  online?: boolean;
  last_seen_at?: string;
  connections?: Connection[];
  home_relay?: string;
};
type Detail = DeviceIdentity &
  Mesh & {
    state: "pending" | "approved" | "denied";
    network_name?: string;
    network_id: string;
    endpoint_id: string;
    discovery?: { addresses: { ip: string; port: number }[]; relay?: string; expires_at: string };
    last_route_at?: string;
    requested_at?: string;
    approved_at?: string;
  };
const heading = document.querySelector("h1")!;
const id = location.pathname.split("/").pop() ?? "";
const path = "/api/devices/" + id;
let device: Detail | null = null;
let busy = false;
let checkingMesh = false;
let renderedConnections: string | undefined;
let renderedDiscovery: string | undefined;
const dateFormat = new Intl.DateTimeFormat(undefined, {
  dateStyle: "medium",
  timeStyle: "long",
});
const shortRtt = new Intl.NumberFormat(undefined, { maximumFractionDigits: 3 });
const longRtt = new Intl.NumberFormat(undefined, { maximumFractionDigits: 1 });

function timestamp(row: HTMLElement, value?: string) {
  const date = new Date(value ?? "");
  row.hidden = !value || Number.isNaN(date.valueOf());
  if (!row.hidden && value) {
    const time = row.querySelector("time")!;
    time.dateTime = value;
    time.textContent = dateFormat.format(date);
  }
}

function hideDevice() {
  device = null;
  document.title = "Device details · Howl";
  heading.textContent = "Device details";
  element("details").hidden = true;
  element("rename").hidden = true;
  element("editor").hidden = true;
  element<HTMLInputElement>("name").value = "";
  element("peer-connections").replaceChildren();
  element("published-addresses").replaceChildren();
  renderedConnections = undefined;
  renderedDiscovery = undefined;
  for (const value of element("details").querySelectorAll("dd code, dd time, dd[id]")) {
    value.replaceChildren();
    value.removeAttribute("datetime");
  }
}

function metric(label: string, text: string, code = false) {
  const item = document.createElement("div");
  const name = document.createElement("dt");
  const value = document.createElement("dd");
  name.textContent = label;
  if (code) {
    item.className = "path-relay";
    const address = document.createElement("code");
    address.dir = "ltr";
    address.textContent = text;
    value.append(address);
  } else value.textContent = text;
  item.append(name, value);
  return item;
}

function rtt(microseconds?: number) {
  if (microseconds === undefined) return "Not measured";
  const format = microseconds < 1000 ? shortRtt : longRtt;
  return `${format.format(microseconds / 1000)} ms`;
}

function renderMesh(view: Mesh, publishedRelay?: string) {
  const status = view.online === true ? "Online" : view.online === false ? "Offline" : "Unknown";
  element("mesh-status").textContent = status;
  timestamp(element("last-seen"), view.last_seen_at);
  const connectedToPublished = !!publishedRelay && view.home_relay === publishedRelay;
  element("published-relay-connected").hidden = !connectedToPublished;
  element("home-relay-row").hidden = !view.home_relay || connectedToPublished;
  element("home-relay").textContent = view.home_relay ?? "";
  const connections = view.connections ?? [];
  const serialized = JSON.stringify(connections);
  if (serialized !== renderedConnections) {
    const list = element("peer-connections");
    const focused = document.activeElement;
    const items = connections.map((connection) => {
      const item = document.createElement("li");
      const peer = document.createElement("a");
      peer.href = "/devices/" + connection.device;
      peer.className = "device-name";
      peer.dir = "auto";
      peer.textContent = connection.name;
      const kind = document.createElement("span");
      kind.textContent = connection.kind === "direct" ? "Direct" : "Relay";
      const heading = document.createElement("div");
      heading.className = "peer-path-heading";
      heading.append(peer, kind);
      item.append(heading);
      if (
        connection.direct_rtt_us !== undefined ||
        connection.relay_rtt_us !== undefined ||
        connection.relay
      ) {
        const metrics = document.createElement("dl");
        metrics.className = "peer-path-metrics";
        metrics.append(
          metric("Direct RTT", rtt(connection.direct_rtt_us)),
          metric("Relay RTT", rtt(connection.relay_rtt_us)),
        );
        if (connection.relay) metrics.append(metric("Peer path relay", connection.relay, true));
        item.append(metrics);
      }
      return item;
    });
    const restoreFocus =
      focused instanceof HTMLAnchorElement && list.contains(focused)
        ? items
            .flatMap((item) => [...item.querySelectorAll("a")])
            .find((link) => link.href === focused.href)
        : undefined;
    list.replaceChildren(...items);
    restoreFocus?.focus({ preventScroll: true });
    renderedConnections = serialized;
  }
  element("peer-status").textContent = connections.length
    ? ""
    : view.online === true
      ? "No active peer connections reported"
      : "No recent connection report";
}

function renderDiscovery(view: Detail) {
  const serialized = JSON.stringify([view.discovery, view.last_route_at]);
  if (serialized === renderedDiscovery) return;
  renderedDiscovery = serialized;
  const addresses = view.discovery?.addresses ?? [];
  const items = addresses.map(({ ip, port }) => {
    const item = document.createElement("li");
    const address = document.createElement("code");
    address.dir = "ltr";
    address.textContent = `${ip.includes(":") ? `[${ip}]` : ip}:${port}`;
    item.append(address);
    return item;
  });
  element("published-addresses").replaceChildren(...items);
  element("route-status").textContent = items.length
    ? ""
    : !view.discovery && view.last_route_at
      ? "Published routes expired"
      : "No UDP addresses published";
  element("published-relay-row").hidden = !view.discovery?.relay;
  element("published-relay").textContent = view.discovery?.relay ?? "";
  timestamp(element("last-route"), view.last_route_at);
  timestamp(element("route-expires"), view.discovery?.expires_at);
}

function render(view: Detail) {
  device = view;
  const name = deviceName(view);
  heading.textContent = name;
  document.title = name + " · Howl";
  element("login").hidden = true;
  element("logout").hidden = false;
  element("rename").hidden = false;
  element("details").hidden = false;
  element("state").textContent = { pending: "Pending", approved: "Approved", denied: "Denied" }[
    view.state
  ];
  fillIdentity(element("details"), view);
  element("network-name-row").hidden = !view.network_name;
  element("network-name").textContent = view.network_name ?? "";
  element("network-id").textContent = view.network_id;
  element("endpoint-id").textContent = view.endpoint_id;
  timestamp(element("requested"), view.requested_at);
  timestamp(element("admitted"), view.approved_at);
  renderDiscovery(view);
  renderMesh(view, view.discovery?.relay);
}

async function request(resource: string, options?: RequestInit) {
  const response = await fetch(resource, {
    credentials: "same-origin",
    mode: "same-origin",
    cache: "no-store",
    signal: AbortSignal.timeout(15000),
    ...options,
  });
  if (response.status === 401) {
    hideDevice();
    element("login").hidden = false;
    element("logout").hidden = true;
    return null;
  }
  if (response.status === 403 || response.status === 404) {
    hideDevice();
    element("login").hidden = true;
    element("error").textContent = "This device is unavailable to this account.";
    return null;
  }
  return response;
}

async function load() {
  const response = await request(path);
  if (!response) return;
  if (!response.ok) throw new Error("Could not load the device. Try again.");
  render(await response.json());
}

async function refreshMesh() {
  if (document.hidden || busy || checkingMesh || !device) return;
  checkingMesh = true;
  try {
    const response = await request(path);
    if (response?.ok) {
      const view: Detail = await response.json();
      if (device) {
        device.last_seen_at = view.last_seen_at;
        renderDiscovery(view);
        renderMesh(view, view.discovery?.relay);
      }
    } else if (device) {
      renderMesh({ last_seen_at: device.last_seen_at });
    }
  } catch {
    if (device) renderMesh({ last_seen_at: device.last_seen_at });
  } finally {
    checkingMesh = false;
  }
}

function editName() {
  if (!device) return;
  element<HTMLInputElement>("name").value = deviceName(device);
  element("name-error").textContent = "";
  element<HTMLInputElement>("name").removeAttribute("aria-invalid");
  element("editor").hidden = false;
  element("rename").hidden = true;
  element<HTMLInputElement>("name").select();
}

function endEdit() {
  element("editor").hidden = true;
  element("rename").hidden = false;
  element("name-error").textContent = "";
  element<HTMLInputElement>("name").removeAttribute("aria-invalid");
}

function invalidName(text: string) {
  element("name-error").textContent = text;
  element<HTMLInputElement>("name").setAttribute("aria-invalid", "true");
  element<HTMLInputElement>("name").focus();
}

async function save() {
  if (!device) return;
  const input = element<HTMLInputElement>("name").value;
  const name = input.trim();
  if (/\p{Cc}/u.test(input) || !name || Array.from(name).length > 80) {
    invalidName("Use 1 to 80 characters and leave out control characters.");
    return;
  }
  const response = await request(path + "/name", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name, fingerprint: device.fingerprint }),
  });
  if (!response) return;
  if (response.status === 400) {
    invalidName("Choose a name with 1 to 80 characters.");
    return;
  }
  if (!response.ok) throw new Error("Could not save the device name. Try again.");
  render(await response.json());
  endEdit();
  element("status").textContent = "Device name saved.";
}

async function run(operation: () => Promise<void>) {
  if (busy) return;
  busy = true;
  for (const button of document.querySelectorAll("button")) button.disabled = true;
  element("error").textContent = "";
  element("status").textContent = "";
  element("retry").hidden = true;
  try {
    await operation();
  } catch (error) {
    element("error").textContent =
      error instanceof TypeError || (error instanceof Error && error.name === "TimeoutError")
        ? "Could not reach the control plane. Check your connection and try again."
        : error instanceof Error
          ? error.message
          : "Could not complete the request.";
    if (element("editor").hidden) {
      hideDevice();
      element("retry").hidden = false;
    }
  } finally {
    for (const button of document.querySelectorAll("button")) button.disabled = false;
    busy = false;
  }
}

element("login")
  .querySelector("a")!
  .addEventListener("click", () => sessionStorage.setItem(resumeKey, id));
element("retry").addEventListener("click", () => run(load));
element("rename").addEventListener("click", editName);
element("cancel").addEventListener("click", () => {
  endEdit();
  element("rename").focus();
});
element("editor").addEventListener("submit", async (event) => {
  event.preventDefault();
  await run(save);
  if (device && element("editor").hidden) element("rename").focus();
});
element("logout").addEventListener("click", () =>
  run(async () => {
    const response = await request("/logout", { method: "POST" });
    if (response && !response.ok) throw new Error("Could not sign out. Try again.");
    location.replace("/devices");
  }),
);
window.addEventListener("pageshow", (event) => {
  if (event.persisted) location.reload();
});
document.addEventListener("visibilitychange", () => {
  if (!document.hidden && element("editor").hidden) run(load);
});
setInterval(refreshMesh, 10000);
run(load);
