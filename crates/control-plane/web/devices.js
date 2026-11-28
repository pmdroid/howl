const element = id => document.getElementById(id);
let busy = false;
let currentView = "";
const linkPage = location.pathname === "/link";
const secretKey = "howl.deviceLink";
const resumeKey = "howl.resumeDeviceLink";
let linkSecret;

function clearLink() {
  sessionStorage.removeItem(secretKey);
  sessionStorage.removeItem(resumeKey);
  linkSecret = null;
}

function finishLink(message, failed = false) {
  clearLink();
  element("dashboard").hidden = true;
  element("login").hidden = true;
  element("retry").hidden = true;
  element("pending").replaceChildren();
  element("network").querySelector("code").textContent = "";
  element("status").textContent = failed ? "" : message;
  element("error").textContent = failed ? message : "";
  element("leave-link").textContent = "Return to devices";
}

function prepareLink() {
  const fragment = location.hash.slice(1);
  if (location.hash) {
    history.replaceState(null, "", "/link");
    clearLink();
    if (/^[0-9a-f]{64}$/.test(fragment)) sessionStorage.setItem(secretKey, fragment);
  }
  linkSecret = sessionStorage.getItem(secretKey);
  document.title = "Connect a device · Howl";
  document.querySelector("h1").textContent = "Connect a device";
  document.querySelector("#login p").textContent = "Sign in with the GitHub account that owns the network you want this device to join.";
  document.querySelector("#requests h2").textContent = "Requesting device";
  element("members").hidden = true;
  element("leave-link").hidden = false;
  for (const link of document.querySelectorAll("#leave-link, .wordmark")) {
    link.addEventListener("click", clearLink);
  }
  element("login").querySelector("a").addEventListener("click", () => sessionStorage.setItem(resumeKey, "1"));
  if (!linkSecret) finishLink("Open the full device link printed by Howl on the requesting device.", true);
}

function signedOut() {
  currentView = "";
  element("network").querySelector("code").textContent = "";
  element("pending").replaceChildren();
  element("approved").replaceChildren();
  element("dashboard").hidden = true;
  element("logout").hidden = true;
  element("login").hidden = false;
  element("retry").hidden = true;
  element("status").textContent = "";
  element("error").textContent = "";
}

function deviceRow(device, decideRequest) {
  const row = element("device").content.firstElementChild.cloneNode(true);
  row.querySelector(".device-id code").textContent = device.id;
  const fingerprint = row.querySelector(".fingerprint code");
  for (const part of device.fingerprint.match(/.{1,8}/g)) {
    const span = document.createElement("span");
    span.textContent = part;
    fingerprint.append(span);
  }
  const actions = row.querySelector(".actions");
  if (decideRequest) {
    actions.setAttribute("aria-label", "Decision for device " + device.id);
    for (const button of actions.querySelectorAll("button")) {
      button.addEventListener("click", () => run(() => decideRequest(device, button.dataset.action)));
    }
  } else {
    actions.remove();
  }
  return row;
}

function render(view) {
  element("login").hidden = true;
  element("dashboard").hidden = false;
  element("logout").hidden = false;
  element("network").hidden = !view.network;
  element("network").querySelector("code").textContent = view.network || "";
  element("transfer").hidden = view.account_managed;
  element("transfer").textContent = view.network
    ? 'To manage approvals here, run howl control transfer "$founder_state" once on the founding device.'
    : "This account uses a manually enrolled network. Manage its devices with the enrollment CLI.";
  element("requests").hidden = !view.account_managed;
  element("pending").replaceChildren(...view.pending.map(device => deviceRow(device, decide)));
  element("empty").hidden = view.pending.length !== 0;
  element("instructions").hidden = view.pending.length === 0;
  element("approved").replaceChildren(...view.approved.map(device => deviceRow(device)));
  element("members").hidden = view.approved.length === 0;
  element("members").querySelector("summary").textContent = "Approved devices (" + view.approved.length + ")";
}

async function request(path, options) {
  const response = await fetch(path, {
    credentials: "same-origin", mode: "same-origin", cache: "no-store",
    signal: AbortSignal.timeout(15000), ...options,
  });
  if (response.status === 401) signedOut();
  return response;
}

async function refresh() {
  if (linkPage) return loadLink();
  const response = await request("/api/devices");
  if (response.status === 401) return;
  if (!response.ok) throw new Error("Could not load your network. Try again.");
  const view = await response.json();
  const serialized = JSON.stringify(view);
  if (currentView !== serialized) {
    render(view);
    currentView = serialized;
  }
  element("retry").hidden = true;
}

async function linkRequest(action, fields = {}) {
  const response = await request("/api/device-links/" + action, {
    method: "POST", headers: {"Content-Type": "application/json"},
    body: JSON.stringify({secret: linkSecret, ...fields}),
  });
  if (response.status === 401) return null;
  if (response.status === 404 || response.status === 410) {
    finishLink("This link has expired or is unavailable to this account. Request a new link on the device.", true);
    return null;
  }
  return response;
}

async function loadLink() {
  if (!linkSecret) return;
  const response = await linkRequest("view");
  if (!response) return;
  if (!response.ok) throw new Error("Could not load this device link. Try again.");
  const view = await response.json();
  element("login").hidden = true;
  element("logout").hidden = false;
  element("retry").hidden = true;
  if (view.state === "approved" || view.state === "denied") {
    finishLink("Device " + view.device.slice(0, 12) + "… " + view.state + ".");
    return;
  }
  if (view.state !== "pending") throw new Error("Could not read the state of this device link. Try again.");
  element("dashboard").hidden = false;
  element("empty").hidden = true;
  element("network").querySelector("code").textContent = view.network;
  const serialized = JSON.stringify(view);
  if (currentView !== serialized) {
    element("pending").replaceChildren(deviceRow({id: view.device, fingerprint: view.fingerprint}, decideLink));
    currentView = serialized;
  }
}

async function decideLink(device, decision) {
  const response = await linkRequest("decide", {device: device.id, fingerprint: device.fingerprint, decision});
  if (!response) return;
  if (response.status === 409) return loadLink();
  if (!response.ok) throw new Error("Could not save the decision. Try again to check the device link.");
  const result = decision === "approve" ? "approved" : "denied";
  finishLink("Device " + device.id.slice(0, 12) + "… " + result + ".");
}

async function decide(device, action) {
  const response = await request("/api/devices/" + action, {
    method: "POST", headers: {"Content-Type": "application/json"},
    body: JSON.stringify({device: device.id, fingerprint: device.fingerprint}),
  });
  if (response.status === 401) return;
  if (response.ok) {
    const result = action === "approve" ? "approved" : "denied";
    element("status").textContent = "Device " + device.id.slice(0, 12) + "… " + result + ".";
  } else if ([404, 409].includes(response.status)) {
    element("error").textContent = "This request has changed. Review the latest list.";
  } else {
    throw new Error("Could not save the decision. Refresh to check the request.");
  }
  await refresh();
}

async function run(operation) {
  if (busy) return;
  busy = true;
  const controls = document.querySelectorAll("button");
  for (const button of controls) button.disabled = true;
  element("status").textContent = "";
  element("error").textContent = "";
  try {
    await operation();
  } catch (error) {
    element("error").textContent = error instanceof TypeError || error.name === "TimeoutError"
      ? "Could not reach the control plane. Check your connection and try again."
      : error.message;
    element("retry").hidden = false;
    element("dashboard").hidden = true;
    currentView = "";
  } finally {
    for (const button of controls) button.disabled = false;
    busy = false;
  }
}

element("logout").addEventListener("click", () => run(async () => {
  const response = await request("/logout", {method: "POST"});
  if (!response.ok && response.status !== 401) throw new Error("Could not sign out. Try again.");
  signedOut();
  if (linkPage) {
    clearLink();
    location.replace("/devices");
  }
}));
element("refresh").addEventListener("click", () => run(refresh));
element("retry").addEventListener("click", () => run(refresh));
window.addEventListener("pageshow", event => {
  if (event.persisted) window.location.reload();
});
document.addEventListener("visibilitychange", () => {
  if (!document.hidden && (!linkPage || linkSecret)) run(refresh);
});
setInterval(() => {
  if (!document.hidden && !element("dashboard").hidden) run(refresh);
}, 15000);
if (linkPage) {
  window.addEventListener("hashchange", () => {
    if (location.hash) location.reload();
  });
  prepareLink();
  if (linkSecret) run(refresh);
} else if (location.pathname === "/devices" && sessionStorage.getItem(resumeKey) && sessionStorage.getItem(secretKey)) {
  sessionStorage.removeItem(resumeKey);
  location.replace("/link");
} else {
  run(refresh);
}
