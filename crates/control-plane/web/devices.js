const element = id => document.getElementById(id);
let busy = false;
let currentView = "";

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

function deviceRow(device, actionable) {
  const row = element("device").content.firstElementChild.cloneNode(true);
  row.querySelector(".device-id code").textContent = device.id;
  const fingerprint = row.querySelector(".fingerprint code");
  for (const part of device.fingerprint.match(/.{1,8}/g)) {
    const span = document.createElement("span");
    span.textContent = part;
    fingerprint.append(span);
  }
  const actions = row.querySelector(".actions");
  if (actionable) {
    actions.setAttribute("aria-label", "Decision for device " + device.id);
    for (const button of actions.querySelectorAll("button")) {
      button.addEventListener("click", () => run(() => decide(device, button.dataset.action)));
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
  element("pending").replaceChildren(...view.pending.map(device => deviceRow(device, true)));
  element("empty").hidden = view.pending.length !== 0;
  element("instructions").hidden = view.pending.length === 0;
  element("approved").replaceChildren(...view.approved.map(device => deviceRow(device, false)));
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
}));
element("refresh").addEventListener("click", () => run(refresh));
element("retry").addEventListener("click", () => run(refresh));
window.addEventListener("pageshow", event => {
  if (event.persisted) window.location.reload();
});
document.addEventListener("visibilitychange", () => {
  if (!document.hidden) run(refresh);
});
setInterval(() => {
  if (!document.hidden && !element("dashboard").hidden) run(refresh);
}, 15000);
run(refresh);
