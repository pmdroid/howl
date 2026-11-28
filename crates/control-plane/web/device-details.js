import { deviceName, fillIdentity, resumeKey } from "./device-identity.js";

const element = id => document.getElementById(id);
const heading = document.querySelector("h1");
const id = location.pathname.split("/").pop();
const path = "/api/devices/" + id;
let device;
let busy = false;
const dateFormat = new Intl.DateTimeFormat(undefined, {
  dateStyle: "medium", timeStyle: "long",
});

function timestamp(row, value) {
  const date = new Date(value);
  row.hidden = !value || Number.isNaN(date.valueOf());
  if (!row.hidden) {
    const time = row.querySelector("time");
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
  element("name").value = "";
  for (const value of element("details").querySelectorAll("dd code, dd time, #state")) {
    value.replaceChildren();
    value.removeAttribute("datetime");
  }
}

function render(view) {
  device = view;
  const name = deviceName(view);
  heading.textContent = name;
  document.title = name + " · Howl";
  element("login").hidden = true;
  element("logout").hidden = false;
  element("rename").hidden = false;
  element("details").hidden = false;
  element("state").textContent = {pending: "Pending", approved: "Approved", denied: "Denied"}[view.state];
  fillIdentity(element("details"), view);
  timestamp(element("requested"), view.requested_at);
  timestamp(element("admitted"), view.approved_at);
  timestamp(element("last-route"), view.last_route_at);
}

async function request(resource, options) {
  const response = await fetch(resource, {
    credentials: "same-origin", mode: "same-origin", cache: "no-store",
    signal: AbortSignal.timeout(15000), ...options,
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

function editName() {
  element("name").value = deviceName(device);
  element("name-error").textContent = "";
  element("name").removeAttribute("aria-invalid");
  element("editor").hidden = false;
  element("rename").hidden = true;
  element("name").select();
}

function endEdit() {
  element("editor").hidden = true;
  element("rename").hidden = false;
  element("name-error").textContent = "";
  element("name").removeAttribute("aria-invalid");
}

function invalidName(text) {
  element("name-error").textContent = text;
  element("name").setAttribute("aria-invalid", "true");
  element("name").focus();
}

async function save() {
  const input = element("name").value;
  const name = input.trim();
  if (/\p{Cc}/u.test(input) || !name || Array.from(name).length > 80) {
    invalidName("Use 1 to 80 characters and leave out control characters.");
    return;
  }
  const response = await request(path + "/name", {
    method: "POST", headers: {"Content-Type": "application/json"},
    body: JSON.stringify({name, fingerprint: device.fingerprint}),
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

async function run(operation) {
  if (busy) return;
  busy = true;
  for (const button of document.querySelectorAll("button")) button.disabled = true;
  element("error").textContent = "";
  element("status").textContent = "";
  element("retry").hidden = true;
  try {
    await operation();
  } catch (error) {
    element("error").textContent = error instanceof TypeError || error.name === "TimeoutError"
      ? "Could not reach the control plane. Check your connection and try again."
      : error.message;
    if (element("editor").hidden) {
      hideDevice();
      element("retry").hidden = false;
    }
  } finally {
    for (const button of document.querySelectorAll("button")) button.disabled = false;
    busy = false;
  }
}

element("login").querySelector("a").addEventListener("click", () => sessionStorage.setItem(resumeKey, id));
element("retry").addEventListener("click", () => run(load));
element("rename").addEventListener("click", editName);
element("cancel").addEventListener("click", () => {
  endEdit();
  element("rename").focus();
});
element("editor").addEventListener("submit", async event => {
  event.preventDefault();
  await run(save);
  if (device && element("editor").hidden) element("rename").focus();
});
element("logout").addEventListener("click", () => run(async () => {
  const response = await request("/logout", {method: "POST"});
  if (response && !response.ok) throw new Error("Could not sign out. Try again.");
  location.replace("/devices");
}));
window.addEventListener("pageshow", event => {
  if (event.persisted) location.reload();
});
document.addEventListener("visibilitychange", () => {
  if (!document.hidden && element("editor").hidden) run(load);
});
run(load);
