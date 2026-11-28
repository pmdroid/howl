export function dashboard(nonce) {
  return new Response(`<!doctype html>
<html lang="en">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Howl devices</title>
<style nonce="${nonce}">
:root { color-scheme: light dark; font: 1rem/1.5 system-ui, sans-serif; }
body { margin: 3rem auto; padding: 0 1.25rem; max-width: 44rem; }
section { border-block-start: 1px solid GrayText; padding: 1rem 0; }
code { display: block; overflow-wrap: anywhere; }
button { font: inherit; padding: .3rem .7rem; margin: .5rem .5rem .5rem 0; }
</style>
<main>
<h1>Howl devices</h1>
<p id="status" aria-live="polite"></p>
<a id="login" href="/login/github">Sign in with GitHub</a>
<div id="devices" hidden>
  <form method="post" action="/logout"><button>Sign out</button></form>
  <div id="list"></div>
</div>
</main>
<script nonce="${nonce}">
const find = id => document.getElementById(id);
const secret = location.hash.slice(1);
if (/^[0-9a-f]{64}$/.test(secret)) {
  sessionStorage.setItem("device-link", secret);
  history.replaceState(null, "", "/");
}
async function api(path, body) {
  const response = await fetch(path, body ? {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body)
  } : {});
  if (!response.ok) throw Error("Request failed (" + response.status + ").");
  return response.json();
}
async function refresh() {
  const { devices } = await api("/api/devices");
  find("status").textContent = devices.length ? "" : "Open a device’s link to approve it here.";
  const entries = devices.map(device => {
    const section = document.createElement("section");
    const title = document.createElement("strong");
    title.textContent = device.name + " · " + device.state;
    const fingerprint = document.createElement("code");
    fingerprint.textContent = device.fingerprint;
    section.append(title, fingerprint);
    if (device.state === "pending") for (const decision of ["approve", "deny"]) {
      const button = document.createElement("button");
      button.textContent = decision === "approve" ? "Approve" : "Deny";
      button.onclick = async () => {
        button.disabled = true;
        try {
          await api("/api/devices/decide", { device: device.device, fingerprint: device.fingerprint, decision });
          await refresh();
        } catch (error) {
          button.disabled = false;
          find("status").textContent = error.message;
        }
      };
      section.append(button);
    }
    return section;
  });
  find("list").replaceChildren(...entries);
}
async function start() {
  if (!(await fetch("/api/session")).ok) return;
  find("login").hidden = true;
  find("devices").hidden = false;
  const pending = sessionStorage.getItem("device-link");
  if (pending) {
    sessionStorage.removeItem("device-link");
    await api("/api/device-links/claim", { secret: pending });
  }
  await refresh();
}
start().catch(error => { find("status").textContent = error.message; });
</script>
</html>`, { headers: {
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "no-store",
    "Content-Security-Policy": `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'`,
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff"
  } });
}
