// Telltale SOC console (plan section 6). Plain JS, no build step.
// Login: Cloudflare Access (in front of this site) + Cognito here (PKCE, passkey or TOTP).
// Everything that comes from devices (names, paths, IPs) is shown with text nodes, never as HTML.
"use strict";

const CFG = window.TELLTALE;
const IDLE_MS = 15 * 60 * 1000; // plan 6.4: 15 min idle timeout
let idToken = null; // memory only, never localStorage
let timer = null; // the current view's auto-refresh
let lastInput = Date.now();

// ───────────── login (Cognito managed login, authorization code + PKCE) ─────────────
const b64url = (bytes) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const redirectUri = () => `${location.origin}/`;

async function login(reauth = false) {
  const verifier = b64url(crypto.getRandomValues(new Uint8Array(32)));
  const challenge = b64url(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))));
  const state = b64url(crypto.getRandomValues(new Uint8Array(16)));
  sessionStorage.setItem("pkce", JSON.stringify({ verifier, state, back: location.hash }));
  const q = new URLSearchParams({
    response_type: "code", client_id: CFG.clientId, redirect_uri: redirectUri(), scope: "openid email",
    code_challenge_method: "S256", code_challenge: challenge, state,
  });
  if (reauth) q.set("prompt", "login"); // step-up: a fresh passkey / TOTP check
  location.assign(`${CFG.cognitoDomain}/oauth2/authorize?${q}`);
}

async function finishLogin() {
  const q = new URLSearchParams(location.search);
  if (!q.has("code")) return;
  const saved = JSON.parse(sessionStorage.getItem("pkce") ?? "null");
  sessionStorage.removeItem("pkce");
  history.replaceState(null, "", `/${saved?.back ?? ""}`);
  if (!saved || saved.state !== q.get("state")) return;
  const res = await fetch(`${CFG.cognitoDomain}/oauth2/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code", client_id: CFG.clientId, code: q.get("code"),
      redirect_uri: redirectUri(), code_verifier: saved.verifier,
    }),
  });
  if (res.ok) idToken = (await res.json()).id_token;
}

function logout() {
  idToken = null;
  location.assign(`${CFG.cognitoDomain}/logout?${new URLSearchParams({ client_id: CFG.clientId, logout_uri: redirectUri() })}`);
}

function claims() {
  try {
    return JSON.parse(atob(idToken.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")));
  } catch {
    return {};
  }
}

// ───────────── API ─────────────
class StepUp extends Error {}

async function api(path, method = "GET") {
  const res = await fetch(`/admin/${path}`, { method, headers: { "x-tt-admin-token": idToken ?? "" } });
  const body = await res.json().catch(() => ({}));
  if (res.status === 401 && body.error === "step_up") throw new StepUp("needs a fresh sign-in");
  if (res.status === 401) {
    idToken = null;
    showLogin();
    throw new Error("signed out");
  }
  if (!res.ok) throw new Error(body.error ?? `HTTP ${res.status}`);
  return body;
}

async function act(path, label) {
  if (!confirm(`${label}?`)) return;
  try {
    await api(path, "POST");
    toast(`${label}: done`);
    render();
  } catch (e) {
    if (e instanceof StepUp) {
      if (confirm(`${label} needs a fresh sign-in. Sign in again now?`)) login(true);
    } else {
      toast(`${label} failed: ${e.message}`);
    }
  }
}

// ───────────── DOM helpers ─────────────
function el(tag, props = {}, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === "class") n.className = v;
    else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
    else n.setAttribute(k, v);
  }
  n.append(...kids.filter((k) => k != null).map((k) => (k instanceof Node ? k : String(k))));
  return n;
}

const toast = (msg) => {
  const t = document.getElementById("toast");
  t.textContent = msg;
  setTimeout(() => { if (t.textContent === msg) t.textContent = ""; }, 5000);
};
const when = (ts) => (ts ? new Date(ts * 1000).toLocaleString() : "—");
const short = (s, n = 12) => (s && s.length > n ? `${s.slice(0, n)}…` : s ?? "");

const BADGES = {
  tpm: ["ok", "✓ Verified (TPM)"], software: ["warn", "! Lower trust (software)"], failed: ["bad", "✕ Failed"],
  KILL: ["bad", "✕ KILL"], BENIGN: ["ok", "✓ BENIGN"], active: ["ok", "✓ active"], revoked: ["bad", "✕ revoked"],
};
const badge = (v) => {
  const [cls, text] = BADGES[v] ?? ["", v ?? "—"];
  return el("span", { class: `badge ${cls}` }, text);
};

/** Sortable, filterable table. columns: [{key, label, render?(row), mono?}] */
function table(columns, rows) {
  let sortKey = null, asc = true;
  const filter = el("input", { type: "search", placeholder: "Filter…", "aria-label": "Filter rows" });
  const tbody = el("tbody");
  const draw = () => {
    const f = filter.value.toLowerCase();
    const shown = rows
      .filter((r) => !f || columns.some((c) => String(r[c.key] ?? "").toLowerCase().includes(f)))
      .sort((a, b) => (sortKey ? (a[sortKey] > b[sortKey] ? 1 : a[sortKey] < b[sortKey] ? -1 : 0) * (asc ? 1 : -1) : 0));
    tbody.replaceChildren(...shown.map((r) => el("tr", {}, ...columns.map((c) => el("td", c.mono ? { class: "mono" } : {}, c.render ? c.render(r) : r[c.key] ?? "")))));
  };
  const head = el("tr", {}, ...columns.map((c) => el("th", { scope: "col", onclick: () => { asc = sortKey === c.key ? !asc : true; sortKey = c.key; draw(); } }, c.label)));
  filter.addEventListener("input", draw);
  draw();
  return el("div", {}, el("div", { class: "bar" }, filter, el("span", { class: "muted" }, `${rows.length} rows`)),
    el("div", { class: "tablewrap" }, el("table", {}, el("thead", {}, head), tbody)));
}

function dayPicker(onchange) {
  const input = el("input", { type: "date", "aria-label": "Day (UTC)", value: new Date().toISOString().slice(0, 10) });
  input.addEventListener("change", () => onchange(input.value));
  return input;
}

const eventCols = [
  { key: "ts", label: "Time", render: (r) => when(r.ts) },
  { key: "device", label: "Device", mono: true, render: (r) => (r.device ? el("a", { href: `#/device/${r.device}` }, short(r.device)) : "—") },
  { key: "ip", label: "IP", mono: true },
  { key: "country", label: "Country" },
  { key: "verified", label: "Verified", render: (r) => badge(r.verified) },
  { key: "path", label: "Path", mono: true },
  { key: "verdict", label: "Verdict", render: (r) => (r.verdict ? badge(r.verdict) : "—") },
  { key: "status", label: "HTTP", mono: true },
  { key: "reason", label: "Rejected because" },
  { key: "ms", label: "ms", mono: true, render: (r) => (r.ms ?? 0).toFixed(1) },
];

// ───────────── views ─────────────
const VIEWS = {
  async overview(view) {
    const o = await api("overview");
    const kpi = (label, value, cls = "") => el("div", { class: "kpi" }, el("b", { class: cls }, value), el("span", {}, label));
    view.append(el("h1", {}, "Overview"), el("div", { class: "kpis" },
      kpi("Devices", o.devices), kpi("Online (24 h)", o.online_24h), kpi("Revoked", o.revoked, o.revoked ? "bad" : ""),
      kpi("Lower trust (no TPM)", o.lower_trust, o.lower_trust ? "warn" : ""), kpi("Tier-2 requests (1 h)", o.requests_1h),
      kpi("Rejected (1 h)", o.rejected_1h, o.rejected_1h ? "warn" : ""), kpi("KILL verdicts (1 h)", o.kills_1h, o.kills_1h ? "bad" : ""),
      kpi("p50 / p99 ms", `${o.p50_ms.toFixed(1)} / ${o.p99_ms.toFixed(1)}`)));
    view.append(el("h2", {}, "Latest requests"), table(eventCols, (await api("events")).slice(0, 20)));
    return 60_000;
  },

  async devices(view) {
    const rows = await api("devices");
    view.append(el("h1", {}, "Devices"), table([
      { key: "device_id", label: "Device", mono: true, render: (r) => el("a", { href: `#/device/${r.device_id}` }, short(r.device_id)) },
      { key: "kind", label: "Key", render: (r) => badge(r.kind) },
      { key: "status", label: "Status", render: (r) => badge(r.status) },
      { key: "last_ip", label: "Current IP", mono: true },
      { key: "last_seen", label: "Last seen", render: (r) => when(r.last_seen) },
      { key: "first_ip", label: "First IP", mono: true },
      { key: "created_at", label: "Registered", render: (r) => when(r.created_at) },
      { key: "action", label: "", render: (r) => r.status === "revoked"
        ? el("button", { class: "btn", onclick: () => act(`devices/${r.device_id}/restore`, `Restore ${short(r.device_id)}`) }, "Restore")
        : el("button", { class: "btn danger", onclick: () => act(`devices/${r.device_id}/revoke`, `Revoke ${short(r.device_id)}`) }, "Revoke") },
    ], rows));
    return 0;
  },

  async device(view, id) {
    const { device: d, ips } = await api(`devices/${encodeURIComponent(id)}`);
    view.append(el("h1", {}, "Device ", el("span", { class: "mono" }, d.device_id)),
      el("p", {}, badge(d.kind), " ", badge(d.status), ` Registered ${when(d.created_at)} from `, el("span", { class: "mono" }, d.first_ip || "—")),
      el("h2", {}, "IP history"),
      table([
        { key: "sk", label: "IP", mono: true, render: (r) => r.sk.replace(/^ip#/, "") },
        { key: "country", label: "Country" },
        { key: "hits", label: "Requests", mono: true },
        { key: "first_seen", label: "First seen", render: (r) => when(r.first_seen) },
        { key: "last_seen", label: "Last seen", render: (r) => when(r.last_seen) },
      ], ips));
    return 0;
  },

  async ips(view) {
    view.append(el("h1", {}, "IPs"), el("p", { class: "muted" }, "Many devices behind one IP, or one IP with many failures, are worth a look."),
      table([
        { key: "ip", label: "IP", mono: true },
        { key: "devices", label: "Devices", mono: true },
        { key: "hits", label: "Requests", mono: true },
        { key: "country", label: "Country" },
        { key: "last_seen", label: "Last seen", render: (r) => when(r.last_seen) },
        { key: "action", label: "", render: (r) => el("span", {},
          el("button", { class: "btn danger", onclick: () => act(`ips/${encodeURIComponent(r.ip)}/block`, `Block ${r.ip}`) }, "Block"), " ",
          el("button", { class: "btn", onclick: () => act(`ips/${encodeURIComponent(r.ip)}/unblock`, `Unblock ${r.ip}`) }, "Unblock")) },
      ], await api("ips")));
    return 0;
  },

  async log(view) {
    return eventsView(view, "Live Tier-2 log", "events", () => true, 5000);
  },

  async rejected(view) {
    return eventsView(view, "Rejected requests", "events", (r) => r.status !== 200, 0);
  },

  async reports(view) {
    return dayView(view, "Reports sent from user dialogs", "reports", [
      { key: "ts", label: "Time", render: (r) => when(r.ts) },
      { key: "device", label: "Device", mono: true, render: (r) => el("a", { href: `#/device/${r.device}` }, short(r.device)) },
      { key: "name", label: "App" },
      { key: "path", label: "Path", mono: true },
      { key: "sha256", label: "SHA-256", mono: true, render: (r) => short(r.sha256, 16) },
      { key: "reasons", label: "What it did", render: (r) => (r.reasons ?? []).join("; ") },
    ]);
  },

  async licences(view) {
    view.append(el("h1", {}, "Licences"), table([
      { key: "licence_hash", label: "Licence (SHA-256)", mono: true, render: (r) => short(r.licence_hash, 16) },
      { key: "seats", label: "Seats", mono: true },
      { key: "used", label: "Used", mono: true, render: (r) => el("span", { class: r.used >= r.seats ? "warn" : "" }, r.used) },
    ], await api("licences")));
    return 0;
  },

  async audit(view) {
    return dayView(view, "Audit log", "audit", [
      { key: "ts", label: "Time", render: (r) => when(r.ts) },
      { key: "admin", label: "Admin" },
      { key: "action", label: "Action" },
      { key: "target", label: "Target", mono: true },
    ]);
  },
};

async function eventsView(view, title, path, keep, refresh) {
  let paused = false;
  const pause = el("button", { class: "btn", "aria-pressed": "false", onclick: () => {
    paused = !paused;
    pause.textContent = paused ? "Resume" : "Pause";
    pause.setAttribute("aria-pressed", String(paused));
  } }, "Pause");
  const slot = el("div");
  let day = "";
  const load = async () => slot.replaceChildren(table(eventCols, (await api(day ? `${path}?day=${day}` : path)).filter(keep)));
  view.append(el("h1", {}, title), el("div", { class: "bar" }, dayPicker((d) => { day = d; load(); }), refresh ? pause : null), slot);
  await load();
  if (refresh) timer = setInterval(() => { if (!paused && !document.hidden) load().catch(() => {}); }, refresh);
  return 0;
}

async function dayView(view, title, path, columns) {
  const slot = el("div");
  const load = async (day) => slot.replaceChildren(table(columns, await api(day ? `${path}?day=${day}` : path)));
  view.append(el("h1", {}, title), el("div", { class: "bar" }, dayPicker(load)), slot);
  await load();
  return 0;
}

// ───────────── router ─────────────
function showLogin() {
  clearInterval(timer);
  document.getElementById("logout").hidden = true;
  document.getElementById("who").textContent = "";
  document.getElementById("view").replaceChildren(el("h1", {}, "Sign in"),
    el("p", { class: "muted" }, "Use your passkey or authenticator app."),
    el("button", { class: "btn", onclick: () => login() }, "Sign in"));
}

// One render at a time: a hash change during an auto-refresh queues one more, never a duplicate.
let rendering = false, renderAgain = false;
async function render() {
  if (rendering) {
    renderAgain = true;
    return;
  }
  rendering = true;
  try {
    await draw();
  } finally {
    rendering = false;
    if (renderAgain) {
      renderAgain = false;
      render();
    }
  }
}

async function draw() {
  clearInterval(timer);
  if (!idToken) return showLogin();
  const [name, arg] = location.hash.replace(/^#\//, "").split("/");
  const viewName = VIEWS[name] ? name : "overview";
  document.querySelectorAll(".side a").forEach((a) => a.toggleAttribute("aria-current", a.getAttribute("href") === `#/${viewName}`));
  document.querySelectorAll(".side a[aria-current]").forEach((a) => a.setAttribute("aria-current", "page"));
  const view = document.getElementById("view");
  view.replaceChildren();
  try {
    const refresh = await VIEWS[viewName](view, arg && decodeURIComponent(arg));
    if (refresh) timer = setInterval(render, refresh);
  } catch (e) {
    if (idToken) view.append(el("p", { class: "bad" }, `Could not load: ${e.message}`));
  }
  view.focus();
}

for (const ev of ["mousemove", "keydown", "click"]) addEventListener(ev, () => { lastInput = Date.now(); });
setInterval(() => { if (idToken && Date.now() - lastInput > IDLE_MS) { idToken = null; showLogin(); } }, 30_000);

(async () => {
  document.getElementById("logout").addEventListener("click", logout);
  await finishLogin().catch(() => {});
  if (idToken) {
    document.getElementById("who").textContent = claims().email ?? "";
    document.getElementById("logout").hidden = false;
  }
  addEventListener("hashchange", render);
  render();
})();
