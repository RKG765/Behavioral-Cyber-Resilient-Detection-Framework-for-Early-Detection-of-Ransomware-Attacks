// Telltale SOC console (plan section 6). Plain JS, no build step.
// Login: Cloudflare Access (in front of this site) + Cognito here (PKCE, passkey or TOTP).
// Everything that comes from devices (names, paths, IPs) is shown with text nodes, never as HTML.
"use strict";

const CFG = window.TELLTALE;
const IDLE_MS = 15 * 60 * 1000; // plan 6.4: 15 min idle timeout
let idToken = null; // memory only, never localStorage
let timer = null; // the current view's auto-refresh
let lastInput = Date.now();
const $ = (id) => document.getElementById(id);

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
  if (res.status === 502 && body.edge_updated === false) throw new Error("saved, but the edge did not update. Try again.");
  if (!res.ok) throw new Error(body.error ?? `HTTP ${res.status}`);
  return body;
}

/** Confirm in the dialog, then POST. `a` = {title, body, target, ok, danger}. */
async function act(path, a) {
  if (!(await ask(a))) return;
  try {
    await api(path, "POST");
    toast(`${a.ok}: done.`);
    render();
  } catch (e) {
    if (e instanceof StepUp) {
      const again = await ask({ title: "Sign in again to continue", body: `${a.ok} needs a fresh passkey or authenticator check. You will come back to this page.`, ok: "Sign in again" });
      if (again) login(true);
    } else {
      toast(`${a.ok} failed: ${e.message}`);
    }
  }
}

// ───────────── DOM helpers ─────────────
function el(tag, props = {}, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (v == null || v === false) continue;
    if (k === "class") n.className = v;
    else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
    else n.setAttribute(k, v);
  }
  n.append(...kids.flat().filter((k) => k != null && k !== false).map((k) => (k instanceof Node ? k : String(k))));
  return n;
}

function ask({ title, body, target, ok, danger }) {
  const d = $("ask");
  $("ask-title").textContent = title;
  $("ask-body").textContent = body ?? "";
  $("ask-target").textContent = target ?? "";
  $("ask-ok").textContent = ok;
  $("ask-ok").className = danger ? "btn danger solid" : "btn primary";
  d.classList.toggle("danger", !!danger);
  d.returnValue = "";
  d.showModal();
  return new Promise((done) => d.addEventListener("close", () => done(d.returnValue === "ok"), { once: true }));
}

const toast = (msg) => {
  const t = $("toast");
  t.textContent = msg;
  setTimeout(() => { if (t.textContent === msg) t.textContent = ""; }, 6000);
};
const when = (ts) => (ts ? new Date(ts * 1000).toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit", hourCycle: "h23" }) : "—");
const short = (s, n = 12) => (s && s.length > n ? `${s.slice(0, n)}…` : s ?? "");
const plural = (n, one, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

// Triage levels: 0 revoked, 1 failed, 2 lower trust, 3 verified. Every tag carries its word.
// The band strip only ever means trust; model verdicts get their own marker (verdict()).
const TRUST = { revoked: [0, "Revoked"], failed: [1, "Failed"], software: [2, "Lower trust"], tpm: [3, "Verified"] };
const verdict = (v) => (v === "KILL" ? el("span", { class: "kill" }, "Kill") : v === "BENIGN" ? "Benign" : el("span", { class: "quiet" }, v ?? "—"));
function tag(v, lg = false) {
  const t = TRUST[v];
  if (!t) return el("span", { class: "quiet" }, v ?? "—");
  const [lvl, word] = t;
  return el("span", { class: `tag l${lvl}${lg ? " lg" : ""}` },
    el("span", { class: "bands", "aria-hidden": "true" }, [0, 1, 2, 3].map((i) => el("i", { class: `b${i}${i === lvl ? " on" : ""}` }))),
    word);
}
const trustOf = (d) => (d.status === "revoked" ? "revoked" : d.kind);
const keyName = (d) => (d.kind === "tpm" ? "TPM" : "Software");
const joined = (r) => (r.reasons ?? []).join("; ");

/**
 * Sortable, filterable table. columns: [{key, label, render?(row), value?(row), mono?, num?, wrap?}]
 * opts: {sort, desc, filter, empty, tools, rowClass?(row)}. Returns the element; `.update(rows)`
 * redraws in place so a refresh keeps the filter, the sort and the focus.
 */
function table(columns, rows, opts = {}) {
  let sortKey = opts.sort ?? null, asc = !opts.desc;
  const val = (c, r) => (c.value ? c.value(r) : r[c.key]);
  const filter = el("input", { type: "search", placeholder: "Any column", value: opts.filter ?? "" });
  const count = el("span", { class: "count" });
  const tbody = el("tbody");
  const heads = columns.map((c) => el("th", { scope: "col", class: c.num ? "num" : null },
    c.label ? el("button", { type: "button", onclick: () => { asc = sortKey === c.key ? !asc : true; sortKey = c.key; draw(); } }, c.label) : el("span", { class: "sr" }, "Actions")));
  const draw = () => {
    const f = filter.value.trim().toLowerCase();
    const col = columns.find((c) => c.key === sortKey);
    const shown = rows
      .filter((r) => !f || columns.some((c) => String(val(c, r) ?? "").toLowerCase().includes(f)))
      .sort((a, b) => {
        if (!col) return 0;
        const x = val(col, a) ?? "", y = val(col, b) ?? "";
        return (x > y ? 1 : x < y ? -1 : 0) * (asc ? 1 : -1);
      });
    heads.forEach((th, i) => (columns[i].key === sortKey ? th.setAttribute("aria-sort", asc ? "ascending" : "descending") : th.removeAttribute("aria-sort")));
    count.textContent = shown.length === rows.length ? plural(rows.length, "row") : `${shown.length} of ${plural(rows.length, "row")}`;
    tbody.replaceChildren(...(shown.length
      ? shown.map((r) => el("tr", { class: opts.rowClass?.(r) || null }, columns.map((c) => el("td", {
        class: [c.mono && "mono", c.num && "num", c.wrap && "wrap", c.key === "do" && "act"].filter(Boolean).join(" ") || null,
      }, c.render ? c.render(r) : r[c.key] ?? ""))))
      : [el("tr", {}, el("td", { class: "empty", colspan: columns.length }, f ? `Nothing matches “${filter.value.trim()}”.` : opts.empty ?? "Nothing here yet."))]));
  };
  filter.addEventListener("input", draw);
  draw();
  const wrap = el("div", {},
    el("div", { class: "tools" }, el("label", { class: "field" }, "Filter", filter), ...(opts.tools ?? []), count),
    el("div", { class: "tablewrap" }, el("table", {}, el("thead", {}, el("tr", {}, heads)), tbody)));
  wrap.update = (next) => { rows = next; draw(); };
  return wrap;
}

function dayPicker(onchange) {
  const today = new Date().toISOString().slice(0, 10);
  const input = el("input", { type: "date", value: today, max: today });
  input.addEventListener("change", () => onchange(input.value));
  return el("label", { class: "field" }, "Day (UTC)", input);
}

const header = (title, lede, ...extra) => el("div", { class: "head" }, el("div", {}, el("h1", {}, title), lede ? el("p", { class: "lede" }, lede) : null), ...extra);
const deviceLink = (id) => (id ? el("a", { class: "mono", href: `#/device/${encodeURIComponent(id)}` }, short(id)) : "—");

const eventCols = [
  { key: "ts", label: "Time", render: (r) => when(r.ts) },
  { key: "verified", label: "Trust", value: (r) => TRUST[r.verified]?.[1] ?? r.verified, render: (r) => tag(r.verified) },
  { key: "device", label: "Device", render: (r) => deviceLink(r.device) },
  { key: "ip", label: "IP", mono: true },
  { key: "country", label: "Country" },
  { key: "path", label: "Path", mono: true },
  { key: "verdict", label: "Verdict", render: (r) => verdict(r.verdict) },
  { key: "status", label: "HTTP", mono: true, num: true },
  { key: "reason", label: "Reason" },
  { key: "ms", label: "ms", mono: true, num: true, render: (r) => (r.ms ?? 0).toFixed(1) },
];

// ───────────── views ─────────────
const VIEWS = {
  async overview(view) {
    const [o, devices, events] = await Promise.all([api("overview"), api("devices"), api("events")]);
    const n = { revoked: 0, software: 0, tpm: 0 };
    for (const d of devices) n[trustOf(d)] = (n[trustOf(d)] ?? 0) + 1;
    const total = devices.length;
    const hourAgo = Date.now() / 1000 - 3600;
    const failed1h = events.filter((e) => e.ts > hourAgo && e.verified === "failed").length;

    const band = (key, lvl, word, link) => {
      const pct = total ? Math.round((n[key] / total) * 100) : 0;
      const bar = el("b");
      bar.style.setProperty("--share", `${pct}%`); // CSSOM, allowed by the style-src 'self' CSP
      return el("div", { class: `band b${lvl}${n[key] ? "" : " zero"}` },
        el("span", { class: "band-name" }, word),
        el("span", { class: "band-count" }, n[key]),
        el("span", { class: "share" }, el("span", { class: "share-bar", "aria-hidden": "true" }, bar), el("span", {}, `${pct}% of fleet`)),
        n[key] ? el("a", { href: `#/devices/${link}` }, `Show ${plural(n[key], "device")}`) : el("span", { class: "quiet" }, "None"));
    };
    const fig = (label, value, extra) => el("div", {}, el("dt", {}, label), el("dd", {}, value, extra));

    view.append(
      header("Overview", "Every registered device, sorted by how much Tier 2 trusts it."),
      el("section", { "aria-labelledby": "h-fleet" },
        el("h2", { id: "h-fleet" }, "Fleet by trust"),
        el("div", { class: "board" },
          band("revoked", 0, "Revoked", "revoked"),
          band("software", 2, "Lower trust", "lower"),
          band("tpm", 3, "Verified", "verified"),
          el("p", { class: "board-foot" },
            el("span", {}, el("b", {}, total), " registered"),
            el("span", {}, el("b", {}, o.online_24h), " seen in the last 24 h"),
            el("span", {}, "Lower trust: software key, no TPM")))),
      el("section", { "aria-labelledby": "h-hour" },
        el("h2", { id: "h-hour" }, "Tier 2, last hour"),
        el("dl", { class: "hour" },
          fig("Requests", o.requests_1h),
          fig("Rejected", o.rejected_1h),
          fig("Failed verification", failed1h, failed1h ? tag("failed") : null),
          fig("Kill verdicts", o.kills_1h, o.kills_1h ? verdict("KILL") : null),
          fig("Latency p50 / p99", `${o.p50_ms.toFixed(1)} / ${o.p99_ms.toFixed(1)}`, el("span", { class: "quiet" }, "ms")))),
      el("section", { "aria-labelledby": "h-latest" },
        el("h2", { id: "h-latest" }, "Latest requests"),
        table(eventCols, [...events].sort((a, b) => b.ts - a.ts).slice(0, 20), { sort: "ts", desc: true, empty: "No Tier-2 requests today." })));
    return 60_000;
  },

  async devices(view, arg) {
    const rows = await api("devices");
    const filter = { revoked: "Revoked", lower: "Lower trust", verified: "Verified" }[arg] ?? "";
    view.append(header("Devices", "Revoking a device stops its Tier-2 access at the edge."), table([
      { key: "device_id", label: "Device", render: (r) => deviceLink(r.device_id) },
      { key: "trust", label: "Trust", value: (r) => TRUST[trustOf(r)]?.[1], render: (r) => tag(trustOf(r)) },
      { key: "kind", label: "Key", value: keyName, render: keyName },
      { key: "last_ip", label: "Current IP", mono: true },
      { key: "last_seen", label: "Last seen", render: (r) => when(r.last_seen) },
      { key: "first_ip", label: "First IP", mono: true },
      { key: "created_at", label: "Registered", render: (r) => when(r.created_at) },
      { key: "do", label: "", render: (r) => (r.status === "revoked" ? restoreBtn(r.device_id) : revokeBtn(r.device_id)) },
    ], rows, { sort: "last_seen", desc: true, filter, empty: "No devices have registered yet.", rowClass: (r) => (r.status === "revoked" ? "gone" : "") }));
    return 0;
  },

  async device(view, id) {
    const { device: d, ips } = await api(`devices/${encodeURIComponent(id)}`);
    const fact = (label, value) => el("div", {}, el("dt", {}, label), el("dd", {}, value));
    view.append(
      el("a", { class: "crumb", href: "#/devices" }, "Devices"),
      header(el("span", {}, "Device ", el("span", { class: "mono" }, d.device_id)), null,
        d.status === "revoked" ? restoreBtn(d.device_id) : revokeBtn(d.device_id)),
      el("dl", { class: "facts" },
        el("div", { class: "trust" }, el("div", {}, el("dt", {}, "Trust"), el("dd", {}, tag(trustOf(d), true))),
          el("span", { class: "quiet" }, d.status === "revoked" ? "Tier 2 refuses this device." : d.kind === "tpm" ? "Key held in the TPM." : "Software key: this PC has no usable TPM.")),
        fact("Key", keyName(d)),
        fact("Current IP", el("span", { class: "mono" }, d.last_ip || "—")),
        fact("Last seen", when(d.last_seen)),
        fact("Registered", when(d.created_at)),
        fact("First IP", el("span", { class: "mono" }, d.first_ip || "—"))),
      el("h2", {}, "IP history"),
      table([
        { key: "sk", label: "IP", mono: true, value: (r) => r.sk.replace(/^ip#/, ""), render: (r) => r.sk.replace(/^ip#/, "") },
        { key: "country", label: "Country" },
        { key: "hits", label: "Requests", mono: true, num: true },
        { key: "first_seen", label: "First seen", render: (r) => when(r.first_seen) },
        { key: "last_seen", label: "Last seen", render: (r) => when(r.last_seen) },
      ], ips, { sort: "last_seen", desc: true, empty: "This device has not called Tier 2 yet." }));
    return 0;
  },

  async ips(view) {
    view.append(header("IPs", "Many devices behind one IP, or one IP with many failures, are worth a look. Blocking applies at the Cloudflare edge."),
      table([
        { key: "ip", label: "IP", mono: true },
        { key: "devices", label: "Devices", mono: true, num: true },
        { key: "hits", label: "Requests", mono: true, num: true },
        { key: "country", label: "Country" },
        { key: "last_seen", label: "Last seen", render: (r) => when(r.last_seen) },
        { key: "do", label: "", render: (r) => [
          el("button", { class: "btn", type: "button", onclick: () => act(`ips/${encodeURIComponent(r.ip)}/unblock`, { title: "Unblock this IP?", body: "Requests from it reach Tier 2 again.", target: r.ip, ok: "Unblock IP" }) }, "Unblock"),
          el("button", { class: "btn danger", type: "button", onclick: () => act(`ips/${encodeURIComponent(r.ip)}/block`, { title: "Block this IP?", body: `Every device behind it (${plural(r.devices, "device")} so far) loses Tier 2 until you unblock it.`, target: r.ip, ok: "Block IP", danger: true }) }, "Block"),
        ] },
      ], await api("ips"), { sort: "hits", desc: true, empty: "No IPs have called Tier 2 yet." }));
    return 0;
  },

  log: (view) => eventsView(view, "Live log", "Every Tier-2 request, newest first. Refreshes every 5 seconds; new rows stay marked until you mark them seen.", () => true, 5000),
  rejected: (view) => eventsView(view, "Rejected", "Requests Tier 2 turned away, and why.", (r) => r.status !== 200, 0),

  reports: (view) => dayView(view, "Reports", "What people sent from the agent's dialog when Telltale stopped an app.", "reports", [
    { key: "ts", label: "Time", render: (r) => when(r.ts) },
    { key: "device", label: "Device", render: (r) => deviceLink(r.device) },
    { key: "name", label: "App" },
    { key: "reason", label: "Their reason" },
    { key: "path", label: "Path", mono: true, wrap: true },
    { key: "sha256", label: "SHA-256", mono: true, render: (r) => el("span", { title: r.sha256 ?? "" }, short(r.sha256, 16)) },
    { key: "reasons", label: "What it did", wrap: true, value: joined, render: joined },
  ], "No reports on this day."),

  async licences(view) {
    view.append(header("Licences", "Read only. Licence keys are stored as hashes."), table([
      { key: "licence_hash", label: "Licence (SHA-256)", mono: true, render: (r) => el("span", { title: r.licence_hash }, short(r.licence_hash, 16)) },
      { key: "seats", label: "Seats", mono: true, num: true },
      { key: "used", label: "Used", mono: true, num: true },
      { key: "left", label: "Left", num: true, value: (r) => r.seats - r.used, render: (r) => (r.used >= r.seats ? el("span", { class: "chip" }, "Full") : r.seats - r.used) },
    ], await api("licences"), { sort: "left", empty: "No licences issued yet." }));
    return 0;
  },

  audit: (view) => dayView(view, "Audit", "Every admin action, who took it and on what.", "audit", [
    { key: "ts", label: "Time", render: (r) => when(r.ts) },
    { key: "admin", label: "Admin" },
    { key: "action", label: "Action" },
    { key: "target", label: "Target", mono: true },
  ], "No admin actions on this day."),
};

function revokeBtn(id) {
  return el("button", { class: "btn danger", type: "button", onclick: () => act(`devices/${encodeURIComponent(id)}/revoke`, {
    title: "Revoke this device?", body: "Tier 2 refuses it at the edge from now on. The PC keeps its local protection. You can restore it later.", target: id, ok: "Revoke device", danger: true,
  }) }, "Revoke");
}
function restoreBtn(id) {
  return el("button", { class: "btn", type: "button", onclick: () => act(`devices/${encodeURIComponent(id)}/restore`, {
    title: "Restore this device?", body: "It can call Tier 2 again with its existing key.", target: id, ok: "Restore device",
  }) }, "Restore");
}

async function eventsView(view, title, lede, keep, refresh) {
  const key = (r) => `${r.ts}|${r.device}|${r.ip}|${r.path}|${r.status}`;
  let day = "", paused = false, seen = null, t = null, rows = [];
  const isFresh = (r) => !!seen && !seen.has(key(r));
  const cols = refresh
    ? [{ ...eventCols[0], render: (r) => (isFresh(r) ? [el("span", { class: "chip" }, "New"), " ", when(r.ts)] : when(r.ts)) }, ...eventCols.slice(1)]
    : eventCols;
  const pause = el("button", { class: "btn", type: "button", "aria-pressed": "false", onclick: () => {
    paused = !paused;
    pause.textContent = paused ? "Paused" : "Pause";
    pause.setAttribute("aria-pressed", String(paused));
  } }, "Pause");
  const markSeen = el("button", { class: "btn", type: "button", disabled: "", onclick: () => {
    rows.forEach((r) => seen.add(key(r)));
    t.update(rows);
    markSeen.disabled = true;
    markSeen.textContent = "Mark seen";
  } }, "Mark seen");
  const load = async () => {
    rows = (await api(day ? `events?day=${day}` : "events")).filter(keep);
    if (refresh) {
      seen ??= new Set(rows.map(key)); // first load: nothing is new yet
      const fresh = rows.filter(isFresh).length;
      markSeen.disabled = !fresh;
      markSeen.textContent = fresh ? `Mark ${fresh} seen` : "Mark seen";
    }
    if (!t) view.append(t = table(cols, rows, {
      sort: "ts", desc: true, empty: refresh ? "No Tier-2 requests on this day." : "Nothing rejected on this day.",
      rowClass: (r) => (isFresh(r) ? "fresh" : ""),
      tools: [dayPicker((d) => { day = d; seen = null; load().catch((e) => toast(`Could not load: ${e.message}`)); }), refresh ? pause : null, refresh ? markSeen : null],
    }));
    else t.update(rows);
  };
  view.append(header(title, lede));
  await load();
  if (refresh) timer = setInterval(() => { if (!paused && !document.hidden) load().catch(() => {}); }, refresh);
  return 0;
}

async function dayView(view, title, lede, path, columns, empty) {
  let t = null;
  const load = async (day) => {
    const rows = await api(day ? `${path}?day=${day}` : path);
    if (!t) view.append(t = table(columns, rows, { sort: "ts", desc: true, empty, tools: [dayPicker((d) => load(d).catch((e) => toast(`Could not load: ${e.message}`)))] }));
    else t.update(rows);
  };
  view.append(header(title, lede));
  await load();
  return 0;
}

// ───────────── router ─────────────
function showLogin() {
  clearInterval(timer);
  lastRoute = null;
  $("logout").hidden = true;
  $("who").textContent = "";
  $("view").replaceChildren(el("div", { class: "signin" },
    el("h1", {}, "Sign in"),
    el("p", {}, "Use your passkey or authenticator app. You are signed out after 15 minutes without activity."),
    el("button", { class: "btn primary", type: "button", onclick: () => login() }, "Sign in")));
}

const skeleton = () => el("div", { class: "skel", "aria-busy": "true", "aria-label": "Loading" }, Array.from({ length: 7 }, () => el("i")));

// One render at a time: a hash change during an auto-refresh queues one more, never a duplicate.
let rendering = false, renderAgain = false, lastRoute = null;
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
  const navName = viewName === "device" ? "devices" : viewName;
  const navLink = document.querySelector(`nav a[href="#/${navName}"]`);
  document.querySelectorAll("nav a").forEach((a) => (a === navLink ? a.setAttribute("aria-current", "page") : a.removeAttribute("aria-current")));
  document.title = `${viewName === "device" ? "Device" : navLink.textContent} · Telltale SOC`;
  const view = $("view");
  const moved = location.hash !== lastRoute; // a refresh redraws quietly; a new page shows a skeleton
  lastRoute = location.hash;
  if (moved) view.replaceChildren(skeleton());
  const page = el("div");
  try {
    const refresh = await VIEWS[viewName](page, arg && decodeURIComponent(arg));
    if (refresh) timer = setInterval(render, refresh);
  } catch (e) {
    if (!idToken) return;
    page.replaceChildren(el("div", { class: "problem", role: "alert" }, `Could not load this page: ${e.message}`,
      el("button", { class: "btn", type: "button", onclick: render }, "Try again")));
  }
  view.replaceChildren(page);
  if (moved) { scrollTo(0, 0); view.focus({ preventScroll: true }); }
}

for (const ev of ["mousemove", "keydown", "click"]) addEventListener(ev, () => { lastInput = Date.now(); });
setInterval(() => { if (idToken && Date.now() - lastInput > IDLE_MS) { idToken = null; showLogin(); } }, 30_000);

(async () => {
  const rail = document.querySelector(".rail");
  const menu = $("menu");
  const setMenu = (open) => { rail.classList.toggle("open", open); menu.setAttribute("aria-expanded", String(open)); };
  menu.addEventListener("click", () => setMenu(!rail.classList.contains("open")));
  $("logout").addEventListener("click", logout);
  // Local preview only: `?demo` on localhost answers /admin/* with sample data (console/dev-stub.js).
  if (["127.0.0.1", "localhost"].includes(location.hostname) && new URLSearchParams(location.search).has("demo")) {
    idToken = (await import("/dev-stub.js")).token;
  }
  await finishLogin().catch(() => {});
  if (idToken) {
    $("who").textContent = claims().email ?? "";
    $("logout").hidden = false;
  }
  addEventListener("hashchange", () => { setMenu(false); render(); });
  render();
})();
