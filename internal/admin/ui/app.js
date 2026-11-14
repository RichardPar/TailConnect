"use strict";

const $ = (id) => document.getElementById(id);

// el("td", {class: "x"}, "text", childNode, ...) – builds DOM safely (no innerHTML).
function el(tag, attrs, ...children) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
    else if (k === "class") n.className = v;
    else n.setAttribute(k, v);
  }
  for (const c of children.flat()) {
    if (c == null || c === false) continue;
    n.append(c instanceof Node ? c : String(c));
  }
  return n;
}

class AuthError extends Error {}

async function api(method, path, body) {
  const opts = { method, headers: {}, credentials: "same-origin" };
  if (body !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  const r = await fetch(path, opts);
  if (r.status === 401 && path !== "/api/login") throw new AuthError("not logged in");
  if (r.status === 204) return null;
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || `HTTP ${r.status}`);
  return data;
}

let toastTimer;
function toast(msg, isErr) {
  const t = $("toast");
  t.textContent = msg;
  t.className = "toast" + (isErr ? " err" : "");
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (t.hidden = true), 3500);
}

function ago(iso) {
  if (!iso) return "never";
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}
const fmtDate = (iso) => new Date(iso).toLocaleString();

// ---- views ----

function showLogin(msg) {
  $("app").hidden = true;
  $("login").hidden = false;
  $("login-error").textContent = msg || "";
  $("token").focus();
}

function showApp() {
  $("login").hidden = true;
  $("app").hidden = false;
}

let currentTab = "nodes";
function selectTab(name) {
  currentTab = name;
  document.querySelectorAll(".tabs button").forEach((b) => b.classList.toggle("active", b.dataset.tab === name));
  document.querySelectorAll("[data-panel]").forEach((p) => (p.hidden = p.dataset.panel !== name));
  refresh();
}

function stat(value, label, small) {
  return el("div", { class: "stat" }, el("div", { class: "v" + (small ? " small" : "") }, value), el("div", { class: "l" }, label));
}

async function loadStatus() {
  const s = await api("GET", "/api/v1/status");
  $("stats").replaceChildren(
    stat(`${s.online} / ${s.nodes}`, "machines online"),
    stat(s.users, "users"),
    stat(s.baseDomain, "MagicDNS domain", true),
    stat(s.version || "dev", "server version", true),
  );
}

async function loadNodes() {
  const nodes = await api("GET", "/api/v1/nodes");
  $("nodes-empty").hidden = nodes.length > 0;
  $("nodes-body").replaceChildren(
    ...nodes.map((n) =>
      el("tr", {},
        el("td", {}, el("span", { class: "dot" + (n.online ? " on" : ""), title: n.online ? "online" : "offline" })),
        el("td", {}, el("div", {}, n.name), el("div", { class: "sub" }, n.fqdn), n.ephemeral && el("span", { class: "badge" }, "ephemeral")),
        el("td", {}, n.user),
        el("td", { class: "mono" }, el("div", {}, n.ipv4), el("div", { class: "sub" }, n.ipv6)),
        el("td", {}, n.os || "–", el("div", { class: "sub" }, n.hostname)),
        el("td", { title: n.lastSeen ? fmtDate(n.lastSeen) : "" }, ago(n.lastSeen)),
        el("td", { class: "actions" },
          el("button", { class: "ghost", onclick: () => renameNode(n) }, "Rename"),
          el("button", { class: "danger", onclick: () => deleteNode(n) }, "Remove"),
        ),
      ),
    ),
  );
  $("nodes-updated").textContent = "updated " + new Date().toLocaleTimeString();
}

async function renameNode(n) {
  const name = prompt(`New MagicDNS name for ${n.name}:`, n.name);
  if (!name || name === n.name) return;
  try {
    await api("POST", `/api/v1/nodes/${n.id}/rename`, { name: name.trim() });
    toast(`Renamed to ${name}`);
    refresh();
  } catch (e) { handleErr(e); }
}

async function deleteNode(n) {
  if (!confirm(`Remove ${n.name} (${n.ipv4}) from the network? It will need a new auth key to rejoin.`)) return;
  try {
    await api("DELETE", `/api/v1/nodes/${n.id}`);
    toast(`Removed ${n.name}`);
    refresh();
  } catch (e) { handleErr(e); }
}

async function loadUsers() {
  const users = await api("GET", "/api/v1/users");
  $("users-body").replaceChildren(
    ...users.map((u) =>
      el("tr", {},
        el("td", {}, u.name),
        el("td", {}, u.nodes),
        el("td", {}, fmtDate(u.created)),
        el("td", { class: "actions" }, el("button", { class: "danger", onclick: () => deleteUser(u) }, "Delete")),
      ),
    ),
  );
  const sel = $("key-user");
  const prev = sel.value;
  sel.replaceChildren(...users.map((u) => el("option", { value: u.name }, u.name)));
  if (users.some((u) => u.name === prev)) sel.value = prev;
  return users;
}

async function deleteUser(u) {
  const extra = u.nodes ? ` This also removes their ${u.nodes} machine(s) and all of their auth keys.` : "";
  if (!confirm(`Delete user ${u.name}?${extra}`)) return;
  try {
    await api("DELETE", `/api/v1/users/${encodeURIComponent(u.name)}`);
    toast(`Deleted ${u.name}`);
    refresh();
  } catch (e) { handleErr(e); }
}

async function loadKeys() {
  await loadUsers(); // populate user selector
  const keys = await api("GET", "/api/v1/keys");
  $("keys-body").replaceChildren(
    ...keys.reverse().map((k) => {
      const status = k.revoked ? ["revoked", "bad"] : !k.usable ? [new Date(k.expires) <= new Date() ? "expired" : "used", ""] : ["active", "ok"];
      return el("tr", {},
        el("td", {}, k.id),
        el("td", { class: "mono" }, k.prefix + "…"),
        el("td", {}, k.user),
        el("td", {}, k.reusable ? "reusable" : "one-off", k.ephemeral && el("div", { class: "sub" }, "ephemeral")),
        el("td", {}, k.uses),
        el("td", { title: fmtDate(k.expires) }, fmtDate(k.expires)),
        el("td", {}, el("span", { class: "badge " + status[1] }, status[0])),
        el("td", { class: "actions" }, !k.revoked && k.usable && el("button", { class: "danger", onclick: () => revokeKey(k) }, "Revoke")),
      );
    }),
  );
}

async function revokeKey(k) {
  if (!confirm(`Revoke auth key ${k.prefix}…? Machines already registered with it are not affected.`)) return;
  try {
    await api("DELETE", `/api/v1/keys/${k.id}`);
    toast("Key revoked");
    refresh();
  } catch (e) { handleErr(e); }
}

async function refresh() {
  try {
    await loadStatus();
    if (currentTab === "nodes") await loadNodes();
    else if (currentTab === "users") await loadUsers();
    else await loadKeys();
  } catch (e) { handleErr(e); }
}

function handleErr(e) {
  if (e instanceof AuthError) showLogin("Session expired. Sign in again.");
  else toast(e.message, true);
}

// ---- wiring ----

$("login-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  $("login-error").textContent = "";
  try {
    await api("POST", "/api/login", { Token: $("token").value });
    $("token").value = "";
    showApp();
    refresh();
  } catch (e) {
    $("login-error").textContent = e.message;
  }
});

$("logout").addEventListener("click", async () => {
  await api("POST", "/api/logout", {}).catch(() => {});
  showLogin();
});

document.querySelectorAll(".tabs button").forEach((b) => b.addEventListener("click", () => selectTab(b.dataset.tab)));

$("user-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  try {
    const u = await api("POST", "/api/v1/users", { name: $("user-name").value.trim() });
    $("user-name").value = "";
    toast(`Created ${u.name}`);
    refresh();
  } catch (e) { handleErr(e); }
});

$("key-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  if (!$("key-user").value) return toast("Create a user first", true);
  try {
    const r = await api("POST", "/api/v1/keys", {
      user: $("key-user").value,
      ttl: $("key-ttl").value,
      reusable: $("key-reusable").checked,
      ephemeral: $("key-ephemeral").checked,
    });
    $("new-key-value").textContent = r.key;
    $("new-key").hidden = false;
    refresh();
  } catch (e) { handleErr(e); }
});

$("copy-key").addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText($("new-key-value").textContent);
    toast("Copied");
  } catch {
    toast("Copy failed. Select the key and copy it manually.", true);
  }
});

// Initial load: probe the session, then poll while the tab is visible.
(async () => {
  try {
    await api("GET", "/api/v1/status");
    showApp();
    refresh();
  } catch (e) {
    if (e instanceof AuthError) showLogin();
    else showLogin(e.message);
  }
  setInterval(() => {
    if (!$("app").hidden && document.visibilityState === "visible" && currentTab === "nodes") refresh();
  }, 10000);
})();
