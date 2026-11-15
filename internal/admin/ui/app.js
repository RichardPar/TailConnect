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
  if (r.status === 401 && !path.startsWith("/api/login")) throw new AuthError("not logged in");
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

// ---- state ----

let config = { signup: "off" }; // public server settings
let me = null; // {login, operator, token, role, status}

// ---- sign-in, sign-up ----

const loginViews = ["login-form", "token-form", "signup-form", "signup-done"];
function showLoginView(id) {
  for (const v of loginViews) $(v).hidden = v !== id;
  const focus = { "login-form": "login-name", "token-form": "token", "signup-form": "signup-name" }[id];
  if (focus) $(focus).focus();
}

function showLogin(msg) {
  $("toast").hidden = true; // don't carry messages over to the next session
  $("new-key").hidden = $("new-invite").hidden = true;
  $("app").hidden = true;
  $("login").hidden = false;
  $("show-signup").hidden = config.signup === "off";
  showLoginView("login-form");
  $("login-error").textContent = msg || "";
}

function showSignup() {
  const hints = {
    approval: "The operator approves new accounts. Have an invite code? Enter it to start straight away.",
    invite: "You need an invite code from the server's operator.",
    open: "Your account is ready as soon as you create it.",
  };
  $("signup-hint").textContent = hints[config.signup] || "";
  $("signup-invite-row").hidden = config.signup === "open";
  $("signup-invite").required = config.signup === "invite";
  $("signup-invite").placeholder = config.signup === "invite" ? "tc-invite-…" : "tc-invite-… (optional)";
  $("signup-error").textContent = "";
  showLoginView("signup-form");
}

async function signIn(body, errEl) {
  $(errEl).textContent = "";
  try {
    await api("POST", "/api/login", body);
    await enterApp();
  } catch (e) {
    $(errEl).textContent = e.message;
  }
}

$("login-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  await signIn({ login: $("login-name").value.trim(), password: $("login-password").value }, "login-error");
  $("login-password").value = "";
});

$("token-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  await signIn({ token: $("token").value.trim() }, "token-error");
  $("token").value = "";
});

$("show-token").addEventListener("click", (ev) => { ev.preventDefault(); showLoginView("token-form"); });
$("show-signup").addEventListener("click", (ev) => { ev.preventDefault(); showSignup(); });
document.querySelectorAll(".back-to-login").forEach((a) =>
  a.addEventListener("click", (ev) => { ev.preventDefault(); showLoginView("login-form"); }));

$("signup-name").addEventListener("input", () => {
  $("signup-preview").textContent = $("signup-name").value.trim().toLowerCase() || "name";
});

$("signup-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  $("signup-error").textContent = "";
  const login = $("signup-name").value.trim().toLowerCase();
  const password = $("signup-password").value;
  if (password !== $("signup-password2").value) {
    $("signup-error").textContent = "The passwords don't match.";
    return;
  }
  try {
    const r = await api("POST", "/api/signup", { login, password, invite: $("signup-invite").value.trim() });
    $("signup-password").value = $("signup-password2").value = "";
    if (r.status === "active") {
      await signIn({ login, password }, "signup-error");
      return;
    }
    $("signup-done-msg").textContent = `Your account "${r.login}" is waiting for the operator's approval. You can sign in once it's approved.`;
    showLoginView("signup-done");
  } catch (e) {
    $("signup-error").textContent = e.message;
  }
});

$("logout").addEventListener("click", async () => {
  await api("POST", "/api/logout", {}).catch(() => {});
  me = null;
  showLogin();
});

// ---- app shell ----

async function enterApp() {
  me = await api("GET", "/api/v1/me");
  $("login").hidden = true;
  $("app").hidden = false;
  $("who-name").textContent = me.login;
  $("who-role").textContent = me.operator ? "operator" : "tenant";
  document.querySelectorAll(".op-only").forEach((e) => (e.hidden = !me.operator));
  $("password-form").hidden = me.token;
  $("token-account").hidden = !me.token;
  $("account-info").textContent = me.token
    ? "Signed in with the admin token."
    : `Signed in as ${me.login} (${me.operator ? "operator" : "tenant"}).`;
  selectTab("nodes");
}

let currentTab = "nodes";
function selectTab(name) {
  currentTab = name;
  document.querySelectorAll(".tabs button").forEach((b) => b.classList.toggle("active", b.dataset.tab === name));
  document.querySelectorAll("[data-panel]").forEach((p) => (p.hidden = p.dataset.panel !== name));
  refresh();
}
document.querySelectorAll(".tabs button").forEach((b) => b.addEventListener("click", () => selectTab(b.dataset.tab)));

function stat(value, label, small) {
  return el("div", { class: "stat" }, el("div", { class: "v" + (small ? " small" : "") }, value), el("div", { class: "l" }, label));
}

async function loadStatus() {
  const s = await api("GET", "/api/v1/status");
  const stats = [stat(`${s.online} / ${s.nodes}`, "machines online")];
  if (me.operator) {
    stats.push(stat(s.users, "accounts"));
    if (s.pending) stats.push(stat(s.pending, "waiting for approval"));
  }
  stats.push(stat(s.baseDomain, "MagicDNS domain", true), stat(s.version || "dev", "server version", true));
  $("stats").replaceChildren(...stats);
  document.querySelectorAll(".control-url").forEach((e) => (e.textContent = s.controlURL || "URL"));
  const badge = $("pending-badge");
  badge.hidden = !s.pending;
  badge.textContent = s.pending || "";
  const modes = { off: "sign-up off", approval: "sign-up needs approval", invite: "sign-up by invite", open: "open sign-up" };
  $("signup-mode").textContent = modes[s.signup] || "";
}

// ---- machines ----

async function loadNodes() {
  const nodes = await api("GET", "/api/v1/nodes");
  $("nodes-empty").hidden = nodes.length > 0;
  $("nodes-body").replaceChildren(
    ...nodes.map((n) =>
      el("tr", {},
        el("td", {}, el("span", { class: "dot" + (n.online ? " on" : ""), title: n.online ? "online" : "offline" })),
        el("td", {}, el("div", {}, n.name), el("div", { class: "sub" }, n.fqdn), n.ephemeral && el("span", { class: "badge" }, "ephemeral")),
        me.operator && el("td", {}, n.user),
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

// ---- auth keys ----

async function loadKeys() {
  if (me.operator) {
    const users = await api("GET", "/api/v1/users");
    const sel = $("key-user");
    const prev = sel.value || (me.token ? "" : me.login);
    sel.replaceChildren(...users.filter((u) => u.status === "active").map((u) => el("option", { value: u.name }, u.name)));
    if (users.some((u) => u.name === prev)) sel.value = prev;
  }
  const keys = await api("GET", "/api/v1/keys");
  $("keys-body").replaceChildren(
    ...keys.reverse().map((k) => {
      const status = k.revoked ? ["revoked", "bad"] : !k.usable ? [new Date(k.expires) <= new Date() ? "expired" : "used", ""] : ["active", "ok"];
      return el("tr", {},
        el("td", {}, k.id),
        el("td", { class: "mono" }, k.prefix + "…"),
        me.operator && el("td", {}, k.user),
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

$("key-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const body = { ttl: $("key-ttl").value, reusable: $("key-reusable").checked, ephemeral: $("key-ephemeral").checked };
  if (me.operator) {
    if (!$("key-user").value) return toast("Create an account first", true);
    body.user = $("key-user").value;
  }
  try {
    const r = await api("POST", "/api/v1/keys", body);
    $("new-key-value").textContent = r.key;
    $("new-key").hidden = false;
    refresh();
  } catch (e) { handleErr(e); }
});

// ---- accounts (operator) ----

const statusBadge = { active: "ok", pending: "warn", suspended: "bad" };

async function loadUsers() {
  const users = await api("GET", "/api/v1/users");
  // Pending accounts first: they need attention.
  users.sort((a, b) => (b.status === "pending") - (a.status === "pending"));
  $("users-body").replaceChildren(
    ...users.map((u) => {
      const self = !me.token && u.name === me.login;
      const btn = (label, cls, fn) => el("button", { class: cls, onclick: fn }, label);
      const actions = [];
      if (!self) {
        if (u.status === "pending") actions.push(btn("Approve", "primary small", () => setStatus(u, "active")));
        if (u.status === "suspended") actions.push(btn("Reactivate", "ghost", () => setStatus(u, "active")));
        if (u.status === "active") actions.push(btn("Suspend", "ghost", () => setStatus(u, "suspended")));
        actions.push(btn(u.role === "operator" ? "Make tenant" : "Make operator", "ghost", () => setRole(u, u.role === "operator" ? "tenant" : "operator")));
      }
      actions.push(btn(u.hasPassword ? "Reset password" : "Set password", "ghost", () => setPassword(u)));
      if (!self) actions.push(btn("Delete", "danger", () => deleteUser(u)));
      return el("tr", {},
        el("td", {}, u.name, self && el("span", { class: "sub" }, " (you)"), !u.hasPassword && el("div", { class: "sub" }, "no password: can't sign in")),
        el("td", {}, u.role),
        el("td", {}, el("span", { class: "badge " + (statusBadge[u.status] || "") }, u.status)),
        el("td", {}, u.nodes),
        el("td", {}, fmtDate(u.created)),
        el("td", { class: "actions" }, actions),
      );
    }),
  );
}

async function setStatus(u, status) {
  if (status === "suspended" && !confirm(`Suspend ${u.name}? Their ${u.nodes} machine(s) are cut off from the network and they are signed out.`)) return;
  try {
    await api("POST", `/api/v1/users/${encodeURIComponent(u.name)}/status`, { status });
    toast(status === "active" ? (u.status === "pending" ? `Approved ${u.name}` : `Reactivated ${u.name}`) : `Suspended ${u.name}`);
    refresh();
  } catch (e) { handleErr(e); }
}

async function setRole(u, role) {
  if (!confirm(`Make ${u.name} ${role === "operator" ? "an operator (full control of this server)" : "a tenant"}?`)) return;
  try {
    await api("POST", `/api/v1/users/${encodeURIComponent(u.name)}/role`, { role });
    toast(`${u.name} is now ${role === "operator" ? "an operator" : "a tenant"}`);
    refresh();
  } catch (e) { handleErr(e); }
}

async function setPassword(u) {
  const pw = prompt(`New password for ${u.name} (at least 10 characters). They are signed out everywhere.`);
  if (!pw) return;
  try {
    await api("POST", `/api/v1/users/${encodeURIComponent(u.name)}/password`, { password: pw });
    toast(`Password set for ${u.name}`);
    refresh();
  } catch (e) { handleErr(e); }
}

async function deleteUser(u) {
  const extra = u.nodes ? ` This also removes their ${u.nodes} machine(s) and all of their auth keys.` : "";
  if (!confirm(`Delete account ${u.name}?${extra}`)) return;
  try {
    await api("DELETE", `/api/v1/users/${encodeURIComponent(u.name)}`);
    toast(`Deleted ${u.name}`);
    refresh();
  } catch (e) { handleErr(e); }
}

$("user-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  try {
    const u = await api("POST", "/api/v1/users", {
      name: $("user-name").value.trim(),
      password: $("user-password").value,
      role: $("user-operator").checked ? "operator" : "tenant",
    });
    $("user-name").value = $("user-password").value = "";
    $("user-operator").checked = false;
    toast(`Created ${u.name}`);
    refresh();
  } catch (e) { handleErr(e); }
});

async function loadInvites() {
  const list = await api("GET", "/api/v1/invites");
  $("invites-body").replaceChildren(
    ...list.reverse().map((i) => {
      const status = i.revoked ? ["revoked", "bad"] : i.usedBy || i.usedAt ? [`used by ${i.usedBy || "a deleted account"}`, ""] : !i.usable ? ["expired", ""] : ["unused", "ok"];
      return el("tr", {},
        el("td", {}, i.id),
        el("td", { class: "mono" }, i.prefix + "…"),
        el("td", {}, fmtDate(i.expires)),
        el("td", {}, el("span", { class: "badge " + status[1] }, status[0])),
        el("td", { class: "actions" }, i.usable && el("button", { class: "danger", onclick: () => revokeInvite(i) }, "Revoke")),
      );
    }),
  );
}

async function revokeInvite(i) {
  if (!confirm(`Revoke invite ${i.prefix}…?`)) return;
  try {
    await api("DELETE", `/api/v1/invites/${i.id}`);
    toast("Invite revoked");
    refresh();
  } catch (e) { handleErr(e); }
}

$("invite-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  try {
    const r = await api("POST", "/api/v1/invites", { ttl: $("invite-ttl").value });
    $("new-invite-value").textContent = r.code;
    $("new-invite").hidden = false;
    refresh();
  } catch (e) { handleErr(e); }
});

// ---- my account ----

$("password-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  if ($("pw-new").value !== $("pw-new2").value) return toast("The new passwords don't match", true);
  try {
    await api("POST", "/api/v1/me/password", { current: $("pw-current").value, new: $("pw-new").value });
    ["pw-current", "pw-new", "pw-new2"].forEach((id) => ($(id).value = ""));
    toast("Password changed");
  } catch (e) { handleErr(e); }
});

// ---- shared ----

document.querySelectorAll("[data-copy]").forEach((b) =>
  b.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText($(b.dataset.copy).textContent);
      toast("Copied");
    } catch {
      toast("Copy failed. Select the text and copy it manually.", true);
    }
  }));

async function refresh() {
  if (!me) return;
  try {
    await loadStatus();
    if (currentTab === "nodes") await loadNodes();
    else if (currentTab === "keys") await loadKeys();
    else if (currentTab === "users") { await loadUsers(); await loadInvites(); }
  } catch (e) { handleErr(e); }
}

function handleErr(e) {
  if (e instanceof AuthError) showLogin("Session ended. Sign in again.");
  else toast(e.message, true);
}

// Initial load: fetch public settings, probe the session, then poll while visible.
(async () => {
  config = await api("GET", "/api/config").catch(() => config);
  try {
    await enterApp();
  } catch (e) {
    showLogin(e instanceof AuthError ? "" : e.message);
  }
  setInterval(() => {
    if (!$("app").hidden && document.visibilityState === "visible" && currentTab === "nodes") refresh();
  }, 10000);
})();
