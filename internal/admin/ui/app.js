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
  $("new-key").hidden = $("new-invite").hidden = $("new-share-link").hidden = true;
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
  $("settings-form").hidden = me.token;
  $("domain-form").hidden = me.token;
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
  const mb = $("machine-badge");
  mb.hidden = !s.pendingMachines;
  mb.textContent = s.pendingMachines || "";
  mb.title = "machines waiting for approval";
  const sb = $("share-badge");
  sb.hidden = !s.pendingShares;
  sb.textContent = s.pendingShares || "";
  const badge = $("pending-badge");
  badge.hidden = !s.pending;
  badge.textContent = s.pending || "";
  const modes = { off: "sign-up off", approval: "sign-up needs approval", invite: "sign-up by invite", open: "open sign-up" };
  $("signup-mode").textContent = modes[s.signup] || "";
}

// ---- machines ----

const openTraffic = new Set(); // machines whose per-peer traffic is shown

async function loadNodes() {
  const nodes = await api("GET", "/api/v1/nodes");
  $("nodes-empty").hidden = nodes.length > 0;
  const cols = me.operator ? 9 : 8;
  $("nodes-body").replaceChildren(
    ...nodes.flatMap((n) => [
      el("tr", {},
        el("td", {}, el("span", { class: "dot" + (n.online ? " on" : ""), title: n.online ? "online" : "offline" })),
        el("td", {}, el("div", {}, n.name), el("div", { class: "sub" }, n.fqdn),
          n.ephemeral && el("span", { class: "badge" }, "ephemeral"),
          n.exitNode && el("span", { class: "badge", title: "Machines in this account can send their internet traffic through it" }, "exit node"),
          n.tags.length > 0 && el("div", { class: "tags" }, n.tags.map((t) => el("span", { class: "badge" }, "tag:" + t)))),
        me.operator && el("td", {}, n.user),
        el("td", { class: "mono" }, el("div", {}, n.ipv4), el("div", { class: "sub" }, n.ipv6)),
        el("td", {}, n.os || "–", el("div", { class: "sub" }, n.hostname)),
        el("td", { title: n.lastSeen ? fmtDate(n.lastSeen) : "" }, ago(n.lastSeen)),
        el("td", {}, trafficCell(n)),
        el("td", {}, keyCell(n)),
        el("td", { class: "actions" },
          !n.approved && el("button", { class: "primary small", onclick: () => approveNode(n) }, "Approve"),
          el("button", { class: "ghost", onclick: () => toggleExpiry(n) }, n.keyExpiry ? "Never expire" : "Set expiry"),
          el("button", { class: "ghost", onclick: () => editTags(n) }, "Tags"),
          (n.exitNode || n.os === "linux") && el("button", {
            class: "ghost", onclick: () => toggleExitNode(n),
            title: n.exitNode ? "Stop carrying this account's internet traffic" : "Let this account's machines send their internet traffic through this machine",
          }, n.exitNode ? "Exit node: on" : "Exit node: off"),
          el("button", { class: "ghost", onclick: () => renameNode(n) }, "Rename"),
          el("button", { class: "danger", onclick: () => deleteNode(n) }, "Remove"),
        ),
      ),
      openTraffic.has(n.id) && n.traffic && trafficDetail(n, cols),
    ].filter(Boolean)),
  );
  $("nodes-updated").textContent = "updated " + new Date().toLocaleTimeString();
}

// ---- traffic ----

function fmtBytes(b) {
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (b >= 1000 && i < u.length - 1) { b /= 1000; i++; }
  return (i === 0 || b >= 100 ? Math.round(b) : b.toFixed(1)) + " " + u[i];
}
const fmtRate = (r) => (r < 1 ? "0 B/s" : fmtBytes(r) + "/s");

// trafficCell: current download and upload, and totals; click for per peer.
function trafficCell(n) {
  const t = n.traffic;
  if (!t) return el("span", { class: "sub", title: "This machine hasn't reported any traffic (idle, offline, or an older client)" }, "–");
  return el("button", {
    class: "traffic-link", title: "Traffic per peer",
    onclick: () => { openTraffic.has(n.id) ? openTraffic.delete(n.id) : openTraffic.add(n.id); loadNodes().catch(handleErr); },
  },
    el("div", {}, "↓ " + fmtRate(t.rxRate) + "  ↑ " + fmtRate(t.txRate)),
    el("div", { class: "sub" }, fmtBytes(t.rx) + " in, " + fmtBytes(t.tx) + " out"),
  );
}

// trafficDetail: a row under the machine with its traffic per peer.
function trafficDetail(n, cols) {
  const t = n.traffic;
  const rows = t.peers.map((p) => el("tr", {},
    el("td", {}, el("div", {}, p.name), el("div", { class: "sub" }, p.fqdn)),
    el("td", {}, "↓ " + fmtRate(p.rxRate)), el("td", {}, "↑ " + fmtRate(p.txRate)),
    el("td", {}, fmtBytes(p.rx) + " in"), el("td", {}, fmtBytes(p.tx) + " out"),
  ));
  return el("tr", { class: "detail" }, el("td", { colspan: cols },
    el("div", { class: "sub" }, `${n.name}'s traffic with each peer, as it reported it (totals since its tunnel started; updated ${ago(t.updated)}):`),
    t.peers.length
      ? el("table", { class: "peer-traffic" }, el("tbody", {}, ...rows))
      : el("div", { class: "sub" }, "No traffic yet."),
  ));
}

// keyCell shows approval and key expiry.
function keyCell(n) {
  if (!n.approved) return el("span", { class: "badge warn" }, "needs approval");
  if (n.expired) return el("span", { class: "badge bad" }, "expired");
  if (!n.keyExpiry) return el("span", { class: "sub" }, "never expires");
  const days = Math.round((new Date(n.keyExpiry) - Date.now()) / 86400000);
  const label = days > 60 ? `${Math.round(days / 30)} months` : `${days} days`;
  return el("span", { class: days <= 14 ? "badge warn" : "sub", title: fmtDate(n.keyExpiry) }, "expires in " + label);
}

async function approveNode(n) {
  try {
    await api("POST", `/api/v1/nodes/${n.id}/approve`, {});
    toast(`Approved ${n.name}`);
    refresh();
  } catch (e) { handleErr(e); }
}

async function toggleExpiry(n) {
  const never = !!n.keyExpiry;
  const q = never
    ? `Let ${n.name}'s key never expire? Use this for servers that must not drop off.`
    : `Give ${n.name} the server's normal key lifetime, starting now? It will need re-authenticating when it expires.`;
  if (!confirm(q)) return;
  try {
    await api("POST", `/api/v1/nodes/${n.id}/expiry`, { expiry: never ? "never" : "default" });
    toast(never ? `${n.name}'s key never expires` : `${n.name}'s key expiry set`);
    refresh();
  } catch (e) { handleErr(e); }
}

async function toggleExitNode(n) {
  const on = !n.exitNode;
  const q = on
    ? `Make ${n.name} an exit node? Machines in ${n.user}'s account can then send all their internet traffic through it, and websites will see ${n.name}'s public address. Each machine still chooses whether to use it (tc up --exit-node ${n.name}).`
    : `Stop ${n.name} being an exit node? Machines using it go back to their own internet connection.`;
  if (!confirm(q)) return;
  try {
    await api("POST", `/api/v1/nodes/${n.id}/exit-node`, { enabled: on });
    toast(on ? `${n.name} is an exit node` : `${n.name} is no longer an exit node`);
    refresh();
  } catch (e) { handleErr(e); }
}

async function editTags(n) {
  const v = prompt(`Tags for ${n.name}, separated by commas (used by access rules, e.g. server, db):`, n.tags.join(", "));
  if (v === null) return;
  try {
    const r = await api("POST", `/api/v1/nodes/${n.id}/tags`, { tags: v.split(",") });
    toast(r.tags.length ? `${n.name}: ${r.tags.map((t) => "tag:" + t).join(", ")}` : `Removed ${n.name}'s tags`);
    refresh();
  } catch (e) { handleErr(e); }
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
        el("td", {}, k.reusable ? "reusable" : "one-off", k.ephemeral && el("div", { class: "sub" }, "ephemeral"), k.preapproved && el("div", { class: "sub" }, "pre-approved")),
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
  const body = { ttl: $("key-ttl").value, reusable: $("key-reusable").checked, ephemeral: $("key-ephemeral").checked, preapproved: $("key-preapproved").checked };
  if (me.operator) {
    if (!$("key-user").value) return toast("Create an account first", true);
    body.user = $("key-user").value;
  }
  try {
    const r = await api("POST", "/api/v1/keys", body);
    $("new-key-value").textContent = r.key;
    $("new-key-qr").hidden = !r.qrSvg;
    if (r.qrSvg) $("new-key-qr-img").src = "data:image/svg+xml;charset=utf-8," + encodeURIComponent(r.qrSvg);
    $("new-key").hidden = false;
    refresh();
  } catch (e) { handleErr(e); }
});

// ---- access rules ----

async function loadRules() {
  let account = "";
  if (me.operator) {
    const users = await api("GET", "/api/v1/users");
    const sel = $("rules-account");
    const prev = sel.value || (me.token ? (users[0] || {}).name : me.login);
    sel.replaceChildren(...users.map((u) => el("option", { value: u.name }, u.name)));
    if (users.some((u) => u.name === prev)) sel.value = prev;
    account = sel.value;
  }
  const q = account ? `?user=${encodeURIComponent(account)}` : "";
  const [rules, nodes] = await Promise.all([api("GET", "/api/v1/rules" + q), api("GET", "/api/v1/nodes")]);
  const mine = nodes.filter((n) => !account || n.user === account);
  const tags = [...new Set(mine.flatMap((n) => n.tags))].sort();
  $("rule-selectors").replaceChildren(
    el("option", { value: "*" }), ...tags.map((t) => el("option", { value: "tag:" + t })), ...mine.map((n) => el("option", { value: n.name })));
  $("rules-mode").textContent = rules.length === 0
    ? "No rules: every machine of the account can reach every other, on any port. Add a rule to switch to allowing only what the rules say."
    : "Only what these rules allow is reachable between the account's machines (plus replies). Everything else is blocked.";
  $("rules-body").replaceChildren(...rules.map((r) =>
    el("tr", {},
      el("td", { class: "mono" }, r.src),
      el("td", { class: "mono" }, r.dst),
      el("td", { class: "mono" }, r.ports),
      el("td", {}, fmtDate(r.created)),
      el("td", { class: "actions" }, el("button", { class: "danger", onclick: () => deleteRule(r, rules.length) }, "Delete")))));
}

async function deleteRule(r, count) {
  const extra = count === 1 ? " It's the last rule: everything becomes reachable again." : "";
  if (!confirm(`Delete the rule ${r.src} → ${r.dst} on ${r.ports}?${extra}`)) return;
  try {
    await api("DELETE", `/api/v1/rules/${r.id}`);
    toast("Rule deleted");
    refresh();
  } catch (e) { handleErr(e); }
}

$("rules-account").addEventListener("change", () => refresh());

$("rule-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const body = { src: $("rule-src").value, dst: $("rule-dst").value, ports: $("rule-ports").value || "*" };
  if (me.operator) body.user = $("rules-account").value;
  try {
    const first = $("rules-body").children.length === 0;
    if (first && !confirm("This is the account's first rule: from now on only what the rules allow is reachable. Continue?")) return;
    const r = await api("POST", "/api/v1/rules", body);
    $("rule-src").value = $("rule-dst").value = $("rule-ports").value = "";
    toast(`Added ${r.src} → ${r.dst} on ${r.ports}`);
    refresh();
  } catch (e) { handleErr(e); }
});

// ---- sharing ----

async function loadSharing() {
  const [shares, nodes] = await Promise.all([api("GET", "/api/v1/shares"), api("GET", "/api/v1/nodes")]);
  const sel = $("share-machine");
  const prev = sel.value;
  sel.replaceChildren(...nodes.map((n) => el("option", { value: n.id }, me.operator && n.user !== me.login ? `${n.name} (${n.user})` : n.name)));
  if (nodes.some((n) => String(n.id) === prev)) sel.value = prev;
  $("share-form").hidden = nodes.length === 0;
  $("outgoing-empty").textContent = nodes.length === 0 ? "Add a machine to your network to share it." : "You haven't shared any machines.";

  const statusOf = (s) => s.inEffect ? ["active", "ok"] : s.status === "pending" ? ["pending", "warn"] : ["inactive", ""];
  $("incoming-empty").hidden = shares.incoming.length > 0;
  $("incoming-body").replaceChildren(...shares.incoming.map((s) => {
    const st = statusOf(s);
    const actions = s.status === "pending"
      ? [el("button", { class: "primary small", onclick: () => acceptShare(s) }, "Accept"),
         el("button", { class: "ghost", onclick: () => removeShare(s, `Decline ${s.fqdn}?`) }, "Decline")]
      : [el("button", { class: "danger", onclick: () => removeShare(s, `Stop using ${s.fqdn}? You'd need the owner to share it again.`) }, "Remove")];
    return el("tr", {},
      el("td", {}, el("div", {}, s.machine), el("div", { class: "sub" }, s.fqdn)),
      el("td", {}, s.owner),
      el("td", {}, el("span", { class: "badge " + st[1] }, st[0])),
      el("td", {}, s.acceptedAt ? fmtDate(s.acceptedAt) : "–"),
      el("td", { class: "actions" }, actions));
  }));
  $("outgoing-empty").hidden = shares.outgoing.length > 0;
  $("outgoing-body").replaceChildren(...shares.outgoing.map((s) => {
    const st = s.recipient ? statusOf(s) : ["link not used yet", ""];
    const who = s.recipient || el("span", { class: "mono" }, s.linkPrefix + "…");
    return el("tr", {},
      el("td", {}, el("div", {}, s.machine), el("div", { class: "sub" }, me.operator && s.owner !== me.login ? `owner: ${s.owner}` : s.fqdn)),
      el("td", {}, who, s.expires && el("div", { class: "sub" }, "expires " + fmtDate(s.expires))),
      el("td", {}, el("span", { class: "badge " + st[1] }, st[0])),
      el("td", {}, fmtDate(s.created)),
      el("td", { class: "actions" }, el("button", { class: "danger", onclick: () => removeShare(s, `Stop sharing ${s.machine}${s.recipient ? " with " + s.recipient : ""}? Access ends immediately.`) }, "Revoke")));
  }));
}

async function acceptShare(s) {
  try {
    await api("POST", `/api/v1/shares/${s.id}/accept`, {});
    toast(`${s.fqdn} is now available to your machines`);
    refresh();
  } catch (e) { handleErr(e); }
}

async function removeShare(s, question) {
  if (!confirm(question)) return;
  try {
    await api("DELETE", `/api/v1/shares/${s.id}`);
    toast("Share removed");
    refresh();
  } catch (e) { handleErr(e); }
}

$("share-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const recipient = $("share-recipient").value.trim().toLowerCase();
  if (!recipient) return toast("Enter an account name, or create a link", true);
  try {
    const s = await api("POST", `/api/v1/nodes/${$("share-machine").value}/shares`, { recipient });
    $("share-recipient").value = "";
    toast(`Offered ${s.machine} to ${s.recipient}. It takes effect when they accept.`);
    refresh();
  } catch (e) { handleErr(e); }
});

$("share-link").addEventListener("click", async () => {
  if (!$("share-machine").value) return toast("You have no machines to share", true);
  try {
    const r = await api("POST", `/api/v1/nodes/${$("share-machine").value}/share-links`, { ttl: $("share-link-ttl").value });
    $("new-share-link-value").textContent = r.code;
    $("new-share-link").hidden = false;
    refresh();
  } catch (e) { handleErr(e); }
});

$("redeem-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  try {
    const s = await api("POST", "/api/v1/shares/redeem", { code: $("redeem-code").value.trim() });
    $("redeem-code").value = "";
    toast(`${s.fqdn} is now available to your machines`);
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
      actions.push(btn("Domain", "ghost", () => setUserDomain(u)));
      actions.push(btn(u.hasPassword ? "Reset password" : "Set password", "ghost", () => setPassword(u)));
      if (!self) actions.push(btn("Delete", "danger", () => deleteUser(u)));
      return el("tr", {},
        el("td", {}, u.name, self && el("span", { class: "sub" }, " (you)"), !u.hasPassword && el("div", { class: "sub" }, "no password: can't sign in")),
        el("td", {}, u.role),
        el("td", {}, el("span", { class: "badge " + (statusBadge[u.status] || "") }, u.status)),
        el("td", {}, el("code", {}, u.dnsDomain), !u.customDomain && el("div", { class: "sub" }, "default")),
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

async function setUserDomain(u) {
  const d = prompt(`MagicDNS domain for ${u.name}'s machines (empty for the default). This renames all ${u.nodes} of them.`, u.customDomain ? u.dnsDomain : "");
  if (d === null) return;
  try {
    const r = await api("POST", `/api/v1/users/${encodeURIComponent(u.name)}/dns-domain`, { domain: d.trim().toLowerCase() });
    toast(`${u.name}'s machines are now <machine>.${r.dnsDomain}`);
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

async function loadAccount() {
  if (me.token) return;
  const st = await api("GET", "/api/v1/me/settings");
  $("require-approval").checked = st.requireMachineApproval;
  showDomain(st);
}

function showDomain(st) {
  $("domain-example").textContent = `machine.${st.dnsDomain}`;
  $("dns-domain").value = st.dnsDomain;
  $("dns-domain").placeholder = st.defaultDomain;
  $("dns-domain").disabled = !st.canSetDomain;
  $("domain-form").querySelectorAll("button").forEach((b) => (b.disabled = !st.canSetDomain));
  $("domain-reset").hidden = !st.customDomain;
  const suf = st.domainSuffixes || [];
  $("domain-hint").textContent = !st.canSetDomain
    ? "Only an operator can change your domain on this server."
    : suf.length
      ? `Default: ${st.defaultDomain}. Your own must end in ${suf.map((s) => "." + s).join(" or ")}, for example acme.${suf[0]}.`
      : `Default: ${st.defaultDomain}.`;
}

async function saveDomain(domain) {
  const label = domain || "the default";
  if (!confirm(`Rename every machine in your account to <machine>.${label}? Names under the old domain stop resolving.`)) return;
  try {
    const st = await api("POST", "/api/v1/me/settings", { dnsDomain: domain });
    showDomain(st);
    toast(`Your machines are now <machine>.${st.dnsDomain}`);
  } catch (e) { handleErr(e); }
}

$("domain-form").addEventListener("submit", (ev) => {
  ev.preventDefault();
  saveDomain($("dns-domain").value.trim().toLowerCase().replace(/\.$/, ""));
});
$("domain-reset").addEventListener("click", () => saveDomain(""));

$("require-approval").addEventListener("change", async () => {
  try {
    const st = await api("POST", "/api/v1/me/settings", { requireMachineApproval: $("require-approval").checked });
    toast(st.requireMachineApproval ? "New machines now need your approval" : "New machines are approved automatically");
  } catch (e) { handleErr(e); }
});

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
    else if (currentTab === "sharing") await loadSharing();
    else if (currentTab === "rules") await loadRules();
    else if (currentTab === "account") await loadAccount();
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
