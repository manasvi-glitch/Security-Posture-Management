// ============================================================
// API client
// ============================================================
const API_BASE = (() => {
  // Same origin when served by the backend (recommended). If the page is
  // opened from another origin/port, fall back to the local API.
  if (location.protocol === "file:" || (location.port && location.port !== "8420")) {
    return "http://localhost:8420";
  }
  return "";
})();

const state = {
  token: localStorage.getItem("spp_token") || null,
  user: null,
  route: "dashboard",
  usersCache: null,
};

async function api(path, { method = "GET", body, isForm = false } = {}) {
  const headers = {};
  if (state.token) headers["Authorization"] = "Bearer " + state.token;
  if (body && !isForm) headers["Content-Type"] = "application/json";

  const resp = await fetch(API_BASE + path, {
    method,
    headers,
    body: body ? (isForm ? body : JSON.stringify(body)) : undefined,
  });

  if (resp.status === 401) {
    logout();
    throw new Error("Your session expired. Please sign in again.");
  }
  if (!resp.ok) {
    let detail = resp.statusText;
    try { detail = (await resp.json()).detail || detail; } catch (e) {}
    throw new Error(typeof detail === "string" ? detail : JSON.stringify(detail));
  }
  if (resp.status === 204) return null;
  const ct = resp.headers.get("content-type") || "";
  return ct.includes("application/json") ? resp.json() : resp.text();
}

// ============================================================
// Auth
// ============================================================
function logout() {
  state.token = null;
  state.user = null;
  state.usersCache = null;
  localStorage.removeItem("spp_token");
  document.getElementById("app").style.display = "none";
  document.getElementById("loginScreen").style.display = "grid";
}

async function login(username, password) {
  const form = new URLSearchParams();
  form.set("username", username);
  form.set("password", password);
  const resp = await fetch(API_BASE + "/api/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: form.toString(),
  });
  if (!resp.ok) {
    const err = await resp.json().catch(() => ({}));
    throw new Error(err.detail || "That didn't work. Check your username and password.");
  }
  const data = await resp.json();
  state.token = data.access_token;
  state.user = data.user;
  localStorage.setItem("spp_token", state.token);
  onAuthenticated();
}

async function tryResumeSession() {
  if (!state.token) return false;
  try { state.user = await api("/api/auth/me"); return true; }
  catch (e) { return false; }
}

function onAuthenticated() {
  document.getElementById("loginScreen").style.display = "none";
  document.getElementById("app").style.display = "grid";
  document.getElementById("userName").textContent = state.user.username;
  document.getElementById("userRole").textContent = state.user.role;
  document.getElementById("adminNavItem").style.display = state.user.role === "admin" ? "block" : "none";
  navigate(location.hash.replace("#/", "") || "dashboard");
}

// ============================================================
// Router
// ============================================================
const routes = {
  dashboard: renderDashboard,
  findings: renderFindings,
  assets: renderAssets,
  reports: renderReports,
  admin: renderAdmin,
};

function navigate(route) {
  if (!routes[route]) route = "dashboard";
  if (route === "admin" && (!state.user || state.user.role !== "admin")) route = "dashboard";
  state.route = route;
  location.hash = "#/" + route;
  document.querySelectorAll("#nav a").forEach(el => el.classList.toggle("active", el.dataset.route === route));
  window.scrollTo(0, 0);
  routes[route]();
}

document.querySelectorAll("#nav a").forEach(el => el.addEventListener("click", () => navigate(el.dataset.route)));

// ============================================================
// Helpers
// ============================================================
const CATEGORY_LABEL = {
  authentication: "Authentication", network: "Network", configuration: "Configuration",
  patch_management: "Patching", access_control: "Access control", application: "Applications",
};
const STATUS_LABEL = {
  detected: "New", triaged: "Triaged", assigned: "Assigned", fix_in_progress: "Being fixed",
  remediated: "Fixed, unchecked", verification: "Being verified", resolved: "Resolved", reopened: "Reopened",
};
const NEXT_STATUS = {
  detected: ["triaged"], triaged: ["assigned"], assigned: ["fix_in_progress"],
  fix_in_progress: ["remediated"], remediated: ["verification"], verification: ["resolved", "reopened"],
  resolved: ["reopened"], reopened: ["triaged"],
};

const main = () => document.getElementById("mainContent");
const canEdit = () => state.user && (state.user.role === "admin" || state.user.role === "analyst");
const isAdmin = () => state.user && state.user.role === "admin";

function escapeHtml(s) {
  return String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
function plural(n, one, many) { return `${n} ${n === 1 ? one : (many || one + "s")}`; }
function sevLabel(s) { return s.charAt(0).toUpperCase() + s.slice(1); }
function sevHtml(s) { return `<span class="sev sev-${s}">${sevLabel(s)}</span>`; }
function scoreColor(score) {
  if (score >= 75) return "var(--good)";
  if (score >= 60) return "var(--med)";
  if (score >= 40) return "var(--high)";
  return "var(--crit)";
}
function fmtDate(iso) {
  if (!iso) return "—";
  return new Date(iso).toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" });
}
function fmtDateTime(iso) {
  return new Date(iso).toLocaleString(undefined, { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" });
}
function fmtAge(iso) {
  const days = Math.floor((Date.now() - new Date(iso).getTime()) / 86400000);
  if (days < 1) return "today";
  if (days < 14) return days + "d";
  if (days < 60) return Math.floor(days / 7) + "w";
  return Math.floor(days / 30) + "mo";
}

function toast(msg, isError = false) {
  const host = document.getElementById("toastHost");
  host.innerHTML = "";
  const el = document.createElement("div");
  el.className = "toast" + (isError ? " error" : "");
  el.textContent = msg;
  host.appendChild(el);
  setTimeout(() => el.remove(), 3800);
}

function openModal(html, asDrawer = false) {
  const bd = document.getElementById("modalBackdrop");
  bd.classList.toggle("drawer", asDrawer);
  document.getElementById("modalBody").innerHTML = html;
  bd.classList.add("open");
}
function closeModal() {
  document.getElementById("modalBackdrop").classList.remove("open");
  document.getElementById("modalBody").innerHTML = "";
}
document.getElementById("modalBackdrop").addEventListener("click", e => { if (e.target.id === "modalBackdrop") closeModal(); });
document.addEventListener("keydown", e => { if (e.key === "Escape") closeModal(); });

async function ensureUsersCache() {
  if (!state.usersCache) state.usersCache = await api("/api/users");
  return state.usersCache;
}
function refreshCurrentView() { if (routes[state.route]) routes[state.route](); }

// ============================================================
// TODAY (dashboard)
// ============================================================
async function renderDashboard() {
  main().innerHTML = `<div class="page-head"><h1>Today</h1></div><div class="empty">Loading…</div>`;
  let d;
  try { d = await api("/api/dashboard/summary"); }
  catch (e) { main().innerHTML = `<div class="page-head"><h1>Today</h1></div><div class="empty">${escapeHtml(e.message)}</div>`; return; }

  const score = d.posture.overall;
  const trend = d.posture.trend_30d;
  const trendPhrase = trend > 0 ? `up ${trend} points over the past month`
    : trend < 0 ? `down ${Math.abs(trend)} points over the past month` : "unchanged over the past month";
  const critLine = d.findings.critical > 0
    ? `<b>${plural(d.findings.critical, "critical finding")}</b> ${d.findings.critical === 1 ? "is" : "are"} still open`
    : `No critical findings are open`;
  const closedLine = d.remediation.resolved_30d > 0
    ? ` The team has closed ${d.remediation.resolved_30d} in the last 30 days.` : "";
  const lede = `Your security posture is <b>${d.posture.rating.toLowerCase()}</b> at ${Math.round(score)}, ${trendPhrase}. ${critLine}.${closedLine}`;

  const cats = [...d.posture.categories].sort((a, b) => a.score - b.score);
  const catRows = cats.map(c => `
    <tr>
      <td class="cat-name">${CATEGORY_LABEL[c.category]}</td>
      <td><div class="cat-bar"><i data-w="${c.score}" style="background:${scoreColor(c.score)}"></i></div></td>
      <td class="cat-val">${Math.round(c.score)}</td>
    </tr>`).join("");

  const fixRows = d.top_priorities.length ? d.top_priorities.map(p => `
    <li>
      <span class="rank">${p.rank}</span>
      <div><div class="t">${escapeHtml(p.title)}</div>
        <div class="m">on ${escapeHtml(p.asset_name)} · ${sevHtml(p.severity)} · risk ${Math.round(p.risk_score)}</div></div>
      <button class="link" data-open-finding="${p.finding_id}">Open</button>
    </li>`).join("") : `<li><div class="empty" style="grid-column:1/-1">Nothing open. Enjoy the quiet.</div></li>`;

  const stages = [
    ["New", d.pipeline.detected, "#CFCFC8"], ["Triaged", d.pipeline.triaged, "#B3BDC9"],
    ["Assigned", d.pipeline.assigned, "#93A5BA"], ["Being fixed", d.pipeline.fix_in_progress, "#6B88A8"],
    ["Fixed", d.pipeline.remediated, "#46698F"], ["Verifying", d.pipeline.verification, "#274B73"],
    ["Resolved (30d)", d.pipeline.resolved_30d, "#2D6A4F"],
  ];
  const pipeBar = stages.map(([, n, c]) => `<i data-g="${n}" style="background:${c}; flex-grow:0; flex-basis:0"></i>`).join("");
  const pipeCols = stages.map(([name, n]) => `<div><b class="num">${n}</b>${name}</div>`).join("");

  const t = d.trend;
  const W = 320, H = 110, pad = 8;
  const lo = Math.min(...t.map(p => p.score)), hi = Math.max(...t.map(p => p.score));
  const span = Math.max(hi - lo, 5);
  const xy = t.map((p, i) => [pad + (i / (t.length - 1)) * (W - 2 * pad), H - pad - ((p.score - lo) / span) * (H - 2 * pad)]);
  const trendLine = xy.map(([x, y]) => `${x.toFixed(1)},${y.toFixed(1)}`).join(" ");
  const last = xy[xy.length - 1];
  const trendAgo = t[0].label.replace("-", "").replace("w", " weeks ago");

  main().innerHTML = `<div class="fade">
    <div class="page-head"><h1>Today</h1><p class="lede">${lede}</p></div>

    <div class="posture">
      <div>
        <div><span class="score-num num">${Math.round(score)}</span><span class="score-of">out of 100</span></div>
        <div class="score-word" style="color:${scoreColor(score)}">${d.posture.rating}</div>
        <div class="scale">
          <i style="width:40%; background:#E7C9C5"></i><i style="width:20%; background:#EBD3BC"></i>
          <i style="width:15%; background:#E6DDB4"></i><i style="width:15%; background:#CFDDCB"></i>
          <i style="width:10%; background:#B6D1BF"></i>
          <span class="scale-marker" id="scaleMarker"></span>
        </div>
        <div class="scale-ticks"><span>0</span><span>40</span><span>60</span><span>75</span><span>90</span><span>100</span></div>
      </div>
      <div>
        <div class="block-title" style="margin-top:0">By area <span class="hint">weakest first</span></div>
        <table class="cat-table">${catRows}</table>
      </div>
    </div>

    <section class="block">
      <div class="block-title">Fix these first <span class="hint">ranked by risk score</span></div>
      <ul class="fixlist">${fixRows}</ul>
    </section>

    <section class="block">
      <div class="block-title">The numbers</div>
      <div class="figures" style="margin-top:20px">
        <div class="fig"><h3>Open findings</h3><div class="big num">${d.findings.total}</div>
          <dl><dt>Critical</dt><dd>${d.findings.critical}</dd><dt>High</dt><dd>${d.findings.high}</dd>
          <dt>Medium</dt><dd>${d.findings.medium}</dd><dt>Low</dt><dd>${d.findings.low}</dd></dl></div>
        <div class="fig"><h3>Assets</h3><div class="big num">${d.assets.total}</div>
          <dl><dt>With serious findings</dt><dd>${d.assets.high_risk}</dd><dt>Facing the internet</dt><dd>${d.assets.internet_facing}</dd>
          <dt>Need some attention</dt><dd>${d.assets.needs_attention}</dd></dl></div>
        <div class="fig"><h3>Fixing</h3><div class="big num">${d.remediation.in_progress}</div>
          <dl><dt>In progress now</dt><dd>${d.remediation.in_progress}</dd><dt>Closed, last 30 days</dt><dd>${d.remediation.resolved_30d}</dd>
          <dt>Average days to fix</dt><dd>${d.remediation.avg_days_to_fix ?? "—"}</dd></dl></div>
      </div>
    </section>

    <section class="block">
      <div class="block-title">Where findings are in the process</div>
      <div class="pipe-bar">${pipeBar}</div>
      <div class="pipe-cols">${pipeCols}</div>
    </section>

    <section class="block">
      <div class="block-title">Posture over time <span class="hint">approximate</span></div>
      <div class="trend-wrap">
        <svg viewBox="0 0 ${W} ${H}" role="img" aria-label="Posture score trend">
          <line x1="${pad}" x2="${W - pad}" y1="${H - pad}" y2="${H - pad}" stroke="var(--rule)" stroke-width="1"/>
          <polyline fill="none" stroke="var(--ink)" stroke-width="1.6" stroke-linejoin="round" points="${trendLine}"/>
          ${xy.map(([x, y]) => `<circle cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="2.3" fill="var(--paper)" stroke="var(--ink)" stroke-width="1.2"/>`).join("")}
          <circle cx="${last[0].toFixed(1)}" cy="${last[1].toFixed(1)}" r="3.6" fill="var(--ink)"/>
        </svg>
        <div class="trend-notes"><span>${trendAgo}: ${Math.round(t[0].score)}</span><span>Now: ${Math.round(t[t.length - 1].score)}</span></div>
      </div>
    </section>
  </div>`;

  requestAnimationFrame(() => requestAnimationFrame(() => {
    const marker = document.getElementById("scaleMarker");
    if (marker) marker.style.left = `calc(${Math.min(Math.max(score, 0), 100)}% - 1px)`;
    document.querySelectorAll(".cat-bar i").forEach((el, i) => setTimeout(() => { el.style.width = el.dataset.w + "%"; }, 80 + i * 50));
    document.querySelectorAll(".pipe-bar i").forEach(el => { el.style.flexGrow = el.dataset.g; });
  }));
  main().querySelectorAll("[data-open-finding]").forEach(b => b.addEventListener("click", () => openFindingDetail(b.dataset.openFinding)));
}

// ============================================================
// FINDINGS
// ============================================================
let findingsFilters = { severity: "", category: "", status: "", q: "" };
let findingsCache = { findings: [], assetNames: {} };\nlet findingsPage = 0;\nconst FINDINGS_PAGE_SIZE = 100;

async function renderFindings() {
  main().innerHTML = `<div class="fade">
    <div class="page-head"><div class="row">
      <div><h1>Findings</h1><div class="sub">Everything that's been found, riskiest first.</div></div>
      ${canEdit() ? `<button class="btn" id="newFindingBtn">Add a finding</button>` : ""}
    </div></div>
    <div class="controls">
      <select id="f_severity"><option value="">Any severity</option>
        <option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select>
      <select id="f_category"><option value="">Any area</option>
        ${Object.entries(CATEGORY_LABEL).map(([k, v]) => `<option value="${k}">${v}</option>`).join("")}</select>
      <select id="f_status"><option value="">Any status</option>
        ${Object.entries(STATUS_LABEL).map(([k, v]) => `<option value="${k}">${v}</option>`).join("")}</select>
      <input id="f_q" class="grow" placeholder="Search by title or asset" type="text">
    </div>
    <div id="findingsTable"><div class="empty">Loading…</div></div></div>`;

  ["severity", "category", "status"].forEach(k => {
    const el = document.getElementById("f_" + k);
    el.value = findingsFilters[k];
    el.addEventListener("change", () => { findingsFilters[k] = el.value; findingsPage = 0; loadFindings(); });
  });
  const q = document.getElementById("f_q");
  q.value = findingsFilters.q;
  q.addEventListener("input", () => { findingsFilters.q = q.value; drawFindingsTable(); });
  if (canEdit()) document.getElementById("newFindingBtn").addEventListener("click", openFindingForm);
  await loadFindings();
}

async function loadFindings() {
  const params = new URLSearchParams();
  ["severity", "category", "status"].forEach(k => { if (findingsFilters[k]) params.set(k, findingsFilters[k]); });
  try {
    const [findings, assets] = await Promise.all([api("/api/findings?" + params.toString() + "&limit=" + FINDINGS_PAGE_SIZE + "&offset=" + (findingsPage * FINDINGS_PAGE_SIZE)), api("/api/assets")]);
    findingsCache.findings = findings;
    findingsCache.assetNames = Object.fromEntries(assets.map(a => [a.id, a.name]));
  } catch (e) {
    document.getElementById("findingsTable").innerHTML = `<div class="empty">${escapeHtml(e.message)}</div>`;
    return;
  }
  drawFindingsTable();
}

function bindFindingsPaging(host, count) {\n  const prev = host.querySelector("#findingsPrev");\n  const next = host.querySelector("#findingsNext");\n  if (prev) prev.addEventListener("click", () => { if (findingsPage > 0) { findingsPage--; loadFindings(); } });\n  if (next) next.addEventListener("click", () => { if (count === FINDINGS_PAGE_SIZE) { findingsPage++; loadFindings(); } });\n}\n\nfunction drawFindingsTable() {
  const host = document.getElementById("findingsTable");
  if (!host) return;
  const q = findingsFilters.q.trim().toLowerCase();
  const rows = findingsCache.findings.filter(f => !q ||
    f.title.toLowerCase().includes(q) || (findingsCache.assetNames[f.asset_id] || "").toLowerCase().includes(q));

  if (!rows.length) { host.innerHTML = `<div class="empty">Nothing matches those filters on this page.</div><div class="row" style="justify-content:space-between;margin-top:12px"><button class="btn quiet" id="findingsPrev" ${findingsPage === 0 ? "disabled" : ""}>Previous</button><span class="muted">Page ${findingsPage + 1}</span><button class="btn quiet" id="findingsNext" disabled>Next</button></div>`; bindFindingsPaging(host, 0); return; }
  host.innerHTML = `<table class="data"><thead><tr>
      <th>Severity</th><th>Finding</th><th>Area</th><th class="r">Risk</th><th>Status</th><th>Age</th><th></th>
    </tr></thead><tbody>${rows.map(f => `
      <tr>
        <td>${sevHtml(f.severity)}</td>
        <td><div>${escapeHtml(f.title)}</div><div class="sub-line">${escapeHtml(findingsCache.assetNames[f.asset_id] || "unknown asset")}</div></td>
        <td class="muted">${CATEGORY_LABEL[f.category]}</td>
        <td class="r num">${Math.round(f.risk_score)}</td>
        <td>${STATUS_LABEL[f.status]}</td>
        <td class="muted num">${fmtAge(f.created_at)}</td>
        <td class="r"><button class="link" data-open-finding="${f.id}">Open</button></td>
      </tr>`).join("")}</tbody></table>`;
  host.querySelectorAll("[data-open-finding]").forEach(b => b.addEventListener("click", () => openFindingDetail(b.dataset.openFinding)));\n  host.insertAdjacentHTML("beforeend", `<div class="row" style="justify-content:space-between;margin-top:12px"><button class="btn quiet" id="findingsPrev" ${findingsPage === 0 ? "disabled" : ""}>Previous</button><span class="muted">Page ${findingsPage + 1} · ${rows.length} shown</span><button class="btn quiet" id="findingsNext" ${rows.length < FINDINGS_PAGE_SIZE ? "disabled" : ""}>Next</button></div>`);\n  bindFindingsPaging(host, rows.length);
}

async function openFindingForm() {
  let assets;
  try { assets = await api("/api/assets"); } catch (e) { toast(e.message, true); return; }
  if (!assets.length) { toast("Add an asset first, then you can attach findings to it.", true); return; }

  openModal(`
    <h3>Add a finding</h3>
    <div class="field"><label>Which asset?</label><select id="nf_asset">${assets.map(a => `<option value="${a.id}">${escapeHtml(a.name)}</option>`).join("")}</select></div>
    <div class="field"><label>What's wrong?</label><input id="nf_title" type="text" placeholder="e.g. SSH open to the whole internet"></div>
    <div class="field"><label>Details (optional)</label><textarea id="nf_desc"></textarea></div>
    <div class="field"><label>Severity</label><select id="nf_sev"><option value="critical">Critical</option><option value="high" selected>High</option><option value="medium">Medium</option><option value="low">Low</option></select></div>
    <div class="field"><label>Area</label><select id="nf_cat">${Object.entries(CATEGORY_LABEL).map(([k, v]) => `<option value="${k}">${v}</option>`).join("")}</select></div>
    <div class="field"><label>Is it being exploited?</label><select id="nf_expl"><option value="theoretical">No known exploit</option><option value="poc" selected>A proof of concept exists</option><option value="active">Yes, actively exploited</option></select></div>
    <div class="field"><label>CVE ID (optional)</label><input id="nf_cve" type="text" placeholder="CVE-2024-12345"></div>
    <div class="sheet-actions"><button class="btn quiet" id="nf_cancel">Cancel</button><button class="btn" id="nf_save">Add finding</button></div>`);
  document.getElementById("nf_cancel").addEventListener("click", closeModal);
  document.getElementById("nf_save").addEventListener("click", async () => {
    const title = document.getElementById("nf_title").value.trim();
    if (!title) { toast("Give it a title first.", true); return; }
    try {
      await api("/api/findings", { method: "POST", body: {
        asset_id: document.getElementById("nf_asset").value, title,
        description: document.getElementById("nf_desc").value || null,
        severity: document.getElementById("nf_sev").value, category: document.getElementById("nf_cat").value,
        exploitability: document.getElementById("nf_expl").value, cve_id: document.getElementById("nf_cve").value || null,
      }});
      toast("Finding added."); closeModal(); refreshCurrentView();
    } catch (e) { toast(e.message, true); }
  });
}

async function openFindingDetail(findingId) {
  let f, assetName = "";
  try {
    f = await api(`/api/findings/${findingId}`);
    assetName = (await api(`/api/assets/${f.asset_id}`)).name;
  } catch (e) { toast(e.message, true); return; }

  const next = NEXT_STATUS[f.status] || [];
  const users = canEdit() ? await ensureUsersCache() : [];
  const assignee = users.find(u => u.id === f.assigned_to);
  const timeline = (f.events || []).slice().reverse().map(ev => `
    <li>${eventLabel(ev)}<div class="when">${fmtDateTime(ev.created_at)}</div></li>`).join("") || `<li class="muted">Nothing yet.</li>`;

  openModal(`
    <h3>${escapeHtml(f.title)}</h3>
    <div class="meta">${sevHtml(f.severity)}<span>${STATUS_LABEL[f.status]}</span><span>Risk ${Math.round(f.risk_score)}</span></div>
    <div class="meta"><span>On <b>${escapeHtml(assetName)}</b></span><span>${CATEGORY_LABEL[f.category]}</span>${f.cve_id ? `<span>${escapeHtml(f.cve_id)}</span>` : ""}<span>Found ${fmtDate(f.created_at)}</span></div>
    ${f.description ? `<p class="desc">${escapeHtml(f.description)}</p>` : ""}
    ${assignee ? `<p class="muted" style="font-size:14px">Owned by ${escapeHtml(assignee.username)}</p>` : ""}

    ${canEdit() ? `
      <h4>Next step</h4>
      <div class="inline-row">
        <select id="fd_status" ${next.length ? "" : "disabled"}>${next.map(s => `<option value="${s}">Mark as: ${STATUS_LABEL[s].toLowerCase()}</option>`).join("") || "<option>No further steps</option>"}</select>
        <button class="btn small" id="fd_status_go" ${next.length ? "" : "disabled"}>Update</button>
      </div>
      <h4>Owner</h4>
      <div class="inline-row">
        <select id="fd_assignee"><option value="">Choose someone</option>${users.map(u => `<option value="${u.id}" ${u.id === f.assigned_to ? "selected" : ""}>${escapeHtml(u.username)} (${u.role})</option>`).join("")}</select>
        <button class="btn quiet small" id="fd_assign_go">Assign</button>
      </div>
      <h4>Leave a note</h4>
      <div class="inline-row"><input id="fd_note" type="text" placeholder="What happened, or what's next?"><button class="btn quiet small" id="fd_note_go">Add</button></div>
    ` : ""}

    <h4>History</h4>
    <ul class="timeline">${timeline}</ul>
    <div class="sheet-actions"><button class="btn quiet" id="fd_close">Close</button></div>`, true);

  document.getElementById("fd_close").addEventListener("click", closeModal);
  if (!canEdit()) return;
  const go = document.getElementById("fd_status_go");
  if (go) go.addEventListener("click", async () => {
    try {
      await api(`/api/findings/${f.id}/status`, { method: "POST", body: { to_status: document.getElementById("fd_status").value } });
      toast("Status updated."); closeModal(); refreshCurrentView();
    } catch (e) { toast(e.message, true); }
  });
  document.getElementById("fd_assign_go").addEventListener("click", async () => {
    const uid = document.getElementById("fd_assignee").value;
    if (!uid) { toast("Pick someone to assign it to.", true); return; }
    try { await api(`/api/findings/${f.id}/assign`, { method: "POST", body: { user_id: uid } }); toast("Assigned."); closeModal(); refreshCurrentView(); }
    catch (e) { toast(e.message, true); }
  });
  document.getElementById("fd_note_go").addEventListener("click", async () => {
    const note = document.getElementById("fd_note").value.trim();
    if (!note) return;
    try { await api(`/api/findings/${f.id}/notes`, { method: "POST", body: { note } }); toast("Note added."); openFindingDetail(f.id); }
    catch (e) { toast(e.message, true); }
  });
}

function eventLabel(ev) {
  if (ev.action === "status_change") {
    if (!ev.from_status) return `Logged as ${STATUS_LABEL[ev.to_status] ? STATUS_LABEL[ev.to_status].toLowerCase() : ev.to_status}`;
    return `Moved from ${(STATUS_LABEL[ev.from_status] || ev.from_status).toLowerCase()} to ${(STATUS_LABEL[ev.to_status] || ev.to_status).toLowerCase()}${ev.note ? " — " + escapeHtml(ev.note) : ""}`;
  }
  if (ev.action === "assignment") return escapeHtml(ev.note || "Assigned");
  if (ev.action === "note") return escapeHtml(ev.note || "");
  if (ev.action === "evidence") return `Evidence added: ${escapeHtml(ev.evidence_url || "")}`;
  return escapeHtml(ev.action);
}

// ============================================================
// ASSETS
// ============================================================
async function renderAssets() {
  main().innerHTML = `<div class="fade">
    <div class="page-head"><div class="row">
      <div><h1>Assets</h1><div class="sub">The servers, apps and devices you're keeping an eye on.</div></div>
      ${canEdit() ? `<button class="btn" id="newAssetBtn">Add an asset</button>` : ""}
    </div></div>
    <div id="assetsTable"><div class="empty">Loading…</div></div></div>`;
  if (canEdit()) document.getElementById("newAssetBtn").addEventListener("click", openAssetForm);

  let assets;
  try { assets = await api("/api/assets"); }
  catch (e) { document.getElementById("assetsTable").innerHTML = `<div class="empty">${escapeHtml(e.message)}</div>`; return; }
  if (!assets.length) { document.getElementById("assetsTable").innerHTML = `<div class="empty">No assets yet. Add one, or import a scan and they'll appear on their own.</div>`; return; }

  const label = s => s.replace("_", " ");
  document.getElementById("assetsTable").innerHTML = `<table class="data"><thead><tr>
      <th>Name</th><th>Type</th><th>Criticality</th><th>Exposure</th><th>Address</th><th class="r">Open findings</th><th></th>
    </tr></thead><tbody>${assets.map(a => `<tr>
      <td>${escapeHtml(a.name)}</td><td class="muted">${label(a.asset_type)}</td><td>${sevLabel(a.criticality)}</td>
      <td>${a.internet_facing ? "Internet-facing" : '<span class="muted">Internal</span>'}</td>
      <td class="muted">${a.ip_address ? escapeHtml(a.ip_address) : "—"}</td>
      <td class="r num">${a.open_finding_count}</td>
      <td class="r">${isAdmin() ? `<button class="link" data-delete-asset="${a.id}">Delete</button>` : ""}</td>
    </tr>`).join("")}</tbody></table>`;

  document.querySelectorAll("[data-delete-asset]").forEach(btn => btn.addEventListener("click", async () => {
    if (!confirm("Delete this asset and every finding attached to it? This can't be undone.")) return;
    try { await api(`/api/assets/${btn.dataset.deleteAsset}`, { method: "DELETE" }); toast("Asset deleted."); renderAssets(); }
    catch (e) { toast(e.message, true); }
  }));
}

function openAssetForm() {
  openModal(`
    <h3>Add an asset</h3>
    <div class="field"><label>Name</label><input id="af_name" type="text" placeholder="e.g. billing-db-01"></div>
    <div class="field"><label>Type</label><select id="af_type"><option value="server">Server</option><option value="workstation">Workstation</option><option value="network_device">Network device</option><option value="application">Application</option><option value="cloud_resource">Cloud resource</option></select></div>
    <div class="field"><label>How much does the business depend on it?</label><select id="af_crit"><option value="low">Not much</option><option value="medium" selected>Moderately</option><option value="high">A lot</option><option value="critical">It's essential</option></select></div>
    <div class="field"><label>IP address (optional)</label><input id="af_ip" type="text"></div>
    <div class="field"><label>Owner (optional)</label><input id="af_owner" type="text"></div>
    <div class="field"><label><input type="checkbox" id="af_internet" style="width:auto; margin-right:8px">Reachable from the internet</label></div>
    <div class="sheet-actions"><button class="btn quiet" id="af_cancel">Cancel</button><button class="btn" id="af_save">Add asset</button></div>`);
  document.getElementById("af_cancel").addEventListener("click", closeModal);
  document.getElementById("af_save").addEventListener("click", async () => {
    const name = document.getElementById("af_name").value.trim();
    if (!name) { toast("It needs a name.", true); return; }
    try {
      await api("/api/assets", { method: "POST", body: {
        name, asset_type: document.getElementById("af_type").value, criticality: document.getElementById("af_crit").value,
        ip_address: document.getElementById("af_ip").value || null, owner: document.getElementById("af_owner").value || null,
        internet_facing: document.getElementById("af_internet").checked,
      }});
      toast("Asset added."); closeModal(); renderAssets();
    } catch (e) { toast(e.message, true); }
  });
}

// ============================================================
// IMPORT & EXPORT
// ============================================================
// Stream a CSV file in the browser so large catalogs do not need to be loaded
// into memory or uploaded as one oversized request.
async function processCatalogCsv(file, statusNode) {
  const batchSize = 2000;
  let header = null, row = [], field = "", inQuotes = false, quotePending = false;
  let batch = [], imported = 0, skipped = 0, errors = 0, processed = 0, bytesRead = 0;
  const norm = value => String(value || "").replace(/^\uFEFF/, "").toLowerCase().replace(/[^a-z0-9]/g, "");
  const headers = {};
  const get = (record, names) => {
    for (const name of names) {
      const key = headers[norm(name)];
      if (key !== undefined && record[key] != null && String(record[key]).trim() !== "") return String(record[key]).trim();
    }
    return "";
  };
  const categoryFor = (cwe, description) => {
    const n = Number((String(cwe).match(/\d+/) || [])[0]);
    const d = description.toLowerCase();
    if ([287,306,798,522,521,862,863,269,284,295,294,640,384,290].includes(n) || /authentication|password|credential|privilege escalation|access control|unauthori[sz]ed access/.test(d)) return "authentication";
    if ([79,89,352,22,434,918,94,78,611,601,502,77,917,98,74].includes(n) || /cross.site scripting|sql injection|web application|http request|command injection/.test(d)) return "application";
    if ([119,120,121,122,125,416,787,190,476,400,401,134,20].includes(n) || /buffer overflow|out.of.bounds|memory corruption/.test(d)) return "configuration";
    if (/tcp|udp|dns|network|router|firewall|remote attacker|nfs|ssh|tls|ssl|ip protocol/.test(d)) return "network";
    if (/outdated|end.of.life|unsupported version|missing patch|security update/.test(d)) return "patch_management";
    return "configuration";
  };
  const parseRecord = async record => {
    if (!header) {
      header = record.map(v => v.trim().replace(/^\uFEFF/, ""));
      header.forEach((name, i) => headers[norm(name)] = i);
      const cveCol = ["cveid","cve","cveidentifier"].some(k => headers[k] !== undefined);
      const descCol = ["description","shortdescription","summary"].some(k => headers[k] !== undefined);
      if (!cveCol || !descCol) throw new Error("This does not look like a CVE/CWE catalog CSV. Expected CVE-ID and DESCRIPTION columns.");
      return;
    }
    if (record.length === 1 && !record[0].trim()) return;
    processed++;
    const cve = get(record, ["CVE-ID","CVE ID","CVE"]);
    const description = get(record, ["DESCRIPTION","SHORT DESCRIPTION","SUMMARY"]);
    if (!cve || !/^CVE-\d{4}-\d+$/i.test(cve) || !description) { errors++; return; }
    let score = null;
    for (const col of ["CVSS-V4","CVSS-V3","CVSS-V2","CVSS","CVSS Score","Base Score"]) {
      const raw = get(record, [col]);
      if (/^(?:10(?:\.0)?|[0-9](?:\.\d+)?)$/.test(raw)) { score = Number(raw); break; }
    }
    let severity = get(record, ["SEVERITY","CVSS Severity","Base Severity"]).toLowerCase();
    if (!["critical","high","medium","low"].includes(severity)) {
      severity = score !== null ? (score >= 9 ? "critical" : score >= 7 ? "high" : score >= 4 ? "medium" : "low") : "medium";
    }
    const titleText = description.split(/(?<=[.!?])\s/)[0].slice(0, 420);
    batch.push({
      cve_id: cve,
      external_id: get(record, ["ID","Plugin ID"]) || cve,
      title: (cve + ": " + titleText).slice(0, 500),
      description: description.slice(0, 10000),
      severity,
      category: categoryFor(get(record, ["CWE-ID","CWE ID","CWE"]), description)
    });
    if (batch.length >= batchSize) await sendBatch();
  };
  const sendBatch = async () => {
    if (!batch.length) return;
    const payload = batch;
    batch = [];
    const result = await api("/api/findings/import/catalog-batch", {method:"POST", body:payload});
    imported += result.findings_created || 0;
    skipped += result.findings_skipped || 0;
    errors += (result.errors || []).length;
    statusNode.textContent = "Processed " + processed.toLocaleString() + " rows · imported " + imported.toLocaleString() + " · skipped " + skipped.toLocaleString() + " · errors " + errors.toLocaleString();
  };
  const reader = file.stream().getReader();
  const decoder = new TextDecoder("utf-8");
  const consume = async chunk => {
    for (let i = 0; i < chunk.length; i++) {
      const ch = chunk[i];
      if (quotePending) {
        quotePending = false;
        if (ch === '"') { field += '"'; continue; }
        inQuotes = false;
      }
      if (inQuotes) {
        if (ch === '"') quotePending = true;
        else field += ch;
      } else if (ch === '"' && field.length === 0) {
        inQuotes = true;
      } else if (ch === ",") {
        row.push(field); field = "";
      } else if (ch === "\n") {
        row.push(field); field = "";
        await parseRecord(row); row = [];
      } else if (ch !== "\r") {
        field += ch;
      }
    }
  };
  try {
    while (true) {
      const {value, done} = await reader.read();
      if (done) break;
      bytesRead += value.byteLength;
      await consume(decoder.decode(value, {stream:true}));
      statusNode.textContent = "Reading CSV… " + Math.min(99, Math.round(bytesRead / file.size * 100)) + "% · " + processed.toLocaleString() + " rows";
    }
    const tail = decoder.decode();
    if (tail) await consume(tail);
    if (quotePending) { quotePending = false; inQuotes = false; }
    if (field.length || row.length) { row.push(field); await parseRecord(row); }
    await sendBatch();
  } catch (error) {
    try { await reader.cancel(); } catch (_) {}
    throw error;
  }
  return {processed, imported, skipped, errors};
}

function renderReports() {
  main().innerHTML = `<div class="fade">
    <div class="page-head"><h1>Import &amp; export</h1><div class="sub">Bring in scanner results, or take the findings register out.</div></div>

    <section class="block" style="margin-top:0">
      <div class="block-title">Export</div>
      <div class="prose"><p>Download every finding as a spreadsheet-friendly CSV, with risk scores, status and owner.</p>
      <button class="btn" id="exportCsvBtn">Download findings.csv</button></div>
    </section>

    ${canEdit() ? `
    <section class="block">
      <div class="block-title">Import</div>
      <div class="cols-2" style="margin-top:20px">
        <div class="prose">
          <h4 style="font-size:16px; font-weight:600; color:var(--ink)">JSON scan results</h4>
          <p>Paste a list of findings with <span class="mono">host</span>, <span class="mono">finding</span>, <span class="mono">severity</span> and optionally <span class="mono">ip</span>, <span class="mono">description</span>, <span class="mono">cve</span>. Unknown hosts become new assets.</p>
          <textarea class="code" id="importJson" placeholder='[{"host":"web-edge-05","finding":"Outdated TLS library","severity":"high"}]'></textarea>
          <div style="margin-top:12px"><button class="btn" id="importJsonBtn">Import JSON</button></div>
          <div class="result" id="importJsonResult"></div>
        </div>
        <div class="prose">
          <h4 style="font-size:16px; font-weight:600; color:var(--ink)">Nessus or OpenVAS CSV</h4>
          <p>Upload an export with columns like <span class="mono">Host</span>, <span class="mono">Name</span>, <span class="mono">Risk</span>, <span class="mono">Synopsis</span>, <span class="mono">CVE</span>.</p>
          <input type="file" id="importCsvFile" accept=".csv">
          <div style="margin-top:12px"><button class="btn" id="importCsvBtn">Import CSV</button></div>
          <div class="result" id="importCsvResult"></div>
        </div>
      </div>
    </section>` : ""}</div>`;

  document.getElementById("exportCsvBtn").addEventListener("click", async () => {
    try {
      const resp = await fetch(API_BASE + "/api/reports/findings.csv", { headers: { Authorization: "Bearer " + state.token } });
      if (!resp.ok) throw new Error("The export didn't work. Try again.");
      const url = URL.createObjectURL(await resp.blob());
      const a = document.createElement("a"); a.href = url; a.download = "findings_report.csv"; a.click();
      URL.revokeObjectURL(url);
    } catch (e) { toast(e.message, true); }
  });
  if (!canEdit()) return;

  const summarize = r => `Added ${plural(r.findings_created, "finding")} and ${plural(r.assets_created, "new asset")}; skipped ${plural(r.findings_skipped, "duplicate")}.` + (r.errors.length ? ` Problems: ${r.errors.join("; ")}` : "");
  document.getElementById("importJsonBtn").addEventListener("click", async () => {
    const raw = document.getElementById("importJson").value.trim();
    if (!raw) { toast("Paste some JSON first.", true); return; }
    let parsed; try { parsed = JSON.parse(raw); } catch (e) { toast("That isn't valid JSON.", true); return; }
    try { const r = await api("/api/findings/import/kestrel-scan", { method: "POST", body: parsed }); document.getElementById("importJsonResult").textContent = summarize(r); toast("Import finished."); }
    catch (e) { toast(e.message, true); }
  });
  document.getElementById("importCsvBtn").addEventListener("click", async () => {
    const input = document.getElementById("importCsvFile");
    const button = document.getElementById("importCsvBtn");
    const resultNode = document.getElementById("importCsvResult");
    if (!input.files.length) { toast("Choose a CSV file first.", true); return; }
    const file = input.files[0];
    button.disabled = true;
    button.textContent = "Processing…";
    resultNode.textContent = "Checking CSV format…";
    try {
      const sample = await file.slice(0, 8192).text();
      const header = (sample.split(/\\r?\\n/, 1)[0] || "").replace(/^\\uFEFF/, "").toLowerCase().replace(/[^a-z0-9,]/g, "");
      let result;
      if (header.includes("cveid") && header.includes("description")) {
        resultNode.textContent = "CVE/CWE catalog detected. Streaming and importing in batches…";
        result = await processCatalogCsv(file, resultNode);
        resultNode.textContent = `Completed: ${result.imported.toLocaleString()} findings imported; ${result.skipped.toLocaleString()} duplicates skipped; ${result.errors.toLocaleString()} rows skipped due to invalid data.`;
        toast("Catalog import finished.");
      } else {
        resultNode.textContent = "Uploading scanner CSV…";
        const form = new FormData(); form.append("file", file);
        const r = await api("/api/findings/import/nessus-csv", { method: "POST", body: form, isForm: true });
        resultNode.textContent = summarize(r);
        toast("CSV import finished.");
      }
      findingsPage = 0;
      findingsFilters = {severity:"", category:"", status:"", q:""};
      navigate("findings");
    } catch (e) {
      resultNode.textContent = "Import failed: " + e.message;
      toast(e.message, true);
    } finally {
      button.disabled = false;
      button.textContent = "Import CSV";
    }
  });
}

// ============================================================
// ADMIN
// ============================================================
async function renderAdmin() {
  main().innerHTML = `<div class="fade">
    <div class="page-head"><h1>Admin</h1><div class="sub">Who can do what, and a record of what's been done.</div></div>
    <section class="block" style="margin-top:0"><div class="block-title">People</div><div id="usersTable"><div class="empty">Loading…</div></div></section>
    <section class="block"><div class="block-title">Activity log <span class="hint">latest 50</span></div><div id="auditTable"><div class="empty">Loading…</div></div></section></div>`;

  try {
    const users = await api("/api/users");
    state.usersCache = users;
    document.getElementById("usersTable").innerHTML = `<table class="data"><thead><tr><th>Username</th><th>Email</th><th>Role</th><th>Status</th><th></th></tr></thead><tbody>
      ${users.map(u => `<tr><td>${escapeHtml(u.username)}</td><td class="muted">${escapeHtml(u.email)}</td>
        <td><select data-role-select="${u.id}" ${u.id === state.user.id ? "disabled" : ""} style="background:var(--card); border:1px solid var(--rule); border-radius:3px; padding:4px 6px;">
          ${["admin", "analyst", "viewer"].map(r => `<option value="${r}" ${r === u.role ? "selected" : ""}>${r}</option>`).join("")}</select></td>
        <td>${u.is_active ? "Active" : '<span class="muted">Disabled</span>'}</td>
        <td class="r">${u.is_active && u.id !== state.user.id ? `<button class="link" data-deactivate="${u.id}">Disable</button>` : ""}</td></tr>`).join("")}
    </tbody></table>`;
    document.querySelectorAll("[data-role-select]").forEach(sel => sel.addEventListener("change", async () => {
      try { await api(`/api/users/${sel.dataset.roleSelect}/role?role=${sel.value}`, { method: "PATCH" }); toast("Role updated."); state.usersCache = null; }
      catch (e) { toast(e.message, true); }
    }));
    document.querySelectorAll("[data-deactivate]").forEach(btn => btn.addEventListener("click", async () => {
      if (!confirm("Disable this account? They won't be able to sign in.")) return;
      try { await api(`/api/users/${btn.dataset.deactivate}/deactivate`, { method: "PATCH" }); toast("Account disabled."); state.usersCache = null; renderAdmin(); }
      catch (e) { toast(e.message, true); }
    }));
  } catch (e) { document.getElementById("usersTable").innerHTML = `<div class="empty">${escapeHtml(e.message)}</div>`; }

  try {
    const logs = await api("/api/audit?limit=50");
    document.getElementById("auditTable").innerHTML = logs.length ? `<table class="data"><thead><tr><th>When</th><th>Who</th><th>Action</th><th>Detail</th></tr></thead><tbody>
      ${logs.map(l => `<tr><td class="muted" style="white-space:nowrap">${fmtDateTime(l.created_at)}</td><td>${escapeHtml(l.username || "—")}</td>
        <td>${escapeHtml(l.action)}</td><td class="muted">${escapeHtml(l.detail || "—")}</td></tr>`).join("")}</tbody></table>` : `<div class="empty">Nothing recorded yet.</div>`;
  } catch (e) { document.getElementById("auditTable").innerHTML = `<div class="empty">${escapeHtml(e.message)}</div>`; }
}

// ============================================================
// Bootstrap
// ============================================================
document.getElementById("loginForm").addEventListener("submit", async e => {
  e.preventDefault();
  const btn = document.getElementById("loginBtn"), err = document.getElementById("loginError");
  err.textContent = ""; btn.disabled = true;
  try { await login(document.getElementById("loginUsername").value, document.getElementById("loginPassword").value); }
  catch (ex) { err.textContent = ex.message; }
  finally { btn.disabled = false; }
});
document.getElementById("signOut").addEventListener("click", logout);
window.addEventListener("hashchange", () => {
  const route = location.hash.replace("#/", "");
  if (state.user && route && route !== state.route) navigate(route);
});
(async function boot() { if (await tryResumeSession()) onAuthenticated(); })();
