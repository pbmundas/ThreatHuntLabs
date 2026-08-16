const DATA_URL = "data/hypotheses.json";
const PAGE_SIZE = 24;
const severityRank = { Critical: 4, High: 3, Medium: 2, Low: 1 };
const canonicalTactics = ["Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact"];
const normalizeTactic = (record) => {
  const raw = `${record["MITRE ATT&CK Tactic"] || ""} ${record["Threat Category"] || ""}`;
  const match = canonicalTactics.find((tactic) => raw.toLowerCase().includes(tactic.toLowerCase()));
  if (match) return match;
  if (/command and scripting interpreter/i.test(raw)) return "Execution";
  if (/stealth/i.test(raw)) return "Defense Evasion";
  return "Multiple";
};

const elements = {
  search: document.querySelector("#global-search"),
  tactic: document.querySelector("#filter-tactic"),
  severity: document.querySelector("#filter-severity"),
  platform: document.querySelector("#filter-platform"),
  priority: document.querySelector("#filter-priority"),
  sort: document.querySelector("#sort-order"),
  reset: document.querySelector("#clear-filters"),
  active: document.querySelector("#active-filters"),
  grid: document.querySelector("#results-grid"),
  summary: document.querySelector("#result-summary"),
  loadMore: document.querySelector("#load-more"),
  empty: document.querySelector("#empty-state"),
  emptyReset: document.querySelector("#empty-reset"),
};

let payload;
let records = [];
let visibleCount = PAGE_SIZE;

const state = {
  query: "",
  tactic: "",
  severity: "",
  platform: "",
  priority: "",
  sort: "id",
};

const escapeHtml = (value = "") => String(value)
  .replaceAll("&", "&amp;")
  .replaceAll("<", "&lt;")
  .replaceAll(">", "&gt;")
  .replaceAll('"', "&quot;")
  .replaceAll("'", "&#039;");

const compact = (value, limit = 200) => {
  const text = String(value || "").replace(/\s+/g, " ").trim();
  return text.length > limit ? `${text.slice(0, limit - 1).trim()}…` : text;
};

const fillSelect = (select, values) => {
  for (const value of values) {
    const option = document.createElement("option");
    option.value = value;
    option.textContent = value;
    select.append(option);
  }
};

const loadParams = () => {
  const params = new URLSearchParams(location.search);
  state.query = params.get("q") || "";
  state.tactic = params.get("tactic") || "";
  state.severity = params.get("severity") || "";
  state.platform = params.get("platform") || "";
  state.priority = params.get("priority") || "";
  state.sort = params.get("sort") || "id";
};

const syncControls = () => {
  elements.search.value = state.query;
  elements.tactic.value = state.tactic;
  elements.severity.value = state.severity;
  elements.platform.value = state.platform;
  elements.priority.value = state.priority;
  elements.sort.value = state.sort;
};

const syncUrl = () => {
  const params = new URLSearchParams();
  if (state.query) params.set("q", state.query);
  if (state.tactic) params.set("tactic", state.tactic);
  if (state.severity) params.set("severity", state.severity);
  if (state.platform) params.set("platform", state.platform);
  if (state.priority) params.set("priority", state.priority);
  if (state.sort !== "id") params.set("sort", state.sort);
  const query = params.toString();
  history.replaceState(null, "", query ? `?${query}` : location.pathname);
};

const matches = (record) => {
  const query = state.query.trim().toLowerCase();
  return (!query || record._search.includes(query))
    && (!state.tactic || normalizeTactic(record) === state.tactic)
    && (!state.severity || record.Severity === state.severity)
    && (!state.platform || record["Operating System"].split(/\s*,\s*/).includes(state.platform))
    && (!state.priority || record.Priority.startsWith(state.priority));
};

const sortRecords = (items) => items.sort((a, b) => {
  if (state.sort === "severity") {
    return (severityRank[b.Severity] || 0) - (severityRank[a.Severity] || 0)
      || a["Hypothesis ID"].localeCompare(b["Hypothesis ID"], undefined, { numeric: true });
  }
  if (state.sort === "tactic") {
    return normalizeTactic(a).localeCompare(normalizeTactic(b))
      || a["Hypothesis ID"].localeCompare(b["Hypothesis ID"], undefined, { numeric: true });
  }
  return a["Hypothesis ID"].localeCompare(b["Hypothesis ID"], undefined, { numeric: true });
});

const cardTemplate = (record) => {
  const id = record["Hypothesis ID"];
  const title = record["Hypothesis Name"] || record["Core Hypothesis Statement"];
  const statement = record["Core Hypothesis Statement"] || title;
  const tactic = normalizeTactic(record);
  const severity = record.Severity || "Unknown";
  return `
    <article class="hypothesis-card">
      <div class="card-top">
        <span class="record-id">${escapeHtml(id)}</span>
        <span class="severity severity-${escapeHtml(severity.toLowerCase())}">${escapeHtml(severity)}</span>
      </div>
      <p class="card-tactic">${escapeHtml(tactic)}</p>
      <h3><a href="details.html?id=${encodeURIComponent(id)}">${escapeHtml(compact(title, 165))}</a></h3>
      <p class="card-statement">${escapeHtml(compact(statement, 260))}</p>
      <div class="card-meta">
        <div><span>Technique</span><strong>${escapeHtml(record["MITRE Technique ID"] || "—")}</strong></div>
        <div><span>Platform</span><strong>${escapeHtml(record["Operating System"] || "—")}</strong></div>
        <div><span>Priority</span><strong>${escapeHtml((record.Priority || "—").split(" (")[0])}</strong></div>
        <div><span>Log source</span><strong>${escapeHtml(record["Required Log Sources"] || "—")}</strong></div>
      </div>
    </article>`;
};

const renderActiveFilters = () => {
  const filters = [
    ["query", state.query ? `Search: ${state.query}` : ""],
    ["tactic", state.tactic],
    ["severity", state.severity],
    ["platform", state.platform],
    ["priority", state.priority],
  ].filter(([, value]) => value);
  elements.active.innerHTML = filters.map(([key, value]) => `
    <span class="filter-chip">${escapeHtml(value)}<button type="button" data-clear="${key}" aria-label="Remove ${escapeHtml(value)} filter">×</button></span>
  `).join("");
};

const render = () => {
  const filtered = sortRecords(records.filter(matches));
  const visible = filtered.slice(0, visibleCount);
  elements.grid.innerHTML = visible.map(cardTemplate).join("");
  elements.grid.hidden = filtered.length === 0;
  elements.empty.hidden = filtered.length !== 0;
  elements.loadMore.hidden = visible.length >= filtered.length;
  elements.summary.innerHTML = `<strong>${filtered.length}</strong> of ${records.length} hypotheses`;
  elements.loadMore.textContent = `Load more hypotheses (${filtered.length - visible.length} remaining)`;
  renderActiveFilters();
  syncUrl();
};

const reset = () => {
  Object.assign(state, { query: "", tactic: "", severity: "", platform: "", priority: "", sort: "id" });
  visibleCount = PAGE_SIZE;
  syncControls();
  render();
};

const renderSignalPanel = () => {
  document.querySelector("#total-count").textContent = payload.meta.total;
  document.querySelector("#search-field-count").textContent = payload.meta.searchableFields;
  document.querySelector("#tactic-count").textContent = payload.meta.tactics;
  document.querySelector("#technique-count").textContent = payload.meta.techniques;
  const counts = Object.entries(records.reduce((acc, record) => {
    const tactic = normalizeTactic(record);
    acc[tactic] = (acc[tactic] || 0) + 1;
    return acc;
  }, {})).sort((a, b) => b[1] - a[1]).slice(0, 4);
  const max = counts[0]?.[1] || 1;
  document.querySelector("#tactic-scan").innerHTML = counts.map(([name, count]) => `
    <div class="tactic-row"><span>${escapeHtml(name)}</span><span class="tactic-bar"><i style="width:${Math.round((count / max) * 100)}%"></i></span><b>${count}</b></div>
  `).join("");
};

const bindControls = () => {
  const map = [[elements.tactic, "tactic"], [elements.severity, "severity"], [elements.platform, "platform"], [elements.priority, "priority"], [elements.sort, "sort"]];
  for (const [element, key] of map) {
    element.addEventListener("change", () => { state[key] = element.value; visibleCount = PAGE_SIZE; render(); });
  }
  elements.search.addEventListener("input", () => { state.query = elements.search.value; visibleCount = PAGE_SIZE; render(); });
  elements.reset.addEventListener("click", reset);
  elements.emptyReset.addEventListener("click", reset);
  elements.loadMore.addEventListener("click", () => { visibleCount += PAGE_SIZE; render(); });
  elements.active.addEventListener("click", (event) => {
    const button = event.target.closest("[data-clear]");
    if (!button) return;
    state[button.dataset.clear] = "";
    visibleCount = PAGE_SIZE;
    syncControls();
    render();
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "/" && !event.ctrlKey && !event.metaKey && !event.altKey && !["INPUT", "TEXTAREA", "SELECT"].includes(document.activeElement.tagName)) {
      event.preventDefault();
      elements.search.focus();
    }
  });
};

const initialize = async () => {
  try {
    const response = await fetch(DATA_URL);
    if (!response.ok) throw new Error(`Dataset request failed: ${response.status}`);
    payload = await response.json();
    records = payload.records.map((record) => ({ ...record, _search: Object.values(record).join(" ").toLowerCase() }));
    fillSelect(elements.tactic, payload.facets.tactics);
    fillSelect(elements.severity, payload.facets.severities);
    fillSelect(elements.platform, payload.facets.platforms);
    fillSelect(elements.priority, payload.facets.priorities);
    loadParams();
    syncControls();
    renderSignalPanel();
    bindControls();
    render();
  } catch (error) {
    elements.summary.textContent = "Dataset unavailable";
    elements.grid.innerHTML = `<div class="empty-state"><h3>Unable to load the catalog</h3><p>${escapeHtml(error.message)}</p><p>Serve this folder through GitHub Pages or a local web server; browsers cannot fetch JSON directly from a file URL.</p></div>`;
  }
};

initialize();
