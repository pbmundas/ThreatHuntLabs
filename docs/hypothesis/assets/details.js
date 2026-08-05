const DATA_URL = "data/hypotheses.json";
const canonicalTactics = ["Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact"];
const normalizeTactic = (record) => {
  const raw = `${record["MITRE ATT&CK Tactic"] || ""} ${record["Threat Category"] || ""}`;
  const match = canonicalTactics.find((tactic) => raw.toLowerCase().includes(tactic.toLowerCase()));
  if (match) return match;
  if (/command and scripting interpreter/i.test(raw)) return "Execution";
  if (/stealth/i.test(raw)) return "Defense Evasion";
  return "Multiple";
};

const fieldGroups = {
  overview: [
    "Threat Actor Behavior", "Attack Objective", "Attack Flow Summary", "Initial Indicators", "Behavioral Indicators", "Risk Explanation", "Business Impact",
  ],
  requirements: [
    "Prerequisites", "Required Data Sources", "Required Log Sources", "Required Event IDs", "Required EDR Telemetry", "Required Network Telemetry", "Required Cloud Telemetry", "Required Identity Logs", "Environment", "Target Assets", "Operating System", "Baseline Recommendations", "Filtering Strategy",
  ],
  detection: [
    "Detection Logic", "Threat Hunting Strategy", "Anomaly Detection Strategy", "Investigation Steps", "Evidence to Collect", "Threat Confirmation Criteria", "False Positive Scenarios", "Known Legitimate Processes", "Suspicious Parent Processes", "Suspicious Child Processes", "Suspicious Process Paths", "Suspicious Command Lines",
  ],
  queries: [
    "Sigma Rule Suggestions", "YARA Rule Suggestions", "Splunk Query", "Microsoft Sentinel KQL", "Elastic KQL", "Kibana KQL", "Microsoft Defender XDR Query", "CrowdStrike Query", "Carbon Black Query", "Sysmon Detection Logic", "Windows Security Detection Logic", "Linux Detection Logic", "macOS Detection Logic", "Azure Detection", "AWS Detection", "GCP Detection",
  ],
  artifacts: [
    "Registry Artifacts", "File Artifacts", "Memory Artifacts", "Persistence Artifacts", "Network Indicators", "IOC Examples",
  ],
  response: [
    "Response Actions", "Containment Actions", "Eradication Actions", "Recovery Steps",
  ],
  references: [
    "MITRE ATT&CK References", "Additional References", "Notes",
  ],
};

const isUseful = (value) => {
  const text = String(value || "").trim();
  return text && !/^N\/A\b/i.test(text) && !/^Not applicable\b/i.test(text);
};

const severityClass = (severity) => `severity severity-${String(severity || "unknown").toLowerCase()}`;

const createField = (label, value) => {
  const block = document.createElement("article");
  block.className = "field-block";
  const heading = document.createElement("h3");
  heading.textContent = label;
  const paragraph = document.createElement("p");
  paragraph.textContent = value;
  block.append(heading, paragraph);
  return block;
};

const copyText = async (text) => {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const textarea = document.createElement("textarea");
    textarea.value = text;
    textarea.style.position = "fixed";
    textarea.style.opacity = "0";
    document.body.append(textarea);
    textarea.select();
    document.execCommand("copy");
    textarea.remove();
  }
};

const createQuery = (label, value) => {
  const block = document.createElement("article");
  block.className = "query-block";
  const head = document.createElement("div");
  head.className = "query-head";
  const heading = document.createElement("h3");
  heading.textContent = label;
  const button = document.createElement("button");
  button.type = "button";
  button.textContent = "Copy";
  button.addEventListener("click", async () => {
    await copyText(value);
    button.textContent = "Copied";
    setTimeout(() => { button.textContent = "Copy"; }, 1600);
  });
  const pre = document.createElement("pre");
  pre.textContent = value;
  head.append(heading, button);
  block.append(head, pre);
  return block;
};

const setText = (selector, value) => { document.querySelector(selector).textContent = value || "—"; };

const renderFacts = (record) => {
  const facts = [
    ["Threat category", record["Threat Category"]],
    ["ATT&CK technique", record["MITRE Technique ID"]],
    ["Platform", record["Operating System"]],
    ["Priority", (record.Priority || "").split(" (")[0]],
    ["Target assets", record["Target Assets"]],
  ];
  const container = document.querySelector("#quick-facts");
  for (const [label, value] of facts) {
    const fact = document.createElement("div");
    fact.className = "fact";
    const span = document.createElement("span");
    span.textContent = label;
    const strong = document.createElement("strong");
    strong.textContent = value || "—";
    fact.append(span, strong);
    container.append(fact);
  }
};

const renderGroups = (record) => {
  for (const [group, fields] of Object.entries(fieldGroups)) {
    const container = document.querySelector(`[data-section="${group}"]`);
    let rendered = 0;
    for (const field of fields) {
      const value = record[field];
      if (!isUseful(value)) continue;
      container.append(group === "queries" ? createQuery(field, value) : createField(field, value));
      rendered += 1;
    }
    if (!rendered) container.append(createField("Status", "No applicable data is specified for this hypothesis."));
  }
};

const firstUrl = (value) => String(value || "").match(/https?:\/\/[^\s|]+/)?.[0] || "";

const renderRecord = (payload, record) => {
  const id = record["Hypothesis ID"];
  document.title = `${id}: ${record["Hypothesis Name"]} — HUNTGRID`;
  const kicker = document.querySelector("#record-kicker");
  const idTag = document.createElement("span");
  idTag.className = "record-id";
  idTag.textContent = id;
  const severityTag = document.createElement("span");
  severityTag.className = severityClass(record.Severity);
  severityTag.textContent = record.Severity;
  const tacticTag = document.createElement("span");
  tacticTag.className = "card-tactic";
  tacticTag.style.margin = "0";
  tacticTag.textContent = normalizeTactic(record);
  kicker.append(idTag, severityTag, tacticTag);
  setText("#record-title", record["Hypothesis Name"]);
  setText("#record-statement", record["Core Hypothesis Statement"]);

  const mitreUrl = firstUrl(record["MITRE ATT&CK References"]);
  const mitreLink = document.querySelector("#mitre-link");
  if (mitreUrl) mitreLink.href = mitreUrl;
  else mitreLink.hidden = true;

  document.querySelector("#copy-link").addEventListener("click", async (event) => {
    await copyText(location.href);
    event.currentTarget.textContent = "Link copied";
    setTimeout(() => { event.currentTarget.textContent = "Copy record link"; }, 1600);
  });

  renderFacts(record);
  renderGroups(record);

  const index = payload.records.findIndex((item) => item["Hypothesis ID"] === id);
  const previous = payload.records[index - 1];
  const next = payload.records[index + 1];
  const previousLink = document.querySelector("#previous-record");
  const nextLink = document.querySelector("#next-record");
  if (previous) previousLink.href = `details.html?id=${encodeURIComponent(previous["Hypothesis ID"])}`;
  else previousLink.setAttribute("aria-disabled", "true");
  if (next) nextLink.href = `details.html?id=${encodeURIComponent(next["Hypothesis ID"])}`;
  else nextLink.setAttribute("aria-disabled", "true");

  document.querySelector("#detail-loading").hidden = true;
  document.querySelector("#detail-content").hidden = false;
};

const initialize = async () => {
  const id = new URLSearchParams(location.search).get("id");
  try {
    const response = await fetch(DATA_URL);
    if (!response.ok) throw new Error("Dataset unavailable");
    const payload = await response.json();
    const record = payload.records.find((item) => item["Hypothesis ID"].toLowerCase() === String(id || "").toLowerCase());
    if (!record) throw new Error("not-found");
    renderRecord(payload, record);
  } catch (error) {
    document.querySelector("#detail-loading").hidden = true;
    document.querySelector("#record-not-found").hidden = false;
    if (error.message !== "not-found") document.querySelector("#record-not-found p").textContent = "The dataset could not be loaded. Serve this folder through GitHub Pages or a local web server.";
  }
};

initialize();
