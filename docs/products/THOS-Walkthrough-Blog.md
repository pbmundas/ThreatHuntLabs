# Inside THOS: A Walkthrough of the AI Agentic Threat Hunting Operating System

Most "AI in security" pitches ask you to rip out your SIEM, migrate your data, and trust a black box to tell you what's wrong. THOS takes a different position: keep your existing SIEM, EDR, and telemetry sources exactly where they are, and add an evidence-governed hunting layer on top of them. It's a local-first platform built for analysts who need hypothesis-driven threat hunting, log investigation, detection monitoring, digital forensics, risk management, and threat-intelligence correlation — without shipping data to a cloud model or trusting an LLM to freelance a verdict.

This walkthrough covers what THOS actually does, how a hunt moves through the system, and what to expect if you stand it up yourself.

## The core idea: evidence before reasoning

THOS combines deterministic security controls with locally hosted agent models. Telemetry and submitted evidence get collected, normalized, bounded, and verified *before* any model reasoning is allowed to produce a finding or report. If the evidence doesn't support a conclusion, THOS records that outcome instead of manufacturing one. That "negative-evidence gate" shows up throughout the platform — no supported evidence means no report, not a hedged one.

This matters in practice: a no-match result from a scan tool is treated as inconclusive, not proof that an artifact is benign. Nothing gets waved through just because a model didn't find anything.

## A tour of the workspace

THOS organizes the analyst experience into task-focused workspaces, in the same order as the actual investigative workflow:

- **Overview** — security-impact KPIs, operating efficiency, service health, and recent activity for a selected period.
- **Hunt Board** — search HEARTH and locally authored hunt hypotheses, review ATT&CK mappings and run history, launch hunts, and follow timestamped agent progress in real time.
- **Forensic** — upload and preserve evidence, examine logs and artifacts, run file or memory analysis, build timelines, and generate evidence-backed forensic reports.
- **Reports** — search hunt and forensic reports, filter by age, preview investigations, and download as Markdown or styled PDF.
- **Risks** — review automatically materialized, evidence-backed risks, filter by period or state, inspect affected entities, and resolve risks (Admin/SME).
- **Detections** — review scheduled detections, unique detection IDs, matched source events, and expandable AI-assisted analysis.
- **Threat Intelligence** — manage IOC sources, monitor freshness, search local indicators, and correlate intelligence against evidence.
- **Log Search** — write a portable correlation query once, and let THOS translate it for whichever SIEM is connected.
- **Integrations** — configure governed SIEM and direct security-source connections, and test connectivity.
- **Configurations** — account, runtime, model routing, rules, schedules, audit logs, knowledge, users, roles, and permissions.

There's also **Ask THOS**, a read-only assistant for security questions that can delegate bounded work to the hunt and forensic specialists rather than answering from thin air.

## Log Search without learning five query languages

One of the more practically useful pieces is the portable Log Search workspace. Instead of memorizing SPL for Splunk, AQL for QRadar, and OpenSearch DSL for Wazuh, an analyst writes one normalized expression — either KQL-like syntax or plain language:

```text
process_name == "powershell.exe" and command_line contains "-enc"
```

or

```text
Find the same user authenticating from multiple source IPs followed by privileged process execution.
```

THOS grounds the expression against the selected source's actual field mappings, translates it in the background into the target syntax, executes it read-only with the chosen lookback and row limit, and returns normalized records — exportable straight to Excel. Under the hood it currently targets Wazuh (OpenSearch DSL), Elasticsearch, Splunk (SPL), IBM QRadar (AQL), LogRhythm, and folder-based evidence. Field semantics are handled carefully here too — for Wazuh, a normalized `message` maps to the raw `full_log` field rather than the rule description, so a keyword search actually searches the right place.

## How a hunt actually runs

A THOS hunt follows a defined pipeline rather than an open-ended prompt-and-pray loop:

```text
Knowledge refresh
  -> Hypothesis selection and prior hunt memory
  -> Supervisor plan
  -> Portable query generation and source-specific translation
  -> Bounded SIEM or folder retrieval
  -> Normalization, deduplication, and guardrails
  -> Detection, artifact, IOC, and behavior checks
  -> ATT&CK coverage and intelligence correlation
  -> Adaptive retrieval when supported evidence requires it
  -> Negative-evidence gate
       -> no supported evidence: retain outcome; create no report
       -> supported evidence: local reasoning
  -> Citation and record-reference verification
  -> Detection-engineering proposal
  -> Audience-aware communication
  -> Evidence-backed report
  -> Automatic risk refresh
```

Only one interactive hunt runs at a time per session, but it keeps executing server-side even if the analyst navigates away — the active-hunt banner reopens the live progress view. If a model response comes back malformed despite supported evidence existing, THOS retries within bounds; a persistent failure gets recorded honestly rather than papered over with a generic conclusion.

## Risks: a materialized view, not a raw feed

The Risks page isn't a dump of every report or detection — it's a curated, evidence-backed snapshot. THOS refreshes it automatically after verified hunt reports and positive scheduled detections are persisted, and again on orchestrator startup.

To become a live risk, a finding has to pass deterministic citation verification, complete model reasoning, and generate successfully. Explicitly negative findings ("no evidence observed") are excluded, and broad or unrelated detection matches get rejected if the raw records don't actually support the rule. The model owns the risk's explanation, affected entity, and severity scoring; deterministic code independently validates the references, entity grounding, schema, and score consistency. Admins and SMEs can resolve risks, which moves them to inactive without deleting history — every resolution is stored with actor, timestamp, and note.

## Digital forensics, built on real tooling

The forensic workspace streams submitted evidence into managed case storage, recording original name, stored name, SHA-256 hash, size, collector, and acquisition notes, then verifies integrity before anything else happens. From there, a planning agent decides whether deeper memory, disk, executable, registry, or document analysis is warranted.

Supported artifact types include PE/ELF executables, DLLs, scripts, PDFs, Office/OLE documents, archives, registry hives, and raw/VM/LiME memory images, processed with established tools — YARA, capa, FLOSS, pefile, ExifTool, ClamAV, oletools, Volatility 3, RegRipper, libewf, and The Sleuth Kit among them. Tool processes run with fixed argument arrays (no shell), timeouts, and resource caps, and submitted samples are preserved but never executed by THOS itself.

## Architecture, in brief

```
Analyst (React workspace)
   -> FastAPI UI gateway (signed session, role, feature, route checks)
   -> LangGraph orchestrator (agents, tools, model routing)
   -> Connectors (bounded retrieval from active sources)
   -> PostgreSQL / Redis / ChromaDB (state, cache, semantic retrieval)
```

The platform runs as a set of Docker services — `chat-ui`, `orchestrator`, `mcp`, `ollama`, `chromadb`, `postgres`, and `redis` — with only `chat-ui` published by default. Model inference is entirely local via Ollama, with task-specific routing for fast, reasoning, verification, coding, and guard tasks, so no cloud model API is required.

Security boundaries are explicit rather than implied: signed HttpOnly sessions, API-key auth between internal services, read-only bounded SIEM operations, allowlisted evidence roots, prompt-injection screening, and — notably — **no** autonomous host isolation, traffic blocking, evidence deletion, live-rule deployment, or attribution. THOS surfaces findings; it doesn't act on the network unsupervised.

## Getting it running

For a small deployment, plan for 8 x86-64 CPU cores, 16 GB RAM, 50 GB SSD, and Docker Compose. For real daily use, 12–16 cores, 32 GB RAM, 100+ GB SSD, and a GPU with 8–12 GB VRAM for the reasoning model is the recommended baseline.

The quick-start path is a standard clone-and-configure flow:

```bash
git clone <repository-url>
cd AI-Threat-Hunting-Docker
cp env.example .env
```

Before first boot, you set unique secrets — `MCP_AUTH_TOKEN`, `ORCHESTRATOR_API_KEY`, `CHATUI_SESSION_SECRET`, `REDIS_PASSWORD`, `POSTGRES_PASSWORD`, and initial admin credentials — then bring it up:

```bash
docker compose up -d --build
docker compose ps
```

The UI is available at `http://localhost:7860`. The safe default telemetry source is local folder evidence; you configure and test a live SIEM connection under **Integrations** before pointing hunts, schedules, or Log Search at it.

## Licensing

THOS 1.0 ships source-available under the **Business Source License 1.1 (BUSL-1.1)**. You can use, modify, and self-host it for internal purposes, but commercial hosting or managed-service offerings require a separate license. Each release converts to **Apache 2.0** four years after it's first published.

## Where to go next

- **Product page:** [THOS — AI Agentic Threat Hunting Operating System](https://threathuntlabs.com/products/AI-Agentic-THOS-Threat-Hunting-Operating-System.html)
- **README reference:** the full project README documents the workspace-by-workspace feature set, route table, threat-hunting pipeline, forensic tool matrix, network allowlist, and operational configuration referenced throughout this walkthrough.

THOS is aimed squarely at teams who want an AI hunting layer without giving up control of their SIEM, their evidence, or their audit trail — the design choices (local inference, deterministic gates, fail-closed connectors) all point the same direction: augment the hunter, don't replace the accountability.
