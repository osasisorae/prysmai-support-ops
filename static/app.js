const bootstrap = window.SUPPORT_OPS_BOOTSTRAP;

const state = {
  sessionId: null,
  totalTurns: bootstrap.total_turns,
  currentTurn: 0,
  blocks: 0,
  tools: 0,
  caseData: null,
  controlPlane: null,
  attribution: null,
};

const caseSelect = document.getElementById("case-select");
const caseSummary = document.getElementById("case-summary");
const primaryModelSelect = document.getElementById("primary-model");
const reviewerModelSelect = document.getElementById("reviewer-model");
const resolverModelSelect = document.getElementById("resolver-model");
const workspace = document.getElementById("workspace");
const startButton = document.getElementById("start-button");
const nextTurnButton = document.getElementById("next-turn-button");
const resolveButton = document.getElementById("resolve-button");
const customerMessage = document.getElementById("customer-message");
const turnTitle = document.getElementById("turn-title");
const attackBanner = document.getElementById("attack-banner");
const actionLog = document.getElementById("action-log");
const statusList = document.getElementById("status-list");
const controlPlaneList = document.getElementById("control-plane-list");
const controlPlaneLog = document.getElementById("control-plane-log");
const attachmentList = document.getElementById("attachment-list");
const agentOutput = document.getElementById("agent-output");
const reviewerOutput = document.getElementById("reviewer-output");
const agentStatus = document.getElementById("agent-status");
const reviewerStatus = document.getElementById("reviewer-status");
const resolutionOutput = document.getElementById("resolution-output");
const attributionStatus = document.getElementById("attribution-status");
const attributionCounts = document.getElementById("attribution-counts");
const attributionList = document.getElementById("attribution-list");

function fillModels(select, selectedId) {
  bootstrap.model_catalog.forEach((model) => {
    const option = document.createElement("option");
    option.value = model.id;
    option.textContent = `${model.name} · ${model.provider}`;
    option.selected = model.id === selectedId;
    select.appendChild(option);
  });
}

function renderCaseSummary(caseData) {
  caseSummary.innerHTML = `
    <strong>${caseData.title}</strong><br>
    ${caseData.issue}<br><br>
    Customer: ${caseData.customer_name} · ${caseData.tier}<br>
    Risk: ${caseData.risk_note}
  `;
}

function renderAttachments() {
  if (!state.caseData?.attachments?.length) {
    attachmentList.innerHTML = "<li>No attachments for this case.</li>";
    return;
  }
  attachmentList.innerHTML = state.caseData.attachments.map((item) => `
    <li>
      <span class="attachment-name">${item.name}</span>
      <div class="attachment-meta">
        <span class="attachment-pill">${item.type}</span>
        <span class="attachment-pill">${item.classification}</span>
      </div>
      <div>${item.summary}</div>
    </li>
  `).join("");
}

function updateMetrics() {
  document.getElementById("metric-blocks").textContent = String(state.blocks);
  document.getElementById("metric-tools").textContent = String(state.tools);
}

function updateStatusList() {
  if (!state.caseData) return;
  statusList.innerHTML = `
    <li>Session: ${state.sessionId || "not started"}</li>
    <li>Case: ${state.caseData.title}</li>
    <li>Customer: ${state.caseData.customer_name}</li>
    <li>Turns completed: ${state.currentTurn}/${state.totalTurns}</li>
    <li>Attachments: ${state.caseData.attachments?.length || 0}</li>
  `;
}

function renderControlPlane() {
  const cp = state.controlPlane;
  if (!cp) {
    controlPlaneList.innerHTML = "<li>Control plane not started</li>";
    return;
  }
  const lastTrace = cp.trace_records && cp.trace_records.length ? cp.trace_records[cp.trace_records.length - 1] : null;
  controlPlaneList.innerHTML = `
    <li>Governance: ${cp.governance_session_id || "not started"}</li>
    <li>MCP: ${cp.connection?.transport || "n/a"} · ${cp.mcp_url || "unavailable"}</li>
    <li>Policies: ${cp.policies?.length || 0}</li>
    <li>Attachments indexed: ${cp.attachments_indexed?.length || 0}</li>
    <li>Behavior checks: ${cp.behavior_checks?.length || 0}</li>
    <li>Code scans: ${cp.code_scans?.length || 0}</li>
    <li>Last trace: ${lastTrace?.trace_id || "none yet"}</li>
  `;
}

function renderAttribution() {
  const data = state.attribution;
  if (!data) {
    attributionStatus.textContent = "No attribution data loaded yet.";
    attributionCounts.innerHTML = "";
    attributionList.innerHTML = "";
    return;
  }

  if (!data.available) {
    attributionStatus.textContent = data.reason || "Live attribution is not available.";
  } else {
    attributionStatus.textContent = `Source: ${data.source} · ${data.trace_ids.length} trace(s) with live attribution.`;
  }

  attributionCounts.innerHTML = `
    <div class="metric-chip"><span class="metric-label">Clean</span><strong>${data.attribution_counts?.clean || 0}</strong></div>
    <div class="metric-chip"><span class="metric-label">Base LLM</span><strong>${data.attribution_counts?.base_llm || 0}</strong></div>
    <div class="metric-chip"><span class="metric-label">Guardrail</span><strong>${data.attribution_counts?.guardrail || 0}</strong></div>
  `;

  const liveRows = (data.spans || []).map((span) => `
    <li data-kind="trace">
      <span class="timeline-pill">${span.attribution}</span>
      ${span.model || "model"} · trace ${span.trace_id} · ${span.guardrail_modified ? "modified" : "unchanged"}
    </li>
  `);

  const inventoryRows = Object.entries(data.trace_inventory || {}).flatMap(([traceId, items]) =>
    items.map((item) => `
      <li data-kind="governance">
        <span class="timeline-pill">trace</span>
        ${traceId} · turn ${item.turn} · ${item.slot} · ${item.model_id} · ${item.threat_level || "unknown"}${item.threat_score != null ? ` (${item.threat_score})` : ""}
      </li>
    `),
  );

  attributionList.innerHTML = (liveRows.length ? liveRows : inventoryRows).join("") || "<li>No trace attribution rows yet.</li>";
}

function appendControlPlaneLine(text, kind = "governance", label = kind) {
  const item = document.createElement("li");
  item.dataset.kind = kind;
  item.innerHTML = `<span class="timeline-pill">${label}</span>${text}`;
  controlPlaneLog.prepend(item);
}

function appendActionLine(text, kind = "tool", label = kind) {
  const item = document.createElement("li");
  item.dataset.kind = kind;
  item.innerHTML = `<span class="timeline-pill">${label}</span>${text}`;
  actionLog.prepend(item);
}

function resetOutputs() {
  agentOutput.textContent = "";
  reviewerOutput.textContent = "";
  agentStatus.textContent = "Waiting";
  reviewerStatus.textContent = "Waiting";
}

async function refreshAttribution() {
  if (!state.sessionId) return;
  try {
    const response = await fetch(`/api/session/${state.sessionId}/attribution`);
    const data = await response.json();
    state.attribution = data;
  } catch (error) {
    state.attribution = {
      available: false,
      source: "error",
      reason: `Failed to load attribution: ${error}`,
      trace_ids: [],
      traces: [],
      spans: [],
      attribution_counts: { clean: 0, base_llm: 0, guardrail: 0 },
      trace_inventory: {},
    };
  }
  renderAttribution();
}

async function startSession() {
  const payload = {
    case_id: caseSelect.value,
    model_config: {
      primary: primaryModelSelect.value,
      reviewer: reviewerModelSelect.value,
      resolver: resolverModelSelect.value,
    },
  };

  startButton.disabled = true;
  startButton.textContent = "Starting...";
  const response = await fetch("/api/session/start", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  const data = await response.json();

  state.sessionId = data.session_id;
  state.caseData = data.case;
  state.currentTurn = 0;
  state.blocks = 0;
  state.tools = 0;
  state.controlPlane = data.control_plane || null;
  state.attribution = null;
  updateMetrics();
  updateStatusList();
  renderControlPlane();
  renderAttachments();
  renderAttribution();

  workspace.classList.remove("hidden");
  resolutionOutput.textContent = "Resolve the case to generate the final summary.";
  actionLog.innerHTML = "";
  controlPlaneLog.innerHTML = "";
  nextTurnButton.classList.add("hidden");
  resolveButton.classList.add("hidden");

  document.getElementById("primary-heading").textContent = `Primary Agent · ${data.slot_models.agent.name}`;
  document.getElementById("reviewer-heading").textContent = `Reviewer · ${data.slot_models.reviewer.name}`;

  startButton.disabled = false;
  startButton.textContent = "Restart Case";
  runTurn(1);
}

function runTurn(turnNumber) {
  state.currentTurn = turnNumber;
  updateStatusList();
  turnTitle.textContent = `Turn ${turnNumber} · ${bootstrap.turns[turnNumber].label}`;
  attackBanner.classList.toggle("hidden", !bootstrap.turns[turnNumber].attack);
  attackBanner.textContent = bootstrap.turns[turnNumber].attack
    ? `Attack turn · ${bootstrap.turns[turnNumber].attack_type.replaceAll("_", " ")}`
    : "";
  nextTurnButton.classList.add("hidden");
  resolveButton.classList.add("hidden");
  resetOutputs();

  const source = new EventSource(`/api/session/${state.sessionId}/turn/${turnNumber}`);

  source.addEventListener("turn_start", (event) => {
    const data = JSON.parse(event.data);
    customerMessage.textContent = data.customer_message;
  });

  source.addEventListener("model_start", (event) => {
    const data = JSON.parse(event.data);
    if (data.model === "agent") {
      agentStatus.textContent = "Streaming";
      agentOutput.textContent = "";
    } else {
      reviewerStatus.textContent = "Streaming";
      reviewerOutput.textContent = "";
    }
  });

  source.addEventListener("token", (event) => {
    const data = JSON.parse(event.data);
    if (data.model === "agent") {
      agentOutput.textContent += data.content;
    } else if (data.model === "reviewer") {
      reviewerOutput.textContent += data.content;
    }
  });

  source.addEventListener("security_blocked", (event) => {
    const data = JSON.parse(event.data);
    state.blocks += 1;
    updateMetrics();
    appendActionLine(`Turn ${turnNumber}: Prysm blocked ${data.model}.`, "security", "blocked");
  });

  source.addEventListener("tool_start", (event) => {
    const data = JSON.parse(event.data);
    appendActionLine(`Turn ${turnNumber}: starting tool ${data.tool}.`, "tool", "tool");
  });

  source.addEventListener("tool_result", (event) => {
    const data = JSON.parse(event.data);
    state.tools += 1;
    updateMetrics();
    appendActionLine(`Turn ${turnNumber}: ${data.tool} → ${data.status}. ${data.summary}`, "tool", "tool");
    appendControlPlaneLine(`Tool call recorded: ${data.tool} (${data.status}).`, "tool", "tool");
  });

  source.addEventListener("attachment_indexed", (event) => {
    const data = JSON.parse(event.data);
    if (state.controlPlane) {
      state.controlPlane.attachments_indexed = state.controlPlane.attachments_indexed || [];
      state.controlPlane.attachments_indexed.push(data);
      renderControlPlane();
    }
    appendActionLine(`Indexed attachment ${data.name} (${data.classification}).`, "attachment", "attachment");
    appendControlPlaneLine(`Recorded attachment file read: ${data.path}.`, "attachment", "attachment");
  });

  source.addEventListener("done", (event) => {
    const data = JSON.parse(event.data);
    if (state.controlPlane) {
      state.controlPlane.trace_records = state.controlPlane.trace_records || [];
      state.controlPlane.trace_records.push({
        turn: turnNumber,
        slot: data.model,
        model_id: data.model_id,
        trace_id: data.trace_id,
        threat_level: data.threat_level,
        threat_score: data.threat_score,
        blocked: Boolean(data.blocked),
      });
      renderControlPlane();
      if (data.trace_id) {
        appendControlPlaneLine(
          `Trace ${data.trace_id} · ${data.model} · ${data.threat_level || "unknown"}${data.threat_score != null ? ` (${data.threat_score})` : ""}`,
          "trace",
          "trace",
        );
      }
    }
    if (data.model === "agent") {
      agentStatus.textContent = data.blocked ? "Blocked" : "Done";
      agentOutput.textContent = data.content || agentOutput.textContent;
    } else if (data.model === "reviewer") {
      reviewerStatus.textContent = data.blocked ? "Blocked" : "Done";
      reviewerOutput.textContent = data.content || reviewerOutput.textContent;
    }
  });

  source.addEventListener("behavior_check", (event) => {
    const data = JSON.parse(event.data);
    if (state.controlPlane) {
      state.controlPlane.behavior_checks = state.controlPlane.behavior_checks || [];
      state.controlPlane.behavior_checks.push(data);
      renderControlPlane();
    }
    appendControlPlaneLine(`Behavior check on turn ${data.turn}: ${data.flags} flag(s).`, "governance", "governance");
  });

  source.addEventListener("code_scan", (event) => {
    const data = JSON.parse(event.data);
    if (state.controlPlane) {
      state.controlPlane.code_scans = state.controlPlane.code_scans || [];
      state.controlPlane.code_scans.push(data);
      renderControlPlane();
    }
    appendControlPlaneLine(
      `Code scan ${data.file_path}: ${data.vulnerability_count} issue(s), max ${data.max_severity}, score ${data.threat_score}.`,
      "scan",
      "scan",
    );
  });

  source.addEventListener("governance_error", (event) => {
    const data = JSON.parse(event.data);
    if (state.controlPlane) {
      state.controlPlane.errors = state.controlPlane.errors || [];
      state.controlPlane.errors.push(data.message);
      renderControlPlane();
    }
    appendControlPlaneLine(`Governance error: ${data.message}`, "security", "error");
  });

  source.addEventListener("turn_end", () => {
    source.close();
    updateStatusList();
    renderControlPlane();
    refreshAttribution();
    if (turnNumber < state.totalTurns) {
      nextTurnButton.classList.remove("hidden");
    } else {
      resolveButton.classList.remove("hidden");
    }
  });
}

async function resolveCase() {
  resolveButton.disabled = true;
  resolveButton.textContent = "Resolving...";
  const response = await fetch(`/api/session/${state.sessionId}/resolve`, { method: "POST" });
  const data = await response.json();
  resolutionOutput.textContent = data.content || JSON.stringify(data, null, 2);
  if (data.control_plane) {
    state.controlPlane = data.control_plane;
    renderControlPlane();
    if (data.control_plane.report?.summary) {
      appendControlPlaneLine(`Governance report: ${data.control_plane.report.summary}`, "governance", "report");
    }
  }
  await refreshAttribution();
  resolveButton.disabled = false;
  resolveButton.textContent = "Resolve Case";
}

bootstrap.cases.forEach((caseData) => {
  const option = document.createElement("option");
  option.value = caseData.id;
  option.textContent = caseData.title;
  caseSelect.appendChild(option);
});

fillModels(primaryModelSelect, bootstrap.default_model_config.primary);
fillModels(reviewerModelSelect, bootstrap.default_model_config.reviewer);
fillModels(resolverModelSelect, bootstrap.default_model_config.resolver);
state.caseData = bootstrap.cases[0];
renderCaseSummary(state.caseData);
updateStatusList();
renderControlPlane();
renderAttachments();
renderAttribution();

caseSelect.addEventListener("change", () => {
  state.caseData = bootstrap.cases.find((item) => item.id === caseSelect.value);
  renderCaseSummary(state.caseData);
  updateStatusList();
  renderAttachments();
});

startButton.addEventListener("click", startSession);
nextTurnButton.addEventListener("click", () => runTurn(state.currentTurn + 1));
resolveButton.addEventListener("click", resolveCase);
