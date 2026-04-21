const bootstrap = window.SUPPORT_OPS_BOOTSTRAP;

const state = {
  sessionId: null,
  totalTurns: bootstrap.total_turns,
  currentTurn: 0,
  blocks: 0,
  tools: 0,
  caseData: null,
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
const agentOutput = document.getElementById("agent-output");
const reviewerOutput = document.getElementById("reviewer-output");
const agentStatus = document.getElementById("agent-status");
const reviewerStatus = document.getElementById("reviewer-status");
const resolutionOutput = document.getElementById("resolution-output");

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
  `;
}

function appendActionLine(text) {
  const item = document.createElement("li");
  item.textContent = text;
  actionLog.prepend(item);
}

function resetOutputs() {
  agentOutput.textContent = "";
  reviewerOutput.textContent = "";
  agentStatus.textContent = "Waiting";
  reviewerStatus.textContent = "Waiting";
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
  updateMetrics();
  updateStatusList();

  workspace.classList.remove("hidden");
  resolutionOutput.textContent = "Resolve the case to generate the final summary.";
  actionLog.innerHTML = "";
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
    appendActionLine(`Turn ${turnNumber}: Prysm blocked ${data.model}.`);
  });

  source.addEventListener("tool_start", (event) => {
    const data = JSON.parse(event.data);
    appendActionLine(`Turn ${turnNumber}: starting tool ${data.tool}.`);
  });

  source.addEventListener("tool_result", (event) => {
    const data = JSON.parse(event.data);
    state.tools += 1;
    updateMetrics();
    appendActionLine(`Turn ${turnNumber}: ${data.tool} → ${data.status}. ${data.summary}`);
  });

  source.addEventListener("done", (event) => {
    const data = JSON.parse(event.data);
    if (data.model === "agent") {
      agentStatus.textContent = data.blocked ? "Blocked" : "Done";
      agentOutput.textContent = data.content || agentOutput.textContent;
    } else if (data.model === "reviewer") {
      reviewerStatus.textContent = data.blocked ? "Blocked" : "Done";
      reviewerOutput.textContent = data.content || reviewerOutput.textContent;
    }
  });

  source.addEventListener("turn_end", () => {
    source.close();
    updateStatusList();
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

caseSelect.addEventListener("change", () => {
  state.caseData = bootstrap.cases.find((item) => item.id === caseSelect.value);
  renderCaseSummary(state.caseData);
  updateStatusList();
});

startButton.addEventListener("click", startSession);
nextTurnButton.addEventListener("click", () => runTurn(state.currentTurn + 1));
resolveButton.addEventListener("click", resolveCase);
