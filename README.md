# PrysmAI Support Ops

`prysmai-support-ops` is a FastAPI example app that simulates a high-risk customer support operations desk routed through PrysmAI.

It is designed to exercise the parts of Prysm that matter in production:

- proxy-routed LLM traffic through the Python SDK
- multi-model slot selection
- per-turn tracing metadata via `prysm_context`
- trace headers surfaced back into the app (`trace_id`, threat level, threat score)
- MCP connection discovery and policy/resource reads
- governance session lifecycle for the full case
- explicit recording of tool calls, file reads/writes, and reviewer decisions
- policy/resource drill-down in the operator UI
- explicit human approval gate for risky actions
- behavioral checks during the workflow
- code scanning against a risky automation snippet
- prompt injection blocking on hostile customer messages
- PII-heavy customer contexts
- attachment ingestion with operator-visible evidence
- risky operational actions like refunds and account changes
- human-review style second-model oversight
- end-of-case resolver summary

## Demo Flow

The app runs a case through multiple turns:

1. intake and customer lookup
2. KB retrieval and response drafting
3. attack round: jailbreak / malicious instruction
4. refund and entitlement policy checks
5. attack round: system prompt extraction
6. high-risk billing / financial action review
7. attack round: role hijack / account takeover request
8. attack round: data exfiltration / credentials request

Then the operator can generate a case resolution summary.

Each turn streams:

- primary agent output
- reviewer output
- local mock tool activity
- attachment indexing events for uploaded case artifacts
- governance behavior-check events
- code-scan events during the financial review turn
- security-block events when Prysm stops a malicious request

The UI also shows a control-plane pane with:

- governance session ID
- MCP transport details
- active policy/resource snapshots
- recorded traces
- behavior checks
- code-scan findings

Risky turns can also enter an approval gate. When the reviewer escalates or a tool lands in a queued/manual-review state, the operator must explicitly approve or deny the action before the case can continue to resolution.

## Run Locally

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
uvicorn app:app --reload
```

Open `http://localhost:8000`.

## Environment

Required:

- `PRYSM_API_KEY`

Optional:

- `PRYSM_BASE_URL`
- `PRYSM_BACKEND_URL`
- `PRYSM_CONTROL_BASE_URL`
- `PRYSM_USER_BEARER_TOKEN`

The app uses a placeholder key if none is set so the module can still import during local testing, but live model calls require a real Prysm key.

By default the app uses `PRYSM_BASE_URL` for proxy-routed model traffic and derives a separate control-plane host from `PRYSM_BACKEND_URL` for governance, MCP, and attribution calls. If your deployment splits those hosts in a different way, set `PRYSM_CONTROL_BASE_URL` explicitly.

If `PRYSM_USER_BEARER_TOKEN` is set, the app will also call Prysm's live `/traces/{trace_id}/attribution` endpoint for the traces generated during the session. Without it, the Attribution View still shows the recorded trace inventory but explains that live attribution is unavailable.

## Tests

```bash
pytest
```

The included tests use `fastapi.testclient.TestClient`, so PrysmAI's dynamic audit recognizes the repo as having a self-contained in-process integration path.
