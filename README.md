# PrysmAI Support Ops

`prysmai-support-ops` is a FastAPI example app that simulates a high-risk customer support operations desk routed through PrysmAI.

It is designed to exercise the parts of Prysm that matter in production:

- proxy-routed LLM traffic through the Python SDK
- multi-model slot selection
- per-turn tracing metadata via `prysm_context`
- prompt injection blocking on hostile customer messages
- PII-heavy customer contexts
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
- security-block events when Prysm stops a malicious request

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

The app uses a placeholder key if none is set so the module can still import during local testing, but live model calls require a real Prysm key.

## Tests

```bash
pytest
```

The included tests use `fastapi.testclient.TestClient`, so PrysmAI's dynamic audit recognizes the repo as having a self-contained in-process integration path.
