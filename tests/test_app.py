from fastapi.testclient import TestClient

import app as app_module

app = app_module.app

client = TestClient(app)


def _fake_control_plane():
    return {
        "enabled": True,
        "mcp_url": "https://prysmai.example/api/mcp",
        "connection": {
            "server_url": "https://prysmai.example/api/mcp",
            "transport": "streamable_http",
        },
        "policies": [{"id": "prompt-injection", "name": "Prompt Injection Defense"}],
        "resources": [{"uri": "prysm://policies", "name": "Policies"}],
        "governance_session_id": "gov-test-1",
        "governance": object(),
        "mcp": object(),
        "trace_records": [],
        "tool_calls": [],
        "file_events": [],
        "attachments_indexed": [],
        "decisions": [],
        "behavior_checks": [],
        "code_scans": [],
        "report": {},
        "errors": [],
    }


def test_homepage_loads():
    response = client.get("/")
    assert response.status_code == 200, response.text
    assert "PrysmAI Support Ops" in response.text


def test_start_session_and_status_flow(monkeypatch):
    monkeypatch.setattr(app_module, "init_control_plane_session", lambda **kwargs: _fake_control_plane())
    monkeypatch.setattr(
        app_module,
        "get_session_attribution",
        lambda control_plane: {
            "available": False,
            "source": "unavailable",
            "reason": "Set PRYSM_USER_BEARER_TOKEN to fetch live hallucination attribution from Prysm.",
            "trace_ids": [],
            "traces": [],
            "spans": [],
            "attribution_counts": {"clean": 0, "base_llm": 0, "guardrail": 0},
            "trace_inventory": {},
        },
    )
    payload = {
        "case_id": "chargeback-triangle",
        "model_config": {
            "primary": "llama-3.3-70b-versatile",
            "reviewer": "llama-3.1-8b-instant",
            "resolver": "llama-3.3-70b-versatile",
        },
    }
    start = client.post("/api/session/start", json=payload)
    assert start.status_code == 200, start.text
    data = start.json()
    assert data["case"]["id"] == payload["case_id"]
    assert data["status"] == "active"
    assert data["session_id"]
    assert data["slot_models"]["agent"]["id"] == payload["model_config"]["primary"]
    assert data["control_plane"]["governance_session_id"] == "gov-test-1"
    assert len(data["case"]["attachments"]) >= 1

    status = client.get(f"/api/session/{data['session_id']}/status")
    assert status.status_code == 200, status.text
    session = status.json()
    assert session["status"] == "active"
    assert session["current_turn"] == 0
    assert session["total_turns"] >= 1
    assert session["control_plane"]["enabled"] is True

    control_plane = client.get(f"/api/session/{data['session_id']}/control-plane")
    assert control_plane.status_code == 200, control_plane.text
    assert control_plane.json()["governance_session_id"] == "gov-test-1"

    attribution = client.get(f"/api/session/{data['session_id']}/attribution")
    assert attribution.status_code == 200, attribution.text
    assert attribution.json()["available"] is False


def test_turn_stream_and_resolve_flow(monkeypatch):
    monkeypatch.setattr(app_module, "init_control_plane_session", lambda **kwargs: _fake_control_plane())
    monkeypatch.setattr(
        app_module,
        "get_session_attribution",
        lambda control_plane: {
            "available": True,
            "source": "live",
            "reason": "",
            "trace_ids": ["trace-agent-1", "trace-reviewer-1"],
            "traces": [],
            "spans": [{"trace_id": "trace-agent-1", "attribution": "clean", "guardrail_modified": False, "model": "llama-3.3-70b-versatile"}],
            "attribution_counts": {"clean": 1, "base_llm": 0, "guardrail": 0},
            "trace_inventory": {
                "trace-agent-1": [{"turn": 1, "slot": "agent", "model_id": "llama-3.3-70b-versatile"}],
            },
        },
    )

    def fake_turn_stream(**kwargs):
        turn = kwargs["turn_num"]
        yield {"type": "turn_start", "turn": turn, "turn_label": "Intake Triage", "customer_message": "hello"}
        yield {
            "type": "attachment_indexed",
            "turn": turn,
            "id": "invoice-diff",
            "name": "invoice-diff.csv",
            "attachment_type": "billing_export",
            "classification": "internal-finance",
            "summary": "Loaded invoice attachment.",
            "path": "attachments/invoice-diff.csv",
        }
        yield {"type": "model_start", "model": "agent", "model_id": "llama-3.3-70b-versatile", "model_name": "Llama 3.3 70B"}
        yield {"type": "token", "model": "agent", "content": "We can help."}
        yield {
            "type": "done",
            "model": "agent",
            "content": "We can help.",
            "blocked": False,
            "trace_id": "trace-agent-1",
            "threat_level": "low",
            "threat_score": 5,
        }
        yield {"type": "tool_result", "tool": "lookup_customer", "status": "success", "summary": "Loaded record."}
        yield {
            "type": "model_start",
            "model": "reviewer",
            "model_id": "llama-3.1-8b-instant",
            "model_name": "Llama 3.1 8B",
        }
        yield {"type": "token", "model": "reviewer", "content": "Decision: APPROVE"}
        yield {
            "type": "done",
            "model": "reviewer",
            "content": "Decision: APPROVE",
            "blocked": False,
            "trace_id": "trace-reviewer-1",
            "threat_level": "low",
            "threat_score": 4,
        }
        yield {"type": "behavior_check", "turn": turn, "flags": 0, "recommendations": [], "violations": []}
        yield {
            "type": "turn_end",
            "turn": turn,
            "agent_preview": "We can help.",
            "reviewer_preview": "Decision: APPROVE",
            "agent_blocked": False,
            "reviewer_blocked": False,
        }

    def fake_resolve_case(**kwargs):
        return {
            "content": "Case resolved safely.",
            "model": "resolver",
            "control_plane": {
                "enabled": True,
                "governance_session_id": "gov-test-1",
                "trace_records": [{"trace_id": "trace-resolver-1"}],
                "behavior_checks": [{"turn": 1, "flags": 0}],
                "code_scans": [],
                "tool_calls": [],
                "file_events": [],
                "attachments_indexed": [{"name": "invoice-diff.csv"}],
                "decisions": [],
                "policies": [],
                "resources": [],
                "report": {"behavior_score": 95, "summary": "Session completed cleanly."},
                "errors": [],
                "mcp_url": "https://prysmai.example/api/mcp",
                "connection": {"server_url": "https://prysmai.example/api/mcp", "transport": "streamable_http"},
            },
        }

    monkeypatch.setattr(app_module, "run_support_turn_streaming", fake_turn_stream)
    monkeypatch.setattr(app_module, "resolve_case", fake_resolve_case)

    start = client.post("/api/session/start", json={"case_id": "chargeback-triangle"})
    assert start.status_code == 200, start.text
    session_id = start.json()["session_id"]

    with client.stream("GET", f"/api/session/{session_id}/turn/1") as response:
        body = "".join(chunk.decode() if isinstance(chunk, bytes) else chunk for chunk in response.iter_text())
    assert response.status_code == 200
    assert "event: turn_start" in body
    assert "event: done" in body
    assert "Loaded record." in body

    status = client.get(f"/api/session/{session_id}/status")
    assert status.status_code == 200, status.text
    status_data = status.json()
    assert status_data["current_turn"] == 1
    assert status_data["actions_logged"] == 3
    assert status_data["turns_completed"] == 1
    assert status_data["control_plane"]["governance_session_id"] == "gov-test-1"

    resolve = client.post(f"/api/session/{session_id}/resolve")
    assert resolve.status_code == 200, resolve.text
    assert resolve.json()["content"] == "Case resolved safely."
    assert resolve.json()["control_plane"]["report"]["behavior_score"] == 95

    attribution = client.get(f"/api/session/{session_id}/attribution")
    assert attribution.status_code == 200, attribution.text
    assert attribution.json()["attribution_counts"]["clean"] == 1
