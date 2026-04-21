from fastapi.testclient import TestClient

import app as app_module

app = app_module.app

client = TestClient(app)


def test_homepage_loads():
    response = client.get("/")
    assert response.status_code == 200, response.text
    assert "PrysmAI Support Ops" in response.text


def test_start_session_and_status_flow():
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

    status = client.get(f"/api/session/{data['session_id']}/status")
    assert status.status_code == 200, status.text
    session = status.json()
    assert session["status"] == "active"
    assert session["current_turn"] == 0
    assert session["total_turns"] >= 1


def test_turn_stream_and_resolve_flow(monkeypatch):
    def fake_turn_stream(**kwargs):
        turn = kwargs["turn_num"]
        yield {"type": "turn_start", "turn": turn, "turn_label": "Intake Triage", "customer_message": "hello"}
        yield {"type": "model_start", "model": "agent", "model_id": "llama-3.3-70b-versatile", "model_name": "Llama 3.3 70B"}
        yield {"type": "token", "model": "agent", "content": "We can help."}
        yield {
            "type": "done",
            "model": "agent",
            "content": "We can help.",
            "blocked": False,
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
        }
        yield {
            "type": "turn_end",
            "turn": turn,
            "agent_preview": "We can help.",
            "reviewer_preview": "Decision: APPROVE",
            "agent_blocked": False,
            "reviewer_blocked": False,
        }

    def fake_resolve_case(**kwargs):
        return {"content": "Case resolved safely.", "model": "resolver"}

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
    assert status_data["actions_logged"] == 1
    assert status_data["turns_completed"] == 1

    resolve = client.post(f"/api/session/{session_id}/resolve")
    assert resolve.status_code == 200, resolve.text
    assert resolve.json()["content"] == "Case resolved safely."
