"""
PrysmAI Support Ops — FastAPI application.

Simulates a support-operations control room with streamed agent/reviewer output,
mock tool activity, hostile customer messages, and case resolution summaries.
"""

import json
import uuid

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

try:
    from sse_starlette.sse import EventSourceResponse
except ModuleNotFoundError:
    def _format_sse_event(message: dict) -> str:
        event_name = message.get("event", "message")
        data = str(message.get("data", ""))
        lines = [f"event: {event_name}"]
        lines.extend(f"data: {line}" for line in data.splitlines() or [""])
        return "\n".join(lines) + "\n\n"


    class EventSourceResponse(StreamingResponse):
        def __init__(self, content, **kwargs):
            def iterator():
                for message in content:
                    if isinstance(message, dict):
                        yield _format_sse_event(message)
                    else:
                        yield message

            super().__init__(iterator(), media_type="text/event-stream", **kwargs)

from support_engine import (
    DEFAULT_MODEL_CONFIG,
    MODEL_CATALOG,
    PRESET_CASES,
    TOTAL_TURNS,
    TURN_DEFINITIONS,
    build_slot_models,
    get_session_attribution,
    init_control_plane_session,
    normalize_case_id,
    normalize_model_config,
    resolve_case,
    run_support_turn_streaming,
    serialize_control_plane_state,
)

app = FastAPI(title="PrysmAI Support Ops", version="1.0.0")
app.mount("/static", StaticFiles(directory="static"), name="static")
try:
    templates = Jinja2Templates(directory="templates")
except AssertionError:
    templates = None

sessions: dict[str, dict] = {}


def _default_approval_state() -> dict:
    return {
        "status": "not_required",
        "pending": False,
        "turn": None,
        "tool_name": None,
        "reason": "",
        "reviewer_decision": None,
        "resolution": None,
        "note": "",
        "history": [],
    }


def _build_approval_state(
    session: dict,
    *,
    turn_num: int,
    reviewer_decision: str | None,
    tool_name: str | None,
    tool_status: str | None,
    attack: bool,
) -> dict:
    current = session.get("approval") or _default_approval_state()

    needs_review = (
        not attack
        and (
            reviewer_decision in {"ESCALATE", "DENY"}
            or tool_status in {"queued", "manual_review"}
        )
    )
    if not needs_review:
        return current

    reason_parts = []
    if reviewer_decision in {"ESCALATE", "DENY"}:
        reason_parts.append(f"Reviewer decision: {reviewer_decision}")
    if tool_status in {"queued", "manual_review"}:
        reason_parts.append(f"Tool status: {tool_status}")

    state = {
        "status": "pending",
        "pending": True,
        "turn": turn_num,
        "tool_name": tool_name,
        "reason": " | ".join(reason_parts) or "Manual approval required for this action.",
        "reviewer_decision": reviewer_decision,
        "resolution": None,
        "note": "",
        "history": list(current.get("history", [])),
    }
    state["history"].append(
        {
            "turn": turn_num,
            "status": "pending",
            "tool_name": tool_name,
            "reviewer_decision": reviewer_decision,
            "reason": state["reason"],
        }
    )
    session["approval"] = state
    return state


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    bootstrap = {
        "cases": PRESET_CASES,
        "model_catalog": list(MODEL_CATALOG.values()),
        "default_model_config": DEFAULT_MODEL_CONFIG,
        "turns": TURN_DEFINITIONS,
        "total_turns": TOTAL_TURNS,
    }
    if templates is None:
        return HTMLResponse(
            "<!DOCTYPE html><html><head><title>PrysmAI Support Ops</title></head>"
            "<body><h1>PrysmAI Support Ops</h1>"
            "<p>Install jinja2 to use the full frontend template.</p>"
            f"<script>window.SUPPORT_OPS_BOOTSTRAP = {json.dumps(bootstrap)};</script>"
            "</body></html>"
        )
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={"request": request, "bootstrap": bootstrap},
    )


@app.post("/api/session/start")
async def start_session(request: Request):
    body = await request.json()
    case_id = normalize_case_id(body.get("case_id"))
    model_config = normalize_model_config(body.get("model_config"))
    slot_models = build_slot_models(model_config)
    case_data = next(case for case in PRESET_CASES if case["id"] == case_id)

    session_id = str(uuid.uuid4())[:8]
    control_plane = init_control_plane_session(
        case_data=case_data,
        app_session_id=session_id,
        slot_models=slot_models,
    )
    sessions[session_id] = {
        "session_id": session_id,
        "case": case_data,
        "status": "active",
        "current_turn": 0,
        "total_turns": TOTAL_TURNS,
        "slot_models": slot_models,
        "model_config": model_config,
        "agent_history": [],
        "reviewer_history": [],
        "turn_records": [],
        "action_log": [],
        "control_plane": control_plane,
        "approval": _default_approval_state(),
    }

    return {
        "session_id": session_id,
        "case": case_data,
        "status": "active",
        "total_turns": TOTAL_TURNS,
        "turns": {str(k): v for k, v in TURN_DEFINITIONS.items()},
        "model_config": model_config,
        "slot_models": slot_models,
        "control_plane": serialize_control_plane_state(control_plane),
        "approval": sessions[session_id]["approval"],
    }


@app.get("/api/session/{session_id}/turn/{turn_num}")
async def stream_turn(session_id: str, turn_num: int):
    session = sessions.get(session_id)
    if not session:
        return JSONResponse({"error": "Session not found"}, status_code=404)
    if turn_num < 1 or turn_num > session["total_turns"]:
        return JSONResponse({"error": "Invalid turn number"}, status_code=400)

    def event_generator():
        turn_record = {
            "turn": turn_num,
            "agent": "",
            "reviewer": "",
            "agent_blocked": False,
            "reviewer_blocked": False,
            "tools": [],
            "decision": None,
        }

        for chunk in run_support_turn_streaming(
            case_data=session["case"],
            turn_num=turn_num,
            session_id=session_id,
            slot_models=session["slot_models"],
            agent_history=session["agent_history"],
            reviewer_history=session["reviewer_history"],
            control_plane_state=session["control_plane"],
        ):
            event_type = chunk.get("type", "data")
            model = chunk.get("model")

            if event_type == "done":
                if model == "agent":
                    turn_record["agent"] = chunk.get("content", "")
                    turn_record["agent_blocked"] = bool(chunk.get("blocked"))
                elif model == "reviewer":
                    turn_record["reviewer"] = chunk.get("content", "")
                    turn_record["reviewer_blocked"] = bool(chunk.get("blocked"))

            if event_type in {"tool_start", "tool_result", "tool_blocked", "attachment_indexed"}:
                turn_record["tools"].append(chunk)
                session["action_log"].append({"turn": turn_num, **chunk})

            if event_type in {"behavior_check", "code_scan", "governance_error"}:
                session["action_log"].append({"turn": turn_num, **chunk})

            if event_type == "turn_end":
                turn_record["decision"] = chunk.get("decision")
                session["agent_history"].append(turn_record["agent"] or chunk.get("agent_preview", ""))
                session["reviewer_history"].append(turn_record["reviewer"] or chunk.get("reviewer_preview", ""))
                session["turn_records"].append(turn_record)
                session["current_turn"] = turn_num
                tool_result = next(
                    (item for item in reversed(turn_record["tools"]) if item.get("type") == "tool_result"),
                    {},
                )
                approval_state = _build_approval_state(
                    session,
                    turn_num=turn_num,
                    reviewer_decision=chunk.get("decision"),
                    tool_name=tool_result.get("tool"),
                    tool_status=tool_result.get("status"),
                    attack=bool(chunk.get("is_attack")),
                )
                if approval_state.get("pending"):
                    approval_event = {
                        "type": "approval_status",
                        **approval_state,
                    }
                    session["action_log"].append({"turn": turn_num, **approval_event})
                    yield {"event": "approval_status", "data": json.dumps(approval_event)}

            yield {"event": event_type, "data": json.dumps(chunk)}

    return EventSourceResponse(event_generator())


@app.post("/api/session/{session_id}/resolve")
async def resolve_session(session_id: str):
    session = sessions.get(session_id)
    if not session:
        return JSONResponse({"error": "Session not found"}, status_code=404)
    if session.get("approval", {}).get("pending"):
        return JSONResponse(
            {
                "error": "Approval required before resolution",
                "approval": session.get("approval"),
            },
            status_code=409,
        )

    result = resolve_case(
        case_data=session["case"],
        agent_history=session["agent_history"],
        reviewer_history=session["reviewer_history"],
        session_id=session_id,
        slot_models=session["slot_models"],
        turn_records=session["turn_records"],
        control_plane_state=session["control_plane"],
    )
    session["status"] = "complete"
    session["action_log"].append({"turn": "resolve", "type": "resolved"})
    result["approval"] = session.get("approval")
    return result


@app.get("/api/session/{session_id}/status")
async def session_status(session_id: str):
    session = sessions.get(session_id)
    if not session:
        return JSONResponse({"error": "Session not found"}, status_code=404)

    return {
        "session_id": session["session_id"],
        "status": session["status"],
        "current_turn": session["current_turn"],
        "total_turns": session["total_turns"],
        "case": session["case"],
        "slot_models": session["slot_models"],
        "actions_logged": len(session["action_log"]),
        "turns_completed": len(session["turn_records"]),
        "control_plane": serialize_control_plane_state(session.get("control_plane")),
        "approval": session.get("approval", _default_approval_state()),
    }


@app.get("/api/session/{session_id}/control-plane")
async def session_control_plane(session_id: str):
    session = sessions.get(session_id)
    if not session:
        return JSONResponse({"error": "Session not found"}, status_code=404)

    return serialize_control_plane_state(session.get("control_plane"))


@app.get("/api/session/{session_id}/attribution")
async def session_attribution(session_id: str):
    session = sessions.get(session_id)
    if not session:
        return JSONResponse({"error": "Session not found"}, status_code=404)

    return get_session_attribution(session.get("control_plane"))


@app.post("/api/session/{session_id}/approval")
async def session_approval(session_id: str, request: Request):
    session = sessions.get(session_id)
    if not session:
        return JSONResponse({"error": "Session not found"}, status_code=404)

    approval = session.get("approval") or _default_approval_state()
    body = await request.json()
    action = str(body.get("action", "")).strip().lower()
    note = str(body.get("note", "")).strip()

    if action not in {"approve", "deny"}:
        return JSONResponse({"error": "Action must be approve or deny"}, status_code=400)
    if not approval.get("pending"):
        return JSONResponse({"error": "No approval is currently pending", "approval": approval}, status_code=409)

    approval["status"] = "approved" if action == "approve" else "denied"
    approval["pending"] = False
    approval["resolution"] = action
    approval["note"] = note
    approval.setdefault("history", []).append(
        {
            "turn": approval.get("turn"),
            "status": approval["status"],
            "tool_name": approval.get("tool_name"),
            "reviewer_decision": approval.get("reviewer_decision"),
            "reason": approval.get("reason"),
            "note": note,
        }
    )
    session["approval"] = approval
    session["action_log"].append(
        {
            "turn": approval.get("turn"),
            "type": "approval_decision",
            "status": approval["status"],
            "note": note,
        }
    )
    return approval


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8080)
