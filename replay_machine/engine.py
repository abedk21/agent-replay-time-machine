"""Tamper-evident *checksums* and deterministic reducer for synthetic tool traces.

SHA-256 links detect accidental modification when compared against a trusted
head hash. They are NOT digital signatures; anyone can rebuild a new chain.
"""
from __future__ import annotations
import hashlib
import json
from copy import deepcopy
from typing import Any

ALLOWED_TOOLS = frozenset({"fetch_metrics", "inspect_logs", "check_connector"})
SEVERITIES = frozenset({"normal", "warning", "high", "critical"})
KINDS = frozenset({"start", "tool_call", "tool_result", "finalize"})
ZERO = "0" * 64


class TraceError(ValueError):
    pass


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def event_hash(event: dict) -> str:
    return hashlib.sha256(b"agent-replay-v1\x00" + canonical({k: event[k] for k in ("seq", "id", "kind", "payload", "prev_hash")})).hexdigest()


def build_trace(actions: list[dict]) -> list[dict]:
    if not isinstance(actions, list) or not 1 <= len(actions) <= 300:
        raise TraceError("Expected between 1 and 300 actions")
    events: list[dict] = []
    last = ZERO
    for n, action in enumerate(actions, start=1):
        if not isinstance(action, dict) or action.get("kind") not in KINDS or not isinstance(action.get("payload"), dict):
            raise TraceError("Invalid action kind or payload")
        # JSON copy avoids shared mutable objects and rejects non-serializable input.
        try:
            payload = json.loads(canonical(action["payload"]))
        except (TypeError, ValueError) as exc:
            raise TraceError("Payload must be finite JSON") from exc
        event = {"seq": n, "id": f"evt-{n:03d}", "kind": action["kind"],
                 "payload": payload, "prev_hash": last}
        event["hash"] = event_hash(event)
        events.append(event)
        last = event["hash"]
    replay(events)
    return events


def verify_chain(events: list[dict], trusted_head: str | None = None) -> str:
    if not isinstance(events, list) or not events:
        raise TraceError("Empty or invalid trace")
    prev = ZERO
    for seq, event in enumerate(events, start=1):
        if not isinstance(event, dict) or event.get("seq") != seq or event.get("id") != f"evt-{seq:03d}":
            raise TraceError("Sequence or event IDs invalid")
        if event.get("kind") not in KINDS or not isinstance(event.get("payload"), dict):
            raise TraceError("Event schema invalid")
        if event.get("prev_hash") != prev or event.get("hash") != event_hash(event):
            raise TraceError(f"Hash-chain mismatch at evt-{seq:03d}")
        prev = event["hash"]
    if trusted_head is not None and prev != trusted_head:
        raise TraceError("Trace does not match the trusted head")
    return prev


def replay(events: list[dict], up_to: int | None = None) -> dict:
    verify_chain(events)
    if up_to is None:
        up_to = len(events)
    if type(up_to) is not int or not 0 <= up_to <= len(events):
        raise TraceError("up_to must be a valid event count")
    state: dict[str, Any] = {"status": "not_started", "case_id": None, "tenant": None,
                             "pending": {}, "completed": {}, "evidence": [],
                             "decision": None, "citations": [], "events_seen": 0}
    for event in events[:up_to]:
        kind, payload, eid = event["kind"], event["payload"], event["id"]
        if kind == "start":
            if state["status"] != "not_started" or not isinstance(payload.get("case_id"), str) or not payload["case_id"] or not isinstance(payload.get("tenant"), str) or not payload["tenant"]:
                raise TraceError("Expected one valid start event first")
            state.update({"status": "running", "case_id": payload["case_id"], "tenant": payload["tenant"]})
        elif kind == "tool_call":
            call = payload.get("call_id")
            if state["status"] != "running" or payload.get("tool") not in ALLOWED_TOOLS or not isinstance(call, str) or not call or call in state["pending"] or call in state["completed"]:
                raise TraceError("Invalid tool invocation or duplicate call")
            state["pending"][call] = payload["tool"]
        elif kind == "tool_result":
            call = payload.get("call_id")
            if state["status"] != "running" or not isinstance(call, str) or call not in state["pending"] or payload.get("severity") not in SEVERITIES or not isinstance(payload.get("summary"), str) or len(payload["summary"]) > 2000:
                raise TraceError("Unexpected or invalid tool result")
            tool = state["pending"].pop(call)
            state["completed"][call] = eid
            state["evidence"].append({"event": eid, "tool": tool, "severity": payload["severity"],
                                      "summary": payload["summary"]})
        elif kind == "finalize":
            if state["status"] != "running" or state["pending"] or payload:
                raise TraceError("Finalize requires no pending calls and empty payload")
            sev = {e["severity"] for e in state["evidence"]}
            state["decision"] = ("escalate" if sev & {"high", "critical"} else
                                 "investigate" if "warning" in sev else
                                 "monitor" if sev else "abstain")
            if state["decision"] == "escalate":
                state["citations"] = [e["event"] for e in state["evidence"] if e["severity"] in ("critical", "high")]
            elif state["decision"] == "investigate":
                state["citations"] = [e["event"] for e in state["evidence"] if e["severity"] == "warning"]
            elif state["decision"] == "monitor":
                state["citations"] = [e["event"] for e in state["evidence"]]
            state["status"] = "finished"
        if state["status"] == "not_started" or state["status"] == "finished" and kind != "finalize":
            raise TraceError("Invalid event order")
        state["events_seen"] += 1
    return state


def fork_trace(events: list[dict], event_id: str, *, severity: str, summary: str | None = None) -> dict:
    """Counterfactual: replace one recorded tool result; rehash the full branch."""
    parent = verify_chain(events)
    target = next((e for e in events if e["id"] == event_id), None)
    if target is None or target["kind"] != "tool_result":
        raise TraceError("Can only fork a recorded tool_result event")
    if severity not in SEVERITIES or summary is not None and (not isinstance(summary, str) or len(summary) > 2000):
        raise TraceError("Invalid replacement")
    actions = []
    for event in events:
        payload = deepcopy(event["payload"])
        if event["id"] == event_id:
            payload["severity"] = severity
            if summary is not None: payload["summary"] = summary
        actions.append({"kind": event["kind"], "payload": payload})
    branch = build_trace(actions)
    return {"parent_head": parent, "fork_at": event_id, "head": branch[-1]["hash"], "events": branch}


def compare_traces(original: list[dict], modified: list[dict]) -> dict:
    verify_chain(original)
    verify_chain(modified)
    if len(original) != len(modified):
        raise TraceError("Comparison expects traces with aligned event counts")
    content_diff = []
    rehashed = []
    for a,b in zip(original,modified):
        if a["kind"] != b["kind"] or a["payload"] != b["payload"]:
            content_diff.append(a["id"])
        if a["hash"] != b["hash"]:
            rehashed.append(a["id"])
    before, after = replay(original), replay(modified)
    return {"before": before["decision"], "after": after["decision"],
            "semantic_changes": content_diff, "hash_changes": rehashed,
            "before_citations": before["citations"], "after_citations": after["citations"]}
