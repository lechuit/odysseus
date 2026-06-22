"""Agent loop state telemetry must be forwarded by the chat route.

The loop emits lightweight `agent_state` SSE events so the frontend/logging can
distinguish thinking/tool/waiting/done states.  The route keeps an allowlist of
event types to forward; forgetting to include the new type silently drops the
telemetry before the UI can observe it.
"""

from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


def test_chat_route_forwards_agent_state_events():
    source = (ROOT / "routes" / "chat_routes.py").read_text(encoding="utf-8")
    assert '"agent_state"' in source
