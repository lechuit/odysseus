"""Agent promises to use a tool must be followed by a real tool call.

Regression for Gemma 4 in Spanish: after resolving the workspace, the model
said ``Voy a reintentar la lectura...`` and ended the turn.  The existing
intent-without-action supervisor only recognized English promises, so the
agent silently stopped instead of nudging Gemma to emit ``read_file``.
"""

import asyncio
import json

import src.agent_loop as agent_loop


def _collect(gen):
    async def _run():
        return [chunk async for chunk in gen]

    return asyncio.run(_run())


def _events(chunks):
    events = []
    for chunk in chunks:
        if chunk.startswith("data: ") and not chunk.startswith("data: [DONE]"):
            events.append(json.loads(chunk[6:]))
    return events


def _patch_basics(monkeypatch, streams, executed):
    monkeypatch.setattr(agent_loop, "get_setting", lambda key, default=None: default, raising=False)
    monkeypatch.setattr(agent_loop, "get_mcp_manager", lambda: None, raising=False)
    monkeypatch.setattr(agent_loop, "estimate_tokens", lambda *args, **kwargs: 10, raising=False)

    async def fake_stream(_candidates, messages, **kwargs):
        round_index = len(streams)
        streams.append(messages)
        if round_index == 0:
            text = (
                "Dado que el workspace actual es `/Users/gabrielpena`, voy a "
                "intentar leerlo usando la ruta completa.\n\n"
                "Voy a reintentar la lectura del archivo en la carpeta Desktop."
            )
            yield f'data: {json.dumps({"delta": text})}\n\n'
        elif round_index == 1:
            call = {
                "name": "read_file",
                "arguments": json.dumps({
                    "path": "/Users/gabrielpena/Desktop/resumen-sincronizacion-rutas-facturas.md"
                }),
            }
            yield f'data: {json.dumps({"type": "tool_calls", "calls": [call]})}\n\n'
        else:
            yield f'data: {json.dumps({"delta": "Archivo leído correctamente."})}\n\n'
        yield "data: [DONE]\n\n"

    async def fake_execute(block, *args, **kwargs):
        executed.append(block)
        return ("read_file", {"content": "# Resumen", "exit_code": 0})

    monkeypatch.setattr(agent_loop, "stream_llm_with_fallback", fake_stream, raising=False)
    monkeypatch.setattr(agent_loop, "execute_tool_block", fake_execute, raising=False)


def test_spanish_tool_promise_is_nudged_and_executed(monkeypatch):
    streams = []
    executed = []
    _patch_basics(monkeypatch, streams, executed)

    chunks = _collect(
        agent_loop.stream_agent_loop(
            "http://localhost:8000/v1",
            "gemma-4-E4B-it-Q4_K_M.gguf",
            [{"role": "user", "content": "Lee el archivo del escritorio."}],
            relevant_tools={"read_file"},
            max_rounds=4,
            _is_teacher_run=True,
        )
    )
    events = _events(chunks)

    assert len(streams) == 3
    assert len(executed) == 1
    assert executed[0].tool_type == "read_file"
    assert "/Users/gabrielpena/Desktop/resumen-sincronizacion-rutas-facturas.md" in executed[0].content
    assert any(event.get("type") == "agent_step" and event.get("round") == 2 for event in events)


def test_spanish_explanation_without_tool_action_is_not_nudged(monkeypatch):
    streams = []
    executed = []

    monkeypatch.setattr(agent_loop, "get_setting", lambda key, default=None: default, raising=False)
    monkeypatch.setattr(agent_loop, "get_mcp_manager", lambda: None, raising=False)
    monkeypatch.setattr(agent_loop, "estimate_tokens", lambda *args, **kwargs: 10, raising=False)

    async def fake_stream(_candidates, messages, **kwargs):
        streams.append(messages)
        yield f'data: {json.dumps({"delta": "Voy a explicarte cómo funciona la lectura de archivos."})}\n\n'
        yield "data: [DONE]\n\n"

    monkeypatch.setattr(agent_loop, "stream_llm_with_fallback", fake_stream, raising=False)

    chunks = _collect(
        agent_loop.stream_agent_loop(
            "http://localhost:8000/v1",
            "gemma-4-E4B-it-Q4_K_M.gguf",
            [{"role": "user", "content": "Explícame cómo funciona."}],
            relevant_tools={"read_file"},
            max_rounds=3,
            _is_teacher_run=True,
        )
    )
    events = _events(chunks)

    assert len(streams) == 1
    assert not executed
    assert not any(event.get("type") == "agent_step" for event in events)
