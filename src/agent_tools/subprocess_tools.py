import asyncio
import os
import sys
import time
import collections
from typing import Optional, Callable, Awaitable, Tuple, Dict
from src.constants import MAX_OUTPUT_CHARS

DEFAULT_BASH_TIMEOUT = 60 * 60     # 1 hour
DEFAULT_PYTHON_TIMEOUT = 60 * 60

PROGRESS_INTERVAL_S = 2.0
PROGRESS_TAIL_LINES = 12

async def _run_subprocess_streaming(
    proc: asyncio.subprocess.Process,
    *,
    timeout: float,
    progress_cb: Optional[Callable[[Dict], Awaitable[None]]] = None,
) -> Tuple[str, str, Optional[int], bool]:
    started = time.time()
    stdout_full: list[str] = []
    stderr_full: list[str] = []
    tail = collections.deque(maxlen=PROGRESS_TAIL_LINES)

    async def _reader(stream, full_buf, label: str):
        if stream is None:
            return
        while True:
            line = await stream.readline()
            if not line:
                break
            decoded = line.decode("utf-8", errors="replace").rstrip("\n")
            full_buf.append(decoded)
            if label == "err":
                tail.append(f"! {decoded}")
            else:
                tail.append(decoded)

    async def _progress_emitter():
        await asyncio.sleep(PROGRESS_INTERVAL_S)
        while True:
            if progress_cb:
                try:
                    await progress_cb({
                        "elapsed_s": round(time.time() - started, 1),
                        "tail": "\n".join(list(tail)),
                    })
                except Exception:
                    pass
            await asyncio.sleep(PROGRESS_INTERVAL_S)

    rd_out = asyncio.create_task(_reader(proc.stdout, stdout_full, "out"))
    rd_err = asyncio.create_task(_reader(proc.stderr, stderr_full, "err"))
    prog_task = asyncio.create_task(_progress_emitter()) if progress_cb else None

    timed_out = False
    try:
        await asyncio.wait_for(proc.wait(), timeout=timeout)
    except asyncio.TimeoutError:
        timed_out = True
        try:
            proc.kill()
        except Exception:
            pass
        try:
            await asyncio.wait_for(proc.wait(), timeout=2)
        except Exception:
            pass
    except asyncio.CancelledError:
        try:
            proc.kill()
        except Exception:
            pass
        try:
            await asyncio.wait_for(proc.wait(), timeout=2)
        except Exception:
            pass
        for t in (rd_out, rd_err):
            t.cancel()
        if prog_task is not None:
            prog_task.cancel()
        raise
    finally:
        if prog_task is not None and not prog_task.done():
            prog_task.cancel()
            try:
                await prog_task
            except (asyncio.CancelledError, Exception):
                pass
        for t in (rd_out, rd_err):
            try:
                await asyncio.wait_for(t, timeout=1)
            except Exception:
                pass

    return (
        "\n".join(stdout_full),
        "\n".join(stderr_full),
        proc.returncode,
        timed_out,
    )

class BashTool:
    async def execute(self, content: str, ctx: dict) -> dict:
        from src.tool_execution import agent_cwd, _truncate
        from src.operation_permissions import record_sandbox_run
        from src.sandbox_runner import build_sandbox_plan, fail_if_unavailable, sandbox_enabled
        progress_cb = ctx.get("progress_cb")
        _subproc_env = ctx.get("subproc_env")
        sandbox_allow = ctx.get("sandbox_allow") or {}
        cwd = agent_cwd()
        plan = build_sandbox_plan(
            ("/bin/sh", "-c", content),
            cwd=cwd,
            extra_allow_read=sandbox_allow.get("allow_read") or [],
            extra_allow_write=sandbox_allow.get("allow_write") or [],
        )
        record_sandbox_run(sandboxed=plan.sandboxed)
        if sandbox_enabled() and fail_if_unavailable() and not plan.sandboxed:
            return {"error": f"bash: sandbox unavailable: {plan.reason}", "exit_code": 126}
        profile_path = plan.reason if plan.backend == "sandbox-exec" else ""
        try:
            if plan.enabled:
                proc = await asyncio.create_subprocess_exec(
                    *plan.command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    env=_subproc_env,
                    cwd=cwd,
                )
            else:
                proc = await asyncio.create_subprocess_shell(
                    content,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    env=_subproc_env,
                    cwd=cwd,
                )
            stdout, stderr, rc, timed_out = await _run_subprocess_streaming(
                proc,
                timeout=DEFAULT_BASH_TIMEOUT,
                progress_cb=progress_cb,
            )
        finally:
            if profile_path:
                try:
                    os.unlink(profile_path)
                except OSError:
                    pass
        if timed_out:
            return {"error": f"bash: timed out after {DEFAULT_BASH_TIMEOUT}s — process killed", "exit_code": 124, "stdout": _truncate(stdout, MAX_OUTPUT_CHARS), "stderr": _truncate(stderr, MAX_OUTPUT_CHARS)}
        output = stdout.rstrip()
        err = stderr.rstrip()
        if plan.enabled and not plan.sandboxed and plan.reason:
            err = (err + "\n" if err else "") + f"[sandbox] {plan.reason}"
        if err:
            output = (output + "\nSTDERR: " + err).strip() if output else "STDERR: " + err
        output = _truncate(output, MAX_OUTPUT_CHARS)
        return {"output": output or "(no output)", "exit_code": rc or 0, "sandboxed": plan.sandboxed, "sandbox_backend": plan.backend}

class PythonTool:
    async def execute(self, content: str, ctx: dict) -> dict:
        from src.tool_execution import agent_cwd, _truncate
        from src.operation_permissions import record_sandbox_run
        from src.sandbox_runner import build_sandbox_plan, fail_if_unavailable, sandbox_enabled
        progress_cb = ctx.get("progress_cb")
        _subproc_env = ctx.get("subproc_env")
        sandbox_allow = ctx.get("sandbox_allow") or {}
        cwd = agent_cwd()
        command = ((sys.executable or "python"), "-I", "-c", content)
        plan = build_sandbox_plan(
            command,
            cwd=cwd,
            extra_allow_read=sandbox_allow.get("allow_read") or [],
            extra_allow_write=sandbox_allow.get("allow_write") or [],
        )
        record_sandbox_run(sandboxed=plan.sandboxed)
        if sandbox_enabled() and fail_if_unavailable() and not plan.sandboxed:
            return {"error": f"python: sandbox unavailable: {plan.reason}", "exit_code": 126}
        profile_path = plan.reason if plan.backend == "sandbox-exec" else ""
        try:
            proc = await asyncio.create_subprocess_exec(
                *plan.command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=_subproc_env,
                cwd=cwd,
            )
            stdout, stderr, rc, timed_out = await _run_subprocess_streaming(
                proc,
                timeout=DEFAULT_PYTHON_TIMEOUT,
                progress_cb=progress_cb,
            )
        finally:
            if profile_path:
                try:
                    os.unlink(profile_path)
                except OSError:
                    pass
        if timed_out:
            return {"error": f"python: timed out after {DEFAULT_PYTHON_TIMEOUT}s — process killed", "exit_code": 124, "stdout": _truncate(stdout, MAX_OUTPUT_CHARS), "stderr": _truncate(stderr, MAX_OUTPUT_CHARS)}
        output = stdout.rstrip()
        err = stderr.rstrip()
        if plan.enabled and not plan.sandboxed and plan.reason:
            err = (err + "\n" if err else "") + f"[sandbox] {plan.reason}"
        if err:
            output = (output + "\nSTDERR: " + err).strip() if output else "STDERR: " + err
        output = _truncate(output, MAX_OUTPUT_CHARS)
        return {"output": output or "(no output)", "exit_code": rc or 0, "sandboxed": plan.sandboxed, "sandbox_backend": plan.backend}
