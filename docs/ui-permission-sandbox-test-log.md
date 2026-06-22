# UI permission + sandbox test log

Date: 2026-06-22  
Local app: `http://127.0.0.1:7860/`  
Local install: `/Users/gabrielpena/Library/Application Support/Odysseus`

## Completed UI checks

### Sandbox status with strict single-tool guardrail

- Marker: `UI_SANDBOX_STATUS_37DC798`
- Local install commit: `37dc798`
- Prompt: asked the agent to execute exactly `manage_settings` with `{"action":"sandbox_status"}` and no other tools.
- Result: one `MANAGE_SETTINGS done`, no visible `MANAGE_SKILLS`, and a concise sandbox status answer.
- Observed answer: `enabled: true`, `sandboxed: true`, `backend: sandbox-exec`, `platform: darwin`, `warnings: []`.
- Server log confirmation:
  - `Suppressing memory/RAG/skills for explicit single-tool turn: ['manage_settings']`
  - `[agent-intent] selected_tools=['manage_settings']`
  - `[agent-debug] ... tools_sent=1 tool_names=['manage_settings'] relevant_tools=['manage_settings']`

### Operation permission card for path outside workspace

- Scenario: agent requested a Bash read outside the active workspace.
- Observed UI: approval card appeared with options:
  - `Permitir una vez`
  - `Permitir esta sesión`
  - `Permitir siempre`
  - `Denegar`
- Representative card text: `bash: ls /Users/gabrielpena/Documents`, reason `bash read targets a path outside the active workspace`.
- Result: UI correctly paused execution for approval instead of running silently.

### Strict permission resume after `Permitir esta sesión`

- Marker: `UI_STRICT_SESSION_1782105642`
- Setup file: `/tmp/ody_strict_session_1782105642.txt`
- Expected content: `strict-session-ok-1782105642`
- First prompt: requested literal Bash read of that exact file.
- User action: clicked `Permitir esta sesión`.
- Result: Bash ran and returned `strict-session-ok-1782105642`.
- Reuse marker: `UI_STRICT_REUSE_1782105642`
- Reuse prompt: requested the exact same literal Bash read again.
- Expected: no second approval card for the same operation in the same session.
- Result: no approval card appeared; Bash ran and returned `strict-session-ok-1782105642`.

### Strict turn leakage regression

- Reason for test: earlier strict turns could accidentally expand into unrelated tools after approval.
- Bad behavior previously observed:
  - `manage_skills`
  - `read_file ~/.bashrc`
  - `read_file /home/user11/.ody/.strict_session.json`
  - textual `<tool_call>` leakage
- Final validated behavior:
  - strict literal turn sent only `bash` on the first round;
  - after Bash execution, the forced answer round sent zero tools;
  - no `READ_FILE`, `MANAGE_SKILLS`, `browser_open`, `.bashrc`, `strict_session.json`, or `<tool_call>` appeared in the scoped UI output.
- Server log confirmation:
  - `selected_tools=['bash']`
  - `tools_sent=['bash']`
  - second round `tools_sent=0`
  - executed `bash: cat /tmp/ody_strict_session_1782105642.txt -> exit_code=0`

### Sandbox approved outside read

- Marker: `UI_SANDBOX_OUTSIDE_READ_240622`
- Setup file: `/Users/gabrielpena/Desktop/Personal/ody-sandbox-outside/read.txt`
- Expected content: `outside-read-ok-240622`
- Prompt: requested literal Bash command `cat /Users/gabrielpena/Desktop/Personal/ody-sandbox-outside/read.txt`.
- Expected: because the active workspace was `odysseus-path-policy-test-workspace`, reading this path should require approval.
- User action: clicked `Permitir una vez`.
- Result: Bash replayed deterministically and returned `outside-read-ok-240622`.
- Server log confirmation:
  - `[agent-intent] selected_tools=['bash']`
  - `[agent-debug] ... tools_sent=1 tool_names=['bash'] relevant_tools=['bash']`
  - `Operation permission requires approval ... reason=bash read targets a path outside the active workspace`
  - `[operation-permissions] deterministic replay of approved bash`
  - `Tool executed: bash: cat /Users/gabrielpena/Desktop/Personal/ody-sandbox-outside/read.txt -> exit_code=0`

### Sandbox approved outside write

- Marker: `UI_SANDBOX_OUTSIDE_WRITE_240622`
- Target file: `/Users/gabrielpena/Desktop/Personal/ody-sandbox-outside/write.txt`
- Prompt: requested literal Bash command `printf 'outside-write-ok-240622\n' > /Users/gabrielpena/Desktop/Personal/ody-sandbox-outside/write.txt && cat /Users/gabrielpena/Desktop/Personal/ody-sandbox-outside/write.txt`.
- Expected: writing this path outside the active workspace should require approval, then receive a narrow sandbox write allowance.
- User action: clicked `Permitir una vez`.
- Result: Bash replayed deterministically, wrote the file, and returned `outside-write-ok-240622`.
- Filesystem verification: `/Users/gabrielpena/Desktop/Personal/ody-sandbox-outside/write.txt` contained `outside-write-ok-240622`.
- Server log confirmation:
  - `[agent-intent] selected_tools=['bash']`
  - `[agent-debug] ... tools_sent=1 tool_names=['bash'] relevant_tools=['bash']`
  - `Operation permission requires approval ... reason=bash write targets a path outside the active workspace`
  - `[operation-permissions] deterministic replay of approved bash`
  - `Tool executed: bash: printf 'outside-write-ok-240622\n' ... -> exit_code=0`

### Sandbox sensitive protected read denied

- Marker: `UI_SANDBOX_SENSITIVE_DENY_240622`
- Prompt: requested literal Bash command `cat /Users/gabrielpena/Desktop/Personal/odysseus/.git/config`.
- Expected: reading `.git/config` should never run silently.
- Observed UI: approval card appeared with reason `bash read targets a protected path`.
- User action: clicked `Denegar`.
- Result: terminal denial message was rendered by the route without re-entering the model/tool loop.
- Leak check: UI text did not contain `.git/config` contents such as `[remote "origin"]`, `url =`, `github.com`, or `git@`.
- Server log confirmation:
  - `[agent-intent] selected_tools=['bash']`
  - `[agent-debug] ... tools_sent=1 tool_names=['bash'] relevant_tools=['bash']`
  - `Operation permission requires approval ... reason=bash read targets a protected path`
  - `[operation-permissions] OPERATION PERMISSION RESUME`
  - `The user denied the pending operation permission.`

### Git cwd guardrail and literal-argument preservation

- First marker: `UI_GIT_CD_GUARD_240622`
- Prompt: requested literal Bash command `cd /Users/gabrielpena/Desktop/Personal/odysseus && git status`.
- Expected: the new Git+cwd guardrail should ask before running the command.
- Observed before literal-argument fix:
  - approval card appeared with reason `compound command changes directory before running git`;
  - the model mistyped the copied command as `/Users/gabielpena/...`;
  - this proved that strict single-tool mode limited schemas but still trusted the model to transcribe arguments.
- Fix:
  - literal Bash prompts with a high-confidence `comando literal exacto:` shape now extract the command from the user message;
  - strict tool turns override model-produced Bash args with that extracted command.
- Follow-up marker: `UI_GIT_CD_GUARD_LITERAL_542ACE5`
- Result after fix:
  - approval card still appeared with reason `compound command changes directory before running git`;
  - the card and denial message preserved the exact command with `/Users/gabrielpena/...`;
  - user action was `Denegar`;
  - no `git status` output leaked.
- Server log confirmation:
  - before fix: `Denied operation: bash: cd /Users/gabielpena/Desktop/Personal/odysseus && git status`
  - after fix: `Denied operation: bash: cd /Users/gabrielpena/Desktop/Personal/odysseus && git status`

### Sandbox network-deny approval override

- Marker: `UI_SANDBOX_NETWORK_ALLOW_240622`
- Current local sandbox setting:
  - `enabled: true`
  - `fail_if_unavailable: true`
  - `network.deny: true`
  - backend: `sandbox-exec`
- Prompt: requested literal Bash command `curl -I --max-time 5 https://example.com`.
- Expected: network access should ask while `network.deny` is enabled.
- Observed UI:
  - approval card appeared with reason `bash may use network access while sandbox network.deny is enabled`;
  - user action was `Permitir una vez`;
  - Bash replayed deterministically;
  - final assistant message reported that HTTP headers were received and no error occurred.
- Server log confirmation:
  - `Operation permission requires approval tool=bash source=builtin reason=bash may use network access while sandbox network.deny is enabled`
  - `Approved operation: bash: curl -I --max-time 5 https://example.com`
  - `Tool executed: bash: curl -I --max-time 5 https://example.com -> exit_code=0`
- Automation note:
  - The UI detector initially waited for literal `HTTP/` in visible assistant text and timed out after 5 minutes.
  - Manual state/log inspection showed the command had completed successfully; the model summarized the result instead of echoing headers verbatim.

## Important UI testing note

The in-app textarea did not submit reliably with `Enter` during these tests. For future UI automation, after typing the prompt, click the visible send button.

## Pending UI checks for sandbox hardening

These should be run after the sandbox runner changes are installed locally and the app is restarted.

No pending macOS UI checks remain from this sandbox batch.

## Linux sandbox plan hardening

- Date: 2026-06-22
- Scope: unit-level command-plan validation for Linux backends; not a real Linux runtime execution yet.
- Change validated:
  - `bubblewrap` now keeps operation-scoped approved read/write mounts separate from baseline workspace mounts;
  - default/sensitive deny masks are applied first;
  - approved one-shot paths are rebound after those masks so the explicit approval wins for the reviewed path;
  - nested approved reads inside a masked directory recreate the required in-sandbox parent directories after the mask;
  - `firejail` emits operation-scoped whitelists/read-write overrides after blacklist/read-only rules.
- Tests added:
  - approved read after file deny;
  - approved nested read after directory mask;
  - approved write after write deny;
  - firejail operation overrides ordered after denies.
- Runtime tests prepared for Linux:
  - `test_linux_bubblewrap_runtime_enforces_paths`
  - `test_linux_bubblewrap_runtime_rebinds_approved_child_inside_mask`
  - These skip automatically on non-Linux or when `bubblewrap` is unavailable.
- Validation run:
  - `tests/test_sandbox_runner.py tests/test_operation_permissions.py tests/test_subprocess_sandbox_enforcement.py`: 66 passed, 2 skipped on macOS.
  - broader permission/sandbox/agent suite: 166 passed, 2 skipped on macOS.
- Remaining real-host check:
  - Run the same scenarios on a Linux host with `bubblewrap` or `firejail` installed to confirm runtime enforcement, not just generated command shape.

## Linux sandbox runtime readiness diagnostics

- Date: 2026-06-22
- Scope: mocked Linux backend validation on macOS; no real Linux host runtime execution yet.
- Change validated:
  - `sandbox_status` can now report runtime smoke-test results, not only binary presence;
  - `bubblewrap`/`firejail` report `available`, `path`, `runnable`, `returncode`, `stdout`, `stderr`, and `error` where applicable;
  - the Linux plan selector skips an installed-but-unrunnable `bubblewrap` and falls back to runnable `firejail`;
  - if no installed Linux backend passes the smoke test, fail-closed mode reports `effective_mode=blocked`;
  - `bubblewrap` no longer emits a `/lib64` bind on hosts where `/lib64` does not exist.
- Tests added:
  - fallback from failed `bubblewrap` probe to `firejail`;
  - blocked status when an installed backend cannot create a sandbox;
  - positive status when the preferred backend passes the smoke test;
  - missing Linux system mount path skipped in generated `bubblewrap` command.
- Validation run:
  - `tests/test_sandbox_runner.py`: 34 passed, 3 skipped on macOS.
  - Permission/sandbox/agent regression suite: 252 passed, 3 skipped on macOS.
  - Full repository suite attempted: 3649 passed, 4 skipped, 7 failed on macOS. Failures were outside this sandbox change area:
    - README/doc asset expectations: `tests/test_docs_no_orphan_images.py`, `tests/test_readme_ascii_fenced.py`, `tests/test_security_regressions.py`.
    - `run_focus` dry-run string expectations when `sys.executable` contains spaces: `tests/test_run_focus.py`.
- Remaining real-host check:
  - On Linux, run `manage_settings {"action":"sandbox_status"}` with `bubblewrap` installed and confirm `backend_runtime_ready=true`.
  - Repeat on a Linux host/container where `bubblewrap` is installed but user namespaces are unavailable and confirm the warning/error surfaces clearly.

## Sandbox runtime self-test action

- Date: 2026-06-22
- Scope: code-level and macOS runtime validation; Linux runtime validation still pending.
- Change validated:
  - `manage_settings` now supports `{"action":"sandbox_self_test"}`;
  - the self-test creates temporary sibling directories, runs controlled sandboxed commands, and cleans them up;
  - it verifies:
    - workspace writes are allowed;
    - outside writes are denied without approval;
    - protected reads such as workspace `.env` do not leak contents;
    - operation-scoped outside write allowances work;
    - operation-scoped protected read allowances work.
- Safety behavior:
  - if sandbox is disabled or no sandboxed backend is active, it skips enforcement commands instead of intentionally writing outside the workspace unsandboxed.
- Validation run:
  - `tests/test_sandbox_runner.py tests/test_operation_permission_settings.py`: 45 passed, 3 skipped on macOS.
  - Manual macOS runtime self-test with temporary in-process sandbox settings: passed 5/5 on `sandbox-exec`.
  - CLI harness added: `python scripts/sandbox_self_test.py --preset strict_local --pretty --fail-on-fail`.
  - CLI harness macOS runtime run: passed 5/5 on `sandbox-exec`.
- Repro doc:
  - See `docs/linux-sandbox-validation.md` for the Linux CLI/UI validation commands.
- Remaining real-host check:
  - In the UI on a Linux host, run strict single-tool `manage_settings` with `{"action":"sandbox_self_test"}` and confirm `overall_passed=true`, `passed_count=5`, and `selected_backend` is `bubblewrap` or `firejail`.

### UI self-test after local install sync

- Marker: `UI_SANDBOX_SELF_TEST_C143B79`
- Local install commit: `c143b79`
- Prompt: strict single-tool `manage_settings` with `{"action":"sandbox_self_test"}`, submitted by clicking the visible Send button.
- Result:
  - clean chat created from the composer `+ New` button;
  - one visible `MANAGE_SETTINGS done` tool card;
  - assistant returned JSON:
    - `overall_passed: true`
    - `skipped: false`
    - `passed_count: 5`
    - `total_count: 5`
    - `selected_backend: sandbox-exec`
    - `platform: darwin`
    - `failed_checks: []`
- UI automation note:
  - The visible transcript can retain a `Thinking` label even after the final answer is rendered; validation keyed off the final JSON and absence of `Generating response`.

### UI smoke after local install sync

- Marker: `UI_SANDBOX_STATUS_7159FBE`
- Local install commit: `7159fbe`
- Prompt: strict single-tool `manage_settings` with `{"action":"sandbox_status"}`, submitted by clicking the visible Send button.
- Result:
  - clean chat created from the composer `+ New` button;
  - one visible `MANAGE_SETTINGS done` tool card;
  - assistant returned JSON:
    - `enabled: true`
    - `sandboxed: true`
    - `selected_backend: sandbox-exec`
    - `effective_mode: sandboxed`
    - `command_execution_blocked: false`
    - `backend_runtime_ready: null`
    - `platform: darwin`
- Note:
  - The browser automation detector waited for the word `Thinking` to disappear and timed out after 5 minutes, but the final UI state was already complete. The visible transcript retained a `Thinking` label above the completed tool card/answer, so future detectors should key off the final answer/tool card rather than the raw presence of `Thinking`.

## Regression found during sandbox status UI check

### `UI_SANDBOX_STATUS_2091`

- Prompt asked the agent to execute exactly `manage_settings` with `{"action":"sandbox_status"}` and not use any other tools.
- Actual behavior before fix:
  - `manage_settings` executed successfully.
  - The model then drifted into `manage_skills`.
  - It created and published an unintended skill named `verify-sbx-validity`.
- Root cause:
  - Tool RAG classified the prompt into an adjacent admin/cookbook tool set and included `manage_skills`.
  - The phrase "no uses otras herramientas" was only prompt text, not a deterministic schema guardrail.
- Fix:
  - Explicit single-tool prompts such as `Ejecuta exactamente la herramienta manage_settings ... no uses otras herramientas` now become strict tool turns.
  - Only the named tool schema is exposed.
  - After that tool executes, the final answer round receives zero tools.
- Cleanup:
  - Removed the generated local test artifact `data/skills/system/verify-sbx-validity/SKILL.md`.
- Follow-up UI validation: passed with marker `UI_SANDBOX_STATUS_37DC798`; details are recorded above.

## Hardening added after comparing `/Users/gabrielpena/Downloads/code-source-main`

- Reference behavior reviewed:
  - sandbox settings include explicit filesystem/network controls;
  - read-only Bash validation treats `cd` + `git` as approval-required to reduce bare-repository/sandbox-escape risk;
  - Git control paths such as `git -C`, `--git-dir`, `--work-tree`, and `GIT_DIR=...` are security-relevant.
- Odysseus hardening added:
  - compound Bash commands that change directory and then run Git now require approval;
  - compound Bash commands that change directory before another command now require review;
  - Git control paths are extracted and passed through the existing workspace/protected-path checks.
  - strict literal Bash turns preserve extracted command arguments instead of trusting model transcription.

## Bare Git sentinel sandbox hardening

- Date: 2026-06-22
- Reference behavior reviewed:
  - sandboxed commands should not be able to plant top-level bare-repository sentinel paths such as `HEAD`, `objects`, `refs`, `hooks`, or `config` and then rely on later unsandboxed Git calls seeing the workspace as a bare repo.
- Odysseus hardening added:
  - existing top-level bare Git sentinel paths are included in sandbox deny-write paths;
  - Bash/Python capture absent sentinel paths before sandboxed execution;
  - after a sandboxed command finishes, newly planted sentinel files/directories are scrubbed;
  - planted sentinel symlinks are removed without following/deleting their targets;
  - pre-existing user files are preserved because only absent-before-execution candidates are eligible.
- Validation run:
  - `tests/test_sandbox_runner.py tests/test_operation_permissions.py tests/test_subprocess_sandbox_enforcement.py`: 68 passed, 2 skipped on macOS.
  - broader permission/sandbox/agent suite: 168 passed, 2 skipped on macOS.

## Persistent `allow_read` sandbox precedence

- Date: 2026-06-22
- Reference behavior reviewed:
  - `sandbox.filesystem.allowRead` is meant to re-allow reading inside a `denyRead` region.
- Odysseus hardening added:
  - persistent `filesystem.allow_read` is kept separate from baseline read mounts;
  - macOS appends persistent read allowances after `deny_read`, same as one-shot approvals;
  - Linux `bubblewrap` rebinds persistent read allowances after deny masks and recreates masked parent directories when needed;
  - Linux `firejail` emits persistent read whitelists after blacklists.
- Runtime tests prepared for Linux:
  - `test_linux_bubblewrap_runtime_honors_configured_allow_read_inside_mask`
  - This skips automatically on non-Linux or when `bubblewrap` is unavailable.
- Validation run:
  - `tests/test_sandbox_runner.py tests/test_operation_permissions.py tests/test_subprocess_sandbox_enforcement.py`: 72 passed, 3 skipped on macOS.
  - broader permission/sandbox/agent suite: 172 passed, 3 skipped on macOS.

## Sandbox filesystem glob warning

- Date: 2026-06-22
- Reference behavior reviewed:
  - Linux sandbox backends work with concrete mount paths, so glob-like filesystem settings can be misleading.
- Odysseus hardening added:
  - `sandbox_status` now warns when `filesystem.allow_read`, `allow_write`, `deny`, `deny_read`, or `deny_write` contains glob-like characters such as `*`, `?`, `[]`, or `{}`.
  - The warning explains that sandbox filesystem settings require concrete paths.
- Validation run:
  - `tests/test_sandbox_runner.py tests/test_operation_permissions.py tests/test_subprocess_sandbox_enforcement.py`: 73 passed, 3 skipped on macOS.
  - broader permission/sandbox/agent suite: 173 passed, 3 skipped on macOS.

## Sandbox readiness/status mode

- Date: 2026-06-22
- Reference behavior reviewed:
  - The reference sandbox manager reports when sandboxing is requested but unavailable, and separates warning/fallback from fail-closed blocking.
- Odysseus hardening added:
  - `sandbox_status` now reports `effective_mode`:
    - `disabled`: OS sandbox is off; operation permissions still apply;
    - `sandboxed`: Bash/Python commands will run through an OS sandbox backend;
    - `unsandboxed_fallback`: sandbox was requested but commands may run without OS sandbox because `fail_if_unavailable=false`;
    - `blocked`: sandbox was requested in fail-closed mode and no backend is available, so Bash/Python execution should be blocked.
  - The status payload also includes `enforcement_level`, `command_execution_blocked`, and `fallback_unsandboxed`.
  - `manage_settings action=sandbox_status` includes the effective mode and blocked flag in its short text response.
- Validation planned:
  - Added unit coverage for disabled, fail-open fallback, fail-closed blocking, and sandboxed-backend status cases.
- Validation run:
  - `tests/test_sandbox_runner.py tests/test_operation_permissions.py tests/test_subprocess_sandbox_enforcement.py`: 75 passed, 3 skipped on macOS.
  - broader permission/sandbox/agent suite: 247 passed, 3 skipped on macOS.

### UI regression: strict single-tool prompt with colon was not recognized

- UI marker: `UI_SANDBOX_MODE_515DB42`
- Prompt:
  - `Ejecuta exactamente una sola herramienta: manage_settings con este JSON: {"action":"sandbox_status"}`
  - `No uses ninguna otra herramienta.`
- Actual behavior before fix:
  - The first agent round did not enter strict single-tool mode.
  - Logs showed low-signal workspace fallback instead:
    - `selected_tools=['ask_user', 'get_workspace', 'glob', 'grep', 'ls', 'manage_memory', 'manage_skills', 'read_file', 'update_plan']`
    - `tools_sent=23`
  - The model drifted into unrelated skill/session work and eventually requested approval for `ls: /tmp`.
  - The pending permission card was denied in the UI to leave the chat safe.
- Root cause:
  - `_explicit_single_tool_control_relevant_tools()` recognized `la herramienta manage_settings` but not `herramienta: manage_settings`.
- Fix:
  - The explicit single-tool parser now accepts `herramienta: tool_name`, `tool: tool_name`, backticked names, and `una sola/single` qualifiers.
- Validation run:
  - Added `tests/test_chat_route_strict_tool_parser.py`.
  - `tests/test_chat_route_strict_tool_parser.py tests/test_chat_route_tool_policy.py tests/test_agent_intent_followthrough.py tests/test_agent_loop.py tests/test_tool_policy.py`: 102 passed on macOS.
  - broader permission/sandbox/agent suite: 255 passed, 3 skipped on macOS.
- Follow-up UI validation after fix:
  - Marker: `UI_SANDBOX_MODE_CLEAN_B5B8FA8`
  - Session: `1d4911dc-5487-4de2-946b-975ebaa368ea`
  - Created a clean chat via the visible `+ New` composer button.
  - Result: the UI executed exactly one `MANAGE_SETTINGS` call and returned:
    - `sandbox_effective_mode`: `sandboxed`
    - `sandbox_command_execution_blocked`: `false`
    - `sandbox_fallback_unsandboxed`: `false`
  - Logs:
    - `Suppressing memory/RAG/skills for explicit single-tool turn: ['manage_settings']`
    - round 1: `tools_sent=1 tool_names=['manage_settings']`
    - round 2: `tools_sent=0 tool_names=[]`
