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
