# UI permission + sandbox test log

Date: 2026-06-22  
Local app: `http://127.0.0.1:7860/`  
Local install: `/Users/gabrielpena/Library/Application Support/Odysseus`

## Completed UI checks

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

## Important UI testing note

The in-app textarea did not submit reliably with `Enter` during these tests. For future UI automation, after typing the prompt, click the visible send button.

## Pending UI checks for sandbox hardening

These should be run after the sandbox runner changes are installed locally and the app is restarted.

1. `sandbox_status`
   - Ask the agent to report the sandbox status via settings.
   - Expected on this Mac: `sandbox-exec` available; sandbox may be disabled until explicitly enabled.

2. Enable local sandbox
   - Ask the agent to set sandbox preset `local` or `strict_local`.
   - Expected: settings update succeeds and `sandbox_status` reports enabled.

3. Approved outside read
   - Create/read a known file outside the active workspace.
   - Expected: approval card appears; after `Permitir una vez`, the exact operation succeeds.

4. Approved outside write
   - Write to a reviewed file or directory outside the active workspace.
   - Expected: approval card appears; after approval, sandbox receives a narrow write allowance and the operation succeeds.

5. Sensitive read/write block or approval
   - Try reading/writing protected locations such as `.ssh`, `.gnupg`, `.env`, `.git/config`, `.github/workflows`.
   - Expected: operation is never silent. It should ask or deny depending on builtin severity/rule.

6. Network-deny sandbox override
   - Enable sandbox with network denied.
   - Try a Bash/Python network operation.
   - Expected: approval card appears; if approved, only that reviewed operation receives a network override.

