# Linux sandbox validation

Use this checklist when validating Odysseus sandbox behavior on a real Linux host.

The important distinction is:

- `sandbox_status` proves a backend is configured and can start.
- `sandbox_self_test` proves the sandbox policy actually enforces filesystem boundaries.

## Quick CLI validation

From the Odysseus repo or local install:

```bash
python scripts/sandbox_self_test.py --preset strict_local --pretty --fail-on-fail
```

Expected successful Linux shape:

```json
{
  "summary": {
    "overall_passed": true,
    "skipped": false,
    "passed_count": 5,
    "total_count": 5,
    "failed_checks": []
  },
  "status": {
    "platform": "linux",
    "sandboxed": true,
    "selected_backend": "bubblewrap"
  }
}
```

`selected_backend` may be `firejail` if `bubblewrap` is unavailable or fails its runtime smoke test.

## UI validation prompt

Create a clean chat and send this prompt by clicking the visible Send button:

```text
UI_SANDBOX_SELF_TEST_LINUX
Ejecuta exactamente una sola herramienta: manage_settings con argumentos {"action":"sandbox_self_test"}.
No uses otras herramientas. Después responde solo JSON con estos campos: overall_passed, skipped, passed_count, total_count, selected_backend, platform, failed_checks.
```

Expected:

- one visible `MANAGE_SETTINGS done` tool card;
- `overall_passed: true`;
- `skipped: false`;
- `passed_count: 5`;
- `total_count: 5`;
- `platform: linux`;
- `selected_backend: bubblewrap` or `firejail`;
- `failed_checks: []`.

## What the self-test verifies

The self-test creates temporary sibling directories, runs controlled sandboxed commands, and cleans them up.

Checks:

1. workspace writes are allowed;
2. outside writes are denied without an operation allowance;
3. protected reads such as workspace `.env` do not leak contents;
4. operation-scoped outside write allowances work;
5. operation-scoped protected read allowances work.

If the sandbox is disabled or no backend is active, the self-test skips instead of intentionally writing outside the workspace unsandboxed.

## Dependency notes

For Debian/Ubuntu-like hosts:

```bash
sudo apt-get update
sudo apt-get install -y bubblewrap firejail
```

Then run:

```bash
python scripts/sandbox_self_test.py --preset strict_local --pretty --fail-on-fail
```

If `bubblewrap` is installed but fails with a namespace or permissions error, check:

- unprivileged user namespaces;
- container restrictions;
- AppArmor/SELinux policy;
- whether `firejail` is installed and runnable as fallback.

## Docker-based smoke, when Docker daemon is available

From macOS or another host with a running Docker daemon:

```bash
docker run --rm -it \
  -v "$PWD":/work \
  -w /work \
  python:3.11-slim \
  sh -lc 'apt-get update && apt-get install -y bubblewrap firejail && python scripts/sandbox_self_test.py --preset strict_local --pretty --fail-on-fail'
```

Some containers intentionally disallow the namespaces required by `bubblewrap`; in that case the expected outcome is a clear status/self-test failure explaining that installed Linux backends failed runtime smoke tests. That is still useful evidence: it proves Odysseus is not silently claiming to be sandboxed.
