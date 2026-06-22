from pathlib import Path


def test_workspace_copy_mentions_optional_os_sandbox():
    source = Path("static/js/workspace.js").read_text(encoding="utf-8")

    assert "not sandboxed" not in source
    assert "may be OS-sandboxed" in source
    assert "Without sandbox enabled" in source
