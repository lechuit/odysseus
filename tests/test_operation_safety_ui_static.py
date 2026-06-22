"""Static regressions for the Settings → Agent Tools operation safety panel."""

from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
INDEX = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
ADMIN_JS = (ROOT / "static" / "js" / "admin.js").read_text(encoding="utf-8")
STYLE = (ROOT / "static" / "style.css").read_text(encoding="utf-8")


def test_operation_safety_panel_is_present_in_agent_tools():
    assert 'id="adm-operation-safety"' in INDEX
    assert "Operation Safety" in INDEX
    assert "Permission rules, session approvals, and OS sandbox status" in INDEX
    assert "loadOperationSafety();" in ADMIN_JS
    assert "initOperationSafety" in ADMIN_JS


def test_operation_safety_renderer_escapes_numeric_values_as_strings():
    assert "esc(String(value))" in ADMIN_JS
    assert "esc(String(fs.allow_read_count || 0))" in ADMIN_JS
    assert "esc(String(counts.session || 0))" in ADMIN_JS


def test_operation_safety_styles_define_layout_and_responsive_state():
    assert ".operation-safety-grid {" in STYLE
    assert ".operation-safety-columns {" in STYLE
    assert ".operation-safety-badge-ok {" in STYLE
    assert "@media (max-width: 720px)" in STYLE
