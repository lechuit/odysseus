from routes.chat_routes import _explicit_single_tool_control_relevant_tools


def test_explicit_single_tool_parser_accepts_colon_after_tool_word():
    prompt = (
        "UI_SANDBOX_MODE_515DB42\n"
        "Ejecuta exactamente una sola herramienta: manage_settings con este JSON:\n"
        '{"action":"sandbox_status"}\n'
        "No uses ninguna otra herramienta."
    )

    assert _explicit_single_tool_control_relevant_tools(prompt) == {"manage_settings"}


def test_explicit_single_tool_parser_accepts_backticked_tool_name():
    prompt = "Run exactly one tool: `manage_settings` with {\"action\":\"sandbox_status\"}. Do not use other tools."

    assert _explicit_single_tool_control_relevant_tools(prompt) == {"manage_settings"}
