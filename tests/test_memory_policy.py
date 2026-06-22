from src.chat_processor import ChatProcessor
from src.memory_policy import (
    auto_memory_enabled_from_prefs,
    explicit_memory_requested,
    memory_enabled_from_prefs,
    rag_enabled_from_request_and_prefs,
)
from src.tool_index import ALWAYS_AVAILABLE, ToolIndex


def test_memory_and_auto_memory_default_off():
    assert memory_enabled_from_prefs({}) is False
    assert auto_memory_enabled_from_prefs({}) is False


def test_memory_and_auto_memory_require_explicit_prefs():
    assert memory_enabled_from_prefs({"memory_enabled": True}) is True
    assert auto_memory_enabled_from_prefs({"memory_enabled": True, "auto_memory": True}) is True
    assert auto_memory_enabled_from_prefs({"auto_memory": True}) is False


def test_personal_rag_default_off_but_request_can_opt_in():
    assert rag_enabled_from_request_and_prefs(None, {}) is False
    assert rag_enabled_from_request_and_prefs("false", {"rag_enabled": True}) is False
    assert rag_enabled_from_request_and_prefs("true", {}) is True
    assert rag_enabled_from_request_and_prefs(None, {"rag_enabled": True}) is True


def test_explicit_memory_request_detection_spanish_and_english():
    assert explicit_memory_requested("recuerda esto para mañana")
    assert explicit_memory_requested("what do you remember about me?")
    assert not explicit_memory_requested("my name is Gabriel")
    assert not explicit_memory_requested("sin usar memoria ni documentos")
    assert not explicit_memory_requested("guarda esto en un archivo")


def test_chat_processor_defaults_do_not_touch_memory_or_rag():
    class ExplodingMemory:
        def load(self, owner=None):
            raise AssertionError("memory should be opt-in")

    class ExplodingRag:
        def search(self, *args, **kwargs):
            raise AssertionError("RAG should be opt-in")

    class Docs:
        rag_manager = ExplodingRag()

    processor = ChatProcessor(memory_manager=ExplodingMemory(), personal_docs_manager=Docs())

    preface, rag_sources, web_sources = processor.build_context_preface(
        message="hola",
        session=None,
    )

    assert preface
    assert rag_sources == []
    assert web_sources == []


def test_manage_memory_is_not_always_available_but_explicit_intent_adds_it():
    assert "manage_memory" not in ALWAYS_AVAILABLE

    idx = object.__new__(ToolIndex)
    idx.retrieve = lambda query, k=8: []

    assert "manage_memory" in idx.get_tools_for_query("recuerda esto: uso respuestas cortas")
    assert "manage_memory" not in idx.get_tools_for_query("hola, puedes revisar esto?")
    assert "manage_memory" not in idx.get_tools_for_query("sin usar memoria ni documentos")
