from backend.ai.scan_profiles import (
    max_tool_budget,
    resolve_scan_tools,
    scan_profile_prompt_block,
)


def test_resolve_basic_subset_of_catalog():
    tools = resolve_scan_tools("basic")
    assert len(tools) >= 8
    assert "nmap" in tools
    assert "nuclei" in tools


def test_resolve_full_is_catalog():
    from backend.tool_catalog import TOOL_CATALOG

    full = resolve_scan_tools("full")
    assert len(full) == len(TOOL_CATALOG)


def test_custom_dedupes():
    tools = resolve_scan_tools("custom", ["nmap", "NMAP", "nikto"])
    assert tools == ["nmap", "nikto"]


def test_max_tool_budget_scales():
    assert max_tool_budget("full", 78) >= 150


def test_resolve_full_allowed():
    from backend.config_tools import ALLOWED_TOOLS

    tools = resolve_scan_tools("full", include_all_allowed=True)
    assert len(tools) == len(ALLOWED_TOOLS)


def test_prompt_block_lists_tools():
    block = scan_profile_prompt_block("basic", ["nmap"], target="example.com")
    assert "nmap" in block
    assert "example.com" in block
