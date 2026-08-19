from guppy_ics.protocols.registry import available_protocols, load_plugins


def test_neighbor_discovery_runs_with_limited_protocol_selection():
    slugs = {plugin.slug for plugin in load_plugins(enabled=["profinet"])}

    assert "profinet" in slugs
    assert "lldp" in slugs
    assert "cdp" in slugs


def test_neighbor_discovery_is_not_shown_as_user_filter_choice():
    slugs = {protocol["slug"] for protocol in available_protocols()}

    assert "lldp" not in slugs
    assert "cdp" not in slugs
