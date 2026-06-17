from shared.source_registry import get_registered_sources, get_mitre_coverage

def test_get_registered_sources():
    sources = get_registered_sources()
    assert isinstance(sources, list)
    assert len(sources) > 0
    assert "id" in sources[0]
    assert "connected" in sources[0]

def test_get_mitre_coverage():
    coverage = get_mitre_coverage()
    assert isinstance(coverage, dict)
    for tactic, sources in coverage.items():
        assert len(sources) > 0
