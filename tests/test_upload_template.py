from pathlib import Path


def test_protocol_checkboxes_are_not_preselected_by_default():
    template = Path("guppy_ics/web/templates/upload.html").read_text(encoding="utf-8")

    assert "proto.safe_by_default" not in template
    assert 'name="oads_enhance"' in template


def test_base_template_uses_guppy_logo_asset():
    template = Path("guppy_ics/web/templates/base.html").read_text(encoding="utf-8")

    assert "🐟" in template
    assert "brand-name\">Guppy ICS" in template
