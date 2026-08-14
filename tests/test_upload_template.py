from pathlib import Path


def test_protocol_checkboxes_are_not_preselected_by_default():
    template = Path("guppy_ics/web/templates/upload.html").read_text(encoding="utf-8")

    assert "proto.safe_by_default" not in template
    assert 'name="oads_enhance"' in template
