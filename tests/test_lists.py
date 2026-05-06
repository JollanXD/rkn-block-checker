from __future__ import annotations

import json
from pathlib import Path

import pytest

from rkn_checker.lists import ListLoadError, load_targets


def _write(tmp_path: Path, name: str, content: str) -> str:
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return str(p)


class TestJsonFormat:
    def test_basic_object_loads(self, tmp_path):
        path = _write(tmp_path, "list.json", json.dumps({
            "google": "https://google.com",
            "github": "https://github.com",
        }))
        out = load_targets(path)
        assert out == {
            "google": "https://google.com",
            "github": "https://github.com",
        }

    def test_url_without_scheme_gets_https(self, tmp_path):
        path = _write(tmp_path, "list.json", json.dumps({"x": "example.com"}))
        out = load_targets(path)
        assert out == {"x": "https://example.com"}

    def test_invalid_json_raises_with_path_in_message(self, tmp_path):
        path = _write(tmp_path, "list.json", "{ not valid json")
        with pytest.raises(ListLoadError) as ei:
            load_targets(path)
        assert "list.json" in str(ei.value)

    def test_top_level_array_rejected(self, tmp_path):
        path = _write(tmp_path, "list.json", json.dumps(["a", "b"]))
        with pytest.raises(ListLoadError):
            load_targets(path)

    def test_non_string_value_rejected(self, tmp_path):
        path = _write(tmp_path, "list.json", json.dumps({"x": 42}))
        with pytest.raises(ListLoadError):
            load_targets(path)


class TestTextFormat:
    def test_bare_url_lines_get_autonames(self, tmp_path):
        path = _write(tmp_path, "list.txt", "\n".join([
            "https://example.com",
            "https://www.bbc.com/russian",
        ]))
        out = load_targets(path)
        assert "example-com" in out
        assert "www-bbc-com" in out
        assert out["example-com"] == "https://example.com"

    def test_name_then_url_form(self, tmp_path):
        path = _write(tmp_path, "list.txt", "myname https://example.com")
        out = load_targets(path)
        assert out == {"myname": "https://example.com"}

    def test_name_equals_url_form(self, tmp_path):
        path = _write(tmp_path, "list.txt", "myname=https://example.com")
        out = load_targets(path)
        assert out == {"myname": "https://example.com"}

    def test_comments_are_skipped(self, tmp_path):
        path = _write(tmp_path, "list.txt", "\n".join([
            "# this is a comment",
            "  # indented comment too",
            "real https://example.com  # trailing comment",
            "",
        ]))
        out = load_targets(path)
        assert out == {"real": "https://example.com"}

    def test_blank_lines_skipped(self, tmp_path):
        path = _write(tmp_path, "list.txt", "\n\n\nx https://e.com\n\n")
        out = load_targets(path)
        assert out == {"x": "https://e.com"}

    def test_url_without_scheme_normalized(self, tmp_path):
        path = _write(tmp_path, "list.txt", "x example.com")
        out = load_targets(path)
        assert out == {"x": "https://example.com"}

    def test_empty_file_raises(self, tmp_path):
        path = _write(tmp_path, "list.txt", "# only comments here\n#and here\n")
        with pytest.raises(ListLoadError):
            load_targets(path)

    def test_duplicate_names_overwrite(self, tmp_path):
        path = _write(tmp_path, "list.txt", "\n".join([
            "x https://first.com",
            "x https://second.com",
        ]))
        out = load_targets(path)
        assert out == {"x": "https://second.com"}


class TestPathHandling:
    def test_missing_file_raises(self, tmp_path):
        with pytest.raises(ListLoadError) as ei:
            load_targets(str(tmp_path / "nope.txt"))
        assert "not found" in str(ei.value)

    def test_format_picked_by_extension(self, tmp_path):
        path = _write(tmp_path, "noext", '{"x": "https://e.com"}')
        out = load_targets(path)
        assert len(out) == 1