from unittest.mock import patch, MagicMock

from rkn_checker.http import (
    GENERIC_USER_AGENT,
    HONEST_USER_AGENT,
    build_headers,
    fetch,
    looks_like_stub,
)


class TestFetch:
    @patch("rkn_checker.http.requests.get")
    def test_success_returns_probe(self, mock_get):
        resp = MagicMock()
        resp.status_code = 200
        resp.elapsed.total_seconds.return_value = 0.1
        resp.text = "<html>ok</html>"
        mock_get.return_value = resp
        probe = fetch("https://example.com")
        assert probe.status_code == 200
        assert probe.error is None

    @patch("rkn_checker.http.requests.get",
           side_effect=__import__("requests").exceptions.Timeout("t"))
    def test_timeout_returns_timed_out_probe(self, mock_get):
        probe = fetch("https://example.com")
        assert probe.timed_out is True
        assert probe.error == "timeout"

    @patch("rkn_checker.http.requests.get",
           side_effect=__import__("requests").exceptions.RequestException("e"))
    def test_generic_error_returns_error_probe(self, mock_get):
        probe = fetch("https://example.com")
        assert probe.error is not None
        assert probe.timed_out is False

    @patch("rkn_checker.http.requests.get")
    def test_passes_timeout_param(self, mock_get):
        resp = MagicMock()
        resp.status_code = 200
        resp.elapsed.total_seconds.return_value = 0.05
        resp.text = "ok"
        mock_get.return_value = resp
        fetch("https://example.com", timeout=2.0)
        mock_get.assert_called_once()
        assert mock_get.call_args[1]["timeout"] == 2.0


class TestUserAgentDefault:
    """The default UA must be generic to avoid leaving a unique fingerprint
    in network logs along the path. This is the user-protection behaviour;
    any regression here would re-expose users to log-correlation risk."""

    @patch("rkn_checker.http.requests.get")
    def test_default_ua_is_generic_chrome(self, mock_get):
        resp = MagicMock()
        resp.status_code = 200
        resp.elapsed.total_seconds.return_value = 0.05
        resp.text = "ok"
        mock_get.return_value = resp

        fetch("https://example.com")

        sent_headers = mock_get.call_args[1]["headers"]
        assert sent_headers["User-Agent"] == GENERIC_USER_AGENT
        # Sanity: it shouldn't include the project name in any header by default.
        assert "rkn" not in sent_headers["User-Agent"].lower()

    @patch("rkn_checker.http.requests.get")
    def test_default_sends_chrome_like_header_set(self, mock_get):
        # A correct UA alone isn't enough — Chrome sends a specific *set* of
        # headers; missing ones (Sec-Fetch-*, Accept-Language, etc) make the
        # request stand out even if UA looks right.
        resp = MagicMock()
        resp.status_code = 200
        resp.elapsed.total_seconds.return_value = 0.05
        resp.text = "ok"
        mock_get.return_value = resp

        fetch("https://example.com")

        sent_headers = mock_get.call_args[1]["headers"]
        for h in ("Accept", "Accept-Language", "Accept-Encoding",
                  "Sec-Fetch-Dest", "Sec-Fetch-Mode", "Sec-Fetch-Site",
                  "Upgrade-Insecure-Requests"):
            assert h in sent_headers, f"missing browser-like header: {h}"


class TestUserAgentIdentify:
    """When --identify is on, the request *should* be self-identifying so
    operators of probed infrastructure can distinguish this tool from
    anonymous scraping or attacks."""

    @patch("rkn_checker.http.requests.get")
    def test_identify_flag_uses_honest_ua(self, mock_get):
        resp = MagicMock()
        resp.status_code = 200
        resp.elapsed.total_seconds.return_value = 0.05
        resp.text = "ok"
        mock_get.return_value = resp

        fetch("https://example.com", identify=True)

        sent_headers = mock_get.call_args[1]["headers"]
        assert sent_headers["User-Agent"] == HONEST_USER_AGENT
        assert "rkn-block-checker" in sent_headers["User-Agent"]

    def test_build_headers_default_does_not_identify(self):
        h = build_headers(identify=False)
        assert "rkn" not in h["User-Agent"].lower()

    def test_build_headers_identify_keeps_other_headers(self):
        # Switching to identify mode must not strip the rest of the
        # browser-like header set — only swap UA.
        default = build_headers(identify=False)
        identifying = build_headers(identify=True)
        assert set(default.keys()) == set(identifying.keys())
        assert identifying["User-Agent"] != default["User-Agent"]

    def test_build_headers_returns_independent_copies(self):
        # Mutating the returned dict must not affect future callers.
        a = build_headers()
        a["X-Test"] = "1"
        b = build_headers()
        assert "X-Test" not in b


class TestLooksLikeStubNegative:
    def test_generic_blocked_by_does_not_match(self):
        assert looks_like_stub("this resource is blocked by your provider") is False

    def test_bare_rkn_gov_ru_does_not_match(self):
        assert looks_like_stub("for more information visit rkn.gov.ru") is False

    def test_generic_po_resheniu_does_not_match(self):
        assert looks_like_stub("по решению суда") is False
