import json

from rkn_checker.models import BLOCKED_VERDICTS, CheckResult, Verdict


class TestVerdict:
    def test_verdict_is_string_enum(self):
        assert Verdict.OK == "OK"
        assert Verdict.DNS_BLOCK.value == "DNS_BLOCK"

    def test_blocked_verdicts_does_not_include_ok_or_down(self):
        # OK is success; DOWN means the site is dead, not that we're blocked.
        assert Verdict.OK not in BLOCKED_VERDICTS
        assert Verdict.DOWN not in BLOCKED_VERDICTS
        assert Verdict.UNKNOWN not in BLOCKED_VERDICTS

    def test_blocked_verdicts_contains_all_block_types(self):
        for v in (
            Verdict.DNS_BLOCK,
            Verdict.TCP_RESET,
            Verdict.TLS_BLOCK,
            Verdict.HTTP_STUB,
            Verdict.TIMEOUT,
        ):
            assert v in BLOCKED_VERDICTS


class TestCheckResult:
    def test_default_state(self):
        r = CheckResult(name="test", url="https://example.com/")
        assert r.verdict == Verdict.UNKNOWN
        assert r.notes == []
        assert r.tcp_ok is False
        assert r.tls_ok is False
        assert r.status_code is None

    def test_to_dict_serializes_verdict_as_string(self):
        r = CheckResult(name="test", url="https://example.com/")
        r.verdict = Verdict.TLS_BLOCK
        d = r.to_dict()
        assert d["verdict"] == "TLS_BLOCK"
        assert isinstance(d["verdict"], str)

    def test_to_dict_round_trips_through_json(self):
        r = CheckResult(name="test", url="https://example.com/")
        r.verdict = Verdict.OK
        r.tcp_ok = True
        r.tcp_time_ms = 12.5
        r.notes.append("looks fine")

        loaded = json.loads(json.dumps(r.to_dict()))

        assert loaded["name"] == "test"
        assert loaded["verdict"] == "OK"
        assert loaded["tcp_time_ms"] == 12.5
        assert loaded["notes"] == ["looks fine"]

    def test_notes_are_independent_between_instances(self):
        a = CheckResult(name="a", url="https://a.example/")
        b = CheckResult(name="b", url="https://b.example/")
        a.notes.append("only on a")
        assert b.notes == []
