from rkn_checker.output import _summary_verdict


class TestSummaryVerdict:
    def test_degraded_connection_when_whitelist_mostly_fails(self):
        _, msg = _summary_verdict(
            white_ok=5, white_total=20, black_ok=0, black_blocked=15, black_total=15
        )
        assert "degraded" in msg.lower()

    def test_no_blocks_when_blacklist_fully_open(self):
        _, msg = _summary_verdict(
            white_ok=20, white_total=20, black_ok=15, black_blocked=0, black_total=15
        )
        assert "not in" in msg.lower()

    def test_blocked_zone_when_majority_of_blacklist_fails(self):
        _, msg = _summary_verdict(
            white_ok=20, white_total=20, black_ok=3, black_blocked=12, black_total=15
        )
        assert "are in" in msg.lower()

    def test_partial_blocks_when_some_blacklist_loads(self):
        _, msg = _summary_verdict(
            white_ok=20, white_total=20, black_ok=10, black_blocked=5, black_total=15
        )
        assert "partial" in msg.lower()

    def test_partial_blocks_at_threshold_boundary(self):
        # 11/15 = ~73% — should already be over the 70% threshold.
        _, msg = _summary_verdict(
            white_ok=20, white_total=20, black_ok=3, black_blocked=11, black_total=15
        )
        assert "are in" in msg.lower()

    def test_whitelist_check_takes_priority(self):
        _, msg = _summary_verdict(
            white_ok=2, white_total=20, black_ok=0, black_blocked=15, black_total=15
        )
        assert "degraded" in msg.lower()
