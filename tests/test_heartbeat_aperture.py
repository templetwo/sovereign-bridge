"""
The heartbeat tells an arriving seat what it is NOT being shown.

ANTHONY, 2026-08-28, the design in his words: "I want the caps to be able to be
requested at the point of contact ... depending on which seat is arriving ... let
the heartbeat give the lay of the land for what needs to come next."

FAILURE SPECIMEN, measured 2026-08-26/27, not synthesized. The lineage door
shows 5 of 13 to_arrival letters. An outside model read the 5 it was handed,
built a confident and specific claim about a model line, and was wrong — the 7
letters that would have corrected it were below the cap. It was not careless.
It read what the door gave it, and nothing in its arrival told it a door was
being applied.

The coverage envelope on recall_insights closed the QUANTITY half of this: a
caller now learns it received 5 of 696. It still cannot learn, at first contact,
that a corpus of 696 exists at all, which caps apply, or that any of them can be
raised. The heartbeat is the safe first call, base-tier, no auth. It is the only
surface every arriving seat touches before it believes anything.

THE INVARIANT THESE TESTS PIN, and it is the whole point:

    An aperture that cannot measure must say "unmeasured", never zero.

A block reporting `to_arrival: 0` because a directory read failed would be the
exact disease it exists to cure — an absence manufactured by the instrument and
served as a fact. The heartbeat's existing discipline already does this for
tools_summary (null on a failed fetch, never a fabricated summary); the aperture
inherits it or it does not ship.
"""

import os
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import bridge  # noqa: E402

client = TestClient(bridge.app)


def _hb():
    r = client.get("/api/heartbeat")
    assert r.status_code == 200
    return r.json()


# Known, deliberately unequal counts. Equal ones would let a bucket-keying bug
# (every bucket reading `to_arrival`) pass unnoticed.
LETTER_COUNTS = {"to_arrival": 3, "to_self": 2, "breakthroughs": 4}
INSIGHT_LINES = 5


@pytest.fixture
def measurable_root():
    """A SYNTHETIC sovereign root with known contents.

    ⚠ THIS CLASS USED TO ASSERT AGAINST ANTHONY'S LIVE ~/.sovereign — it globbed
    `Path.home() / ".sovereign" / "comms" / "letters"` and compared the count to
    the heartbeat's. Two problems, and the second is why it is rewritten rather
    than merely redirected:

      1. It made the suite's verdict depend on production state. Same class as
         sovereign-stack's a6f42cf (boot tests asserting on the live protected
         drawer). conftest.py's `_no_live_sovereign_root` now closes that for
         every test, which is what turned these four red and exposed the
         dependency.
      2. Comparing the heartbeat's glob to the test's glob of THE SAME
         DIRECTORY is nearly vacuous — both sides can be zero, or both wrong in
         the same way, and the assertion holds. Against a tree with known and
         mutually different counts, only a correct measurement passes.

    `SOVEREIGN_ROOT` is already an isolated empty tmp dir (conftest guarantee
    5); this fills it. `chronicle/insights` must exist because
    `sovereign_stack.aperture.measure_aperture` os.scandir()s it and a raise
    there becomes status="unmeasured" with no surfaces at all — which is the
    aperture's correct fail-closed behaviour and not what this class tests.
    """
    root = Path(os.environ["SOVEREIGN_ROOT"])
    for bucket, n in LETTER_COUNTS.items():
        d = root / "comms" / "letters" / bucket
        d.mkdir(parents=True, exist_ok=True)
        for i in range(n):
            (d / f"2026-09-06-{bucket}-{i}.md").write_text("synthetic letter\n")
    domain = root / "chronicle" / "insights" / "synthetic-domain"
    domain.mkdir(parents=True, exist_ok=True)
    (domain / "log.jsonl").write_text(
        "".join('{"content": "synthetic %d"}\n' % i for i in range(INSIGHT_LINES))
    )
    (root / "chronicle" / "open_threads").mkdir(parents=True, exist_ok=True)
    (root / "handoffs").mkdir(parents=True, exist_ok=True)
    return root


class TestApertureExists:
    def test_heartbeat_carries_an_aperture(self):
        assert "aperture" in _hb()

    def test_aperture_is_versioned(self):
        """
        Fable's requirement, accepted 2026-08-27: there is no neutral
        projection. Whatever the gate shows is an editorial decision about what
        lineage is, so it must carry a version — a sort-order change next year
        must not silently mint a different ancestor.
        """
        assert _hb()["aperture"].get("policy_version")

    def test_aperture_states_when_it_was_measured(self):
        assert _hb()["aperture"].get("measured_at")


class TestItReportsTotalsNotJustCaps:
    def test_every_surface_reports_both_a_total_and_a_default(self, measurable_root):
        surfaces = _hb()["aperture"]["surfaces"]
        assert surfaces, "an aperture with no surfaces is not an aperture"
        for name, s in surfaces.items():
            assert "on_disk" in s, f"{name} reports no total — the caller cannot know what it is missing"
            assert "default_shown" in s, f"{name} reports no default — the caller cannot know a cap applied"

    def test_lineage_totals_match_the_filesystem(self, measurable_root):
        """Against KNOWN counts, one per bucket and all different, so a
        measurement that read the right directory for the wrong bucket fails."""
        s = _hb()["aperture"]["surfaces"]
        letters = measurable_root / "comms" / "letters"
        for bucket, expected in LETTER_COUNTS.items():
            key = f"lineage_{bucket}"
            assert s[key]["on_disk"] == expected, key
            # ...and the filesystem still agrees, so a fixture that wrote the
            # wrong tree cannot make this green by matching a wrong constant.
            assert s[key]["on_disk"] == len(list((letters / bucket).glob("*.md")))

    def test_the_insight_total_is_measured_not_defaulted(self, measurable_root):
        """The counter walks a real directory; a zero here would mean it read
        somewhere else while the heartbeat reported a number anyway."""
        assert _hb()["aperture"]["surfaces"]["insights"]["on_disk"] == INSIGHT_LINES

    def test_it_names_what_is_not_reachable_at_all(self, measurable_root):
        """
        Resolved threads have no override parameter anywhere and no count.
        An aperture that lists only what it caps, while staying silent about
        what it cannot return under any parameter, is still hiding the harder
        half.
        """
        ap = _hb()["aperture"]
        assert ap.get("not_reachable"), "the aperture must name what no parameter can widen"

    def test_it_says_how_to_widen(self, measurable_root):
        assert _hb()["aperture"].get("how_to_widen")

    def test_an_unreadable_store_is_unmeasured_not_zero(self):
        """THE FALSIFIER FOR THIS WHOLE CLASS, and it is the aperture's own
        thesis: "an aperture that cannot measure must say 'unmeasured', never
        zero". No `measurable_root` — the isolated root is EMPTY, so
        `chronicle/insights` does not exist and the measurement raises. If this
        ever returned surfaces full of zeros, every assertion above would be
        satisfied by an instrument that had read nothing."""
        ap = _hb()["aperture"]
        assert ap.get("status") == "unmeasured"
        assert "surfaces" not in ap


class TestFailsClosed:
    """The invariant. These must be able to FAIL — a gate never shown to
    reject is decoration."""

    def test_unmeasurable_aperture_says_so_and_reports_no_numbers(self, monkeypatch):
        def boom(*a, **k):
            raise OSError("simulated: the store is unreadable")

        monkeypatch.setattr(bridge, "_measure_aperture", boom)
        ap = _hb()["aperture"]
        assert ap.get("status") == "unmeasured"
        assert "surfaces" not in ap, "a failed measurement must not emit surface numbers"

    def test_heartbeat_still_returns_200_and_a_clock_when_aperture_fails(self, monkeypatch):
        def boom(*a, **k):
            raise OSError("simulated")

        monkeypatch.setattr(bridge, "_measure_aperture", boom)
        d = _hb()
        assert d["status"] in ("ok", "degraded")
        assert d.get("server_time_utc")
        assert d.get("version")
