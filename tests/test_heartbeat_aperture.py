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

import sys
from pathlib import Path

from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import bridge  # noqa: E402

client = TestClient(bridge.app)


def _hb():
    r = client.get("/api/heartbeat")
    assert r.status_code == 200
    return r.json()


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
    def test_every_surface_reports_both_a_total_and_a_default(self):
        surfaces = _hb()["aperture"]["surfaces"]
        assert surfaces, "an aperture with no surfaces is not an aperture"
        for name, s in surfaces.items():
            assert "on_disk" in s, f"{name} reports no total — the caller cannot know what it is missing"
            assert "default_shown" in s, f"{name} reports no default — the caller cannot know a cap applied"

    def test_lineage_totals_match_the_filesystem(self):
        s = _hb()["aperture"]["surfaces"]
        letters = Path.home() / ".sovereign" / "comms" / "letters"
        for bucket in ("to_arrival", "to_self", "breakthroughs"):
            key = f"lineage_{bucket}"
            assert s[key]["on_disk"] == len(list((letters / bucket).glob("*.md")))

    def test_it_names_what_is_not_reachable_at_all(self):
        """
        Resolved threads have no override parameter anywhere and no count.
        An aperture that lists only what it caps, while staying silent about
        what it cannot return under any parameter, is still hiding the harder
        half.
        """
        ap = _hb()["aperture"]
        assert ap.get("not_reachable"), "the aperture must name what no parameter can widen"

    def test_it_says_how_to_widen(self):
        assert _hb()["aperture"].get("how_to_widen")


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
