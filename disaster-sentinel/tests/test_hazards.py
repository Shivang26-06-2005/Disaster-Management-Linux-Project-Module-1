from pathlib import Path

import pytest
from defusedxml.common import EntitiesForbidden

from sentinel.correlation.engine import haversine_km
from sentinel.hazards.feeds import covering_area, earthquake_severity, hazard_type_from_text, parse_cap, parse_sachet_rss, parse_usgs

FIX = Path(__file__).parent / "fixtures"


def test_usgs_filters_small_and_non_earthquake():
    out = parse_usgs((FIX / "usgs.geojson").read_bytes(), 4.0, 24)
    assert [h.external_id for h in out] == ["us7000tv5i", "big1"]
    big = out[1]
    assert (big.lat, big.lon) == (13.2, 80.3) and big.severity == "extreme" and big.verified
    assert (big.expires_at - big.starts_at).total_seconds() == 24 * 3600


def test_earthquake_severity_bands():
    assert [earthquake_severity(m) for m in (4.0, 5.0, 6.5, 7.5)] == ["minor", "moderate", "severe", "extreme"]


def test_sachet_rss_item():
    items = parse_sachet_rss((FIX / "sachet_rss.xml").read_bytes())
    assert items[0]["id"] == "1793733411445007" and items[0]["category"] == "Met"


def test_cap_without_inline_polygon_locates_by_place_names():
    h = parse_cap((FIX / "sachet_cap.xml").read_bytes())
    assert h.severity == "moderate" and h.hazard_type == "storm" and h.verified
    assert "Erode" in h.raw["located_by"] and "Tamil Nadu" not in h.raw["located_by"]
    # All three named districts must fall inside the circle.
    for lat, lon in [(11.34, 77.72), (10.01, 77.48), (11.11, 77.34)]:
        assert haversine_km(h.lat, h.lon, lat, lon) <= h.radius_km
    assert h.starts_at.utcoffset().total_seconds() == 5.5 * 3600


def test_cap_inline_polygon_is_used_when_present():
    data = (FIX / "sachet_cap.xml").read_bytes().replace(
        b"<cap:geocode>", b"<cap:polygon>13.0,80.0 13.0,80.4 13.4,80.4 13.4,80.0 13.0,80.0</cap:polygon><cap:geocode>", 1
    )
    h = parse_cap(data)
    assert h.raw["located_by"] == "polygon" and 13.0 < h.lat < 13.4


@pytest.mark.parametrize("old,new", [(b"<cap:status>Actual", b"<cap:status>Test"), (b"<cap:msgType>Alert", b"<cap:msgType>Cancel")])
def test_test_and_cancel_alerts_are_ignored(old, new):
    assert parse_cap((FIX / "sachet_cap.xml").read_bytes().replace(old, new)) is None


def test_unknown_place_leaves_hazard_unlocated():
    data = (FIX / "sachet_cap.xml").read_bytes().replace(b"Erode, Theni, Tiruppur districts of Tamil Nadu", b"Somewhere unnamed")
    h = parse_cap(data)
    assert h.lat is None and h.raw["located_by"] == "none"


def test_xml_entity_attack_is_rejected():
    bomb = b'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY a "b">]><rss><item><guid>&a;</guid></item></rss>'
    with pytest.raises(EntitiesForbidden):
        parse_sachet_rss(bomb)


def test_hazard_type_words():
    assert hazard_type_from_text("Severe Cyclonic storm cyclone warning") == "cyclone"
    assert hazard_type_from_text("Massive gas leak at plant") == "industrial"
    assert hazard_type_from_text("a pleasant day") == "other"


def test_place_lookup_does_not_match_inside_words():
    assert covering_area("the pune-based firm") is not None
    assert covering_area("opportune moment") is None
