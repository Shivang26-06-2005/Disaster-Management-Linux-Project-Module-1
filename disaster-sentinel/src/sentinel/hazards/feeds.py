"""External hazard indicators: USGS earthquakes and NDMA SACHET CAP alerts.

Parsers are pure functions over bytes, so they are tested against fixtures shaped
like the real feeds. XML goes through defusedxml because it comes from the network.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime

from defusedxml import ElementTree as ET

from .gazetteer import locate_all

CAP_NS = {"cap": "urn:oasis:names:tc:emergency:cap:1.2"}
CAP_SEVERITY = {"Extreme": "extreme", "Severe": "severe", "Moderate": "moderate", "Minor": "minor"}

_TYPE_WORDS = [
    ("cyclone", ("cyclone", "hurricane", "typhoon")),
    ("earthquake", ("earthquake", "tremor", "seismic")),
    ("tsunami", ("tsunami",)),
    ("flood", ("flood", "inundation", "cloudburst", "dam ")),
    ("landslide", ("landslide", "avalanche", "mudslide")),
    ("fire", ("wildfire", "forest fire", "fire")),
    ("heatwave", ("heat wave", "heatwave")),
    ("storm", ("thunderstorm", "lightning", "squall", "storm", "rain", "hail")),
    ("industrial", ("explosion", "chemical", "gas leak", "nuclear", "industrial")),
]


@dataclass
class ParsedHazard:
    source: str
    external_id: str
    hazard_type: str
    severity: str
    title: str
    lat: float | None
    lon: float | None
    radius_km: float
    verified: bool
    starts_at: datetime
    expires_at: datetime
    raw: dict = field(default_factory=dict)


def hazard_type_from_text(text: str) -> str:
    lowered = text.lower()
    for name, words in _TYPE_WORDS:
        if any(w in lowered for w in words):
            return name
    return "other"


def earthquake_radius_km(magnitude: float) -> float:
    """Rough zone of possible infrastructure impact. A design heuristic, not seismology."""
    return round(min(10 ** (0.4 * magnitude - 0.3), 800.0), 1)


def earthquake_severity(magnitude: float) -> str:
    if magnitude >= 7:
        return "extreme"
    if magnitude >= 6:
        return "severe"
    if magnitude >= 4.5:
        return "moderate"
    return "minor"


def parse_usgs(data: bytes, min_magnitude: float, ttl_h: float) -> list[ParsedHazard]:
    doc = json.loads(data)
    out = []
    for feature in doc.get("features", []):
        props = feature.get("properties") or {}
        coords = (feature.get("geometry") or {}).get("coordinates") or []
        mag = props.get("mag")
        if mag is None or mag < min_magnitude or len(coords) < 2 or props.get("type") != "earthquake":
            continue
        start = datetime.fromtimestamp(props["time"] / 1000, timezone.utc)
        out.append(ParsedHazard(
            source="usgs",
            external_id=str(feature["id"]),
            hazard_type="earthquake",
            severity=earthquake_severity(mag),
            title=props.get("title") or f"M {mag} earthquake",
            lat=float(coords[1]),
            lon=float(coords[0]),
            radius_km=earthquake_radius_km(mag),
            verified=True,
            starts_at=start,
            expires_at=start + timedelta(hours=ttl_h),
            raw={"mag": mag, "depth_km": coords[2] if len(coords) > 2 else None,
                 "url": props.get("url"), "status": props.get("status")},
        ))
    return out


def parse_sachet_rss(data: bytes) -> list[dict]:
    root = ET.fromstring(data)
    items = []
    for item in root.iter("item"):
        items.append({
            "id": (item.findtext("guid") or item.findtext("link") or "").strip(),
            "title": (item.findtext("title") or "").strip(),
            "link": (item.findtext("link") or "").strip(),
            "category": (item.findtext("category") or "").strip(),
            "author": (item.findtext("author") or "").strip(),
            "pubDate": (item.findtext("pubDate") or "").strip(),
        })
    return [i for i in items if i["id"]]


def _centroid_radius(polygon_text: str) -> tuple[float, float, float] | None:
    """CAP polygons are "lat,lon lat,lon ...". Returns the centre and a covering radius."""
    points = []
    for pair in polygon_text.split():
        try:
            lat, lon = (float(x) for x in pair.split(",")[:2])
        except ValueError:
            continue
        if -90 <= lat <= 90 and -180 <= lon <= 180:
            points.append((lat, lon))
    if not points:
        return None
    lat = sum(p[0] for p in points) / len(points)
    lon = sum(p[1] for p in points) / len(points)
    from ..correlation.engine import haversine_km

    return lat, lon, max(max(haversine_km(lat, lon, *p) for p in points), 10.0)


def covering_area(text: str) -> tuple[float, float, float, str] | None:
    """Centre and radius covering the named places. Districts win over their state."""
    from ..correlation.engine import haversine_km

    places = locate_all(text)
    if not places:
        return None
    specific = [p for p in places if p.radius_km <= 70]
    chosen = specific or places
    lat = sum(p.lat for p in chosen) / len(chosen)
    lon = sum(p.lon for p in chosen) / len(chosen)
    radius = max(haversine_km(lat, lon, p.lat, p.lon) + p.radius_km for p in chosen)
    return lat, lon, round(radius, 1), ", ".join(p.name for p in chosen)


def _iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.strip())
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def parse_cap(data: bytes, item: dict | None = None, ttl_h: float = 24) -> ParsedHazard | None:
    """Parse one CAP 1.2 alert. Returns None for tests, cancellations and non-actual alerts."""
    root = ET.fromstring(data)
    find = lambda parent, tag: parent.findtext(f"cap:{tag}", default=None, namespaces=CAP_NS)
    if (find(root, "status") or "") != "Actual" or (find(root, "msgType") or "") == "Cancel":
        return None
    info = root.find("cap:info", CAP_NS)
    if info is None:
        return None
    area = info.find("cap:area", CAP_NS)
    area_desc = (find(area, "areaDesc") or "") if area is not None else ""
    event = find(info, "event") or (item or {}).get("title") or "Alert"
    headline = find(info, "headline") or event
    title = f"{event}: {area_desc}" if area_desc else headline

    lat = lon = None
    radius = 150.0
    polygon = find(area, "polygon") if area is not None else None
    geo = _centroid_radius(polygon) if polygon else None
    how = "polygon"
    if geo:
        lat, lon, radius = geo
    else:
        # Live SACHET alerts often link their polygon instead of embedding it,
        # so fall back to matching the place names in areaDesc.
        found = covering_area(area_desc)
        if found:
            lat, lon, radius, names = found
            how = f"place names: {names}"
        else:
            how = "none"

    sent = _iso(find(root, "sent")) or datetime.now(timezone.utc)
    start = _iso(find(info, "effective")) or _iso(find(info, "onset")) or sent
    expires = _iso(find(info, "expires")) or start + timedelta(hours=ttl_h)
    identifier = find(root, "identifier") or (item or {}).get("id") or ""
    return ParsedHazard(
        source="sachet",
        external_id=identifier[:120],
        hazard_type=hazard_type_from_text(f"{event} {headline}"),
        severity=CAP_SEVERITY.get(find(info, "severity") or "", "unknown"),
        title=re.sub(r"\s+", " ", title)[:300],
        lat=lat, lon=lon, radius_km=radius,
        verified=True,
        starts_at=start, expires_at=expires,
        raw={"sender": find(root, "sender"), "urgency": find(info, "urgency"),
             "certainty": find(info, "certainty"), "located_by": how,
             "instruction": (find(info, "instruction") or "")[:500]},
    )


def rss_date(value: str) -> datetime | None:
    try:
        return parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
