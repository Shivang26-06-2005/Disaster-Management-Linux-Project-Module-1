"""Small place-name lookup for alerts and reports that have no coordinates.

Coordinates are approximate centres. The radius is a rough size of the place, which
is enough to answer "could this hazard affect that node", and nothing finer.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Place:
    name: str
    lat: float
    lon: float
    radius_km: float


_CITY = 60.0
_DISTRICT = 70.0
_PLACES: list[Place] = [Place(*p) for p in [
    # Cities and districts come first so the most specific name wins.
    ("Mumbai", 19.08, 72.88, _CITY), ("Delhi", 28.61, 77.21, _CITY), ("New Delhi", 28.61, 77.21, _CITY),
    ("Bengaluru", 12.97, 77.59, _CITY), ("Bangalore", 12.97, 77.59, _CITY),
    ("Chennai", 13.08, 80.27, _CITY), ("Kolkata", 22.57, 88.36, _CITY), ("Hyderabad", 17.39, 78.49, _CITY),
    ("Pune", 18.52, 73.86, _CITY), ("Ahmedabad", 23.02, 72.57, _CITY), ("Surat", 21.17, 72.83, _CITY),
    ("Jaipur", 26.91, 75.79, _CITY), ("Lucknow", 26.85, 80.95, _CITY), ("Patna", 25.59, 85.14, _CITY),
    ("Bhopal", 23.26, 77.41, _CITY), ("Bhubaneswar", 20.30, 85.82, _CITY), ("Puri", 19.81, 85.83, _CITY),
    ("Visakhapatnam", 17.69, 83.22, _CITY), ("Vijayawada", 16.51, 80.65, _CITY),
    ("Kochi", 9.93, 76.27, _CITY), ("Thiruvananthapuram", 8.52, 76.94, _CITY), ("Wayanad", 11.70, 76.13, _DISTRICT),
    ("Coimbatore", 11.02, 76.96, _CITY), ("Madurai", 9.93, 78.12, _CITY), ("Erode", 11.34, 77.72, _DISTRICT),
    ("Theni", 10.01, 77.48, _DISTRICT), ("Tiruppur", 11.11, 77.34, _DISTRICT),
    ("Guwahati", 26.14, 91.74, _CITY), ("Shillong", 25.58, 91.89, _CITY), ("Imphal", 24.82, 93.94, _CITY),
    ("Dehradun", 30.32, 78.03, _CITY), ("Rishikesh", 30.09, 78.27, _CITY), ("Haridwar", 29.95, 78.16, _CITY),
    ("Kedarnath", 30.73, 79.07, _DISTRICT), ("Shimla", 31.10, 77.17, _CITY), ("Manali", 32.24, 77.19, _CITY),
    ("Srinagar", 34.08, 74.80, _CITY), ("Jammu", 32.73, 74.87, _CITY), ("Leh", 34.15, 77.58, _CITY),
    ("Chandigarh", 30.73, 76.78, _CITY), ("Amritsar", 31.63, 74.87, _CITY), ("Ranchi", 23.34, 85.31, _CITY),
    ("Raipur", 21.25, 81.63, _CITY), ("Nagpur", 21.15, 79.09, _CITY), ("Gangtok", 27.34, 88.61, _CITY),
    ("Port Blair", 11.62, 92.73, _CITY), ("Kattankulathur", 12.82, 80.04, _CITY),
    # States and union territories.
    ("Andhra Pradesh", 15.9, 79.7, 400), ("Arunachal Pradesh", 28.1, 94.7, 300), ("Assam", 26.2, 92.9, 300),
    ("Bihar", 25.8, 85.6, 250), ("Chhattisgarh", 21.3, 81.9, 350), ("Goa", 15.4, 74.0, 60),
    ("Gujarat", 22.4, 71.6, 400), ("Haryana", 29.2, 76.1, 170), ("Himachal Pradesh", 31.9, 77.2, 170),
    ("Jharkhand", 23.6, 85.5, 230), ("Karnataka", 14.9, 75.9, 400), ("Kerala", 10.4, 76.4, 280),
    ("Madhya Pradesh", 23.7, 78.4, 480), ("Maharashtra", 19.5, 75.9, 480), ("Manipur", 24.8, 93.8, 110),
    ("Meghalaya", 25.5, 91.3, 150), ("Mizoram", 23.3, 92.8, 130), ("Nagaland", 26.1, 94.5, 110),
    ("Odisha", 20.5, 84.4, 330), ("Orissa", 20.5, 84.4, 330), ("Punjab", 31.0, 75.4, 180),
    ("Rajasthan", 26.6, 73.8, 480), ("Sikkim", 27.5, 88.5, 60), ("Tamil Nadu", 10.9, 78.4, 350),
    ("Telangana", 17.9, 79.1, 220), ("Tripura", 23.8, 91.3, 80), ("Uttar Pradesh", 27.1, 80.9, 480),
    ("Uttarakhand", 30.1, 79.2, 180), ("West Bengal", 23.8, 87.9, 320), ("Ladakh", 34.3, 77.3, 300),
    ("Andaman", 11.7, 92.7, 300), ("Lakshadweep", 10.6, 72.6, 200),
]]
_PATTERNS = [(re.compile(rf"\b{re.escape(p.name)}\b", re.IGNORECASE), p) for p in _PLACES]


def locate(text: str | None) -> Place | None:
    """Return the most specific place named in the text, or None."""
    if not text:
        return None
    for pattern, place in _PATTERNS:
        if pattern.search(text):
            return place
    return None


def locate_all(text: str | None) -> list[Place]:
    if not text:
        return []
    return [place for pattern, place in _PATTERNS if pattern.search(text)]
