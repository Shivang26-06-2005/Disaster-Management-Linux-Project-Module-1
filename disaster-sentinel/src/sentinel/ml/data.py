"""CrisisMMD damage-severity data loading and text cleaning (slide 9, steps 1 and 2)."""
from __future__ import annotations

import csv
import html
import re
from dataclasses import dataclass
from pathlib import Path

LABELS = ["little_or_no_damage", "mild_damage", "severe_damage"]
LABEL_DISPLAY = {
    "little_or_no_damage": "Little or no",
    "mild_damage": "Mild",
    "severe_damage": "Severe",
}
_ALIASES = {
    "little or no damage": "little_or_no_damage",
    "little_or_none": "little_or_no_damage",
    "mild damage": "mild_damage",
    "severe damage": "severe_damage",
}

_URL = re.compile(r"https?://\S+|www\.\S+")
_MENTION = re.compile(r"@\w+")
_RT = re.compile(r"^\s*RT\b:?", re.IGNORECASE)
_HASH = re.compile(r"#(\w+)")
_NON_TEXT = re.compile(r"[^a-z0-9\s'\-]+")
_SPACE = re.compile(r"\s+")


def clean_text(text: str | None) -> str:
    """Remove URLs, handles and symbols. Hashtag words are kept because #flood carries meaning."""
    if not text:
        return ""
    t = html.unescape(text)
    t = _RT.sub(" ", t)
    t = _URL.sub(" ", t)
    t = _MENTION.sub(" ", t)
    t = _HASH.sub(r"\1", t)
    t = t.lower()
    t = _NON_TEXT.sub(" ", t)
    return _SPACE.sub(" ", t).strip()


@dataclass(frozen=True)
class Example:
    tweet_id: str
    image_id: str
    event: str
    text: str
    image: Path
    label: int


def normalise_label(raw: str) -> str | None:
    value = raw.strip().lower()
    value = _ALIASES.get(value, value)
    return value if value in LABELS else None


def load_split(path: Path, root: Path) -> list[Example]:
    """Read one TSV. Examples whose image is missing are dropped and counted by the caller."""
    examples: list[Example] = []
    with open(path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh, delimiter="\t", quoting=csv.QUOTE_NONE):
            label = normalise_label(row.get("label") or row.get("image_damage") or "")
            if label is None:
                continue
            rel = row.get("image") or row.get("image_path") or ""
            image = root / rel
            if not rel or not image.is_file():
                continue
            examples.append(Example(
                tweet_id=row["tweet_id"],
                image_id=row.get("image_id") or rel,
                event=row.get("event_name") or "unknown",
                text=row.get("tweet_text") or "",
                image=image,
                label=LABELS.index(label),
            ))
    return examples


def load_dataset(root: Path) -> dict[str, list[Example]]:
    """Find the official damage split files under ``root``."""
    out: dict[str, list[Example]] = {}
    for split in ("train", "dev", "test"):
        matches = sorted(root.rglob(f"task_damage_text_img_{split}.tsv"))
        if not matches:
            raise FileNotFoundError(
                f"Could not find task_damage_text_img_{split}.tsv under {root}. "
                "See the dataset section of the README."
            )
        out[split] = load_split(matches[0], root)
    return out
