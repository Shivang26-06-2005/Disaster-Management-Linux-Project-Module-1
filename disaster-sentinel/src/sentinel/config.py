"""Versioned policy profile (slide 4: "Config Versioning") plus runtime settings.

The profile in config/config.json holds behaviour. Secrets only ever come from
the environment, so the profile can be committed and audited.
"""
from __future__ import annotations

import hashlib
import json
import os
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

ROOT = Path(__file__).resolve().parents[2]


class MetricRule(BaseModel):
    floor: float
    ceiling: float


class Detection(BaseModel):
    window: int = Field(gt=10)
    min_samples: int = Field(gt=2)
    z_threshold: float = Field(gt=0)
    min_std: float = Field(gt=0)
    consecutive: int = Field(ge=1)
    adapt_after: int = Field(ge=1)
    refire_every: int = Field(ge=1)
    max_gap_s: float = Field(gt=0)
    metrics: dict[str, MetricRule]


class Signature(BaseModel):
    name: str
    class_: Literal["breach", "critical", "auth_failed", "failed"] = Field(alias="class")
    strength: Literal["hard", "weak"]
    pattern: str
    ignore_case: bool = False


class Correlation(BaseModel):
    window_s: int
    corroboration_s: int
    sustained_s: int
    brute_force_count: int
    service_failed_count: int
    heartbeat_silent_s: int
    auto_resolve_s: int
    hazard_watch_severity: Literal["moderate", "severe", "extreme"]


class Step(BaseModel):
    action: Literal[
        "restart_service", "clear_cache", "isolate_ip", "preserve_evidence", "backup_snapshot"
    ]
    arg_from: str | None = None
    auto: bool = True


class Playbook(BaseModel):
    certin_type: str | None
    escalate: bool
    steps: list[Step]


class Recovery(BaseModel):
    action_ttl_s: int
    cooldown_s: int
    max_attempts_per_incident: int


class Compliance(BaseModel):
    report_deadline_hours: float
    retention_days: int
    max_clock_skew_s: float
    anchor_every_s: int

    @field_validator("retention_days")
    @classmethod
    def at_least_180(cls, v: int) -> int:
        # CERT-In Directions of 28 April 2022: rolling period of 180 days.
        if v < 180:
            raise ValueError("retention_days must be at least 180 for CERT-In alignment")
        return v


class Hazards(BaseModel):
    usgs_url: str
    sachet_url: str
    poll_s: int
    usgs_min_magnitude: float
    hazard_ttl_h: float
    sachet_max_cap_fetch: int


class Verification(BaseModel):
    corroboration_km: float
    corroboration_hours: float


class Policy(BaseModel):
    profile_version: str
    detection: Detection
    signatures: list[Signature]
    self_log_tags: list[str]
    correlation: Correlation
    playbooks: dict[str, Playbook]
    recovery: Recovery
    compliance: Compliance
    hazards: Hazards
    verification: Verification

    digest: str = ""


def load_policy(path: str | os.PathLike[str] | None = None) -> Policy:
    p = Path(path or os.environ.get("SENTINEL_CONFIG", ROOT / "config" / "config.json"))
    raw = p.read_bytes()
    data: dict[str, Any] = json.loads(raw)
    policy = Policy.model_validate(data)
    policy.digest = hashlib.sha256(raw).hexdigest()
    return policy


@lru_cache
def policy() -> Policy:
    return load_policy()


def env(name: str, default: str | None = None) -> str:
    """Read a required setting from the environment, failing with a clear message."""
    value = os.environ.get(name, default)
    if value is None or value == "":
        raise RuntimeError(f"{name} is not set. See .env.example.")
    return value


def database_url() -> str:
    return env("DATABASE_URL")
