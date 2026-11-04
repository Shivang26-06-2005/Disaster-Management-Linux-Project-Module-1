"""Statistical Z-score and thresholding detector (slide 10, technique 1).

A plain z-score misfires in three ways that this class guards against:

* Flat baselines. An idle CPU has almost no variance, so a move from 2% to 9%
  scores a huge z. ``min_std`` caps the score and ``floor`` requires the value
  to actually be high.
* Baseline poisoning. Anomalous samples are kept out of the baseline, otherwise
  a long incident teaches the detector that the incident is normal.
* Slow leaks. Memory that creeps up never scores a high z, so ``ceiling`` fires
  regardless of the baseline.
"""
from __future__ import annotations

import math
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime

from ..config import Detection


@dataclass(frozen=True)
class Anomaly:
    node_id: str
    metric: str
    ts: datetime
    value: float
    z: float
    mean: float
    std: float
    reason: str          # "z_score" or "ceiling"
    duration_s: float


@dataclass
class _State:
    values: deque[float]
    sum: float = 0.0
    sum_sq: float = 0.0
    streak: int = 0
    streak_start: datetime | None = None
    last_ts: datetime | None = None
    since_fire: int = 0
    held_back: list[float] = field(default_factory=list)

    def push(self, v: float, maxlen: int) -> None:
        if len(self.values) == maxlen:
            old = self.values.popleft()
            self.sum -= old
            self.sum_sq -= old * old
        self.values.append(v)
        self.sum += v
        self.sum_sq += v * v

    def stats(self) -> tuple[float, float]:
        n = len(self.values)
        if n == 0:
            return 0.0, 0.0
        mean = self.sum / n
        variance = max(self.sum_sq / n - mean * mean, 0.0)
        return mean, math.sqrt(variance)


class ZScoreDetector:
    def __init__(self, cfg: Detection):
        self.cfg = cfg
        self._states: dict[tuple[str, str], _State] = {}

    def _state(self, node_id: str, metric: str) -> _State:
        key = (node_id, metric)
        if key not in self._states:
            self._states[key] = _State(values=deque(maxlen=self.cfg.window))
        return self._states[key]

    def seed(self, node_id: str, metric: str, values: list[float]) -> None:
        """Rebuild the baseline after a restart so detection does not need a re-warm-up."""
        state = self._state(node_id, metric)
        for v in values[-self.cfg.window:]:
            state.push(v, self.cfg.window)

    def observe(self, node_id: str, metric: str, ts: datetime, value: float | None) -> Anomaly | None:
        rule = self.cfg.metrics.get(metric)
        if rule is None or value is None or not math.isfinite(value):
            return None
        state = self._state(node_id, metric)

        # A telemetry gap means the streak no longer describes consecutive samples.
        if state.last_ts is not None and (ts - state.last_ts).total_seconds() > self.cfg.max_gap_s:
            self._end_streak(state)
        state.last_ts = ts

        mean, std = state.stats()
        warm = len(state.values) >= self.cfg.min_samples
        effective_std = max(std, self.cfg.min_std)
        z = (value - mean) / effective_std if warm else 0.0

        over_ceiling = value >= rule.ceiling
        over_z = warm and z >= self.cfg.z_threshold and value >= rule.floor

        if not (over_ceiling or over_z):
            self._end_streak(state)
            state.push(value, self.cfg.window)
            return None

        state.streak += 1
        if state.streak_start is None:
            state.streak_start = ts
        state.held_back.append(value)

        # A shift that lasts this long is the new normal, unless it sits at the ceiling.
        if state.streak >= self.cfg.adapt_after and not over_ceiling:
            for held in state.held_back:
                state.push(held, self.cfg.window)
            self._end_streak(state)
            return None

        if state.streak < self.cfg.consecutive:
            return None
        if state.streak > self.cfg.consecutive:
            state.since_fire += 1
            if state.since_fire < self.cfg.refire_every:
                return None
        state.since_fire = 0
        return Anomaly(
            node_id=node_id,
            metric=metric,
            ts=ts,
            value=value,
            z=round(z, 2),
            mean=round(mean, 2),
            std=round(std, 2),
            reason="ceiling" if over_ceiling and not over_z else "z_score",
            duration_s=(ts - state.streak_start).total_seconds(),
        )

    def _end_streak(self, state: _State) -> None:
        state.streak = 0
        state.streak_start = None
        state.since_fire = 0
        state.held_back = []
