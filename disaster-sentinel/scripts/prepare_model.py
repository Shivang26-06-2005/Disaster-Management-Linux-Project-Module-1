#!/usr/bin/env python3
"""Download the pretrained MobileNetV2 and cut it down to a feature extractor.

Only needed to retrain. The project already ships models/mobilenetv2_features.onnx.
The download is checked against a pinned SHA-256 before it is used.
"""
from __future__ import annotations

import sys
import tempfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from sentinel.ml.image import SOURCE_SHA256, SOURCE_URL, prepare_extractor, sha256  # noqa: E402


def main() -> int:
    target = ROOT / "models" / "mobilenetv2_features.onnx"
    target.parent.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        source = Path(tmp) / "mobilenetv2-12.onnx"
        print("Downloading", SOURCE_URL)
        urllib.request.urlretrieve(SOURCE_URL, source)
        actual = sha256(source)
        if actual != SOURCE_SHA256:
            print(f"Checksum mismatch: got {actual}, expected {SOURCE_SHA256}", file=sys.stderr)
            return 1
        prepare_extractor(source, target)
    print("Wrote", target)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
