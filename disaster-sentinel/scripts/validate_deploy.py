#!/usr/bin/env python3
"""Offline checks of deployment files: Kubernetes schemas, env var order, and required files."""
from __future__ import annotations

import re
import sys
from pathlib import Path

import kubernetes_validate
import yaml

ROOT = Path(__file__).resolve().parents[1]
K8S_VERSION = "1.31"


def main() -> int:
    problems: list[str] = []
    docs = [d for d in yaml.safe_load_all((ROOT / "deploy/k8s/sentinel.yaml").read_text()) if d]
    for doc in docs:
        name = f"{doc['kind']}/{doc['metadata']['name']}"
        try:
            kubernetes_validate.validate(doc, K8S_VERSION, strict=True)
        except kubernetes_validate.ValidationError as exc:
            problems.append(f"{name}: {exc.message} at {list(exc.path)}")
        # Kubernetes only expands $(VAR) in an env entry when VAR is defined earlier.
        spec = doc.get("spec", {}).get("template", {}).get("spec", {})
        for container in spec.get("containers", []):
            defined = set()
            from_secret = bool(container.get("envFrom"))
            for entry in container.get("env", []):
                for ref in re.findall(r"\$\((\w+)\)", entry.get("value", "")):
                    if ref not in defined and not from_secret:
                        problems.append(f"{name}: {entry['name']} uses $({ref}) before it is defined")
                defined.add(entry["name"])
    for required in ("models/severity_model.joblib", "models/mobilenetv2_features.onnx", "config/config.json"):
        if not (ROOT / required).exists():
            problems.append(f"Missing {required}, which the images copy")
    print(f"Checked {len(docs)} Kubernetes objects")
    for p in problems:
        print("PROBLEM:", p)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
