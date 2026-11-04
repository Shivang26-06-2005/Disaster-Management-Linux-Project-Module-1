# Module 1: Monitoring and AI Detection

You own everything that watches a machine and decides what is wrong: the agent, the detectors, the correlation engine, the hazard feeds and the AI models. In the brief's flow this is **Monitor, Detect, Identify, Analyse, Classify**.

Your requirements: 5 built, 7 partly built, 7 to build. `TEAM-PLAN.md` explains how the three modules fit together.

## Set up once

Use Linux, or Ubuntu in WSL on Windows, with Python 3.12 or newer. Replace `YOUR-WINDOWS-NAME` with your Windows username. Unzip inside Ubuntu as shown, not in Windows, so the scripts stay runnable.

```bash
sudo apt update
sudo apt install -y unzip python3-venv
cd ~
cp /mnt/c/Users/YOUR-WINDOWS-NAME/Downloads/module-1-monitoring-ai.zip .
unzip module-1-monitoring-ai.zip
cd disaster-sentinel
python3 -m venv .venv
.venv/bin/pip install -r requirements/dev.txt
```

Run every command below from this `disaster-sentinel` folder.

## Run your module

Run the monitoring and detection demo. It needs no database or Docker, and it changes nothing on your computer:

```bash
.venv/bin/python scripts/module1_demo.py
```

You'll see this computer's live CPU, memory and disk readings, then a sample CPU spike being detected, then sample log incidents rated LOW or HIGH with their reasons, then the AI damage rating of two sample reports.

Rate your own report:

```bash
.venv/bin/python scripts/module1_demo.py --report "Bridge collapsed and houses destroyed by the flood"
```

Run the AI model as a service. In one terminal:

```bash
MODEL_DIR=models CLASSIFIER_TOKEN=demo-token PYTHONPATH=src .venv/bin/python -m uvicorn sentinel.services.classifier:app --port 8002
```

In a second terminal, from the same folder:

```bash
curl -s -H "X-Internal-Token: demo-token" -F "text=Bridge collapsed after the flood" http://127.0.0.1:8002/predict
```

The reply is the rating as JSON. To include a photo, add `-F "image=@photo.jpg"`. Press Ctrl+C in the first terminal to stop.

The agent, ingest and analytics services need the whole system, so see "Run the whole system" in `TEAM-PLAN.md`.

## Test your module

These tests need no Docker or database.

```bash
.venv/bin/python -m pytest tests/test_detection.py tests/test_correlation.py tests/test_hazards.py tests/test_ml.py -q
```

## What to build, in order

1. Add the missing checks to the agent: network, processes, `systemctl is-active`, watched files with SHA-256, and URL or port checks.
2. Accept those results in `services/ingest.py` and store them in the `resources` table. Unknown fields in a batch are silently ignored until you add them to the `Batch` model.
3. Add the three families, four severity levels and the risk score to the correlation engine. Keep each decision's plain-language reasons, and include the score's reasons.
4. Add ML anomaly detection with scikit-learn. `IsolationForest` trained on normal metrics is a good start, because it needs no labelled disasters. Measure false alerts with the existing `eval/` scripts and report the real numbers.
5. Detect ransomware-like activity: many watched files changing in a short time, new unusual extensions, and contents that suddenly look random.
6. Flag suspicious processes with simple, explainable rules, such as a process running from `/tmp` or a very high file change rate.

## Watch out for

- Changing severity touches more than the engine. Also update `SEVERITY_ORDER` and the CERT-In checks in `analytics.py`, the `severity == "HIGH"` filter in `services/recovery.py`, the sort and threat level in `services/dashboard.py`, and `app.js`. Tell Modules 2 and 3 before you merge.
- Hard signals must never be downgraded, and unverified public reports must never raise severity. Tests enforce both, so keep them passing.
- The agent must stay light. It used about 0.17% CPU and 26 MB when measured, and the service is limited to 10% CPU and 128 MB. Hash only watched files, and don't rescan unchanged ones constantly.
- `agent/daemon.py` also holds the recovery allowlist. Module 2 will ask you to add new actions there, so review those changes together.

## Done when

Module 1 is finished when each simulated disaster creates one incident with the correct family, severity, risk score, reasons and affected resources, and normal activity stays quiet.

## Your requirements

| Brief section | Requirement | Status | Today |
|---|---|---|---|
| 1 AI detection | Analyse Linux system logs | Built | Agent tails logs; `detection/signatures.py` matches them |
| 1 AI detection | Detect unusual system behaviour | Built | Z-score detector on CPU, memory and disk |
| 1 AI detection | Identify suspicious activities | Partly built | Breach, rootkit and repeated-login log patterns; no process or file behaviour |
| 1 AI detection | Detect possible resource failures | Partly built | Service failures, disk errors and out-of-memory kills from logs; a node going silent; no direct checks |
| 1 AI detection | Classify as natural, man-made or infrastructure | Partly built | Eight incident categories exist; they are not grouped into these three |
| 1 AI detection | Machine learning for anomaly detection and classification | To build | Detection uses statistics and rules. The only ML model rates damage in text and photo reports |
| 2 Monitoring | CPU usage | Built | `agent/daemon.py` |
| 2 Monitoring | RAM usage | Built | `agent/daemon.py` |
| 2 Monitoring | Disk storage | Built | `agent/daemon.py` |
| 2 Monitoring | Network connectivity | Partly built | The server notices a silent node; the agent doesn't test connectivity |
| 2 Monitoring | Running processes | To build | Not collected |
| 2 Monitoring | Linux service status | Partly built | Failures seen in logs only; no `systemctl is-active` check |
| 2 Monitoring | File availability and integrity | To build | Not collected |
| 3 Severity and risk | Low, Medium, High and Critical levels | Partly built | Only LOW and HIGH exist |
| 3 Severity and risk | Risk score from 0 to 100 | To build | Not present |
| 7 Online resources | Detect unavailable online services | To build | No URL or port checks |
| 7 Online resources | Identify failed servers | Partly built | Silent nodes only |
| 8 Cybersecurity | Identify suspicious processes | To build | No process data yet |
| 8 Cybersecurity | Detect possible ransomware activity | To build | Not present |

## Files

### Yours

- `deploy/agent.example.json`
- `deploy/demo-agent.json`
- `deploy/systemd/sentinel-agent.service`
- `eval/correlation_eval.py`
- `eval/real_data_eval.py`
- `models/mobilenetv2_features.onnx`
- `models/severity_model.joblib`
- `reports/classifier_eval.json`
- `reports/correlation_eval.json`
- `reports/real_data_eval.json`
- `scripts/install_agent.sh`
- `scripts/module1_demo.py`
- `scripts/prepare_model.py`
- `src/sentinel/agent/__init__.py`
- `src/sentinel/agent/daemon.py`
- `src/sentinel/correlation/__init__.py`
- `src/sentinel/correlation/engine.py`
- `src/sentinel/detection/__init__.py`
- `src/sentinel/detection/signatures.py`
- `src/sentinel/detection/zscore.py`
- `src/sentinel/hazards/__init__.py`
- `src/sentinel/hazards/feeds.py`
- `src/sentinel/hazards/gazetteer.py`
- `src/sentinel/ml/__init__.py`
- `src/sentinel/ml/data.py`
- `src/sentinel/ml/guidance.py`
- `src/sentinel/ml/image.py`
- `src/sentinel/ml/infer.py`
- `src/sentinel/ml/train.py`
- `src/sentinel/services/analytics.py`
- `src/sentinel/services/classifier.py`
- `src/sentinel/services/hazards.py`
- `src/sentinel/services/ingest.py`
- `tests/fixtures/sachet_cap.xml`
- `tests/fixtures/sachet_rss.xml`
- `tests/fixtures/usgs.geojson`
- `tests/test_correlation.py`
- `tests/test_detection.py`
- `tests/test_hazards.py`
- `tests/test_ml.py`

### Read-only copies

These are here so your code and tests can run. Their owners change them.

None. Everything your code imports is yours or shared.

### Shared

Ask the project lead before changing these.

- `.dockerignore`
- `.gitignore`
- `.github/workflows/ci.yml`
- `README.md`
- `compose.yaml`
- `config/config.json`
- `deploy/Containerfile`
- `deploy/k8s/sentinel.yaml`
- `requirements/agent.txt`
- `requirements/core.txt`
- `requirements/dev.txt`
- `requirements/ml.txt`
- `scripts/setup.sh`
- `scripts/validate_deploy.py`
- `src/sentinel/__init__.py`
- `src/sentinel/admin.py`
- `src/sentinel/config.py`
- `src/sentinel/db.py`
- `src/sentinel/compliance/__init__.py`
- `src/sentinel/compliance/audit.py`
- `src/sentinel/services/__init__.py`
- `tests/conftest.py`
- `tests/test_setup.py`
- `tests/test_system.py`
