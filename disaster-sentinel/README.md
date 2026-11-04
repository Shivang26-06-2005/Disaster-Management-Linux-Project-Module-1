# Disaster Sentinel

Monitors Linux systems, identifies natural and man-made threats, starts recovery automatically, and prepares CERT-In incident report drafts. It also assesses disaster severity from a message and a photo, and links those reports to the monitoring side.

Built from the SRM C.Tech project deck "Disaster monitor, identify, Recovery Natural, Man Made (CERT-in)". This is an academic project. It is not affiliated with or endorsed by CERT-In, NDMA or USGS, and using it does not by itself make an organisation compliant.

## How it fits together

```
 Edge nodes                     Central server (one container each)
 ┌───────────────┐  HTTPS   ┌────────┐
 │ Agent         │ ───────▶ │ ingest │──┐        ┌───────────┐
 │ metrics, logs │          └────────┘  │        │ analytics │ z-score, regex,
 │ disk spool    │                      ▼        │           │ correlation, triage
 │ local policy  │             ┌──────────────┐◀▶└───────────┘
 │ recovery.sh   │             │  PostgreSQL/ │◀▶ recovery     playbooks, notifications
 └───────────────┘             │  TimescaleDB │◀▶ hazards      USGS and SACHET feeds
        ▲  collects actions    │ (repository) │◀▶ dashboard    browser UI, CERT-In drafts
        └──────────────────────┴──────────────┘        │
                                                       ▼
                                                  classifier   text + image severity
```

Components never call each other, apart from the dashboard calling the classifier. They read and write the shared repository, each with its own database role limited to the tables it needs. The server never reaches into a node: the agent connects out, collects actions, and checks them against its own allowlist before running anything.

## Quick start

You need Podman or Docker, plus bash and OpenSSL. On Windows, use Docker Desktop and Git Bash (which includes both). Python isn't needed on your machine, because everything runs in containers.

```bash
./scripts/setup.sh                 # Creates .env with random secrets, plus TLS certificates
docker compose up -d --build       # Or: podman compose up -d --build
```

The first build downloads images and takes a few minutes. Then open **https://localhost:8443**, accept the local certificate warning, and sign in with the `OPERATOR_PASSWORD` value from `.env`.

If other machines will send telemetry, pass their view of the server: `./scripts/setup.sh localhost,192.168.1.50`. The dashboard listens only on this machine unless you set `DASHBOARD_BIND`.

To use plain PostgreSQL instead of TimescaleDB, as slide 14 describes, add `DB_IMAGE=docker.io/library/postgres:16` to `.env`. Everything works the same without hypertables.

### Try it with no Linux machine

The agent needs Linux, so on Windows run it in a container. This node is simulated, its metrics describe Docker's virtual machine, and it has no log files, so incidents come from drills:

```bash
./scripts/demo.sh start        # Registers a demo node in Chennai and starts its agent
./scripts/demo.sh noise        # One stray failure: stays LOW, no action
./scripts/demo.sh breach       # HIGH, with a 6-hour CERT-In clock
./scripts/demo.sh brute_force  # HIGH, blocks the address (simulated)
./scripts/demo.sh quake        # Earthquake alert near the node plus a service failure
```

### Connect your first node

```bash
# Prints the node's token once. The coordinates are what allow matching to nearby hazards.
docker compose run --rm -T migrate python -m sentinel.admin add-node chennai-1 \
    --lat 13.08 --lon 80.27 --region Chennai

# On a Linux node, or in WSL2 with systemd, as root, from this project folder:
sudo ./scripts/install_agent.sh --server https://localhost:8444 --token PASTE_TOKEN --ca deploy/certs/ca.crt
```

The agent starts in **simulation mode**. It records what it would do and changes nothing on the machine.

### Demo it

Each of these travels the real path. The first two go through the agent's own log files, on a node that has `/var/log/syslog`:

```bash
logger -t ids "BREACH detected, unexpected change to /etc/passwd"   # HIGH, with a 6-hour CERT-In clock
logger -t cron "nightly report job FAILED"                          # LOW, logged with no action
```

No syslog file? Send drills straight to ingest:

```bash
python3 scripts/drill.py --server https://localhost:8444 --ca deploy/certs/ca.crt \
    --token PASTE_TOKEN breach      # Also: brute_force, outage, noise
```

Then try these in the dashboard:

* **Monitor:** the threat level changes, with plain reasons and recovery status.
* **Crisis reports:** add a message such as "Flood destroyed houses in Chennai" and a photo. You get severity, reliability, influential words, a photo heatmap and recommended actions.
* **Compliance:** download the report draft, and press **Check records**.

To demonstrate tamper detection, edit a stored log line and check again:

```bash
docker compose exec -T db psql -U sentinel_owner -d sentinel \
    -c "UPDATE log_events SET line='nothing happened' WHERE line LIKE '%BREACH%'"
```

## Before you turn on real recovery

In `/etc/sentinel/agent.json` on each node:

| Setting | Default | What it does |
|---|---|---|
| `recovery_mode` | `dry_run` | Set to `enforce` for actions to really run |
| `allowed_services` | a short list | Only these can be restarted |
| `allow_isolate` | `false` | Set to `true` to allow firewall blocks |
| `protected_cidrs` | private ranges | These addresses can never be blocked |

Also set `BACKUP_PATHS` and `CACHE_DIRS` in `/etc/sentinel/recovery.conf`. Until `BACKUP_PATHS` is set, backups fail and the incident goes to the response team.

**Log text can be forged.** Any local user can write a fake line with `logger`. So a BREACH line only preserves evidence and alerts people, and blocking an address needs repeated failures from that address, an address outside the protected ranges, and `allow_isolate`. `recovery.sh` also refuses to restart `sshd`, `systemd-*`, `dbus` and the agent automatically, so a bad decision cannot cut off your access.

## Results

All numbers come from files in `reports/`. Regenerate them with the commands further down.

### Severity classifier

CrisisMMD v2.0 damage task, official agreed-label split: 2,468 train, 529 dev, 529 test. Test macro-F1 is the headline measure because the classes are imbalanced.

| Model | Macro-F1 | Accuracy |
|---|---|---|
| Majority class (baseline) | 0.257 | 0.628 |
| Text only | 0.451 | 0.537 |
| Image only | 0.537 | 0.611 |
| **Text + image, deployed** | **0.521** (95% CI 0.472–0.566) | 0.614 |

* **Fusion did not beat image-only on the test set.** The difference is -0.016 (95% CI -0.067 to +0.034), which is within noise. It does clearly beat text-only (+0.070, CI +0.027 to +0.114). In cross-validation fusion scored higher (0.529 against 0.494), but those settings were chosen on the same folds, so that figure is optimistic.
* **Unseen disasters score much lower.** Holding out one whole event at a time gives macro-F1 from 0.26 (California wildfires) to 0.50 (Iraq-Iran earthquake). This matters more than the headline: none of the training events are in India, so expect the lower range there.
* **Mild damage is the weak class** (F1 0.35, against 0.76 for severe).
* **Some test tweets also appear in training,** with different images: 68 tweets across train and dev. Without them, fused macro-F1 is 0.494.
* **The test set was scored in three runs during development,** with fused macro-F1 of 0.577, 0.557 and 0.521 as the tuning method changed. The last, and lowest, is reported because its method was the soundest, and it was fixed before seeing its score. The spread shows how sensitive this result is.
* The damage labels come from image annotators, which limits what text alone can do.

### Correlation engine against siloed alerts

This is **simulated data written by the same author as the rules** (30 runs of 12 hours). It checks the logic and shows the trade-off, and it is not field performance.

| | Siloed baseline | Correlation engine |
|---|---|---|
| False alerts per day | 14.3 | 2.1 |
| Alert precision | 0.42 | 0.75 |
| Incidents found, all | 120 of 120 | 89 of 120 |
| Incidents found, excluding the subtle type | 90 of 90 | 88 of 90 |
| Median detection delay | 0 s | 30 s |

Fewer false alarms has a cost. Almost all the misses are the deliberately included slow login attack (5 failures over 8 minutes), which sits under every threshold. The baseline only "finds" it because it alerts on every failed login. Breaches and critical faults were never missed in this simulation.

### Detectors on real data

* **NAB EC2 CPU series** (8 series, 12 human-labelled anomaly windows): the z-score detector with the 70% floor found 3 of 12 windows, and 4 of 12 without the floor. Precision was 0.28 and 0.19. A fixed 90% threshold also found 4 of 12, with precision 0.12, though it counts every sample as an alert, so its alert count is not directly comparable. **A simple z-score misses most subtle anomalies.** Treat this detector as a cheap first filter.
* **LogHub Linux_2k.log** (2,000 real lines, unlabelled): 490 lines matched failed logins and nothing else matched. No false critical or breach alerts on this sample.

### Agent overhead

0.17% CPU and 26 MB of memory, measured over 60 seconds on a 2-core VM, sampling every 2 seconds with idle log files. The systemd unit also caps it at 10% CPU and 128 MB.

## What was and wasn't verified

**Run and passing:**

* 152 automated tests against real PostgreSQL 16, including the whole flow under the restricted database roles.
* Live run with real TLS, real agents and a real browser: backlog delivery after an outage, real CPU load detection, tamper detection, restart after a forced kill, and a second analytics replica waiting as standby.
* The real `Containerfile` and `compose.yaml`, end to end, including non-root, read-only filesystems and network isolation.
* Pinned requirements in clean environments, and the Kubernetes manifests against their schemas.

**Not run, so check these first on your machine:**

| Item | Why | How it was covered instead |
|---|---|---|
| The real `python:3.13-slim` and TimescaleDB images, and hypertable setup | Registries are blocked in the build environment | Containers ran on a stand-in base image and plain PostgreSQL. Set `DB_IMAGE` to `postgres:16` if TimescaleDB gives trouble |
| Podman | Not available in the build environment | Compose was run with Docker only |
| Windows and Git Bash | No Windows machine in the build environment | `setup.sh` and `demo.sh` were run with no Python and with Windows detection simulated, so the demo flow is covered but Git Bash itself is not. The certificate step no longer passes any path-like argument |
| `install_agent.sh`, systemd and sudo | No systemd there | The agent ran directly. The sudo command line is unit tested |
| `--enforce` for `restart_service` and `isolate_ip` on a real system | These would change the machine | Dry run tested, bad input tested. Evidence, backup and cache-clearing ran for real |
| Live USGS and SACHET polling | Blocked from that shell | Parsers tested on samples matching the real feed formats, which were checked through a separate fetch. SACHET polygons could not be retrieved, so alerts are located from place names in `areaDesc` |
| Kubernetes on a real cluster, and GitHub Actions | Neither was available | Schema and YAML checks only |
| Email and SMS through real providers | No accounts | Slack webhook delivered to a local server, SMS failure and retry tested, email tested with a stub |

## Differences from the deck

* **Model:** TF-IDF with logistic regression and MobileNetV2 features replace BERT, CNN training and CLIP, because this was built for laptop CPU training. It trains in about 2–3 minutes on 2 cores.
* **Explanations:** word contributions and occlusion heatmaps replace SHAP, LIME and Grad-CAM. Word contributions are the model's exact arithmetic.
* **Not included:** video analysis, the xBD-S12 dataset, NDEM (no public feed was found), a map view, and Ansible (playbooks are `recovery.sh` and `config.json`).
* **SMS** goes through a generic webhook, so you can point it at any gateway.
* **Data volume:** slide 9 mentions about 14,996 image-text pairs. The damage task here has 3,526, because only those carry damage labels.

## CERT-In alignment

Based on the Directions of 28 April 2022: reporting within 6 hours of noticing, logs kept for a rolling 180 days within Indian jurisdiction, clocks synchronised to NIC or NPL NTP (or traceable to them), and the Annexure I incident types.

The system tracks the deadline, drafts the report, keeps tamper-evident records and flags clock drift. **It never files anything.** A designated Point of Contact reviews the draft and sends it, because whether an incident is reportable is a legal decision, and the category mapping here is only a suggestion. You are responsible for hosting in India and for pointing nodes at the right NTP servers. Check [cert-in.org.in](https://www.cert-in.org.in) for current rules and forms, since this is not legal advice.

## Retrain and re-evaluate

```bash
pip install -r requirements/dev.txt
export PYTHONPATH=src

# Get CrisisMMD v2.0 and its agreed-label split from https://crisisnlp.qcri.org/crisismmd,
# or the Kaggle copy on slide 14. Under one folder you need data_image/ and
# task_damage_text_img_{train,dev,test}.tsv. Check the dataset's terms of use.
python scripts/prepare_model.py            # Only if the model file is missing
python -m sentinel.ml.train --data path/to/CrisisMMD_v2.0   # Writes models/ and reports/

python eval/correlation_eval.py            # Simulated baseline comparison
python eval/real_data_eval.py              # NAB and LogHub

# On Windows, run this section in WSL2 or use `python` in place of `python3`.
# Tests need an empty throwaway database. They wipe its contents.
TEST_DATABASE_URL=postgresql+psycopg2://postgres:PASSWORD@localhost:5432/sentinel_test \
    python -m pytest tests -q
```

**Data source of the included model:** the build environment could not reach the official dataset host. The split files came from the GitHub repository `Donny-Guo/CrisisMMD_LoRA` and the images from `leo-luoson/crisismmd_Clip`. The split sizes match the published 2,468 / 529 / 529 and the image folder matches the published 18,082 total, but these are unofficial copies. Retrain on an official copy before quoting results formally.

## Where each slide lives

| Slide | Item | Code |
|---|---|---|
| 4 | Multi-container, config versioning, CI/CD | `compose.yaml`, `deploy/`, `config/config.json`, `.github/workflows/ci.yml` |
| 4 | Telemetry, low overhead, high availability | `src/sentinel/agent/daemon.py`, `deploy/systemd/`, analytics standby lock |
| 4, 12 | Tamper-evident records | `src/sentinel/compliance/audit.py` |
| 5, 10 | Correlation engine | `src/sentinel/correlation/engine.py` |
| 10 | Z-scores and regex signatures | `src/sentinel/detection/` |
| 10, 12 | Playbooks and recovery | `src/sentinel/services/recovery.py`, `scripts/recovery.sh` |
| 7, 16 | USGS and SACHET | `src/sentinel/hazards/`, `src/sentinel/services/hazards.py` |
| 9, 11 | Multimodal severity, explanations, advice | `src/sentinel/ml/` |
| 12 | Notifications (email, Slack, SMS) | `src/sentinel/services/recovery.py` |
| 13, 14 | Repository and roles, host volumes with `:Z` | `src/sentinel/db.py`, `compose.yaml` |
| 15 | Browser dashboard | `src/sentinel/services/dashboard.py`, `src/sentinel/web/static/` |

## Kubernetes

Push the images, replace `OWNER` in `deploy/k8s/sentinel.yaml`, then:

```bash
kubectl create namespace sentinel
kubectl -n sentinel create secret generic sentinel --from-env-file=.env
kubectl -n sentinel create configmap sentinel-config --from-file=config/config.json
kubectl -n sentinel create secret tls sentinel-tls --cert=deploy/certs/server.crt --key=deploy/certs/server.key
kubectl apply -f deploy/k8s/sentinel.yaml
```

NetworkPolicies need a CNI that enforces them. The anchors volume needs a storage class with ReadWriteMany, and the images need pushing to a registry you control.

## Known limits

* One operator password, with no per-user accounts. The audit log records "operator", not a named person.
* A brute-force attack from many addresses, or from a hostname with no IP in the log, does not reach the per-address threshold. While a brute-force incident is open, later attackers do not get their own block.
* The place-name list is short and India-focused, and matching is plain text. A report naming a place in passing gets located there.
* Audit verification reads the whole log, so it slows as the log grows.
* The development certificates and the plain password are for local use. Replace both before any real deployment.
