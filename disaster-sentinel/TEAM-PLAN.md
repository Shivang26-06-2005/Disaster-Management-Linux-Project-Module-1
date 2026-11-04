# Team plan: Disaster Monitoring, Identification and Recovery

This plan compares the project brief with the code. **The total is 95 requirements: 19 built, 27 partly built, 49 to build.** Everything listed as to build is a proposal to agree on. None of it has been built yet.

## The three modules

| Module | Package | Requirements |
|---|---|---|
| 1. Monitoring and AI Detection | `module-1-monitoring-ai.zip` | 5 built, 7 partly built, 7 to build |
| 2. Backup and Recovery | `module-2-backup-recovery.zip` | 5 built, 8 partly built, 30 to build |
| 3. Dashboard, Alerts and Reports | `module-3-dashboard-alerts-reports.zip` | 9 built, 12 partly built, 12 to build |

The brief's flow maps onto them like this:

| Step | Monitor | Detect | Identify | Analyse | Classify | Assess damage | Alert | Recover | Verify | Report |
|---|---|---|---|---|---|---|---|---|---|---|
| Module | 1 | 1 | 1 | 1 | 1 | 2 | 3 | 2 | 2 | 3 |

## How the modules connect

The modules run as separate programs and pass work through the database, so each person can work without waiting for the others.

1. **Module 1** collects telemetry, then writes `incidents` and (proposed) `resources` rows.
2. **Module 2** reads them, queues `recovery_actions`, and records results and (proposed) `backups` rows.
3. **Module 3** shows all of it, sends alerts, and records administrator decisions.

The agent on each machine collects actions itself and checks them against its own allowlist. The server can't run commands on a machine directly. Keep it that way.

## Shared changes to agree first

These go in shared files, so the project lead makes them once the team agrees:

- `incidents`: add `family` (natural, man_made or infrastructure) and `risk_score` (0 to 100). Allow LOW, MEDIUM, HIGH and CRITICAL in `severity`.
- New `resources` table: node, kind (file, service, database, url or server), target, status (ok, missing, corrupted or down), details and time checked.
- New `backups` table: node, path, location, SHA-256, size, time created, time verified and whether it is known clean.
- `recovery_actions`: add `verified` and `verification_detail`.
- `ROLE_GRANTS` in `db.py`: give each service only the access it needs. A test checks these limits.

`migrate` creates new tables but doesn't add columns to existing ones. After a column change, wipe the local test database with `docker compose down -v` and `sudo rm -rf data/postgres`.

## Suggested order

| Stage | Brief phases | Module 1 | Module 2 | Module 3 |
|---|---|---|---|---|
| 1 | Agree shared changes | Agree | Agree | Agree |
| 2 | 1 to 4 | New checks, families, risk score | Backup catalogue, verify, restore | Sandbox, simulations, sample data views |
| 3 | 5 to 8 | ML anomaly and ransomware detection | Service, database and server recovery | Alerts, new dashboard panels, reports |
| 4 | 9 | Tune against simulations | Fix recovery failures | Full demonstration and final report |

## Working rules

- **Your files:** change them freely.
- **Shared files:** ask the project lead, because a change can break everyone.
- **Read-only copies:** don't edit them. If you need a change, ask that file's owner.
- **Safety:** dry run stays the default. Destructive tests happen only inside the sandbox. Critical recovery needs administrator approval. Real recovery on a real system needs the project lead's explicit approval.
- **Honesty:** report measured results. Never claim data was recovered without a verified copy.
- **Sharing work:** use one private Git repository with a branch per module if you can. It makes combining work much safer than passing zip files around.

## Run each module

Each person can run their own module from their own package. Their guide has the full steps.

| Module | Command | What runs | Needs |
|---|---|---|---|
| 1 | `.venv/bin/python scripts/module1_demo.py` | Live readings, detection, correlation and the AI model | Python |
| 2 | `./scripts/module2_demo.sh` | Backup, evidence, cache clearing and safety checks, on temporary sample files | Bash |
| 3 | `./scripts/run_module3.sh start` | The dashboard with labelled sample data | Python and Docker |

## Run the whole system

Live monitoring from a real machine needs all three packages, so unzip them into the same folder and let matching files overwrite each other:

```bash
unzip -o module-1-monitoring-ai.zip
unzip -o module-2-backup-recovery.zip
unzip -o module-3-dashboard-alerts-reports.zip
cd disaster-sentinel
./scripts/setup.sh
docker compose build
docker compose up -d
```

Do this with the original packages only. Unzipping over edited files replaces your changes. The README covers sign-in and demos. To run every test, follow "Retrain and re-evaluate" in the README.

## Not yet tested

Earlier testing didn't cover these, so check them before relying on them: the real Docker base images on Docker Desktop, the systemd installation, real service restarts and address blocking, live USGS and SACHET feeds, and real email or SMS delivery.

## Every requirement

| Brief section | Requirement | Status | Today | Module |
|---|---|---|---|---|
| 1 AI detection | Analyse Linux system logs | Built | Agent tails logs; `detection/signatures.py` matches them | 1 |
| 1 AI detection | Detect unusual system behaviour | Built | Z-score detector on CPU, memory and disk | 1 |
| 1 AI detection | Identify suspicious activities | Partly built | Breach, rootkit and repeated-login log patterns; no process or file behaviour | 1 |
| 1 AI detection | Detect possible resource failures | Partly built | Service failures, disk errors and out-of-memory kills from logs; a node going silent; no direct checks | 1 |
| 1 AI detection | Classify as natural, man-made or infrastructure | Partly built | Eight incident categories exist; they are not grouped into these three | 1 |
| 1 AI detection | Machine learning for anomaly detection and classification | To build | Detection uses statistics and rules. The only ML model rates damage in text and photo reports | 1 |
| 2 Monitoring | CPU usage | Built | `agent/daemon.py` | 1 |
| 2 Monitoring | RAM usage | Built | `agent/daemon.py` | 1 |
| 2 Monitoring | Disk storage | Built | `agent/daemon.py` | 1 |
| 2 Monitoring | Network connectivity | Partly built | The server notices a silent node; the agent doesn't test connectivity | 1 |
| 2 Monitoring | Running processes | To build | Not collected | 1 |
| 2 Monitoring | Linux service status | Partly built | Failures seen in logs only; no `systemctl is-active` check | 1 |
| 2 Monitoring | File availability and integrity | To build | Not collected | 1 |
| 3 Severity and risk | Low, Medium, High and Critical levels | Partly built | Only LOW and HIGH exist | 1 |
| 3 Severity and risk | Risk score from 0 to 100 | To build | Not present | 1 |
| 4 Damage assessment | Identify deleted files | To build | Needs Module 1's file checks | 2 |
| 4 Damage assessment | Identify corrupted files | To build | Needs Module 1's file checks | 2 |
| 4 Damage assessment | Identify unavailable databases | To build | Not present | 2 |
| 4 Damage assessment | Identify failed Linux services | Partly built | The failed service is named from logs | 2 |
| 4 Damage assessment | Identify unavailable servers and online resources | Partly built | Silent nodes only | 2 |
| 4 Damage assessment | Check available backups | To build | Backups aren't recorded anywhere the server can see | 2 |
| 4 Damage assessment | Identify alternative recovery resources | To build | Not present | 2 |
| 4 Damage assessment | Maintain resource availability records | To build | No table for this | 2 |
| 5 Data recovery | Automatic backup creation | Built | `backup_snapshot` runs from playbooks; tested for real in a temporary folder | 2 |
| 5 Data recovery | Scheduled backups | To build | Backups only run in response to incidents | 2 |
| 5 Data recovery | Backup version management | Partly built | Timestamped archives; keeps the seven newest | 2 |
| 5 Data recovery | Restore deleted files from backups | To build | No restore action exists | 2 |
| 5 Data recovery | Restore corrupted files | To build | No restore action exists | 2 |
| 5 Data recovery | Database recovery | To build | Not present | 2 |
| 5 Data recovery | Backup integrity verification | Partly built | A SHA-256 file is written but nothing ever checks it | 2 |
| 5 Data recovery | Recovery from separate backup storage | To build | Backups sit on the same machine | 2 |
| 6 System recovery | Restart failed services | Built | `restart_service` with allowlists; real restart not yet tested | 2 |
| 6 System recovery | Restore configuration files | To build | Not present | 2 |
| 6 System recovery | Recover important application files | To build | Not present | 2 |
| 6 System recovery | Identify system failures | Built | Kernel panic, out-of-memory and disk error patterns | 2 |
| 6 System recovery | Check service availability after recovery | To build | Only the command's exit code is recorded | 2 |
| 7 Online resources | Detect unavailable online services | To build | No URL or port checks | 1 |
| 7 Online resources | Identify failed servers | Partly built | Silent nodes only | 1 |
| 7 Online resources | Switch to alternative servers | To build | Not present | 2 |
| 7 Online resources | Restore website and application files | To build | Not present | 2 |
| 7 Online resources | Recover cloud resources from replicas or backups | To build | Not present; demonstrate with a local stand-in | 2 |
| 8 Cybersecurity | Identify suspicious processes | To build | No process data yet | 1 |
| 8 Cybersecurity | Detect possible ransomware activity | To build | Not present | 1 |
| 8 Cybersecurity | Isolate compromised systems | Partly built | `isolate_ip` blocks an attacker's address; it doesn't isolate the machine | 2 |
| 8 Cybersecurity | Preserve incident logs and evidence | Built | `preserve_evidence` writes a checksummed archive | 2 |
| 8 Cybersecurity | Restore clean files from verified backups | To build | Not present | 2 |
| 8 Cybersecurity | Avoid restoring infected backups | To build | Not present | 2 |
| 9 Alerts | Real-time disaster notifications | Built | Dashboard feed, plus email, Slack and SMS code | 3 |
| 9 Alerts | Severity-based alerts | Partly built | Only HIGH incidents send alerts | 3 |
| 9 Alerts | Risk score display | To build | Needs Module 1's score | 3 |
| 9 Alerts | Affected system identification | Built | Each incident names its node | 3 |
| 9 Alerts | Email notifications | Built | Tested against a fake mail server; no real email sent yet | 3 |
| 9 Alerts | Recovery progress notifications | Partly built | Shown on the dashboard; no message is sent for each step | 3 |
| 9 Alerts | Recovery success and failure alerts | Partly built | Failures alert a person; successes don't | 3 |
| 9 Alerts | Administrator acknowledgement | Partly built | Resolve, approve and reject exist; no separate acknowledge step | 3 |
| 9 Alerts | Incident history | Partly built | Open incidents, a short activity feed and reportable incidents; no searchable history | 3 |
| 10 Verification and reports | Check that files are restored | To build | Needs restore first | 2 |
| 10 Verification and reports | Verify file integrity with SHA-256 | To build | Needs restore first | 2 |
| 10 Verification and reports | Check that services are running | To build | Not present | 2 |
| 10 Verification and reports | Verify database availability | To build | Not present | 2 |
| 10 Verification and reports | Confirm resources are operational | To build | Not present | 2 |
| 10 Verification and reports | Generate recovery reports | Partly built | A CERT-In incident draft exists; no recovery report | 3 |
| 10 Verification and reports | Record successful and failed attempts | Built | `recovery_actions` table and tamper-evident log | 3 |
| Simulation | Accidental file deletion | To build | Needs a sandbox | 3 |
| Simulation | File corruption | To build | Needs a sandbox | 3 |
| Simulation | Linux service failure | Partly built | `outage` drill sends log lines; no service really stops | 3 |
| Simulation | High CPU usage | To build | Not present | 3 |
| Simulation | High disk usage | To build | Not present | 3 |
| Simulation | Network disconnection | To build | Not present | 3 |
| Simulation | Ransomware-like file changes | To build | Not present; sandbox files only | 3 |
| Simulation | Natural disaster alerts | Built | `demo.sh quake` and `admin drill-hazard` | 3 |
| Dashboard | System health overview | Partly built | CPU, memory and threat level; no disk, network or services | 3 |
| Dashboard | Real-time disaster monitoring | Built | Monitor view refreshes itself | 3 |
| Dashboard | AI detection results | Partly built | Incident reasons and the report assessment page | 3 |
| Dashboard | Disaster category | Partly built | Internal categories; not the three families | 3 |
| Dashboard | Severity classification | Partly built | Two levels | 3 |
| Dashboard | Risk score | To build | Needs Module 1's score | 3 |
| Dashboard | Affected resources | To build | Needs the resources table | 3 |
| Dashboard | Backup availability | To build | Needs the backups table | 3 |
| Dashboard | Recovery operations | Built | Listed under each incident, with approve and reject | 3 |
| Dashboard | Recovery progress | Partly built | Status for each action; no overall progress | 3 |
| Dashboard | Recovery history | To build | Actions show only while their incident is open | 3 |
| Dashboard | Alerts and notifications | Built | Activity feed | 3 |
| Dashboard | Incident reports | Built | Download a draft report | 3 |
| Dashboard | Charts | To build | No charts yet; Chart.js is suggested in the brief | 3 |
| Recovery rules | Search for backups before restoring | To build | Needs restore | 2 |
| Recovery rules | Select the latest valid backup | To build | Needs restore | 2 |
| Recovery rules | Verify integrity before restoring | To build | Needs restore | 2 |
| Recovery rules | Keep existing backups protected | Partly built | Rotation can delete the last clean backup | 2 |
| Recovery rules | Administrator approval for critical actions | Partly built | The approval flow works, but every current playbook step runs automatically | 2 |
| Recovery rules | Preserve evidence during cyber incidents | Built | First step of the breach playbook | 2 |
| Recovery rules | Avoid restoring compromised files | To build | Needs restore | 2 |
| Recovery rules | Verify recovery after every operation | To build | Only exit codes today | 2 |
| Recovery rules | Report failure if recovery fails | Partly built | Failed actions alert a person; a failed check can't trigger this yet | 2 |
| Recovery rules | Never claim lost data is recoverable without a copy | To build | Enforce in restore results and report wording | 2 |
