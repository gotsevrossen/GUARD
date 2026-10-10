# Backend completion requirements

> **Legacy (Linux appliance era); not current.** This document describes the original Linux appliance plan and is kept for history only. LightHouse is now Windows-only; see [windows-install.md](windows-install.md) and the README for the current product.

This document lists the information and access needed to run, validate, and complete LightHouse's backend on the planned Linux VM.

## Required before backend validation

### Linux VM

- Linux distribution and version (Ubuntu 24.04 LTS is a practical default).
- VM CPU cores, RAM, disk size, and whether it has GPU access.
- SSH or console access, plus an account permitted to install packages and read monitoring logs.
- The network interface that will see the monitored traffic, and confirmation that the VM may run in promiscuous mode if required.

### Runtime and model

- Python 3.11 or newer and Node.js 20 or newer installed on the VM.
- Ollama installed and running locally at `http://localhost:11434`.
- `qwen3:8b` pulled locally and enough RAM available for it alongside the monitoring stack.
- A model-quality decision after sample testing: keep Qwen3 8B, use a smaller model, or specify a different local Ollama model.

### Monitoring inputs

- Exact paths for the live JSON-line log files:
  - Suricata alert events from `eve.json`
  - Zeek JSON logs, including which logs to ingest first (`conn`, `dns`, `notice`, etc.)
  - Wazuh alert JSON export
- The Linux user/group that owns each log and the read-access method for the LightHouse service.
- Confirmation that Zeek is configured for JSON output (`LogAscii::use_json=T`).
- The log rotation behavior for each source, so the tailing worker can handle file replacement correctly.

### Safe test data

- 5–10 anonymized real records from each monitoring source, including normal/low-risk activity and at least one important event.
- Approval to store these fixtures in `samples/` for regression tests, with customer identifiers, public IPs, hostnames, usernames, and credentials removed.
- A controlled test procedure, such as an authorized Nmap scan or failed-login test, that can generate live records without touching a production network.

## Required before LAN use

- Appliance dashboard bind address and port.
- Firewall policy identifying which local subnets may reach the API and dashboard.
- TLS decision: local certificate/HTTPS setup or strictly isolated demo-network HTTP.
- Secure initial-admin password delivery and password-change requirement. The application generates a one-time random bootstrap password and requires it to be changed before normal access.
- Data-retention policy for raw alerts, model explanations, and duplicate occurrences.

## Decisions needed to finish production behavior

- Deduplication window and whether each source/rule requires an exception to the default 30-minute window.
- Alert status workflow: who may resolve or dismiss an alert, and whether a resolution note/audit history is required.
- Meaning of notification sensitivity for each user and the final severity threshold defaults. Actual email/SMS delivery belongs to Phase 6.
- Appliance-health telemetry source for CPU, memory, model latency, and monitoring-service state.
- Zeek fields/logs to use for definitive per-device traffic-volume graphs; the current view is an event-activity summary.

## Backend validation checklist

1. Install project dependencies with `pip install -e '.[dev]'`.
2. Run `pytest` successfully.
3. Seed the fixture demo: `python -m triage.main replay --mock`.
4. Start the API: `uvicorn triage.api:app --host 127.0.0.1 --port 8000`.
5. Verify login, alert listing/detail, status changes, role restrictions, preferences, device activity, and health endpoints.
6. Pull Qwen3 and rerun fixture replay without `--mock`; inspect validation failures and triage quality.
7. Configure live paths, run the tailing worker, and generate an authorized test event.
8. Record model latency, duplicate suppression behavior, and any source-format differences in `docs/implementation-log.md`.

## Not needed yet

- Public cloud hosting or external access
- Postgres migration
- Email/SMS provider credentials
- Raspberry Pi 5 packaging or appliance image

Those are later phases unless a live pilot requires them earlier.
