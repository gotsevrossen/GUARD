# Missing deployment information

> **Legacy (Linux appliance era); not current.** This document describes the original Linux appliance plan and is kept for history only. LightHouse is now Windows-only; see [windows-install.md](windows-install.md) and the README for the current product.

These items do not block code scaffolding, but they block a validated appliance deployment.

1. **Linux VM** — distro/version, CPU/RAM/disk, and whether it has a dedicated monitoring NIC.
2. **Monitoring sources** — exact Linux paths, read permissions/service user, Zeek JSON logging configuration, and Wazuh alert export format.
3. **Real fixtures** — anonymized captured Suricata `eve.json`, Zeek connection/protocol JSON, and Wazuh alert JSON. The current records are format-faithful starters, not real customer events.
4. **Ollama** — pull `qwen3:8b` on the VM and confirm model latency/memory under simultaneous Zeek and Suricata load.
5. **Network security** — dashboard bind address, TLS/local-certificate policy, bootstrap-admin password handoff, and firewall rules. Do not expose the development CORS/API configuration to the public internet.
6. **Developer telemetry** — selected source for per-device bandwidth and host CPU/RAM readings. Current technical views expose persisted evidence; production graphs need Zeek volume aggregation and Linux host metrics.
7. **Phase 6** — email/SMS provider, notification threshold defaults, and recipient-management rules.
8. **Visual direction** — the dashboard is deliberately minimal and mobile responsive; provide the desired application layout or visual references for a later UI refinement.
