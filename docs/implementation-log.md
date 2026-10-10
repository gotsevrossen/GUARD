# Implementation log

> **Legacy (Linux appliance era); not current.** This document describes the original Linux appliance plan and is kept for history only. LightHouse is now Windows-only; see [windows-install.md](windows-install.md) and the README for the current product.

## 2026-09-08 — Phases 3–5 initial build

- Added a Python/FastAPI triage service with source-specific JSON parsers, a common Pydantic alert schema, duplicate suppression, a swappable Ollama/fixture model interface, and SQLite storage.
- Added fixture replay for Suricata, Zeek JSON, and Wazuh, plus a live JSON-lines tail reader for Linux log paths.
- Added authenticated Owner, Analyst, and Admin API roles. Passwords are BCrypt-hashed; server-side random sessions expire after eight hours.
- Added React/Vite dashboard views for plain-language alerts, resolution/dismissal, trends, technical evidence, appliance status, and admin user creation.
- Added unit tests for source formats, validation failure, deduplication, persistence, and session authentication.

## Validation status

Static implementation is complete. This Windows workspace has no Python or Node runtime, so tests, backend startup, frontend build, live ingestion, Qwen3 calls, and responsive-browser validation have not yet been run. Perform them on the planned Linux VM.
