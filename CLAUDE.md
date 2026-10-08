# LightHouse — Local AI Security Copilot

LightHouse is a Windows desktop app that gives small-business owners SOC-style security monitoring with no security background required and no cloud. It collects alerts from local sensors, triages each one with an on-device LLM, and shows plain-English explanations and one concrete next step in a desktop dashboard. **No monitoring data or AI inference ever leaves the user's machine.** Treat that as a hard product requirement, not a preference.

## Platform: Windows only

LightHouse is now a **Windows-only** product. Build, test and design for Windows 10 22H2+ x64.

- **Network sensor:** Suricata + Npcap
- **Host sensor:** Sysmon + Windows Security event log
- **Local AI:** llama.cpp in-process (`llama-cpp-python`, exact pin) running a Phi-4-mini GGUF model
- **Services:** NSSM runs the API, ingestion and Suricata as Windows services
- **Packaging:** Inno Setup → `dist/LightHouse-Setup.exe` (`packaging/windows/`)
- **UI:** the Start-menu and desktop shortcuts open the dashboard at `http://127.0.0.1:8000` in its own window (Microsoft Edge app mode, `--app=`), backed by `dashboard/public/manifest.json`; default browser if Edge is absent. No pywebview, no service worker (nothing is cached offline)
- **Network exposure:** loopback only

Notes:
- **Linux code is legacy.** The `.deb` build, Ollama backend, Zeek reader, Linux Wazuh log tailing, systemd units, `debian/`, `packaging/build-deb.sh`, `triage/desktop.py` (pywebview) and the appliance section of the README are no longer maintained. Don't extend them or design around them. Ask before deleting any of it, since some shared code (e.g. the Wazuh parser) is still used by Windows.
- Windows event logs are adapted into the existing Wazuh alert shape (`Source.WAZUH`) in `triage/ingest/windows.py`, so the DB and UI need no new source enum. No Wazuh process runs.
- llama.cpp is an internal detail. Users never install, launch or see an AI runtime. Only `triage/local_model.py` and `build_model()` may know llama.cpp exists; everything else talks to the `TriageModel` interface.
- Local AI needs an x64 CPU with AVX2. Without it, LightHouse still monitors and stores alerts for human review.

## Repo map

```
triage/                 Python backend (FastAPI + ingestion + triage)
  api.py                Routes, auth, role checks, lifespan (starts ingestion in desktop mode)
  schema.py             Pydantic models: NormalizedAlert, TriageResult, Severity, owner vs analyst shapes
  llm.py                Prompt building, untrusted-evidence fencing, TriageModel ABC, fixture model (Ollama model is legacy)
  local_model.py        llama.cpp runtime (lazy load, retry, AVX2 check, installer CLI)
  service.py            Pipeline: dedupe → model → sensor severity floor → store
  db.py                 SQLite (WAL): users, sessions, alerts, preferences
  dedupe.py             Duplicate suppression
  ingest/readers.py     Suricata / Wazuh-shape parsers + tailers (Zeek parts are legacy)
  ingest/windows.py     Windows Event Log reader (Sysmon + Security) → Wazuh-shaped alerts
  ingest/health.py      Ingestion health for analyst views
  desktop.py            pywebview window (legacy Linux desktop)
  main.py               CLI: `replay --mock`, `tail`
  paths.py              Per-platform data/config paths
dashboard/              React 18 + TypeScript + Vite (no UI library)
  src/main.tsx          Whole app: login, home, alerts, trends, advanced, settings, admin, chat
  src/api.ts            Fetch wrapper, session storage
  src/conversations.ts  Chat history (localStorage only)
  src/styles.css        Design tokens + layout (signed-off frame)
  src/sidebar.css       Sidebar rules
packaging/windows/      build.ps1, install.ps1, lighthouse.iss, security.ps1, configure_suricata.py, dependency-hashes.json
packaging/              Legacy Linux packaging (build-deb.sh, systemd, monitoring-stack installer), PyInstaller spec
samples/                Fixture records for Suricata, Zeek, Wazuh
tests/                  pytest suite (+ windows_security.ps1)
docs/                   windows-install.md, implementation-log.md, missing-information.md, backend-completion-requirements.md
*-ui-frame.html         Static design references for the dashboard frame (lighthouse-ui-frame.html is current)
```

## Commands

Run these in PowerShell on Windows.

```powershell
# Backend
uv sync                                  # or: pip install -e '.[dev]'
python -m pytest                         # backend tests
python -m triage.main replay --mock      # seed DB from samples/ without a model

# Frontend dev (hot reload): API on loopback + Vite proxy
$env:LIGHTHOUSE_DEV=1; uvicorn triage.api:app --reload --host 127.0.0.1 --port 8000
cd dashboard; npm ci; npm run dev        # http://localhost:5173, proxies /api
cd dashboard; npm run build              # tsc -b && vite build -> dashboard/dist
cd dashboard; npm test                   # vitest

# Windows installer (x64, needs Node/npm + uv, AVX2 CPU, VC++ runtime)
powershell -NoProfile -ExecutionPolicy Bypass -File packaging/windows/build.ps1

# Local model helpers used by the installer
python -m triage.local_model check-cpu
python -m triage.local_model smoke-test --model-path <file.gguf>
```

## Architecture rules

- **One process on desktop:** the FastAPI app serves `/api/*` and the built dashboard from the same origin on `127.0.0.1:8000`, and runs ingestion as a background asyncio task. The ingestion task must catch everything below `CancelledError` and log it; a bad sensor record must never take down login.
- **Loopback only.** Never bind to `0.0.0.0`, add CORS origins, or expose the Vite dev server. LAN access exists only in the appliance deployment, behind TLS.
- **`LIGHTHOUSE_DEV`** publishes the schema and route table. Workstation only; never set it in packaging.
- Config is via `LIGHTHOUSE_*` env vars and `<install folder>\data\config\windows.json`. Add new settings the same way and document them in `docs/windows-install.md`.
- Windows paths follow the install folder chosen in setup (default `C:\Program Files\LightHouse`, may be on any internal NTFS drive): app in `<install folder>`, data (DB, config, models, logs, state) in `<install folder>\data`, Suricata in `<install folder>\Suricata`. The installer passes every path to the services as `LIGHTHOUSE_*` variables; never hard-code `C:\` or `ProgramData`. `C:\ProgramData\LightHouse` is only the legacy location setup migrates from. Only the Npcap driver, VC++ runtime, Sysmon binary and Windows event logs stay on the system drive.
- The install folder is locked by setup (SYSTEM/Administrators full, Users read+execute) because every service runs from it as LocalSystem; keep it that way.

## Security rules (do not weaken)

This is a security product; these controls are the point of the code.

1. **Sensor data is attacker-controlled.** Everything from a sensor record goes to the model inside `<untrusted_evidence>` fences, as an allowlisted, length-capped projection (`build_prompt`, `EVIDENCE_MAX_CHARS`, `_scrub`). Never send the whole raw record, and never put sensor text outside the fence.
2. **Severity floor.** Stored severity = `max(sensor_severity, model_severity)` (`apply_sensor_floor`). The model may raise severity, never lower it. This is the control that survives prompt injection.
3. **Model output is untrusted too.** `TriageResult` validation is the trust boundary. Model runtimes never raise for a bad or missing model; they return `unavailable_result()` (severity `UNKNOWN`, "needs human review") so ingestion keeps going.
4. **Roles are enforced server-side** (`require(...)` in `api.py`). Owner < Analyst < Admin. Owners get `AlertDetailOwner`, which filters out `raw`, `rule_id` and `reasoning` via the model itself. Hiding a tab in the UI is not access control.
5. **Auth:** bcrypt hashes, random server-side sessions (8 h), no default credential, generated one-time admin password with forced change (min 12 chars).
6. **Supply chain:** use `npm ci` (never `npm install` in builds), keep `uv.lock` and `package-lock.json` committed, keep exact pins for native packages (`llama-cpp-python`), and update `packaging/windows/dependency-hashes.json` when installer downloads change.
7. Windows data, config, models and logs are Administrators/SYSTEM-only ACL. Keep it that way.

## Dashboard design

The frame was signed off. **Match it strictly.** Reuse the existing tokens, components and layout; `lighthouse-ui-frame.html` is the reference. Ask before introducing any new colour, font, spacing scale or visual pattern, and never restyle existing screens unprompted. (`guard-ui-frame.html` is an older version that used Poppins; ignore it.)

- **Layout:** flat green sidebar rail (300px) with the content sheet lapping over its right edge (large rounded left corners). Only `.sheet` scrolls; the shell never does. Content max-width 1020px, centred.
- **Tokens (in `styles.css` `:root`, always use the variables):**
  `--green #2A9679`, `--green-dark #217a61`, `--green-deep #186049`, `--ink #000`, `--paper #fff`, `--ground #E9E9E9`, `--line rgba(0,0,0,.18)`, `--muted #4b524f`; radii `--r-lg 40px`, `--r-md 24px`, `--r-sm 14px`.
- **Severity colours:** `--sev-low #2A9679`, `--sev-med #C08A1E`, `--sev-high #BF4536`. They're validated for colour-vision deficiency. **Always pair colour with a text label, never colour alone.**
- **Type:** system font stack, no web fonts (must render offline). Uppercase extra-bold `h1`, small uppercase letter-spaced eyebrows, white rounded cards on the grey ground; the lead card is solid green.
- **Audience is a non-technical owner.** Plain-English first; technical evidence lives behind analyst/admin views. One concrete recommended action per alert.
- **Accessibility:** native elements where possible (alerts are `<details>` so they open without JS and are keyboard-operable), `role="status"` for notices, `aria-label` on icon-only controls.
- **No UI or CSS framework.** Plain React components in `main.tsx` + hand-written CSS.
- **Resilience:** parse localStorage defensively (`safeParse`); corrupt storage must never white-screen the app.
- **Chat** ("Ask LightHouse"): see below.

## Chat ("Ask LightHouse") — planned work

Currently a front-end stub (`setTimeout` placeholder in `main.tsx`, history in localStorage via `conversations.ts`). The goal is to **wire it to the same on-device model** used for triage.

- Answers come from the local llama.cpp runtime only. No cloud API, ever.
- Add a backend route (e.g. `POST /api/chat`) behind `require(*ALL_ROLES)`. Reuse the loaded model behind the model abstraction instead of loading a second copy.
- Any alert data included as context is attacker-controlled: fence it with the same `<untrusted_evidence>` handling as `build_prompt`, and cap its length.
- Respect roles: an owner's chat context must not include `raw`, `rule_id` or `reasoning`.
- Write answers for a non-technical owner. Handle "model unavailable / no AVX2" with a clear message, not an error screen.
- Inference is CPU-only and slow; keep the existing typing indicator and don't block the UI.

## Code style

- Python 3.11+, `from __future__ import annotations`, type hints, Pydantic v2 models for anything crossing a boundary.
- Comments explain **why** (threat model, trade-off), not what. Keep that habit; many existing comments document security decisions, so don't delete them.
- Add or update tests in `tests/` for any change to parsing, triage, auth, roles or the installer. Run `python -m pytest` before calling a change done.
- Keep changes small and surgical; don't refactor unrelated code.
- **Never run `git commit`, `git push` or other history-changing git commands.** Make the file changes and leave committing to me.

## Known gaps

- Clean-machine Windows install, repair and upgrade testing are still outstanding.
- Free Npcap can't install silently (interactive wizard). Fully unattended setup needs preinstalled Npcap or the OEM installer.
- `samples/` are format-faithful starters, not real captured events.
- See `docs/missing-information.md` and `docs/backend-completion-requirements.md` for open decisions.
