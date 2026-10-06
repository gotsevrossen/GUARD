# Native Windows deployment

Build from an x64 Windows development checkout (Node/npm and uv required):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File packaging/windows/build.ps1
```

The build installs Inno Setup with winget if needed, builds the existing React
app, bundles an isolated Python 3.13 runtime and locked backend dependencies,
and produces `dist/LightHouse-Setup.exe`. Target machines do not need Python,
Node, Git, uv, WSL, Docker, Zeek, Wazuh, Ollama or any other AI software: local
AI inference (llama.cpp) is bundled inside LightHouse. Internet access is required
during installation for the sensor packages, rules, the Visual C++ runtime and the
AI model download (about 2.5 GB). Windows 10 22H2 or newer, x64, is required; local
AI additionally needs a CPU with AVX2 (see [Local AI](#local-ai-llamacpp)).
Building also needs, on the build machine, the Visual C++ runtime and an AVX2 CPU:
the build loads the bundled llama.cpp DLLs as a check.

Double-click the EXE and approve Windows elevation. The free Npcap installer
has its own interactive wizard. Enable WinPcap compatibility mode. All other
dependency setup runs unattended. The setup then installs Suricata's official
MSI and Sysmon with the SwiftOnSecurity starting configuration, installs or
updates the Microsoft Visual C++ runtime, downloads the Phi-4-mini GGUF model and
runs a local AI self-test. It enables Security logon success/failure auditing.

**The free Npcap edition cannot install silently.** This is a missing feature,
not a switch that LightHouse can enable. See the [Npcap vendor guide](https://npcap.com/guide/npcap-users-guide.html).
For a completely unattended install, preinstall Npcap or supply an OEM installer
path in `C:\ProgramData\LightHouse\config\windows.json` under
`NpcapOemInstaller`. Then run, from an elevated terminal:

```powershell
.\dist\LightHouse-Setup.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /LOG="C:\Temp\LightHouse-setup.log"
```

Absent Npcap/OEM, silent setup fails explicitly and does not open a hidden driver
wizard. On an incomplete install, correct the reported cause and rerun the EXE.
The application payload may already be installed, but that is not a running stack.

## Files, credentials, and services

- Application and dashboard: `C:\Program Files\LightHouse`.
- Database: `C:\ProgramData\LightHouse\lighthouse.db`.
- Operator configuration: `C:\ProgramData\LightHouse\config\windows.json`.
- Sysmon rules: `C:\ProgramData\LightHouse\config\sysmon.xml`.
- Suricata configuration/rules/EVE: `config\suricata.yaml`, `rules`, and `suricata\eve.json` below the data directory.
- Event Log checkpoints: `C:\ProgramData\LightHouse\state`.
- AI model (GGUF): `C:\ProgramData\LightHouse\models\microsoft_Phi-4-mini-instruct-Q4_K_M.gguf`.
- Installer transcript: `C:\ProgramData\LightHouse\logs\install.log`.
- Last setup result: `C:\Program Files\LightHouse\setup\last-result.txt`.
- Initial `admin` password: `C:\ProgramData\LightHouse\logs\LightHouse-API.stdout.log` (including rotated copies).

Read the credential log using an elevated editor/terminal. The existing generated
password banner and mandatory first-login password change are unchanged. Data,
configuration, model storage and logs have an Administrators/SYSTEM-only ACL.
API startup initializes the database before ingestion starts, so the credential
banner is in the API log. Repair preserves accounts and does not reset passwords.

NSSM registers these automatic LocalSystem services, with restart-on-failure and
rotating stdout/stderr logs under the data directory:

| Service | Command / responsibility |
| --- | --- |
| LightHouse-API | `python -m uvicorn triage.api:app --host 127.0.0.1 --port 8000` |
| LightHouse-Ingestion | `python -m triage.main tail` |
| LightHouse-Suricata | Native Suricata packet capture and EVE output |

There is no separate AI service: the ingestion service runs the model in-process.
The API/dashboard is at http://127.0.0.1:8000.
NSSM's service environment supplies all application settings; no user PATH or
shell activation is required. No inbound firewall rule is added.

## Local AI (llama.cpp)

Owners install LightHouse, not an AI application. The llama.cpp runtime is part of
the LightHouse payload (the `llama-cpp-python` wheel and its DLLs in the bundled
Python), and the model is one GGUF file in the data directory. Nothing listens on
a network port for it and no separate AI service exists.

- **Where it runs.** Inside the LightHouse-Ingestion service, the only process that
  triages alerts. The API service never loads the model, so dashboard startup does
  not wait for it.
- **Lifecycle.** The model loads once, on the first alert after the service starts
  (a few seconds), in a worker thread, and is reused for every later alert. Alerts
  from all sensors are triaged one at a time; meanwhile readers keep polling and
  reporting health.
- **Output.** The first attempt generates freely and the JSON object is extracted.
  If it does not validate, the retry uses grammar-constrained generation from the
  result's JSON schema, which cannot produce malformed JSON. Constrained decoding
  is not the first attempt because llama-cpp-python applies the grammar to the
  whole vocabulary: with Phi-4-mini's 200k-token vocabulary it was about three
  times slower per alert. Pydantic validation (`TriageResult`) remains the trust
  boundary for both attempts, and the sensor severity floor still applies.
- **Failures degrade, never crash.** Missing, corrupt or incompatible model,
  insufficient memory, missing native runtime, unsupported CPU, malformed output or
  an inference error all produce the existing "have a technical user review this
  alert" result, with the reason in the analyst-only reasoning. Monitoring and
  storage continue. A failed model load is retried after five minutes, so a
  repaired model is picked up without restarting the service.
- **Speed.** CPU inference of the pinned model took about 25-45 seconds per alert
  on the 14-thread development machine, plus about 5-10 seconds to load once. A
  burst of distinct alerts is therefore worked through over minutes; repeats are
  deduplicated first and never reach the model.

**CPU and runtime requirements.** The bundled wheel is the upstream prebuilt CPU
build, compiled for AVX2/FMA/F16C (Intel Haswell 2013+, AMD Zen/Excavator+). On a
CPU without AVX2 the native library would crash the service outright, so the CPU is
checked before llama.cpp is loaded: setup then skips the model download and
self-test and finishes with a warning, and the service stores alerts for human
review. The DLLs also need the Visual C++ 2015-2022 runtime 14.44 or later
(`msvcp140.dll`, `vcomp140.dll`), which setup installs from Microsoft. If that
update needs a restart because the old DLLs are in use, setup says so; restart and
run setup again.

**GPU acceleration** is not included. CPU inference works on any supported PC.
`LIGHTHOUSE_MODEL_GPU_LAYERS` (0 = CPU, -1 = all layers) takes effect only with a
GPU-enabled llama.cpp build (CUDA or Vulkan wheel), which would change the
packaged wheel, add vendor driver/runtime requirements, and need its own clean-
machine validation. Nothing else in LightHouse would change.

**Upgrading from an Ollama release.** Setup removes the old LightHouse-Ollama
service and its model store (`models\blobs`, `models\manifests`). The Ollama
application those releases installed under `C:\Program Files\LightHouse\tools\ollama`
is left installed; remove it from Apps & features if nothing else uses it.

## Network configuration and repair

First setup selects the IPv4 default-route adapter and its subnet. Review
`HomeNet` and `CaptureInterface` before relying on coverage, particularly on
machines with multiple adapters or a VPN. A host's adapter only sees traffic
available to that host/interface; full LAN monitoring requires an appropriate
mirror/TAP arrangement.

Example `windows.json` (use your real adapter GUID and subnet):

```json
{
  "HomeNet": "192.168.1.0/24",
  "CaptureInterface": "\\Device\\NPF_{YOUR-ADAPTER-GUID}",
  "SuricataDir": "C:\\Suricata",
  "ApiPort": 8000,
  "ModelPath": "",
  "NpcapOemInstaller": ""
}
```

`ModelPath` is empty for the LightHouse-managed model. To use another GGUF model,
set it to the file's path and rerun setup: the file is copied once into the
protected `models` directory (the SYSTEM service never reads a user-writable model
file, and later reruns do not re-import it) and must pass the self-test. To switch
models, use a file with a new name, or delete the copy under `models` first. Configurations from earlier releases may still contain
`Model` and `OllamaPort`; both are ignored.

Rerun setup after changing the JSON. It stops only the LightHouse services before
updating files, preserves the database/config/checkpoints/models, updates service
settings in place, reapplies the existing Sysmon XML, regenerates Suricata YAML
from the vendor file and JSON, validates it with `suricata -T`, and starts services
in dependency order. ET Open's currently published Suricata 7.0.3 rule archive is
used with Suricata 8; setup validates the resulting rules/configuration. `suricata -T`
fails on any single rule it cannot parse (for example rules using `file.magic`,
which the Windows build of Suricata lacks), so setup comments out exactly the rules
that failed, lists them in `rules\disabled-by-lighthouse.txt`, and tests again.
A configuration error, or more than 100 failing rules (a ruleset that does not
match the engine), still stops setup. The test output is in `install.log`.
`SuricataDir` defaults to `Suricata` on the Windows system drive. Download
SHA256 values are recorded in the transcript and executable packages (including
cached copies) are checked against `packaging/windows/dependency-hashes.json`.
The Visual C++ runtime installer and an operator-supplied Npcap OEM installer must
have a valid Authenticode signature from the expected publisher. The GGUF model is
downloaded from a commit-pinned Hugging Face URL and checked against its pinned
SHA256; downloads are retried on transient network errors. Sysmon is published only at a fixed
latest-release URL, so instead of a hash its `Sysmon64.exe` must carry a valid
Microsoft signature and the Sysinternals Sysmon product name. OEM files are copied
into the protected cache before verification/execution. NSSM is restored from its
verified archive on repair. The build also checks the embedded Python archive
against a pinned hash and installs Python wheels, including the llama-cpp-python
wheel with its native DLLs, only with the hashes in `uv.lock`.
Downloads are verified before they enter the cache; a download or cached copy
that fails verification is discarded and fetched again on the next run.

Pins were established from the official vendor downloads on 2026-09-18. Updating
a pinned dependency requires reviewing its vendor release and updating the
committed hash; mismatches fail closed. Never update a pin simply to accept a
failed download. Rule/config text downloads are not executable
packages and continue to use HTTPS and the existing configuration validation.

The data tree receives a complete Administrators/SYSTEM-only DACL and trusted
ownership, including existing children. Setup rejects reparse points, untrusted
ownership, and preexisting untrusted write permissions (including generic-rights
entries) before consuming files. SYSTEM and Administrators are trusted owners.
When setup runs with a full, unsplit admin token (the built-in Administrator, or
UAC turned off), the account running it is trusted too: such accounts own what they
create and never run reduced-rights programs. Elevated UAC admins are not, since
their normal programs run as the same account without admin rights. At the end of every run, successful or
not, setup hands what it created to Administrators so any administrator can repair.
A rejection is shown in the setup error and `last-result.txt`; it happens before
`install.log` is opened. If rejected, preserve the old tree separately and
reinstall into a clean location; do not blindly copy potentially modified
configuration or cached executables back.

Uninstall removes the LightHouse service registrations and application payload.
It preserves data (including the model) and the separately installed Npcap/
Suricata/Sysmon dependencies and Visual C++ runtime; it does not change auditing
back or remove shared drivers.
Installation is repairable, but does not offer transactional rollback of vendor
installers. Honor a dependency's reported reboot requirement.

## Ingestion configuration

| Environment variable | Windows default |
| --- | --- |
| LIGHTHOUSE_SURICATA_PATH | `C:\Suricata\log\eve.json`; installer overrides to ProgramData |
| LIGHTHOUSE_SYSMON_CHANNEL | `Microsoft-Windows-Sysmon/Operational` |
| LIGHTHOUSE_SECURITY_CHANNEL | `Security` |
| LIGHTHOUSE_EVENT_STATE_DIR | `C:\ProgramData\LightHouse\state` |
| LIGHTHOUSE_MODEL_BACKEND | `llama_cpp` (`ollama` is the Linux default) |
| LIGHTHOUSE_MODEL_PATH | unset; installer sets the GGUF path under `models` |
| LIGHTHOUSE_MODEL_CONTEXT_SIZE | `4096` tokens |
| LIGHTHOUSE_MODEL_GPU_LAYERS | `0` (CPU only; see Local AI) |

Set a channel/path to an empty string to disable that input. Windows ignores
`LIGHTHOUSE_WAZUH_PATH` and `LIGHTHOUSE_ZEEK_PATH`. Linux keeps its existing file
sources, environment variables, commands and Ollama model runtime.

Sysmon/Security events use the existing Wazuh-compatible host-alert shape and
therefore retain `source=wazuh` in the existing dashboard/API. Native provider,
channel, Event ID, record ID and event data are retained in `raw.data.win`; no
Wazuh process runs. All Sysmon events are accepted. Security events include
4624, 4625, 4648, 4672, 4720, 4726, 4732 and 1102. Routine activity has a low
sensor floor; failed logon and account changes are medium; audit clearing and
Sysmon process tampering are high. The model can raise these floors as before.

First Event Log startup follows new events. Later starts resume saved record
positions, advancing only after successful processing. Log clear/rollover is
detected using both record ID and timestamp and replays retained records.
Normal downstream deduplication still applies. Failures are logged and retried.
Windows inputs add a hash of event-specific evidence (commands, images, accounts,
target paths, remote addresses) to their deduplication key, preventing unrelated
activity on the same host from being suppressed. Per-occurrence values (process and
logon IDs/GUIDs, source ports, timestamps, DNS answers) are excluded, so repeats
of one activity, such as a password-guessing burst, still collapse into one alert.
The detector rule ID stays readable. Event 1102 accepts the actual Eventlog provider and preserves UserData.

The installer probes both Event Log channels right after installing Sysmon (before
the model download) and waits for fresh reader health reports from the newly
started ingestion service. A reader reports `ok` once it has read its channel,
without waiting for the model to triage a backlog; after a processing failure it
stays `error` until an event is processed. Unchanged status is refreshed every
30 seconds. Analysts/admins can inspect `GET /api/advanced/ingestion`; missing,
failed, stopped or stale readers report `ok: false`. Off Windows no Event Log
readers run, so it reports `ok: true` with no channels. These reports cover Event
Log access/processing, not proof of network capture or AI accuracy. Reader reports
expire after four minutes without progress.
Suricata accepts alert, flow, http, tls, dns and smb records. Its Windows reader
waits for file creation, handles partial lines, and reopens on rotation/truncate.
As with the original file tailer, it starts at EOF and has no persistent file
offset across service downtime. The event channels have independent readers.

## Clean-machine validation checklist

Required before release, on a clean Windows 10 22H2 and Windows 11 x64 machine or
VM with no Python, Visual C++ runtime, Ollama or other AI software installed:

1. Run `LightHouse-Setup.exe`; setup completes and `last-result.txt` reads
   `Installation completed.` without an AVX2 warning (on an AVX2 CPU).
2. The transcript shows the Visual C++ runtime installed and the self-test JSON
   (`"ok": true`) for the GGUF under `C:\ProgramData\LightHouse\models`.
3. `C:\Program Files\LightHouse\runtime\Lib\site-packages\llama_cpp\lib`
   contains `llama.dll`, `ggml.dll`, `ggml-base.dll` and `ggml-cpu.dll`.
4. The API, Ingestion and Suricata services are running; no LightHouse-Ollama
   service exists, no `ollama.exe` is present or running, and nothing listens on
   ports 11434/11435.
5. Trigger a failed logon; within about a minute the dashboard shows the alert with
   a model-written explanation (not the "technical user review" fallback).
6. Reboot: services start, the model loads on the first alert, and triage works.
7. Rename the GGUF file and trigger an alert: the alert is stored with the review
   fallback and ingestion keeps running. Restore it: triage resumes within five
   minutes without a restart.
8. Repeat step 1 over an existing install (repair), and over an install of the
   previous Ollama-based release (upgrade: legacy service and model store removed).
9. On a machine without AVX2, setup completes with the warning and monitoring works.

## Validation status (2026-09-18)

- llama.cpp packaging: the full `build.ps1` build produced `LightHouse-Setup.exe`
  with the llama-cpp-python 0.3.35 CPU wheel installed hash-verified into the
  embedded runtime. The staged embedded runtime loaded the native DLLs and, with
  the pinned Phi-4-mini Q4_K_M GGUF, passed `triage.local_model smoke-test`
  (load 4.5 s, one validated triage). Five sample alerts, including the prompt-
  injection fixture, all validated on the first, unconstrained attempt.
- **The clean-machine checklist above has not been run.** The development machine
  already had the Visual C++ runtime and no clean VM was available.

- Backend suite: **95 passed, 1 skipped** (the optional real-GGUF test, run
  separately with `LIGHTHOUSE_TEST_GGUF`), including 21 llama.cpp backend tests
  with a mocked runtime, 21 Windows ingestion tests, an installer security
  regression suite, and authentication coverage for ingestion health.
- Installer guard tests cover ACL construction, unsafe ownership/write grants
  (including generic rights), reparse rejection with the specific reason, changed/
  missing hashes, unsigned files, wrong publishers and unsigned/corrupt Sysmon
  archives. The real Sysmon 15.22 archive passes the signer/product check. Download
  verification, cache rejection and re-download were exercised against local files.
  Applying protected ACLs and restoring ownership on an elevated installed tree
  remain unvalidated.
- React production build: passed; the only UI change is model wording (no Ollama).
- Embedded Python: backend, bcrypt, uvicorn and pywin32 import smoke test passed.
- Bundled API/dashboard: health and HTML checks passed on two consecutive starts;
  the existing administrator password hash was preserved on restart.
- Native pywin32: successfully read the developer machine's Application channel.
- Suricata: official MSI downloaded/extracted; generated configuration and ET Open
  rule assembly verified against its vendor YAML. Live `suricata -T`/capture has
  not been validated because Npcap is not installed.
- Inno Setup: compiled to an actual EXE. An initial EXE was run on the development
  machine and installed the application payload, then reported incomplete
  dependency setup. No LightHouse services were created. Its dependency log is
  admin-protected; a later UAC request to inspect it was cancelled. The final
  build additionally returns a failing exit code and records dependency failure
  text in the Inno log and `last-result.txt`.
- **Full dependency installation, model download, service startup, reboot
  survival, and end-to-end repair/reinstall/upgrade have not been validated.**
- **No clean-machine or VM validation was performed.** All checks above used this
  Windows development machine. Do not interpret compilation as a successful
  clean-machine installation.
