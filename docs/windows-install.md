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
Plan for at least 8 GB of RAM (8192 MB on a VM, as startup memory if Dynamic Memory
is on): the loaded model takes about 3 GB and Suricata with the full ET Open ruleset
about 1 GB, on top of Windows itself. Below that, the services fail or thrash.
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
path in `<install folder>\data\config\windows.json` under
`NpcapOemInstaller`. Then run, from an elevated terminal:

```powershell
.\dist\LightHouse-Setup.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /LOG="C:\Temp\LightHouse-setup.log"
```

Absent Npcap/OEM, silent setup fails explicitly and does not open a hidden driver
wizard. On an incomplete install, correct the reported cause and rerun the EXE.
The application payload may already be installed, but that is not a running stack.

## Files, credentials, and services

Everything large follows the install folder chosen in setup (default
`C:\Program Files\LightHouse`), so LightHouse can live entirely on another internal
NTFS drive. Below, `<app>` is that folder and `<data>` is `<app>\data`.

- Application and dashboard: `<app>`. Locked by setup before any file is copied in:
  SYSTEM and Administrators full control, Users read and execute only (every service
  runs from here as LocalSystem). Setup refuses network, removable and FAT32/exFAT
  drives, drive roots, and any non-empty folder other than the existing install
  recorded in Windows' (admin-only) uninstall registry entry. A file inside the
  folder never counts as proof of an install, because anyone can fake one. On every
  run, the owner of everything below `<app>` is reset to Administrators (except
  `<data>`, which has its own protection), permissions are reset to inherit from
  `<app>`, and each item is then checked. A file with another owner could otherwise
  reopen its own permissions.
- Suricata: `<app>\Suricata`. Upgrades move it there from the old `C:\Suricata`
  default. A custom `SuricataDir` elsewhere gets the same permissions and owner as
  `<app>` (suricata.exe runs as LocalSystem). If it already exists, it must not
  have been writable by non-administrators, or setup stops (see below).
- Database: `<data>\lighthouse.db`. It holds alerts, accounts, sessions,
  preferences and the Admin page's activity log (who signed in, changed users,
  paused monitoring, changed the AI settings or started an update; read-only, and
  alerts are named by id only). Nothing is deleted automatically: data is
  currently kept until it is removed.
- Operator configuration: `<data>\config\windows.json`.
- Sysmon rules: `<data>\config\sysmon.xml`.
- Suricata configuration/rules/EVE: `config\suricata.yaml`, `rules`, and `suricata\eve.json` below `<data>`.
- Event Log checkpoints: `<data>\state`.
- AI model (GGUF): `<data>\models\microsoft_Phi-4-mini-instruct-Q4_K_M.gguf`.
- Installer transcript: `<data>\logs\install.log`.
- Dashboard updates ("Update now"): the verified installer and its task script in `<data>\updates`,
  run once as SYSTEM by the scheduled task `LightHouse-Update`; setup log in
  `<data>\logs\update-install.log`. The API removes the task and the downloaded files
  10 minutes after it next starts.
- Last setup result: `<app>\setup\last-result.txt`.
- Dashboard port for the shortcut and the Finish page: `<app>\setup\api-port.txt`.
  Setup copies `ApiPort` from `windows.json` there on every run, because the
  shortcut runs as the signed-in user, who can't read the admin-only data folder.
  It holds only the port number (Users can read it; only administrators can change
  it).
- Initial `admin` password: `<data>\first-run-password.txt`, written
  on the first start only (`LIGHTHOUSE_FIRST_RUN_DIR`) and deleted when the admin
  sets their own password. It is also printed once to `logs\LightHouse-API.stdout.log`,
  but NSSM renames that log on every service restart, so search `LightHouse-API*`.
- Always on the Windows drive (Windows requires it, ~100 MB): the Npcap driver, the
  Visual C++ runtime, the Sysmon service binary, the Windows event logs, the Start
  menu entries and setup's temporary files.

**Upgrading from a release that used `C:\ProgramData\LightHouse`:** when `<data>` has
no database yet, setup stops the services, verifies the old folder is owned and
writable only by Administrators/SYSTEM (ordinary users can create folders in
ProgramData, so an untrusted tree is refused, never reused), checks free space,
moves it into `<data>` and removes the original. If the program itself moved, the
services are re-pointed at the new folder and, once everything is running, the old
program folder is deleted (only if it is a LightHouse folder). Suricata is moved
into `<app>\Suricata` (its MSI is uninstalled and installed fresh there) when it
is in LightHouse's own old default (`C:\Suricata` on the system drive), on any
drive, or in the previous program folder. A new folder at the root of `C:` lets
every signed-in user add files, and suricata.exe runs as LocalSystem. A
different folder chosen in `SuricataDir` stays where it is and is locked like
`<app>`. If it existed and could be changed by non-administrators, setup stops:
uninstall Suricata in Apps & features, delete that folder, and run setup again.

Read the password from an elevated terminal:

```powershell
$lh = Join-Path (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' | Where-Object DisplayName -like 'LightHouse*').InstallLocation 'data'
Get-Content "$lh\first-run-password.txt"
```

Do not browse there in File Explorer and accept its "Continue" prompt, which
permanently grants your account access to the protected folder. The generated
password banner and mandatory first-login password change are unchanged. Data,
configuration, model storage and logs have an Administrators/SYSTEM-only ACL.
API startup initializes the database before ingestion starts, so the credential
banner is in the API log. Repair preserves accounts and does not reset passwords.

**Lost password.** Passwords are stored only as bcrypt hashes, so none can be shown.
From an elevated terminal, give the account a new random password instead (default
account `admin`; pass a username for another). It is printed once, the account is
signed out everywhere, and it must choose its own password at next sign-in:

```powershell
$app = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' | Where-Object DisplayName -like 'LightHouse*').InstallLocation
& "$app\runtime\python.exe" -m triage.reset_password            # or: ... reset_password owner1
```

NSSM registers these automatic LocalSystem services, with restart-on-failure and
rotating stdout/stderr logs under the data directory:

| Service | Command / responsibility |
| --- | --- |
| LightHouse-API | `python -m uvicorn triage.api:app --host 127.0.0.1 --port <ApiPort>` (8000 by default) |
| LightHouse-Ingestion | `python -m triage.main tail` |
| LightHouse-Suricata | Native Suricata packet capture and EVE output |

There is no separate AI service: the ingestion service runs the model in-process.
The API/dashboard is at http://127.0.0.1:8000, or the `ApiPort` in `windows.json`.
The LightHouse Dashboard shortcuts run `<app>\setup\open-lighthouse.ps1`. It reads the port from `api-port.txt` beside it (8000 if that is missing or not a valid port). If an admin used "Shut down", it starts LightHouse-API (which resumes monitoring itself) and waits for `/health`. Then it opens the dashboard. Setup's Finish page uses the same port.
Setup lets interactive users start and query LightHouse-API only (`(A;;RPLCLORC;;;IU)` via `sc.exe sdset`); stopping or reconfiguring any service stays admin-only.
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
- **Speed-ups that never change an answer.** *Prompt-lookup speculative decoding*
  proposes up to 10 tokens copied from the prompt (addresses, process names, JSON
  keys) and the model checks them in one batch; a proposed token is kept only if
  it is exactly the token the model itself chose, so replies are the same, only
  sooner (`LIGHTHOUSE_MODEL_SPECULATIVE=0` turns it off). *Chat comes first:*
  while the API service answers or warms a chat it holds the `Global\LightHouse-LocalAI-Chat`
  mutex; background triage waits for it (at most 120 s per alert) and stops at
  the next token if a chat starts, then re-runs that alert from the start, so its
  result is what an uninterrupted run gives. After three interruptions of one
  alert it finishes regardless, so monitoring never stalls. *Saved instructions:*
  the API service saves the context state of chat's system prompt (instructions
  only; never alerts, questions or history) in `LIGHTHOUSE_MODEL_STATE_DIR`, so the
  first question after a restart does not re-read it. The file (about 130 KB per
  token: about 70 MB for the built-in instructions) is keyed to the model file, runtime version,
  context and thread settings and the exact prompt; editing the AI instructions
  makes a new one, and only the two newest are kept. A file that does not match
  is ignored and rebuilt.
- **Proving it.** With the services stopped (or monitoring paused), an
  administrator can run
  `& "$app\runtime\python.exe" -m triage.local_model bench --model-path <model.gguf> --samples <repo>\samples --out <folder>`.
  It triages the sample records and asks three fixed questions at temperature 0,
  with speculative decoding off and then on, prints load time, time to first chat
  token, tokens per second, triage time and grammar retries for each, says whether
  every answer was byte-identical, times a cold first question with and without
  the saved state, and writes a JSON report. It loads the model three times and
  takes several minutes; setup never runs it.

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
application those releases installed under `<app>\tools\ollama`
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
  "SuricataDir": "D:\\LightHouse\\Suricata",
  "ApiPort": 8000,
  "ModelPath": "",
  "NpcapOemInstaller": ""
}
```

This example is for LightHouse installed in `D:\LightHouse`. Setup writes
`SuricataDir` as `<app>\Suricata`; leave it there. `ApiPort` (1024-65535) is the
loopback port of the dashboard. After changing it, rerun setup: setup re-registers
the API service and updates the port the shortcuts use.

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
in dependency order. Rerunning setup, or "Update now", also turns paused
monitoring back on: it sets every service to automatic start and starts it. Pause
again from Home afterwards if needed. ET Open's currently published Suricata 7.0.3
rule archive is used with Suricata 8; setup validates the resulting rules/configuration.
ET Open publishes new rules at that fixed address every day, so every setup run
(fresh install, repair and "Update now") downloads the archive again. If that
download fails (no internet), setup warns and reuses the copy from the previous run,
so an offline repair still works. Between runs, the rules don't change. `suricata -T`
fails on any single rule it cannot parse (for example rules using `file.magic`,
which the Windows build of Suricata lacks), so setup comments out exactly the rules
that failed, lists them in `rules\disabled-by-lighthouse.txt`, and tests again.
A configuration error, or more than 100 failing rules (a ruleset that does not
match the engine), still stops setup. The test output is in `install.log`.
`SuricataDir` defaults to `<app>\Suricata`. Download
SHA256 values are recorded in the transcript and executable packages (including
cached copies) are checked against `packaging/windows/dependency-hashes.json`.
The Visual C++ runtime installer and an operator-supplied Npcap OEM installer must
have a valid Authenticode signature from the expected publisher. The GGUF model is
downloaded from a commit-pinned Hugging Face URL and checked against its pinned
SHA256; downloads are retried on transient network errors. Sysmon is published only at a fixed
latest-release URL, so instead of a hash its `Sysmon64.exe` must carry a valid
Microsoft signature and the Sysinternals Sysmon product name. The starting Sysmon
configuration (fresh installs only; an existing `config\sysmon.xml` is kept) comes
from SwiftOnSecurity/sysmon-config at one pinned commit, not the moving `master`
branch, and is checked against its SHA256 in `dependency-hashes.json`. OEM files are copied
into the protected cache before verification/execution. NSSM is restored from its
verified archive on repair. The build also checks the embedded Python archive
against a pinned hash and installs Python wheels, including the llama-cpp-python
wheel with its native DLLs, only with the hashes in `uv.lock`.
Downloads are verified before they enter the cache; a download or cached copy
that fails verification is discarded and fetched again on the next run.

Pins were established from the official vendor downloads on 2026-09-18. Updating
a pinned dependency requires reviewing its vendor release and updating the
committed hash; mismatches fail closed. Never update a pin simply to accept a
failed download. The ET Open rule archive changes daily, so it has no pinned hash;
it relies on HTTPS and on `suricata -T` validating the result.

The build pins its own tools too: Inno Setup is installed with winget at a fixed
version (raise it deliberately in `build.ps1`). LightHouse's own package is built
without build isolation, with the build backend (setuptools) installed from
`uv.lock`'s hashes into a throwaway `build\windows\build-env`. setuptools is locked
only as a dev-extra dependency (through pyinstaller), so keep it in `uv.lock` when
changing dev dependencies; the build stops if it is not hash-locked. Each build
removes earlier `build\windows\payload-*` staging folders.

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

Uninstall removes the LightHouse service registrations, the application payload
and any leftover `LightHouse-Update` scheduled task from "Update now".
It preserves data (including the model) and the separately installed Npcap/
Suricata/Sysmon dependencies and Visual C++ runtime; it does not change auditing
back or remove shared drivers.
Installation is repairable, but does not offer transactional rollback of vendor
installers. Honor a dependency's reported reboot requirement.

## Ingestion configuration

**What survives an update.** Setup writes the services' whole environment on every
run (`AppEnvironmentExtra` in `install.ps1`), and "Update now" runs setup. So a
variable added to a service by hand (with `nssm set`) is lost at the next repair or
update. On an installed LightHouse, only the `windows.json` keys are lasting settings:
`HomeNet`, `CaptureInterface`, `SuricataDir`, `ApiPort`, `ModelPath`,
`NpcapOemInstaller` and `ModelThreads`. Variables marked *developer only* below have
no `windows.json` key. Use them when running LightHouse from a checkout, or for a
temporary experiment on an install that the next setup run will undo.

| Environment variable | Windows default |
| --- | --- |
| LIGHTHOUSE_DB_PATH | installer sets `<data>\lighthouse.db` |
| LIGHTHOUSE_STATIC_DIR | installer sets `<app>\dashboard\dist` (the built dashboard, served at `/`) |
| LIGHTHOUSE_DESKTOP | installer sets `0`: the API and ingestion run as separate services, so the API does not start ingestion itself |
| LIGHTHOUSE_FIRST_RUN_DIR | installer sets `<data>`: where `first-run-password.txt` is written |
| LIGHTHOUSE_DEV | unset. Publishes the API schema and route table; workstation only, **never set in packaging** |
| LIGHTHOUSE_CORS_ORIGINS | unset. **Leave unset**: the dashboard is same-origin on loopback and needs no CORS |
| LIGHTHOUSE_SURICATA_PATH | `<install>\data\suricata\eve.json` (no network sensor on a copy that isn't installed); installer sets `<data>\suricata\eve.json` |
| LIGHTHOUSE_SYSMON_CHANNEL | `Microsoft-Windows-Sysmon/Operational` |
| LIGHTHOUSE_SECURITY_CHANNEL | `Security` |
| LIGHTHOUSE_EVENT_STATE_DIR | `<install>\data\state` (`.\state` on a copy that isn't installed; never ProgramData); installer sets `<data>\state` |
| LIGHTHOUSE_MODEL_BACKEND | `llama_cpp` (`ollama` is the Linux default) |
| LIGHTHOUSE_MODEL_PATH | unset; installer sets the GGUF path under `models` |
| LIGHTHOUSE_MODEL_CONTEXT_SIZE | `4096` tokens. *Developer only* |
| LIGHTHOUSE_MODEL_GPU_LAYERS | `0` (CPU only; see Local AI). *Developer only* |
| LIGHTHOUSE_GENAI_KEY_FILE | `<data>\config\genai-key.bin`: the DPAPI-encrypted Purdue GenAI Studio key (opt-in chat, `python -m triage.cloud_key set`; see README) |
| LIGHTHOUSE_GENAI_MODEL | the model saved with `cloud_key model` or chosen in Settings → Chat AI, else `gpt-oss:120b`. *Developer only*: on an install, choose the model in Settings |
| LIGHTHOUSE_MODEL_THREADS | automatic: one thread per physical core, skipping the separate low-power core island of hybrid laptop CPUs (Intel Core Ultra). Set `"ModelThreads": N` in `windows.json` and rerun setup to override; compare values with `python -m triage.local_model smoke-test --threads N` |
| LIGHTHOUSE_MODEL_SPECULATIVE | `1` (on): prompt-lookup speculative decoding, same answers sooner. `0` turns it off; compare with `python -m triage.local_model bench`. *Developer only* |
| LIGHTHOUSE_MODEL_STATE_DIR | unset (off); installer sets `<data>\cache\llm-state`. Where the API service keeps chat's already-read system prompt across restarts |
| LIGHTHOUSE_STATUS_READER_STALE_MINUTES | `10`: minutes without a check-in from the Sysmon or Security Event Log reader before the dashboard says that sensor is "Not reporting" (API service). *Developer only* |
| LIGHTHOUSE_STATUS_NETWORK_QUIET_MINUTES | `30`: minutes without a write to Suricata's `eve.json` before the dashboard says the network sensor is "Not reporting" (API service). *Developer only* |

The background triage service runs at below-normal CPU priority, so a chat the
owner is waiting on always gets the processor first. Chat keeps recent prompt
states in a 512 MB in-memory cache, so follow-up questions re-read only their new
words.

Every role sees whether LightHouse is watching (Home's health card and Settings →
Monitoring sources, from `GET /api/status`). Each sensor is Working, Not reporting,
Paused or Not installed, judged by "is its reader alive", never by alerts arriving:
a quiet network is not a failure. The network sensor is working while the Suricata
and ingestion services run and `eve.json` was written within the network limit
(Suricata logs flow and DNS records for ordinary background traffic, so a
connected computer's log changes within minutes). The Sysmon and Security sensors
are working while the ingestion service runs, the Sysmon service runs (Sysmon
only), and the reader's health file in `LIGHTHOUSE_EVENT_STATE_DIR` reports `ok`
within the reader limit; an idle reader checks in every 30 seconds, but not while
one alert is being triaged on a slow CPU, hence minutes. While monitoring is paused
all three say Paused. "Paused" means an admin paused it: both monitoring services
are stopped and set to manual start, which is what Pause does. Services that are
stopped but still set to start automatically (a crash, or Suricata failing at boot)
show as Not reporting instead. The page carries fixed sentences and times only, never paths,
service names or sensor text.

**Desktop alerts** (Settings, per user and per browser) come from the open
dashboard window, not from the services: those run in session 0 and can't reach
the desktop. While the window is open (even minimised), it polls
`GET /api/notifications` every 45 seconds. When an alert at or above the user's
notification threshold arrives, it shows a Windows notification with fixed wording,
never the alert's own text. Nothing is shown while the window is closed.

**User management** is server-side (Admin page; `PATCH /api/users/{id}/role`,
`PATCH /api/users/{id}/password`, `POST /api/users/{id}/sign-out`,
`DELETE /api/users/{id}`, admin only). A role change or password reset also ends
that user's sessions. The last admin can't be demoted or removed, nobody can remove
their own account, and the built-in `admin` can't be removed (setup would recreate
it with a new one-time password). Its role and password can still be changed.
`python -m triage.reset_password` (above) is the offline fallback.

**Chat model.** With a GenAI Studio key stored, an admin picks the default chat
model in Settings → Chat AI (Thinking, Balanced, Quick or Local (slow)). Anyone can
override it for one question with the picker beside Send, unless the default is
Local (slow). Alert triage always stays on the local model.

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
   (`"ok": true`) for the GGUF under `<data>\models`.
3. `<app>\runtime\Lib\site-packages\llama_cpp\lib`
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

## Current status

- The automated suite passes: run `python -m pytest` (backend, plus static and
  ACL/signature guard tests for the installer scripts in
  `tests/test_windows_installer.py` and `tests/windows_security.ps1`), and
  `npm test` and `npm run build` in `dashboard`. The tests check the scripts'
  structure and guards. They don't run setup.
- Releases are built with `build.ps1` and installed on a test VM by hand. The
  full clean-machine checklist above, including repair and upgrade, has not yet
  been run end to end on clean Windows 10 and Windows 11 machines.
- The free Npcap edition still needs its interactive wizard (see the top of this
  guide).
