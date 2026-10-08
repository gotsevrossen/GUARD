# LightHouse — Local AI Security Copilot

LightHouse gives a small business SOC-style security monitoring without needing a security background. It watches your network and your Windows computer, has an on-device AI read every alert, and shows a plain-English explanation and one concrete next step in a dashboard.

**Nothing leaves your machine.** The monitoring data, the alerts and the AI all stay on the computer LightHouse is installed on. There is no cloud service and no account to create.

LightHouse is a Windows application. The older Linux build is no longer maintained; see [Legacy: Linux and appliance deployments](#legacy-linux-and-appliance-deployments).

---

## Requirements

| | |
| --- | --- |
| **Windows** | Windows 10 22H2 or newer, or Windows 11. x64 only. |
| **Memory** | **8 GB of RAM.** The AI model needs about 3 GB on its own and Suricata about 1 GB, on top of Windows. With less, the services fail or stall. |
| **Virtual machines** | Give the VM a fixed **8192 MB** and **turn Dynamic Memory off** (Hyper-V: *Settings → Memory*). With Dynamic Memory, the AI model can fail to load because it needs its memory all at once. |
| **CPU** | x64 with **AVX2** for the local AI (most Intel CPUs from 2013 on, AMD Zen and later). Without AVX2, LightHouse still monitors and keeps every alert, marked for a person to review. |
| **Disk** | Several GB free. The AI model alone is about 2.5 GB. |
| **Internet** | **During setup only**, to download Suricata, Sysmon, Npcap, the detection rules, the Visual C++ runtime and the AI model. LightHouse does not need the internet afterwards. |
| **Rights** | An administrator account to install. |

---

## Installing

1. Download `LightHouse-Setup.exe` from the [Releases](../../releases) page.
2. *(Recommended)* Check the download matches the SHA256 in the release notes:
   ```powershell
   (Get-FileHash .\LightHouse-Setup.exe -Algorithm SHA256).Hash
   ```
3. Double-click it and approve the Windows administrator prompt.
4. **Npcap** (the packet-capture driver) opens its own setup wizard. Tick **WinPcap API-compatible mode** and finish it. This is the only screen you need to answer.
5. Wait. Setup installs the sensors and downloads the AI model, which can take a while on a slow connection.
6. On the last page, leave **Open the LightHouse dashboard** ticked and click **Finish**.

LightHouse runs in the background and starts with Windows, so there is nothing to launch. To open the dashboard again, use the **LightHouse Dashboard** shortcut on the desktop or in the Start menu, or go to `http://127.0.0.1:8000` in your browser.

### First sign-in

LightHouse creates an `admin` account with a random one-time password. There is no default password. To read it, open **PowerShell as administrator** and run:

```powershell
Get-Content "$env:ProgramData\LightHouse\first-run-password.txt"
```

Sign in as `admin` with that password. LightHouse then makes you choose your own (at least 12 characters) before anything else opens, and deletes the file.

Installed with an earlier version? The file won't exist; the password is in the dashboard's logs instead:

```powershell
Select-String -Path "$env:ProgramData\LightHouse\logs\LightHouse-API*" -Pattern 'password:'
```

Don't open the `ProgramData\LightHouse` folder in File Explorer and click **Continue** when it asks for permission. That permanently gives your Windows account access to LightHouse's protected data folder.

For a fully unattended install (no Npcap wizard), see [docs/windows-install.md](docs/windows-install.md).

### What gets installed

| Component | What it does |
| --- | --- |
| **Suricata + Npcap** | Watches network traffic for known attacks, using the free Emerging Threats rule set. |
| **Sysmon + Windows Security auditing** | Watches this computer: programs starting, sign-ins, accounts created, logs cleared. |
| **LightHouse services** | `LightHouse-API` (the dashboard), `LightHouse-Ingestion` (reads the sensors and runs the AI), `LightHouse-Suricata`. They start automatically with Windows. |
| **Local AI** | The Phi-4-mini model, run inside LightHouse. There is no separate AI program to install or manage. |
| **Visual C++ runtime** | Needed by the AI runtime. |

The dashboard listens on `127.0.0.1` only. Other computers on the network cannot reach it, and setup adds no firewall rule.

---

## How LightHouse decides what to tell you

Each alert gets two ratings, and together they decide how cautious LightHouse is.

**Severity** (low, medium, high, critical, or unknown) is how serious the activity could be. The sensor that raised the alert sets a minimum; the AI may raise severity but **can never lower it below what the sensor reported**. That holds even if an attacker plants text in the traffic to talk the AI down.

**Confidence** (high, medium or low) is how sure LightHouse is about its reading. The AI rates itself, then LightHouse's own checks can only lower it, never raise it. Confidence is lowered when:

- the alert comes from a rule LightHouse hasn't been tested against;
- the sensor recorded very little evidence;
- the AI rated the alert much more severe than the sensor did;
- the AI's explanation mentions an address or file that isn't in the alert (a sign it made something up);
- the AI's first answer was malformed and had to be retried;
- the AI wasn't available at all.

The dashboard shows both as text, for example **High severity · Low confidence**. They pick one of four messages, written by LightHouse rather than the AI, so nothing inside an alert can remove or soften them:

| Severity ↓ / Confidence → | High | Medium | Low |
| --- | --- | --- | --- |
| **Low** | standard | standard | double-check |
| **Medium** | standard | double-check | second opinion |
| **High** | double-check | second opinion | **get help now** |
| **Critical** | second opinion | **get help now** | **get help now** |
| **Unknown** | second opinion | second opinion | second opinion |

- **Standard:** the AI's explanation and recommended step.
- **Double-check:** the same, plus one thing to verify before acting.
- **Second opinion:** LightHouse isn't sure; have someone technical look before you change anything.
- **Get help now:** contact your IT provider or a security professional. LightHouse lists only safe things to do while you wait (don't delete anything, don't pay anyone who demands money, write down what you saw, disconnect the device if that's safe). Open alerts like this are shown first on Home and Alerts.

Analysts and admins also see why confidence was lowered, and what the AI said it couldn't work out, in the technical evidence view.

### Ask LightHouse (chat)

The chat box at the bottom of Home answers questions using the same on-device AI. Nothing is sent anywhere.

- **Ask about one alert:** open the alert and click **Ask LightHouse about this**. The chat is then linked to that alert, follow-up questions included.
- **Ask in general:** type in the box, or pick one of the common questions. LightHouse uses your most recent open alerts as context.
- **Chat names:** each new chat gets a short name, such as "Sysmon activity question", written by the AI once it has answered. Chats are kept only in this browser.
- **Speed:** the AI runs on your computer's processor, so an answer can take a minute or more. You can keep using the dashboard while you wait.
- **The AI can't overrule the warnings.** For a "get help now" or "second opinion" alert, LightHouse adds a fixed reminder above the AI's answer, so nothing written into an alert can talk you out of getting help.
- **Without AVX2, or if the AI isn't working,** the chat says so plainly. Monitoring carries on as normal.

The first question after a restart takes longer, while the AI loads.

### Roles

- **Owner:** plain-English alerts, trends and personal preferences.
- **Analyst:** everything an owner sees, plus technical evidence and health views.
- **Admin:** everything an analyst sees, plus user management.

Roles are enforced by the server. Hiding a tab in the dashboard is presentation, not access control.

---

## Running setup again, upgrading and uninstalling

**Running `LightHouse-Setup.exe` again** repairs or upgrades the install in place; it never makes a second copy. Your alerts, accounts, passwords and settings are kept, and the AI model is reused rather than downloaded again. If setup stopped partway, fix the cause it reports and run it again.

**Uninstalling** (Windows *Settings → Apps*) removes the LightHouse services and program files. It keeps your data in `C:\ProgramData\LightHouse` (alerts, accounts and the AI model). It also leaves Npcap, Suricata, Sysmon and the Visual C++ runtime installed, since other software may use them. Remove those separately if you want them gone.

---

## Troubleshooting

If setup ends with **"LightHouse setup is incomplete"**, the message includes the reason. For the full picture, open **PowerShell as administrator** and paste:

```powershell
$d = "$env:ProgramData\LightHouse"
$app = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' | Where-Object DisplayName -like 'LightHouse*').InstallLocation
"--- setup result";     Get-Content "$app\setup\last-result.txt"
"--- install.log";      Get-Content "$d\logs\install.log" -Tail 30
"--- services";         Get-Service LightHouse-* | Format-Table Name, Status -AutoSize
"--- suricata.log";     Get-Content "$d\suricata\suricata.log" -Tail 12
"--- ingestion errors"; Get-Content "$d\logs\LightHouse-Ingestion.stderr.log" -Tail 25 -ErrorAction SilentlyContinue
"--- crashes";          Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='Application Error'; StartTime=(Get-Date).AddMinutes(-30)} -MaxEvents 3 -ErrorAction SilentlyContinue | Format-List TimeCreated, Message
"--- memory";           "{0:N1} GB RAM" -f ((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB)
```

"Access is denied" means the window isn't running as administrator. LightHouse's data folder is restricted to administrators on purpose.

| Symptom | Likely cause and fix |
| --- | --- |
| `The remote name could not be resolved: '...'` | No internet or DNS during setup. Check with `Test-NetConnection aka.ms -Port 443`. On a VM, give it a network switch with internet access (Hyper-V: *Default Switch*), wait a minute after it boots, then rerun setup. |
| `LightHouse-Ingestion is not running` | Check `ingestion errors` above. If memory shows under 8 GB, or it changes between runs (Dynamic Memory), fix the memory first. |
| `Free Npcap cannot install silently` | A silent install was attempted without Npcap. Install Npcap first, or run setup normally to get its wizard. |
| `Cannot read required Event Log channels` | Setup must run as administrator, and Sysmon must be installed (setup does this). |
| `Visual C++ runtime ... restart Windows` | Restart Windows, then rerun setup. |
| `The local AI model failed its self-test` | Usually not enough memory, or a damaged model download. Fix the memory, then rerun setup (a damaged download is fetched again). |

Some Emerging Threats rules use features the Windows build of Suricata lacks. Setup switches off exactly those rules, lists them in `C:\ProgramData\LightHouse\rules\disabled-by-lighthouse.txt`, and keeps the rest. A handful there is normal.

More detail, including every file location and setting, is in [docs/windows-install.md](docs/windows-install.md).

---

## Building from source

On Windows, in PowerShell, with Python 3.11+, [uv](https://docs.astral.sh/uv/) and Node.js:

```powershell
uv sync                                  # backend dependencies (or: pip install -e '.[dev]')
python -m pytest                         # backend tests
python -m triage.main replay --mock      # fill a demo database from samples/ without a model

cd dashboard; npm ci; npm run build      # dashboard -> dashboard/dist

# The installer (needs an AVX2 CPU and the Visual C++ runtime on the build machine)
powershell -NoProfile -ExecutionPolicy Bypass -File packaging/windows/build.ps1   # -> dist/LightHouse-Setup.exe
```

For dashboard work with hot reload:

```powershell
$env:LIGHTHOUSE_DEV=1; uvicorn triage.api:app --reload --host 127.0.0.1 --port 8000
cd dashboard; npm run dev                # http://localhost:5173, proxies /api
```

`LIGHTHOUSE_DEV` publishes the API schema and route table, so only use it on a development machine; it is never set by the installer. Both servers stay on loopback.

Use `npm ci`, not `npm install`: it installs exactly the reviewed `dashboard/package-lock.json` tree. That lockfile and `uv.lock` are committed on purpose. Review changes to them as you would review code.

### Architecture

- **LightHouse-API:** FastAPI on `127.0.0.1:8000`, serving `/api/*` and the built dashboard from the same origin.
- **LightHouse-Ingestion:** tails Suricata's `eve.json` and the Sysmon and Security event logs, deduplicates alerts, runs the local AI, applies the severity floor and confidence checks, and stores the result in SQLite.
- **LightHouse-Suricata:** packet capture on the network adapter chosen at install.

Sensor data is treated as attacker-controlled. Only a short, length-capped extract of each alert reaches the AI, fenced off as untrusted evidence, and the AI's answer is validated before it is stored. Settings live in `C:\ProgramData\LightHouse\config\windows.json`; see [docs/windows-install.md](docs/windows-install.md).

### Known gaps

- Clean-machine install, repair and upgrade testing is still in progress.
- The free Npcap edition can't install silently, so a fully unattended install needs Npcap preinstalled or its OEM installer.
- `samples/` are format-faithful starters, not captured real-world events.

See `docs/implementation-log.md`, `docs/missing-information.md` and `docs/backend-completion-requirements.md` for implementation status and open decisions.

---

## Legacy: Linux and appliance deployments

> **No longer maintained.** LightHouse is now Windows-only. The Linux `.deb` build, its Ollama model runner and the hardware appliance deployment below are kept for reference only. They are not updated or tested, and do not include the confidence and guidance features above.

### Installing (Ubuntu 22.04 LTS or 24.04 LTS)

Download `lighthouse_0.1.0_amd64.deb`, then either double-click it in Files, or run:

```
sudo apt install ./lighthouse_0.1.0_amd64.deb
```

That single step installs the application, installs and configures the sensors it reads (Suricata, Zeek, the Wazuh manager) and the local AI model runner (Ollama), detects your actual local network, creates the background monitoring service, and adds LightHouse to your applications menu. It takes a while the first time, mostly downloading the AI model.

Then open **LightHouse** from your applications menu. On the very first launch it shows you a one-time administrator password; write it down, sign in with it, and LightHouse immediately asks you to choose your own.

That is the whole install. There is no terminal step, no config file to edit, and no password to go hunting for in a log.

#### What gets installed

| Component | Purpose |
| --- | --- |
| Suricata | Network intrusion detection, configured for your real local subnet |
| Zeek | Network traffic analysis, set to emit JSON |
| Wazuh manager | Host security monitoring. The CVE feed and the OpenSearch indexer are switched off — they are a multi-gigabyte download that duplicates what LightHouse already shows you |
| Ollama | Runs the AI model locally. Model size is chosen from your hardware (GPU, RAM) |
| `lighthouse.service` | The background monitoring service, started at boot |

#### Monitoring runs whether the window is open or not

The window is a **viewer**, not the product. Closing it does not stop protection — `lighthouse.service` keeps reading your sensors and triaging alerts from boot onwards, and the window simply shows you what it found.

```
systemctl status lighthouse     # is monitoring running?
journalctl -u lighthouse -f     # what is it doing?
```

**Known limitation.** Unlike a dedicated always-on appliance, this runs on a computer you also use for other things. When it is asleep, shut down, or off the network, it is not monitoring. The "continuous" in continuous monitoring is bounded by how often the machine is actually on. If you need genuinely uninterrupted coverage, see the appliance deployment at the end of this document.

#### Uninstalling

```
sudo apt remove lighthouse    # removes the app, keeps your alert history
sudo apt purge  lighthouse    # removes the alert history and credentials too
```

Neither removes Suricata, Zeek, Wazuh, or Ollama — they are ordinary packages and may be in use by something else. Remove them explicitly if you want them gone.

#### Building the package

On **Ubuntu 22.04**, not 24.04: the bundled binary links against the build machine's glibc, and a 22.04 build runs on 24.04 while the reverse does not.

```
sudo apt install python3-pip nodejs npm dpkg-dev
pip install -e '.[desktop,dev]'
./packaging/build-deb.sh
```

This builds the dashboard with `npm ci`, bundles the backend with PyInstaller, and assembles `build/lighthouse_0.1.0_amd64.deb`.

`npm ci` and not `npm install`: it installs exactly the reviewed `dashboard/package-lock.json` tree and nothing newer. That lockfile is committed, and it matters here more than it does in most projects — npm runs dependency install scripts as the building user, and this build output is embedded in a package that installs with root privileges on somebody else's computer. Review lockfile changes as you would review code.

#### Running from source

You do not need to build a package to work on it:

```
pip install -e '.[desktop,dev]'
cd dashboard && npm ci && npm run build && cd ..
python -m triage.desktop
```

The desktop entry point checks whether a LightHouse service is already answering on `127.0.0.1:8000`. If one is, it opens a window onto it; if not, it starts the API itself in a background thread. It never enables `--reload` or `LIGHTHOUSE_DEV` — the desktop build behaves like production always.

For frontend work, the Vite dev server with hot reload is faster:

```
LIGHTHOUSE_DEV=1 uvicorn triage.api:app --reload --host 127.0.0.1 --port 8000
cd dashboard && npm run dev
```

Vite serves the dashboard on `http://localhost:5173` and proxies `/api` to `127.0.0.1:8000`. Both stay on loopback. `LIGHTHOUSE_DEV` publishes the schema and the route table, so it is a workstation-only setting.

Run the tests with `python -m pytest`.

#### Architecture

The desktop build is a single process doing two jobs:

- **The API** — FastAPI on `127.0.0.1:8000`, serving both `/api/...` and the built dashboard from the same origin.
- **Ingestion** — the sensor log tails, running as a background `asyncio` task inside the API's lifespan.

Folding ingestion into the API process means one service to install and one to supervise, rather than two that can fail independently on a machine with nobody watching. The cost is that they now share a process, so the ingestion task is deliberately isolated: it catches everything below `CancelledError` and logs it. A parsing bug in a sensor record leaves you with a degraded install; letting it escape would leave you with an application you cannot even log in to.

The appliance deployment keeps the original two-process split — see below.

**Loopback only.** The API is never exposed on the LAN, there is no TLS termination, and there is no reverse proxy. There is nothing to expose: it listens on `127.0.0.1` and the window connects to it locally. LAN access is what the appliance deployment is for.

#### Configuration

Set in `/etc/lighthouse/lighthouse.env` by the installer. You will not normally edit these.

| Variable | Default | Purpose |
| --- | --- | --- |
| `LIGHTHOUSE_DESKTOP` | unset | Selects desktop behavior: per-user data directory, in-process ingestion, first-run password handoff. Implied by a bundled build. |
| `LIGHTHOUSE_DB_PATH` | `~/.local/share/lighthouse/lighthouse.db` (desktop), `lighthouse.db` (appliance) | SQLite database, WAL mode. Holds password hashes and live session tokens; the directory is created `0700`. |
| `LIGHTHOUSE_FIRST_RUN_DIR` | the data directory | Where the one-time admin password is handed from the service to the window. The package points this at `/var/lib/lighthouse/handoff` (`0750`, group `lighthouse`), because service and window run as different accounts. |
| `LIGHTHOUSE_STATIC_DIR` | `dashboard/dist` under the bundle or working directory | Built dashboard, mounted at `/` when present. |
| `LIGHTHOUSE_MODEL_BACKEND` | `ollama` (Linux), `llama_cpp` (Windows) | Local model runtime. `llama_cpp` runs a GGUF file in-process and also needs `LIGHTHOUSE_MODEL_PATH`; see the Windows guide. |
| `LIGHTHOUSE_MODEL` | chosen by hardware at install | Local Ollama model used for triage. |
| `LIGHTHOUSE_PORT` | `8000` | Loopback port for the API. |
| `LIGHTHOUSE_SURICATA_PATH` | `/var/log/suricata/eve.json` | Suricata `eve.json` to tail. |
| `LIGHTHOUSE_ZEEK_PATH` | `/opt/zeek/logs/current/conn.log` | Zeek JSON log to tail. |
| `LIGHTHOUSE_WAZUH_PATH` | `/var/ossec/logs/alerts/alerts.json` | Wazuh alert JSON to tail. |
| `LIGHTHOUSE_CORS_ORIGINS` | empty | Extra browser origins. Leave empty: same-origin needs none. |
| `LIGHTHOUSE_DEV` | unset | Development conveniences. Never set outside a workstation. |

#### First sign-in, in detail

On first start LightHouse generates a random administrator password and does two things with it: prints it once to stdout (which lands in the systemd journal), and — in desktop mode only — writes it to a one-time file that the window reads, displays, and deletes. It is stored only as a bcrypt hash.

Signing in with it forces a password change before anything else renders; every request except login, logout, and the password change itself is refused until it is replaced. The new password must be at least 12 characters. There is no default credential. If the generated one is lost before it is changed, the admin account has to be re-provisioned against the database.

If the window never showed you a password, it is still in the journal:

```
sudo journalctl -u lighthouse --no-pager | grep -A3 "administrator account"
```

### Alternative: hardware appliance deployment

**This is not the default deployment, and most readers should stop here.** It describes running LightHouse as a dedicated always-on box on a customer network, reachable from other machines over the LAN — the original deployment model, kept because it is real working knowledge and because it solves the always-on limitation the desktop app has.

It is a fundamentally different security posture: the desktop app is loopback-only and has no network attack surface, while this one is exposed on the LAN and therefore *requires* TLS in front of it. Do not mix the two sets of instructions.

#### What you need on the appliance

- A Linux machine or VM (Ubuntu 24.04 LTS is a practical default) with Python 3.11+.
- Ollama on `http://localhost:11434` with `qwen3:8b` pulled.
- nginx or Caddy on the appliance to terminate TLS. LightHouse itself speaks plain HTTP on loopback only.
- Node 20+ **on the machine that builds the dashboard**. The appliance needs no Node at runtime — it serves static files.

#### 1. Install the backend

```
python -m venv .venv && . .venv/bin/activate
pip install -e .
```

Use `pip install -e '.[dev]'` to also run the test suite.

#### 2. Build the dashboard

```
cd dashboard
npm ci
npm run build
```

`npm run build` writes to `dashboard/dist`. Nothing from `dashboard/` other than `dist/` needs to reach the appliance: build on a workstation, copy the directory across (`rsync -a dashboard/dist/ appliance:/opt/lighthouse/dashboard/dist/`), and point `LIGHTHOUSE_STATIC_DIR` at it. Build output is deliberately not committed.

#### 3. Seed the demo database (optional)

```
python -m triage.main replay --mock
```

Fills the database from `samples/` without calling a model. Skip on a real deployment.

#### 4. Run the API on loopback

```
uvicorn triage.api:app --host 127.0.0.1 --port 8000
```

No `--reload`: it is a development file-watcher, it doubles the process count, and it re-executes application code on any file change.

`LIGHTHOUSE_DESKTOP` is left unset here, so the API does **not** start ingestion — that stays a separate process on the appliance (step 7).

#### 5. Terminate TLS in front of it

Publish only 443 on the LAN and proxy to `127.0.0.1:8000`. Session tokens are bearer tokens valid for eight hours; without TLS both the login POST and every later request carry them across the customer network in cleartext.

nginx:

```
server {
    listen 443 ssl;
    server_name lighthouse.lan;
    ssl_certificate     /etc/ssl/lighthouse/fullchain.pem;
    ssl_certificate_key /etc/ssl/lighthouse/privkey.pem;
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Caddy needs one line: `lighthouse.lan { reverse_proxy 127.0.0.1:8000 }`.

Never expose uvicorn directly, and never run the Vite dev server on the customer network — `--host 0.0.0.0` on a dev server publishes unminified sources, source maps, and an unauthenticated module endpoint.

#### 6. Run it under systemd

`/etc/systemd/system/lighthouse.service`:

```
[Unit]
Description=LightHouse local security copilot
After=network-online.target

[Service]
User=lighthouse
Group=lighthouse
WorkingDirectory=/opt/lighthouse
Environment=LIGHTHOUSE_DB_PATH=/var/lib/lighthouse/lighthouse.db
Environment=LIGHTHOUSE_STATIC_DIR=/opt/lighthouse/dashboard/dist
Environment=LIGHTHOUSE_MODEL=qwen3:8b
ExecStart=/opt/lighthouse/.venv/bin/uvicorn triage.api:app --host 127.0.0.1 --port 8000
Restart=on-failure
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/lighthouse

[Install]
WantedBy=multi-user.target
```

Keep the database directory readable only by the service account: it holds password hashes, live session tokens, and raw alert payloads.

#### 7. Live ingestion, as a second unit

Set `LIGHTHOUSE_SURICATA_PATH`, `LIGHTHOUSE_ZEEK_PATH`, and `LIGHTHOUSE_WAZUH_PATH` to the JSON-line log paths, then run:

```
python -m triage.main tail
```

Zeek must be configured to emit JSON (`LogAscii::use_json=T`). The service account needs read access to each file *and its directory*, so log rotation does not silently stop ingestion.

#### First sign-in on the appliance

The generated admin password reaches the journal, not a window:

```
sudo journalctl -u lighthouse --no-pager | grep -i password
```
