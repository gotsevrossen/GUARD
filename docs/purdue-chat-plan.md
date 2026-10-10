# Purdue GenAI Studio chat (option A): plan and progress

> **Done: shipped in v0.3.1.** Kept as a record of how it was built. Only item 15
> below is still open. The current behaviour is described in the README and
> `docs/windows-install.md`.

Chat answers come from Purdue GenAI Studio (`gpt-oss:120b`) when an API key is set;
alert triage stays local. Purdue failures fall back to the local model. Approved by
the owner on 2026-10-08, including the privacy change: "alerts stay on this
computer; chat goes to Purdue GenAI Studio when you turn it on".

API facts (https://docs.rcac.purdue.edu/services/genai/api/): base
`https://genai.rcac.purdue.edu`, `POST /api/chat/completions` (OpenAI format,
`"stream": true` gives SSE `data: {...}` lines), `GET /api/models`,
`Authorization: Bearer <key>`, 20 requests/min/user, over-limit may return JSON
`null`, allow 120 s. Measured: 1.8 s for a full short answer.

## Steps

- [x] 1. `triage/cloud_key.py`: DPAPI (machine scope + app entropy) key file at
      `<install>\data\config\genai-key.bin` (admin/SYSTEM-only folder). CLI:
      `python -m triage.cloud_key set|clear|status` (hidden prompt, never echoes).
      Path from `LIGHTHOUSE_GENAI_KEY_FILE`, else `<runtime python>\..\data\config`.
- [x] 2. `triage/cloud_model.py` (+ `cloud_key model <name>` saves the model choice in `genai.json`): `PurdueChatModel(TriageModel)` wrapping the local
      model. `triage`/`warm` go local; `chat`/`chat_stream` go to Purdue (fixed host,
      HTTPS, no redirects, 120 s), fall back to local before the first piece on
      any failure (401/429/5xx/null/network); 60 s cool-down after a rate limit.
      Key never logged or returned. Model from `LIGHTHOUSE_GENAI_MODEL`
      (default `gpt-oss:120b`).
- [x] 3. `triage/api.py`: `chat_model()` wraps the local model when a key exists;
      `GET /api/chat/provider` -> `{"provider": "purdue"|"local"}`.
- [x] 4. Dashboard: footer says "Answers by Purdue GenAI Studio (online). Alerts stay
      on this computer." when provider is purdue.
- [x] 5. Tests (13 passing) (`tests/test_cloud_chat.py`): key round trip, SSE parsing, fallback
      cases, no redirect, key never in logs/API, provider route.
- [x] 6. Docs: README optional section, `docs/windows-install.md`, CLAUDE.md privacy
      rule (owner approved).
- [x] 7. Run `python -m pytest` (292 passed), `npm run build`, `npm test` (14 passed); then the owner applies
      it with `packaging\windows\dev-update.ps1` and runs
      `runtime\python.exe -m triage.cloud_key set` as administrator.

- [x] 8. "Chat AI" default-model picker on the **Settings** page (admin only):
      **Thinking** (GPT-OSS 120B), **Balanced** (Llama 4), **Quick** (Gemma 4 26B)
      or **Local (slow)**. `GET /api/chat/models`, `PUT /api/chat/model` (curated
      list only, 409 without a key), applies on the next question without a
      restart. Plus a per-question picker beside the chat box's Send button, for
      everyone, while the default is an online model (it offers no online models
      while the default is Local (slow)). Tests in `tests/test_cloud_chat.py`.

## Next batch (requested 2026-10-08)

- [x] 9. Pause/resume monitoring (admin only): `triage/monitoring.py` stops
      LightHouse-Ingestion and LightHouse-Suricata and sets them to manual start
      (so a reboot keeps them off), unloads the chat AI; resume restores automatic
      start and starts them. The API service stays up so the dashboard can turn it
      back on. Routes `GET/POST /api/monitoring`. Home shows the state; admins get
      the button.
- [x] 10. Words beside the chat loader: rotating, lighthouse-themed status lines
      ("Reading your alerts…", "Asking Purdue GenAI Studio…", "Charting safe
      waters…"), first line depends on the provider/alert.
- [x] 11. Update check: `triage/updates.py` asks GitHub for the latest release of
      gotsevrossen/LightHouse (cached 15 min, no monitoring data sent), compares with
      the installed version; `GET /api/updates` (admin). Dashboard pops up a native
      `<dialog>` on every load when newer. **Update now** downloads the release's
      installer, checks it against the release's SHA-256 file and installs it
      silently through a one-time SYSTEM scheduled task (`POST /api/updates/install`);
      **Open release page** is the fallback, and "Later" dismisses until the next load.
- [x] 12. Tests, docs, full suite + dashboard build.
- [x] 13. Remove the static green dot above finished LightHouse replies (only the
      animated loader shows while thinking).

- [x] 14. More local speed without quality loss: flash attention (fall back if the
      build rejects it), load the model in the background when the API starts,
      prompt-lookup speculative decoding (lossless), larger prompt batch.
- [ ] 15. Owner idea: "Purdue fills in for a second before the local AI takes
      over" — e.g. Purdue answers while the local model is still loading. Conflicts
      with "On this computer only"; needs the owner's choice of when it applies.

Progress: 9-14 done: full suite 309+ passing, dashboard builds; docs updated. 15 is explained to the owner (not built: it conflicts with "On this computer only").
Speed pass (14) added: flash attention with fallback, chat model preload + pre-read 30 s after the API starts (skipped when GenAI Studio answers or monitoring is paused), ingestion model preload at start, shorter triage reasoning, and prompt-lookup speculative decoding (lossless; on by default, `LIGHTHOUSE_MODEL_SPECULATIVE=0` turns it off). Not done on purpose: quantized KV cache / Q4_0 model (small accuracy cost).

## Status

Everything above except item 15 shipped in v0.3.1 (warm-up while typing, shorter
answers and the Suricata/Sysmon/Windows Security wording included) and has been
committed since. Item 15 remains an open idea for the owner to decide on.
