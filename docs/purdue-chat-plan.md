# Purdue GenAI Studio chat (option A): plan and progress

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

- [x] 8. Admin page "Chat AI" picker (admin only): GPT-OSS 120B, Gemma 4 26B,
      Llama 3.3 70B, Llama 4, or "On this computer only". `GET /api/chat/models`,
      `PUT /api/chat/model` (curated list only, 409 without a key), applies on the
      next question without a restart. Tests in `tests/test_cloud_chat.py`.

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
      `<dialog>` on every load when newer: "Download update" opens the release page
      (only that repo's releases URL), "Later" dismisses until the next load.
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
Speed pass (14) added: flash attention with fallback, chat model preload + pre-read 30 s after the API starts (skipped when GenAI Studio answers or monitoring is paused), ingestion model preload at start, shorter triage reasoning. Not done on purpose: prompt-lookup speculative decoding (gain unproven on CPU), quantized KV cache / Q4_0 model (small accuracy cost).

## Also uncommitted from before this plan

Warm-up while typing, shorter answers (300 tokens), Zeek/Wazuh wording replaced
by Suricata/Sysmon/Windows Security. Chat and confidence tests passed; the full
suite and dashboard build were interrupted and still need a run.

## Where work stopped

2026-10-08: all code steps done and tested; nothing committed yet (this work plus
the earlier warm-up/shorter-answers/Zeek-Wazuh changes). Remaining, for the owner:
run `packaging\windows\dev-update.ps1` as administrator, then
`runtime\python.exe -m triage.cloud_key set` and `Restart-Service LightHouse-API -Force` (then `Start-Service LightHouse-Ingestion`),
and check chat answers and the footer. Model choice: see
https://docs.rcac.purdue.edu/services/genai/models/ (default `gpt-oss:120b`).
