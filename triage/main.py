from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

from .db import Database, default_db_path
from .ingest import parse_record, tail_json_lines
from .llm import DEFAULT_OLLAMA_MODEL, FixtureTriageModel, OllamaTriageModel, TriageModel, model_backend
from .schema import Source
from .service import TriageService

# The live log file for each sensor, as documented in the README.
SOURCE_ENV_VARS: dict[Source, str] = {
    Source.SURICATA: "LIGHTHOUSE_SURICATA_PATH",
    Source.ZEEK: "LIGHTHOUSE_ZEEK_PATH",
    Source.WAZUH: "LIGHTHOUSE_WAZUH_PATH",
}


def build_model(mock: bool) -> TriageModel:
    if mock:
        return FixtureTriageModel()
    if model_backend() == "llama_cpp":
        # Imported only when selected: the Linux builds do not install llama.cpp.
        from .local_model import LlamaCppSettings, LlamaCppTriageModel
        return LlamaCppTriageModel(LlamaCppSettings.from_env())
    return OllamaTriageModel(os.getenv("LIGHTHOUSE_MODEL", DEFAULT_OLLAMA_MODEL),
                             os.getenv("LIGHTHOUSE_OLLAMA_URL", "http://localhost:11434"))


def build_service(mock: bool) -> TriageService:
    service = TriageService(Database(default_db_path()), build_model(mock))
    service.db.initialize()
    # The admin's "About this business" note, saved by the API process into the same
    # database, read per alert (see TriageModel.triage_system_prompt). The answer
    # style note is chat-only and deliberately not wired here.
    service.model.business_context = lambda: service.db.ai_instructions()["business"]
    return service


def configured_sources() -> dict[Source, Path]:
    """Sensors with a path set. Anything unset is simply not ingested."""
    configured: dict[Source, Path] = {}
    for source, variable in SOURCE_ENV_VARS.items():
        if sys.platform == "win32" and source is not Source.SURICATA:
            continue
        value = (os.getenv(variable) or "").strip()
        if sys.platform == "win32" and source is Source.SURICATA and variable not in os.environ:
            # Windows is not always on C:.
            value = os.path.join(os.getenv("SystemDrive", "C:") + "\\", "Suricata", "log", "eve.json")
        if value:
            configured[source] = Path(value)
    return configured


async def replay(mock: bool) -> None:
    service = build_service(mock)
    for path in Path("samples").glob("*.jsonl"):
        source = Source(path.stem)
        for line in path.read_text(encoding="utf-8").splitlines():
            alert_id, duplicate = await service.process(parse_record(source, json.loads(line)))
            print(f"{'suppressed duplicate' if duplicate else 'triaged'}: {path.name} -> {alert_id}")


async def _tail_source(service: TriageService, source: Source, path: Path) -> None:
    print(f"tailing {source}: {path}", flush=True)
    try:
        reader = tail_json_lines
        if sys.platform == "win32":
            from .ingest.windows import tail_windows_json_lines
            reader = tail_windows_json_lines
        async for alert in reader(path, source):
            try:
                alert_id, duplicate = await service.process(alert)
            except Exception as error:  # one bad record must not stop the sensor
                print(f"error: {source} record could not be triaged: {error}", file=sys.stderr, flush=True)
                continue
            print(f"{'suppressed duplicate' if duplicate else 'triaged'}: {source} -> {alert_id}", flush=True)
    except asyncio.CancelledError:
        raise
    except OSError as error:
        print(f"error: stopped tailing {path}: {error}", file=sys.stderr, flush=True)


def unreadable_sources(configured: dict[Source, Path]) -> list[str]:
    """Describe every configured sensor log that cannot actually be read.

    Returned rather than raised so the API lifespan can log the problem and keep
    serving, while the CLI can still treat it as a startup failure.
    """
    unreadable = []
    for source, path in configured.items():
        if not path.is_file():
            unreadable.append(f"{SOURCE_ENV_VARS[source]}={path} (not a readable file)")
        else:
            try:
                with path.open(encoding="utf-8"):
                    pass
            except OSError as error:
                unreadable.append(f"{SOURCE_ENV_VARS[source]}={path} ({error.strerror or error})")
    return unreadable


async def run_ingestion(service: TriageService, configured: dict[Source, Path]) -> None:
    """Tail every given sensor log until cancelled.

    Takes an already-built service and an already-validated source map so the
    same loop serves the `tail` CLI and the desktop build's in-process background
    task without either one duplicating setup or error handling.
    """
    tasks = [asyncio.create_task(_tail_source(service, source, path), name=str(source))
             for source, path in configured.items()]
    # Load the model now, not when the first alert arrives; it waits its turn on
    # the model lock, so it never delays an alert that gets there first.
    tasks.append(asyncio.create_task(service.model.preload(), name="model-preload"))
    if sys.platform == "win32":
        from .ingest.windows import configured_channels, tail_channel
        tasks.extend(asyncio.create_task(tail_channel(service, channel), name=channel)
                     for channel in configured_channels())
    try:
        await asyncio.gather(*tasks)
    finally:
        # Reached on Ctrl+C as well: stop every tail before the loop closes.
        for task in tasks:
            task.cancel()
        try:
            await asyncio.gather(*tasks, return_exceptions=True)
        except asyncio.CancelledError:
            # Already shutting down; the cancellations above are what matter.
            pass


async def tail(mock: bool) -> None:
    """Follow every configured sensor log at once and triage each new record."""
    configured = configured_sources()
    from .ingest.windows import configured_channels
    windows_channels = configured_channels() if sys.platform == "win32" else []
    if not configured and not windows_channels:
        raise SystemExit("No sensor log paths configured. Set at least one of: " + ", ".join(SOURCE_ENV_VARS.values()))
    unreadable = unreadable_sources(configured)
    if unreadable and sys.platform != "win32":
        raise SystemExit("Cannot read configured sensor log: " + "; ".join(unreadable))
    await run_ingestion(build_service(mock), configured)


def cli() -> None:
    parser = argparse.ArgumentParser(prog="python -m triage.main")
    sub = parser.add_subparsers(dest="command", required=True)
    replay_parser = sub.add_parser("replay", help="triage the bundled sample files")
    replay_parser.add_argument("--mock", action="store_true", help="use the fixture model instead of the local model")
    tail_parser = sub.add_parser("tail", help="follow the configured live sensor logs")
    tail_parser.add_argument("--mock", action="store_true", help="use the fixture model instead of the local model")
    args = parser.parse_args()
    try:
        if args.command == "replay":
            asyncio.run(replay(args.mock))
        elif args.command == "tail":
            asyncio.run(tail(args.mock))
    except KeyboardInterrupt:
        print("\nStopped.", flush=True)


if __name__ == "__main__": cli()
