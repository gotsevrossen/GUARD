"""Health of native Event Log readers, shared by the service, API and installer."""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
from pathlib import Path
import sys
import time

logger = logging.getLogger(__name__)


def state_directory() -> Path:
    return Path(os.getenv('LIGHTHOUSE_EVENT_STATE_DIR') or
                Path(os.getenv('PROGRAMDATA', r'C:\ProgramData')) / 'LightHouse' / 'state')


def channel_filename(channel: str) -> str:
    """One channel-to-name mapping for both checkpoint and health files."""
    return hashlib.sha256(channel.encode()).hexdigest()[:20] + '.json'


def write_json(path: Path, value) -> None:
    """Replace atomically so readers never see a partial document."""
    temporary = path.with_suffix('.tmp')
    with temporary.open('w', encoding='utf-8') as handle:
        handle.write(json.dumps(value))
        # Without this, a hard reset can commit the rename before the data and
        # leave an empty file behind (seen on a Hyper-V VM).
        handle.flush()
        os.fsync(handle.fileno())
    temporary.replace(path)


def report(directory, channel, status) -> bool:
    """Best effort: a failed health write must never stop the reader itself."""
    path = Path(directory) / 'health'
    try:
        path.mkdir(parents=True, exist_ok=True)
        write_json(path / channel_filename(channel), {'channel': channel, 'status': status,
                                                     'checked_at': time.time(), 'pid': os.getpid()})
        return True
    except OSError as error:
        # Windows refuses the replace while another process has the file open.
        logger.warning('Could not record %s health for %s: %s', status, channel, error)
        return False


class ChannelHealth:
    """Throttled status for one reader.

    A changed status is written at once. An unchanged one is refreshed well
    inside snapshot's max_age instead of on every poll. A failed write is
    retried on the next call.
    """

    def __init__(self, directory, channel, refresh_seconds=30):
        self.directory, self.channel, self.refresh_seconds = directory, channel, refresh_seconds
        self.status = None
        self._written = None
        self._written_at = 0.0

    def set(self, status):
        self.status = status
        now = time.monotonic()
        if status != self._written or now - self._written_at >= self.refresh_seconds:
            if report(self.directory, self.channel, status):
                self._written, self._written_at = status, now


def snapshot(directory=None, channels=None, *, since=0, max_age=240):
    if channels is None:
        from .windows import configured_channels
        # Event Log readers only run on Windows; elsewhere none are expected.
        channels = configured_channels() if sys.platform == 'win32' else []
    directory = Path(directory) if directory is not None else state_directory()
    results = {}
    now = time.time()
    for channel in channels:
        path = directory / 'health' / channel_filename(channel)
        try:
            value = json.loads(path.read_text(encoding='utf-8'))
            checked = float(value['checked_at'])
            status = value['status']
            if value['channel'] != channel or not (max(since, now - max_age) <= checked <= now + 5):
                status = 'stale'
        except (OSError, ValueError, KeyError, TypeError):
            status = 'unavailable'
        results[channel] = status
    return {'ok': all(value == 'ok' for value in results.values()), 'channels': results}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--preflight', action='store_true')
    parser.add_argument('--state-dir', type=Path)
    parser.add_argument('--since', type=float, default=0)
    args = parser.parse_args()
    if args.preflight:
        from .windows import EventLogReader, configured_channels
        for channel in configured_channels():
            # Access denied, missing channel and disabled channel are fatal.
            EventLogReader(channel).read('*', True, 1)
        print('Event Log channel access verified')
    else:
        result = snapshot(args.state_dir, since=args.since)
        print(json.dumps(result))
        raise SystemExit(0 if result['ok'] else 1)


if __name__ == '__main__':
    main()
