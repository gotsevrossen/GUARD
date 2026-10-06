"""Disable the individual ET Open rules the installed Suricata cannot parse.

Suricata's -T configuration test treats any rule that fails to load as fatal. ET
Open publishes one ruleset per engine series and ships new rules daily, some using
keywords the Windows build lacks (file.magic needs libmagic, which it is built
without). Nine such rules out of ~52,000 must not stop the install, so the rules
that failed by sid are commented out and the test is run again.

Only rule parse failures are handled. A configuration error leaves no failing sid,
so this exits non-zero and the installer stops as before. Too many failures means
the ruleset does not match the engine at all, which also stops the install rather
than silently running with a gutted ruleset.

    python disable_failed_rules.py <rules file> <report file> <suricata log>...
Exit codes: 0 rules disabled, 2 no rule failures found, 3 too many failures.
"""
from __future__ import annotations

from pathlib import Path
import re
import sys

MAX_DISABLED = 100
DISABLED_PREFIX = "# Disabled by LightHouse: not supported by the installed Suricata engine. "
_FAILED = re.compile(r'error parsing signature ".*?\bsid\s*:\s*(\d+)\s*;')
_SID = re.compile(r"\bsid\s*:\s*(\d+)\s*;")


def failed_sids(log_text: str) -> list[str]:
    return list(dict.fromkeys(_FAILED.findall(log_text)))


def disable(rules_path: Path, sids: set[str]) -> list[str]:
    """Comment out active rules with these sids. Returns the disabled rule lines."""
    lines = rules_path.read_text(encoding="utf-8", errors="surrogateescape").splitlines(keepends=True)
    disabled = []
    for index, line in enumerate(lines):
        stripped = line.lstrip()
        if not stripped or stripped.startswith("#"):
            continue
        match = _SID.search(line)
        if match and match.group(1) in sids:
            lines[index] = DISABLED_PREFIX + line
            disabled.append(line.strip())
    rules_path.write_text("".join(lines), encoding="utf-8", errors="surrogateescape")
    return disabled


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        print(__doc__, file=sys.stderr)
        return 2
    rules_path, report_path, logs = Path(argv[0]), Path(argv[1]), [Path(p) for p in argv[2:]]
    text = "\n".join(log.read_text(encoding="utf-8", errors="replace") for log in logs if log.is_file())
    sids = failed_sids(text)
    if not sids:
        print("Suricata failed without a rule parse error; this is a configuration problem.")
        return 2
    if len(sids) > MAX_DISABLED:
        print(f"{len(sids)} rules failed to load (limit {MAX_DISABLED}); the ruleset does not match this Suricata.")
        return 3
    disabled = disable(rules_path, set(sids))
    if not disabled:
        print(f"Failed sids {', '.join(sids)} are not active rules in {rules_path}; nothing to disable.")
        return 2
    report_path.write_text("".join(f"{rule}\n" for rule in disabled), encoding="utf-8")
    print(f"Disabled {len(disabled)} rule(s) this Suricata build cannot load (sids {', '.join(sids)}); "
          f"listed in {report_path}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
