"""Preserve the vendor configuration; change only Windows deployment settings."""
import ipaddress
import json
import sys
import tarfile
from pathlib import Path
import yaml

vendor, destination, config_path, data_root, rules_archive = map(Path, sys.argv[1:])
# Read only rule members, never extract archive paths into the filesystem.
with tarfile.open(rules_archive, "r:gz") as archive:
    with (data_root / "rules" / "emerging-all.rules").open("wb") as output:
        count = 0
        for member in archive.getmembers():
            if member.isfile() and member.name.endswith(".rules"):
                with archive.extractfile(member) as source:
                    output.write(source.read())
                    output.write(b"\n")
                count += 1
        if not count:
            raise ValueError("The ET Open archive contains no rule files")
settings = json.loads(config_path.read_text(encoding="utf-8-sig"))
network = str(ipaddress.ip_network(settings["HomeNet"], strict=False))
config = yaml.safe_load(vendor.read_text(encoding="utf-8-sig"))
config["vars"]["address-groups"]["HOME_NET"] = f"[{network}]"
config["default-log-dir"] = str(data_root / "suricata")
config["default-rule-path"] = str(data_root / "rules")
config["rule-files"] = ["emerging-all.rules"]
# Use one predictable EVE file; no Zeek process or files are involved.
config["outputs"] = [{"eve-log": {"enabled": True, "filetype": "regular",
    "filename": "eve.json", "types": ["alert", "flow", "http", "tls", "dns", "smb"]}}]
for key in ("classification-file", "reference-config-file", "threshold-file"):
    if key in config:
        name = Path(config[key]).name
        candidates = list(vendor.parent.rglob(name))
        if candidates:
            config[key] = str(candidates[0])
        else:
            config.pop(key)
# Give Suricata its packet sizes up front. Otherwise it asks Windows for the
# capture adapter's MTU; on a Hyper-V adapter that lookup fails (0x490) and
# Suricata 8.0.7 then crashes with heap corruption (0xc0000374) at every start.
# 1514 is a full Ethernet frame (Suricata's own fallback); 65535 is pcap's usual
# snaplen, so offloaded segments larger than one frame are not truncated.
config["default-packet-size"] = 1514
for interface in config.get("pcap") or []:
    if isinstance(interface, dict):
        interface["snaplen"] = 65535
# Relative vendor include paths must not depend on NSSM's working directory.
config.pop("include", None)
destination.write_text("%YAML 1.1\n---\n" + yaml.safe_dump(config, sort_keys=False), encoding="utf-8")
