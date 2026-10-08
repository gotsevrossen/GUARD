"""The installer's handling of ET Open rules the installed Suricata cannot parse."""
import importlib.util
from pathlib import Path

HELPER = Path(__file__).resolve().parent.parent / "packaging" / "windows" / "disable_failed_rules.py"
spec = importlib.util.spec_from_file_location("disable_failed_rules", HELPER)
rules = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rules)

# Verbatim shape of the Suricata 8.0.7 -T failure from a clean VM install.
FILE_MAGIC_RULE = ('alert tcp any any -> $HOME_NET any (msg:"ET HUNTING Observed Zip Slip in ZIP Archive (../) Inbound M1"; '
                   'flow:established,to_client; file.magic; content:"Zip archive"; file.data; content:"|00 00 00 2e 2e 2f|"; '
                   'fast_pattern; classtype:misc-attack; sid:2064945; rev:1; target:dest_ip;)')
SEVEN_ZIP_RULE = ('alert tcp any any -> $HOME_NET any (msg:"ET EXPLOIT 7-Zip 7z File PPMd Properties Parsing Integer Underflow '
                  '(CVE-2023-31102)"; flow:established,to_client; file.magic; content:"7-zip archive"; startswith; '
                  'classtype:misc-attack; sid:2065690; rev:1; target:dest_ip;)')
GOOD_RULE = ('alert http $HOME_NET any -> any any (msg:"ET SCAN Nmap Scripting Engine User-Agent Detected"; '
             'http.user_agent; content:"Nmap Scripting Engine"; classtype:web-application-attack; sid:2009358; rev:7;)')
LOG = f"""[2660 - Suricata-Main] 2026-10-06 13:21:27 Info: suricata: Running suricata under test mode
[2660 - Suricata-Main] 2026-10-06 13:21:27 Error: detect-parse: unknown rule keyword 'file.magic'.
[2660 - Suricata-Main] 2026-10-06 13:21:27 Error: detect: error parsing signature "{SEVEN_ZIP_RULE}" from file C:\\ProgramData\\LightHouse\\rules\\\\emerging-all.rules at line 2
[2660 - Suricata-Main] 2026-10-06 13:21:28 Error: detect-parse: unknown rule keyword 'file.magic'.
[2660 - Suricata-Main] 2026-10-06 13:21:28 Error: detect: error parsing signature "{FILE_MAGIC_RULE}" from file C:\\ProgramData\\LightHouse\\rules\\\\emerging-all.rules at line 3
[2660 - Suricata-Main] 2026-10-06 13:21:32 Info: detect: 1 rule files processed. 52592 rules successfully loaded, 2 rules failed, 0 rules skipped
[2660 - Suricata-Main] 2026-10-06 13:21:32 Error: suricata: Loading signatures failed.
"""


def write_rules(tmp_path, *lines):
    path = tmp_path / "emerging-all.rules"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def test_failed_sids_are_read_from_the_suricata_log():
    assert rules.failed_sids(LOG) == ["2065690", "2064945"]


def test_only_the_failed_rules_are_disabled(tmp_path):
    rules_file = write_rules(tmp_path, "# a comment mentioning sid:2064945;", GOOD_RULE, SEVEN_ZIP_RULE, FILE_MAGIC_RULE)
    log = tmp_path / "suricata.log"; log.write_text(LOG, encoding="utf-8")
    report = tmp_path / "disabled.txt"

    assert rules.main([str(rules_file), str(report), str(log), str(tmp_path / "missing-stderr.txt")]) == 0

    text = rules_file.read_text(encoding="utf-8").splitlines()
    assert text[0] == "# a comment mentioning sid:2064945;"  # already a comment: untouched
    assert text[1] == GOOD_RULE                                  # still active
    assert text[2] == rules.DISABLED_PREFIX + SEVEN_ZIP_RULE
    assert text[3] == rules.DISABLED_PREFIX + FILE_MAGIC_RULE
    assert report.read_text(encoding="utf-8").splitlines() == [SEVEN_ZIP_RULE, FILE_MAGIC_RULE]


def test_a_configuration_error_is_not_papered_over(tmp_path):
    rules_file = write_rules(tmp_path, GOOD_RULE)
    log = tmp_path / "suricata.log"
    log.write_text("Error: conf-yaml-loader: failed to parse configuration file\n", encoding="utf-8")
    assert rules.main([str(rules_file), str(tmp_path / "r.txt"), str(log)]) == 2
    assert rules_file.read_text(encoding="utf-8").strip() == GOOD_RULE


def test_a_mismatched_ruleset_still_fails(tmp_path):
    many = "\n".join(f'Error: detect: error parsing signature "alert ip any any -> any any (msg:"x"; sid:{n}; rev:1;)" '
                     for n in range(rules.MAX_DISABLED + 1))
    log = tmp_path / "suricata.log"; log.write_text(many, encoding="utf-8")
    rules_file = write_rules(tmp_path, GOOD_RULE)
    assert rules.main([str(rules_file), str(tmp_path / "r.txt"), str(log)]) == 3
    assert rules_file.read_text(encoding="utf-8").strip() == GOOD_RULE


def test_failed_sid_with_no_active_rule_is_an_error(tmp_path):
    rules_file = write_rules(tmp_path, GOOD_RULE)
    log = tmp_path / "suricata.log"; log.write_text(LOG, encoding="utf-8")
    assert rules.main([str(rules_file), str(tmp_path / "r.txt"), str(log)]) == 2


def test_generated_config_never_asks_windows_for_the_mtu(tmp_path):
    """The MTU lookup crashes Suricata 8.0.7 on Hyper-V adapters."""
    import io, json, subprocess, sys, tarfile
    import yaml
    vendor = tmp_path / "vendor" / "suricata.yaml"; vendor.parent.mkdir()
    vendor.write_text(yaml.safe_dump({"vars": {"address-groups": {"HOME_NET": "[any]"}},
                                      "pcap": [{"interface": "eth0"}, {"interface": "default"}],
                                      "outputs": []}), encoding="utf-8")
    archive = tmp_path / "rules.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        data = (GOOD_RULE + "\n").encode()
        member = tarfile.TarInfo("rules/emerging-scan.rules"); member.size = len(data)
        tar.addfile(member, io.BytesIO(data))
    settings = tmp_path / "windows.json"; settings.write_text(json.dumps({"HomeNet": "192.168.1.10/24"}), encoding="utf-8")
    data_root = tmp_path / "data"; (data_root / "rules").mkdir(parents=True)
    destination = tmp_path / "suricata.yaml"
    subprocess.run([sys.executable, str(HELPER.with_name("configure_suricata.py")), str(vendor), str(destination),
                    str(settings), str(data_root), str(archive)], check=True)
    config = yaml.safe_load(destination.read_text(encoding="utf-8").split("---", 1)[1])
    assert config["default-packet-size"] == 1514
    assert all(entry["snaplen"] == 65535 for entry in config["pcap"])
    assert config["vars"]["address-groups"]["HOME_NET"] == "[192.168.1.0/24]"


def test_installer_ships_and_uses_the_helper():
    windows = HELPER.parent
    assert 'Source: "disable_failed_rules.py"' in (windows / "lighthouse.iss").read_text(encoding="utf-8")
    install = (windows / "install.ps1").read_text(encoding="utf-8")
    assert "Test-Suricata $suricataExe.FullName $python" in install
    assert "disable_failed_rules.py" in install
    # Windows is not always on C:.
    assert "SuricataDir='C:\\Suricata'" not in install and "$env:SystemDrive\\Suricata" in install
    assert "See C:\\ProgramData" not in (windows / "lighthouse.iss").read_text(encoding="utf-8")
