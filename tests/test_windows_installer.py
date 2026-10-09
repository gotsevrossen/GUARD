import subprocess
import sys
from pathlib import Path
import pytest


WINDOWS = Path(__file__).resolve().parent.parent / 'packaging' / 'windows'


def test_everything_follows_the_chosen_install_folder():
    """Data, model and Suricata live on the drive the owner installs to."""
    iss = (WINDOWS / 'lighthouse.iss').read_text(encoding='utf-8')
    install = (WINDOWS / 'install.ps1').read_text(encoding='utf-8')
    assert 'DisableDirPage=no' in iss, 'upgrades must still offer a new folder'
    assert "' -DataDir \"' + ExpandConstant('{app}\\data')" in iss
    assert '{commonappdata}' not in iss, 'nothing may still point at ProgramData'
    assert 'Filename: "{app}\\data\\logs"' in iss
    assert "if (!$DataDir) { $DataDir = Join-Path $AppDir 'data' }" in install
    assert "SuricataDir=(Join-Path $AppDir 'Suricata')" in install
    assert '$env:SystemDrive\\Suricata"; ApiPort' not in install


def test_upgrades_replace_the_payload_but_never_the_data():
    """A leftover old .dist-info made an updated install report its old version."""
    iss = (WINDOWS / 'lighthouse.iss').read_text(encoding='utf-8')
    section = iss[iss.index('[InstallDelete]'):iss.index('[Files]')]
    assert 'Type: filesandordirs; Name: "{app}\\runtime"' in section
    assert 'Type: filesandordirs; Name: "{app}\\dashboard"' in section
    for kept in ('data', 'Suricata', 'tools', 'setup'):
        assert f'{{app}}\\{kept}' not in section


def test_install_folder_is_locked_before_anything_runs_from_it():
    iss = (WINDOWS / 'lighthouse.iss').read_text(encoding='utf-8')
    install = (WINDOWS / 'install.ps1').read_text(encoding='utf-8')
    prepare = iss[iss.index('function PrepareToInstall'):]
    # Checked, locked (Users read and run only), then re-checked, before any file is copied.
    checks = [prepare.index('TargetProblem(App)'), prepare.index('/inheritance:r /grant:r *S-1-5-18:(OI)(CI)F '
              '*S-1-5-32-544:(OI)(CI)F *S-1-5-32-545:(OI)(CI)RX'), prepare.index('/setowner *S-1-5-32-544'),
              prepare.index('not SafeTarget(App)')]
    assert checks == sorted(checks)
    for problem in ('not a network folder', 'not the root of drive', 'must be installed on an internal drive',
                    'cannot protect LightHouse', 'already contains other files'):
        assert problem in iss
    first = install[:install.index('Start-Transcript')]
    assert first.index('Assert-InstallVolume $AppDir') < first.index('Protect-AppDirectory $AppDir')


def test_old_data_is_verified_before_it_is_moved():
    install = (WINDOWS / 'install.ps1').read_text(encoding='utf-8')
    first = install[:install.index('Start-Transcript')]
    order = [first.index('Stop-Service $name'), first.index('Set-PrivateTree ([IO.Path]::GetFullPath($LegacyDataDir)) $true'),
             first.index('Assert-FreeSpace'), first.index('Move-DataTree $LegacyDataDir $DataDir')]
    assert order == sorted(order)
    # Only when the new folder has no database of its own.
    assert '!(Test-Path -LiteralPath "$DataDir\\lighthouse.db")' in first


def test_moved_install_repoints_services_and_cleans_up_only_lighthouse_folders():
    install = (WINDOWS / 'install.ps1').read_text(encoding='utf-8')
    assert 'sc.exe config $Name binPath=' in install
    cleanup = install[install.index('if ($PreviousAppDir) {'):]
    assert cleanup.index('setup\\install.ps1') < cleanup.index('Remove-Item -LiteralPath $previous')
    assert 'runtime\\python.exe' in cleanup
    # Suricata is moved only from LightHouse's own old default, never an operator's folder.
    assert "$config.SuricataDir -in @('C:\\Suricata', \"$env:SystemDrive\\Suricata\")" in install


def test_dashboard_shortcuts_use_the_launcher():
    """Both shortcuts run open-lighthouse.ps1, so they also restart LightHouse after a shut down."""
    iss = (WINDOWS / 'lighthouse.iss').read_text(encoding='utf-8')
    icons = iss[iss.index('[Icons]'):iss.index('[Run]')]
    dashboard = [line for line in icons.splitlines() if line.startswith('Name: ') and 'Dashboard' in line]
    assert len(dashboard) == 2
    assert dashboard[0].startswith('Name: "{group}\\LightHouse Dashboard"')
    assert dashboard[1].startswith('Name: "{autodesktop}\\LightHouse Dashboard"') and 'Tasks: desktopicon' in dashboard[1]
    for line in dashboard:
        assert 'Filename: "{sys}\\WindowsPowerShell\\v1.0\\powershell.exe"' in line
        assert ('Parameters: "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File '
                '""{app}\\setup\\open-lighthouse.ps1"""') in line
        assert 'IconFilename: "{app}\\lighthouse.ico"' in line
    # No Edge-only or browser-only shortcut is left that would skip the restart.
    assert 'EdgePath' not in icons and 'HasEdge' not in icons and 'Filename: "http://' not in icons
    assert 'Name: "{group}\\LightHouse Logs"' in icons
    # The finish page still opens the dashboard directly; the services run by then.
    assert 'Check: SetupSucceeded and HasEdge' in iss and 'Check: SetupSucceeded and not HasEdge' in iss
    assert 'function FindEdge' in iss
    assert 'Source: "open-lighthouse.ps1"; DestDir: "{app}\\setup"' in iss[iss.index('[Files]'):iss.index('[Icons]')]


def test_launcher_starts_only_the_api_and_opens_the_dashboard():
    launcher = (WINDOWS / 'open-lighthouse.ps1').read_text(encoding='utf-8')
    code = '\n'.join(line for line in launcher.splitlines() if not line.lstrip().startswith('#'))
    # The API resumes ingestion and Suricata itself, as SYSTEM.
    assert "Start-Service 'LightHouse-API'" in code
    assert 'LightHouse-Ingestion' not in code and 'LightHouse-Suricata' not in code
    assert code.count('Start-Service') == 1 and 'Stop-Service' not in code
    assert "$dashboard = 'http://127.0.0.1:8000'" in code
    assert '"$dashboard/health"' in code and '-UseBasicParsing' in code and '-TimeoutSec' in code
    assert '"--app=$dashboard"' in code and 'Start-Process $dashboard' in code
    assert "'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\msedge.exe'" in code
    # A failed start explains itself instead of opening a dead page.
    failure = code[code.index('if (!$ready) {\n    Add-Type'):]
    assert '[System.Windows.MessageBox]::Show(' in failure
    assert failure.index('exit 1') < failure.index('Start-Process')


def test_users_may_start_the_api_but_not_stop_it():
    """Interactive users get start/query rights on LightHouse-API only, never stop or config."""
    import re
    install = (WINDOWS / 'install.ps1').read_text(encoding='utf-8')
    assert re.findall(r'\(A;[^)]*\)', install) == ['(A;;RPLCLORC;;;IU)']
    assert "Grant-InteractiveStart 'LightHouse-API'" in install
    assert install.count('Grant-InteractiveStart') == 2  # definition + one call
    grant = install[install.index('function Grant-InteractiveStart'):install.index('function Wait-Http')]
    assert '& sc.exe sdshow $Name' in grant and '& sc.exe sdset $Name' in grant
    assert grant.count('$LASTEXITCODE -ne 0') == 2 and grant.count('throw') >= 3
    # Added once, inside the DACL, before any SACL.
    assert '$sddl.Contains($ace)' in grant and "IndexOf('S:', $dacl)" in grant
    body = install[install.index("Register 'LightHouse-API'"):]
    assert body.index("Grant-InteractiveStart 'LightHouse-API'") < body.index('Start-Service LightHouse-API')


def test_setup_clears_a_stale_shutdown_marker_before_starting_services():
    install = (WINDOWS / 'install.ps1').read_text(encoding='utf-8')
    marker = install.index('$shutdownMarker = "$DataDir\\config\\shutdown.json"')
    assert 'Remove-Item -LiteralPath $shutdownMarker -Force' in install
    assert marker < install.index("Register 'LightHouse-Suricata'") < install.index('Start-Service LightHouse-Suricata')


def test_touched_scripts_parse():
    if sys.platform != 'win32':
        pytest.skip('PowerShell parser')
    for name in ('install.ps1', 'open-lighthouse.ps1'):
        command = ("$e=$null;[System.Management.Automation.Language.Parser]::ParseFile("
                   f"'{WINDOWS / name}',[ref]$null,[ref]$e)|Out-Null;$e.Count")
        result = subprocess.run(['powershell.exe', '-NoProfile', '-Command', command],
                                capture_output=True, text=True, timeout=60)
        assert result.stdout.strip() == '0', name + result.stdout + result.stderr


def test_web_app_manifest_is_installable_and_cache_free():
    import json
    dashboard = WINDOWS.parent.parent / 'dashboard'
    manifest = json.loads((dashboard / 'public' / 'manifest.json').read_text(encoding='utf-8'))
    assert manifest['name'] == 'LightHouse' and manifest['display'] == 'standalone' and manifest['start_url'] == '/'
    sizes = {icon['sizes'] for icon in manifest['icons']}
    assert {'192x192', '512x512'} <= sizes
    for icon in manifest['icons']:
        assert (dashboard / 'public' / icon['src'].lstrip('/')).is_file()
    index = (dashboard / 'index.html').read_text(encoding='utf-8')
    assert '<link rel="manifest" href="/manifest.json" />' in index
    # No service worker: alert data must never be cached for offline use.
    assert 'serviceWorker' not in index and not list((dashboard / 'src').glob('*sw*.ts'))


def test_icon_has_every_taskbar_size():
    """A size Windows must scale from a neighbour lands off centre in the taskbar."""
    import struct
    data = (WINDOWS / 'art' / 'lighthouse.ico').read_bytes()
    count = struct.unpack_from('<H', data, 4)[0]
    sizes = {data[6 + 16 * index] or 256 for index in range(count)}
    assert {16, 20, 24, 30, 32, 36, 40, 48, 64, 256} <= sizes
    for scale in (100, 125, 150, 175, 200):
        assert (WINDOWS / 'art' / f'wizard-{scale}.png').is_file()
        assert (WINDOWS / 'art' / f'header-{scale}.png').is_file()


def test_background_triage_yields_to_chat():
    install = (WINDOWS / 'install.ps1').read_text(encoding='utf-8')
    update = (WINDOWS / 'dev-update.ps1').read_text(encoding='utf-8')
    for script in (install, update):
        assert 'LightHouse-Ingestion' in script and 'BELOW_NORMAL_PRIORITY_CLASS' in script
    assert 'LIGHTHOUSE_MODEL_THREADS=' in install


def test_saved_chat_state_lives_in_the_protected_data_folder():
    install = (WINDOWS / 'install.ps1').read_text(encoding='utf-8')
    # Under <data>, which Protect-DataDirectory makes Administrators/SYSTEM-only,
    # created by setup and passed to both services like every other path.
    assert '"LIGHTHOUSE_MODEL_STATE_DIR=$DataDir\\cache\\llm-state"' in install
    created = next(line for line in install.splitlines() if 'New-Item -ItemType Directory -Force "$DataDir\\logs"' in line)
    assert '"$DataDir\\cache\\llm-state"' in created
    # Speculative decoding defaults on in code; setup never forces it, and the
    # benchmark is never run by setup.
    assert 'LIGHTHOUSE_MODEL_SPECULATIVE' not in install and 'local_model bench' not in install


def test_dev_update_only_touches_lighthouse_code():
    update = (WINDOWS / 'dev-update.ps1').read_text(encoding='utf-8')
    assert 'IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)' in update
    assert 'Copy-Tree "$repo\\triage" "$sitePackages\\triage"' in update
    assert 'Copy-Tree "$repo\\dashboard\\dist" "$app\\dashboard\\dist"' in update
    # Never the data folder (read only for the API port), the model or Suricata,
    # and nothing is deleted outright.
    code = '\n'.join(line for line in update.splitlines() if not line.lstrip().startswith('#'))
    assert 'Remove-Item' not in code and 'models' not in code and 'Suricata' not in code
    assert [line for line in code.splitlines() if '\\data' in line] == \
        ['$config = "$app\\data\\config\\windows.json"']


@pytest.mark.skipif(sys.platform != 'win32', reason='Windows ACL and Authenticode APIs')
def test_windows_installer_security_guards():
    result = subprocess.run(['powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass',
                             '-File', str(Path(__file__).with_name('windows_security.ps1'))],
                            capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stdout + result.stderr
