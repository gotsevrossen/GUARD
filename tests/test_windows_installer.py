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


def test_dashboard_opens_in_its_own_window():
    """Shortcuts open Edge in app mode, with a browser fallback, never both."""
    iss = (WINDOWS / 'lighthouse.iss').read_text(encoding='utf-8')
    icons = [line for line in iss.splitlines() if line.startswith('Name: ') and 'Dashboard' in line]
    app_mode = [line for line in icons if 'Parameters: "--app=http://127.0.0.1:8000"' in line]
    fallback = [line for line in icons if 'Filename: "http://127.0.0.1:8000"' in line]
    assert len(app_mode) == 2 and all('Check: HasEdge' in line for line in app_mode)
    assert len(fallback) == 2 and all('Check: not HasEdge' in line for line in fallback)
    assert 'Check: SetupSucceeded and HasEdge' in iss and 'Check: SetupSucceeded and not HasEdge' in iss
    assert 'function FindEdge' in iss


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
