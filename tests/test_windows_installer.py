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


@pytest.mark.skipif(sys.platform != 'win32', reason='Windows ACL and Authenticode APIs')
def test_windows_installer_security_guards():
    result = subprocess.run(['powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass',
                             '-File', str(Path(__file__).with_name('windows_security.ps1'))],
                            capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stdout + result.stderr
