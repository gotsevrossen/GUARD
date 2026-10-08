# Opens the dashboard from the LightHouse Dashboard shortcuts. Runs hidden as the
# signed-in user, who may not be an administrator. After an admin chose "Shut down"
# in the dashboard, every LightHouse service is stopped; this starts LightHouse-API
# again (setup lets interactive users start that one service, nothing more) and the
# API itself, as SYSTEM, turns monitoring back on. Ingestion and Suricata are never
# started from here. The script takes no input, so nothing in it can be steered, and
# it runs from the install folder, which only administrators can change.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$dashboard = 'http://127.0.0.1:8000'

function Test-Ready {
    try { return (Invoke-WebRequest "$dashboard/health" -UseBasicParsing -TimeoutSec 2).StatusCode -eq 200 }
    catch { return $false }
}

$ready = Test-Ready
if (!$ready) {
    $started = $false
    $service = Get-Service 'LightHouse-API' -ErrorAction SilentlyContinue
    if ($service) {
        try {
            # A shut down still finishing must end before the service can start again.
            if ($service.Status -eq 'StopPending') { $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30)) }
            if ((Get-Service 'LightHouse-API').Status -ne 'Running') { Start-Service 'LightHouse-API' }
            $started = $true
        } catch { $started = $false }
    }
    if ($started) {
        # The API loads before it answers; on a slow machine that takes a while.
        $deadline = (Get-Date).AddSeconds(90)
        while (!($ready = Test-Ready) -and (Get-Date) -lt $deadline) { Start-Sleep -Seconds 2 }
    }
}

if (!$ready) {
    Add-Type -AssemblyName PresentationFramework
    [System.Windows.MessageBox]::Show('LightHouse could not start. Restart the computer, or run the LightHouse installer again to repair it.',
        'LightHouse', 'OK', 'Warning') | Out-Null
    exit 1
}

# Its own window (Edge app mode: no address bar or tabs, its own taskbar entry);
# the default browser where Edge has been removed.
$edge = $null
try { $edge = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\msedge.exe' -ErrorAction Stop).'(default)' } catch { }
if (!$edge -or !(Test-Path -LiteralPath $edge)) { $edge = "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe" }
if (Test-Path -LiteralPath $edge) { Start-Process -FilePath $edge -ArgumentList "--app=$dashboard" }
else { Start-Process $dashboard }
