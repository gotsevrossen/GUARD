# Developer shortcut: push this checkout's LightHouse code into the installed copy
# on this computer without rerunning setup. Seconds instead of minutes.
#
# Updates only LightHouse's own Python package and the built dashboard, then
# restarts the services. It does not touch Python dependencies, Suricata, Sysmon,
# the AI model or service settings: after changing pyproject.toml/uv.lock or
# install.ps1, run the full installer instead. Never part of a release.
#
# Run from an elevated PowerShell in the repository:
#   powershell -NoProfile -ExecutionPolicy Bypass -File packaging\windows\dev-update.ps1
param([switch]$SkipDashboard)
$ErrorActionPreference = 'Stop'
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run this from PowerShell opened as administrator: the installed copy is admin-only.' }

$repo = (Resolve-Path "$PSScriptRoot\..\..").Path
$entries = @(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' | Where-Object DisplayName -like 'LightHouse*')
if ($entries.Count -ne 1) { throw "Expected one installed LightHouse, found $($entries.Count). Install it with the installer first." }
$app = $entries[0].InstallLocation.TrimEnd('\')
$sitePackages = "$app\runtime\Lib\site-packages"
if (!(Test-Path "$sitePackages\triage\api.py")) { throw "No installed LightHouse code under $sitePackages." }
Write-Host "Updating the LightHouse installed in $app from $repo"

function Copy-Tree([string]$From, [string]$To) {
    # /MIR keeps the target an exact copy (stale files go); copied files take the
    # install folder's permissions, not the checkout's.
    & robocopy.exe $From $To /MIR /XD __pycache__ node_modules /COPY:DAT /R:2 /W:2 /NFL /NDL /NJH /NJS /NP | Out-Null
    if ($LASTEXITCODE -ge 8) { throw "Copying $From to $To failed (robocopy $LASTEXITCODE)." }
}

if (!$SkipDashboard) {
    Push-Location "$repo\dashboard"
    try {
        if (!(Test-Path node_modules)) { & npm.cmd ci; if ($LASTEXITCODE -ne 0) { throw 'npm ci failed' } }
        & npm.cmd run build; if ($LASTEXITCODE -ne 0) { throw 'Dashboard build failed' }
    } finally { Pop-Location }
}

# Ingestion before the API, as setup and uninstall do.
foreach ($name in 'LightHouse-Ingestion', 'LightHouse-API') {
    $service = Get-Service $name -ErrorAction SilentlyContinue
    if ($service -and $service.Status -ne 'Stopped') { Stop-Service $name -Force; $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(60)) }
}
Copy-Tree "$repo\triage" "$sitePackages\triage"
if (!$SkipDashboard) { Copy-Tree "$repo\dashboard\dist" "$app\dashboard\dist" }

# Service settings that code changes depend on; the installer sets the same.
$nssm = "$app\tools\nssm.exe"
& $nssm set LightHouse-Ingestion AppPriority BELOW_NORMAL_PRIORITY_CLASS | Out-Null

Start-Service LightHouse-API
$port = 8000
$config = "$app\data\config\windows.json"
if (Test-Path $config) { $port = [int](Get-Content $config -Raw | ConvertFrom-Json).ApiPort }
for ($i = 0; $i -lt 60; $i++) {
    try { Invoke-RestMethod "http://127.0.0.1:$port/api/health" -TimeoutSec 2 | Out-Null; break } catch { Start-Sleep -Seconds 1 }
}
Start-Service LightHouse-Ingestion
Write-Host "Done. Press Ctrl+F5 in the LightHouse window to load the new dashboard."
