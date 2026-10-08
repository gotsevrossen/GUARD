param([Parameter(Mandatory=$true)][string]$AppDir, [switch]$Unattended,
      # Data lives next to the program, on the drive the owner chose.
      [string]$DataDir = '',
      # Where an earlier version was installed, if somewhere else; removed on success.
      [string]$PreviousAppDir = '')
if (!$DataDir) { $DataDir = Join-Path $AppDir 'data' }
# Releases before data moved next to the program kept it here.
$LegacyDataDir = "$env:ProgramData\LightHouse"
$LighthouseServices = @('LightHouse-Ingestion', 'LightHouse-API', 'LightHouse-Suricata')
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$resultPath = "$AppDir\setup\last-result.txt"
function Set-Result([string]$Text) { [IO.File]::WriteAllText($resultPath, $Text) }
# Replace the previous run's outcome before anything can fail.
Set-Result 'Installation started.'
try {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run the LightHouse installer as administrator.' }
    . "$PSScriptRoot\security.ps1"
    Assert-InstallVolume $AppDir
    # Nothing may hold the program or data files while they are locked down or moved.
    foreach ($name in $LighthouseServices) {
        $service = Get-Service $name -ErrorAction SilentlyContinue
        if ($service -and $service.Status -ne 'Stopped') { Stop-Service $name -Force; $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(60)) }
    }
    Protect-AppDirectory $AppDir -Except @((Split-Path $DataDir -Leaf))
    $dataFull = [IO.Path]::GetFullPath($DataDir).TrimEnd('\')
    if ((Test-Path -LiteralPath $LegacyDataDir) -and ($dataFull -ne [IO.Path]::GetFullPath($LegacyDataDir).TrimEnd('\')) -and
        !(Test-Path -LiteralPath "$DataDir\lighthouse.db") -and @(Get-ChildItem -LiteralPath $LegacyDataDir -Force).Count) {
        # An earlier release's data: verified as trusted (ordinary users can create
        # folders in ProgramData) before anything in it is reused, then moved.
        Set-PrivateTree ([IO.Path]::GetFullPath($LegacyDataDir)) $true
        Protect-DataDirectory $DataDir
        Assert-FreeSpace $DataDir ((Get-TreeSize $LegacyDataDir) + 512MB)
        Write-Host "Moving existing LightHouse data from $LegacyDataDir to $DataDir"
        Move-DataTree $LegacyDataDir $DataDir
    }
    Protect-DataDirectory $DataDir
    $dependencyHashes = Get-Content "$PSScriptRoot\dependency-hashes.json" -Raw | ConvertFrom-Json
    New-Item -ItemType Directory -Force "$DataDir\logs", "$DataDir\cache", "$DataDir\config", "$DataDir\state", "$DataDir\models", "$DataDir\rules", "$DataDir\suricata", "$AppDir\tools" | Out-Null
} catch {
    # The data tree is not trusted yet, so the reason goes only to the result file.
    Write-Host "INSTALLATION FAILED: $_"
    Set-Result "Installation incomplete: $_"
    exit 1
}
Start-Transcript -Path "$DataDir\logs\install.log" -Append | Out-Null
function Complete([string]$Result, [int]$Code) {
    Set-Result $Result
    try { Restore-DataOwnership $DataDir } catch { Write-Host "Could not restore data directory ownership: $_" }
    Stop-Transcript | Out-Null
    exit $Code
}
function Run([string]$File, [string]$Arguments) {
    Write-Host "Running $File"
    $process = Start-Process -FilePath $File -ArgumentList $Arguments -Wait -PassThru -WindowStyle Hidden
    if ($process.ExitCode -eq 3010) { Write-Host 'Dependency requests a reboot; reboot after setup.' }
    elseif ($process.ExitCode -ne 0) { throw "$File failed with exit code $($process.ExitCode)" }
}
function Test-Suricata([string]$Exe, [string]$Python) {
    # -T treats any rule that fails to parse as fatal, and ET Open ships rules using
    # keywords this build lacks (file.magic). Disable exactly those rules once and
    # test again; a configuration error, or a ruleset that does not match the
    # engine, still stops setup. Output goes to the transcript, not a hidden window.
    $testDir = "$DataDir\cache\suricata-test"
    for ($attempt = 1; ; $attempt++) {
        Remove-Item -LiteralPath $testDir -Recurse -Force -ErrorAction SilentlyContinue
        New-Item -ItemType Directory -Force $testDir | Out-Null
        Write-Host "Testing Suricata configuration (attempt $attempt)"
        $process = Start-Process -FilePath $Exe -ArgumentList "-T -c `"$DataDir\config\suricata.yaml`" -l `"$testDir`"" `
            -Wait -PassThru -WindowStyle Hidden -RedirectStandardOutput "$testDir\stdout.txt" -RedirectStandardError "$testDir\stderr.txt"
        $logs = @("$testDir\suricata.log", "$testDir\stdout.txt", "$testDir\stderr.txt") | Where-Object { Test-Path -LiteralPath $_ }
        $output = if ($logs) { Get-Content -LiteralPath $logs } else { @() }
        $output | Where-Object { $_ -match 'Error|Warning' } | Select-Object -Unique -First 40 | ForEach-Object { Write-Host "  $_" }
        if ($process.ExitCode -eq 0) { return }
        if ($attempt -ge 2) { throw "Suricata configuration test failed with exit code $($process.ExitCode); the errors are above." }
        & $Python "$AppDir\setup\disable_failed_rules.py" "$DataDir\rules\emerging-all.rules" "$DataDir\rules\disabled-by-lighthouse.txt" @logs
        if ($LASTEXITCODE -ne 0) { throw "Suricata configuration test failed with exit code $($process.ExitCode); the errors are above." }
    }
}
function Assert-Dependency([string]$Path, [string]$Name) {
    $hash = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
    Write-Host "$Name SHA256 $hash"
    if ($Name -eq 'vc_redist.x64.exe') {
        Assert-Publisher $Path @('Microsoft Corporation')
    } elseif ($Name -eq 'Sysmon.zip') {
        Assert-SysmonArchive $Path "$DataDir\cache\sysmon-verify"
    } elseif ($Name -match '\.(exe|msi|zip|gguf)$') {
        Assert-FileHash $Path $dependencyHashes.$Name $hash
    }
}
function Fetch([string]$Url, [string]$Name, [string]$Directory = "$DataDir\cache") {
    $target = Join-Path $Directory $Name
    if (Test-Path -LiteralPath $target) {
        try { Assert-Dependency $target $Name; return $target }
        catch { Write-Host "Cached $Name failed verification ($_); downloading again."; Remove-Item -LiteralPath $target -Force }
    }
    # Keep the extension: Authenticode and archive checks inspect it.
    $partial = Join-Path $Directory "partial-$Name"
    for ($attempt = 1; ; $attempt++) {
        Write-Host "Downloading $Url"
        try { Invoke-WebRequest -Uri $Url -OutFile $partial -UseBasicParsing; break }
        catch {
            # Multi-gigabyte downloads meet transient DNS failures and resets.
            if ($attempt -ge 3) { Remove-Item -LiteralPath $partial -Force -ErrorAction SilentlyContinue; throw }
            Write-Host "Download attempt $attempt failed ($_); retrying."
            Start-Sleep -Seconds (10 * $attempt)
        }
    }
    # Only verified files enter the cache, so a bad download is retried next run.
    try { Assert-Dependency $partial $Name }
    catch { Remove-Item -LiteralPath $partial -Force -ErrorAction SilentlyContinue; throw }
    Move-Item -LiteralPath $partial -Destination $target -Force
    return $target
}
function Nssm([string[]]$Arguments) {
    & "$AppDir\tools\nssm.exe" @Arguments
    if ($LASTEXITCODE -ne 0) { throw "NSSM failed: $Arguments ($LASTEXITCODE)" }
}
function Register([string]$Name, [string]$Exe, [string]$Arguments, [string[]]$Environment) {
    if (!(Get-Service $Name -ErrorAction SilentlyContinue)) { Nssm @('install', $Name, $Exe) }
    else {
        # A service registered by an install in another folder still starts that
        # folder's nssm.exe; point it at this one before the old folder is removed.
        $wrapper = "$AppDir\tools\nssm.exe"
        $current = (Get-CimInstance Win32_Service -Filter "Name='$Name'").PathName
        if ($current.Trim('"') -ne $wrapper) {
            & sc.exe config $Name binPath= "`"$wrapper`"" | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "Could not move service $Name to $wrapper (sc.exe $LASTEXITCODE)" }
        }
    }
    Nssm @('set', $Name, 'Application', $Exe)
    Nssm @('set', $Name, 'AppParameters', $Arguments)
    Nssm @('set', $Name, 'AppDirectory', $AppDir)
    Nssm @('set', $Name, 'Start', 'SERVICE_AUTO_START')
    Nssm @('set', $Name, 'AppExit', 'Default', 'Restart')
    Nssm @('set', $Name, 'AppRestartDelay', '5000')
    Nssm @('set', $Name, 'AppStdout', "$DataDir\logs\$Name.stdout.log")
    Nssm @('set', $Name, 'AppStderr', "$DataDir\logs\$Name.stderr.log")
    Nssm @('set', $Name, 'AppRotateFiles', '1')
    Nssm @('set', $Name, 'AppRotateOnline', '1')
    Nssm @('set', $Name, 'AppRotateBytes', '10485760')
    Nssm (@('set', $Name, 'AppEnvironmentExtra') + $Environment)
}
function Grant-InteractiveStart([string]$Name) {
    # After an admin chooses "Shut down" in the dashboard, the owner restarts
    # LightHouse from its shortcut without admin rights. Interactive users get start,
    # query status, interrogate and read (RPLCLORC) on this one service; starting it is
    # harmless (Windows does the same at every boot). Stopping it and changing its
    # configuration or permissions stay with Administrators and SYSTEM.
    $ace = '(A;;RPLCLORC;;;IU)'
    $output = & sc.exe sdshow $Name
    if ($LASTEXITCODE -ne 0) { throw "Could not read the permissions of service $Name (sc.exe $LASTEXITCODE)" }
    $sddl = (@($output) | Where-Object { $_ -and $_.Trim() } | Select-Object -First 1)
    $dacl = if ($sddl) { $sddl.Trim().IndexOf('D:') } else { -1 }
    if ($dacl -lt 0) { throw "Service $Name has no readable permission list: $sddl" }
    $sddl = $sddl.Trim()
    if ($sddl.Contains($ace)) { return }
    # The new entry goes at the end of the DACL, before any SACL (S:).
    $end = $sddl.IndexOf('S:', $dacl)
    if ($end -lt 0) { $end = $sddl.Length }
    & sc.exe sdset $Name $sddl.Insert($end, $ace) | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Could not let users start service $Name (sc.exe $LASTEXITCODE)" }
}
function Wait-Http([string]$Url) {
    for ($attempt = 0; $attempt -lt 90; $attempt++) {
        try { return Invoke-RestMethod $Url -TimeoutSec 2 } catch { Start-Sleep -Seconds 2 }
    }
    throw "Service did not become ready: $Url. See $DataDir\logs."
}
try {
    $configPath = "$DataDir\config\windows.json"
    if (!(Test-Path $configPath)) {
        $route = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' |
            Sort-Object @{Expression={$_.RouteMetric + $_.InterfaceMetric}} | Select-Object -First 1
        if (!$route) { throw 'No IPv4 default route. Configure windows.json with HomeNet and CaptureInterface.' }
        $adapter = Get-NetAdapter | Where-Object ifIndex -eq $route.InterfaceIndex | Select-Object -First 1
        if (!$adapter) { throw 'Default route adapter is unavailable. Configure CaptureInterface manually.' }
        $address = Get-NetIPAddress -InterfaceIndex $route.InterfaceIndex -AddressFamily IPv4 |
            Where-Object { $_.AddressState -eq 'Preferred' } | Select-Object -First 1
        [ordered]@{HomeNet="$($address.IPAddress)/$($address.PrefixLength)";
            CaptureInterface="\Device\NPF_$(([guid]$adapter.InterfaceGuid).ToString('B'))";
            SuricataDir=(Join-Path $AppDir 'Suricata'); ApiPort=8000; ModelPath='';
            NpcapOemInstaller=''} | ConvertTo-Json | Set-Content $configPath -Encoding utf8
    }
    # Model and OllamaPort in configurations from earlier releases are ignored.
    $config = Get-Content $configPath -Raw | ConvertFrom-Json
    if ([int]$config.ApiPort -lt 1024 -or [int]$config.ApiPort -gt 65535) { throw 'ApiPort must be in 1024..65535.' }
    # Earlier releases put Suricata at the root of the Windows drive. If LightHouse
    # now lives on another drive, Suricata moves next to it. Only LightHouse's own old
    # default is moved; a folder the operator chose is left where it is.
    $relocateSuricata = ($config.SuricataDir -in @('C:\Suricata', "$env:SystemDrive\Suricata")) -and
        ([IO.Path]::GetPathRoot($config.SuricataDir) -ne [IO.Path]::GetPathRoot([IO.Path]::GetFullPath($AppDir)))
    $oldSuricataDir = $config.SuricataDir
    if ($relocateSuricata) {
        $config.SuricataDir = Join-Path $AppDir 'Suricata'
        $config | ConvertTo-Json | Set-Content $configPath -Encoding utf8
    }
    if (!(Get-Service npcap -ErrorAction SilentlyContinue)) {
        if ($config.NpcapOemInstaller) {
            $oem = "$DataDir\cache\npcap-oem.exe"
            Copy-Item -LiteralPath $config.NpcapOemInstaller -Destination $oem -Force
            Assert-Publisher $oem @('Nmap Software LLC', 'Insecure.Com LLC')
            Run $oem '/S /winpcap_mode=yes'
        } elseif ($Unattended) {
            throw 'Free Npcap cannot install silently. Install it first or set NpcapOemInstaller in config\windows.json to an OEM installer path, then rerun.'
        } else {
            $npcap = Fetch 'https://npcap.com/dist/npcap-1.89.exe' 'npcap-1.89.exe'
            # Free Npcap requires its visible wizard. /S is OEM-only.
            $process = Start-Process $npcap -ArgumentList '/winpcap_mode=yes' -Wait -PassThru -WindowStyle Normal
            if ($process.ExitCode -notin @(0, 3010)) { throw 'Npcap installation was cancelled or failed.' }
        }
        if (!(Get-Service npcap -ErrorAction SilentlyContinue)) { throw 'Npcap driver was not installed.' }
    }
    $suricataMsi = Fetch 'https://www.openinfosecfoundation.org/download/windows/Suricata-8.0.7-1-64bit.msi' 'Suricata-8.0.7-1-64bit.msi'
    $suricataProduct = '{42AB4288-8940-4B7D-97E2-75901A1D188F}'
    $suricataInstalled = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$suricataProduct"
    if ($relocateSuricata -and $suricataInstalled) {
        # An MSI repair cannot change its install folder, so the old copy is removed
        # and Suricata is installed fresh in the new one. Its rules, configuration and
        # logs live in the data folder, so nothing of LightHouse's is lost.
        Write-Host "Moving Suricata from $oldSuricataDir to $($config.SuricataDir)"
        Run 'msiexec.exe' "/x $suricataProduct /qn /norestart /L*v `"$DataDir\logs\suricata-msi-remove.log`""
        if ((Test-Path -LiteralPath $oldSuricataDir) -and !@(Get-ChildItem -LiteralPath $oldSuricataDir -Recurse -Force -File).Count) {
            Remove-Item -LiteralPath $oldSuricataDir -Recurse -Force
        }
        $suricataInstalled = $false
    }
    $repair = if ($suricataInstalled) { 'REINSTALL=ALL REINSTALLMODE=vomus' } else { '' }
    Run 'msiexec.exe' "/i `"$suricataMsi`" /qn /norestart $repair INSTALLDIR=`"$($config.SuricataDir)`" /L*v `"$DataDir\logs\suricata-msi.log`""
    $suricataExe = Get-ChildItem $config.SuricataDir -Filter suricata.exe -Recurse | Select-Object -First 1
    if (!$suricataExe) { throw "Suricata not found in $($config.SuricataDir)" }
    $sysmonZip = Fetch 'https://download.sysinternals.com/files/Sysmon.zip' 'Sysmon.zip'
    Expand-Archive $sysmonZip "$AppDir\tools\sysmon" -Force
    if (!(Test-Path "$DataDir\config\sysmon.xml")) {
        $rules = Fetch 'https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml' 'swift-sysmon.xml'
        Copy-Item $rules "$DataDir\config\sysmon.xml"
    }
    $sysmonSwitch = if (Get-Service Sysmon64,Sysmon -ErrorAction SilentlyContinue) { '-c' } else { '-i' }
    Run "$AppDir\tools\sysmon\Sysmon64.exe" "-accepteula $sysmonSwitch `"$DataDir\config\sysmon.xml`""
    Run 'auditpol.exe' '/set /subcategory:{0CCE9215-69AE-11D9-BED3-505054503030} /success:enable /failure:enable'
    # Fail before the long model download if the service could not read the channels.
    $python = "$AppDir\runtime\python.exe"
    & $python -m triage.ingest.health --preflight
    if ($LASTEXITCODE -ne 0) { throw 'Cannot read required Event Log channels.' }
    # Always restore the wrapper from the verified archive, also on repair.
    $nssmZip = Fetch 'https://nssm.cc/ci/nssm-2.24-101-g897c7ad.zip' 'nssm-2.24-101-g897c7ad.zip'
    Expand-Archive $nssmZip "$DataDir\cache\nssm" -Force
    Copy-Item "$DataDir\cache\nssm\nssm-2.24-101-g897c7ad\win64\nssm.exe" "$AppDir\tools\nssm.exe" -Force
    # Earlier releases ran Ollama as a LightHouse service with its own model store.
    # Remove both before downloading the new model. The Ollama application those
    # releases installed is left in Apps & features for the owner to remove.
    if (Get-Service LightHouse-Ollama -ErrorAction SilentlyContinue) {
        # Drop ingestion's dependency on it first: if setup stops before services
        # are re-registered, ingestion must still start (else error 1075 at boot).
        if (Get-Service LightHouse-Ingestion -ErrorAction SilentlyContinue) {
            Nssm @('set', 'LightHouse-Ingestion', 'DependOnService', 'LightHouse-API', 'LightHouse-Suricata', 'EventLog')
        }
        Stop-Service LightHouse-Ollama -Force
        Nssm @('remove', 'LightHouse-Ollama', 'confirm')
    }
    foreach ($legacy in @("$DataDir\models\blobs", "$DataDir\models\manifests")) {
        if (Test-Path -LiteralPath $legacy) { Write-Host "Removing legacy Ollama model store $legacy"; Remove-Item -LiteralPath $legacy -Recurse -Force }
    }
    # Local AI runs in-process in the ingestion service: llama.cpp from the bundled
    # runtime, and a GGUF model in the protected data directory.
    $aiNote = ''
    $defaultModel = 'microsoft_Phi-4-mini-instruct-Q4_K_M.gguf'
    $modelPath = if ($config.ModelPath) { Join-Path "$DataDir\models" (Split-Path $config.ModelPath -Leaf) } else { "$DataDir\models\$defaultModel" }
    & $python -m triage.local_model check-cpu
    $cpuCheck = $LASTEXITCODE
    if ($cpuCheck -notin @(0, 3)) { throw 'Local AI CPU check failed.' }
    if ($cpuCheck -eq 0) {
        # llama.cpp's DLLs need msvcp140/vcomp140 from the Visual C++ runtime,
        # which the embedded Python lacks. The permalink always serves the latest
        # supported version, so the cached copy is refreshed on every run.
        Remove-Item -LiteralPath "$DataDir\cache\vc_redist.x64.exe" -Force -ErrorAction SilentlyContinue
        $vcRedist = Fetch 'https://aka.ms/vc14/vc_redist.x64.exe' 'vc_redist.x64.exe'
        $process = Start-Process -FilePath $vcRedist -ArgumentList '/install /quiet /norestart' -Wait -PassThru -WindowStyle Hidden
        # 1638: the same or a newer runtime is already installed.
        if ($process.ExitCode -notin @(0, 1638, 3010)) { throw "Visual C++ runtime installation failed with exit code $($process.ExitCode)." }
        # The bundled runtime is built with MSVC 14.44; older msvcp140 builds crash it.
        $msvcp = (Get-Item "$env:WINDIR\System32\msvcp140.dll" -ErrorAction SilentlyContinue).VersionInfo
        if (!$msvcp -or [version]"$($msvcp.FileMajorPart).$($msvcp.FileMinorPart)" -lt [version]'14.44' -or !(Test-Path "$env:WINDIR\System32\vcomp140.dll")) {
            # 3010: files in use are replaced at the next restart.
            if ($process.ExitCode -eq 3010) { throw 'Restart Windows to finish installing the Visual C++ runtime, then run LightHouse setup again.' }
            throw 'Visual C++ runtime 14.44 or later is required for local AI and was not installed.'
        }
        if ($config.ModelPath) {
            # An operator-supplied model is copied into the protected store once:
            # the SYSTEM service must never parse a file non-administrators can
            # replace, and a rerun must not re-import a source that changed since.
            # To switch models, use a new file name (or delete the copy first).
            if (!(Test-Path -LiteralPath $modelPath)) {
                Copy-Item -LiteralPath $config.ModelPath -Destination $modelPath
            }
        } else {
            Fetch 'https://huggingface.co/bartowski/microsoft_Phi-4-mini-instruct-GGUF/resolve/7ff82c2aaa4dde30121698a973765f39be5288c0/microsoft_Phi-4-mini-instruct-Q4_K_M.gguf' $defaultModel "$DataDir\models" | Out-Null
        }
        # Loads the model and validates one triage, exactly as the service will.
        & $python -m triage.local_model smoke-test --model-path $modelPath
        if ($LASTEXITCODE -ne 0) { throw "The local AI model failed its self-test ($modelPath); see the output above." }
    } else {
        $aiNote = ' Local AI triage is unavailable because this CPU lacks AVX2; monitoring runs and alerts are kept for human review.'
        Write-Warning $aiNote.Trim()
    }
    $rules = Fetch 'https://rules.emergingthreats.net/open/suricata-7.0.3/emerging.rules.tar.gz' 'emerging.rules.tar.gz'
    $vendorYaml = Get-ChildItem $config.SuricataDir -Filter suricata.yaml -Recurse | Select-Object -First 1
    if (!$vendorYaml) { throw 'Suricata vendor YAML missing.' }
    & $python "$AppDir\setup\configure_suricata.py" $vendorYaml.FullName "$DataDir\config\suricata.yaml" $configPath $DataDir $rules
    if ($LASTEXITCODE -ne 0) { throw 'Invalid Suricata configuration.' }
    Test-Suricata $suricataExe.FullName $python
    # A "Shut down" from the dashboard leaves this marker for the API's next start.
    # Setup re-registers every service as automatic and starts them all itself, so an
    # old marker would only be acted on again later. Removed only here, just before
    # the services are re-registered: if setup fails earlier, the API still finds it.
    $shutdownMarker = "$DataDir\config\shutdown.json"
    if (Test-Path -LiteralPath $shutdownMarker) { Remove-Item -LiteralPath $shutdownMarker -Force }
    Register 'LightHouse-Suricata' $suricataExe.FullName "-c `"$DataDir\config\suricata.yaml`" -i `"$($config.CaptureInterface)`" -l `"$DataDir\suricata`"" @("PATH=$env:PATH;$env:WINDIR\System32\Npcap")
    Nssm @('set', 'LightHouse-Suricata', 'DependOnService', 'npcap')
    Start-Service LightHouse-Suricata
    $environment = @('PYTHONUNBUFFERED=1', 'LIGHTHOUSE_DESKTOP=0', "LIGHTHOUSE_DB_PATH=$DataDir\lighthouse.db",
        "LIGHTHOUSE_STATIC_DIR=$AppDir\dashboard\dist", "LIGHTHOUSE_SURICATA_PATH=$DataDir\suricata\eve.json",
        'LIGHTHOUSE_SYSMON_CHANNEL=Microsoft-Windows-Sysmon/Operational', 'LIGHTHOUSE_SECURITY_CHANNEL=Security',
        "LIGHTHOUSE_EVENT_STATE_DIR=$DataDir\state", 'LIGHTHOUSE_MODEL_BACKEND=llama_cpp',
        # One-time admin password in a fixed, admin-only file; the service logs are
        # rotated and renamed on every restart.
        "LIGHTHOUSE_FIRST_RUN_DIR=$DataDir",
        "LIGHTHOUSE_MODEL_PATH=$modelPath")
    # Optional "ModelThreads" in windows.json overrides the automatic choice.
    if ($config.ModelThreads -and [int]$config.ModelThreads -gt 0) { $environment += "LIGHTHOUSE_MODEL_THREADS=$([int]$config.ModelThreads)" }
    Register 'LightHouse-API' $python "-m uvicorn triage.api:app --host 127.0.0.1 --port $($config.ApiPort)" $environment
    Grant-InteractiveStart 'LightHouse-API'
    Start-Service LightHouse-API
    # API seeds first, placing the existing credential banner in API stdout.
    Wait-Http "http://127.0.0.1:$($config.ApiPort)/api/health" | Out-Null
    Register 'LightHouse-Ingestion' $python '-m triage.main tail' $environment
    Nssm @('set', 'LightHouse-Ingestion', 'DependOnService', 'LightHouse-API', 'LightHouse-Suricata', 'EventLog')
    # Background triage yields the CPU to a chat the owner is waiting on.
    Nssm @('set', 'LightHouse-Ingestion', 'AppPriority', 'BELOW_NORMAL_PRIORITY_CLASS')
    $ingestionStarted = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    Start-Service LightHouse-Ingestion
    Start-Sleep -Seconds 5
    foreach ($name in @('LightHouse-API', 'LightHouse-Ingestion', 'LightHouse-Suricata')) {
        if ((Get-Service $name).Status -ne 'Running') { throw "$name is not running; see service logs." }
    }
    if (!(Test-Path "$DataDir\suricata\eve.json")) { throw 'Suricata has not created eve.json; check capture interface and service stderr.' }
    $healthy = $false
    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        & $python -m triage.ingest.health --state-dir "$DataDir\state" --since $ingestionStarted
        if ($LASTEXITCODE -eq 0) { $healthy = $true; break }
        Start-Sleep -Seconds 2
    }
    if (!$healthy) { throw 'Event ingestion did not report fresh healthy channels. See ingestion stderr.' }
    Write-Host "LightHouse ready: http://127.0.0.1:$($config.ApiPort)"
    Write-Host "Initial admin password (first install, until you change it): $DataDir\first-run-password.txt"
    Write-Host "Configuration: $configPath. Review HOME_NET and capture adapter for this network."
    Write-Host "Local AI model: $modelPath"
    if ($PreviousAppDir) {
        # The program moved to a new folder. Remove the old copy, but only once this
        # one is running, and only if it really is a LightHouse program folder.
        $previous = [IO.Path]::GetFullPath($PreviousAppDir).TrimEnd('\')
        if ($previous -ne [IO.Path]::GetFullPath($AppDir).TrimEnd('\') -and $previous.Length -gt 3 -and
            (Test-Path -LiteralPath "$previous\setup\install.ps1") -and (Test-Path -LiteralPath "$previous\runtime\python.exe")) {
            try { Remove-Item -LiteralPath $previous -Recurse -Force; Write-Host "Removed the previous program folder $previous" }
            catch { Write-Host "Could not fully remove the previous program folder $previous ($_); delete it by hand." }
        }
    }
    Complete "Installation completed.$aiNote" 0
} catch {
    Write-Host "INSTALLATION FAILED: $_"
    Complete "Installation incomplete: $_" 1
}
