param([string]$PythonVersion = '3.13.7')
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
. "$PSScriptRoot\security.ps1"
$dependencyHashes = Get-Content "$PSScriptRoot\dependency-hashes.json" -Raw | ConvertFrom-Json
$repo = (Resolve-Path "$PSScriptRoot\..\..").Path
$build = Join-Path $repo 'build\windows'
$stage = Join-Path $build ('payload-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force "$stage\runtime", "$stage\dashboard\dist", "$build\downloads" | Out-Null
function Check-Exit { if ($LASTEXITCODE -ne 0) { throw "Command failed: $LASTEXITCODE" } }
Push-Location $repo
try {
    & npm.cmd ci --prefix dashboard; Check-Exit
    & npm.cmd run build --prefix dashboard; Check-Exit
    Copy-Item dashboard\dist\* "$stage\dashboard\dist" -Recurse -Force
    $zip = "$build\downloads\python-$PythonVersion-embed-amd64.zip"
    if (!(Test-Path $zip)) { Invoke-WebRequest "https://www.python.org/ftp/python/$PythonVersion/python-$PythonVersion-embed-amd64.zip" -OutFile $zip -UseBasicParsing }
    Assert-FileHash $zip $dependencyHashes."python-$PythonVersion-embed-amd64.zip"
    Expand-Archive $zip "$stage\runtime" -Force
    $pth = Get-ChildItem "$stage\runtime\python*._pth" | Select-Object -First 1
    # Enable site processing so pywin32's DLL/bootstrap .pth is loaded.
    @("python$($PythonVersion.Split('.')[0])$($PythonVersion.Split('.')[1]).zip", '.', 'Lib\site-packages', 'import site') | Set-Content $pth.FullName -Encoding ascii
    # Wheels (pywin32, bcrypt, llama.cpp, ...) run as SYSTEM; install only what uv.lock
    # hashes. Copies, not links into uv's cache: the payload is packaged as files.
    & uv export --frozen --no-dev --no-emit-project --format requirements-txt --output-file "$build\requirements.txt" | Out-Null; Check-Exit
    & uv pip install --python 3.13 --link-mode copy --require-hashes --target "$stage\runtime\Lib\site-packages" -r "$build\requirements.txt"; Check-Exit
    & uv pip install --python 3.13 --link-mode copy --target "$stage\runtime\Lib\site-packages" --no-deps .; Check-Exit
    & "$stage\runtime\python.exe" -c 'import triage.main, triage.local_model, win32evtlog, uvicorn, yaml, bcrypt'; Check-Exit
    # llama.cpp ships as native DLLs inside the wheel; the model runtime is useless
    # without them. Importing also loads them, which needs the VC++ runtime and an
    # AVX2 CPU on this build machine (the installer provides both checks on targets).
    foreach ($dll in @('llama.dll', 'ggml.dll', 'ggml-base.dll', 'ggml-cpu.dll')) {
        if (!(Test-Path "$stage\runtime\Lib\site-packages\llama_cpp\lib\$dll")) { throw "llama.cpp runtime file missing from payload: $dll" }
    }
    & "$stage\runtime\python.exe" -c 'import llama_cpp; print(llama_cpp.__version__, llama_cpp.llama_print_system_info().decode())'; Check-Exit
    # The owner's Purdue GenAI Studio key is personal and must never ship, even by accident.
    $secrets = Get-ChildItem $stage -Recurse -Force -Include 'genai-key*', 'genai.json' -ErrorAction SilentlyContinue
    if ($secrets) { throw "Refusing to build: a GenAI Studio key file is in the payload: $($secrets.FullName -join ', ')" }
    $compiler = @("${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe", "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (!$compiler) {
        & winget install --id JRSoftware.InnoSetup --exact --source winget --silent --scope user --accept-source-agreements --accept-package-agreements; Check-Exit
        $compiler = "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe"
    }
    # Antivirus scanning the new .exe while Inno writes its resources makes the last
    # step fail now and then ("EndUpdateResource failed (110)"). Start from no old
    # output and retry a couple of times before giving up.
    Remove-Item "$repo\dist\LightHouse-Setup.exe", "$repo\dist\LightHouse-Setup.exe.sha256" -Force -ErrorAction SilentlyContinue
    for ($attempt = 1; ; $attempt++) {
        & $compiler /Qp "/DPayloadDir=$stage" "$PSScriptRoot\lighthouse.iss"
        if ($LASTEXITCODE -eq 0) { break }
        if ($attempt -ge 3) { Check-Exit }
        Write-Warning "Installer compile failed (attempt $attempt of 3), often antivirus holding the file; retrying in 10 seconds."
        Start-Sleep -Seconds 10
    }
    # Attach both files to the GitHub release: the dashboard's "Update now" installs
    # only an installer whose SHA-256 matches this file (triage/updates.py).
    $hash = Get-FileHash "$repo\dist\LightHouse-Setup.exe" -Algorithm SHA256
    "$($hash.Hash.ToLowerInvariant())  LightHouse-Setup.exe" | Set-Content "$repo\dist\LightHouse-Setup.exe.sha256" -Encoding ascii
    $hash
} finally { Pop-Location }
