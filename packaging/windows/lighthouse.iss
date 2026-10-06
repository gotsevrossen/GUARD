#define AppVersion "0.1.0"
#ifndef PayloadDir
  #error Build with packaging/windows/build.ps1 to supply the bundled Python runtime and dashboard.
#endif
[Setup]
AppId={{B2B38EEC-CE7B-4CD4-8F32-658357D28D4D}
AppName=LightHouse
AppVersion={#AppVersion}
DefaultDirName={autopf}\LightHouse
DefaultGroupName=LightHouse
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.19045
OutputDir=..\..\dist
OutputBaseFilename=LightHouse-Setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
SetupLogging=yes
CloseApplications=no
UninstallDisplayIcon={app}\runtime\python.exe
[Files]
Source: "{#PayloadDir}\*"; DestDir: "{app}"; Flags: recursesubdirs createallsubdirs ignoreversion
Source: "install.ps1"; DestDir: "{app}\setup"; Flags: ignoreversion
Source: "security.ps1"; DestDir: "{app}\setup"; Flags: ignoreversion
Source: "dependency-hashes.json"; DestDir: "{app}\setup"; Flags: ignoreversion
Source: "configure_suricata.py"; DestDir: "{app}\setup"; Flags: ignoreversion
Source: "disable_failed_rules.py"; DestDir: "{app}\setup"; Flags: ignoreversion
Source: "uninstall.ps1"; DestDir: "{app}\setup"; Flags: ignoreversion
[Icons]
Name: "{group}\LightHouse Dashboard"; Filename: "http://127.0.0.1:8000"
Name: "{group}\LightHouse Logs"; Filename: "{commonappdata}\LightHouse\logs"
[UninstallRun]
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\setup\uninstall.ps1"" -AppDir ""{app}"""; Flags: runhidden waituntilterminated; RunOnceId: "RemoveServices"
[Code]
var SetupFailed: Boolean;
function GetCustomSetupExitCode: Integer;
begin
  if SetupFailed then Result := 1 else Result := 0;
end;
function PrepareToInstall(var NeedsRestart: Boolean): String;
var Code: Integer;
begin
  Result := '';
  if FileExists(ExpandConstant('{app}\setup\uninstall.ps1')) then
    if not Exec(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'),
      '-NoProfile -ExecutionPolicy Bypass -File "' + ExpandConstant('{app}\setup\uninstall.ps1') + '" -AppDir "' + ExpandConstant('{app}') + '" -StopOnly',
      '', SW_HIDE, ewWaitUntilTerminated, Code) then
      Result := 'Unable to stop existing LightHouse services.'
    else if Code <> 0 then Result := 'Could not stop existing services. See Windows Service Manager.';
end;
procedure CurStepChanged(CurStep: TSetupStep);
var Code: Integer; Args: String; FailureDetail: AnsiString; Detail: String;
begin
  if CurStep = ssPostInstall then begin
    SetupFailed := True;
    WizardForm.StatusLabel.Caption := 'Installing sensors and downloading the local AI model (about 2.5 GB). This can take several minutes...';
    Args := '-NoProfile -ExecutionPolicy Bypass -File "' + ExpandConstant('{app}\setup\install.ps1') + '" -AppDir "' + ExpandConstant('{app}') + '"';
    if WizardSilent then Args := Args + ' -Unattended';
    if not Exec(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'), Args, '', SW_HIDE, ewWaitUntilTerminated, Code) then
      RaiseException('Could not launch dependency setup.');
    if Code <> 0 then begin
      // Data-directory trust failures happen before install.log can be written.
      Detail := '';
      if LoadStringFromFile(ExpandConstant('{app}\setup\last-result.txt'), FailureDetail) then begin
        Detail := Trim(String(FailureDetail));
        Log(Detail);
        Detail := Detail + #13#10#13#10;
      end;
      RaiseException('LightHouse setup is incomplete. ' + Detail + 'See ' + ExpandConstant('{commonappdata}\LightHouse\logs\install.log') + '. Correct the error and rerun this installer.');
    end;
    SetupFailed := False;
  end;
end;
