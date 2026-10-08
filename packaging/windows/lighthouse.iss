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
; Artwork is rendered by make-installer-art.ps1 from the dashboard logo and tokens.
SetupIconFile=art\lighthouse.ico
WizardImageFile=art\wizard-100.png,art\wizard-200.png
WizardSmallImageFile=art\header-100.png,art\header-200.png
; The welcome page carries the plain-English "what this does" and requirements.
DisableWelcomePage=no
SetupLogging=yes
CloseApplications=no
UninstallDisplayIcon={app}\lighthouse.ico
[Messages]
WelcomeLabel1=Welcome to LightHouse
WelcomeLabel2=LightHouse watches your network and this computer for security problems and explains what it finds in plain English. Nothing leaves this computer.%n%nSetup downloads the monitoring tools and the local AI model (about 2.5 GB), so stay connected to the internet.%n%nOne extra window opens for Npcap. Tick "WinPcap API-compatible mode" there.%n%nLightHouse needs at least 8 GB of memory.
FinishedHeadingLabel=LightHouse is ready
FinishedLabel=LightHouse is monitoring in the background and starts with Windows.%n%nOpen the dashboard any time from the Start menu or the desktop shortcut, or go to http://127.0.0.1:8000 in your browser.%n%nSign in as admin. Your one-time password is in first-run-password.txt in the ProgramData\LightHouse folder. Read it from PowerShell run as administrator ("First sign-in" in the README has the command). It is deleted once you choose your own password.
[Tasks]
Name: "desktopicon"; Description: "Put a LightHouse Dashboard shortcut on the desktop"
[Files]
Source: "art\lighthouse.ico"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#PayloadDir}\*"; DestDir: "{app}"; Flags: recursesubdirs createallsubdirs ignoreversion
Source: "install.ps1"; DestDir: "{app}\setup"; Flags: ignoreversion
Source: "security.ps1"; DestDir: "{app}\setup"; Flags: ignoreversion
Source: "dependency-hashes.json"; DestDir: "{app}\setup"; Flags: ignoreversion
Source: "configure_suricata.py"; DestDir: "{app}\setup"; Flags: ignoreversion
Source: "disable_failed_rules.py"; DestDir: "{app}\setup"; Flags: ignoreversion
Source: "uninstall.ps1"; DestDir: "{app}\setup"; Flags: ignoreversion
[Icons]
Name: "{group}\LightHouse Dashboard"; Filename: "http://127.0.0.1:8000"; IconFilename: "{app}\lighthouse.ico"
Name: "{autodesktop}\LightHouse Dashboard"; Filename: "http://127.0.0.1:8000"; IconFilename: "{app}\lighthouse.ico"; Tasks: desktopicon
Name: "{group}\LightHouse Logs"; Filename: "{commonappdata}\LightHouse\logs"
[Run]
; Offered only when dependency setup succeeded; postinstall entries run as the
; signed-in user, so the browser does not open elevated.
Filename: "http://127.0.0.1:8000"; Description: "Open the LightHouse dashboard"; Flags: postinstall shellexec nowait skipifsilent; Check: SetupSucceeded
[UninstallRun]
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\setup\uninstall.ps1"" -AppDir ""{app}"""; Flags: runhidden waituntilterminated; RunOnceId: "RemoveServices"
[Code]
const
  // --green (#2A9679) as a BGR TColor: the dashboard's sidebar rail colour.
  BrandGreen = $0079962A;
var SetupFailed: Boolean;
function GetCustomSetupExitCode: Integer;
begin
  if SetupFailed then Result := 1 else Result := 0;
end;
function SetupSucceeded: Boolean;
begin
  Result := not SetupFailed;
end;
procedure InitializeWizard;
begin
  // Green page header with white titles, like the dashboard's sidebar.
  WizardForm.MainPanel.Color := BrandGreen;
  WizardForm.PageNameLabel.Font.Color := clWhite;
  WizardForm.PageDescriptionLabel.Font.Color := clWhite;
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
    // Two short lines: each label is a single line and clipped, not wrapped.
    WizardForm.StatusLabel.Caption := 'Setting up the sensors and the local AI...';
    WizardForm.FilenameLabel.Caption := 'The AI model is about 2.5 GB. This can take several minutes.';
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
