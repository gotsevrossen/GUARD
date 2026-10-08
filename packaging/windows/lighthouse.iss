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
; Always ask where to install, upgrades included: the folder's drive also holds the
; data, the AI model and Suricata, so the owner can move LightHouse off C:.
DisableDirPage=no
SetupLogging=yes
CloseApplications=no
UninstallDisplayIcon={app}\lighthouse.ico
[Messages]
WelcomeLabel1=Welcome to LightHouse
WelcomeLabel2=LightHouse watches your network and this computer for security problems and explains what it finds in plain English. Nothing leaves this computer.%n%nSetup downloads the monitoring tools and the local AI model (about 2.5 GB), so stay connected to the internet.%n%nOne extra window opens for Npcap. Tick "WinPcap API-compatible mode" there.%n%nLightHouse needs at least 8 GB of memory.
FinishedHeadingLabel=LightHouse is ready
FinishedLabel=LightHouse is monitoring in the background and starts with Windows.%n%nOpen the dashboard any time from the Start menu or the desktop shortcut, or go to http://127.0.0.1:8000 in your browser.%n%nSign in as admin. Your one-time password is in first-run-password.txt in the data folder inside the LightHouse install folder. Read it from PowerShell run as administrator ("First sign-in" in the README has the command). It is deleted once you choose your own password.
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
Name: "{group}\LightHouse Logs"; Filename: "{app}\data\logs"
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
function GetDriveType(lpRootPathName: String): Cardinal;
  external 'GetDriveTypeW@kernel32.dll stdcall';
function GetVolumeInformation(lpRootPathName: String; lpVolumeNameBuffer: String; nVolumeNameSize: Cardinal;
  var lpVolumeSerialNumber: Cardinal; var lpMaximumComponentLength: Cardinal; var lpFileSystemFlags: Cardinal;
  lpFileSystemNameBuffer: String; nFileSystemNameSize: Cardinal): Boolean;
  external 'GetVolumeInformationW@kernel32.dll stdcall';

function SameDir(const A, B: String): Boolean;
begin
  Result := (A <> '') and (B <> '') and (CompareText(RemoveBackslashUnlessRoot(A), RemoveBackslashUnlessRoot(B)) = 0);
end;

function PreviousAppDir: String;
begin
  Result := WizardForm.PrevAppDir;
end;

// True for a folder that is empty, absent, or an existing LightHouse install. Any
// other content could have been placed there by someone else, and the program is
// about to run from this folder as SYSTEM.
function SafeTarget(const Dir: String): Boolean;
var FindRec: TFindRec;
begin
  Result := True;
  if not DirExists(Dir) or FileExists(AddBackslash(Dir) + 'setup\install.ps1') then Exit;
  if FindFirst(AddBackslash(Dir) + '*', FindRec) then begin
    try
      repeat
        if (FindRec.Name <> '.') and (FindRec.Name <> '..') then Result := False;
      until not Result or not FindNext(FindRec);
    finally
      FindClose(FindRec);
    end;
  end;
end;

// Why this folder cannot hold LightHouse, or '' when it can. install.ps1 repeats the
// drive checks; these give the owner the answer on the folder page instead.
function TargetProblem(const Dir: String): String;
var Drive, Root, FsName, VolName: String; Serial, MaxLen, Flags: Cardinal;
begin
  Result := '';
  Drive := ExtractFileDrive(Dir);
  if (Copy(Drive, 1, 2) = '\\') or (Drive = '') then begin
    Result := 'LightHouse must be installed on an internal drive of this computer, not a network folder.';
    Exit;
  end;
  if Length(RemoveBackslashUnlessRoot(Dir)) <= 3 then begin
    Result := 'Choose a folder for LightHouse, not the root of drive ' + Drive + '.';
    Exit;
  end;
  Root := AddBackslash(Drive);
  if GetDriveType(Root) <> 3 then begin  // DRIVE_FIXED
    Result := 'LightHouse must be installed on an internal drive. USB, network and removable drives can be missing when Windows starts.';
    Exit;
  end;
  FsName := StringOfChar(' ', 64);
  VolName := StringOfChar(' ', 261);
  if GetVolumeInformation(Root, VolName, 261, Serial, MaxLen, Flags, FsName, 64) then begin
    FsName := Trim(Copy(FsName, 1, Pos(#0, FsName + #0) - 1));
    if (CompareText(FsName, 'NTFS') <> 0) and (CompareText(FsName, 'ReFS') <> 0) then begin
      Result := 'Drive ' + Drive + ' uses ' + FsName + ', which cannot protect LightHouse''s files. Choose a folder on an NTFS drive.';
      Exit;
    end;
  end;
  if not SafeTarget(Dir) and not SameDir(Dir, PreviousAppDir) then
    Result := 'This folder already contains other files. Choose an empty or new folder for LightHouse.';
end;

function NextButtonClick(CurPageID: Integer): Boolean;
var Problem: String;
begin
  Result := True;
  if CurPageID = wpSelectDir then begin
    Problem := TargetProblem(WizardDirValue);
    if Problem <> '' then begin
      MsgBox(Problem, mbError, MB_OK);
      Result := False;
    end;
  end;
end;

function RunIcacls(const Params: String): Boolean;
var Code: Integer;
begin
  Result := Exec(ExpandConstant('{sys}\icacls.exe'), Params, '', SW_HIDE, ewWaitUntilTerminated, Code) and (Code = 0);
end;

function StopServices(const Dir: String): String;
var Code: Integer;
begin
  Result := '';
  if not FileExists(AddBackslash(Dir) + 'setup\uninstall.ps1') then Exit;
  if not Exec(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'),
    '-NoProfile -ExecutionPolicy Bypass -File "' + AddBackslash(Dir) + 'setup\uninstall.ps1" -AppDir "' + RemoveBackslash(Dir) + '" -StopOnly',
    '', SW_HIDE, ewWaitUntilTerminated, Code) then
    Result := 'Unable to stop existing LightHouse services.'
  else if Code <> 0 then Result := 'Could not stop existing services. See Windows Service Manager.';
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var App: String;
begin
  App := RemoveBackslash(ExpandConstant('{app}'));
  // The folder page already checked; checked again here, where it counts.
  Result := TargetProblem(App);
  if Result <> '' then Exit;
  // Services of an install being moved run from the previous folder.
  Result := StopServices(App);
  if (Result = '') and not SameDir(App, PreviousAppDir) and (PreviousAppDir <> '') then
    Result := StopServices(PreviousAppDir);
  if Result <> '' then Exit;
  // Lock the folder before any file is copied into it: SYSTEM and Administrators
  // may change it, Users may only read and run it. Program Files is like this
  // already; C:\LightHouse or a folder on another drive is not.
  if not ForceDirectories(App) or not RunIcacls('"' + App + '" /reset')
     or not RunIcacls('"' + App + '" /inheritance:r /grant:r *S-1-5-18:(OI)(CI)F *S-1-5-32-544:(OI)(CI)F *S-1-5-32-545:(OI)(CI)RX')
     or not RunIcacls('"' + App + '" /setowner *S-1-5-32-544') then begin
    Result := 'Could not set permissions on ' + App + '. Choose a folder on an internal NTFS drive.';
    Exit;
  end;
  // Re-checked once locked, so nothing can have been added in between.
  if not SafeTarget(App) and not SameDir(App, PreviousAppDir) then
    Result := 'This folder already contains other files. Choose an empty or new folder for LightHouse.';
end;
procedure CurStepChanged(CurStep: TSetupStep);
var Code: Integer; Args: String; FailureDetail: AnsiString; Detail: String;
begin
  if CurStep = ssPostInstall then begin
    SetupFailed := True;
    // Two short lines: each label is a single line and clipped, not wrapped.
    WizardForm.StatusLabel.Caption := 'Setting up the sensors and the local AI...';
    WizardForm.FilenameLabel.Caption := 'The AI model is about 2.5 GB. This can take several minutes.';
    // Data lives in the install folder's data subfolder, on the drive the owner chose.
    Args := '-NoProfile -ExecutionPolicy Bypass -File "' + ExpandConstant('{app}\setup\install.ps1') + '" -AppDir "' + RemoveBackslash(ExpandConstant('{app}')) + '"'
      + ' -DataDir "' + ExpandConstant('{app}\data') + '"';
    if (PreviousAppDir <> '') and not SameDir(PreviousAppDir, ExpandConstant('{app}')) then
      Args := Args + ' -PreviousAppDir "' + RemoveBackslash(PreviousAppDir) + '"';
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
      RaiseException('LightHouse setup is incomplete. ' + Detail + 'See ' + ExpandConstant('{app}\data\logs\install.log') + '. Correct the error and rerun this installer.');
    end;
    SetupFailed := False;
  end;
end;
