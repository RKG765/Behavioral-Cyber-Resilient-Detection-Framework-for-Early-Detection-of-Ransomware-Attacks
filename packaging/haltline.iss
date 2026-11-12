; Haltline installer (plan 5.6), built by packaging\build.ps1:  ISCC /DAppVersion=x.y.z packaging\haltline.iss
; Installs the Nuitka builds, registers the HaltlineAgent service (LocalSystem, auto-start), then runs
; install_windows.ps1 -Packaged for Sysmon (downloaded from Microsoft, signature checked), the ask-mode
; folders and the helper's logon task. The privacy notice is the "I accept" page.
#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif

[Setup]
AppId={{6F4C1E2A-8B7D-4C5E-9A3F-2D1B0E8C7A64}
AppName=Haltline
AppVersion={#AppVersion}
AppPublisher=Haltline
VersionInfoVersion={#AppVersion}
DefaultDirName={autopf}\Haltline
DisableDirPage=yes
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
OutputDir=..\build
OutputBaseFilename=Haltline-Setup-{#AppVersion}
LicenseFile=..\PRIVACY.md
Compression=lzma2/max
SolidCompression=yes
CloseApplications=force
RestartApplications=no
UninstallDisplayName=Haltline
WizardStyle=modern
SetupIconFile=haltline.ico
UninstallDisplayIcon={app}\haltline-helper.exe

[Files]
Source: "..\build\nuitka\haltline_service.dist\*"; DestDir: "{app}"; Flags: recursesubdirs createallsubdirs ignoreversion
Source: "..\build\nuitka\telltale_helper.dist\*"; DestDir: "{app}"; Flags: recursesubdirs createallsubdirs ignoreversion
Source: "..\install_windows.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\edr_sensor\live\sysmon_edr.xml"; DestDir: "{app}\edr_sensor\live"; Flags: ignoreversion
Source: "..\PRIVACY.md"; DestDir: "{app}"; Flags: ignoreversion

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Shortcuts:"

[Icons]
; "Haltline" in Start (and Start search) and optionally on the desktop: opens the window, or offers to
; start Haltline again when it was stopped. The tray itself also starts at every sign-in (helper task).
Name: "{autoprograms}\Haltline"; Filename: "{app}\haltline-helper.exe"; Parameters: "--open"; WorkingDir: "{app}"; Comment: "Haltline ransomware protection"
Name: "{autodesktop}\Haltline"; Filename: "{app}\haltline-helper.exe"; Parameters: "--open"; WorkingDir: "{app}"; Tasks: desktopicon

[Run]
; Show the tray icon now instead of at the next sign-in (not on silent auto-updates).
Filename: "{app}\haltline-helper.exe"; WorkingDir: "{app}"; Description: "Show the Haltline icon"; Flags: nowait postinstall runasoriginaluser skipifsilent

[InstallDelete]
; Logs used to live here, readable by every user; 0.2.2+ logs to ProgramData\Telltale (admins only).
Type: files; Name: "{app}\agent.log*"

[UninstallDelete]
Type: files; Name: "{app}\agent.log*"
Type: files; Name: "{commonappdata}\Telltale\agent.log*"
Type: files; Name: "{app}\whitelist.db"

[Code]
const
  Svc = 'HaltlineAgent';
  SvcKey = 'SYSTEM\CurrentControlSet\Services\HaltlineAgent';

var
  LicencePage: TInputQueryWizardPage;
  OldLicence: String;

function Run(const Exe, Params: String): Integer;
begin
  if not Exec(Exe, Params, '', SW_HIDE, ewWaitUntilTerminated, Result) then
    Result := -1;
end;

function SC(const Params: String): Integer;
begin
  Result := Run(ExpandConstant('{sys}\sc.exe'), Params);
end;

function PS(const Params: String): Integer;
begin
  Result := Run(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'), '-NoProfile -ExecutionPolicy Bypass ' + Params);
end;

{ The licence key from an earlier install, so upgrades (including silent ones) keep it: the protected
  file first, then the registry Environment that versions up to 0.2.0 used. }
function ExistingLicence(): String;
var
  S: AnsiString;
  E: String;
  P: Integer;
begin
  Result := '';
  if LoadStringFromFile(ExpandConstant('{commonappdata}\Telltale\licence.key'), S) and (Trim(String(S)) <> '') then
  begin
    Result := Trim(String(S));
    Exit;
  end;
  if RegQueryMultiStringValue(HKLM, SvcKey, 'Environment', E) then
  begin
    P := Pos('EDR_LICENCE_KEY=', E);
    if P > 0 then
    begin
      E := Copy(E, P + Length('EDR_LICENCE_KEY='), Length(E));
      P := Pos(#0, E);
      if P > 0 then
        E := Copy(E, 1, P - 1);
      Result := E;
    end;
  end;
end;

procedure InitializeWizard();
begin
  OldLicence := ExistingLicence();
  LicencePage := CreateInputQueryPage(wpLicense, 'Licence key', 'Enter the licence key you were given.',
    'Haltline uses it once, to register this PC for cloud checks.');
  LicencePage.Add('Licence key:', False);
  LicencePage.Values[0] := OldLicence;
end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;
  if (CurPageID = LicencePage.ID) and (Trim(LicencePage.Values[0]) = '') then
  begin
    MsgBox('Please enter your licence key.', mbError, MB_OK);
    Result := False;
  end;
end;

{ Upgrades: stop the running service (Stop-Service waits for it) before its files are replaced. }
function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  PS('-Command "Stop-Service ' + Svc + ' -ErrorAction SilentlyContinue"');
  Result := '';
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  Licence: String;
begin
  if CurStep <> ssPostInstall then
    Exit;
  Licence := Trim(LicencePage.Values[0]);
  if Licence = '' then
    Licence := OldLicence;
  if SC('query ' + Svc) <> 0 then
    { The inner quotes matter: an unquoted path with spaces is a privilege-escalation hole. }
    SC('create ' + Svc + ' binPath= "\"' + ExpandConstant('{app}\haltline-agent.exe') + '\"" start= auto DisplayName= "Haltline Agent"');
  SC('description ' + Svc + ' "Behavioral ransomware detection: asks before stopping a threat."');
  SC('failure ' + Svc + ' reset= 86400 actions= restart/60000/restart/60000/restart/60000');
  { The registry Environment is readable by every local user, so the licence goes to a file instead. }
  RegWriteMultiStringValue(HKLM, SvcKey, 'Environment', 'EDR_MODE=ask');
  { -Packaged creates C:\ProgramData\Telltale readable by SYSTEM and Administrators only; the key inherits that. }
  PS('-File "' + ExpandConstant('{app}\install_windows.ps1') + '" -Packaged');
  if not SaveStringToFile(ExpandConstant('{commonappdata}\Telltale\licence.key'), Licence, False) then
    MsgBox('Could not save the licence key; Haltline will run without cloud checks.', mbError, MB_OK);
  SC('start ' + Svc);
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep <> usUninstall then
    Exit;
  PS('-Command "Stop-Service ' + Svc + ' -ErrorAction SilentlyContinue"');
  SC('delete ' + Svc);
  Run(ExpandConstant('{sys}\taskkill.exe'), '/IM haltline-helper.exe /F');
  PS('-File "' + ExpandConstant('{app}\install_windows.ps1') + '" -Uninstall');
  DeleteFile(ExpandConstant('{commonappdata}\Telltale\licence.key'));
end;
