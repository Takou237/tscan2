; ----------------------------------------------------------------------------
; Script Inno Setup — Installeur Windows de Tscan
;
; Prérequis : Inno Setup 6.x (https://jrsoftware.org/isinfo.php).
; Compiler avec : ISCC.exe installer\tscan.iss
;   ou l'IDE Inno Setup : ouvrir ce fichier puis Build > Compile.
; Sortie : installer\Output\tscan-0.1.0-setup.exe
;
; Choix de conception : installation PAR UTILISATEUR (sans droits
; administrateur), comme VS Code — dossier {localappdata}\Programs\Tscan,
; PATH utilisateur. Simplifie le test sur machine propre et évite l'UAC.
;
; Les exécutables doivent être reconstruits avant compilation :
;   .venv\Scripts\python.exe -m PyInstaller tscan.spec --noconfirm
; ----------------------------------------------------------------------------

#define MyAppName "Tscan"
#define MyAppVersion "0.1.0"
#define MyAppPublisher "ANTIC"
#define MyAppExeName "tscan-gui.exe"
#define MyAppCliName "tscan.exe"

[Setup]
AppId={{D4F5A1B2-3C6E-4F70-9A8B-1C2D3E4F5A6B}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={localappdata}\Programs\Tscan
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
; Icône de l'installeur (identique aux exécutables)
SetupIconFile=..\assets\tscan.ico
UninstallDisplayIcon={app}\{#MyAppExeName}
OutputDir=Output
OutputBaseFilename=tscan-{#MyAppVersion}-setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
; Installation par utilisateur : pas d'élévation requise
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog

[Languages]
Name: "french"; MessagesFile: "compiler:Languages\French.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "addpath"; Description: "Ajouter la CLI (tscan.exe) au PATH utilisateur"; GroupDescription: "Intégration :"; Flags: checkedonce

[Files]
Source: "..\dist\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\dist\{#MyAppCliName}"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
; Application desktop dans le menu Démarrer
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
; CLI : ouvre une invite de commandes positionnée dans le dossier d'installation
Name: "{group}\{#MyAppName} (invite de commandes)"; Filename: "{cmd}"; Parameters: "/k cd /d {app}"; Comment: "Ouvre une console où tscan est disponible"
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"
Name: "{userdesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#MyAppName}}"; Flags: nowait postinstall skipifsilent

[Code]
const
  WM_SETTINGCHANGE = $001A;
  // HWND_BROADCAST ($FFFF) est déjà défini par Inno Setup — ne pas redéclarer.

// Diffuse le changement d'environnement pour que les nouvelles consoles
// (et l'Explorateur) prennent en compte le PATH mis à jour sans redémarrer.
procedure EnvChanged;
begin
  SendMessage(HWND_BROADCAST, WM_SETTINGCHANGE, 0, 0);
end;

function GetCurrentUserPath: string;
begin
  if not RegQueryStringValue(HKEY_CURRENT_USER, 'Environment', 'Path', Result) then
    Result := '';
end;

procedure SetCurrentUserPath(Value: string);
begin
  RegWriteExpandStringValue(HKEY_CURRENT_USER, 'Environment', 'Path', Value);
end;

procedure AddToPath(Dir: string);
var
  Current, Updated: string;
begin
  Current := GetCurrentUserPath;
  if Pos(';' + Uppercase(Dir) + ';', ';' + Uppercase(Current) + ';') > 0 then
    Exit; // déjà présent
  if Current = '' then
    Updated := Dir
  else if Copy(Current, Length(Current), 1) = ';' then
    Updated := Current + Dir
  else
    Updated := Current + ';' + Dir;
  SetCurrentUserPath(Updated);
  EnvChanged;
end;

procedure RemoveFromPath(Dir: string);
var
  Current, Updated: string;
begin
  if not RegQueryStringValue(HKEY_CURRENT_USER, 'Environment', 'Path', Current) then
    Exit;
  Updated := ';' + Current + ';';
  StringChangeEx(Updated, ';' + Dir + ';', ';', False);
  // Nettoyage des séparateurs doublés ou en bordure
  while Pos(';;', Updated) > 0 do
    StringChangeEx(Updated, ';;', ';', False);
  if Copy(Updated, 1, 1) = ';' then
    Delete(Updated, 1, 1);
  if Copy(Updated, Length(Updated), 1) = ';' then
    Delete(Updated, Length(Updated), 1);
  if Updated <> Current then
  begin
    SetCurrentUserPath(Updated);
    EnvChanged;
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
    if WizardIsTaskSelected('addpath') then
      AddToPath(ExpandConstant('{app}'));
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  // Retire {app} du PATH utilisateur (sans effet s'il n'y est pas).
  if CurUninstallStep = usUninstall then
    RemoveFromPath(ExpandConstant('{app}'));
end;
