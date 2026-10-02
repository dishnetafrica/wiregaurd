; DishNet Secure Connect — Windows installer (Inno Setup 6)
;
; Build (CI does this): ISCC.exe /DAppVersion=0.1.0 /DPublishDir=..\publish /DWireGuardMsi=..\wireguard-amd64.msi DishNetSecureConnect.iss
;
; What it does:
;   1. Installs the DishNet app (self-contained .NET, no runtime needed).
;   2. Installs the official WireGuard for Windows package silently if absent
;      (provides the signed tunnel driver and the tunnel service host).
;   3. On uninstall: removes the DishNet tunnel service and the device identity.
;      The WireGuard package itself is left in place (it may serve other tunnels);
;      it can be removed from "Apps & features".

#ifndef AppVersion
  #define AppVersion "0.1.0"
#endif
#ifndef PublishDir
  #define PublishDir "..\publish"
#endif
#ifndef WireGuardMsi
  #define WireGuardMsi "..\wireguard-amd64.msi"
#endif

[Setup]
AppId={{7B1C2E64-5F0E-4D1B-9C1F-DISHNETSC001}
AppName=DishNet Secure Connect
AppVersion={#AppVersion}
AppVerName=DishNet Secure Connect {#AppVersion}
AppPublisher=DishNet Africa
AppPublisherURL=https://dishnetuganda.com
AppSupportURL=https://dishnetuganda.com
DefaultDirName={autopf}\DishNet\Secure Connect
DefaultGroupName=DishNet
DisableProgramGroupPage=yes
OutputDir=output
OutputBaseFilename=DishNetSecureConnect-Setup-{#AppVersion}
Compression=lzma2/max
SolidCompression=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
MinVersion=10.0.14393
WizardStyle=modern
UninstallDisplayIcon={app}\DishNetSecureConnect.exe
SetupIconFile=..\src\DishNet.SecureConnect.App\Assets\dishnet.ico
LicenseFile=THIRD-PARTY-NOTICES.txt
CloseApplications=yes
RestartApplications=no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Messages]
WelcomeLabel2=This will install DishNet Secure Connect on your computer.%n%nIt gives this computer secure access to your office server through DishNet. Windows will ask for administrator permission because a secure tunnel service has to be installed.

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional icons:"

[Files]
Source: "{#PublishDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#WireGuardMsi}"; DestDir: "{tmp}"; DestName: "wireguard.msi"; Flags: deleteafterinstall
Source: "THIRD-PARTY-NOTICES.txt"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\DishNet Secure Connect"; Filename: "{app}\DishNetSecureConnect.exe"
Name: "{autodesktop}\DishNet Secure Connect"; Filename: "{app}\DishNetSecureConnect.exe"; Tasks: desktopicon

[Run]
; Official WireGuard package: silent, no UI launched. DO_NOT_LAUNCH keeps its own window from opening.
Filename: "msiexec.exe"; Parameters: "/i ""{tmp}\wireguard.msi"" /qn /norestart DO_NOT_LAUNCH=1"; StatusMsg: "Installing the secure tunnel component (WireGuard)..."; Check: not WireGuardInstalled; Flags: runhidden waituntilterminated
Filename: "{app}\DishNetSecureConnect.exe"; Description: "Open DishNet Secure Connect now"; Flags: nowait postinstall skipifsilent shellexec

[UninstallRun]
Filename: "{pf}\WireGuard\wireguard.exe"; Parameters: "/uninstalltunnelservice DishNetOffice"; Flags: runhidden waituntilterminated; RunOnceId: "RemoveTunnel"

[UninstallDelete]
Type: filesandordirs; Name: "{commonappdata}\DishNet\SecureConnect"

[Code]
function WireGuardInstalled(): Boolean;
begin
  Result := FileExists(ExpandConstant('{pf}\WireGuard\wireguard.exe'));
end;

function InitializeUninstall(): Boolean;
begin
  Result := MsgBox('Uninstalling will remove this computer''s DishNet access. You will need a new activation code to use it again. Continue?', mbConfirmation, MB_YESNO) = IDYES;
end;
