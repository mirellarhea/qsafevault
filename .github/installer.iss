;Inno Setup Script for QSafeVault Windows Installer
#ifndef MyAppVersion
  #define MyAppVersion "1.0"
#endif

[Setup]
AppId={{QSAFEVAULT-A1B2-C3D4-E5F6-123456789ABC}
AppName=QSafeVault
AppVersion={#MyAppVersion}
AppPublisher=QSafeVault
DefaultDirName={autopf}\QSafeVault
DefaultGroupName=QSafeVault
AllowNoIcons=yes
OutputBaseFilename=qsafevault-windows
OutputDir=.
Compression=lzma
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64
PrivilegesRequired=lowest
UninstallDisplayIcon={app}\qsafevault.exe

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[Files]
Source: "build\windows\x64\runner\Release\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\QSafeVault"; Filename: "{app}\qsafevault.exe"
Name: "{group}\{cm:UninstallProgram,QSafeVault}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\QSafeVault"; Filename: "{app}\qsafevault.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\qsafevault.exe"; Description: "{cm:LaunchProgram,QSafeVault}"; Flags: nowait postinstall skipifsilent
