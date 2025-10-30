; .github/installer.iss
[Setup]
AppName=QSafeVault
AppVersion={#MyAppVersion}
DefaultDirName={autopf}\QSafeVault
DefaultGroupName=QSafeVault
OutputBaseFilename=qsafevault-windows
Compression=lzma
SolidCompression=yes

[Files]
Source: "build\windows\x64\runner\Release\*"; DestDir: "{app}"; Flags: recursesubdirs

[Icons]
Name: "{group}\QSafeVault"; Filename: "{app}\qsafevault.exe"
Name: "{userdesktop}\QSafeVault"; Filename: "{app}\qsafevault.exe"
