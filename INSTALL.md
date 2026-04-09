# ScanXSS v1.3.1 — Installation

## Linux
```bash
cd linux
sudo apt install build-essential libcurl4-openssl-dev libssl-dev
make && make test
./scanxss -u https://target.com/
```

## macOS (GUI + CLI)
```bash
cd macos
sudo bash INSTALL.sh
```

## Windows
```
windows/installer/scanxss-setup.exe
```
Run as Administrator. The installer will:
1. Install the root CA certificate (RootBSD-CA.cer) to Trusted Root store
2. Install ScanXSS to C:\Program Files\ScanXSS\

If Windows Defender blocks the installer before it runs:
```powershell
# Run PowerShell as Administrator:
certutil -addstore -f "Root" "windows\installer\RootBSD-CA.cer"
# Then run the installer
```

## Code Signing
Both `scanxss-gui.exe` and `scanxss-setup.exe` are signed with:
- Certificate: ScanXSS Web Vulnerability Scanner
- Issuer: root_bsd CA
- Valid: 2026–2036
