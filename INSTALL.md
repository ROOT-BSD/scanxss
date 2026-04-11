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
cd macos && sudo bash INSTALL.sh
```

## Windows
Run `windows/installer/scanxss-setup.exe` as Administrator.

If Defender blocks installer:
```powershell
certutil -addstore -f "Root" "windows\installer\RootBSD-CA.cer"
```
Then run the installer.
