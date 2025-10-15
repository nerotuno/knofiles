# Adb & Fastboot Installer
### PowerShell Script for Windows 10/11
This scrpit is going to download and config platform-tools and Google USB Driver as Environment Variable.

Steps:
1. Run PowerShell as Admnistrator
2. Execute the following commands:

```
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/nerotuno/knofiles/main/adb/adb-usb-driver.ps1" -OutFile "C:\adb-usb-driver.ps1"
```
```
Powershell.exe -ExecutionPolicy RemoteSigned -File  "C:\adb-usb-driver.ps1"
```
3. Go to Windows Update and check for "Optional Updates"
4. Enjoy :)

# Add adb variable in windows
### PowerShell Script for Windows 10/11
This script will add the ADB variable in windows.

Steps:
1. Run PowerShell as Admnistrator
2. Execute the following commands:

```
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/nerotuno/knofiles/main/adb/variable_adb_windows.ps1" -OutFile "C:\variable_adb_windows.ps1"
```
```
Powershell.exe -ExecutionPolicy RemoteSigned -File  "C:\variable_adb_windows.ps1"
```
3. Enjoy :)
