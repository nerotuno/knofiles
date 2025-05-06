# Adb & Fastboot Instalador
### PowerShell Script para Windows 10/11
Este script irá baixar e configurar as ferramentas do ADB e o driver USB do Google como variável de ambiente.

Passos:
1. Execute o PowerShell como administrador
2. Execute os seguintes comandos:

```
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/nerotuno/knofiles/main/adb/adb-usb-driver.ps1" -OutFile "C:\adb-usb-driver.ps1"
```
```
Powershell.exe -ExecutionPolicy RemoteSigned -File  "C:\adb-usb-driver.ps1"
```
3. Aproveite :)

### Distribuições baseadas em ArchLinux
Passos:
1. Open a Console/Terminal window
2. Execute the following command:

```
sudo pacman -S android-tools
```
3. Aproveite :)
