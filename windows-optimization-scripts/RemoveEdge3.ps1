#Requires -Version 5.0

<#
Este comando muda a política de execução para todos os usuários do computador de forma permanente.
Set-ExecutionPolicy Unrestricted -Scope LocalMachine

Este comando muda a política de execução apenas para o usuário atual de forma permanente.
Set-ExecutionPolicy Unrestricted -Scope CurrentUser

Este comando muda a política de execução apenas para a sessão atual do PowerShell.
Set-ExecutionPolicy Unrestricted -Scope Process

.LINK
	https://github.com/he3als/EdgeRemover
#>

param (
	[switch]$RemoveEdgeData,
	[switch]$KeepAppX
)

$version = '1.9.5'

$ProgressPreference = 'SilentlyContinue'
$sys32 = [Environment]::GetFolderPath('System')
$windir = [Environment]::GetFolderPath('Windows')
$env:path = "$windir;$sys32;$sys32\Wbem;$sys32\WindowsPowerShell\v1.0;" + $env:path
$baseKey = 'HKLM:\SOFTWARE' + $(if ([Environment]::Is64BitOperatingSystem) { '\WOW6432Node' }) + '\Microsoft'
$msedgeExe = "$([Environment]::GetFolderPath('ProgramFilesx86'))\Microsoft\Edge\Application\msedge.exe"
$edgeUWP = "$windir\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe"

function Pause ($message = 'Pressione Enter para sair') {
	$null = Read-Host $message
}

enum LogLevel {
	Success
	Info
	Warning
	Error
	Critical
}
function Write-Status {
	param (
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[string]$Text,
		[LogLevel]$Level = 'Info',
		[switch]$Exit,
		[string]$ExitString = 'Pressione Enter para sair',
		[int]$ExitCode = 1
	)

	$colour = @(
		'Green',
		'White',
		'Yellow',
		'Red',
		'Red'
	)[$([LogLevel].GetEnumValues().IndexOf($Level))]

	$Text -split "`n" | ForEach-Object {
		Write-Host "[$($Level.ToString().ToUpper())] $_" -ForegroundColor $colour
	}

	if ($Exit) {
		Write-Output ''
		Pause $ExitString
		exit $ExitCode
	}
}

function InternetCheck {
	try {
		Invoke-WebRequest -Uri 'https://www.microsoft.com/robots.txt' -Method GET -TimeoutSec 10 -ErrorAction Stop | Out-Null
	} catch {
		Write-Status "Failed to reach Microsoft.com via web request. You must have an internet connection to reinstall Edge and its components.`n$($_.Exception.Message)" -Level Critical -Exit -ExitCode 404
	}
}

function DeleteIfExist($Path) {
	if (Test-Path $Path) {
		Remove-Item -Path $Path -Force -Recurse -Confirm:$false
	}
}

function Get-MsiexecAppByName {
	param(
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[string]$Name
	)

	$uninstallKeyPath = 'Microsoft\Windows\CurrentVersion\Uninstall'
	$uninstallKeys = (Get-ChildItem -Path @(
			"HKLM:\SOFTWARE\$uninstallKeyPath",
			"HKLM:\SOFTWARE\WOW6432Node\$uninstallKeyPath",
			"HKCU:\SOFTWARE\$uninstallKeyPath",
			"HKCU:\SOFTWARE\WOW6432Node\$uninstallKeyPath"
		) -EA SilentlyContinue) -match '\{\b[A-Fa-f0-9]{8}(?:-[A-Fa-f0-9]{4}){3}-[A-Fa-f0-9]{12}\b\}'

	$edges = @()
	foreach ($key in $uninstallKeys.PSPath) {
		if (((Get-ItemProperty -Path $key).DisplayName -like "*$Name*") -and ((Get-ItemProperty -Path $key).UninstallString -like '*MsiExec.exe*')) {
			$edges += Split-Path -Path $key -Leaf
		}
	}

	return $edges
}

# True if it's installed
function EdgeInstalled {
	Test-Path $msedgeExe
}

function KillEdgeProcesses {
	$ErrorActionPreference = 'SilentlyContinue'
	foreach ($service in (Get-Service -Name '*edge*' | Where-Object { $_.DisplayName -like '*Microsoft Edge*' }).Name) {
		Stop-Service -Name $service -Force
	}
	foreach (
		$process in
		(Get-Process | Where-Object { ($_.Path -like "$([Environment]::GetFolderPath('ProgramFilesX86'))\Microsoft\*") -or ($_.Name -like '*msedge*') }).Id
	) {
		Stop-Process -Id $process -Force
	}
	$ErrorActionPreference = 'Continue'
}

function RemoveEdgeChromium([bool]$AlreadyUninstalled) {
	Write-Status -Text 'Tentando encontrar desinstaladores do Edge...'

	# get Edge MsiExec uninstallers
	# commonly installed with WinGet (it installs the Enterprise MSI)
	$msis = Get-MsiexecAppByName -Name 'Microsoft Edge'

	# find using common locations - used as a backup
	function UninstallStringFail {
		if ($msis.Count -le 0) {
			Write-Status -Text "Não foi possível analisar a string de desinstalação do Edge. Tentando encontrar o desinstalador manualmente." -Level Warning
		}

		$script:edgeUninstallers = @()
		'LocalApplicationData', 'ProgramFilesX86', 'ProgramFiles' | ForEach-Object {
			$folder = [Environment]::GetFolderPath($_)
			$script:edgeUninstallers += Get-ChildItem "$folder\Microsoft\Edge*\setup.exe" -Recurse -EA 0 |
				Where-Object { ($_ -like '*Edge\Application*') -or ($_ -like '*SxS\Application*') }
			}
		}

		# find using Registry
		$uninstallKeyPath = "$baseKey\Windows\CurrentVersion\Uninstall\Microsoft Edge"
		$uninstallString = (Get-ItemProperty -Path $uninstallKeyPath -EA 0).UninstallString
		if ([string]::IsNullOrEmpty($uninstallString) -and ($msis.Count -le 0)) {
			$uninstallString = $null
			UninstallStringFail
		} else {
			# split uninstall string for path & args
			$uninstallPath, $uninstallArgs = $uninstallString -split '"', 3 |
				Where-Object { $_ } |
				ForEach-Object { [System.Environment]::ExpandEnvironmentVariables($_.Trim()) }

		# check if fully qualified (should normally be), otherwise it could be null or something in the working dir
		if (![System.IO.Path]::IsPathRooted($uninstallPath) -or !(Test-Path $uninstallPath -PathType Leaf)) {
			$uninstallPath = $null
			UninstallStringFail
		}
	}

	# throw if installers aren't found
	if (($msis.Count -le 0) -and ($script:edgeUninstallers.Count -le 0) -and !$uninstallPath) {
		$uninstallError = @{
			Text     = 'Não foi possível encontrar o desinstalador! ' + $(if ($AlreadyUninstalled) {
					'Isso provavelmente significa que o Edge já está desinstalado.'
				} else {
					"A desinstalação não pode continuar. :("
				})
			Level    = if ($AlreadyUninstalled) { 'Warning' } else { 'Critical' }
			Exit     = $true
			ExitCode = 2
		}
		Write-Status @uninstallError
	} else {
		Write-Status 'Desinstaladores do Edge encontrados.'
	}

	# toggles an EU region - this is because anyone in the EEA can uninstall Edge
	# this key is checked by the Edge uninstaller
	function ToggleEURegion([bool]$Enable) {
		$geoKey = 'Registry::HKEY_USERS\.DEFAULT\Control Panel\International\Geo'

		# sets Geo to France, which is in the EEA
		$values = @{
			'Name'   = 'FR'
			'Nation' = '84'
		}
		$geoChange = 'EdgeSaved'

		if ($Enable) {
			$values.GetEnumerator() | ForEach-Object {
				Rename-ItemProperty -Path $geoKey -Name $_.Key -NewName "$($_.Key)$geoChange" -Force
				Set-ItemProperty -Path $geoKey -Name $_.Key -Value $_.Value -Force
			}
		} else {
			$values.GetEnumerator() | ForEach-Object {
				Remove-ItemProperty -Path $geoKey -Name $_.Key -Force -EA 0
				Rename-ItemProperty -Path $geoKey -Name "$($_.Key)$geoChange" -NewName $_.Key -Force -EA 0
			}
		}
	}

	function ModifyRegionJSON {
		$cleanup = $false
		$script:integratedServicesPath = "$sys32\IntegratedServicesRegionPolicySet.json"

		if (Test-Path $integratedServicesPath) {
			$cleanup = $true
			try {
				$admin = [System.Security.Principal.NTAccount]$(New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')).Translate([System.Security.Principal.NTAccount]).Value

				# get perms (normally TrustedInstaller only)
				$acl = Get-Acl -Path $integratedServicesPath
				$script:backup = [System.Security.AccessControl.FileSecurity]::new()
				$script:backup.SetSecurityDescriptorSddlForm($acl.Sddl)
				# full control
				$acl.SetOwner($admin)
				$rule = New-Object System.Security.AccessControl.FileSystemAccessRule($admin, 'FullControl', 'Allow')
				$acl.AddAccessRule($rule)
				# set modified ACL
				Set-Acl -Path $integratedServicesPath -AclObject $acl

				# modify the stuff
				$integratedServices = Get-Content $integratedServicesPath | ConvertFrom-Json
				($integratedServices.policies | Where-Object { ($_.'$comment' -like '*Edge*') -and ($_.'$comment' -like '*uninstall*') }).defaultState = 'enabled'
				$modifiedJson = $integratedServices | ConvertTo-Json -Depth 100

				$script:backupIntegratedServicesName = "IntegratedServicesRegionPolicySet.json.$([System.IO.Path]::GetRandomFileName())"
				Rename-Item $integratedServicesPath -NewName $script:backupIntegratedServicesName -Force
				Set-Content $integratedServicesPath -Value $modifiedJson -Force -Encoding UTF8
			} catch {
				Write-Error "Failed to modify region policies. $_"
			}
		} else {
			Write-Status -Text "'$integratedServicesPath' not found." -Level Warning
		}

		return $cleanup
	}


	# Edge uninstalling logic
	function UninstallEdge {
		# MSI packages have to be uninstalled first, otherwise it breaks
		foreach ($msi in $msis) {
			Write-Status 'Desinstalando Edge usando o Windows Installer...'
			Start-Process -FilePath 'msiexec.exe' -ArgumentList "/qn /X$(Split-Path -Path $msi -Leaf) REBOOT=ReallySuppress /norestart" -Wait
		}

		# uninstall standard Edge installs
		if ($uninstallPath) {
			# found from Registry
			Start-Process -Wait -FilePath $uninstallPath -ArgumentList "$uninstallArgs --force-uninstall" -WindowStyle Hidden
		} else {
			# found from system files
			foreach ($setup in $edgeUninstallers) {
				if (Test-Path $setup) {
					$sulevel = ('--system-level', '--user-level')[$setup -like '*\AppData\Local\*']
					Start-Process -Wait $setup -ArgumentList "--uninstall --msedge $sulevel --channel=stable --verbose-logging --force-uninstall"
				}
			}
		}

		# return if Edge is installed or not
		return EdgeInstalled
	}

	# things that should always be done before uninstall
	function GlobalRemoveMethods {
		Write-Status "Usando o método $method..." -Level Warning

		# delete experiment_control_labels for key that prevents (or prevented) uninstall
		Remove-ItemProperty -Path "$baseKey\EdgeUpdate\ClientState\{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}" -Name 'experiment_control_labels' -Force -EA 0

		# allow Edge uninstall
		$devKeyPath = "$baseKey\EdgeUpdateDev"
		if (!(Test-Path $devKeyPath)) { New-Item -Path $devKeyPath -ItemType 'Key' -Force | Out-Null }
		Set-ItemProperty -Path $devKeyPath -Name 'AllowUninstall' -Value '' -Type String -Force

		Write-Status 'Encerrando processos do Microsoft Edge...'
		KillEdgeProcesses
	}

	# go through each uninstall method
	# yes, i'm aware this seems excessive, but i'm just trying to make sure it works on the most installs possible
	# it does bloat the script lots though... i'll clean it up in a future release, but for now, i'm just fixing it
	$fail = $true
	$method = 1
	function CleanupMsg { Write-Status "Limpando após o método $method..." }
	while ($fail) {
		switch ($method) {
			# makes Edge think the old legacy UWP is still installed
			# seems to fail on some installs?
			1 {
				GlobalRemoveMethods
				if (!(Test-Path "$edgeUWP\MicrosoftEdge.exe")) {
					New-Item $edgeUWP -ItemType Directory -ErrorVariable cleanup -EA 0 | Out-Null
					New-Item "$edgeUWP\MicrosoftEdge.exe" -EA 0 | Out-Null
					$cleanup = $true
				}

				# attempt uninstall
				$fail = UninstallEdge

				if ($cleanup) {
					CleanupMsg
					Remove-Item $edgeUWP -Force -EA 0 -Recurse
				}
			}

			# not having windir defined is a condition to allow uninstall
			# found in the strings of the setup ^
			2 {
				GlobalRemoveMethods
				$envPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
				try {
					# delete windir variable temporarily
					Set-ItemProperty -Path $envPath -Name 'windir' -Value '' -Type ExpandString
					$env:windir = [System.Environment]::GetEnvironmentVariable('windir', [System.EnvironmentVariableTarget]::Machine)

					# attempt uninstall
					$fail = UninstallEdge
				} finally {
					CleanupMsg
					# this is the default
					Set-ItemProperty -Path $envPath -Name 'windir' -Value '%SystemRoot%' -Type ExpandString
				}
			}

			# changes region in Registry
			# currently not known to work, kept for legacy reasons
			3 {
				GlobalRemoveMethods
				ToggleEURegion $true

				$fail = UninstallEdge

				CleanupMsg
				ToggleEURegion $false
			}

			# modifies IntegratedServicesRegionPolicySet to add current region to allow list
			# currently not known to work, kept for legacy reasons
			4 {
				GlobalRemoveMethods
				$cleanup = ModifyRegionJSON

				# attempt uninstall
				$fail = UninstallEdge

				# cleanup
				if ($cleanup) {
					CleanupMsg
					Remove-Item $integratedServicesPath -Force
					Rename-Item "$sys32\$backupIntegratedServicesName" -NewName $integratedServicesPath -Force
					Set-Acl -Path $integratedServicesPath -AclObject $backup
				}
			}

			# everything fails ╰（‵□′）╯
			default {
				Write-Status 'Não foi possível desinstalar o Microsoft Edge. O desinstalador não foi encontrado ou falhou.' -Level Critical -Exit -ExitCode 3
			}
		}

		$method++
	}
	Write-Status 'Microsoft Edge desinstalado com sucesso.' -Level Success

	# remove old shortcuts
	"$([Environment]::GetFolderPath('Desktop'))\Microsoft Edge.lnk",
	"$([Environment]::GetFolderPath('CommonStartMenu'))\Microsoft Edge.lnk" | ForEach-Object { DeleteIfExist $_ }

	# restart explorer if Copilot is enabled - this will hide the Copilot button
	if ((Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'ShowCopilotButton' -EA 0).'ShowCopilotButton' -eq 1) {
		Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
	}
}

function RemoveEdgeAppX {
	# i'm aware of how this is deprecated
	# kept for legacy purposes just in case someone's using an older build of Windows

	$SID = (New-Object System.Security.Principal.NTAccount([Environment]::UserName)).Translate([Security.Principal.SecurityIdentifier]).Value

	# remove from Registry
	$appxStore = '\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore'
	$pattern = "HKLM:$appxStore\InboxApplications\Microsoft.MicrosoftEdge_*_neutral__8wekyb3d8bbwe"
	$edgeAppXKey = (Get-Item -Path $pattern).PSChildName
	if (Test-Path "$pattern") { reg delete "HKLM$appxStore\InboxApplications\$edgeAppXKey" /f | Out-Null }

	# make the Edge AppX able to uninstall and uninstall
	New-Item -Path "HKLM:$appxStore\EndOfLife\$SID\Microsoft.MicrosoftEdge_8wekyb3d8bbwe" -Force | Out-Null
	Get-AppxPackage -Name Microsoft.MicrosoftEdge | Remove-AppxPackage | Out-Null
	Remove-Item -Path "HKLM:$appxStore\EndOfLife\$SID\Microsoft.MicrosoftEdge_8wekyb3d8bbwe" -Force | Out-Null
}

# SYSTEM check - using SYSTEM previously caused issues
if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -eq 'S-1-5-18') {
	Write-Status "Este script não pode ser executado como TrustedInstaller/SYSTEM.
Por favor, execute este script em uma conta de administrador normal." -Level Critical -Exit
} else {
	if (!([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
		if ($PSBoundParameters.Count -le 0 -and !$args) {
			Start-Process cmd "/c PowerShell -NoP -EP Bypass -File `"$PSCommandPath`"" -Verb RunAs
			exit
		} else {
			throw 'Este script deve ser executado como administrador.'
		}
	}
}

$edgeInstalled = EdgeInstalled
Write-Status 'Desinstalando Edge Chromium...'
RemoveEdgeChromium $(!$edgeInstalled)
if ($null -ne (Get-AppxPackage -Name Microsoft.MicrosoftEdge)) {
	if ($KeepAppX) {
		Write-Status 'O AppX Edge está sendo deixado, pode haver um stub...' -Level Warning
	} else {
		Write-Status 'Desinstalando AppX Edge...' -Level Warning
		RemoveEdgeAppx
	}
}
Write-Output ''


if ($RemoveEdgeData) {
	KillEdgeProcesses
	DeleteIfExist "$([Environment]::GetFolderPath('LocalApplicationData'))\Microsoft\Edge"
	Write-Status 'Dados de usuário existentes do Edge Chromium foram removidos.'
	Write-Output ''
}

Write-Host 'Desinstalação concluída.' -ForegroundColor Cyan
Pause