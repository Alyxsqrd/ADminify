<#┌──────────────────────────────────────────────────────────────────────────────────────────┐
  │ Initialization                                                                           │
  └──────────────────────────────────────────────────────────────────────────────────────────┘#>
	<#┌─────────────────────────────────────────────┐
	  │ Important Script Settings                   │
	  └─────────────────────────────────────────────┘#>
		# $ErrorActionPreference = "Stop"
		# Set-StrictMode -Version "Latest"

	<#┌─────────────────────────────────────────────┐
	  │ Set Working Directory                       │
	  └─────────────────────────────────────────────┘#>
		[Environment]::SystemDirectory | Set-Location

	<#┌─────────────────────────────────────────────┐
	  │ Load Windows Forms                          │
	  └─────────────────────────────────────────────┘#>
		Add-Type -AssemblyName System.Windows.Forms
		[Windows.Forms.Application]::EnableVisualStyles()

	<#┌─────────────────────────────────────────────┐
	  │ Variable Declarations                       │
	  └─────────────────────────────────────────────┘#>
		$Build = "4.0.2"
		$Admin = "slashpowered"

		$BackdoorUser = "CertiportAdmin"
		$BackdoorPass = "C3rt!p0r+"

		$global:HostsPath = "$env:WINDIR\System32\drivers\etc\hosts"
		$global:HostsContent = Get-Content -LiteralPath $global:HostsPath

	<#┌─────────────────────────────────────────────┐
	  │ Function Declarations                       │
	  └─────────────────────────────────────────────┘#>
		function Show-Popup {
			[CmdletBinding()]
			param (
				[Parameter(Mandatory)]
				[ValidateNotNullOrEmpty()]
				[string] $Message,

				[ValidateNotNullOrEmpty()]
				[ValidateSet("OK", "OKCancel", "AbortRetryIgnore", "YesNo", "YesNoCancel", "RetryCancel")]
				[string] $Options = "OK",

				[ValidateNotNullOrEmpty()]
				[ValidateSet("Error", "Question", "Warning", "Information")]
				[string] $Level = "Information"
			)

			switch ($Options) {
				"OK" {$ButtonValue = 0}
				"OKCancel" {$ButtonValue = 1}
				"AbortRetryIgnore" {$ButtonValue = 2}
				"YesNoCancel" {$ButtonValue = 3}
				"YesNo" {$ButtonValue = 4}
				"RetryCancel" {$ButtonValue = 5}
			}

			switch ($Level) {
				"Error" {$IconValue = 16}
				"Question" {$IconValue = 32}
				"Warning" {$IconValue = 48}
				"Information" {$IconValue = 64}
			}

			[Windows.Forms.MessageBox]::Show($this, "$Message", "ADminify Console (v$Build`)", $ButtonValue, $IconValue) > $null
		}

		function Add-HostsEntry {
			[CmdletBinding()]
			param (
				[Parameter(Mandatory)]
				[string] $Address,

				[Parameter(Mandatory)]
				[string] $Hostname
			)

			$EscapedHostname = [Regex]::Escape($Hostname)
			$PatternToMatch = ".*$Address\s+$EscapedHostname.*"

			if ($global:HostsContent -notmatch $PatternToMatch) {
				Add-Content -LiteralPath $global:HostsPath -Value "$Address	$Hostname" -Force
			}
		}


<#┌──────────────────────────────────────────────────────────────────────────────────────────┐
  │ Process Elevation                                                                        │
  └──────────────────────────────────────────────────────────────────────────────────────────┘#>
	$SecurePass = ConvertTo-SecureString -String $BackdoorPass -AsPlainText -Force
	$BackdoorAuth = New-Object -TypeName Management.Automation.PSCredential -ArgumentList "$env:COMPUTERNAME\$BackdoorUser", $SecurePass

	<#┌─────────────────────────────────────────────┐
	  │ Elevate the Console Process                 │
	  └─────────────────────────────────────────────┘#>
		if ([Environment]::UserName -ne $LocalUser) {
			try {
				Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -Command &{ Start-Process -FilePath 'PowerShell.exe' -ArgumentList '-NoProfile -Command &{ takeown.exe /R /A /F ''$PSScriptRoot'' /D N; icacls.exe ''$PSScriptRoot'' /grant ''Everyone:(OI)(CI)F'' /T /C; Start-Process -FilePath ''PowerShell.exe'' -ArgumentList ''-NoProfile -File $PSCommandPath -ExecutionPolicy Bypass'' }' -Verb RunAs -WindowStyle Hidden }" -Credential $BackdoorAuth -WindowStyle Hidden -ErrorAction Stop
			}
			catch {
				Show-Popup -Message "Failed to apply directory permissions. $_" -Level "Error"
			}

			Exit
		}


<#┌──────────────────────────────────────────────────────────────────────────────────────────┐
  │ Pre-Installation                                                                         │
  └──────────────────────────────────────────────────────────────────────────────────────────┘#>
	<#┌─────────────────────────────────────────────┐
	  │ Terminate Monitoring Processes              │
	  └─────────────────────────────────────────────┘#>
		# LanSchool Processes
			Stop-Process -Name "student" -Force -ErrorAction SilentlyContinue
			Stop-Process -Name "LskHelper" -Force -ErrorAction SilentlyContinue
			Stop-Process -Name "lskHlpr64" -Force -ErrorAction SilentlyContinue

		# Lightspeed Processes
			Stop-Process -Name "LMA" -Force -ErrorAction SilentlyContinue
			Stop-Process -Name "Capture" -Force -ErrorAction SilentlyContinue
			Stop-Process -Name "DesktopViewer" -Force -ErrorAction SilentlyContinue
			Stop-Process -Name "UserAction" -Force -ErrorAction SilentlyContinue
			Stop-Process -Name "UserAction32" -Force -ErrorAction SilentlyContinue

		# xdAD Processes
			Stop-Process -Name "xdADWSClient" -Force -ErrorAction SilentlyContinue
			Stop-Process -Name "xdADWSServer" -Force -ErrorAction SilentlyContinue

	<#┌─────────────────────────────────────────────┐
	  │ Check Installation Status                   │
	  └─────────────────────────────────────────────┘#>
		# If the slashpowered directory exists, prompt for selection. If not found, assume not installed.
			if (Test-Path -LiteralPath "$env:SYSTEMDRIVE\Users\$Admin") {
				$UpdatePrompt = Show-Popup -Message "ADminify is already installed on this machine.`nWould you like to update [Yes] or uninstall [No]?" -Options "YesNoCancel" -Level "Question"

				switch ($UpdatePrompt) {
					"Yes" {
						$InstallMode = "Update" # Run the uninstall, reinstall, then RESTART.
					}
					"No" {
						$InstallMode = "Uninstall" # Run the uninstall, then RESTART.
					}
					"Cancel" {
						$InstallMode = "Exit" # Make no system changes, then EXIT.
					}
				}
			}
			else {
				$InstallMode = "Install" # Runs the install, then RESTART.
			}

	<#┌─────────────────────────────────────────────┐
	  │ Create Temporary Folder                     │
	  └─────────────────────────────────────────────┘#>
		if (!(Test-Path -LiteralPath "$env:SYSTEMDRIVE\slashpowered")) {
			New-Item -Path "$env:SYSTEMDRIVE\" -Name "slashpowered" -ItemType Directory -Force > $null
		}

	<#┌─────────────────────────────────────────────┐
	  │ 7-Zip Initialization                        │
	  └─────────────────────────────────────────────┘#>
		if (Test-Path -LiteralPath "$env:PROGRAMFILES\7-Zip\7z.exe") {
			Set-Alias -Name "7z" -Value "$env:PROGRAMFILES\7-Zip\7z.exe"
		}
		elseif (Test-Path -LiteralPath "$env:PROGRAMFILES(x86)\7-Zip\7z.exe") {
			Set-Alias -Name "7z" -Value "$env:PROGRAMFILES(x86)\7-Zip\7z.exe"
		}
		else {
			Show-Popup -Message "Unable to find 7-Zip on this machine. $_" -Level "Error"
			Exit
		}


if ($InstallMode -eq "Uninstall" -or $InstallMode -eq "Update") {
<#┌──────────────────────────────────────────────────────────────────────────────────────────┐
  │ Uninstallation                                                                           │
  └──────────────────────────────────────────────────────────────────────────────────────────┘#>
	<#┌─────────────────────────────────────────────┐
	  │ Account Removal                             │
	  └─────────────────────────────────────────────┘#>
		Write-Host "[INFO] Removing slashpowered local account..."
			if (Get-LocalUser -Name $Admin -ErrorAction SilentlyContinue) {
				Remove-LocalUser -Name $Admin
			}

			if (Get-LocalUser -Name "$Admin.$env:COMPUTERNAME" -ErrorAction SilentlyContinue) {
				Remove-LocalUser -Name "$Admin.$env:COMPUTERNAME"
			}

		Write-Host "[INFO] Cleaning up leftover account data..."
			if (Get-CimInstance -Class Win32_UserProfile | Where-Object {$_.LocalPath.Split("\")[-1] -eq $Admin}) {
				Get-CimInstance -Class Win32_UserProfile | Where-Object {$_.LocalPath.Split("\")[-1] -eq $Admin} | Remove-CimInstance -ErrorAction SilentlyContinue
			}

			if (Get-CimInstance -Class Win32_UserProfile | Where-Object {$_.LocalPath.Split("\")[-1] -eq "$Admin.$env:COMPUTERNAME"}) {
				Get-CimInstance -Class Win32_UserProfile | Where-Object {$_.LocalPath.Split("\")[-1] -eq "$Admin.$env:COMPUTERNAME"} | Remove-CimInstance -ErrorAction SilentlyContinue
			}

	<#┌─────────────────────────────────────────────┐
	  │ Uninstall MeshCentral Agent                 │
	  └─────────────────────────────────────────────┘#>
		if (Test-Path -LiteralPath "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\MeshCentralAgent") {
			# Run the silent uninstaller.
				Start-Process -FilePath "$PSScriptRoot\Programs\MeshCentral\meshagent64.exe" -ArgumentList "-fulluninstall" -NoNewWindow -Wait
		}

	<#┌─────────────────────────────────────────────┐
	  │ Uninstall Psiphon VPN                       │
	  └─────────────────────────────────────────────┘#>
		if (Test-Path -LiteralPath "$env:PROGRAMFILES\Psiphon") {
			Remove-Item -LiteralPath "$env:PROGRAMFILES\Psiphon" -Recurse -Force
		}

	<#┌─────────────────────────────────────────────┐
	  │ Restore AppLocker Policies                  │
	  └─────────────────────────────────────────────┘#>
		Write-Host "[INFO] Checking for AppLocker bypass method..."

		# Gain access to AppLocker policies folder.
			takeown.exe /R /A /F "$env:WINDIR\System32\AppLocker" /D N > $null
			icacls.exe "$env:WINDIR\System32\AppLocker" /grant "Administrators:(OI)(CI)F" /T /C > $null

		# Restore AppLocker policies and remove (if existing) auto-restored ones.
			if (Test-Path -LiteralPath "$env:WINDIR\System32\AppLocker\Appx.AppLocker.slash" -PathType Leaf) {
				Remove-Item -LiteralPath "$env:WINDIR\System32\AppLocker\Appx.AppLocker" -Force -ErrorAction SilentlyContinue
				Rename-Item -LiteralPath "$env:WINDIR\System32\AppLocker\Appx.AppLocker.slash" -NewName "Appx.AppLocker" -Force
			}

			if (Test-Path -LiteralPath "$env:WINDIR\System32\AppLocker\Dll.AppLocker.slash" -PathType Leaf) {
				Remove-Item -LiteralPath "$env:WINDIR\System32\AppLocker\Dll.AppLocker" -Force -ErrorAction SilentlyContinue
				Rename-Item -LiteralPath "$env:WINDIR\System32\AppLocker\Dll.AppLocker.slash" -NewName "Dll.AppLocker" -Force
			}

			if (Test-Path -LiteralPath "$env:WINDIR\System32\AppLocker\Exe.AppLocker.slash" -PathType Leaf) {
				Remove-Item -LiteralPath "$env:WINDIR\System32\AppLocker\Exe.AppLocker" -Force -ErrorAction SilentlyContinue
				Rename-Item -LiteralPath "$env:WINDIR\System32\AppLocker\Exe.AppLocker.slash" -NewName "Exe.AppLocker" -Force
			}

			if (Test-Path -LiteralPath "$env:WINDIR\System32\AppLocker\Msi.AppLocker.slash" -PathType Leaf) {
				Remove-Item -LiteralPath "$env:WINDIR\System32\AppLocker\Msi.AppLocker" -Force -ErrorAction SilentlyContinue
				Rename-Item -LiteralPath "$env:WINDIR\System32\AppLocker\Msi.AppLocker.slash" -NewName "Msi.AppLocker" -Force
			}

			if (Test-Path -LiteralPath "$env:WINDIR\System32\AppLocker\Script.AppLocker.slash" -PathType Leaf) {
				Remove-Item -LiteralPath "$env:WINDIR\System32\AppLocker\Script.AppLocker" -Force -ErrorAction SilentlyContinue
				Rename-Item -LiteralPath "$env:WINDIR\System32\AppLocker\Script.AppLocker.slash" -NewName "Script.AppLocker" -Force
			}

		# Enable VerifiedPublisherCertStoreCheck scheduled task.
			Enable-ScheduledTask -TaskName "VerifiedPublisherCertStoreCheck" -TaskPath "\Microsoft\Windows\AppID\" > $null

		# Enable Application Identity service startup.
			Set-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\AppIDSvc" -Name "Start" -Value 2 -Type DWord -Force

		# Update AppLocker ruleset with restored definitions.
			Start-ScheduledTask -TaskName "VerifiedPublisherCertStoreCheck" -TaskPath "\Microsoft\Windows\AppID\" > $null

		Write-Host "[INFO] AppLocker definition files restored."

	<#┌─────────────────────────────────────────────┐
	  │ Restore Services/Scheduled Tasks            │
	  └─────────────────────────────────────────────┘#>
		Write-Host "[INFO] Restoring disabled services and scheduled tasks..."

		# Services
			Set-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\AdobeARMservice" -Name "Start" -Value 2 -Type DWord -Force
			Set-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\AGSService" -Name "Start" -Value 2 -Type DWord -Force
			Set-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\Certiport.Lockdown.Service" -Name "Start" -Value 2 -Type DWord -Force
			Set-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\CertiportNow" -Name "Start" -Value 2 -Type DWord -Force
			Set-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\ChromeManager" -Name "Start" -Value 2 -Type DWord -Force
			Set-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\LanSchoolStudent" -Name "Start" -Value 2 -Type DWord -Force
			Set-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\LanSchoolHelper" -Name "Start" -Value 2 -Type DWord -Force
			Set-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\LMA_Service" -Name "Start" -Value 2 -Type DWord -Force
			Set-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\SML PingBack" -Name "Start" -Value 2 -Type DWord -Force
			Set-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\xdADWSService" -Name "Start" -Value 2 -Type DWord -Force

			if (Test-Path -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\AGMService") {
				Set-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\AGMService" -Name "Start" -Value 2 -Type DWord -Force
			}

		# Scheduled Tasks
			Enable-ScheduledTask -TaskName "Add Accessibility Checker to Word's Ribbon" > $null
			Enable-ScheduledTask -TaskName "Adobe Acrobat Update Task" > $null
			Enable-ScheduledTask -TaskName "LanSchool Configuration" > $null
			Enable-ScheduledTask -TaskName "OCPS Device Provisioning" > $null
			Enable-ScheduledTask -TaskName "Sync Java Exceptions List" > $null
			Get-ScheduledTask -TaskName "Adobe Flash Player *" | Enable-ScheduledTask > $null
			Get-ScheduledTask -TaskName "AdobeGCInvoker-*" | Enable-ScheduledTask > $null

		# Startup
			Set-ItemProperty -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" -Name "AdobeGCInvoker-1.0" -Value ([byte[]](0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)) -Type Binary -Force
			Set-ItemProperty -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" -Name "AdobeAAMUpdater-1.0" -Value ([byte[]](0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)) -Type Binary -Force
			Set-ItemProperty -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" -Name "xdADWSClient" -Value ([byte[]](0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)) -Type Binary -Force
			Set-ItemProperty -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32" -Name "Acrobat Assistant 8.0" -Value ([byte[]](0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)) -Type Binary -Force
			Set-ItemProperty -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32" -Name "Teacher" -Value ([byte[]](0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)) -Type Binary -Force
			Set-ItemProperty -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder" -Name "Capture.lnk" -Value ([byte[]](0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)) -Type Binary -Force

		Write-Host "[INFO] Services and scheduled tasks restored."

	<#┌─────────────────────────────────────────────┐
	  │ Restore Local Machine Registry Changes      │
	  └─────────────────────────────────────────────┘#>
		New-ItemProperty -LiteralPath "HKLM:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Value 1 -PropertyType DWord -Force > $null
		New-ItemProperty -LiteralPath "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 1 -PropertyType DWord -Force > $null
		New-ItemProperty -LiteralPath "HKLM:\Software\Policies\Microsoft\Windows\Network Connections" -Name "NC_ShowSharedAccessUI" -Value 0 -PropertyType DWord -Force > $null
		New-ItemProperty -LiteralPath "HKLM:\Software\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Value 1 -PropertyType DWord -Force > $null
		New-ItemProperty -LiteralPath "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "ProfileErrorAction" -Value 1 -PropertyType DWord -Force > $null
		New-ItemProperty -LiteralPath "HKLM:\Software\Policies\Microsoft\Windows Defender Security Center\Notifications" -Name "DisableNotifications" -Value 0 -PropertyType DWord -Force > $null
		New-ItemProperty -LiteralPath "HKLM:\Software\Policies\Microsoft\Windows Defender Security Center\Notifications" -Name "DisableEnhancedNotifications" -Value 0 -PropertyType DWord -Force > $null
		New-ItemProperty -LiteralPath "HKLM:\Software\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "SyncForegroundPolicy" -Value 1 -PropertyType DWord -Force > $null
		New-ItemProperty -LiteralPath "HKLM:\Software\Policies\Microsoft\WindowsStore" -Name "RequirePrivateStoreOnly" -Value 1 -PropertyType DWord -Force > $null
		New-ItemProperty -LiteralPath "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "HideFastUserSwitching" -Value 0 -PropertyType DWord -Force > $null

		if (Test-Path -LiteralPath "HKLM:\Software\Policies\Microsoft\Windows\OOBE\DisablePrivacyExperience") {
			Remove-ItemProperty -LiteralPath "HKLM:\Software\Policies\Microsoft\Windows\OOBE" -Name "DisablePrivacyExperience" -Force > $null
		}

		New-ItemProperty -LiteralPath "HKLM:\Software\Policies\Google\Chrome" -Name "AllowDeletingBrowserHistory" -Value 0 -PropertyType DWord -Force > $null
		New-ItemProperty -LiteralPath "HKLM:\Software\Policies\Google\Chrome" -Name "ForceGoogleSafeSearch" -Value 1 -PropertyType DWord -Force > $null
		New-ItemProperty -LiteralPath "HKLM:\Software\Policies\Google\Chrome" -Name "ForceYouTubeRestrict" -Value 0 -PropertyType DWord -Force > $null
		New-ItemProperty -LiteralPath "HKLM:\Software\Policies\Google\Chrome" -Name "HomepageLocation" -Value "http://launch.ocps.net" -PropertyType String -Force > $null
		New-ItemProperty -LiteralPath "HKLM:\Software\Policies\Google\Chrome" -Name "IncognitoModeAvailability" -Value 1 -PropertyType DWord -Force > $null
		New-ItemProperty -LiteralPath "HKLM:\Software\Policies\Google\Chrome" -Name "NetworkPredictionOptions" -Value 2 -PropertyType DWord -Force > $null
		New-ItemProperty -LiteralPath "HKLM:\Software\Policies\Google\Chrome" -Name "NewTabPageLocation" -Value "https://www.ocps.net" -PropertyType String -Force > $null
		New-ItemProperty -LiteralPath "HKLM:\Software\Policies\Google\Chrome" -Name "ProxyMode" -Value "system" -PropertyType String -Force > $null
		New-ItemProperty -LiteralPath "HKLM:\Software\Policies\Google\Chrome" -Name "RestoreOnStartup" -Value 4 -PropertyType DWord -Force > $null
		New-ItemProperty -LiteralPath "HKLM:\Software\Policies\Google\Chrome" -Name "SafeBrowsingEnabled" -Value 1 -PropertyType DWord -Force > $null
		New-ItemProperty -LiteralPath "HKLM:\Software\Policies\Google\Chrome" -Name "SavingBrowserHistoryDisabled" -Value 0 -PropertyType DWord -Force > $null
		New-ItemProperty -LiteralPath "HKLM:\Software\Policies\Google\Chrome" -Name "ShowHomeButton" -Value 1 -PropertyType DWord -Force > $null

	<#┌─────────────────────────────────────────────┐
	  │ Finished                                    │
	  └─────────────────────────────────────────────┘#>
		if ($InstallMode -eq "Uninstall") {
			Write-Host "[PASS] ADminify is finished uninstalling. Press any key to restart..."
			$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

			Restart-Computer -Force
			Exit
		}

		if ($InstallMode -eq "Update") {
			Write-Host "[PASS] ADminify is finished uninstalling. Starting update..."
		}

		Start-Sleep -Seconds 5
}


if ($InstallMode -eq "Install" -or $InstallMode -eq "Update") {
<#┌──────────────────────────────────────────────────────────────────────────────────────────┐
  │ Installation                                                                             │
  └──────────────────────────────────────────────────────────────────────────────────────────┘#>
	<#┌─────────────────────────────────────────────┐
	  │ Administrator Account Creation              │
	  └─────────────────────────────────────────────┘#>
		# Prompt for the student's full name so it doesn't show "slashpowered" on login.
			$StudentName = Read-Host -Prompt "`n[USER] Please enter your student name (LAST, FIRST M.)"

		# Create a new local user account.
			Write-Host "`n[INFO] Creating `"slashpowered`" local user account..."

			# PowerShell requires a secure string for this... WTF >:(
				$AdminPswd = ConvertTo-SecureString $Admin -AsPlainText -Force

			New-LocalUser -Name $Admin -Password $AdminPswd -FullName $StudentName -PasswordNeverExpires -UserMayNotChangePassword -AccountNeverExpires > $null

		# Clean up the variables.
			Remove-Variable StudentName
			Remove-Variable AdminPswd

		# Invite slashpowered to the local administrator party! :)
			Write-Host "[INFO] Adding account to `"Administrators`" local group..."
			Add-LocalGroupMember -Group "Administrators" -Member $Admin


<#┌──────────────────────────────────────────────────────────────────────────────────────────┐
  │ Post-Installation                                                                        │
  └──────────────────────────────────────────────────────────────────────────────────────────┘#>
	<#┌─────────────────────────────────────────────┐
	  │ Install MeshCentral Agent                   │
	  └─────────────────────────────────────────────┘#>
		# Run the silent installer.
			Start-Process -FilePath "$PSScriptRoot\Programs\MeshCentral\meshagent64.exe" -ArgumentList "-fullinstall" -NoNewWindow -Wait

	<#┌─────────────────────────────────────────────┐
	  │ Install Psiphon VPN                         │
	  └─────────────────────────────────────────────┘#>
		# Extract and remove the archive.
			Write-Host "[INFO] Extracting Psiphon VPN..."

			7z x "$PSScriptRoot\Programs\Psiphon\Psiphon.7z" -o"$env:ProgramFiles\Psiphon" -aoa -y > $null
			Remove-Item -LiteralPath "$PSScriptRoot\Programs\Psiphon\Psiphon.7z" -Force

	<#┌─────────────────────────────────────────────┐
	  │ Unblock All Executable Files                │
	  └─────────────────────────────────────────────┘#>
		# Take ownership of the AppLocker directory.
			takeown.exe /R /A /F "$env:WINDIR\System32\AppLocker" /D N > $null
			icacls.exe "$env:WINDIR\System32\AppLocker" /grant "Administrators:(OI)(CI)F" /T /C > $null

		# Bypass the AppLocker definitions by replacing them with blanks.
			if (Test-Path -LiteralPath "$env:WINDIR\System32\AppLocker\Appx.AppLocker" -PathType Leaf) {
				Rename-Item -LiteralPath "$env:WINDIR\System32\AppLocker\Appx.AppLocker" -NewName "Appx.AppLocker.slash" -Force
			}

			if (Test-Path -LiteralPath "$env:WINDIR\System32\AppLocker\Dll.AppLocker" -PathType Leaf) {
				Rename-Item -LiteralPath "$env:WINDIR\System32\AppLocker\Dll.AppLocker" -NewName "Dll.AppLocker.slash" -Force
			}

			if (Test-Path -LiteralPath "$env:WINDIR\System32\AppLocker\Exe.AppLocker" -PathType Leaf) {
				Rename-Item -LiteralPath "$env:WINDIR\System32\AppLocker\Exe.AppLocker" -NewName "Exe.AppLocker.slash" -Force
			}

			if (Test-Path -LiteralPath "$env:WINDIR\System32\AppLocker\Msi.AppLocker" -PathType Leaf) {
				Rename-Item -LiteralPath "$env:WINDIR\System32\AppLocker\Msi.AppLocker" -NewName "Msi.AppLocker.slash" -Force
			}

			if (Test-Path -LiteralPath "$env:WINDIR\System32\AppLocker\Script.AppLocker" -PathType Leaf) {
				Rename-Item -LiteralPath "$env:WINDIR\System32\AppLocker\Script.AppLocker" -NewName "Script.AppLocker.slash" -Force
			}

		# Force update the active AppLocker definitions.
			Start-ScheduledTask -TaskName "VerifiedPublisherCertStoreCheck" -TaskPath "\Microsoft\Windows\AppID\" > $null

		# Disable automatic AppLocker definition updates.
			Disable-ScheduledTask -TaskName "VerifiedPublisherCertStoreCheck" -TaskPath "\Microsoft\Windows\AppID\" > $null

		# Disable the Application Identity service.
			Set-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\AppIDSvc" -Name "Start" -Value 4 -Type DWord -Force

	<#┌─────────────────────────────────────────────┐
	  │ Disable Monitoring Processes                │
	  └─────────────────────────────────────────────┘#>
		# LanSchool Student startup.
			Set-ItemProperty -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32" -Name "Teacher" -Value ([byte[]](0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)) -Type Binary -Force

		# LanSchool Student service startup.
			Set-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\LanSchoolStudent" -Name "Start" -Value 4 -Type DWord -Force

		# LanSchool Helper service startup.
			Set-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\LanSchoolHelper" -Name "Start" -Value 4 -Type DWord -Force

		# LanSchool Configuration scheduled task.
			Disable-ScheduledTask -TaskName "LanSchool Configuration" > $null

		# Lightspeed CO Capture startup.
			Set-ItemProperty -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder" -Name "Capture.lnk" -Value ([byte[]](0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)) -Type Binary -Force

		# Lightspeed Management Agent service startup.
			Set-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\LMA_Service" -Name "Start" -Value 4 -Type DWord -Force

		# Chrome Manager service startup.
			Set-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\ChromeManager" -Name "Start" -Value 4 -Type DWord -Force

	<#┌─────────────────────────────────────────────┐
	  │ Disable Other Shit Processes                │
	  └─────────────────────────────────────────────┘#>
		# Word Accessbility Checker scheduled task.
			Disable-ScheduledTask -TaskName "Add Accessibility Checker to Word's Ribbon" > $null

		# Acrobat Update service startup.
			Set-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\AdobeARMservice" -Name "Start" -Value 4 -Type DWord -Force

		# Acrobat Update scheduled task.
			Disable-ScheduledTask -TaskName "Adobe Acrobat Update Task" > $null

		# ActroTray startup.
			Set-ItemProperty -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32" -Name "Acrobat Assistant 8.0" -Value ([byte[]](0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)) -Type Binary -Force

		# Adobe GC Invoker Utility startup.
			Set-ItemProperty -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" -Name "AdobeGCInvoker-1.0" -Value ([byte[]](0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)) -Type Binary -Force

		# Adobe GC Invoker scheduled tasks.
			Get-ScheduledTask -TaskName "AdobeGCInvoker-*" | Disable-ScheduledTask > $null

		# Adobe Genuine Monitor service startup.
			if (Test-Path -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\AGMService") {
				Set-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\AGMService" -Name "Start" -Value 4 -Type DWord -Force
			}

		# Adobe Genuine Software Integrity service startup.
			Set-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\AGSService" -Name "Start" -Value 4 -Type DWord -Force

		# Adobe Updater startup.
			Set-ItemProperty -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" -Name "AdobeAAMUpdater-1.0" -Value ([byte[]](0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)) -Type Binary -Force

		# Certiport Lockdown service startup.
			Set-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\Certiport.Lockdown.Service" -Name "Start" -Value 4 -Type DWord -Force

		# CertiportNow service startup.
			Set-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\CertiportNow" -Name "Start" -Value 4 -Type DWord -Force

		# Flash Player scheduled tasks.
			Get-ScheduledTask -TaskName "Adobe Flash Player *" | Disable-ScheduledTask > $null

		# OCPS Device Provisioning scheduled task.
			Disable-ScheduledTask -TaskName "OCPS Device Provisioning" > $null

		# Safari Montage Pingback service startup.
			Set-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\SML PingBack" -Name "Start" -Value 4 -Type DWord -Force

		# Service Host-8214 startup.
			Set-ItemProperty -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder" -Name "Service Host - 8214.lnk" -Value ([byte[]](0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)) -Type Binary -Force

		# SMART Ink startup.
			Set-ItemProperty -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32" -Name "SMART Ink" -Value ([byte[]](0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)) -Type Binary -Force

		# SMART Helper service startup.
			if (Test-Path -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\SMARTHelperService") {
				Set-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\SMARTHelperService" -Name "Start" -Value 4 -Type DWord -Force
			}

		# SMART Node Launcher startup.
			Set-ItemProperty -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32" -Name "sbsdk-server" -Value ([byte[]](0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)) -Type Binary -Force

		# SMART Notification startup.
			Set-ItemProperty -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32" -Name "SMARTNotification" -Value ([byte[]](0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)) -Type Binary -Force

		# Sync Java Exceptions scheduled task.
			Disable-ScheduledTask -TaskName "Sync Java Exceptions List" > $null

		# xdAD Workstation Client startup.
			Set-ItemProperty -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" -Name "xdADWSClient" -Value ([byte[]](0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)) -Type Binary -Force

		# xdAD Workstation service startup.
			Set-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\xdADWSService" -Name "Start" -Value 4 -Type DWord -Force

	<#┌─────────────────────────────────────────────┐
	  │ Bypass Lightspeed Filter                    │
	  └─────────────────────────────────────────────┘#>
		Add-HostsEntry -Address "127.0.0.1" -Hostname "mobilefilter.dadeschools.net"
		Add-HostsEntry -Address "127.0.0.1" -Hostname "ls-rf-filter.ocps.net"
		Add-HostsEntry -Address "127.0.0.1" -Hostname "ls-ia.ocps.net"
		Add-HostsEntry -Address "127.0.0.1" -Hostname "api.lsfilter.com"
		Add-HostsEntry -Address "127.0.0.1" -Hostname "api.mybigcampus.com"
		Add-HostsEntry -Address "127.0.0.1" -Hostname "devices.lsmdm.com"
		Add-HostsEntry -Address "127.0.0.1" -Hostname "mobile.lsfilter.com"

	<#┌─────────────────────────────────────────────┐
	  │ Block Other OCPS Domains                    │
	  └─────────────────────────────────────────────┘#>
		Add-HostsEntry -Address "127.0.0.1" -Hostname "aelcmmpa1.ocps.net"
		Add-HostsEntry -Address "127.0.0.1" -Hostname "aelcmmpa1.ocps.k12.fl.us"
		Add-HostsEntry -Address "127.0.0.1" -Hostname "aelcmmpa2.ocps.net"
		Add-HostsEntry -Address "127.0.0.1" -Hostname "aelcmmpa2.ocps.k12.fl.us"
		Add-HostsEntry -Address "127.0.0.1" -Hostname "aelcmmpa3.ocps.net"
		Add-HostsEntry -Address "127.0.0.1" -Hostname "aelcmmpa3.ocps.k12.fl.us"
		Add-HostsEntry -Address "127.0.0.1" -Hostname "aelcmpra.ocps.net"
		Add-HostsEntry -Address "127.0.0.1" -Hostname "aelcmpra.ocps.k12.fl.us"
		Add-HostsEntry -Address "127.0.0.1" -Hostname "aelmak01.ocps.net"
		Add-HostsEntry -Address "127.0.0.1" -Hostname "aelmak01.ocps.k12.fl.us"
		Add-HostsEntry -Address "127.0.0.1" -Hostname "awscmmpa1.ocps.net"
		Add-HostsEntry -Address "127.0.0.1" -Hostname "awscmmpa1.ocps.k12.fl.us"
		Add-HostsEntry -Address "127.0.0.1" -Hostname "awscmmpa2.ocps.net"
		Add-HostsEntry -Address "127.0.0.1" -Hostname "awscmmpa2.ocps.k12.fl.us"
		Add-HostsEntry -Address "127.0.0.1" -Hostname "pac.ocps.net"

	<#┌─────────────────────────────────────────────┐
	  │ Startup Programs Governor                   │
	  └─────────────────────────────────────────────┘#>
		<#

		# Create Script
			Write-Host "[INFO] Creating startup governor script..."
			$GovernorScript = @'
Add-Type -AssemblyName System.Windows.Forms
[Windows.Forms.Application]::EnableVisualStyles()

if (([Environment]::UserName) -eq $LocalUser) {
	[Windows.Forms.MessageBox]::Show($this, "This is slashpowered.", "ADminify", 0, 64)
}
else {
	[Windows.Forms.MessageBox]::Show($this, "This is not slashpowered.", "ADminify", 0, 64)
}
'@

			$GovernorScript | Out-File "$env:SYSTEMDRIVE\slashpowered\Startup Governor.ps1" -Force
			Remove-Variable GovernorScript

		# Scheduled Task
			$GVAct = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-NoProfile -File `"$env:SYSTEMDRIVE\slashpowered\Startup Governor.ps1`" -ExecutionPolicy Bypass"
			$GVTrg = New-ScheduledTaskTrigger -AtLogOn
			$GVSet = New-ScheduledTaskSettingsSet
			$GVTsk = New-ScheduledTask -Action $GVAct -Trigger $GVTrg -Settings $GVSet
			Register-ScheduledTask -TaskName "Startup Governor" -TaskPath "\Slash\" -InputObject $GVTsk -Force

		#>

	<#┌─────────────────────────────────────────────┐
	  │ Local Machine Registry Changes              │
	  └─────────────────────────────────────────────┘#>
		# Disable Google Chrome restrictions and other policies.
			Remove-ItemProperty -LiteralPath "HKLM:\Software\Policies\Google\Chrome" -Name "AllowDeletingBrowserHistory" -Force
			Remove-ItemProperty -LiteralPath "HKLM:\Software\Policies\Google\Chrome" -Name "ForceGoogleSafeSearch" -Force
			Remove-ItemProperty -LiteralPath "HKLM:\Software\Policies\Google\Chrome" -Name "ForceYouTubeRestrict" -Force
			Remove-ItemProperty -LiteralPath "HKLM:\Software\Policies\Google\Chrome" -Name "HomepageLocation" -Force
			Remove-ItemProperty -LiteralPath "HKLM:\Software\Policies\Google\Chrome" -Name "IncognitoModeAvailability" -Force
			Remove-ItemProperty -LiteralPath "HKLM:\Software\Policies\Google\Chrome" -Name "NetworkPredictionOptions" -Force
			Remove-ItemProperty -LiteralPath "HKLM:\Software\Policies\Google\Chrome" -Name "NewTabPageLocation" -Force
			Remove-ItemProperty -LiteralPath "HKLM:\Software\Policies\Google\Chrome" -Name "ProxyMode" -Force
			Remove-ItemProperty -LiteralPath "HKLM:\Software\Policies\Google\Chrome" -Name "RestoreOnStartup" -Force
			Remove-ItemProperty -LiteralPath "HKLM:\Software\Policies\Google\Chrome" -Name "SafeBrowsingEnabled" -Force
			Remove-ItemProperty -LiteralPath "HKLM:\Software\Policies\Google\Chrome" -Name "SavingBrowserHistoryDisabled" -Force
			Remove-ItemProperty -LiteralPath "HKLM:\Software\Policies\Google\Chrome" -Name "ShowHomeButton" -Force

		# Disable "Switch user" button to isolate slashpowered admin from the student account.
			if (!(Test-Path -LiteralPath "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System")) {
				New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Force > $null
			}

			New-ItemProperty -LiteralPath "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "HideFastUserSwitching" -Value 1 -PropertyType DWord -Force > $null

		# Disable Windows advertising indentifiers.
			if (!(Test-Path -LiteralPath "HKLM:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo")) {
				New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Force > $null
			}

			New-ItemProperty -LiteralPath "HKLM:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Value 0 -PropertyType DWord -Force > $null

		# Disable creepy Windows telemetry stuff.
			if (!(Test-Path -LiteralPath "HKLM:\Software\Policies\Microsoft\Windows\DataCollection")) {
				New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Force > $null
			}

			New-ItemProperty -LiteralPath "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0 -PropertyType DWord -Force > $null

		# Disable privacy experience screen (for our 1903+ kings).
			if (!(Test-Path -LiteralPath "HKLM:\Software\Policies\Microsoft\Windows\OOBE")) {
				New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\OOBE" -Force > $null
			}

			New-ItemProperty -LiteralPath "HKLM:\Software\Policies\Microsoft\Windows\OOBE" -Name "DisablePrivacyExperience" -Value 1 -PropertyType DWord -Force > $null

		# Disable mobile hotspot restrictions.
			if (!(Test-Path -LiteralPath "HKLM:\Software\Policies\Microsoft\Windows\Network Connections")) {
				New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\Network Connections" -Force > $null
			}

			New-ItemProperty -LiteralPath "HKLM:\Software\Policies\Microsoft\Windows\Network Connections" -Name "NC_ShowSharedAccessUI" -Value 1 -PropertyType DWord -Force > $null

		# Disable Xbox Game DVR restrictions.
			if (!(Test-Path -LiteralPath "HKLM:\Software\Policies\Microsoft\Windows\GameDVR")) {
				New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\GameDVR" -Force > $null
			}

			New-ItemProperty -LiteralPath "HKLM:\Software\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Value 1 -PropertyType DWord -Force > $null

		# Don't create a temporary profile if slashpowered profile is corrupted.
			if (!(Test-Path -LiteralPath "HKLM:\Software\Policies\Microsoft\Windows\System")) {
				New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Force > $null
			}

			New-ItemProperty -LiteralPath "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "ProfileErrorAction" -Value 1 -PropertyType DWord -Force > $null

		# Disable the annoying firewall notifications every minute.
			if (!(Test-Path -LiteralPath "HKLM:\Software\Policies\Microsoft\Windows Defender Security Center\Notifications")) {
				New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows Defender Security Center\Notifications" -Force > $null
			}

			New-ItemProperty -LiteralPath "HKLM:\Software\Policies\Microsoft\Windows Defender Security Center\Notifications" -Name "DisableNotifications" -Value 1 -PropertyType DWord -Force > $null
			New-ItemProperty -LiteralPath "HKLM:\Software\Policies\Microsoft\Windows Defender Security Center\Notifications" -Name "DisableEnhancedNotifications" -Value 1 -PropertyType DWord -Force > $null

		# Disable automatically connecting to OCPS Wi-Fi during logon.
			if (!(Test-Path -LiteralPath "HKLM:\Software\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon")) {
				New-Item -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Force > $null
			}

			New-ItemProperty -LiteralPath "HKLM:\Software\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "SyncForegroundPolicy" -Value 0 -PropertyType DWord -Force > $null

		# Allow installing non-OCPS apps from the Microsoft Store.
			if (!(Test-Path -LiteralPath "HKLM:\Software\Policies\Microsoft\WindowsStore")) {
				New-Item -Path "HKLM:\Software\Policies\Microsoft\WindowsStore" -Force > $null
			}

			New-ItemProperty -LiteralPath "HKLM:\Software\Policies\Microsoft\WindowsStore" -Name "RequirePrivateStoreOnly" -Value 0 -PropertyType DWord -Force > $null

		# Disable laptop power throttling to improve gaming performance.
			if (!(Test-Path -LiteralPath "HKLM:\System\CurrentControlSet\Control\Power\PowerThrottling")) {
				New-Item -Path "HKLM:\System\CurrentControlSet\Control\Power\PowerThrottling" -Force > $null
			}

			New-ItemProperty -LiteralPath "HKLM:\System\CurrentControlSet\Control\Power\PowerThrottling" -Name "PowerThrottlingOff" -Value 1 -PropertyType DWord -Force > $null

	<#┌─────────────────────────────────────────────┐
	  │ RunOnce script for account configuration    │
	  └─────────────────────────────────────────────┘#>
		Write-Host "[INFO] Creating post-configuration startup script..."
		$PostScript = @'
if (!(Test-Path -LiteralPath "HKCU:\Control Panel\Desktop")) {
	New-Item -Path "HKCU:\Control Panel\Desktop" -Force
}

if (!(Test-Path -LiteralPath "HKCU:\Control Panel\Desktop\UserPreferencesMask")) {
	New-Item -Path "HKCU:\Control Panel\Desktop\UserPreferencesMask" -Force
}

if (!(Test-Path -LiteralPath "HKCU:\Control Panel\International\User Profile")) {
	New-Item -Path "HKCU:\Control Panel\International\User Profile" -Force
}

if (!(Test-Path -LiteralPath "HKCU:\Software\Microsoft\Clipboard")) {
	New-Item -Path "HKCU:\Software\Microsoft\Input\Clipboard" -Force
}

if (!(Test-Path -LiteralPath "HKCU:\Software\Microsoft\Input\TIPC")) {
	New-Item -Path "HKCU:\Software\Microsoft\Input\TIPC" -Force
}

if (!(Test-Path -LiteralPath "HKCU:\Software\Microsoft\InputPersonalization")) {
	New-Item -Path "HKCU:\Software\Microsoft\InputPersonalization" -Force
}

if (!(Test-Path -LiteralPath "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore")) {
	New-Item -Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" -Force
}

if (!(Test-Path -LiteralPath "HKCU:\Software\Microsoft\Personalization\Settings")) {
	New-Item -Path "HKCU:\Software\Microsoft\Personalization\Settings" -Force
}

if (!(Test-Path -LiteralPath "HKCU:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy")) {
	New-Item -Path "HKCU:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" -Force
}

if (!(Test-Path -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR")) {
	New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Force
}

if (!(Test-Path -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")) {
	New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Force
}

if (!(Test-Path -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Ribbon")) {
	New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Ribbon" -Force
}

if (!(Test-Path -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects")) {
	New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Ribbon" -Force
}

if (!(Test-Path -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop")) {
	New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop" -Force
}

if (!(Test-Path -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
	New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Force
}

if (!(Test-Path -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System")) {
	New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Force
}

if (!(Test-Path -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\TextInput")) {
	New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\TextInput" -Force
}

if (!(Test-Path -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy")) {
	New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy" -Force
}

if (!(Test-Path -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search")) {
	New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Force
}

if (!(Test-Path -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize")) {
	New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Force
}

if (!(Test-Path -LiteralPath "HKCU:\Software\Microsoft\Windows Security Health\State")) {
	New-Item -Path "HKCU:\Software\Microsoft\Windows Security Health\State" -Force
}

if (!(Test-Path -LiteralPath "HKCU:\Software\Microsoft\Windows\OneDrive")) {
	New-Item -Path "HKCU:\Software\Microsoft\Windows\OneDrive" -Force
}

if (!(Test-Path -LiteralPath "HKCU:\Software\Policies\Microsoft\Windows\Explorer")) {
	New-Item -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Force
}

if (!(Test-Path -LiteralPath "HKCU:\Software\Policies\Microsoft\WindowsStore")) {
	New-Item -Path "HKCU:\Software\Policies\Microsoft\WindowsStore" -Force
}

if (!(Test-Path -LiteralPath "HKCU:\System\GameConfigStore")) {
	New-Item -Path "HKCU:\System\GameConfigStore" -Force
}

if (!(Test-Path -LiteralPath "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon")) {
	New-Item -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Force
}

New-ItemProperty -LiteralPath "HKCU:\Control Panel\Desktop" -Name "PaintDesktopVersion" -Value 1 -PropertyType DWord -Force
New-ItemProperty -LiteralPath "HKCU:\Control Panel\International\User Profile" -Name "HttpAcceptLanguageOptOut" -Value 1 -PropertyType DWord -Force
New-ItemProperty -LiteralPath "HKCU:\Software\Microsoft\Clipboard" -Name "ClipboardTipRequired" -Value 0 -PropertyType DWord -Force
New-ItemProperty -LiteralPath "HKCU:\Software\Microsoft\Clipboard" -Name "EnableClipboardHistory" -Value 1 -PropertyType DWord -Force
New-ItemProperty -LiteralPath "HKCU:\Software\Microsoft\Clipboard" -Name "PastedFromClipboardUI" -Value 1 -PropertyType DWord -Force
New-ItemProperty -LiteralPath "HKCU:\Software\Microsoft\Input\TIPC" -Name "Enabled" -Value 0 -PropertyType DWord -Force
New-ItemProperty -LiteralPath "HKCU:\Software\Microsoft\InputPersonalization" -Name "AllowInputPersonalization" -Value 0 -PropertyType DWord -Force
New-ItemProperty -LiteralPath "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Value 1 -PropertyType DWord -Force
New-ItemProperty -LiteralPath "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Value 1 -PropertyType DWord -Force
New-ItemProperty -LiteralPath "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Value 0 -PropertyType DWord -Force
New-ItemProperty -LiteralPath "HKCU:\Software\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Value 0 -PropertyType DWord -Force
New-ItemProperty -LiteralPath "HKCU:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" -Name "HasAccepted" -Value 0 -PropertyType DWord -Force
New-ItemProperty -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowRecent" -Value 0 -PropertyType DWord -Force
New-ItemProperty -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowFrequent" -Value 0 -PropertyType DWord -Force
New-ItemProperty -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value 0 -PropertyType DWord -Force
New-ItemProperty -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Value 1 -PropertyType DWord -Force
New-ItemProperty -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Value 3 -PropertyType DWord -Force
New-ItemProperty -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Value 1 -PropertyType DWord -Force
New-ItemProperty -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackDocs" -Value 0 -PropertyType DWord -Force
New-ItemProperty -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackProgs" -Value 0 -PropertyType DWord -Force
New-ItemProperty -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Ribbon" -Name "MinimizedStateTabletModeOff" -Value 0 -PropertyType DWord -Force
New-ItemProperty -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Value 3 -PropertyType DWord -Force
New-ItemProperty -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop" -Name "NoChangingWallPaper" -Value 0 -PropertyType DWord -Force
New-ItemProperty -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoInstrumentation" -Value 1 -PropertyType DWord -Force
New-ItemProperty -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoInternetOpenWith" -Value 1 -PropertyType DWord -Force
New-ItemProperty -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoStartMenuMFUprogramsList" -Value 1 -PropertyType DWord -Force
New-ItemProperty -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoThemesTab" -Value 0 -PropertyType DWord -Force
New-ItemProperty -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableChangePassword" -Value 1 -PropertyType DWord -Force
New-ItemProperty -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "NoColorChoice" -Value 0 -PropertyType DWord -Force
New-ItemProperty -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "NoDispAppearancePage" -Value 0 -PropertyType DWord -Force
New-ItemProperty -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\TextInput" -Name "AllowLinguisticDataCollection" -Value 0 -PropertyType DWord -Force
New-ItemProperty -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy" -Name "TailoredExperiencesWithDiagnosticDataEnabled" -Value 0 -PropertyType DWord -Force
New-ItemProperty -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Value 0 -PropertyType DWord -Force
New-ItemProperty -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Value 0 -PropertyType DWord -Force
New-ItemProperty -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Value 2 -PropertyType DWord -Force
New-ItemProperty -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Value 0 -PropertyType DWord -Force
New-ItemProperty -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Value 0 -PropertyType DWord -Force
New-ItemProperty -LiteralPath "HKCU:\Software\Microsoft\Windows Security Health\State" -Name "AccountProtection_MicrosoftAccount_Disconnected" -Value 0 -PropertyType DWord -Force
New-ItemProperty -LiteralPath "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Name "NoPinningStoreToTaskbar" -Value 0 -PropertyType DWord -Force
New-ItemProperty -LiteralPath "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Name "DisableSearchBoxSuggestions" -Value 1 -PropertyType DWord -Force
New-ItemProperty -LiteralPath "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Name "DisableSearchHistory" -Value 1 -PropertyType DWord -Force
New-ItemProperty -LiteralPath "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Name "HideRecentlyAddedApps" -Value 1 -PropertyType DWord -Force
New-ItemProperty -LiteralPath "HKCU:\Software\Policies\Microsoft\WindowsStore" -Name "RemoveWindowsStore" -Value 0 -PropertyType DWord -Force

New-ItemProperty -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name "AppCaptureEnabled" -Value 1 -PropertyType DWord -Force
New-ItemProperty -LiteralPath "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Value 1 -PropertyType DWord -Force

New-ItemProperty -LiteralPath "HKCU:\Software\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Value 1 -PropertyType DWord -Force
Remove-Item -LiteralPath "$env:USERPROFILE\OneDrive" -Force -Recurse
Remove-Item -LiteralPath "$env:LOCALAPPDATA\Microsoft\OneDrive" -Force -Recurse
Remove-Item -LiteralPath "$env:PROGRAMDATA\Microsoft OneDrive" -Force -Recurse
Remove-Item -LiteralPath "$env:SYSTEMDRIVE\OneDriveTemp" -Force -Recurse

if (!(Test-Path "HKCR:")) {
	New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT
}

Remove-Item -LiteralPath "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse
Remove-Item -LiteralPath "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse

New-ItemProperty -LiteralPath "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon" -Value 0 -PropertyType DWord -Force
New-ItemProperty -LiteralPath "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "ForceAutoLogon" -Value 0 -PropertyType DWord -Force
Remove-ItemProperty -LiteralPath "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoLogonCount" -Force
Remove-ItemProperty -LiteralPath "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultUserName" -Force
Remove-ItemProperty -LiteralPath "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultPassword" -Force

Rename-ItemProperty -LiteralPath "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LegalNoticeCaption.slash" -NewName "LegalNoticeCaption" -Force
Rename-ItemProperty -LiteralPath "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LegalNoticeText.slash" -NewName "LegalNoticeText" -Force

Stop-Process -ProcessName "explorer" -Force
Start-Process -FilePath "explorer.exe"

Remove-Item -LiteralPath "$env:SYSTEMDRIVE\Windows\Temp\ADminify" -Recurse -Force
Remove-Item -LiteralPath "$PSCommandPath" -Force
'@

		$PostScript | Out-File "$env:SYSTEMDRIVE\slashpowered\Post-Configuration.ps1" -Force
		Remove-Variable PostScript

		# Configure the post-configuration script to run on slashpowered first logon.
			Write-Host "[INFO] Adding post-configuration script to startup registry..."

			if (!(Test-Path -LiteralPath "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce")) {
				New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -Force > $null
			}

			New-ItemProperty -LiteralPath "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -Name "slashpowered Account Configuration" -Value "PowerShell.exe -NoLogo -NoProfile -File `"$env:SYSTEMDRIVE\slashpowered\Post-Configuration.ps1`" -ExecutionPolicy Bypass" -PropertyType String -Force > $null

	<#┌─────────────────────────────────────────────┐
	  │ Auto Logon for Quick Setup                  │
	  └─────────────────────────────────────────────┘#>
		# Temporarily activate automatic logon for account configuration.
			if (!(Test-Path -LiteralPath "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon")) {
				New-Item -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Force > $null
			}

			New-ItemProperty -LiteralPath "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "ForceAutoLogon" -Value 1 -PropertyType DWord -Force > $null
			New-ItemProperty -LiteralPath "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon" -Value 1 -PropertyType DWord -Force > $null
			New-ItemProperty -LiteralPath "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultUserName" -Value "$env:COMPUTERNAME\$Admin" -PropertyType String -Force > $null
			New-ItemProperty -LiteralPath "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultPassword" -Value "$Admin" -PropertyType String -Force > $null

			# Workaround for some student's computers not logging in.
				if (Test-Path -LiteralPath "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AutoLogonCount") {
					Remove-ItemProperty -LiteralPath "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoLogonCount" -Force
				}

		# The legal notice overrides auto logon, temporarily disabled for seamless configuration.
			Rename-ItemProperty -LiteralPath "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LegalNoticeCaption" -NewName "LegalNoticeCaption.slash" -Force
			Rename-ItemProperty -LiteralPath "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LegalNoticeText" -NewName "LegalNoticeText.slash" -Force
}


<#┌──────────────────────────────────────────────────────────────────────────────────────────┐
  │ Script Finished                                                                          │
  └──────────────────────────────────────────────────────────────────────────────────────────┘#>
	<#┌─────────────────────────────────────────────┐
	  │ Continue Prompt                             │
	  └─────────────────────────────────────────────┘#>
		# If installing...
			if ($InstallMode -eq "Install") {
				Write-Host "`n[USER] Restart required to complete ADMinify installation. Press any key to restart..." -NoNewline
				$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") > $null

				Restart-Computer -Force
				Exit
			}

		# If uninstalling...
			if ($InstallMode -eq "Uninstall") {
				Write-Host "`n[DONE] Restart required to cleanup ADminify. Press any key to restart..." -NoNewline
				$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") > $null

				Restart-Computer -Force
				Exit
			}

		# If updating...
			if ($InstallMode -eq "Update") {
				Write-Host "`n[USER] Restart required to complete ADMinify update. Press any key to restart..." -NoNewline
				$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") > $null

				Restart-Computer -Force
				Exit
			}
