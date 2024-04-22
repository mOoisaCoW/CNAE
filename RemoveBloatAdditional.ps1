<#
.SYNOPSIS
.Quick and dirty to unhide hidden sleep, turn off hibernation to fix fast start issue and also install HEIC and HEVC plugins if they are not already installed
.DESCRIPTION
.INPUTS
.OUTPUTS
.NOTES
  Version:        1.0
  Author:         Michael Charles
  Creation Date:  2022
  Purpose/Change: Initial script development
  Change: 22/04/2024 - Added check for update
.EXAMPLE
N/A
#>

##Elevate if needed

If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
    Write-Host "You didn't run this script as an Administrator. This script will self elevate to run as an Administrator and continue."
    Start-Sleep 1
    Write-Host "                                               3"
    Start-Sleep 1
    Write-Host "                                               2"
    Start-Sleep 1
    Write-Host "                                               1"
    Start-Sleep 1
    Start-Process powershell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
    Exit
}

#no errors throughout
$ErrorActionPreference = 'silentlycontinue'


# Set the execution policy to RemoteSigned if it not already set to bypass or RemoteSigned
$policy = Get-ExecutionPolicy
if ($policy -eq "Bypass") {
    Write-Host "Execution policy is set to Bypass mode. Scripts will run without any restrictions."
} elseif ($policy -ne "RemoteSigned") {
    $choice = Read-Host "Execution policy is not RemoteSigned. Do you want to enable it? (y/n)"
    if ($choice.ToLower() -eq "y") {
        Set-ExecutionPolicy RemoteSigned
        Write-Host "RemoteSigned execution policy has been enabled."
    } else {
        Write-Host "RemoteSigned execution policy was not enabled."
    }
} else {
    Write-Host "Execution policy is already RemoteSigned."
}

Function Get-ScriptVersion(){
    
    <#
    .SYNOPSIS
    This function is used to check if the running script is the latest version
    .DESCRIPTION
    This function checks GitHub and compares the 'live' version with the one running
    .EXAMPLE
    Get-ScriptVersion
    Returns a warning and URL if outdated
    .NOTES
    NAME: Get-ScriptVersion
    #>
    
    [cmdletbinding()]
    
    param
    (
        $liveuri
    )
$contentheaderraw = (Invoke-WebRequest -Uri $liveuri -Method Get)
$contentheader = $contentheaderraw.Content.Split([Environment]::NewLine)
$liveversion = (($contentheader | Select-String 'Version:') -replace '[^0-9.]','') | Select-Object -First 1
$currentversion = ((Get-Content -Path $PSCommandPath | Select-String -Pattern "Version: *") -replace '[^0-9.]','') | Select-Object -First 1
if ($liveversion -ne $currentversion) {
write-host "Script has been updated, please download the latest version from $liveuri" -ForegroundColor Red
}
}
Get-ScriptVersion -liveuri "https://github.com/mOoisaCoW/CNAE/blob/main/RemoveBloatAdditional.ps1"


# Update registry key to unhide hidden sleep
Write-Output "Updating Registry to unhide hidden sleep"
REG ADD HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\238C9FA8-0AAD-41ED-83F4-97BE242C8F20\7bc4a2f9-d8fc-4469-b07b-33eb785aaca0 /v Attributes /t REG_DWORD /d 2 /f
# Gets the specified registry value or $null if it is missing
function Get-RegistryValue($path, $name)
{
    $key = Get-Item -LiteralPath $path -ErrorAction SilentlyContinue
    if ($key) {
        $key.GetValue($name, $null)
    }
}

# Test missing value - If missing above command hasn't worked so will exit
$val = Get-RegistryValue HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\238C9FA8-0AAD-41ED-83F4-97BE242C8F20\7bc4a2f9-d8fc-4469-b07b-33eb785aaca0 Attributes
if ($val -eq $null) 
	{ 'Missing value - Please check script is running in admin mode'
			Write-Host "Press any key to exit ..."
		$x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") 
		exit
	}
	#Report value of available - This has been disabled
	#else { $val }

# Test existing value
$val = Get-RegistryValue HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\238C9FA8-0AAD-41ED-83F4-97BE242C8F20\7bc4a2f9-d8fc-4469-b07b-33eb785aaca0 Attributes
if ($val -eq 2) 
	{ 'Registry Correctly Set' } 
	else { 'Registry NOT CORRECT - Please check you ran as Administrator - Any value other than 2 below is wrong and need to be fixed' 
		$val
		Write-Host "Press any key to continue ..."
		$x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
		}


#Test if Hibernation is enabled or disabled
$val = Get-RegistryValue HKLM:\SYSTEM\CurrentControlSet\Control\Power -name HibernateEnabled
if ($val -eq 0) 
	{ 'Hibernation and Fast Start are disabled - This is a good thing' } 
	else { 'Hibernation is enabled.  This will turn it off to prevent fast start from being enabled' 
		powercfg -h off
		$val = Get-RegistryValue HKLM:\SYSTEM\CurrentControlSet\Control\Power -name HibernateEnabled
		if ($val -eq 0) 
			{ 'Hibernation is now disabled' } 
		}

#Check if HEIF and HEVC packages installed.  If not, install them
if ($null -eq (Get-AppxPackage -Name Microsoft.HEVCVideoExtension) -or $null -eq (Get-AppxPackage -Name Microsoft.HEIFImageExtension)) {
    Write-Output "Neither HEIC Image or HEVC Video Extensions are present - Calling Enable-HEIC-Extension-Feature script to install"
	& "$PSScriptRoot\Enable-HEIC-Extension-Feature.ps1"
}
Else { 
        Write-Output "HEIC image and HEVC Video Extentions already installed"
     }

If ($null -eq (get-appxpackage -Name Microsoft.HEIFImageExtension)) {
    Write-Output "HEIF Image Extension not present - So will call store to attempt manual install"
	start ms-windows-store://pdp/?ProductId=9pmmsr1cgpwg
Write-Host "Press any key to continue ..."
$x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
clear
}
Else { 
        # Write-Output "HEIF Image Extentions already installed"
     }



If ($null -eq (get-appxpackage -Name Microsoft.HEVCVideoExtension)) {
    Write-Output "HEVC Video Extension not present - So will call store to attempt manual install"
	start ms-windows-store://pdp/?ProductId=9n4wgh0z6vhq
}
Else { 
       # Write-Output "Double check that HEVC Video Extentions already installed"
     }



# Check if the version of Windows is Windows 11 22H2 or 23H2
$versionInfo = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name DisplayVersion -ErrorAction SilentlyContinue
if ($versionInfo.DisplayVersion -eq "22H2" -or $versionInfo.DisplayVersion -eq "23H2") {
    # This will set default startmenu layout
    # Set the source file path
    $sourceFile = Join-Path -Path $PSScriptRoot -ChildPath "start2.bin"

    # Set the destination directory path
    $destinationDir = "C:\Users\Default\AppData\Local\Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\LocalState"

    # Check if the destination directory exists, and create it if necessary
    if (-not (Test-Path -Path $destinationDir -PathType Container)) {
        New-Item -Path $destinationDir -ItemType Directory -Force | Out-Null
    }

    # Set the destination file path
    $destinationFile = Join-Path -Path $destinationDir -ChildPath "start2.bin"

    # Copy the file
    Copy-Item -Path $sourceFile -Destination $destinationFile -Force

    # Check if the file was copied successfully
    if (Test-Path -Path $destinationFile -PathType Leaf) {
        Write-Host "File copied successfully!"
    } else {
        Write-Host "File copy failed!"
    }
	Write-Host "Running fix for task manager link"
	$key1 = "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FeatureManagement\Overrides\4\1887869580"
	New-Item -Path $key1 -Force | Out-Null
	New-ItemProperty -Path $key1 -Name "EnabledState" -Value 0x00000002 -PropertyType DWORD -Force | Out-Null
	New-ItemProperty -Path $key1 -Name "EnabledStateOptions" -Value 0x00000000 -PropertyType DWORD -Force | Out-Null
} else {
    Write-Host "This script is only compatible with Windows 11 22H2 or 23H2"
}

#Turn off chat for default user
$key = "Registry::HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
New-Item -Path $key -Force | Out-Null
New-ItemProperty -Path $key -Name "TaskbarDa" -Value 0x00000000 -PropertyType DWORD -Force | Out-Null
New-ItemProperty -Path $key -Name "TaskbarMn" -Value 0x00000000 -PropertyType DWORD -Force | Out-Null

write-host "Completed"
Write-Host "Press any key to continue ..."
$x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

Stop-Transcript
