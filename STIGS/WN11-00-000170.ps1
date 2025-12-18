<#
.SYNOPSIS
    This PowerShell script ensures SMB v1 protocol is disabled on the SMB client.

.NOTES
    Author          : Brett Cook
    LinkedIn        : linkedin.com/in/brettcook/
    GitHub          : github.com/bcook449
    Date Created    : 2025-12-17
    Last Modified   : 2025-12-17
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-00-000170 

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    PS C:\> .\__remediation_template(STIG-ID-WN10-AU-000500).ps1 
#>

# STIG ID: WN11-00-000170
# Title: Disable SMBv1 client driver (MrxSmb10)
# Severity: High
# Reboot Required: Yes

$RegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10"
$ValueName = "Start"
$ExpectedValue = 4  # Disabled

Write-Output "Remediating STIG WN11-00-000170 (Disable SMBv1 client)..."

# Ensure registry path exists
if (-not (Test-Path $RegPath)) {
    Write-Output "Registry path not found. Creating path..."
    New-Item -Path $RegPath -Force | Out-Null
}

# Set the registry value
New-ItemProperty -Path $RegPath `
    -Name $ValueName `
    -PropertyType DWord `
    -Value $ExpectedValue `
    -Force | Out-Null

Write-Output "SMBv1 client driver (MrxSmb10) has been disabled."
Write-Output "A system restart is required for this change to take effect."
