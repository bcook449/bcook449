<#
.SYNOPSIS
    This PowerShell script ensures Windows Ink Workspace is configured to disallow access above the lock.

.NOTES
    Author          : Brett Cook 
    LinkedIn        : linkedin.com/in/brettcook/
    GitHub          : github.com/bcook449
    Date Created    : 2025-12-17
    Last Modified   : 2025-12-17
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000385

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    PS C:\> .\__remediation_template(STIG-IDWN11-CC-000385-).ps1 
#>

# STIG ID: WN11-CC-000385
# Title: Allow Windows Ink Workspace
# Severity: Medium

$RegPath = "HKLM:\Software\Policies\Microsoft\WindowsInkWorkspace"
$ValueName = "AllowWindowsInkWorkspace"
$ExpectedValue = 1

Write-Output "Remediating STIG WN11-CC-000385..."

# Ensure registry path exists
if (-not (Test-Path $RegPath)) {
    Write-Output "Registry path not found. Creating path..."
    New-Item -Path $RegPath -Force | Out-Null
}

# Create or set the registry value
New-ItemProperty -Path $RegPath `
    -Name $ValueName `
    -PropertyType DWord `
    -Value $ExpectedValue `
    -Force | Out-Null

Write-Output "STIG WN11-CC-000385 remediated successfully."
