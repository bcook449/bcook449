<#
.SYNOPSIS
    This PowerShell script ensures Microsoft consumer experience is turned off to avoid installation of unwanted applications.

.NOTES
    Author          : Brett Cook
    LinkedIn        : linkedin.com/in/brettcook/
    GitHub          : github.com/bcook449
    Date Created    : 2025-12-17
    Last Modified   : 2025-12-17
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000197

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    PS C:\> .\__remediation_template(STIG-ID-WN11-CC-000197).ps1 
#>

# STIG ID: WN11-CC-000197
# Title: Turn off Microsoft consumer experiences
# Severity: Medium

$RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
$ValueName = "DisableWindowsConsumerFeatures"
$ExpectedValue = 1

Write-Output "Remediating STIG WN11-CC-000197..."

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

Write-Output "STIG WN11-CC-000197 remediated successfully."
