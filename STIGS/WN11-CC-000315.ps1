<#
.SYNOPSIS
    This PowerShell script ensures that Standard user accounts are not granted elevated privileges by Windows Installer.

.NOTES
    Author          : Brett Cook
    LinkedIn        : linkedin.com/in/brettcook/
    GitHub          : github.com/bcook449
    Date Created    : 2025-12-17
    Last Modified   : 2025-12-17
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000315

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    
    PS C:\> .\__remediation_template(STIG-ID-WN11-CC-000315).ps1 
#>

# STIG ID: WN11-CC-000315
# Title: Always install with elevated privileges must be disabled
# Severity: High

$RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"
$ValueName = "AlwaysInstallElevated"
$ExpectedValue = 0

Write-Output "Checking STIG WN11-CC-000315..."

# Ensure registry path exists
if (-not (Test-Path $RegPath)) {
    Write-Output "Registry path does not exist. Creating path..."
    New-Item -Path $RegPath -Force | Out-Null
}

# Get current value if it exists
$CurrentValue = Get-ItemProperty -Path $RegPath -Name $ValueName -ErrorAction SilentlyContinue

if ($null -eq $CurrentValue) {
    Write-Output "Registry value does not exist. Creating and setting to Disabled (0)."
    New-ItemProperty -Path $RegPath `
        -Name $ValueName `
        -PropertyType DWord `
        -Value $ExpectedValue `
        -Force | Out-Null

    Write-Output "STIG WN11-CC-000315 remediated."
}
elseif ($CurrentValue.$ValueName -ne $ExpectedValue) {
    Write-Output "Registry value is misconfigured. Correcting value to Disabled (0)."
    Set-ItemProperty -Path $RegPath -Name $ValueName -Value $ExpectedValue

    Write-Output "STIG WN11-CC-000315 remediated."
}
else {
    Write-Output "Compliant: AlwaysInstallElevated is correctly set to Disabled (0)."
}
