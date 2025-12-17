<#
.SYNOPSIS
    This PowerShell script ensures that Group Policy Objects are processed even if they are not changed. 

.NOTES
    Author          : Brett Cook
    LinkedIn        : linkedin.com/in/brettcook/
    GitHub          : github.com/bcook449
    Date Created    : 2025-12-17
    Last Modified   : 2024-12-17
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000090

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
  
    PS C:\> .\__remediation_template(STIG-ID-WN11-CC-000090).ps1 
#>

# STIG ID: WN11-CC-000090
# Title: Group Policy processing 
# Severity: Medium

$RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}"
$ValueName = "NoGPOListChanges"
$ExpectedValue = 0

Write-Output "Checking STIG WN11-CC-000090..."

# Ensure registry path exists
if (-not (Test-Path $RegPath)) {
    Write-Output "Registry path does not exist. Creating path..."
    New-Item -Path $RegPath -Force | Out-Null
}

# Get current value
$CurrentValue = Get-ItemProperty -Path $RegPath -Name $ValueName -ErrorAction SilentlyContinue

if ($null -eq $CurrentValue) {
    Write-Output "Registry value does not exist. Creating value and setting to 0."
    New-ItemProperty -Path $RegPath `
        -Name $ValueName `
        -PropertyType DWord `
        -Value $ExpectedValue `
        -Force | Out-Null

    Write-Output "STIG WN11-CC-000090 remediated."
}
elseif ($CurrentValue.$ValueName -ne $ExpectedValue) {
    Write-Output "Registry value is misconfigured. Correcting value to 0."
    Set-ItemProperty -Path $RegPath -Name $ValueName -Value $ExpectedValue

    Write-Output "STIG WN11-CC-000090 remediated."
}
else {
    Write-Output "Compliant: NoGPOListChanges is correctly set to 0."
}
