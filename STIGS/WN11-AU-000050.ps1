<#
.SYNOPSIS
    This PowerShell script ensures that the Audit subcategory override is enabled and Enables Audit Process Creation.

.NOTES
    Author          : Brett Cook
    LinkedIn        : linkedin.com/in/brettcook/
    GitHub          : github.com/bcook449
    Date Created    : 2025-12-17
    Last Modified   : 2025-12-17
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-AU-000500 & WN11-SO-000030

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    
    PS C:\> .\__remediation_template(STIG-ID-WN10-AU-000500).ps1 
#>

# STIG IDs:
# WN11-SO-000030 - Force audit policy subcategory settings override
# WN11-AU-000050 - Audit Process Creation (Success)

Write-Output "Checking audit policy STIG compliance..."

############################################
# WN11-SO-000030
# Force audit subcategory override
############################################

$RegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$ValueName = "SCENoApplyLegacyAuditPolicy"
$ExpectedValue = 1

$CurrentValue = Get-ItemProperty -Path $RegPath -Name $ValueName -ErrorAction SilentlyContinue

if ($null -eq $CurrentValue -or $CurrentValue.$ValueName -ne $ExpectedValue) {
    Write-Output "Remediating WN11-SO-000030: Enabling audit subcategory override..."
    New-ItemProperty -Path $RegPath `
        -Name $ValueName `
        -PropertyType DWord `
        -Value $ExpectedValue `
        -Force | Out-Null
    Write-Output "WN11-SO-000030 remediated."
} else {
    Write-Output "Compliant: Audit subcategory override is enabled."
}

############################################
# WN11-AU-000050
# Audit Process Creation - Success
############################################

$AuditCheck = auditpol /get /subcategory:"Process Creation" | Select-String "Success"

if ($null -eq $AuditCheck) {
    Write-Output "Remediating WN11-AU-000050: Enabling Audit Process Creation (Success)..."
    auditpol /set /subcategory:"Process Creation" /success:enable | Out-Null
    Write-Output "WN11-AU-000050 remediated."
} else {
    Write-Output "Compliant: Audit Process Creation (Success) is enabled."
}

Write-Output "Audit policy STIG check completed."
