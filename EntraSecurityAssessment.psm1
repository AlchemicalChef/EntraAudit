<#
.SYNOPSIS
    Entra Security Assessment Module

.DESCRIPTION
    Root module for the Entra Security Assessment tool. This module orchestrates
    security assessments for Microsoft Entra ID (Azure AD) environments, including
    general security configuration checks and Conditional Access policy analysis.

.NOTES
    Author: AlchemicalChef
    Version: 1.0.0
    Requires: PowerShell 5.1 or later, Microsoft Graph PowerShell SDK
#>

#Requires -Version 5.1

# Get the module path
$ModulePath = $PSScriptRoot

# Import nested module scripts
$ModulesToImport = @(
    'Modules\GeneralSecurityAssessment.ps1',
    'Modules\ConditionalAccessAssessment.ps1',
    'Modules\ReportGenerator.ps1'
)

foreach ($Module in $ModulesToImport) {
    $ModuleFullPath = Join-Path -Path $ModulePath -ChildPath $Module
    
    if (Test-Path -Path $ModuleFullPath) {
        Write-Verbose "Loading module: $Module"
        . $ModuleFullPath
    }
    else {
        Write-Error "Required module not found: $ModuleFullPath"
    }
}

<#
.SYNOPSIS
    Performs comprehensive security assessment of Microsoft Entra ID configuration.

.DESCRIPTION
    The Invoke-EntraSecurityAssessment cmdlet performs a thorough security assessment
    of your Microsoft Entra ID (Azure AD) tenant. It evaluates general security
    configurations and Conditional Access policies against Microsoft best practices
    and generates detailed reports with remediation guidance.

.PARAMETER OutputPath
    Specifies the directory where assessment reports will be saved.
    Default: .\Reports

.PARAMETER IncludeConditionalAccess
    Indicates whether to include Conditional Access policy assessment.
    Default: $true

.PARAMETER ExportToJson
    Indicates whether to generate a JSON report.
    Default: $true

.PARAMETER ExportToHTML
    Indicates whether to generate an HTML report.
    Default: $true

.EXAMPLE
    Invoke-EntraSecurityAssessment
    
    Runs complete assessment with default settings (both general security and
    Conditional Access checks) and saves reports to .\Reports directory.

.EXAMPLE
    Invoke-EntraSecurityAssessment -OutputPath "C:\SecurityReports"
    
    Runs complete assessment and saves reports to C:\SecurityReports directory.

.EXAMPLE
    Invoke-EntraSecurityAssessment -IncludeConditionalAccess:$false
    
    Runs only general security checks, skipping Conditional Access assessment.

.EXAMPLE
    Invoke-EntraSecurityAssessment -ExportToHTML:$false
    
    Generates only JSON report, skipping HTML report generation.

.NOTES
    Prerequisites:
    - Connected to Microsoft Graph with appropriate permissions
    - Required permissions: Policy.Read.All, Directory.Read.All, 
      UserAuthenticationMethod.Read.All, Organization.Read.All,
      RoleManagement.Read.All, Application.Read.All
    
    Before running:
    Connect-MgGraph -Scopes "Policy.Read.All", "Directory.Read.All", 
                             "UserAuthenticationMethod.Read.All", 
                             "Organization.Read.All", "RoleManagement.Read.All", 
                             "Application.Read.All"

.LINK
    https://learn.microsoft.com/entra/identity/
    https://learn.microsoft.com/entra/identity/conditional-access/best-practices
#>
function Invoke-EntraSecurityAssessment {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = ".\Reports",
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeConditionalAccess = $true,
        
        [Parameter(Mandatory = $false)]
        [switch]$ExportToJson = $true,
        
        [Parameter(Mandatory = $false)]
        [switch]$ExportToHTML = $true
    )
    
    begin {
        Write-Host "`n========================================" -ForegroundColor Cyan
        Write-Host "  Entra Security Assessment Tool v1.0" -ForegroundColor Cyan
        Write-Host "========================================`n" -ForegroundColor Cyan
        
        # Verify Microsoft Graph connection
        Write-Host "[INFO] Verifying Microsoft Graph connection..." -ForegroundColor Yellow
        
        try {
            $context = Get-MgContext
            if (-not $context) {
                throw "Not connected to Microsoft Graph"
            }
            Write-Host "[SUCCESS] Connected to tenant: $($context.TenantId)" -ForegroundColor Green
        }
        catch {
            Write-Host "[ERROR] Not connected to Microsoft Graph!" -ForegroundColor Red
            Write-Host "Please run: Connect-MgGraph -Scopes 'Policy.Read.All', 'Directory.Read.All', 'UserAuthenticationMethod.Read.All', 'Organization.Read.All', 'RoleManagement.Read.All', 'Application.Read.All'" -ForegroundColor Yellow
            throw "Microsoft Graph connection required"
        }
        
        # Create output directory if it doesn't exist
        if (-not (Test-Path -Path $OutputPath)) {
            New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
            Write-Host "[INFO] Created output directory: $OutputPath" -ForegroundColor Yellow
        }
        
        # Initialize findings collection
        $allFindings = @()
        $startTime = Get-Date
    }
    
    process {
        try {
            # Gather tenant information
            Write-Host "`n[STEP 1/4] Gathering tenant information..." -ForegroundColor Cyan
            
            try {
                $organization = Get-MgOrganization -ErrorAction Stop
                $tenantInfo = @{
                    TenantId = $organization.Id
                    DisplayName = $organization.DisplayName
                    TechnicalNotificationMails = $organization.TechnicalNotificationMails -join ', '
                    AssessmentDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                }
                Write-Host "[SUCCESS] Tenant information retrieved" -ForegroundColor Green
            }
            catch {
                Write-Host "[WARNING] Could not retrieve full tenant information: $($_.Exception.Message)" -ForegroundColor Yellow
                $tenantInfo = @{
                    TenantId = (Get-MgContext).TenantId
                    DisplayName = "Unknown"
                    TechnicalNotificationMails = "N/A"
                    AssessmentDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                }
            }
            
            # Run General Security Assessment
            Write-Host "`n[STEP 2/4] Running general security assessment..." -ForegroundColor Cyan
            $generalFindings = Get-GeneralSecurityFindings
            $allFindings += $generalFindings
            Write-Host "[SUCCESS] Completed general security assessment - Found $($generalFindings.Count) issues" -ForegroundColor Green
            
            # Run Conditional Access Assessment
            if ($IncludeConditionalAccess) {
                Write-Host "`n[STEP 3/4] Running Conditional Access assessment..." -ForegroundColor Cyan
                $caFindings = Get-ConditionalAccessFindings
                $allFindings += $caFindings
                Write-Host "[SUCCESS] Completed Conditional Access assessment - Found $($caFindings.Count) issues" -ForegroundColor Green
            }
            else {
                Write-Host "`n[STEP 3/4] Skipping Conditional Access assessment (disabled)" -ForegroundColor Yellow
            }
            
            # Generate Reports
            Write-Host "`n[STEP 4/4] Generating assessment reports..." -ForegroundColor Cyan
            
            $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
            $reportBaseName = "EntraSecurityAssessment_$timestamp"
            
            if ($ExportToHTML) {
                $htmlPath = Join-Path -Path $OutputPath -ChildPath "$reportBaseName.html"
                New-AssessmentReport -Findings $allFindings -TenantInfo $tenantInfo -OutputPath $htmlPath -Format "HTML"
                Write-Host "[SUCCESS] HTML report saved: $htmlPath" -ForegroundColor Green
            }
            
            if ($ExportToJson) {
                $jsonPath = Join-Path -Path $OutputPath -ChildPath "$reportBaseName.json"
                New-AssessmentReport -Findings $allFindings -TenantInfo $tenantInfo -OutputPath $jsonPath -Format "JSON"
                Write-Host "[SUCCESS] JSON report saved: $jsonPath" -ForegroundColor Green
            }
            
            # Display summary
            $endTime = Get-Date
            $duration = $endTime - $startTime
            
            Write-Host "`n========================================" -ForegroundColor Cyan
            Write-Host "  Assessment Complete!" -ForegroundColor Cyan
            Write-Host "========================================" -ForegroundColor Cyan
            
            Write-Host "`nSummary:" -ForegroundColor White
            Write-Host "  Duration: $($duration.ToString('mm\:ss'))" -ForegroundColor White
            Write-Host "  Total Findings: $($allFindings.Count)" -ForegroundColor White
            
            $criticalCount = ($allFindings | Where-Object { $_.Severity -eq 'Critical' }).Count
            $highCount = ($allFindings | Where-Object { $_.Severity -eq 'High' }).Count
            $mediumCount = ($allFindings | Where-Object { $_.Severity -eq 'Medium' }).Count
            $lowCount = ($allFindings | Where-Object { $_.Severity -eq 'Low' }).Count
            
            Write-Host "`nBy Severity:" -ForegroundColor White
            if ($criticalCount -gt 0) { Write-Host "  Critical: $criticalCount" -ForegroundColor Red }
            if ($highCount -gt 0) { Write-Host "  High: $highCount" -ForegroundColor DarkRed }
            if ($mediumCount -gt 0) { Write-Host "  Medium: $mediumCount" -ForegroundColor Yellow }
            if ($lowCount -gt 0) { Write-Host "  Low: $lowCount" -ForegroundColor Gray }
            
            Write-Host "`nReports saved to: $OutputPath`n" -ForegroundColor Green
            
        }
        catch {
            Write-Host "`n[ERROR] Assessment failed: $($_.Exception.Message)" -ForegroundColor Red
            Write-Host "Stack Trace: $($_.ScriptStackTrace)" -ForegroundColor Red
            throw
        }
    }
    
    end {
        Write-Host "Assessment complete. Review the reports for detailed findings and remediation guidance.`n" -ForegroundColor Cyan
    }
}

# Export module members
Export-ModuleMember -Function @(
    'Invoke-EntraSecurityAssessment',
    'Get-GeneralSecurityFindings',
    'Get-ConditionalAccessFindings',
    'New-AssessmentReport'
)

Write-Verbose "EntraSecurityAssessment module loaded successfully"
