<#
.SYNOPSIS
    Report generation module for Entra security assessments.

.DESCRIPTION
    Generates comprehensive HTML and JSON reports from security findings.
    Includes severity-based color coding, detailed remediation guidance,
    and executive summary statistics.
#>

function New-AssessmentReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [Array]$Findings,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$TenantInfo,
        
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet('HTML', 'JSON')]
        [string]$Format
    )
    
    switch ($Format) {
        'HTML' {
            New-HTMLReport -Findings $Findings -TenantInfo $TenantInfo -OutputPath $OutputPath
        }
        'JSON' {
            New-JSONReport -Findings $Findings -TenantInfo $TenantInfo -OutputPath $OutputPath
        }
    }
}

function New-HTMLReport {
    param(
        [Array]$Findings,
        [hashtable]$TenantInfo,
        [string]$OutputPath
    )
    
    $criticalCount = ($Findings | Where-Object { $_.Severity -eq 'Critical' }).Count
    $highCount = ($Findings | Where-Object { $_.Severity -eq 'High' }).Count
    $mediumCount = ($Findings | Where-Object { $_.Severity -eq 'Medium' }).Count
    $lowCount = ($Findings | Where-Object { $_.Severity -eq 'Low' }).Count
    
    $totalFindings = $Findings.Count
    $riskScore = [math]::Min(100, ($criticalCount * 25) + ($highCount * 10) + ($mediumCount * 5) + ($lowCount * 1))
    
    $findingsHTML = ""
    $categories = $Findings | Group-Object -Property Category
    
    foreach ($category in $categories) {
        $categoryName = $category.Name
        $categoryFindings = $category.Group
        
        $findingsHTML += @"
        <div class="category-section">
            <h2>$categoryName</h2>
"@
        
        foreach ($finding in $categoryFindings) {
            $severityClass = $finding.Severity.ToLower()
            $severityIcon = switch ($finding.Severity) {
                'Critical' { '🔴' }
                'High' { '🟠' }
                'Medium' { '🟡' }
                'Low' { '⚪' }
            }
            
            $affectedItemsHTML = ""
            if ($finding.AffectedItems.Count -gt 0) {
                $itemCount = $finding.AffectedItems.Count
                $displayItems = $finding.AffectedItems | Select-Object -First 10
                $affectedItemsHTML = "<div class='affected-items'><strong>Affected Items ($itemCount):</strong><ul>"
                foreach ($item in $displayItems) {
                    $affectedItemsHTML += "<li>$item</li>"
                }
                if ($itemCount -gt 10) {
                    $affectedItemsHTML += "<li><em>... and $($itemCount - 10) more</em></li>"
                }
                $affectedItemsHTML += "</ul></div>"
            }
            
            $remediationHTML = "<div class='remediation-steps'><strong>Remediation Steps:</strong><ol>"
            foreach ($step in $finding.RemediationSteps) {
                $remediationHTML += "<li>$step</li>"
            }
            $remediationHTML += "</ol></div>"
            
            $findingsHTML += @"
            <div class="finding-card severity-$severityClass">
                <div class="finding-header">
                    <span class="severity-badge severity-$severityClass">$severityIcon $($finding.Severity)</span>
                    <span class="finding-id">$($finding.FindingId)</span>
                </div>
                <h3>$($finding.Title)</h3>
                <div class="finding-section">
                    <h4>Description</h4>
                    <p>$($finding.Description)</p>
                </div>
                <div class="finding-section">
                    <h4>Security Impact</h4>
                    <p>$($finding.Impact)</p>
                </div>
                <div class="finding-section">
                    <h4>Recommendation</h4>
                    <p>$($finding.Recommendation)</p>
                </div>
                $affectedItemsHTML
                $remediationHTML
            </div>
"@
        }
        
        $findingsHTML += "</div>"
    }
    
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Entra Security Assessment Report</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
            padding: 20px;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        .header {
            background: linear-gradient(135deg, #0078d4 0%, #00bcf2 100%);
            color: white;
            padding: 40px;
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        
        .header p {
            font-size: 1.1em;
            opacity: 0.9;
        }
        
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px 40px;
            background: #f8f8f8;
            border-bottom: 3px solid #0078d4;
        }
        
        .summary-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            text-align: center;
        }
        
        .summary-card h3 {
            font-size: 2em;
            margin-bottom: 5px;
        }
        
        .summary-card p {
            color: #666;
            font-size: 0.9em;
        }
        
        .summary-card.critical h3 { color: #d13438; }
        .summary-card.high h3 { color: #ff8c00; }
        .summary-card.medium h3 { color: #ffb900; }
        .summary-card.low h3 { color: #107c10; }
        .summary-card.risk h3 { 
            color: $($riskScore -gt 70 ? '#d13438' : $riskScore -gt 40 ? '#ff8c00' : '#107c10'); 
        }
        
        .tenant-info {
            padding: 30px 40px;
            background: white;
            border-bottom: 1px solid #e0e0e0;
        }
        
        .tenant-info h2 {
            color: #0078d4;
            margin-bottom: 15px;
        }
        
        .tenant-info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
        }
        
        .tenant-info-item {
            padding: 10px;
            background: #f8f8f8;
            border-radius: 5px;
        }
        
        .tenant-info-item strong {
            display: block;
            color: #0078d4;
            margin-bottom: 5px;
        }
        
        .content {
            padding: 40px;
        }
        
        .category-section {
            margin-bottom: 50px;
        }
        
        .category-section h2 {
            color: #0078d4;
            border-bottom: 2px solid #0078d4;
            padding-bottom: 10px;
            margin-bottom: 25px;
            font-size: 1.8em;
        }
        
        .finding-card {
            background: white;
            border-left: 5px solid #ccc;
            padding: 25px;
            margin-bottom: 25px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            border-radius: 5px;
        }
        
        .finding-card.severity-critical {
            border-left-color: #d13438;
            background: #fff5f5;
        }
        
        .finding-card.severity-high {
            border-left-color: #ff8c00;
            background: #fff8f0;
        }
        
        .finding-card.severity-medium {
            border-left-color: #ffb900;
            background: #fffef0;
        }
        
        .finding-card.severity-low {
            border-left-color: #107c10;
            background: #f0fff0;
        }
        
        .finding-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }
        
        .severity-badge {
            display: inline-block;
            padding: 5px 15px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 0.9em;
        }
        
        .severity-badge.severity-critical {
            background: #d13438;
            color: white;
        }
        
        .severity-badge.severity-high {
            background: #ff8c00;
            color: white;
        }
        
        .severity-badge.severity-medium {
            background: #ffb900;
            color: #333;
        }
        
        .severity-badge.severity-low {
            background: #107c10;
            color: white;
        }
        
        .finding-id {
            font-family: 'Courier New', monospace;
            color: #666;
            font-size: 0.9em;
        }
        
        .finding-card h3 {
            font-size: 1.4em;
            color: #333;
            margin-bottom: 15px;
        }
        
        .finding-section {
            margin-bottom: 20px;
        }
        
        .finding-section h4 {
            color: #0078d4;
            margin-bottom: 10px;
            font-size: 1.1em;
        }
        
        .finding-section p {
            line-height: 1.8;
        }
        
        .affected-items {
            background: rgba(0, 120, 212, 0.05);
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        
        .affected-items ul {
            margin-left: 20px;
            margin-top: 10px;
        }
        
        .affected-items li {
            margin-bottom: 5px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
        }
        
        .remediation-steps {
            background: rgba(16, 124, 16, 0.05);
            padding: 15px;
            border-radius: 5px;
            border-left: 3px solid #107c10;
        }
        
        .remediation-steps ol {
            margin-left: 20px;
            margin-top: 10px;
        }
        
        .remediation-steps li {
            margin-bottom: 8px;
            line-height: 1.6;
        }
        
        .footer {
            background: #333;
            color: white;
            padding: 30px 40px;
            text-align: center;
        }
        
        .footer p {
            margin-bottom: 10px;
        }
        
        @media print {
            body {
                padding: 0;
            }
            
            .container {
                box-shadow: none;
            }
            
            .finding-card {
                page-break-inside: avoid;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Entra Security Assessment Report</h1>
            <p>Comprehensive security configuration analysis</p>
            <p>Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
        </div>
        
        <div class="summary">
            <div class="summary-card critical">
                <h3>$criticalCount</h3>
                <p>Critical</p>
            </div>
            <div class="summary-card high">
                <h3>$highCount</h3>
                <p>High</p>
            </div>
            <div class="summary-card medium">
                <h3>$mediumCount</h3>
                <p>Medium</p>
            </div>
            <div class="summary-card low">
                <h3>$lowCount</h3>
                <p>Low</p>
            </div>
            <div class="summary-card risk">
                <h3>$riskScore</h3>
                <p>Risk Score (0-100)</p>
            </div>
        </div>
        
        <div class="tenant-info">
            <h2>Tenant Information</h2>
            <div class="tenant-info-grid">
                <div class="tenant-info-item">
                    <strong>Tenant ID</strong>
                    $($TenantInfo.TenantId)
                </div>
                <div class="tenant-info-item">
                    <strong>Display Name</strong>
                    $($TenantInfo.DisplayName)
                </div>
                <div class="tenant-info-item">
                    <strong>Default Domain</strong>
                    $($TenantInfo.DefaultDomain)
                </div>
                <div class="tenant-info-item">
                    <strong>Assessment Date</strong>
                    $(Get-Date -Format "yyyy-MM-dd")
                </div>
            </div>
        </div>
        
        <div class="content">
            <h2 style="color: #0078d4; margin-bottom: 30px;">Security Findings</h2>
            $findingsHTML
        </div>
        
        <div class="footer">
            <p><strong>Entra Security Assessment Tool</strong></p>
            <p>This report contains security findings and recommendations. Review all findings in context of your organization's requirements.</p>
            <p>For questions or support, consult your security team or Microsoft documentation.</p>
        </div>
    </div>
</body>
</html>
"@
    
    $html | Out-File -FilePath $OutputPath -Encoding UTF8
    Write-Host "[+] HTML report generated: $OutputPath" -ForegroundColor Green
}

function New-JSONReport {
    param(
        [Array]$Findings,
        [hashtable]$TenantInfo,
        [string]$OutputPath
    )
    
    $report = @{
        GeneratedDate = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
        TenantInfo = $TenantInfo
        Summary = @{
            TotalFindings = $Findings.Count
            Critical = ($Findings | Where-Object { $_.Severity -eq 'Critical' }).Count
            High = ($Findings | Where-Object { $_.Severity -eq 'High' }).Count
            Medium = ($Findings | Where-Object { $_.Severity -eq 'Medium' }).Count
            Low = ($Findings | Where-Object { $_.Severity -eq 'Low' }).Count
        }
        Findings = $Findings
    }
    
    $report | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputPath -Encoding UTF8
    Write-Host "[+] JSON report generated: $OutputPath" -ForegroundColor Green
}

Export-ModuleMember -Function New-AssessmentReport
