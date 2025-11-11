<#
.SYNOPSIS
    Conditional Access policy security assessment module.

.DESCRIPTION
    Performs comprehensive analysis of Conditional Access policies including:
    - Baseline policy coverage
    - MFA enforcement
    - Legacy authentication blocking
    - Device compliance
    - Risk-based policies
    - Session controls
    - Policy conflicts and gaps
#>

function Get-ConditionalAccessFindings {
    [CmdletBinding()]
    param()
    
    Write-Host "[*] Running Conditional Access policy assessment..." -ForegroundColor Cyan
    
    $findings = @()
    
    try {
        # Get all Conditional Access policies
        $policies = Get-MgIdentityConditionalAccessPolicy -All
        
        Write-Host "  [+] Found $($policies.Count) Conditional Access policies" -ForegroundColor Gray
        
        # Check 1: MFA for all users
        Write-Host "  [+] Checking MFA enforcement for all users..." -ForegroundColor Gray
        $findings += Test-MFAForAllUsers -Policies $policies
        
        # Check 2: MFA for administrators
        Write-Host "  [+] Checking MFA for administrators..." -ForegroundColor Gray
        $findings += Test-MFAForAdministrators -Policies $policies
        
        # Check 3: Legacy authentication blocking
        Write-Host "  [+] Checking legacy authentication blocking..." -ForegroundColor Gray
        $findings += Test-LegacyAuthBlocking -Policies $policies
        
        # Check 4: Device compliance
        Write-Host "  [+] Checking device compliance requirements..." -ForegroundColor Gray
        $findings += Test-DeviceCompliance -Policies $policies
        
        # Check 5: Break-glass accounts
        Write-Host "  [+] Checking break-glass account exclusions..." -ForegroundColor Gray
        $findings += Test-BreakGlassAccounts -Policies $policies
        
        # Check 6: Risk-based policies
        Write-Host "  [+] Checking risk-based policies..." -ForegroundColor Gray
        $findings += Test-RiskBasedPolicies -Policies $policies
        
        # Check 7: Session controls
        Write-Host "  [+] Checking session controls..." -ForegroundColor Gray
        $findings += Test-SessionControls -Policies $policies
        
        # Check 8: Location-based policies
        Write-Host "  [+] Checking location-based policies..." -ForegroundColor Gray
        $findings += Test-LocationPolicies -Policies $policies
        
        # Check 9: Policy state (enabled/disabled/report-only)
        Write-Host "  [+] Checking policy states..." -ForegroundColor Gray
        $findings += Test-PolicyStates -Policies $policies
        
        # Check 10: Policy complexity
        Write-Host "  [+] Analyzing policy complexity..." -ForegroundColor Gray
        $findings += Test-PolicyComplexity -Policies $policies
        
        # Check 11: Application-specific policies
        Write-Host "  [+] Checking application-specific controls..." -ForegroundColor Gray
        $findings += Test-ApplicationPolicies -Policies $policies
        
        # Check 12: Policy conflicts
        Write-Host "  [+] Checking for policy conflicts..." -ForegroundColor Gray
        $findings += Test-PolicyConflicts -Policies $policies
        
    }
    catch {
        Write-Warning "Failed to retrieve Conditional Access policies: $_"
        
        $findings += [PSCustomObject]@{
            Category = "Conditional Access"
            FindingId = "CA000"
            Title = "Unable to Retrieve Conditional Access Policies"
            Severity = "High"
            Description = "Failed to retrieve Conditional Access policies. This may indicate insufficient permissions or missing Azure AD Premium licensing."
            Impact = "Cannot assess Conditional Access configuration, which is critical for modern security posture. Without CA policies, organizations lack granular access controls."
            Recommendation = "Verify you have 'Policy.Read.All' permission and Azure AD Premium P1 or P2 licensing."
            AffectedItems = @("Conditional Access assessment incomplete")
            RemediationSteps = @(
                "1. Verify Azure AD Premium P1 or P2 licenses are assigned",
                "2. Ensure you have 'Policy.Read.All' Graph API permission",
                "3. Try disconnecting and reconnecting: Disconnect-MgGraph; Connect-MgGraph -Scopes 'Policy.Read.All'",
                "4. If issue persists, contact your Global Administrator"
            )
        }
    }
    
    return $findings
}

function Test-MFAForAllUsers {
    param($Policies)
    $findings = @()
    
    # Check if there's a policy requiring MFA for all users
    $mfaPolicy = $policies | Where-Object {
        $_.Conditions.Users.IncludeUsers -contains 'All' -and
        $_.GrantControls.BuiltInControls -contains 'mfa' -and
        $_.State -eq 'enabled'
    }
    
    if (-not $mfaPolicy) {
        $findings += [PSCustomObject]@{
            Category = "MFA Enforcement"
            FindingId = "CA001"
            Title = "No MFA Policy for All Users"
            Severity = "Critical"
            Description = "No Conditional Access policy found that requires MFA for all users."
            Impact = "Without universal MFA enforcement, user accounts are vulnerable to credential theft, phishing, and password-based attacks. This represents the single most critical security gap. Microsoft reports that MFA blocks 99.9% of account compromise attacks."
            Recommendation = "Create a Conditional Access policy requiring MFA for all users with appropriate break-glass account exclusions."
            AffectedItems = @("All users potentially at risk")
            RemediationSteps = @(
                "1. Navigate to Entra ID > Security > Conditional Access > New Policy",
                "2. Name: 'Require MFA for All Users'",
                "3. Assignments > Users: Include 'All users'",
                "4. Assignments > Users: Exclude emergency access accounts (2 accounts)",
                "5. Assignments > Cloud apps: Include 'All cloud apps'",
                "6. Access controls > Grant: Select 'Grant access'",
                "7. Access controls > Grant: Check 'Require multi-factor authentication'",
                "8. Enable policy: Select 'Report-only' initially",
                "9. Monitor sign-in logs for 7-14 days to identify impact",
                "10. Review report-only results in Conditional Access Insights",
                "11. Communicate MFA registration process to users",
                "12. Change policy to 'On' after validation period",
                "13. Monitor for support issues and user feedback",
                "14. Ensure help desk is prepared for MFA support calls"
            )
        }
    }
    
    return $findings
}

function Test-MFAForAdministrators {
    param($Policies)
    $findings = @()
    
    # Check for admin MFA policy
    $adminMFAPolicy = $policies | Where-Object {
        $_.Conditions.Users.IncludeRoles.Count -gt 0 -and
        $_.GrantControls.BuiltInControls -contains 'mfa' -and
        $_.State -eq 'enabled'
    }
    
    if (-not $adminMFAPolicy) {
        $findings += [PSCustomObject]@{
            Category = "Privileged Access Protection"
            FindingId = "CA002"
            Title = "No MFA Policy for Administrator Roles"
            Severity = "Critical"
            Description = "No Conditional Access policy found specifically requiring MFA for administrator roles."
            Impact = "Administrator accounts are high-value targets with elevated privileges. Compromised admin accounts can lead to complete tenant takeover, data breaches, and ransomware deployment. Admin accounts must have the strongest protection."
            Recommendation = "Create a dedicated Conditional Access policy requiring MFA for all administrator roles, even if a general MFA policy exists."
            AffectedItems = @("All administrator roles")
            RemediationSteps = @(
                "1. Navigate to Entra ID > Security > Conditional Access > New Policy",
                "2. Name: 'Require MFA for Administrators'",
                "3. Assignments > Users: Select 'Directory roles'",
                "4. Select all admin roles: Global Administrator, Security Administrator, User Administrator, etc.",
                "5. Assignments > Cloud apps: Include 'All cloud apps'",
                "6. Access controls > Grant: 'Require multi-factor authentication'",
                "7. Session: Sign-in frequency = 4 hours (reduce session lifetime)",
                "8. Enable policy: 'On' (admins should already have MFA)",
                "9. Consider requiring compliant device for admins",
                "10. Implement Privileged Access Workstation (PAW) requirements",
                "11. Monitor admin sign-ins closely",
                "12. Set up alerts for admin account anomalies"
            )
        }
    }
    
    return $findings
}

function Test-LegacyAuthBlocking {
    param($Policies)
    $findings = @()
    
    # Check for policy blocking legacy authentication
    $legacyAuthBlock = $policies | Where-Object {
        $_.Conditions.ClientAppTypes -contains 'exchangeActiveSync' -or
        $_.Conditions.ClientAppTypes -contains 'other' -and
        $_.GrantControls.BuiltInControls -contains 'block' -and
        $_.State -eq 'enabled'
    }
    
    if (-not $legacyAuthBlock) {
        $findings += [PSCustomObject]@{
            Category = "Legacy Authentication"
            FindingId = "CA003"
            Title = "Legacy Authentication Not Blocked"
            Severity = "High"
            Description = "No Conditional Access policy found blocking legacy authentication protocols."
            Impact = "Legacy authentication protocols (Basic Auth, POP, IMAP, SMTP) don't support MFA and are primary attack vectors for credential stuffing and password spray attacks. These protocols bypass all modern security protections."
            Recommendation = "Block legacy authentication for all users except documented service accounts that require it (with plan to modernize)."
            AffectedItems = @("All authentication protocols")
            RemediationSteps = @(
                "1. First, identify legacy auth usage in sign-in logs:",
                "   - Entra ID > Sign-in logs > Add filters > Client app",
                "   - Document apps/users using legacy authentication",
                "2. Work with app owners to migrate to modern authentication",
                "3. For Exchange Online: Disable basic auth in Exchange admin center",
                "4. Create Conditional Access policy:",
                "   - Name: 'Block Legacy Authentication'",
                "   - Assignments > Users: 'All users'",
                "   - Exclude service accounts if necessary (document exceptions)",
                "   - Cloud apps: 'All cloud apps'",
                "   - Conditions > Client apps: Check 'Exchange ActiveSync clients' and 'Other clients'",
                "   - Grant: 'Block access'",
                "5. Enable in Report-only mode for 30 days",
                "6. Review impact and address any legitimate usage",
                "7. Enable policy after migration complete",
                "8. Monitor for blocked attempts",
                "9. Create alerts for legacy auth attempts"
            )
        }
    }
    
    return $findings
}

function Test-DeviceCompliance {
    param($Policies)
    $findings = @()
    
    # Check for device compliance or hybrid join requirements
    $devicePolicy = $policies | Where-Object {
        $_.GrantControls.BuiltInControls -contains 'compliantDevice' -or
        $_.GrantControls.BuiltInControls -contains 'domainJoinedDevice' -and
        $_.State -eq 'enabled'
    }
    
    if (-not $devicePolicy) {
        $findings += [PSCustomObject]@{
            Category = "Device Management"
            FindingId = "CA004"
            Title = "No Device Compliance Requirements"
            Severity = "Medium"
            Description = "No Conditional Access policies found requiring device compliance or hybrid join."
            Impact = "Without device compliance requirements, users can access corporate resources from unmanaged, potentially compromised devices. This increases risk of data leakage, malware introduction, and lateral movement from compromised endpoints."
            Recommendation = "Implement device-based Conditional Access requiring either Intune compliance or Hybrid Azure AD join for accessing corporate resources."
            AffectedItems = @("All devices")
            RemediationSteps = @(
                "Prerequisites:",
                "1. Enroll devices in Microsoft Intune (or configure Hybrid Azure AD Join)",
                "2. Define device compliance policies in Intune",
                "3. Set baseline requirements: encryption, firewall, antivirus, OS version",
                "",
                "Create Conditional Access policy:",
                "4. Navigate to Entra ID > Security > Conditional Access > New Policy",
                "5. Name: 'Require Compliant or Hybrid Joined Device'",
                "6. Assignments > Users: 'All users' (or start with pilot group)",
                "7. Exclude: Break-glass accounts, guest users if appropriate",
                "8. Cloud apps: 'Office 365' (expand to all apps gradually)",
                "9. Conditions > Client apps: Browser, Mobile apps and desktop clients",
                "10. Grant: Select 'Require device to be marked as compliant' OR 'Require Hybrid Azure AD joined device'",
                "11. Multiple controls: 'Require one of the selected controls'",
                "12. Enable in Report-only mode",
                "13. Communicate device enrollment requirements to users",
                "14. Provide device enrollment instructions and support",
                "15. Monitor compliance status and address device issues",
                "16. Enable policy after validation"
            )
        }
    }
    
    return $findings
}

function Test-BreakGlassAccounts {
    param($Policies)
    $findings = @()
    
    # Check if policies have exclusions (potential break-glass accounts)
    $policiesWithExclusions = $policies | Where-Object {
        $_.Conditions.Users.ExcludeUsers.Count -gt 0
    }
    
    if ($policiesWithExclusions.Count -eq 0) {
        $findings += [PSCustomObject]@{
            Category = "Business Continuity"
            FindingId = "CA005"
            Title = "No Break-Glass Account Exclusions Found"
            Severity = "High"
            Description = "Conditional Access policies don't appear to have emergency access (break-glass) account exclusions."
            Impact = "Without break-glass accounts, organizations risk complete lockout if Conditional Access policies misconfigure or MFA systems fail. This could prevent recovery from policy errors and cause extended outages."
            Recommendation = "Create 2-3 emergency access accounts excluded from all Conditional Access policies. Store credentials securely, monitor closely, and test regularly."
            AffectedItems = @("Emergency access capability")
            RemediationSteps = @(
                "1. Create 2 emergency access accounts:",
                "   - Name clearly: breakglass1@domain.com, breakglass2@domain.com",
                "   - Assign Global Administrator role",
                "   - Use extremely strong passwords (20+ random characters)",
                "   - Do NOT configure MFA on these accounts",
                "   - Set passwords to never expire",
                "2. Store credentials securely:",
                "   - Split credentials between 2-3 executives",
                "   - Use physical secure storage (safe)",
                "   - Document password recovery process",
                "3. Configure monitoring:",
                "   - Create alert for any break-glass account sign-in",
                "   - Alert should go to security team immediately",
                "   - Log Analytics query: SigninLogs | where UserPrincipalName contains 'breakglass'",
                "4. Exclude from all Conditional Access policies:",
                "   - Edit each CA policy",
                "   - Add both break-glass accounts to exclusions",
                "   - Document exclusion reason",
                "5. Test quarterly:",
                "   - Perform test sign-in with break-glass account",
                "   - Verify access to critical admin functions",
                "   - Verify monitoring alerts trigger",
                "   - Verify credential recovery process",
                "6. Document:",
                "   - Break-glass account usage procedures",
                "   - Who has access to credentials",
                "   - Recovery and notification processes"
            )
        }
    }
    else {
        # Check if exclusions are consistent across policies
        $exclusionConsistency = @{}
        foreach ($policy in $policiesWithExclusions) {
            foreach ($excludedUser in $policy.Conditions.Users.ExcludeUsers) {
                if (-not $exclusionConsistency.ContainsKey($excludedUser)) {
                    $exclusionConsistency[$excludedUser] = 0
                }
                $exclusionConsistency[$excludedUser]++
            }
        }
        
        # Find users not excluded from all policies
        $maxExclusions = ($policiesWithExclusions | Measure-Object).Count
        $inconsistentExclusions = $exclusionConsistency.GetEnumerator() | Where-Object { $_.Value -lt $maxExclusions }
        
        if ($inconsistentExclusions.Count -gt 0) {
            $findings += [PSCustomObject]@{
                Category = "Business Continuity"
                FindingId = "CA006"
                Title = "Inconsistent Break-Glass Account Exclusions"
                Severity = "Medium"
                Description = "Emergency access accounts are not excluded from all Conditional Access policies consistently."
                Impact = "Inconsistent exclusions may still result in lockout scenarios if emergency accounts are blocked by some policies. Break-glass accounts must be excluded from ALL policies to ensure emergency access."
                Recommendation = "Ensure all emergency access accounts are excluded from every Conditional Access policy."
                AffectedItems = $inconsistentExclusions.Name
                RemediationSteps = @(
                    "1. Identify all break-glass/emergency access accounts",
                    "2. Review each Conditional Access policy",
                    "3. Add all break-glass accounts to exclusions in every policy",
                    "4. Document which accounts are break-glass accounts",
                    "5. Test break-glass account access regularly",
                    "6. Set up automated monitoring for exclusion consistency"
                )
            }
        }
    }
    
    return $findings
}

function Test-RiskBasedPolicies {
    param($Policies)
    $findings = @()
    
    # Check for risk-based policies (requires Identity Protection)
    $riskPolicy = $policies | Where-Object {
        $_.Conditions.SignInRiskLevels.Count -gt 0 -or
        $_.Conditions.UserRiskLevels.Count -gt 0
    }
    
    if (-not $riskPolicy) {
        $findings += [PSCustomObject]@{
            Category = "Risk-Based Protection"
            FindingId = "CA007"
            Title = "No Risk-Based Conditional Access Policies"
            Severity = "Medium"
            Description = "No Conditional Access policies using sign-in risk or user risk conditions (Azure AD Identity Protection)."
            Impact = "Risk-based policies provide adaptive security by responding to detected threats in real-time. Without them, organizations cannot automatically respond to suspicious sign-ins, leaked credentials, or anomalous behavior patterns detected by Microsoft's threat intelligence."
            Recommendation = "Implement risk-based Conditional Access policies using Azure AD Identity Protection (requires Azure AD Premium P2)."
            AffectedItems = @("Risk-based protection not configured")
            RemediationSteps = @(
                "Prerequisites:",
                "1. Obtain Azure AD Premium P2 licenses",
                "2. Enable Azure AD Identity Protection",
                "3. Review Identity Protection risk detections",
                "",
                "Create Sign-In Risk Policy:",
                "4. Navigate to Entra ID > Security > Conditional Access > New Policy",
                "5. Name: 'Block High Risk Sign-Ins'",
                "6. Assignments > Users: 'All users', exclude break-glass",
                "7. Cloud apps: 'All cloud apps'",
                "8. Conditions > Sign-in risk: Select 'High'",
                "9. Grant: 'Block access' (or require MFA for medium risk)",
                "10. Enable policy: Report-only initially",
                "",
                "Create User Risk Policy:",
                "11. Create new policy: 'Require Password Change for High User Risk'",
                "12. Assignments > Users: 'All users', exclude break-glass",
                "13. Cloud apps: 'All cloud apps'",
                "14. Conditions > User risk: Select 'High'",
                "15. Grant: 'Require password change' + 'Require multi-factor authentication'",
                "16. Enable policy after testing",
                "",
                "17. Monitor Identity Protection dashboard regularly",
                "18. Investigate and remediate flagged users",
                "19. Configure risk event notifications to security team"
            )
        }
    }
    
    return $findings
}

function Test-SessionControls {
    param($Policies)
    $findings = @()
    
    # Check for session control policies
    $sessionPolicy = $policies | Where-Object {
        $_.SessionControls -ne $null -and (
            $_.SessionControls.SignInFrequency -ne $null -or
            $_.SessionControls.ApplicationEnforcedRestrictions -ne $null -or
            $_.SessionControls.CloudAppSecurity -ne $null
        )
    }
    
    if (-not $sessionPolicy) {
        $findings += [PSCustomObject]@{
            Category = "Session Management"
            FindingId = "CA008"
            Title = "No Session Control Policies Configured"
            Severity = "Low"
            Description = "No Conditional Access policies found implementing session controls (sign-in frequency, app restrictions)."
            Impact = "Without session controls, user sessions may persist indefinitely, increasing risk from compromised devices or shared computers. Session controls provide defense-in-depth by limiting session duration and enforcing app-level restrictions."
            Recommendation = "Implement session controls for sensitive applications and privileged accounts to limit session duration and enforce app-level restrictions."
            AffectedItems = @("Session controls not configured")
            RemediationSteps = @(
                "Configure Sign-In Frequency for Privileged Users:",
                "1. Edit your admin MFA policy (or create new)",
                "2. Session controls: Enable 'Sign-in frequency'",
                "3. Set to 4 hours for privileged accounts",
                "4. This forces re-authentication periodically",
                "",
                "Configure for Sensitive Applications:",
                "5. Create policy targeting sensitive apps (HR, Finance systems)",
                "6. Enable 'Sign-in frequency': 8 hours",
                "7. Enable 'Persistent browser session': Never",
                "",
                "Consider Conditional Access App Control (MCAS):",
                "8. Requires Microsoft Defender for Cloud Apps license",
                "9. Enable 'Use Conditional Access App Control'",
                "10. Configure policies: monitor-only or block downloads",
                "11. Useful for contractor/guest access to sensitive apps",
                "",
                "Application Enforced Restrictions:",
                "12. For SharePoint/Exchange: Enable app enforced restrictions",
                "13. Enforces limited web access from unmanaged devices"
            )
        }
    }
    
    return $findings
}

function Test-LocationPolicies {
    param($Policies)
    $findings = @()
    
    # Check for location-based policies
    $locationPolicy = $policies | Where-Object {
        $_.Conditions.Locations -ne $null -and (
            $_.Conditions.Locations.IncludeLocations.Count -gt 0 -or
            $_.Conditions.Locations.ExcludeLocations.Count -gt 0
        )
    }
    
    if (-not $locationPolicy) {
        $findings += [PSCustomObject]@{
            Category = "Location Controls"
            FindingId = "CA009"
            Title = "No Location-Based Conditional Access Policies"
            Severity = "Low"
            Description = "No Conditional Access policies found using location conditions (named locations)."
            Impact = "Location-based policies allow blocking or requiring additional authentication from untrusted locations or countries where your organization doesn't operate. This helps detect impossible travel and reduces risk from international threat actors."
            Recommendation = "Define named locations for your corporate networks and consider blocking access from high-risk countries or requiring additional controls for access outside trusted locations."
            AffectedItems = @("Location-based controls not configured")
            RemediationSteps = @(
                "Define Named Locations:",
                "1. Navigate to Entra ID > Security > Named locations",
                "2. Create 'Corporate Networks' location",
                "3. Add all office IP ranges",
                "4. Mark as 'Trusted location'",
                "5. Create 'High Risk Countries' location (optional)",
                "6. Select countries where organization doesn't operate",
                "",
                "Create Location-Based Policy (Option A - Trusted locations):",
                "7. Create Conditional Access policy",
                "8. Name: 'Require MFA Outside Corporate Network'",
                "9. Users: All users, exclude break-glass",
                "10. Cloud apps: All cloud apps",
                "11. Conditions > Locations: Include 'Any location', Exclude 'Corporate Networks'",
                "12. Grant: Require MFA (or compliant device)",
                "",
                "Create Blocking Policy (Option B - High risk locations):",
                "13. Create new policy: 'Block High Risk Countries'",
                "14. Users: All users, exclude authorized travelers",
                "15. Cloud apps: All cloud apps",
                "16. Conditions > Locations: Include 'High Risk Countries'",
                "17. Grant: Block access",
                "18. Enable in Report-only first to identify legitimate access",
                "",
                "Important Considerations:",
                "19. Be cautious blocking locations - may affect remote workers with VPNs",
                "20. Consider allow-listing for authorized international travel",
                "21. Test thoroughly before enforcing blocking policies",
                "22. Monitor for false positives (VPN exit points, cloud services)"
            )
        }
    }
    
    return $findings
}

function Test-PolicyStates {
    param($Policies)
    $findings = @()
    
    # Check for policies in report-only or disabled state
    $reportOnlyPolicies = $policies | Where-Object { $_.State -eq 'enabledForReportingButNotEnforced' }
    $disabledPolicies = $policies | Where-Object { $_.State -eq 'disabled' }
    
    if ($reportOnlyPolicies.Count -gt 0) {
        $findings += [PSCustomObject]@{
            Category = "Policy Governance"
            FindingId = "CA010"
            Title = "Policies in Report-Only Mode"
            Severity = "Low"
            Description = "Found $($reportOnlyPolicies.Count) Conditional Access policies in Report-only mode."
            Impact = "Policies in report-only mode don't enforce controls, they only log what would happen. While useful for testing, policies left in report-only indefinitely provide no actual protection."
            Recommendation = "Review report-only policies and either enable enforcement or remove them if no longer needed. Report-only should be a temporary testing state."
            AffectedItems = $reportOnlyPolicies.DisplayName
            RemediationSteps = @(
                "1. Review each report-only policy purpose and test results",
                "2. Check Conditional Access Insights for policy impact data",
                "3. Review sign-in logs for 'Report-only' results",
                "4. If testing complete and no issues: Enable the policy",
                "5. If issues found: Adjust policy configuration and continue testing",
                "6. If policy no longer needed: Delete the policy",
                "7. Establish policy: Report-only phase should not exceed 30 days",
                "8. Document reason if report-only state must continue longer"
            )
        }
    }
    
    if ($disabledPolicies.Count -gt 0) {
        $findings += [PSCustomObject]@{
            Category = "Policy Hygiene"
            FindingId = "CA011"
            Title = "Disabled Conditional Access Policies"
            Severity = "Low"
            Description = "Found $($disabledPolicies.Count) disabled Conditional Access policies."
            Impact = "Disabled policies create confusion and clutter. They may represent abandoned configurations or temporarily disabled protections that were never re-enabled."
            Recommendation = "Review all disabled policies and either re-enable if needed or delete if obsolete. Document why any policies must remain disabled."
            AffectedItems = $disabledPolicies.DisplayName
            RemediationSteps = @(
                "1. Review each disabled policy",
                "2. Determine why it was disabled (check modification history if available)",
                "3. If still needed: Update configuration and re-enable",
                "4. If superseded by another policy: Delete the old policy",
                "5. If temporarily disabled: Document reason and timeline for re-enablement",
                "6. Establish policy: Disabled policies should not remain > 90 days",
                "7. Schedule quarterly review of disabled policies"
            )
        }
    }
    
    return $findings
}

function Test-PolicyComplexity {
    param($Policies)
    $findings = @()
    
    # Check for overly complex policies
    $complexPolicies = $policies | Where-Object {
        ($_.Conditions.Users.IncludeUsers.Count + $_.Conditions.Users.IncludeGroups.Count -gt 10) -or
        ($_.Conditions.Applications.IncludeApplications.Count -gt 20) -or
        ($_.Conditions.Users.ExcludeUsers.Count -gt 10)
    }
    
    if ($complexPolicies.Count -gt 0) {
        $findings += [PSCustomObject]@{
            Category = "Policy Management"
            FindingId = "CA012"
            Title = "Overly Complex Conditional Access Policies"
            Severity = "Low"
            Description = "Found $($complexPolicies.Count) policies with high complexity (many inclusions/exclusions)."
            Impact = "Overly complex policies are difficult to understand, maintain, and troubleshoot. They increase risk of misconfiguration and unexpected behavior. Complexity often indicates policy sprawl and lack of strategic design."
            Recommendation = "Simplify policies by using groups instead of individual user assignments, consolidating similar policies, and using a layered security approach with clear baseline policies."
            AffectedItems = $complexPolicies.DisplayName
            RemediationSteps = @(
                "1. Review each complex policy's purpose",
                "2. For user assignments: Create groups instead of individual user inclusions",
                "3. For app assignments: Use 'All cloud apps' with exclusions rather than long inclusion lists",
                "4. Consider breaking complex policies into multiple simpler policies",
                "5. Use naming convention: '[Scope] - [Control] - [Target]'",
                "6. Example: 'AllUsers - Require MFA - AllApps' vs 'Finance - Block - HighRisk'",
                "7. Document policy intent and design decisions",
                "8. Create policy inventory spreadsheet",
                "9. Review policies quarterly for simplification opportunities",
                "10. Establish maximum of 15-20 policies as target state"
            )
        }
    }
    
    return $findings
}

function Test-ApplicationPolicies {
    param($Policies)
    $findings = @()
    
    # Check for application-specific policies for sensitive apps
    $appSpecificPolicies = $policies | Where-Object {
        $_.Conditions.Applications.IncludeApplications.Count -gt 0 -and
        $_.Conditions.Applications.IncludeApplications -notcontains 'All'
    }
    
    if ($appSpecificPolicies.Count -eq 0) {
        $findings += [PSCustomObject]@{
            Category = "Application-Specific Controls"
            FindingId = "CA013"
            Title = "No Application-Specific Policies"
            Severity = "Low"
            Description = "No Conditional Access policies found targeting specific high-value applications."
            Impact = "While broad policies protect most resources, sensitive applications (HR systems, finance apps, admin portals) benefit from additional targeted controls like session limits, device requirements, or restricted access."
            Recommendation = "Identify high-value applications and create additional policies with stricter controls for those specific apps."
            AffectedItems = @("Consider app-specific controls for sensitive apps")
            RemediationSteps = @(
                "1. Identify sensitive/high-value applications:",
                "   - HR systems (Workday, SuccessFactors)",
                "   - Financial systems (ERP, accounting)",
                "   - Admin portals (Azure portal, AWS console)",
                "   - Customer data systems (CRM, databases)",
                "2. For each sensitive app, create additional policy:",
                "   - Require compliant device",
                "   - Shorter sign-in frequency (4 hours)",
                "   - Block downloads to unmanaged devices",
                "   - Require approved client apps",
                "3. For Azure/AWS management portals:",
                "   - Require Privileged Access Workstation",
                "   - Require specific locations",
                "   - Additional MFA prompt",
                "4. Document risk-based approach to app protection",
                "5. Review app categorization quarterly"
            )
        }
    }
    
    return $findings
}

function Test-PolicyConflicts {
    param($Policies)
    $findings = @()
    
    # Look for potential policy conflicts
    $enabledPolicies = $policies | Where-Object { $_.State -eq 'enabled' }
    
    # Check for policies that might conflict (both block and allow same conditions)
    $blockPolicies = $enabledPolicies | Where-Object { $_.GrantControls.BuiltInControls -contains 'block' }
    $grantPolicies = $enabledPolicies | Where-Object { $_.GrantControls.BuiltInControls.Count -gt 0 -and $_.GrantControls.BuiltInControls -notcontains 'block' }
    
    if ($blockPolicies.Count -gt 0 -and $grantPolicies.Count -gt 0) {
        $findings += [PSCustomObject]@{
            Category = "Policy Conflicts"
            FindingId = "CA014"
            Title = "Potential Policy Conflicts Detected"
            Severity = "Medium"
            Description = "Found combination of blocking and granting policies that may conflict. Policy evaluation order is: Block > Grant, but complex conditions may cause unexpected behavior."
            Impact = "Policy conflicts can result in unexpected access denials for legitimate users or unintended access grants. Understanding policy interaction requires careful analysis of conditions, users, and applications."
            Recommendation = "Review all policies for potential conflicts. Test policy combinations thoroughly. Use Conditional Access What If tool and review sign-in logs for unexpected blocks."
            AffectedItems = @("$($blockPolicies.Count) block policies, $($grantPolicies.Count) grant policies")
            RemediationSteps = @(
                "1. Document all policies in a matrix: Users x Apps x Conditions x Controls",
                "2. Use Conditional Access What If tool:",
                "   - Navigate to Conditional Access > What If",
                "   - Test specific user + app combinations",
                "   - Review which policies apply and in what order",
                "3. Review sign-in logs for unexpected failures:",
                "   - Filter by 'Failure' status",
                "   - Look for 'Blocked by Conditional Access' errors",
                "   - Identify which policy blocked the request",
                "4. Common conflict patterns to avoid:",
                "   - Same users/apps with contradictory controls",
                "   - Overlapping device/location requirements",
                "   - Block policies without proper exclusions",
                "5. Simplify policy structure if conflicts found",
                "6. Use clear naming and documentation",
                "7. Test all policy changes in Report-only mode first",
                "8. Maintain policy design document with interaction map"
            )
        }
    }
    
    return $findings
}

Export-ModuleMember -Function Get-ConditionalAccessFindings
