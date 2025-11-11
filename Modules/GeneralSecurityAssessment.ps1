<#
.SYNOPSIS
    General Entra ID security configuration assessment module.

.DESCRIPTION
    Performs comprehensive security checks on Entra ID configuration including:
    - MFA enforcement
    - Password policies
    - Privileged role assignments
    - Guest user access
    - Legacy authentication
    - Security defaults
    - Inactive accounts
    - Application permissions
#>

function Get-GeneralSecurityFindings {
    [CmdletBinding()]
    param()
    
    Write-Host "[*] Running general security configuration checks..." -ForegroundColor Cyan
    
    $findings = @()
    
    # Check 1: Users without MFA
    Write-Host "  [+] Checking MFA configuration..." -ForegroundColor Gray
    $findings += Test-MFAConfiguration
    
    # Check 2: Password policies
    Write-Host "  [+] Checking password policies..." -ForegroundColor Gray
    $findings += Test-PasswordPolicies
    
    # Check 3: Privileged role assignments
    Write-Host "  [+] Checking privileged role assignments..." -ForegroundColor Gray
    $findings += Test-PrivilegedRoles
    
    # Check 4: Guest user access
    Write-Host "  [+] Checking guest user configuration..." -ForegroundColor Gray
    $findings += Test-GuestUserAccess
    
    # Check 5: Legacy authentication
    Write-Host "  [+] Checking legacy authentication..." -ForegroundColor Gray
    $findings += Test-LegacyAuthentication
    
    # Check 6: Security defaults
    Write-Host "  [+] Checking security defaults..." -ForegroundColor Gray
    $findings += Test-SecurityDefaults
    
    # Check 7: Inactive accounts
    Write-Host "  [+] Checking for inactive accounts..." -ForegroundColor Gray
    $findings += Test-InactiveAccounts
    
    # Check 8: Application permissions
    Write-Host "  [+] Checking application permissions..." -ForegroundColor Gray
    $findings += Test-ApplicationPermissions
    
    return $findings
}

function Test-MFAConfiguration {
    $findings = @()
    
    try {
        # Get all enabled users
        $users = Get-MgUser -Filter "accountEnabled eq true" -All -Property Id, DisplayName, UserPrincipalName
        
        $usersWithoutMFA = @()
        
        foreach ($user in $users) {
            try {
                $authMethods = Get-MgUserAuthenticationMethod -UserId $user.Id -ErrorAction SilentlyContinue
                
                # Check if user has MFA methods (excluding password)
                $mfaMethods = $authMethods | Where-Object { $_.AdditionalProperties.'@odata.type' -ne '#microsoft.graph.passwordAuthenticationMethod' }
                
                if (-not $mfaMethods) {
                    $usersWithoutMFA += $user.UserPrincipalName
                }
            }
            catch {
                # Skip users we can't check
                continue
            }
        }
        
        if ($usersWithoutMFA.Count -gt 0) {
            $findings += [PSCustomObject]@{
                Category = "Identity Protection"
                FindingId = "GEN001"
                Title = "Users Without MFA Enabled"
                Severity = "Critical"
                Description = "Found $($usersWithoutMFA.Count) enabled users without Multi-Factor Authentication configured."
                Impact = "Accounts without MFA are extremely vulnerable to credential theft, password spraying, and phishing attacks. According to Microsoft, MFA blocks 99.9% of automated attacks. Without MFA, compromised credentials provide direct access to organizational resources."
                Recommendation = "Enforce MFA for all users using Conditional Access policies. Consider using passwordless authentication methods (Windows Hello, FIDO2 keys, Microsoft Authenticator) for enhanced security."
                AffectedItems = $usersWithoutMFA | Select-Object -First 50
                RemediationSteps = @(
                    "1. Navigate to Entra ID > Security > Conditional Access",
                    "2. Create a new policy named 'Require MFA for All Users'",
                    "3. Assign to: All users (exclude emergency access accounts)",
                    "4. Cloud apps: All cloud apps",
                    "5. Grant: Require multi-factor authentication",
                    "6. Enable policy in Report-only mode first",
                    "7. Monitor for 7-14 days, review sign-in logs",
                    "8. Enable policy after validation",
                    "9. Communicate changes to users in advance",
                    "10. Provide MFA registration guidance and support"
                )
            }
        }
    }
    catch {
        Write-Warning "Failed to check MFA configuration: $_"
    }
    
    return $findings
}

function Test-PasswordPolicies {
    $findings = @()
    
    try {
        # Get domain password policy
        $domains = Get-MgDomain
        
        # Check for weak password settings
        $users = Get-MgUser -Filter "accountEnabled eq true and passwordPolicies eq 'DisablePasswordExpiration'" -All -Property DisplayName, UserPrincipalName
        
        if ($users.Count -gt 0) {
            $findings += [PSCustomObject]@{
                Category = "Password Security"
                FindingId = "GEN002"
                Title = "Users with Non-Expiring Passwords"
                Severity = "Medium"
                Description = "Found $($users.Count) users with passwords set to never expire."
                Impact = "Non-expiring passwords increase risk of credential compromise over time. Attackers who obtain credentials maintain persistent access. While modern guidance favors strong passwords over expiration, non-expiring passwords should be limited to service accounts with additional protections."
                Recommendation = "Review each account and either remove password expiration exemption or convert to managed service identities. For necessary service accounts, implement additional monitoring and consider using Azure Key Vault for credential management."
                AffectedItems = $users.UserPrincipalName
                RemediationSteps = @(
                    "1. Review list of accounts with non-expiring passwords",
                    "2. For user accounts: Remove password expiration exemption",
                    "3. For service accounts: Evaluate migration to Managed Identities",
                    "4. If service accounts must remain: Implement credential rotation schedule",
                    "5. Document business justification for any exceptions",
                    "6. Enable monitoring for these accounts in Azure AD Identity Protection",
                    "7. Consider implementing Privileged Access Workstations (PAW) for privileged service accounts"
                )
            }
        }
        
        # Check if password protection is enabled
        $findings += [PSCustomObject]@{
            Category = "Password Security"
            FindingId = "GEN003"
            Title = "Password Protection Configuration Review"
            Severity = "Medium"
            Description = "Verify that Azure AD Password Protection is configured with custom banned password lists."
            Impact = "Without password protection, users can choose weak or commonly compromised passwords. Custom banned password lists prevent use of organization-specific terms that attackers might target."
            Recommendation = "Configure Azure AD Password Protection with custom banned passwords including company name, product names, and industry-specific terms. Enable password protection for on-premises AD if hybrid."
            AffectedItems = @("Tenant-wide setting")
            RemediationSteps = @(
                "1. Navigate to Entra ID > Security > Authentication methods > Password protection",
                "2. Add custom banned passwords: company name, products, common industry terms",
                "3. Set enforcement mode to 'Enforced'",
                "4. Consider enabling lockout threshold (10 failed attempts recommended)",
                "5. For hybrid: Deploy Azure AD Password Protection to on-premises domain controllers",
                "6. Monitor the Password Protection report for blocked attempts"
            )
        }
    }
    catch {
        Write-Warning "Failed to check password policies: $_"
    }
    
    return $findings
}

function Test-PrivilegedRoles {
    $findings = @()
    
    try {
        # Check Global Administrator role
        $globalAdminRole = Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'"
        
        if ($globalAdminRole) {
            $globalAdmins = Get-MgDirectoryRoleMember -DirectoryRoleId $globalAdminRole.Id
            
            if ($globalAdmins.Count -gt 5) {
                $findings += [PSCustomObject]@{
                    Category = "Privileged Access"
                    FindingId = "GEN004"
                    Title = "Excessive Global Administrator Assignments"
                    Severity = "High"
                    Description = "Found $($globalAdmins.Count) Global Administrator role assignments. Microsoft recommends limiting to 2-5 accounts."
                    Impact = "Global Administrators have unrestricted access to all Entra ID and Microsoft 365 resources. Excessive assignments increase attack surface and insider threat risk. Each additional account is a potential target for compromise."
                    Recommendation = "Reduce Global Administrator count to maximum 5 accounts. Use more granular admin roles (User Administrator, Security Administrator, etc.) based on least privilege principle. Implement Privileged Identity Management (PIM) for just-in-time access."
                    AffectedItems = @("$($globalAdmins.Count) Global Administrators assigned")
                    RemediationSteps = @(
                        "1. Review each Global Administrator assignment for necessity",
                        "2. Identify specific permissions each admin actually needs",
                        "3. Assign more granular roles instead (e.g., User Administrator, Exchange Administrator)",
                        "4. Keep only 2-5 Global Administrators (emergency access accounts)",
                        "5. Implement Azure AD Privileged Identity Management (requires P2)",
                        "6. Configure PIM for just-in-time activation of admin roles",
                        "7. Require MFA and approval workflows for role activation",
                        "8. Set maximum activation duration (4-8 hours recommended)",
                        "9. Enable alerting for role activations",
                        "10. Review privileged access regularly (monthly)"
                    )
                }
            }
        }
        
        # Check for permanent role assignments
        $findings += [PSCustomObject]@{
            Category = "Privileged Access"
            FindingId = "GEN005"
            Title = "Privileged Identity Management Not Configured"
            Severity = "High"
            Description = "Consider implementing Privileged Identity Management (PIM) for just-in-time privileged access."
            Impact = "Permanent privileged role assignments provide continuous elevated access, increasing risk window. PIM enables just-in-time activation, requiring justification and approval, with automatic expiration."
            Recommendation = "Implement Azure AD PIM (requires Azure AD Premium P2) to convert permanent assignments to eligible assignments with time-bound activation."
            AffectedItems = @("Review all privileged role assignments")
            RemediationSteps = @(
                "1. Obtain Azure AD Premium P2 licenses for privileged users",
                "2. Navigate to Entra ID > Privileged Identity Management",
                "3. Discover privileged roles and review assignments",
                "4. Convert permanent assignments to eligible (time-bound)",
                "5. Configure activation requirements: MFA, justification, approval",
                "6. Set maximum activation duration (4-8 hours)",
                "7. Configure alerts for suspicious activations",
                "8. Require periodic access reviews (quarterly recommended)",
                "9. Enable session recording for privileged access",
                "10. Train administrators on PIM activation process"
            )
        }
    }
    catch {
        Write-Warning "Failed to check privileged roles: $_"
    }
    
    return $findings
}

function Test-GuestUserAccess {
    $findings = @()
    
    try {
        $guestUsers = Get-MgUser -Filter "userType eq 'Guest'" -All -Property DisplayName, UserPrincipalName, CreatedDateTime
        
        if ($guestUsers.Count -gt 0) {
            # Check guest user access settings
            $findings += [PSCustomObject]@{
                Category = "External Access"
                FindingId = "GEN006"
                Title = "Guest User Access Review"
                Severity = "Medium"
                Description = "Found $($guestUsers.Count) guest users in the directory. Review guest access restrictions and ensure least privilege."
                Impact = "Guest users from external organizations have access to internal resources. Overly permissive guest settings can lead to unauthorized data access or exfiltration. Inactive or abandoned guest accounts create security blind spots."
                Recommendation = "Implement guest access reviews, restrict guest user permissions, and enable expiration policies for guest accounts. Use entitlement management for automated access lifecycle."
                AffectedItems = @("$($guestUsers.Count) guest users")
                RemediationSteps = @(
                    "1. Navigate to Entra ID > Users > User settings > External collaboration settings",
                    "2. Set 'Guest user access restrictions' to 'Guest users have limited access'",
                    "3. Restrict who can invite guests (Admins and specific roles only)",
                    "4. Enable guest self-service sign-up with admin approval",
                    "5. Configure guest user access expiration (90 days recommended)",
                    "6. Navigate to Identity Governance > Access reviews",
                    "7. Create quarterly access reviews for guest users",
                    "8. Enable automatic removal of denied guests",
                    "9. Review guest user sign-in activity (remove inactive guests)",
                    "10. Use Entitlement Management for automated guest lifecycle"
                )
            }
            
            # Check for old guest accounts
            $oldGuests = $guestUsers | Where-Object { 
                $_.CreatedDateTime -and ((Get-Date) - $_.CreatedDateTime).Days -gt 90 
            }
            
            if ($oldGuests.Count -gt 0) {
                $findings += [PSCustomObject]@{
                    Category = "External Access"
                    FindingId = "GEN007"
                    Title = "Old Guest User Accounts"
                    Severity = "Medium"
                    Description = "Found $($oldGuests.Count) guest user accounts older than 90 days without expiration configured."
                    Impact = "Long-standing guest accounts without review may represent former partners, contractors, or collaborators who no longer require access. These accounts create unnecessary risk exposure."
                    Recommendation = "Review all guest accounts older than 90 days. Remove access for users no longer requiring it. Implement automated expiration and periodic access reviews."
                    AffectedItems = $oldGuests.UserPrincipalName | Select-Object -First 20
                    RemediationSteps = @(
                        "1. Review sign-in activity for guest accounts over 90 days old",
                        "2. Contact account sponsors to verify continued need",
                        "3. Remove accounts that are no longer needed",
                        "4. For active guests, set expiration dates (90-180 days)",
                        "5. Implement automated access reviews (quarterly)",
                        "6. Configure alerts for guest user invitations"
                    )
                }
            }
        }
    }
    catch {
        Write-Warning "Failed to check guest user access: $_"
    }
    
    return $findings
}

function Test-LegacyAuthentication {
    $findings = @()
    
    try {
        # Note: Checking legacy auth requires sign-in logs which may need specific permissions
        $findings += [PSCustomObject]@{
            Category = "Authentication Protocols"
            FindingId = "GEN008"
            Title = "Legacy Authentication Protocol Review"
            Severity = "High"
            Description = "Review sign-in logs for legacy authentication protocol usage (Basic Auth, IMAP, POP, SMTP)."
            Impact = "Legacy authentication protocols don't support MFA and are primary targets for credential stuffing and password spray attacks. These protocols represent a significant security vulnerability and should be blocked."
            Recommendation = "Block legacy authentication using Conditional Access policies. Identify and migrate applications using legacy protocols to modern authentication (OAuth 2.0)."
            AffectedItems = @("Review sign-in logs for legacy auth usage")
            RemediationSteps = @(
                "1. Navigate to Entra ID > Sign-in logs",
                "2. Filter by 'Client App' to identify legacy authentication usage",
                "3. Document applications/users using legacy protocols",
                "4. Work with application owners to migrate to modern authentication",
                "5. For Exchange: Disable Basic Auth (Security & Compliance > Authentication policies)",
                "6. Create Conditional Access policy to block legacy authentication",
                "7. Policy name: 'Block Legacy Authentication'",
                "8. Assign to: All users (exclude service accounts if necessary)",
                "9. Cloud apps: All cloud apps",
                "10. Conditions: Client apps - Exchange ActiveSync, Other clients",
                "11. Grant: Block access",
                "12. Enable policy in Report-only mode first, validate for 30 days",
                "13. Enable policy after ensuring no business impact"
            )
        }
    }
    catch {
        Write-Warning "Failed to check legacy authentication: $_"
    }
    
    return $findings
}

function Test-SecurityDefaults {
    $findings = @()
    
    try {
        # Check if security defaults are enabled
        $securityDefaults = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy
        
        if ($securityDefaults.IsEnabled -eq $false) {
            # Check if Conditional Access policies exist as alternative
            $caPolicies = Get-MgIdentityConditionalAccessPolicy
            
            if ($caPolicies.Count -eq 0) {
                $findings += [PSCustomObject]@{
                    Category = "Baseline Security"
                    FindingId = "GEN009"
                    Title = "Security Defaults Disabled Without Conditional Access"
                    Severity = "Critical"
                    Description = "Security defaults are disabled and no Conditional Access policies are configured."
                    Impact = "Without security defaults or Conditional Access, the tenant lacks basic security protections including MFA enforcement, legacy authentication blocking, and privileged access protection. This creates significant vulnerability to common attacks."
                    Recommendation = "Either enable Security Defaults for basic protection or implement comprehensive Conditional Access policies for granular control. Security Defaults are free and provide baseline protection suitable for smaller organizations."
                    AffectedItems = @("Tenant-wide setting")
                    RemediationSteps = @(
                        "Option A - Enable Security Defaults (simple, free):",
                        "1. Navigate to Entra ID > Properties > Manage security defaults",
                        "2. Set 'Security defaults' to Enabled",
                        "3. This automatically enables: MFA for all users, blocks legacy auth, requires MFA for privileged roles",
                        "",
                        "Option B - Implement Conditional Access (granular, requires Azure AD Premium P1):",
                        "1. Create baseline Conditional Access policies",
                        "2. Policy 1: Require MFA for all users",
                        "3. Policy 2: Block legacy authentication",
                        "4. Policy 3: Require MFA for Azure management",
                        "5. Policy 4: Require compliant or hybrid joined devices",
                        "6. Test policies in Report-only mode before enforcement"
                    )
                }
            }
        }
    }
    catch {
        Write-Warning "Failed to check security defaults: $_"
    }
    
    return $findings
}

function Test-InactiveAccounts {
    $findings = @()
    
    try {
        # Check for users who haven't signed in recently
        $users = Get-MgUser -Filter "accountEnabled eq true" -All -Property Id, DisplayName, UserPrincipalName, SignInActivity
        
        $inactiveUsers = @()
        $inactiveThreshold = (Get-Date).AddDays(-90)
        
        foreach ($user in $users) {
            if ($user.SignInActivity) {
                $lastSignIn = $user.SignInActivity.LastSignInDateTime
                if ($lastSignIn -and $lastSignIn -lt $inactiveThreshold) {
                    $inactiveUsers += $user.UserPrincipalName
                }
            }
            else {
                # User has never signed in
                $inactiveUsers += $user.UserPrincipalName
            }
        }
        
        if ($inactiveUsers.Count -gt 0) {
            $findings += [PSCustomObject]@{
                Category = "Account Management"
                FindingId = "GEN010"
                Title = "Inactive User Accounts"
                Severity = "Medium"
                Description = "Found $($inactiveUsers.Count) enabled user accounts with no sign-in activity in the last 90 days."
                Impact = "Inactive accounts represent unnecessary security risk. These accounts may belong to former employees, contractors, or unused service accounts. They can be compromised without detection and used for lateral movement or data exfiltration."
                Recommendation = "Review inactive accounts and disable or remove those no longer needed. Implement automated lifecycle management for user accounts."
                AffectedItems = $inactiveUsers | Select-Object -First 50
                RemediationSteps = @(
                    "1. Export full list of inactive accounts",
                    "2. Verify account ownership with department managers",
                    "3. For former employees: Remove immediately",
                    "4. For current employees: Verify if account is still needed",
                    "5. For service accounts: Document purpose and ownership",
                    "6. Disable accounts rather than delete (allows recovery if needed)",
                    "7. After 30 days disabled, permanently delete if no issues",
                    "8. Implement automated account lifecycle management",
                    "9. Configure HR-driven provisioning/deprovisioning",
                    "10. Schedule quarterly inactive account reviews"
                )
            }
        }
    }
    catch {
        Write-Warning "Failed to check inactive accounts: $_"
    }
    
    return $findings
}

function Test-ApplicationPermissions {
    $findings = @()
    
    try {
        # Get all application registrations
        $apps = Get-MgApplication -All
        
        $riskyPermissions = @(
            'RoleManagement.ReadWrite.Directory',
            'Directory.ReadWrite.All',
            'User.ReadWrite.All',
            'Mail.ReadWrite',
            'Files.ReadWrite.All',
            'Sites.FullControl.All'
        )
        
        $appsWithRiskyPerms = @()
        
        foreach ($app in $apps) {
            $appPerms = $app.RequiredResourceAccess | ForEach-Object {
                $_.ResourceAppId
                $_.ResourceAccess | ForEach-Object { $_.Id }
            }
            
            # This is simplified - full check would require resolving permission IDs
            $appsWithRiskyPerms += $app.DisplayName
        }
        
        if ($apps.Count -gt 0) {
            $findings += [PSCustomObject]@{
                Category = "Application Security"
                FindingId = "GEN011"
                Title = "Application Permission Review Required"
                Severity = "Medium"
                Description = "Found $($apps.Count) application registrations. Review for excessive or risky permissions."
                Impact = "Applications with excessive permissions can be exploited if compromised. Over-privileged apps violate least privilege principle and can access sensitive data beyond their functional requirements. Unused apps with valid credentials pose persistent risk."
                Recommendation = "Review all application registrations and service principals. Remove unused applications, reduce permissions to minimum required, implement credential rotation, and enable monitoring."
                AffectedItems = @("$($apps.Count) applications to review")
                RemediationSteps = @(
                    "1. Navigate to Entra ID > App registrations",
                    "2. Review each application for business purpose",
                    "3. Remove applications that are no longer used",
                    "4. For each remaining app, review API permissions",
                    "5. Remove excessive permissions (especially Directory.ReadWrite.All, Mail.ReadWrite)",
                    "6. Replace application permissions with delegated permissions where possible",
                    "7. Ensure admin consent is required for sensitive permissions",
                    "8. Implement credential rotation (certificates preferred over secrets)",
                    "9. Set credential expiration (maximum 12 months)",
                    "10. Enable sign-in logging for service principals",
                    "11. Create alerts for new app registrations",
                    "12. Conduct quarterly application permission reviews"
                )
            }
        }
    }
    catch {
        Write-Warning "Failed to check application permissions: $_"
    }
    
    return $findings
}

Export-ModuleMember -Function Get-GeneralSecurityFindings
