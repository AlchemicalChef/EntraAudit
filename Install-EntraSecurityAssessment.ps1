<#
.SYNOPSIS
    Installation script for Entra Security Assessment module.

.DESCRIPTION
    Installs the Entra Security Assessment PowerShell module including all
    dependencies, creates module structure, and verifies installation.

.PARAMETER Scope
    Installation scope: CurrentUser or AllUsers (requires admin for AllUsers)

.PARAMETER SkipDependencies
    Skip installing Microsoft Graph module dependencies

.PARAMETER Force
    Force reinstallation if module already exists

.PARAMETER InstallPath
    Custom installation path (overrides Scope parameter)

.EXAMPLE
    .\Install-EntraSecurityAssessment.ps1

.EXAMPLE
    .\Install-EntraSecurityAssessment.ps1 -Scope AllUsers

.EXAMPLE
    .\Install-EntraSecurityAssessment.ps1 -Force -SkipDependencies
#>

[CmdletBinding()]
param(
    [ValidateSet('CurrentUser', 'AllUsers')]
    [string]$Scope = 'CurrentUser',
    
    [switch]$SkipDependencies,
    
    [switch]$Force,
    
    [string]$InstallPath
)

$ErrorActionPreference = 'Stop'

# Color output functions
function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Type = 'Info'
    )
    
    switch ($Type) {
        'Success' { Write-Host "[+] $Message" -ForegroundColor Green }
        'Error' { Write-Host "[!] $Message" -ForegroundColor Red }
        'Warning' { Write-Host "[!] $Message" -ForegroundColor Yellow }
        'Info' { Write-Host "[*] $Message" -ForegroundColor Cyan }
        default { Write-Host $Message }
    }
}

# Banner
Write-Host "`n===========================================" -ForegroundColor Cyan
Write-Host "  Entra Security Assessment Module" -ForegroundColor Cyan
Write-Host "  Installation Script" -ForegroundColor Cyan
Write-Host "===========================================" -ForegroundColor Cyan
Write-Host ""

# Check PowerShell version
Write-ColorOutput "Checking PowerShell version..." "Info"
$psVersion = $PSVersionTable.PSVersion
if ($psVersion.Major -lt 5) {
    Write-ColorOutput "PowerShell 5.1 or higher is required. Current version: $psVersion" "Error"
    exit 1
}
Write-ColorOutput "PowerShell version: $psVersion" "Success"

# Check for admin rights if AllUsers scope
if ($Scope -eq 'AllUsers') {
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-ColorOutput "AllUsers scope requires administrator privileges. Please run PowerShell as Administrator or use -Scope CurrentUser" "Error"
        exit 1
    }
}

# Determine installation path
if ($InstallPath) {
    $modulePath = $InstallPath
}
else {
    if ($Scope -eq 'CurrentUser') {
        if ($PSVersionTable.PSVersion.Major -ge 6) {
            $modulePath = Join-Path $HOME "Documents\PowerShell\Modules"
        }
        else {
            $modulePath = Join-Path $HOME "Documents\WindowsPowerShell\Modules"
        }
    }
    else {
        if ($PSVersionTable.PSVersion.Major -ge 6) {
            $modulePath = "C:\Program Files\PowerShell\Modules"
        }
        else {
            $modulePath = "C:\Program Files\WindowsPowerShell\Modules"
        }
    }
}

$moduleInstallPath = Join-Path $modulePath "EntraSecurityAssessment"

Write-ColorOutput "Installation path: $moduleInstallPath" "Info"

# Check if module already exists
if (Test-Path $moduleInstallPath) {
    if ($Force) {
        Write-ColorOutput "Module already exists. Removing existing installation..." "Warning"
        Remove-Item $moduleInstallPath -Recurse -Force
    }
    else {
        Write-ColorOutput "Module already exists at $moduleInstallPath. Use -Force to reinstall." "Warning"
        $continue = Read-Host "Do you want to continue and overwrite? (Y/N)"
        if ($continue -ne 'Y') {
            Write-ColorOutput "Installation cancelled." "Info"
            exit 0
        }
        Remove-Item $moduleInstallPath -Recurse -Force
    }
}

# Install dependencies
if (-not $SkipDependencies) {
    Write-ColorOutput "Checking Microsoft Graph PowerShell SDK..." "Info"
    
    $requiredModules = @(
        'Microsoft.Graph.Authentication',
        'Microsoft.Graph.Identity.SignIns',
        'Microsoft.Graph.Users',
        'Microsoft.Graph.Identity.DirectoryManagement',
        'Microsoft.Graph.Applications'
    )
    
    foreach ($module in $requiredModules) {
        $installed = Get-Module -ListAvailable -Name $module
        if (-not $installed) {
            Write-ColorOutput "Installing $module..." "Info"
            try {
                Install-Module -Name $module -Scope $Scope -Force -AllowClobber
                Write-ColorOutput "$module installed successfully" "Success"
            }
            catch {
                Write-ColorOutput "Failed to install $module : $_" "Error"
                Write-ColorOutput "You can install it manually: Install-Module $module -Scope $Scope" "Warning"
            }
        }
        else {
            Write-ColorOutput "$module already installed" "Success"
        }
    }
}
else {
    Write-ColorOutput "Skipping dependency installation" "Warning"
}

# Create module directory structure
Write-ColorOutput "Creating module directory structure..." "Info"
New-Item -ItemType Directory -Path $moduleInstallPath -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $moduleInstallPath "Modules") -Force | Out-Null

Write-ColorOutput "Copying module files..." "Info"

# Get the script directory (where Install script is located)
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Copy module manifest
$psd1Source = Join-Path $scriptDir "EntraSecurityAssessment.psd1"
if (Test-Path $psd1Source) {
    Copy-Item $psd1Source -Destination $moduleInstallPath -Force
    Write-ColorOutput "Copied EntraSecurityAssessment.psd1" "Success"
}
else {
    Write-ColorOutput "EntraSecurityAssessment.psd1 not found in script directory" "Error"
    exit 1
}

# Copy root module
$psm1Source = Join-Path $scriptDir "EntraSecurityAssessment.psm1"
if (Test-Path $psm1Source) {
    Copy-Item $psm1Source -Destination $moduleInstallPath -Force
    Write-ColorOutput "Copied EntraSecurityAssessment.psm1" "Success"
}
else {
    Write-ColorOutput "EntraSecurityAssessment.psm1 not found in script directory" "Error"
    exit 1
}

# Copy module files
$moduleFiles = @(
    "Modules\GeneralSecurityAssessment.ps1",
    "Modules\ConditionalAccessAssessment.ps1",
    "Modules\ReportGenerator.ps1"
)

foreach ($file in $moduleFiles) {
    $sourceFile = Join-Path $scriptDir $file
    $destFile = Join-Path $moduleInstallPath $file
    
    if (Test-Path $sourceFile) {
        Copy-Item $sourceFile -Destination $destFile -Force
        Write-ColorOutput "Copied $file" "Success"
    }
    else {
        Write-ColorOutput "$file not found in script directory" "Error"
        exit 1
    }
}

# Verify installation
Write-ColorOutput "`nVerifying installation..." "Info"
$installedModule = Get-Module -ListAvailable -Name EntraSecurityAssessment

if ($installedModule) {
    Write-ColorOutput "Module installed successfully!" "Success"
    Write-Host ""
    Write-Host "Module Details:" -ForegroundColor Cyan
    Write-Host "  Name: $($installedModule.Name)"
    Write-Host "  Version: $($installedModule.Version)"
    Write-Host "  Path: $($installedModule.ModuleBase)"
    Write-Host ""
}
else {
    Write-ColorOutput "Module installation verification failed" "Error"
    exit 1
}

# Display next steps
Write-Host "===========================================" -ForegroundColor Green
Write-Host "  Installation Complete!" -ForegroundColor Green
Write-Host "===========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Next Steps:" -ForegroundColor Cyan
Write-Host ""
Write-Host "1. Import the module:" -ForegroundColor Yellow
Write-Host "   Import-Module EntraSecurityAssessment" -ForegroundColor White
Write-Host ""
Write-Host "2. Connect to Microsoft Graph:" -ForegroundColor Yellow
Write-Host "   Connect-MgGraph -Scopes 'Policy.Read.All','Directory.Read.All','UserAuthenticationMethod.Read.All','Organization.Read.All','RoleManagement.Read.All','Application.Read.All'" -ForegroundColor White
Write-Host ""
Write-Host "3. Run the assessment:" -ForegroundColor Yellow
Write-Host "   Invoke-EntraSecurityAssessment" -ForegroundColor White
Write-Host ""
Write-Host "4. View help:" -ForegroundColor Yellow
Write-Host "   Get-Help Invoke-EntraSecurityAssessment -Full" -ForegroundColor White
Write-Host ""
Write-Host "For more information, see README.md" -ForegroundColor Cyan
Write-Host ""
