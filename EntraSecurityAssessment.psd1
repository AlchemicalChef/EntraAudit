@{
    # Script module or binary module file associated with this manifest
    RootModule = 'EntraSecurityAssessment.psm1'
    
    # Version number of this module
    ModuleVersion = '1.0.0'
    
    # Supported PSEditions
    CompatiblePSEditions = @('Desktop', 'Core')
    
    # ID used to uniquely identify this module
    GUID = '8a4d7f3e-2b9c-4e1a-9f5d-6c8a7b3e2d1f'
    
    # Author of this module
    Author = 'AlchemicalChef'
    
    # Company or vendor of this module
    CompanyName = 'AlchemicalChef'
    
    # Copyright statement for this module
    Copyright = '(c) 2025. All rights reserved.'
    
    # Description of the functionality provided by this module
    Description = 'Comprehensive security assessment tool for Microsoft Entra ID (Azure AD). Evaluates identity security configurations, Conditional Access policies, privileged access management, and compliance against Microsoft security best practices. Generates detailed HTML and JSON reports with actionable remediation guidance.'
    
    # Minimum version of the PowerShell engine required by this module
    PowerShellVersion = '5.1'
    
    # Modules that must be imported into the global environment prior to importing this module
    RequiredModules = @(
        @{ModuleName='Microsoft.Graph.Authentication'; ModuleVersion='2.0.0'},
        @{ModuleName='Microsoft.Graph.Identity.SignIns'; ModuleVersion='2.0.0'},
        @{ModuleName='Microsoft.Graph.Users'; ModuleVersion='2.0.0'},
        @{ModuleName='Microsoft.Graph.Identity.DirectoryManagement'; ModuleVersion='2.0.0'},
        @{ModuleName='Microsoft.Graph.Applications'; ModuleVersion='2.0.0'}
    )
    
    # Assemblies that must be loaded prior to importing this module
    RequiredAssemblies = @()
    
    # Script files (.ps1) that are run in the caller's environment prior to importing this module
    ScriptsToProcess = @()
    
    # Type files (.ps1xml) to be loaded when importing this module
    TypesToProcess = @()
    
    # Format files (.ps1xml) to be loaded when importing this module
    FormatsToProcess = @()
    
    # Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
    NestedModules = @()
    
    # Functions to export from this module
    FunctionsToExport = @(
        'Invoke-EntraSecurityAssessment',
        'Get-GeneralSecurityFindings',
        'Get-ConditionalAccessFindings',
        'New-AssessmentReport'
    )
    
    # Cmdlets to export from this module
    CmdletsToExport = @()
    
    # Variables to export from this module
    VariablesToExport = @()
    
    # Aliases to export from this module
    AliasesToExport = @()
    
    # DSC resources to export from this module
    DscResourcesToExport = @()
    
    # List of all modules packaged with this module
    ModuleList = @()
    
    # List of all files packaged with this module
    FileList = @(
        'EntraSecurityAssessment.psm1',
        'EntraSecurityAssessment.psd1',
        'Modules\GeneralSecurityAssessment.ps1',
        'Modules\ConditionalAccessAssessment.ps1',
        'Modules\ReportGenerator.ps1'
    )
    
    # Private data to pass to the module specified in RootModule/ModuleToProcess
    PrivateData = @{
        PSData = @{
            # Tags applied to this module for online galleries
            Tags = @('Entra', 'AzureAD', 'Security', 'Assessment', 'ConditionalAccess', 'Compliance', 'Identity', 'MFA', 'Audit')
            
            # A URL to the license for this module
            LicenseUri = ''
            
            # A URL to the main website for this project
            ProjectUri = ''
            
            # A URL to an icon representing this module
            IconUri = ''
            
            # ReleaseNotes of this module
            ReleaseNotes = @'
Version 1.0.0 - Initial Release
- Comprehensive Entra ID security configuration assessment
- Conditional Access policy analysis with 12 check categories
- General security checks covering 8 major areas
- Professional HTML report generation with interactive UI
- JSON export for automation and integration
- Detailed remediation guidance with step-by-step instructions
- Read-only, non-invasive assessment approach
- Support for Azure AD Premium features
'@
            
            # Prerelease string of this module
            Prerelease = ''
            
            # Flag to indicate whether the module requires explicit user acceptance
            RequireLicenseAcceptance = $false
            
            # External dependent modules of this module
            ExternalModuleDependencies = @('Microsoft.Graph.Authentication', 'Microsoft.Graph.Identity.SignIns', 'Microsoft.Graph.Users', 'Microsoft.Graph.Identity.DirectoryManagement', 'Microsoft.Graph.Applications')
        }
    }
    
    # HelpInfo URI of this module
    HelpInfoURI = ''
    
    # Default prefix for commands exported from this module
    DefaultCommandPrefix = ''
}
