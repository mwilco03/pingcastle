# AD-Scout Bootstrap Prompt

> Use this prompt to initialize the AD-Scout repository and begin scaffolding the project.

---

## Prompt for Claude / AI Assistant

```
# Project: AD-Scout - PowerShell-Native Active Directory Security Assessment Framework

## Context

You are helping bootstrap a new open-source project called AD-Scout. This is a PowerShell-native Active Directory security assessment framework inspired by tools like PingCastle, BloodHound, and ADRecon, but designed from the ground up with different goals:

- **PowerShell-first**: Native module experience with tab-completion, pipeline support, Show-Command integration
- **Community-extensible**: Drop-in rule files, no compilation required
- **Cross-version compatible**: Works on PowerShell 2.0, 5.1, and 7.x
- **Output-flexible**: Pluggable reporters (HTML, JSON, Elastic, webhooks, etc.)

This is NOT a fork or port of PingCastle. It is an independent project with its own architecture, licensed under MIT.

## Repository Setup

Create the following repository structure for `github.com/[owner]/ad-scout`:

```
ad-scout/
├── .github/
│   ├── workflows/
│   │   ├── ci.yml                    # Test on PR (Pester, PSScriptAnalyzer)
│   │   ├── release.yml               # Publish to PSGallery on tag
│   │   └── docs.yml                  # Auto-generate documentation
│   ├── ISSUE_TEMPLATE/
│   │   ├── bug_report.md
│   │   ├── feature_request.md
│   │   └── new_rule.md
│   └── PULL_REQUEST_TEMPLATE.md
├── .vscode/
│   ├── settings.json                 # PSScriptAnalyzer, formatting
│   ├── tasks.json                    # Build tasks
│   ├── launch.json                   # Debug configurations
│   └── extensions.json               # Recommended extensions
├── build/
│   ├── Build-Module.ps1              # Build/package script
│   ├── Update-Documentation.ps1     # Generate docs from source
│   └── Publish-Module.ps1            # Publish to PSGallery
├── docs/                             # AUTO-GENERATED - Do not edit manually
│   └── .gitkeep
├── src/
│   └── ADScout/
│       ├── ADScout.psd1              # Module manifest
│       ├── ADScout.psm1              # Module loader
│       ├── Public/                   # Exported functions
│       │   ├── Invoke-ADScoutScan.ps1
│       │   ├── Get-ADScoutRule.ps1
│       │   ├── New-ADScoutRule.ps1
│       │   ├── Register-ADScoutRule.ps1
│       │   ├── Export-ADScoutReport.ps1
│       │   ├── Get-ADScoutRemediation.ps1
│       │   ├── Set-ADScoutConfig.ps1
│       │   ├── Get-ADScoutConfig.ps1
│       │   └── Show-ADScoutDashboard.ps1
│       ├── Private/                  # Internal functions
│       │   ├── Collectors/
│       │   │   ├── Get-ADScoutUserData.ps1
│       │   │   ├── Get-ADScoutComputerData.ps1
│       │   │   ├── Get-ADScoutGroupData.ps1
│       │   │   ├── Get-ADScoutTrustData.ps1
│       │   │   ├── Get-ADScoutGPOData.ps1
│       │   │   └── Get-ADScoutCertificateData.ps1
│       │   ├── Scanners/
│       │   │   └── .gitkeep
│       │   ├── Compatibility/
│       │   │   ├── Test-PSVersion.ps1
│       │   │   ├── Get-CimOrWmi.ps1
│       │   │   └── Invoke-ADScoutParallel.ps1
│       │   └── Helpers/
│       │       ├── Convert-SidToName.ps1
│       │       ├── Get-ADScoutCache.ps1
│       │       ├── Write-ADScoutLog.ps1
│       │       └── Get-ADScoutRulePaths.ps1
│       ├── Rules/                    # Built-in rules
│       │   ├── _RuleTemplate.ps1     # Template for new rules
│       │   ├── Anomalies/
│       │   │   └── .gitkeep
│       │   ├── StaleObjects/
│       │   │   └── .gitkeep
│       │   ├── PrivilegedAccounts/
│       │   │   └── .gitkeep
│       │   └── Trusts/
│       │       └── .gitkeep
│       ├── Reporters/                # Output plugins
│       │   ├── HTMLReporter.ps1
│       │   ├── JSONReporter.ps1
│       │   ├── CSVReporter.ps1
│       │   └── ConsoleReporter.ps1
│       ├── Schemas/                  # JSON schemas
│       │   ├── rule.schema.json
│       │   └── config.schema.json
│       ├── Templates/                # Report templates
│       │   ├── report.html
│       │   └── styles.css
│       └── en-US/
│           └── about_ADScout.help.txt
├── tests/
│   ├── Unit/
│   │   ├── Public/
│   │   └── Private/
│   ├── Integration/
│   ├── Rules/
│   └── ADScout.Tests.ps1             # Main test entry
├── examples/
│   ├── Basic-Scan.ps1
│   ├── Custom-Rule.ps1
│   ├── Elastic-Integration.ps1
│   └── CI-Pipeline.ps1
├── DESIGN_DOCUMENT.md                # Vision and philosophy (STATIC)
├── ARCHITECTURE.md                   # Implementation guide (STATIC)
├── CONTRIBUTING.md                   # How to contribute
├── ACKNOWLEDGMENTS.md                # Credits to prior art
├── SECURITY.md                       # Security policy
├── CODE_OF_CONDUCT.md                # Community guidelines
├── LICENSE                           # MIT License
├── README.md                         # Project overview
├── CHANGELOG.md                      # Version history
└── .psscriptanalyzerrc               # Linting configuration
```

## Phase 1: Foundation Files

Create the following foundational files:

### 1. LICENSE (MIT)

```
MIT License

Copyright (c) 2024 AD-Scout Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

### 2. README.md

Create a README with:
- Project name and tagline
- Badges (build status, PSGallery version, license)
- Quick start (Install-Module, basic usage)
- Key features list
- Comparison table (vs PingCastle, BloodHound, ADRecon)
- Link to full documentation
- Contributing section
- License notice

### 3. ACKNOWLEDGMENTS.md

Credit the giants we stand upon:
- PingCastle (Vincent LE TOUX) - Scoring model, rule concepts
- BloodHound (SpecterOps) - Attack path understanding
- SMBLibrary (Tal Aloni) - LGPL-3.0 SMB implementation
- RPCForSMBLibrary (Vincent LE TOUX) - LGPL-3.0 RPC
- ADRecon (Prashant Mahajan) - Pure PowerShell viability
- PSWriteHTML (Evotec) - HTML reporting
- WebServer (Markus Scholtes) - PowerShell web server
- DSInternals (Michael Grafnetter) - Deep AD access

Include clear statement: "AD-Scout is an independent project, not a fork or derivative."

### 4. Module Manifest (ADScout.psd1)

```powershell
@{
    RootModule = 'ADScout.psm1'
    ModuleVersion = '0.1.0'
    GUID = '[Generate-New-GUID]'
    Author = 'AD-Scout Contributors'
    CompanyName = 'Community'
    Copyright = '(c) 2024 AD-Scout Contributors. MIT License.'
    Description = 'PowerShell-native Active Directory security assessment framework. Extensible rules, pluggable reporters, cross-version compatible.'

    PowerShellVersion = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')

    FunctionsToExport = @(
        'Invoke-ADScoutScan'
        'Get-ADScoutRule'
        'New-ADScoutRule'
        'Register-ADScoutRule'
        'Export-ADScoutReport'
        'Get-ADScoutRemediation'
        'Set-ADScoutConfig'
        'Get-ADScoutConfig'
        'Show-ADScoutDashboard'
    )

    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()

    PrivateData = @{
        PSData = @{
            Tags = @('ActiveDirectory', 'Security', 'Audit', 'Assessment', 'Compliance', 'MITRE', 'CIS')
            LicenseUri = 'https://github.com/[owner]/ad-scout/blob/main/LICENSE'
            ProjectUri = 'https://github.com/[owner]/ad-scout'
            IconUri = ''
            ReleaseNotes = 'Initial release'
            Prerelease = 'alpha'
        }
    }
}
```

### 5. Module Loader (ADScout.psm1)

```powershell
#Requires -Version 5.1

# Get public and private function files
$Public = @(Get-ChildItem -Path "$PSScriptRoot/Public/*.ps1" -ErrorAction SilentlyContinue)
$Private = @(Get-ChildItem -Path "$PSScriptRoot/Private/**/*.ps1" -Recurse -ErrorAction SilentlyContinue)

# Dot source the files
foreach ($file in @($Private + $Public)) {
    try {
        Write-Verbose "Importing $($file.FullName)"
        . $file.FullName
    }
    catch {
        Write-Error "Failed to import $($file.FullName): $_"
    }
}

# Export public functions
Export-ModuleMember -Function $Public.BaseName

# Module-level initialization
$script:ADScoutConfig = @{
    ParallelThrottleLimit = [Environment]::ProcessorCount
    DefaultReporter = 'Console'
    RulePaths = @()
    CacheTTL = 300  # seconds
}

# Register argument completers
Register-ArgumentCompleter -CommandName Invoke-ADScoutScan -ParameterName Category -ScriptBlock {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    @('Anomalies', 'StaleObjects', 'PrivilegedAccounts', 'Trusts', 'All') |
        Where-Object { $_ -like "$wordToComplete*" } |
        ForEach-Object { [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_) }
}

Register-ArgumentCompleter -CommandName Export-ADScoutReport -ParameterName Format -ScriptBlock {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    @('HTML', 'JSON', 'CSV', 'SARIF', 'Markdown', 'Console') |
        Where-Object { $_ -like "$wordToComplete*" } |
        ForEach-Object { [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_) }
}
```

### 6. Rule Template (_RuleTemplate.ps1)

```powershell
<#
.SYNOPSIS
    [Brief description of what this rule checks]

.DESCRIPTION
    [Detailed description including security implications]

.NOTES
    Rule ID    : [CATEGORY]-[Name]
    Category   : [Anomalies|StaleObjects|PrivilegedAccounts|Trusts]
    Author     : [Your Name]
    Version    : 1.0.0
#>

@{
    # === IDENTITY ===
    Id          = "X-RuleName"
    Name        = "Human Readable Rule Name"
    Category    = "Category"              # Anomalies | StaleObjects | PrivilegedAccounts | Trusts
    Model       = "SubCategory"
    Version     = "1.0.0"

    # === SCORING ===
    Computation = "PerDiscover"           # TriggerOnPresence | PerDiscover | TriggerOnThreshold | TriggerIfLessThan
    Points      = 1                        # Points per finding (or total for TriggerOnPresence)
    MaxPoints   = 100                      # Cap for cumulative scoring
    Threshold   = $null                    # For threshold-based rules

    # === FRAMEWORK MAPPINGS ===
    MITRE       = @()                      # e.g., @("T1078.002", "T1558.003")
    CIS         = @()                      # e.g., @("5.1.2")
    STIG        = @()                      # e.g., @("V-8527")
    ANSSI       = @()                      # e.g., @("R36")

    # === THE CHECK ===
    ScriptBlock = {
        param([Parameter(Mandatory)][hashtable]$ADData)

        # Return objects that violate this rule
        # These become the finding details
        $ADData.Users | Where-Object {
            # Your condition here
            $false
        } | Select-Object SamAccountName, DistinguishedName
    }

    # === OUTPUT ===
    DetailProperties = @("SamAccountName", "DistinguishedName")
    DetailFormat     = "{SamAccountName}"

    # === REMEDIATION ===
    Remediation = {
        param([Parameter(Mandatory)]$Finding)
        @"

# Remediation for: $($Finding.SamAccountName)
# Add remediation commands here

"@
    }

    # === DOCUMENTATION ===
    Description = "Brief description for reports."

    TechnicalExplanation = @"
Detailed technical explanation of:
- Why this is a security issue
- How attackers exploit this
- What the impact could be
"@

    References = @(
        # "https://example.com/reference1"
    )

    # === PREREQUISITES ===
    Prerequisites = {
        param([hashtable]$ADData)
        $true  # Return $false to skip this rule
    }

    AppliesTo = @("OnPremises", "Hybrid")  # OnPremises | Hybrid | CloudOnly
}
```

### 7. Core Public Function Stubs

Create stub implementations for:

#### Invoke-ADScoutScan.ps1
- Parameters: -Domain, -Server, -Credential, -Category, -RuleId, -ThrottleLimit, -Reporter
- Pipeline support
- Progress reporting
- Returns [ADScoutResult] object

#### Get-ADScoutRule.ps1
- Parameters: -Id, -Category, -Path
- Tab completion for -Id
- Returns rule definitions

#### Export-ADScoutReport.ps1
- Parameters: -Results (pipeline), -Format, -Path, -Reporter
- Multiple format support

### 8. Core Private Function Stubs

#### Invoke-ADScoutParallel.ps1
- Cross-version parallel execution
- Tiered: PS7 parallel > ThreadJob > Runspaces > Sequential

#### Get-ADScoutRulePaths.ps1
- Returns rule search paths in priority order

### 9. GitHub Workflows

#### ci.yml
- Trigger on PR to main
- Matrix: Windows (PS 5.1, PS 7), Ubuntu (PS 7), macOS (PS 7)
- Run PSScriptAnalyzer
- Run Pester tests
- Upload coverage

#### docs.yml
- Trigger on push to main (src/ changes)
- Generate documentation from source
- Commit back to repo

### 10. .psscriptanalyzerrc

```powershell
@{
    Severity = @('Error', 'Warning')
    ExcludeRules = @(
        'PSUseShouldProcessForStateChangingFunctions'  # We handle this manually
    )
    Rules = @{
        PSAvoidUsingCmdletAliases = @{ Enable = $true }
        PSAvoidUsingPositionalParameters = @{ Enable = $true }
        PSProvideCommentHelp = @{
            Enable = $true
            Placement = 'begin'
        }
        PSUseConsistentWhitespace = @{
            Enable = $true
            CheckOpenBrace = $true
            CheckOpenParen = $true
            CheckOperator = $true
            CheckSeparator = $true
        }
        PSUseConsistentIndentation = @{
            Enable = $true
            IndentationSize = 4
            Kind = 'space'
        }
    }
}
```

## Phase 2: First Working Rule

Create ONE complete rule to prove the architecture:

### S-PwdNeverExpires.ps1

Implement fully with:
- Complete metadata
- Working ScriptBlock that queries AD
- Remediation scriptblock
- MITRE/CIS/STIG mappings
- Tests

### Supporting Collector

Implement Get-ADScoutUserData.ps1 with:
- Try AD module first, fall back to DirectorySearcher
- Return normalized user objects
- Caching support

## Phase 3: Prove the Pipeline

Demonstrate working flow:
```powershell
Import-Module ./src/ADScout
Invoke-ADScoutScan -Category StaleObjects | Export-ADScoutReport -Format Console
```

## Design Documents

The following design documents should be copied from the reference repository:
- DESIGN_DOCUMENT.md - Vision, philosophy, differentiation
- ARCHITECTURE.md - Implementation details, conventions, extensibility

These are the touchstone documents that guide all implementation decisions.

## Key Principles to Follow

1. **PowerShell-first**: Use native cmdlets before CIM before WMI before .NET
2. **Fail gracefully**: Missing data sources shouldn't crash; skip and warn
3. **Verbose everything**: Users should be able to see exactly what's happening
4. **Test everything**: 80% coverage minimum, mock AD for unit tests
5. **Document everything**: Comment-based help on all public functions
6. **No magic**: Explicit over implicit, clear over clever

## Success Criteria for Phase 1

- [ ] Repository structure created
- [ ] All foundational files in place
- [ ] Module loads without error
- [ ] `Get-Command -Module ADScout` shows exported functions
- [ ] Tab completion works for -Category parameter
- [ ] PSScriptAnalyzer passes with no errors
- [ ] One rule (S-PwdNeverExpires) executes successfully
- [ ] Console reporter outputs findings
- [ ] Basic Pester test passes

Begin scaffolding the repository now.
```

---

## How to Use This Prompt

1. Create new repository: `github.com/[owner]/ad-scout`
2. Clone locally: `git clone ...`
3. Start a new Claude session in that directory
4. Paste the prompt above
5. Claude will scaffold the entire project structure

## Files to Copy Manually

After scaffolding, copy these from the reference repo:
- `DESIGN_DOCUMENT.md`
- `ARCHITECTURE.md`

These contain the vision and architectural decisions that should remain static.
