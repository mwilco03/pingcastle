# AD-Scout Architecture & Implementation Guide

## Project Identity

**Name:** `AD-Scout` (hyphenated to avoid trademark conflicts)
**Module Name:** `ADScout` (PowerShell module naming convention)
**Repository:** `ad-scout`

---

## 1. Documentation Strategy: Configuration-Driven

### Document Classification

```
STATIC (Human-Authored, Rarely Change)
├── DESIGN_DOCUMENT.md      # Vision, philosophy, "why we exist"
├── ARCHITECTURE.md         # This file - structural decisions
├── CONTRIBUTING.md         # How to contribute, code style
├── ACKNOWLEDGMENTS.md      # Giants we stand upon
├── LICENSE                 # MIT
└── SECURITY.md             # Vulnerability reporting

DYNAMIC (Auto-Generated at Build/Commit)
├── docs/
│   ├── RULES.md            # Generated from rule metadata
│   ├── CMDLET-REFERENCE.md # Generated from Get-Help
│   ├── CONFIGURATION.md    # Generated from schema
│   ├── COVERAGE.md         # Which checks map to which frameworks
│   └── CHANGELOG.md        # Generated from conventional commits
└── README.md               # Partially templated (badges, stats)
```

### Auto-Generation Strategy

```powershell
# build/Update-Documentation.ps1
# Runs on: pre-commit hook, CI/CD pipeline, release

function Update-RulesDocumentation {
    $rules = Get-ChildItem -Path "./src/ADScout/Rules" -Recurse -Filter "*.ps1" |
        ForEach-Object { . $_.FullName; $_ } |
        Get-ADScoutRuleMetadata

    $markdown = @"
# AD-Scout Rules Reference

> Auto-generated on $(Get-Date -Format "yyyy-MM-dd HH:mm:ss UTC")
> Total Rules: $($rules.Count)

## By Category

$(foreach ($category in $rules | Group-Object Category) {
"### $($category.Name) ($($category.Count) rules)"
$category.Group | ForEach-Object {
"- **$($_.Id)**: $($_.Name) [$($_.Points) pts]"
}
})

## Framework Coverage

| Framework | Rules Mapped |
|-----------|--------------|
$(foreach ($fw in @('MITRE','CIS','STIG','ANSSI')) {
$count = ($rules | Where-Object { $_.$fw }).Count
"| $fw | $count |"
})
"@

    $markdown | Set-Content "./docs/RULES.md" -Encoding UTF8
}

function Update-CmdletReference {
    $commands = Get-Command -Module ADScout
    # Use PlatyPS or custom generator
    foreach ($cmd in $commands) {
        $help = Get-Help $cmd.Name -Full
        # Generate markdown...
    }
}

function Update-ConfigurationDocs {
    # Read schema, generate docs
    $schema = Get-Content "./src/ADScout/Schemas/config.schema.json" | ConvertFrom-Json
    # Generate markdown from JSON schema...
}
```

### Drift Prevention

```yaml
# .github/workflows/docs.yml
name: Documentation Sync
on:
  push:
    paths:
      - 'src/ADScout/Rules/**'
      - 'src/ADScout/Public/**'
      - 'src/ADScout/Schemas/**'

jobs:
  update-docs:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Generate Documentation
        shell: pwsh
        run: ./build/Update-Documentation.ps1
      - name: Commit if changed
        run: |
          git diff --quiet docs/ || (
            git add docs/
            git commit -m "docs: auto-update from source [skip ci]"
            git push
          )
```

---

## 2. Rules Directory & Extensibility Model

### Directory Structure

```
src/ADScout/Rules/
├── _RuleTemplate.ps1           # Copy this to create new rules
├── Anomalies/
│   ├── A-AuditDC.ps1
│   ├── A-DCRefuseComputerPwdChange.ps1
│   └── ...
├── StaleObjects/
│   ├── S-PwdLastSet-DC.ps1
│   ├── S-InactiveComputer.ps1
│   └── ...
├── PrivilegedAccounts/
│   ├── P-Kerberoasting.ps1
│   ├── P-AdminCount.ps1
│   └── ...
└── Trusts/
    ├── T-SIDFiltering.ps1
    └── ...
```

### Rule File Format

```powershell
# src/ADScout/Rules/StaleObjects/S-PwdNeverExpires.ps1

<#
.SYNOPSIS
    Detects user accounts with PasswordNeverExpires flag set.

.DESCRIPTION
    Accounts with passwords that never expire present a persistent
    attack surface. Compromised credentials remain valid indefinitely.

.NOTES
    Rule ID    : S-PwdNeverExpires
    Category   : StaleObjects
    Model      : PasswordPolicy
    Author     : AD-Scout Contributors
    Version    : 1.0.0
#>

@{
    # === IDENTITY ===
    Id          = "S-PwdNeverExpires"
    Name        = "Password Never Expires"
    Category    = "StaleObjects"
    Model       = "PasswordPolicy"
    Version     = "1.0.0"

    # === SCORING ===
    Computation = "PerDiscover"    # TriggerOnPresence | PerDiscover | TriggerOnThreshold | TriggerIfLessThan
    Points      = 1
    MaxPoints   = 30
    Threshold   = $null            # For TriggerOnThreshold

    # === FRAMEWORK MAPPINGS ===
    MITRE       = @("T1078.002")
    CIS         = @("5.1.2")
    STIG        = @("V-8527")
    ANSSI       = @("R36")

    # === THE CHECK ===
    # Returns: Objects that violate the rule (these become finding details)
    # Receives: $ADData (normalized AD data object)
    ScriptBlock = {
        param([Parameter(Mandatory)][hashtable]$ADData)

        $ADData.Users | Where-Object {
            $_.PasswordNeverExpires -eq $true -and
            $_.Enabled -eq $true -and
            $_.SamAccountName -notlike 'krbtgt' -and
            $_.SamAccountName -notlike 'AZUREADSSOACC*'
        } | Select-Object SamAccountName, DistinguishedName, PasswordLastSet, WhenCreated
    }

    # === OUTPUT CONFIGURATION ===
    DetailProperties = @("SamAccountName", "DistinguishedName", "PasswordLastSet")
    DetailFormat     = "{SamAccountName} (Password set: {PasswordLastSet:yyyy-MM-dd})"

    # === REMEDIATION ===
    Remediation = {
        param([Parameter(Mandatory)]$Finding)
        # Returns executable remediation script
        @"
# Remediate: $($Finding.SamAccountName)
Set-ADUser -Identity '$($Finding.SamAccountName)' -PasswordNeverExpires `$false -WhatIf
"@
    }

    # === DOCUMENTATION ===
    Description = "Accounts with passwords that never expire present a persistent attack surface."

    TechnicalExplanation = @"
When PasswordNeverExpires is set, compromised credentials remain valid indefinitely.
This extends the window of opportunity for attackers who obtain password hashes through:
- Kerberoasting (T1558.003)
- AS-REP Roasting (T1558.004)
- NTLM hash extraction
- Credential stuffing
"@

    References = @(
        "https://attack.mitre.org/techniques/T1078/002/"
        "https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/password-policy"
    )

    # === FILTERING ===
    # When should this rule run?
    Prerequisites = {
        param([hashtable]$ADData)
        # Return $true if rule should run, $false to skip
        $ADData.Users.Count -gt 0
    }

    # Environments where rule is relevant
    AppliesTo = @("OnPremises", "Hybrid")  # OnPremises | Hybrid | CloudOnly

    # Minimum severity for this to matter
    MinimumEnvironmentSize = 0  # 0 = all, 100 = medium+, 1000 = enterprise only
}
```

### Extensibility Paths

```
Built-in Rules (ship with module)
└── src/ADScout/Rules/

User Rules (per-machine)
└── ~/.adscout/Rules/
    └── MyOrg/
        └── MYORG-CustomCheck.ps1

System Rules (all users on machine)
└── /etc/adscout/Rules/        # Linux/macOS
└── C:\ProgramData\ADScout\Rules\  # Windows

Environment Variable
└── $env:ADSCOUT_RULES_PATH = "C:\Corp\ADScoutRules;\\server\share\rules"
```

### Rule Loading Order (Last Wins for Overrides)

```powershell
function Get-ADScoutRulePaths {
    @(
        # 1. Built-in (lowest priority)
        Join-Path $PSScriptRoot "Rules"

        # 2. System-wide
        if ($IsWindows) { "C:\ProgramData\ADScout\Rules" }
        else { "/etc/adscout/Rules" }

        # 3. User-specific
        Join-Path $HOME ".adscout/Rules"

        # 4. Environment override (highest priority)
        if ($env:ADSCOUT_RULES_PATH) {
            $env:ADSCOUT_RULES_PATH -split [IO.Path]::PathSeparator
        }
    ) | Where-Object { Test-Path $_ }
}
```

### Rule Registration API

```powershell
# Runtime rule registration (ephemeral, session only)
Register-ADScoutRule -Definition @{
    Id = "CUSTOM-001"
    Name = "My Quick Check"
    Category = "Anomalies"
    ScriptBlock = { param($ADData) $ADData.Users | Where-Object { $_.BadPwdCount -gt 10 } }
}

# Persist a rule to user directory
New-ADScoutRule -Id "MYORG-001" -Name "Org-Specific Check" -ScriptBlock {
    param($ADData)
    # ...
} | Export-ADScoutRule -Path "~/.adscout/Rules/MyOrg/"

# Import rules from URL/gallery
Install-ADScoutRule -Uri "https://gallery.adscout.dev/rules/community-pack.zip"
```

---

## 3. Output & Reporter Extensibility

### Reporter Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        SCAN RESULTS                                  │
│  [ADScoutResult] object with Rules, Scores, Findings, Metadata      │
└─────────────────────────────────┬───────────────────────────────────┘
                                  │
                    ┌─────────────┴─────────────┐
                    ▼                           ▼
           Synchronous Reporters         Async/Streaming Reporters
           (Export-ADScoutReport)        (Send-ADScoutFinding)
                    │                           │
        ┌───────────┼───────────┐    ┌──────────┼──────────┐
        ▼           ▼           ▼    ▼          ▼          ▼
    ┌──────┐   ┌──────┐   ┌──────┐  ┌────┐  ┌───────┐  ┌───────┐
    │ HTML │   │ JSON │   │ CSV  │  │Elstic│ │Webhook│  │MsgBus │
    └──────┘   └──────┘   └──────┘  └────┘  └───────┘  └───────┘
```

### Built-in Reporters

```powershell
# Synchronous (full report after scan)
Export-ADScoutReport -Results $results -Format HTML -Path "./report.html"
Export-ADScoutReport -Results $results -Format JSON -Path "./results.json"
Export-ADScoutReport -Results $results -Format CSV -Path "./findings.csv"
Export-ADScoutReport -Results $results -Format SARIF -Path "./results.sarif"  # GitHub/Azure DevOps
Export-ADScoutReport -Results $results -Format Markdown -Path "./FINDINGS.md"

# Streaming (real-time as findings occur)
Invoke-ADScoutScan -OnFinding {
    param($Finding)
    Send-ADScoutToElastic -Finding $Finding
}
```

### Reporter Plugin Format

```powershell
# ~/.adscout/Reporters/ElasticReporter.ps1

@{
    Name        = "Elastic"
    Type        = "Streaming"  # Streaming | Batch
    Author      = "Community"
    Version     = "1.0.0"

    # Configuration schema
    ConfigSchema = @{
        ElasticUrl = @{ Type = "string"; Required = $true; Default = "http://localhost:9200" }
        IndexName  = @{ Type = "string"; Required = $true; Default = "adscout-findings" }
        ApiKey     = @{ Type = "securestring"; Required = $false }
    }

    # For Streaming reporters - called per finding
    OnFinding = {
        param(
            [Parameter(Mandatory)][hashtable]$Finding,
            [Parameter(Mandatory)][hashtable]$Config
        )

        $body = $Finding | ConvertTo-Json -Depth 10
        $headers = @{ "Content-Type" = "application/json" }
        if ($Config.ApiKey) {
            $headers["Authorization"] = "ApiKey $($Config.ApiKey | ConvertFrom-SecureString -AsPlainText)"
        }

        Invoke-RestMethod -Uri "$($Config.ElasticUrl)/$($Config.IndexName)/_doc" `
            -Method POST -Body $body -Headers $headers
    }

    # For Batch reporters - called with full results
    OnComplete = {
        param(
            [Parameter(Mandatory)][hashtable]$Results,
            [Parameter(Mandatory)][hashtable]$Config
        )
        # Bulk index all findings...
    }
}
```

### Example Reporter Configurations

```powershell
# Configure Elastic output
Set-ADScoutReporter -Name Elastic -Config @{
    ElasticUrl = "https://elastic.corp.local:9200"
    IndexName  = "security-adscout"
    ApiKey     = (Read-Host -AsSecureString "Elastic API Key")
}

# Configure Webhook
Set-ADScoutReporter -Name Webhook -Config @{
    Url     = "https://hooks.slack.com/services/XXX/YYY/ZZZ"
    Format  = "slack"  # slack | teams | discord | generic
    MinSeverity = 50   # Only send findings >= 50 points
}

# Configure Azure Event Hub
Set-ADScoutReporter -Name AzureEventHub -Config @{
    ConnectionString = $env:EVENTHUB_CONNECTION
    HubName = "adscout-events"
}

# Use multiple reporters
Invoke-ADScoutScan -Reporter HTML, JSON, Elastic, Webhook
```

### Common Output Targets

| Target | Reporter | Use Case |
|--------|----------|----------|
| **Elasticsearch** | `Elastic` | SIEM integration, Kibana dashboards |
| **Splunk** | `SplunkHEC` | SIEM integration |
| **Azure Sentinel** | `Sentinel` | Cloud SIEM |
| **Webhook** | `Webhook` | Slack, Teams, Discord, PagerDuty |
| **Azure Event Hub** | `AzureEventHub` | Event-driven architecture |
| **AWS SNS/SQS** | `AWSSns` | AWS integration |
| **Kafka** | `Kafka` | Stream processing |
| **Syslog** | `Syslog` | Traditional logging |
| **Windows Event Log** | `EventLog` | Native Windows integration |
| **File (JSON-L)** | `JsonLines` | Log aggregation, Loki |

---

## 4. Parallelization Strategy

### Tiered Approach

```
┌─────────────────────────────────────────────────────────────────────┐
│                    PARALLELIZATION TIERS                             │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Tier 1: PowerShell 7+ (ForEach-Object -Parallel)                   │
│  └── Native, fastest, preferred                                     │
│                                                                      │
│  Tier 2: PowerShell 5.1 (Runspace Pools)                            │
│  └── ThreadJob module or custom runspaces                           │
│                                                                      │
│  Tier 3: PowerShell 5.1 (Jobs)                                      │
│  └── Start-Job, higher overhead, fallback                           │
│                                                                      │
│  Tier 4: PowerShell 2.0 (Sequential)                                │
│  └── No parallelization, progress indicators                        │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Implementation

```powershell
# src/ADScout/Private/Invoke-ADScoutParallel.ps1

function Invoke-ADScoutParallel {
    <#
    .SYNOPSIS
        Cross-version parallel execution wrapper.
    .DESCRIPTION
        Automatically selects the best parallelization strategy based on
        PowerShell version and available modules.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object[]]$InputObject,

        [Parameter(Mandatory)]
        [scriptblock]$ScriptBlock,

        [Parameter()]
        [int]$ThrottleLimit = [Environment]::ProcessorCount,

        [Parameter()]
        [hashtable]$ArgumentList = @{},

        [Parameter()]
        [switch]$NoProgress
    )

    begin {
        $items = [System.Collections.Generic.List[object]]::new()
        $psVersion = $PSVersionTable.PSVersion.Major
    }

    process {
        foreach ($item in $InputObject) {
            $items.Add($item)
        }
    }

    end {
        $total = $items.Count
        if ($total -eq 0) { return }

        # Tier 1: PowerShell 7+ native parallel
        if ($psVersion -ge 7) {
            Write-Verbose "Using ForEach-Object -Parallel (PS7+)"
            $items | ForEach-Object -Parallel {
                $args = $using:ArgumentList
                & $using:ScriptBlock $_ @args
            } -ThrottleLimit $ThrottleLimit
            return
        }

        # Tier 2: ThreadJob module (PS5.1)
        if (Get-Module -ListAvailable -Name ThreadJob) {
            Write-Verbose "Using ThreadJob module"
            Import-Module ThreadJob -ErrorAction SilentlyContinue
            $jobs = $items | ForEach-Object {
                Start-ThreadJob -ScriptBlock $ScriptBlock -ArgumentList $_, $ArgumentList -ThrottleLimit $ThrottleLimit
            }
            $jobs | Wait-Job | Receive-Job
            $jobs | Remove-Job
            return
        }

        # Tier 3: Runspace Pool (PS3+)
        if ($psVersion -ge 3) {
            Write-Verbose "Using Runspace Pool"
            $pool = [RunspaceFactory]::CreateRunspacePool(1, $ThrottleLimit)
            $pool.Open()

            $runspaces = foreach ($item in $items) {
                $ps = [PowerShell]::Create().AddScript($ScriptBlock).AddArgument($item)
                foreach ($key in $ArgumentList.Keys) {
                    $ps.AddParameter($key, $ArgumentList[$key])
                }
                $ps.RunspacePool = $pool
                @{
                    PowerShell = $ps
                    Handle     = $ps.BeginInvoke()
                }
            }

            $completed = 0
            foreach ($rs in $runspaces) {
                $rs.PowerShell.EndInvoke($rs.Handle)
                $rs.PowerShell.Dispose()
                $completed++
                if (-not $NoProgress) {
                    Write-Progress -Activity "Processing" -PercentComplete (($completed / $total) * 100)
                }
            }
            $pool.Close()
            $pool.Dispose()
            return
        }

        # Tier 4: Sequential fallback (PS2)
        Write-Verbose "Using sequential processing (PS2 fallback)"
        $completed = 0
        foreach ($item in $items) {
            & $ScriptBlock $item @ArgumentList
            $completed++
            if (-not $NoProgress) {
                Write-Progress -Activity "Processing" -PercentComplete (($completed / $total) * 100)
            }
        }
    }
}
```

### Parallelization Points

| Operation | Parallel? | Notes |
|-----------|-----------|-------|
| **LDAP Queries** | No | Single connection, server-side paging |
| **Rule Execution** | Yes | Each rule runs independently |
| **Remote Scans (SMB/RPC)** | Yes | Per-target parallelism |
| **Report Generation** | No | Usually fast, not worth overhead |
| **Output to Multiple Reporters** | Yes | Independent destinations |

### Configuration

```powershell
# User preference
Set-ADScoutConfig -ParallelThrottleLimit 20  # Default: CPU count
Set-ADScoutConfig -ParallelStrategy Auto     # Auto | ForceSequential | ForceJobs

# Per-invocation override
Invoke-ADScoutScan -ThrottleLimit 50 -Verbose
```

---

## 5. Maintainability & PowerShell Conventions

### Code Style Standards

```powershell
# Use PSScriptAnalyzer with strict settings
# .vscode/settings.json or build process
Invoke-ScriptAnalyzer -Path ./src -Recurse -Settings PSGallery

# Custom rules in .psscriptanalyzerrc
@{
    Severity = @('Error', 'Warning', 'Information')
    ExcludeRules = @()
    Rules = @{
        PSAvoidUsingCmdletAliases = @{ Enable = $true }
        PSAvoidUsingPositionalParameters = @{ Enable = $true }
        PSUseConsistentWhitespace = @{
            Enable = $true
            CheckOpenBrace = $true
            CheckOpenParen = $true
        }
    }
}
```

### Naming Conventions

```powershell
# Verb-Noun format (approved verbs only)
Get-ADScoutRule          # Not: Fetch-ADScoutRule
Invoke-ADScoutScan       # Not: Run-ADScoutScan
Export-ADScoutReport     # Not: Save-ADScoutReport

# Parameter naming
-ComputerName            # Not: -Server, -Machine, -Host
-Credential              # Standard credential parameter
-Path                    # Not: -FilePath, -FileName (unless disambiguation needed)
-Force                   # Standard override switch
-WhatIf / -Confirm       # ShouldProcess support

# Internal functions: No prefix needed but use descriptive names
function Convert-SidToName { }      # Private
function Get-CachedDomainInfo { }   # Private
```

### Standard Patterns

```powershell
# 1. Advanced Function Template
function Verb-ADScoutNoun {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Identity,

        [Parameter()]
        [PSCredential]$Credential,

        [Parameter()]
        [switch]$Force
    )

    begin {
        # Initialize, validate environment
    }

    process {
        foreach ($item in $Identity) {
            if ($PSCmdlet.ShouldProcess($item, "Operation description")) {
                try {
                    # Do work
                }
                catch {
                    $PSCmdlet.WriteError($_)
                }
            }
        }
    }

    end {
        # Cleanup
    }
}

# 2. Error Handling
try {
    $result = Get-Something -ErrorAction Stop
}
catch [System.UnauthorizedAccessException] {
    Write-Error "Access denied. Ensure you have Domain Admin rights." -Category PermissionDenied
}
catch {
    Write-Error "Unexpected error: $_" -Category NotSpecified
}

# 3. Verbose/Debug Output
Write-Verbose "Connecting to domain controller: $DC"
Write-Debug "LDAP filter: $filter"  # More detailed, developer-focused

# 4. Progress Reporting
$total = $items.Count
$current = 0
foreach ($item in $items) {
    $current++
    Write-Progress -Activity "Scanning" -Status $item -PercentComplete (($current / $total) * 100)
    # Process...
}
Write-Progress -Activity "Scanning" -Completed
```

### Module Structure Standards

```powershell
# Module manifest requirements
@{
    RootModule = 'ADScout.psm1'
    ModuleVersion = '0.1.0'  # SemVer
    GUID = 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
    Author = 'AD-Scout Contributors'
    Description = 'PowerShell-native Active Directory security assessment framework'

    # Explicit exports (no wildcards in production)
    FunctionsToExport = @(
        'Invoke-ADScoutScan'
        'Get-ADScoutRule'
        'New-ADScoutRule'
        # ...
    )
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()

    # Dependencies
    RequiredModules = @()  # Keep minimal
    PowerShellVersion = '5.1'

    # Metadata
    PrivateData = @{
        PSData = @{
            Tags = @('ActiveDirectory', 'Security', 'Audit', 'Assessment')
            LicenseUri = 'https://github.com/mwilco03/ad-scout/blob/main/LICENSE'
            ProjectUri = 'https://github.com/mwilco03/ad-scout'
            ReleaseNotes = 'See CHANGELOG.md'
        }
    }
}

# Module loader pattern (.psm1)
$Public = @(Get-ChildItem -Path $PSScriptRoot/Public/*.ps1 -ErrorAction SilentlyContinue)
$Private = @(Get-ChildItem -Path $PSScriptRoot/Private/*.ps1 -Recurse -ErrorAction SilentlyContinue)

foreach ($file in @($Private + $Public)) {
    try {
        . $file.FullName
    }
    catch {
        Write-Error "Failed to import $($file.FullName): $_"
    }
}

Export-ModuleMember -Function $Public.BaseName
```

### Testing Standards

```powershell
# Pester 5.x structure
Describe "Invoke-ADScoutScan" {
    BeforeAll {
        Import-Module ./src/ADScout/ADScout.psd1 -Force
    }

    Context "Parameter Validation" {
        It "Should require -Domain or default to current domain" {
            { Invoke-ADScoutScan -Domain "" } | Should -Throw
        }
    }

    Context "Rule Execution" {
        It "Should return results with expected properties" {
            $result = Invoke-ADScoutScan -Category Anomalies -WhatIf
            $result | Should -HaveProperty 'GlobalScore'
            $result | Should -HaveProperty 'Rules'
        }
    }
}

# Test coverage requirement: 80%+
Invoke-Pester -CodeCoverage ./src/ADScout/**/*.ps1 -CodeCoverageOutputFile coverage.xml
```

### Documentation Standards

```powershell
# Every public function must have:
<#
.SYNOPSIS
    One-line description.

.DESCRIPTION
    Detailed description including:
    - What it does
    - When to use it
    - Prerequisites

.PARAMETER Identity
    Description of parameter.

.EXAMPLE
    PS> Invoke-ADScoutScan -Domain contoso.com

    Basic scan of contoso.com domain.

.EXAMPLE
    PS> Invoke-ADScoutScan -Category PrivilegedAccounts -Verbose

    Scan only privileged account rules with verbose output.

.INPUTS
    System.String
    You can pipe domain names to this function.

.OUTPUTS
    ADScout.ScanResult
    Returns scan results object.

.NOTES
    Author: AD-Scout Contributors
    Version: 1.0.0

.LINK
    https://adscout.dev/docs/invoke-adscoutscan
#>
```

---

## 6. Repository Layout (Final)

```
ad-scout/
├── .github/
│   ├── workflows/
│   │   ├── ci.yml              # Test on PR
│   │   ├── release.yml         # Publish to PSGallery
│   │   └── docs.yml            # Auto-generate docs
│   ├── ISSUE_TEMPLATE/
│   └── PULL_REQUEST_TEMPLATE.md
├── .vscode/
│   ├── settings.json           # PSScriptAnalyzer, formatting
│   ├── tasks.json              # Build tasks
│   └── launch.json             # Debug configurations
├── build/
│   ├── Build-Module.ps1        # Build script
│   ├── Update-Documentation.ps1
│   └── Publish-Module.ps1
├── docs/                       # AUTO-GENERATED
│   ├── RULES.md
│   ├── CMDLET-REFERENCE.md
│   ├── CONFIGURATION.md
│   └── COVERAGE.md
├── src/
│   └── ADScout/
│       ├── ADScout.psd1
│       ├── ADScout.psm1
│       ├── Public/             # Exported functions
│       ├── Private/            # Internal functions
│       │   ├── Collectors/
│       │   ├── Scanners/
│       │   └── Helpers/
│       ├── Rules/              # Built-in rules
│       │   ├── Anomalies/
│       │   ├── StaleObjects/
│       │   ├── PrivilegedAccounts/
│       │   └── Trusts/
│       ├── Reporters/          # Output plugins
│       ├── Schemas/            # JSON schemas for config
│       ├── Templates/          # Report templates
│       └── Libraries/          # Optional .NET deps
├── tests/
│   ├── Unit/
│   ├── Integration/
│   └── ADScout.Tests.ps1
├── examples/
│   ├── basic-scan.ps1
│   ├── custom-rule.ps1
│   └── elastic-integration.ps1
├── DESIGN_DOCUMENT.md          # STATIC - Vision
├── ARCHITECTURE.md             # STATIC - This file
├── CONTRIBUTING.md             # STATIC - How to contribute
├── ACKNOWLEDGMENTS.md          # STATIC - Giants
├── SECURITY.md                 # STATIC - Vuln reporting
├── LICENSE                     # MIT
├── README.md                   # Partially templated
├── CHANGELOG.md                # Auto from conventional commits
└── .psscriptanalyzerrc         # Linting rules
```

---

## Summary

| Concern | Solution |
|---------|----------|
| **Naming** | `AD-Scout` (repo), `ADScout` (module) |
| **Docs Drift** | Auto-generate dynamic docs at build/commit |
| **Rule Extensibility** | Directory-based, multiple paths, runtime registration |
| **Output Flexibility** | Pluggable reporters, streaming + batch modes |
| **Parallelization** | Tiered strategy (PS7 > ThreadJob > Runspaces > Sequential) |
| **Maintainability** | PSScriptAnalyzer, Pester, strict conventions, clear structure |

