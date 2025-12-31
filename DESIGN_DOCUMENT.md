# ADScout: PowerShell-Native Active Directory Security Assessment Framework

## Design Document v0.1

---

## Executive Summary

**ADScout** is a PowerShell-native Active Directory security assessment framework designed from the ground up for the modern administrator, security professional, and DevOps engineer. While standing on the shoulders of giants like PingCastle, BloodHound, and ADRecon, ADScout is a wholly distinct project with different goals, architecture, and philosophy.

**Core Philosophy:** *"If it can be done in PowerShell, it should be done in PowerShell."*

---

## 1. Vision & Objectives

### What We Are Aiming to Accomplish

1. **Democratize AD Security Assessment** - Make professional-grade AD security auditing accessible to every organization, regardless of budget or expertise level.

2. **PowerShell-Native Experience** - First-class PowerShell citizen with tab-completion, pipeline support, `Show-Command` integration, and idiomatic PowerShell patterns.

3. **Community-Driven Extensibility** - Lower the barrier for security professionals to contribute rules, scanners, and reports without requiring C# compilation or complex toolchains.

4. **Cross-Version Compatibility** - Deterministic behavior across PowerShell 2.0 (legacy), 5.1 (Windows), and 7.x (cross-platform).

5. **Transparency & Education** - Not just "you have a problem" but "here's why it's a problem, here's the attack path, and here's exactly how to fix it."

---

## 2. Differentiation: Why ADScout?

### How ADScout Differs from PingCastle

| Aspect | PingCastle | ADScout |
|--------|------------|---------|
| **Language** | C# compiled executable | PowerShell-native module |
| **Rule Creation** | Requires C# knowledge, recompilation | Drop-in `.ps1` files with scriptblocks |
| **Extensibility** | Modify source, rebuild | `Register-ADScoutRule` at runtime |
| **Integration** | Standalone tool | Pipeline-native, CI/CD ready |
| **Reporting** | Embedded HTML generation | Pluggable reporters (HTML, JSON, CSV, Dashboard) |
| **AV Detection** | Often flagged (15+ vendors) | Scripts rarely flagged |
| **Learning Curve** | Run executable, read report | Interactive exploration, `Get-Help` everywhere |
| **Customization** | Configuration files | PowerShell parameter sets, splatting |
| **Community Rules** | Pull requests to main repo | Local rule directories, community galleries |

### How ADScout Differs from BloodHound

| Aspect | BloodHound | ADScout |
|--------|------------|---------|
| **Focus** | Attack path analysis (graph) | Security posture assessment (score) |
| **Output** | Neo4j database, web UI | PowerShell objects, exportable reports |
| **Use Case** | Red team, penetration testing | Blue team, compliance, continuous monitoring |
| **Dependencies** | Neo4j, SharpHound binary | PowerShell only (optional .NET libs) |
| **Complementary** | Yes - different focus areas | Can feed data TO BloodHound |

### How ADScout Differs from ADRecon

| Aspect | ADRecon | ADScout |
|--------|---------|---------|
| **Focus** | Data collection & inventory | Security assessment & scoring |
| **Output** | Excel spreadsheets | Scored findings with remediation |
| **Rules** | Implicit in code | Explicit, declarative, extensible |
| **Scoring** | None | Risk-based scoring system |

---

## 3. Key Features

### 3.1 Rule Generator Architecture

The heart of ADScout is its **scriptblock-based rule system**:

```powershell
# Defining a rule is as simple as writing a scriptblock
New-ADScoutRule -Id "S-PwdNeverExpires" -Category "StaleObjects" -ScriptBlock {
    param($ADData)

    # Return objects that violate the rule
    $ADData.Users | Where-Object {
        $_.PasswordNeverExpires -eq $true -and
        $_.Enabled -eq $true
    }
}

# The returned objects automatically become the finding details
# Points are calculated based on count and rule configuration
```

#### Rule Definition Schema

```powershell
@{
    # Identity
    Id          = "S-PwdNeverExpires"
    Name        = "Password Never Expires"
    Category    = "StaleObjects"        # Anomalies, StaleObjects, PrivilegedAccounts, Trusts
    Model       = "PasswordPolicy"       # Sub-categorization

    # Scoring
    Computation = "PerDiscover"          # TriggerOnPresence, PerDiscover, TriggerOnThreshold, TriggerIfLessThan
    Points      = 1                       # Points per finding (or total for TriggerOnPresence)
    MaxPoints   = 30                      # Cap for PerDiscover rules

    # Framework Mappings
    MITRE       = @("T1078.002")         # MITRE ATT&CK technique IDs
    ANSSI       = "R36"                   # ANSSI recommendation
    CIS         = "5.1.2"                 # CIS Benchmark control
    STIG        = "V-8527"                # DISA STIG finding ID

    # The Check (returns violating objects)
    ScriptBlock = {
        param($ADData)
        $ADData.Users | Where-Object { $_.PasswordNeverExpires -and $_.Enabled }
    }

    # Output Configuration
    DetailProperties = @("SamAccountName", "DistinguishedName", "PasswordLastSet")

    # Remediation
    Remediation = @"
Set password expiration policy:
    Set-ADUser -Identity <user> -PasswordNeverExpires $false

Or via Group Policy:
    Computer Configuration > Policies > Windows Settings >
    Security Settings > Account Policies > Password Policy >
    Maximum password age: 90 days (or per organizational policy)
"@

    # Documentation
    Description = "Accounts with passwords that never expire present a persistent attack surface."
    TechnicalExplanation = @"
When PasswordNeverExpires is set, compromised credentials remain valid indefinitely.
This violates the principle of credential hygiene and extends the window of opportunity
for attackers who obtain password hashes through techniques like:
- Kerberoasting (T1558.003)
- AS-REP Roasting (T1558.004)
- NTLM hash extraction
"@

    # References
    References = @(
        "https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/password-policy"
        "https://attack.mitre.org/techniques/T1078/002/"
    )
}
```

#### Interactive Rule Builder

```powershell
# GUI-assisted rule creation
Show-Command New-ADScoutRule

# This opens a dialog with:
# - Dropdown for Category (tab-completable)
# - Dropdown for Computation type
# - Script editor for ScriptBlock
# - Framework mapping helpers
```

### 3.2 Tab-Completion & Show-Command Integration

Every command supports rich tab-completion:

```powershell
# Tab through categories
Invoke-ADScoutScan -Category <TAB>
# Shows: Anomalies, StaleObjects, PrivilegedAccounts, Trusts

# Tab through specific rules
Invoke-ADScoutScan -RuleId <TAB>
# Shows: A-AuditDC, A-DCRefuseComputerPwdChange, A-DnsZoneTransfer...

# Tab through output formats
Export-ADScoutReport -Format <TAB>
# Shows: HTML, JSON, CSV, XML, Dashboard

# Show-Command for discovery
Show-Command Invoke-ADScoutScan
# Opens GUI with all parameters, dropdowns, help text
```

#### ArgumentCompleter Implementation

```powershell
# Built-in completers for discoverability
Register-ArgumentCompleter -CommandName Invoke-ADScoutScan -ParameterName Category -ScriptBlock {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)

    @('Anomalies', 'StaleObjects', 'PrivilegedAccounts', 'Trusts') |
        Where-Object { $_ -like "$wordToComplete*" } |
        ForEach-Object { [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_) }
}

Register-ArgumentCompleter -CommandName Invoke-ADScoutScan -ParameterName RuleId -ScriptBlock {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)

    Get-ADScoutRule |
        Where-Object { $_.Id -like "$wordToComplete*" } |
        ForEach-Object {
            [System.Management.Automation.CompletionResult]::new(
                $_.Id,
                $_.Id,
                'ParameterValue',
                "$($_.Id): $($_.Name)"
            )
        }
}
```

### 3.3 Data Collection Priority

**PowerShell-First Philosophy:**

```
Priority 1: Native PowerShell Cmdlets
    Get-ADUser, Get-ADComputer, Get-ADGroup, Get-ADTrust
    Get-ADDomain, Get-ADForest, Get-ADReplicationSite

Priority 2: CIM/WMI (Invoke-CimInstance preferred)
    Invoke-CimInstance -ClassName Win32_OperatingSystem
    Invoke-CimInstance -ClassName Win32_ComputerSystem
    Get-CimInstance vs Get-WmiObject (CIM preferred for PS 3+)

Priority 3: .NET Framework Classes
    [System.DirectoryServices.DirectorySearcher] for LDAP
    [System.DirectoryServices.ActiveDirectory.*] for forest/domain

Priority 4: External Libraries (when no alternative)
    SMBLibrary for protocol-level SMB scanning
    RPCForSMBLibrary for SAMR/LSA/Netlogon
    Only loaded when specific scanners invoked
```

#### Adaptive Collection

```powershell
function Get-ADScoutUserData {
    [CmdletBinding()]
    param([string]$Server)

    # Try native AD cmdlets first (cleanest)
    if (Get-Module ActiveDirectory -ListAvailable) {
        Write-Verbose "Using ActiveDirectory module"
        return Get-ADUser -Filter * -Properties * -Server $Server
    }

    # Fall back to DirectorySearcher (works without RSAT)
    Write-Verbose "Using DirectorySearcher (RSAT not available)"
    $searcher = [System.DirectoryServices.DirectorySearcher]::new()
    $searcher.Filter = "(objectClass=user)"
    $searcher.PageSize = 1000
    return $searcher.FindAll() | Convert-ToADScoutUser
}
```

### 3.4 Cross-Version Compatibility Matrix

| Feature | PS 2.0 | PS 5.1 | PS 7.x | Notes |
|---------|--------|--------|--------|-------|
| **Core Rules** | ✅ | ✅ | ✅ | DirectorySearcher works everywhere |
| **AD Cmdlets** | ❌ | ✅ | ✅ | Graceful fallback to ADSI |
| **CIM Sessions** | ❌ | ✅ | ✅ | Falls back to WMI on PS 2.0 |
| **Tab Completion** | ❌ | ✅ | ✅ | Not available in PS 2.0 |
| **Classes** | ❌ | ✅ | ✅ | Uses hashtables on PS 2.0 |
| **HTML Reports** | ✅ | ✅ | ✅ | ConvertTo-Html universal |
| **PSWriteHTML** | ❌ | ✅ | ✅ | Optional advanced reports |
| **Parallel Scans** | ❌ | ⚠️ | ✅ | Jobs on 5.1, ForEach-Parallel on 7 |

#### Version Detection & Adaptation

```powershell
# Core compatibility module
$script:PSVersion = $PSVersionTable.PSVersion.Major

function Invoke-ADScoutParallel {
    param([scriptblock]$ScriptBlock, [array]$InputObject, [int]$ThrottleLimit = 10)

    switch ($script:PSVersion) {
        { $_ -ge 7 } {
            # PowerShell 7+ - Native ForEach-Object -Parallel
            $InputObject | ForEach-Object -Parallel $ScriptBlock -ThrottleLimit $ThrottleLimit
        }
        { $_ -ge 3 } {
            # PowerShell 3-5 - Runspace pools
            $pool = [RunspaceFactory]::CreateRunspacePool(1, $ThrottleLimit)
            $pool.Open()
            # ... runspace implementation
        }
        default {
            # PowerShell 2 - Sequential with progress
            $i = 0
            foreach ($item in $InputObject) {
                Write-Progress -Activity "Scanning" -PercentComplete (($i++ / $InputObject.Count) * 100)
                & $ScriptBlock $item
            }
        }
    }
}
```

### 3.5 Reporting System

#### Pluggable Reporter Architecture

```powershell
# Register custom reporters
Register-ADScoutReporter -Name "SlackNotify" -ScriptBlock {
    param($Results, $Options)

    $criticalFindings = $Results.Rules | Where-Object Points -ge 50
    if ($criticalFindings) {
        Send-SlackMessage -Channel "#security" -Text "AD Audit found $($criticalFindings.Count) critical issues!"
    }
}

# Use multiple reporters
Invoke-ADScoutScan | Export-ADScoutReport -Reporter HTML, JSON, SlackNotify
```

#### Built-in Reporters

| Reporter | Output | Features |
|----------|--------|----------|
| **HTML** | Static HTML file | PSWriteHTML integration, interactive tables |
| **Dashboard** | Live web server | MScholtes WebServer, real-time updates |
| **JSON** | Structured data | CI/CD integration, API consumption |
| **CSV** | Spreadsheet-ready | Excel import, legacy systems |
| **SARIF** | Security standard | GitHub/Azure DevOps security tab |
| **Markdown** | Documentation | Git-friendly, PR comments |

---

## 4. Community Requests Addressed

Based on analysis of PingCastle GitHub issues and community feedback:

| Request | How ADScout Addresses It |
|---------|-------------------------|
| **API Access** | Native PowerShell objects - IS the API |
| **Scheduled Scanning** | PowerShell + Task Scheduler (trivial) |
| **Impact Reports** | New `-IncludeImpact` shows affected asset counts |
| **AV False Positives** | Scripts don't trigger like compiled EXEs |
| **Integration with Tools** | Pipeline-native, outputs to any format |
| **Multi-Domain Support** | `-Domain` parameter, `-Forest` switch |
| **Continuous Monitoring** | `-WatchMode` for persistent monitoring |
| **Remediation Scripts** | `Get-ADScoutRemediation -RuleId X` outputs runnable scripts |
| **Custom Rules** | First-class citizen, no recompilation |
| **Better Error Handling** | `-ErrorAction`, try/catch, `-Verbose` |
| **Hybrid AD/Azure** | Microsoft.Graph integration planned |

### New Features Not in PingCastle

```powershell
# 1. Differential Scanning - What changed since last scan?
$baseline = Import-ADScoutBaseline -Path "./baseline.json"
Invoke-ADScoutScan -Baseline $baseline | Where-Object IsNew

# 2. Remediation Automation
Get-ADScoutFinding -RuleId "S-PwdNeverExpires" |
    Get-ADScoutRemediation |
    Invoke-ADScoutRemediation -WhatIf  # Safe preview

# 3. Compliance Mapping
Invoke-ADScoutScan -Framework CIS | Format-ADScoutCompliance -Standard "CIS Microsoft Windows Server 2022"

# 4. Impact Analysis
Invoke-ADScoutScan -IncludeImpact | Select-Object RuleId, Points, AffectedUsers, AffectedComputers, BlastRadius

# 5. Attack Path Correlation
Get-ADScoutFinding | Get-ADScoutAttackPath  # What can an attacker do with this?

# 6. Trend Tracking
Get-ADScoutHistory -Days 30 | Show-ADScoutTrend  # Score over time
```

---

## 5. Technical Architecture

### Module Structure

```
ADScout/
├── ADScout.psd1                    # Module manifest
├── ADScout.psm1                    # Module loader
├── Public/                          # Exported functions
│   ├── Invoke-ADScoutScan.ps1
│   ├── New-ADScoutRule.ps1
│   ├── Get-ADScoutRule.ps1
│   ├── Register-ADScoutRule.ps1
│   ├── Export-ADScoutReport.ps1
│   ├── Get-ADScoutRemediation.ps1
│   ├── Import-ADScoutBaseline.ps1
│   ├── Compare-ADScoutBaseline.ps1
│   └── Show-ADScoutDashboard.ps1
├── Private/                         # Internal functions
│   ├── Collectors/
│   │   ├── Get-ADScoutUserData.ps1
│   │   ├── Get-ADScoutComputerData.ps1
│   │   ├── Get-ADScoutGroupData.ps1
│   │   ├── Get-ADScoutTrustData.ps1
│   │   ├── Get-ADScoutGPOData.ps1
│   │   └── Get-ADScoutCertificateData.ps1
│   ├── Scanners/
│   │   ├── Invoke-SMBScan.ps1
│   │   ├── Invoke-NullSessionScan.ps1
│   │   └── Invoke-SpoolerScan.ps1
│   ├── Compatibility/
│   │   ├── Test-PSVersion.ps1
│   │   ├── Get-CimOrWmi.ps1
│   │   └── Invoke-Parallel.ps1
│   └── Helpers/
│       ├── Convert-SidToName.ps1
│       ├── Get-ADScoutCache.ps1
│       └── Write-ADScoutLog.ps1
├── Rules/                           # Built-in rules (189 ported from PingCastle concepts)
│   ├── Anomalies/
│   │   ├── A-AuditDC.ps1
│   │   ├── A-DCRefuseComputerPwdChange.ps1
│   │   └── ...
│   ├── StaleObjects/
│   │   ├── S-PwdLastSet-90.ps1
│   │   ├── S-DC-NotUpdated.ps1
│   │   └── ...
│   ├── PrivilegedAccounts/
│   │   ├── P-Kerberoasting.ps1
│   │   ├── P-DangerousDelegation.ps1
│   │   └── ...
│   └── Trusts/
│       ├── T-SIDFiltering.ps1
│       └── ...
├── Reporters/                       # Output formatters
│   ├── HTMLReporter.ps1
│   ├── JSONReporter.ps1
│   ├── DashboardReporter.ps1
│   └── SARIFReporter.ps1
├── Templates/                       # Report templates
│   ├── report.html
│   ├── dashboard/
│   └── styles.css
├── Libraries/                       # Optional .NET dependencies
│   ├── SMBLibrary.dll              # LGPL-3.0 - Loaded on demand
│   └── RPCForSMBLibrary.dll        # LGPL-3.0 - Loaded on demand
└── en-US/
    └── about_ADScout.help.txt      # Comprehensive help
```

### Data Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                              INVOCATION                                  │
│  Invoke-ADScoutScan -Domain contoso.com -Category Anomalies             │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                           DATA COLLECTION                                │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌─────────────┐  │
│  │ PS Cmdlets   │  │ CIM/WMI      │  │ ADSI/LDAP    │  │ .NET Libs   │  │
│  │ Get-ADUser   │  │ Win32_*      │  │ DirectorySvc │  │ SMBLibrary  │  │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └──────┬──────┘  │
│         └──────────────────┴─────────────────┴─────────────────┘         │
│                                     │                                    │
│                                     ▼                                    │
│                          ┌──────────────────┐                            │
│                          │   $ADData Object │  (Normalized data model)   │
│                          └────────┬─────────┘                            │
└───────────────────────────────────┼─────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                            RULE ENGINE                                   │
│                                                                          │
│   foreach ($Rule in Get-ADScoutRule -Category $Category) {              │
│       $Findings = & $Rule.ScriptBlock -ADData $ADData                   │
│       $Score = Measure-RuleScore -Findings $Findings -Rule $Rule        │
│   }                                                                      │
│                                                                          │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                              RESULTS                                     │
│                                                                          │
│   [PSCustomObject]@{                                                     │
│       Domain        = "contoso.com"                                      │
│       ScanTime      = [datetime]                                         │
│       GlobalScore   = 65                                                 │
│       CategoryScores = @{ Anomalies=35; StaleObjects=45; ... }          │
│       Rules         = @( [RuleResult], [RuleResult], ... )              │
│       RawData       = $ADData  # Optional, for drilling down            │
│   }                                                                      │
│                                                                          │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │
                        ┌────────────┼────────────┐
                        ▼            ▼            ▼
                 ┌──────────┐ ┌──────────┐ ┌──────────┐
                 │ Pipeline │ │  Export  │ │Dashboard │
                 │ Output   │ │  Report  │ │  Live    │
                 └──────────┘ └──────────┘ └──────────┘
```

---

## 6. Considerations & Design Decisions

### Things to Consider

#### Security
- **Credential Handling**: Never store credentials; use `Get-Credential` or Windows auth
- **Execution Policy**: Work within user's policy, don't bypass
- **Least Privilege**: Document minimum required permissions per scan type
- **Output Sanitization**: Don't expose sensitive data in reports by default

#### Performance
- **Lazy Loading**: Don't load SMBLibrary unless SMB scans requested
- **Caching**: Cache expensive queries (schema, forest info) per session
- **Parallelization**: Configurable thread count, respect server limits
- **Incremental**: Support partial scans for large environments

#### Compatibility
- **No Breaking Changes**: Semantic versioning, deprecation warnings
- **Fallback Chains**: Always have a way to get data, even if degraded
- **Offline Mode**: Support analyzing exported data (ntds.dit, LDAP dumps)

#### Usability
- **Verbose by Default**: Progress indicators, `-Verbose` for details
- **Fail Gracefully**: Skip unavailable data sources, continue scanning
- **Helpful Errors**: Not just "Access Denied" but "Try running as Domain Admin"

---

## 7. Licensing Strategy

### Recommendation: MIT License

**Rationale:**

| Factor | MIT Advantage |
|--------|---------------|
| **Simplicity** | One of the most permissive, easy to understand |
| **Adoption** | Maximum adoption potential |
| **Contribution** | No license friction for contributors |
| **Compatibility** | Compatible with LGPL libraries we depend on |
| **Commercial Use** | Allowed (but not your goal) |
| **No Copyleft** | Derivatives don't need to be open source |

### Dependency License Compatibility

| Dependency | License | Compatible with MIT? |
|------------|---------|---------------------|
| SMBLibrary | LGPL-3.0 | ✅ Yes (as separate library) |
| RPCForSMBLibrary | LGPL-3.0 | ✅ Yes (as separate library) |
| PSWriteHTML | MIT | ✅ Yes |
| WebServer (MScholtes) | MIT | ✅ Yes |

**Note:** LGPL libraries can be used by MIT projects as long as they remain as separate DLLs (not statically linked), which is our architecture.

### Alternative: Apache 2.0

If you want patent protection (defensive termination clause):

```
Apache 2.0 Advantages:
- Explicit patent grant
- Contributor license agreement built-in
- Slightly more corporate-friendly for contributors

Apache 2.0 Considerations:
- Requires including NOTICE file
- Slightly more complex than MIT
```

**My Recommendation:** Start with **MIT** for maximum simplicity and adoption. It's the most common license in the PowerShell ecosystem and aligns with community expectations.

---

## 8. Standing on the Shoulders of Giants

### Acknowledgments

ADScout would not be possible without the pioneering work of these projects and individuals:

#### PingCastle
**Author:** Vincent LE TOUX ([@mysmartlogon](https://github.com/vletoux))

> PingCastle established the foundational concepts of Active Directory security scoring, risk categorization, and the rule-based assessment model. Its comprehensive rule library (189 rules) represents years of security research and real-world assessment experience. We are deeply grateful for this work being made available to the security community.

**What we learned:** Risk scoring model, rule categorization (Anomalies/StaleObjects/PrivilegedAccounts/Trusts), framework mappings (MITRE/ANSSI/STIG).

**How we differ:** PowerShell-native, community-extensible rules, no compilation required.

#### BloodHound / SharpHound
**Authors:** SpecterOps team ([@SpecterOps](https://github.com/SpecterOps))

> BloodHound revolutionized understanding of Active Directory attack paths through graph theory. SharpHound's data collection techniques, particularly for SAMR enumeration, represent state-of-the-art in AD reconnaissance.

**What we learned:** SAMR implementation patterns, local group enumeration techniques.

**How we differ:** Focus on security posture vs. attack paths, PowerShell vs. compiled C#.

#### SMBLibrary
**Author:** Tal Aloni ([@TalAloni](https://github.com/TalAloni))

> A complete, open-source SMB 1.0/2.0/2.1/3.0 implementation in C#, enabling protocol-level inspection without Windows API dependencies.

**License:** LGPL-3.0 (used as optional external library)

#### RPCForSMBLibrary
**Author:** Vincent LE TOUX ([@vletoux](https://github.com/vletoux))

> Extension of SMBLibrary providing LSA, NetLogon, and EFS RPC implementations.

**License:** LGPL-3.0 (used as optional external library)

#### ADRecon
**Author:** Prashant Mahajan ([@adrecon](https://github.com/adrecon))

> Demonstrated the viability of comprehensive AD data collection in pure PowerShell, proving that effective security tooling doesn't require compiled code.

#### PSWriteHTML
**Author:** Evotec ([@EvotecIT](https://github.com/EvotecIT))

> Proved that beautiful, interactive HTML reports can be generated entirely from PowerShell, democratizing professional-quality reporting.

#### PowerView / PowerSploit
**Authors:** Will Schroeder, Matt Graeber, and the PowerSploit team

> Pioneered offensive PowerShell for Active Directory, demonstrating what's possible with pure PowerShell AD interaction.

#### DSInternals
**Author:** Michael Grafnetter ([@MichaelGrafnetter](https://github.com/MichaelGrafnetter))

> Showed that deep AD internals (ntds.dit parsing, password auditing, DCSync) can be exposed through PowerShell.

#### WebServer Module
**Author:** Markus Scholtes ([@MScholtes](https://github.com/MScholtes))

> Created a functional PowerShell web server enabling live dashboards without IIS or external dependencies.

---

### This Is a Different Project

While we deeply appreciate and acknowledge these contributions, **ADScout is an independent project** with:

- **Different goals**: PowerShell-native experience over compiled performance
- **Different architecture**: Scriptblock-based rules over C# classes
- **Different philosophy**: Community-first, contribution-friendly design
- **Different licensing**: MIT (vs. OSL 3.0, Apache 2.0, etc.)
- **Different target audience**: PowerShell administrators, DevOps engineers, blue teamers

We are not a fork, port, or derivative work. We are a new tool that applies lessons learned from these giants to create something that fills a different niche in the AD security ecosystem.

---

## 9. Roadmap

### Phase 1: Foundation (MVP)
- [ ] Core module structure
- [ ] Rule engine with scriptblock support
- [ ] 50 essential rules ported (highest-impact from PingCastle concepts)
- [ ] Basic HTML reporting (ConvertTo-Html + CSS)
- [ ] PowerShell 5.1 support
- [ ] Tab completion for all parameters

### Phase 2: Parity
- [ ] All 189 rules implemented
- [ ] PSWriteHTML integration
- [ ] PowerShell 7.x support
- [ ] Parallel scanning
- [ ] JSON/SARIF export
- [ ] Remediation script generation

### Phase 3: Innovation
- [ ] Differential scanning / baselines
- [ ] Live dashboard (MScholtes WebServer)
- [ ] Microsoft Graph integration (Entra ID)
- [ ] Community rule gallery
- [ ] PowerShell 2.0 compatibility layer
- [ ] Impact analysis

### Phase 4: Ecosystem
- [ ] VS Code extension
- [ ] GitHub Actions integration
- [ ] Azure DevOps tasks
- [ ] Ansible/Puppet modules
- [ ] Documentation site

---

## 10. Getting Started (Preview)

```powershell
# Install from PowerShell Gallery (future)
Install-Module ADScout -Scope CurrentUser

# Quick scan
Invoke-ADScoutScan | Format-Table RuleId, Points, Description

# Full scan with HTML report
Invoke-ADScoutScan -Full | Export-ADScoutReport -Format HTML -Path "./ADSecurityReport.html"

# Interactive exploration
Show-Command Invoke-ADScoutScan  # GUI for parameter discovery

# Add custom rule
New-ADScoutRule -Id "CUSTOM-001" -Name "My Custom Check" -Category Anomalies -ScriptBlock {
    param($ADData)
    $ADData.Users | Where-Object { $_.Description -match "password" }
} | Register-ADScoutRule

# Run with custom rules
Invoke-ADScoutScan -IncludeCustomRules
```

---

## Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 0.1 | 2024-XX-XX | [Your Name] | Initial design document |

---

*"In the world of security, sharing knowledge is not a weakness—it's our greatest strength."*
