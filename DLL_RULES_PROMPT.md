# AD-Scout DLL-Dependent Detection Rules Prompt

> Use this prompt to create rules that leverage external .NET libraries (SMBLibrary, RPCForSMBLibrary) for protocol-level detection that PowerShell cannot perform natively.

---

## Prompt for Claude / AI Assistant

```
# Project: AD-Scout DLL-Dependent Detection Rules

## Context

You are developing detection rules for AD-Scout that require external .NET DLL libraries to perform protocol-level security checks. These rules detect configurations and vulnerabilities that cannot be assessed using native PowerShell cmdlets because they require:

1. **Raw SMB protocol negotiation** - Testing specific SMB dialects and signing modes
2. **RPC protocol access** - SAMR, LSA, Netlogon, EFSRPC without authentication
3. **Low-level network probing** - Null session testing, coercion attacks
4. **Protocol capability detection** - NTLM relay conditions, channel binding

## External Libraries Used

### SMBLibrary (LGPL-3.0)
- **Source**: https://github.com/TalAloni/SMBLibrary
- **Purpose**: SMB 1.0/2.0/2.1/3.0/3.1.1 client implementation
- **Capabilities**: Dialect negotiation, signing detection, share enumeration

### RPCForSMBLibrary (LGPL-3.0)
- **Source**: https://github.com/vletoux/RPCForSMBLibrary
- **Purpose**: RPC over SMB for LSA, Netlogon, EFS
- **Capabilities**: Policy queries, trust enumeration, coercion testing

### Loading Pattern

```powershell
# DLLs are loaded on-demand, not at module import
function Initialize-ADScoutSMBLibrary {
    [CmdletBinding()]
    param()

    $dllPath = Join-Path $PSScriptRoot "../../Libraries"

    if (-not $script:SMBLibraryLoaded) {
        $smbLib = Join-Path $dllPath "SMBLibrary.dll"
        $rpcLib = Join-Path $dllPath "RPCForSMBLibrary.dll"

        if (Test-Path $smbLib) {
            Add-Type -Path $smbLib
            Add-Type -Path $rpcLib -ErrorAction SilentlyContinue
            $script:SMBLibraryLoaded = $true
            Write-Verbose "SMBLibrary loaded successfully"
        }
        else {
            Write-Warning "SMBLibrary not found. Some scanners will be unavailable."
            Write-Warning "Download from: https://github.com/TalAloni/SMBLibrary"
            return $false
        }
    }
    return $true
}
```

---

## DLL SCANNER ARCHITECTURE

```
src/ADScout/
├── Private/
│   └── Scanners/                    # DLL-dependent scanners
│       ├── Initialize-ADScoutSMBLibrary.ps1
│       ├── Invoke-SMBDialectScan.ps1
│       ├── Invoke-SMBSigningScan.ps1
│       ├── Invoke-NullSessionScan.ps1
│       ├── Invoke-SpoolerScan.ps1
│       ├── Invoke-PetitPotamScan.ps1
│       ├── Invoke-CoercionScan.ps1
│       ├── Invoke-LDAPSigningScan.ps1
│       └── Invoke-ZerologonScan.ps1
├── Libraries/                        # External DLLs (LGPL-3.0)
│   ├── SMBLibrary.dll
│   ├── RPCForSMBLibrary.dll
│   └── NOTICE.md                     # License attribution
└── Rules/
    └── DLLRequired/                  # Rules requiring DLLs
        ├── SMB/
        ├── RPC/
        └── Coercion/
```

---

## SCANNER TEMPLATE

```powershell
<#
.SYNOPSIS
    [Scanner description]

.DESCRIPTION
    This scanner requires SMBLibrary.dll to perform protocol-level detection.
    It will gracefully skip if the library is not available.

.NOTES
    Scanner    : [Name]
    Requires   : SMBLibrary.dll, RPCForSMBLibrary.dll
    Author     : AD-Scout Contributors
#>

function Invoke-[ScannerName] {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName,

        [Parameter()]
        [int]$Port = 445,

        [Parameter()]
        [int]$TimeoutMs = 5000,

        [Parameter()]
        [PSCredential]$Credential
    )

    # Verify DLL availability
    if (-not (Initialize-ADScoutSMBLibrary)) {
        Write-Warning "Skipping $($MyInvocation.MyCommand.Name): SMBLibrary not available"
        return [PSCustomObject]@{
            ComputerName = $ComputerName
            Status = "Skipped"
            Reason = "SMBLibrary not loaded"
        }
    }

    try {
        # Create SMB client
        $client = [SMBLibrary.Client.SMB2Client]::new()
        $connected = $client.Connect($ComputerName, [SMBLibrary.SMBTransportType]::DirectTCPTransport)

        if (-not $connected) {
            return [PSCustomObject]@{
                ComputerName = $ComputerName
                Status = "ConnectionFailed"
                Error = "Could not connect to $ComputerName:$Port"
            }
        }

        # Perform protocol-specific checks
        # ... scanner logic here ...

        $client.Disconnect()

        return [PSCustomObject]@{
            ComputerName = $ComputerName
            Status = "Success"
            # ... results ...
        }
    }
    catch {
        return [PSCustomObject]@{
            ComputerName = $ComputerName
            Status = "Error"
            Error = $_.Exception.Message
        }
    }
}
```

---

## DLL-REQUIRED RULE TEMPLATE

```powershell
<#
.SYNOPSIS
    [Rule description]

.DESCRIPTION
    This rule requires external DLL libraries for protocol-level detection.
    If libraries are unavailable, the rule will be skipped gracefully.

.NOTES
    Rule ID    : DLL-[Category]-[Name]
    Category   : [Category]
    Requires   : SMBLibrary.dll
    Author     : AD-Scout Contributors
#>

@{
    # === IDENTITY ===
    Id          = "DLL-SMB-SigningNotRequired"
    Name        = "SMB Signing Not Required"
    Category    = "Anomalies"
    Model       = "NetworkSecurity"
    Version     = "1.0.0"

    # === DLL REQUIREMENTS ===
    RequiresDLL = $true
    DLLNames    = @("SMBLibrary.dll")
    FallbackBehavior = "Skip"  # Skip | Warn | Error

    # === SCORING ===
    Computation = "PerDiscover"
    Points      = 10
    MaxPoints   = 100
    Severity    = "High"

    # === FRAMEWORK MAPPINGS ===
    MITRE       = @("T1557.001")  # LLMNR/NBT-NS Poisoning
    CIS         = @("9.2.1")
    STIG        = @("V-73623")
    ANSSI       = @("R29")

    # === THE CHECK ===
    ScriptBlock = {
        param([Parameter(Mandatory)][hashtable]$ADData)

        # This rule requires DLL scanning of each DC
        $results = foreach ($dc in $ADData.DomainControllers) {
            $scanResult = Invoke-SMBSigningScan -ComputerName $dc.DNSHostName -TimeoutMs 5000

            if ($scanResult.Status -eq "Success" -and
                -not $scanResult.SigningRequired) {
                [PSCustomObject]@{
                    ComputerName = $dc.DNSHostName
                    IPAddress = $dc.IPAddress
                    SMBVersion = $scanResult.NegotiatedDialect
                    SigningEnabled = $scanResult.SigningEnabled
                    SigningRequired = $scanResult.SigningRequired
                }
            }
        }

        $results
    }

    # === OUTPUT ===
    DetailProperties = @("ComputerName", "SMBVersion", "SigningEnabled", "SigningRequired")

    # === REMEDIATION ===
    Remediation = {
        param($Finding)
        @"
# Enable SMB Signing on $($Finding.ComputerName)

# Via Group Policy (Recommended):
# Computer Configuration > Policies > Windows Settings > Security Settings >
# Local Policies > Security Options >
#   "Microsoft network server: Digitally sign communications (always)" = Enabled
#   "Microsoft network client: Digitally sign communications (always)" = Enabled

# Via PowerShell (immediate):
Set-SmbServerConfiguration -RequireSecuritySignature `$true -Force

# Via Registry:
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -Value 1 -Type DWord
"@
    }

    # === DOCUMENTATION ===
    Description = "Domain controllers with SMB signing not required are vulnerable to man-in-the-middle attacks."

    TechnicalExplanation = @"
SMB signing provides message integrity for SMB communications. When signing is not
required, attackers can:

1. Intercept SMB traffic between clients and servers
2. Modify SMB packets in transit (MITM)
3. Perform NTLM relay attacks to authenticate as the victim
4. Potentially gain unauthorized access to resources

This check uses SMBLibrary to perform actual SMB protocol negotiation and verify
the signing requirements at the protocol level, not just registry settings.
"@

    References = @(
        "https://attack.mitre.org/techniques/T1557/001/"
        "https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/microsoft-network-server-digitally-sign-communications-always"
    )
}
```

---

## MASTER DLL SCANNER/RULE CHECKLIST

Generate scanners and rules for ALL of the following protocol-level checks:

---

### SMB PROTOCOL SCANNERS

#### SMB Version Detection
- [ ] `Invoke-SMBDialectScan` - Detect supported SMB versions per host
  - SMB 1.0 (NT LM 0.12)
  - SMB 2.0.2
  - SMB 2.1
  - SMB 3.0
  - SMB 3.0.2
  - SMB 3.1.1

#### SMB Signing Detection
- [ ] `Invoke-SMBSigningScan` - Protocol-level signing verification
  - Signing enabled (advertised)
  - Signing required (enforced)
  - Per-dialect signing capabilities

#### SMB Security Features
- [ ] `Invoke-SMBEncryptionScan` - SMB 3.x encryption support
  - AES-128-CCM support
  - AES-128-GCM support
  - AES-256-CCM support (3.1.1)
  - AES-256-GCM support (3.1.1)
- [ ] `Invoke-SMBCompressionScan` - SMB 3.1.1 compression (CVE-2020-0796 related)

#### SMB Share Enumeration
- [ ] `Invoke-SMBShareScan` - Enumerate accessible shares
  - Null session share access
  - Anonymous share listing
  - Sensitive share detection (C$, ADMIN$, SYSVOL)

#### SMB Null Session
- [ ] `Invoke-SMBNullSessionScan` - Test null session capabilities
  - Anonymous IPC$ access
  - Anonymous share enumeration
  - Anonymous user enumeration

---

### RPC PROTOCOL SCANNERS

#### SAMR (Security Account Manager Remote)
- [ ] `Invoke-SAMRScan` - SAM enumeration capabilities
  - Anonymous user enumeration
  - Anonymous group enumeration
  - Password policy retrieval
  - Domain SID enumeration

#### LSA (Local Security Authority)
- [ ] `Invoke-LSAScan` - LSA policy queries
  - Domain information
  - Trust relationships
  - SID-to-name resolution
  - Anonymous access testing

#### Netlogon
- [ ] `Invoke-NetlogonScan` - Netlogon service checks
  - Trust enumeration
  - Zerologon vulnerability (CVE-2020-1472)
  - Secure channel status

#### Print Spooler (MS-RPRN)
- [ ] `Invoke-SpoolerScan` - Print Spooler accessibility
  - Spooler service reachable
  - PrinterBug exploitability (for coercion)

#### EFSRPC (Encrypting File System)
- [ ] `Invoke-EFSRPCScan` - EFS RPC accessibility
  - PetitPotam vulnerability
  - EfsRpcOpenFileRaw accessibility
  - Coercion potential

#### DFSNM (DFS Namespace Management)
- [ ] `Invoke-DFSCoerceScan` - DFS coercion testing
  - NetrDfsRemoveStdRoot accessibility
  - DFSCoerce vulnerability

---

### COERCION ATTACK SCANNERS

- [ ] `Invoke-CoercionScan` - Comprehensive coercion testing
  - PrinterBug (MS-RPRN)
  - PetitPotam (MS-EFSRPC)
  - DFSCoerce (MS-DFSNM)
  - ShadowCoerce (MS-FSRVP)
  - CheeseOunce (MS-EVEN)

---

### LDAP PROTOCOL SCANNERS

#### LDAP Signing and Binding
- [ ] `Invoke-LDAPSigningScan` - LDAP security verification
  - LDAP signing required
  - LDAP channel binding (Windows Server 2020+)
  - Simple bind without TLS

#### LDAPS Configuration
- [ ] `Invoke-LDAPSScan` - LDAPS availability and security
  - LDAPS (port 636) availability
  - Certificate validity
  - TLS version support
  - Cipher suite strength

---

### VULNERABILITY SCANNERS

#### Zerologon (CVE-2020-1472)
- [ ] `Invoke-ZerologonScan` - Safe Zerologon detection
  - Tests authentication with null credentials
  - Does NOT exploit (safe check only)
  - Verifies patch status

#### MS17-010 (EternalBlue)
- [ ] `Invoke-EternalBlueScan` - SMBv1 vulnerability check
  - Transaction2 request detection
  - Safe detection (no exploit)

#### SMBGhost (CVE-2020-0796)
- [ ] `Invoke-SMBGhostScan` - SMB 3.1.1 compression vulnerability
  - Compression capability detection
  - Safe check only

---

## DLL-REQUIRED RULES

Generate complete rules that use the above scanners:

### SMB Rules (DLL-SMB-*)
- [ ] `DLL-SMB-v1Enabled` - SMBv1 protocol enabled on DCs
- [ ] `DLL-SMB-SigningNotEnabled` - SMB signing not advertised
- [ ] `DLL-SMB-SigningNotRequired` - SMB signing not enforced
- [ ] `DLL-SMB-EncryptionNotSupported` - SMB3 encryption unavailable
- [ ] `DLL-SMB-NullSessionAllowed` - Null session access permitted
- [ ] `DLL-SMB-AnonymousShares` - Anonymous share enumeration possible
- [ ] `DLL-SMB-WeakDialect` - Only weak SMB dialects supported
- [ ] `DLL-SMB-GuestFallback` - Guest authentication fallback enabled

### RPC Rules (DLL-RPC-*)
- [ ] `DLL-RPC-SAMRAnonymous` - Anonymous SAMR enumeration allowed
- [ ] `DLL-RPC-LSAAnonymous` - Anonymous LSA queries allowed
- [ ] `DLL-RPC-NetlogonInsecure` - Insecure Netlogon configuration
- [ ] `DLL-RPC-SpoolerExposed` - Print Spooler remotely accessible on DCs
- [ ] `DLL-RPC-EFSRPCExposed` - EFSRPC accessible (PetitPotam)
- [ ] `DLL-RPC-DFSNMExposed` - DFSNM accessible (DFSCoerce)

### Coercion Rules (DLL-COERCE-*)
- [ ] `DLL-COERCE-PrinterBug` - PrinterBug exploitable
- [ ] `DLL-COERCE-PetitPotam` - PetitPotam exploitable
- [ ] `DLL-COERCE-DFSCoerce` - DFSCoerce exploitable
- [ ] `DLL-COERCE-ShadowCoerce` - ShadowCoerce exploitable
- [ ] `DLL-COERCE-MultiVector` - Multiple coercion vectors available

### LDAP Rules (DLL-LDAP-*)
- [ ] `DLL-LDAP-SigningNotRequired` - LDAP signing not enforced
- [ ] `DLL-LDAP-ChannelBindingDisabled` - Channel binding not enabled
- [ ] `DLL-LDAP-SimpleBind` - Simple bind without TLS allowed
- [ ] `DLL-LDAP-WeakCiphers` - Weak TLS ciphers on LDAPS
- [ ] `DLL-LDAP-ExpiredCert` - LDAPS certificate expired

### Vulnerability Rules (DLL-VULN-*)
- [ ] `DLL-VULN-Zerologon` - CVE-2020-1472 vulnerable
- [ ] `DLL-VULN-EternalBlue` - MS17-010 vulnerable
- [ ] `DLL-VULN-SMBGhost` - CVE-2020-0796 vulnerable
- [ ] `DLL-VULN-PrintNightmare` - Print Spooler RCE conditions

---

## SCANNER IMPLEMENTATION DETAILS

### Invoke-SMBSigningScan Implementation

```powershell
function Invoke-SMBSigningScan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias("DNSHostName", "Name")]
        [string]$ComputerName,

        [Parameter()]
        [int]$TimeoutMs = 5000
    )

    process {
        if (-not (Initialize-ADScoutSMBLibrary)) {
            return [PSCustomObject]@{
                ComputerName = $ComputerName
                Status = "Skipped"
                Reason = "SMBLibrary not available"
            }
        }

        try {
            $client = [SMBLibrary.Client.SMB2Client]::new()

            # Connect using DirectTCP (port 445)
            $connected = $client.Connect(
                [System.Net.IPAddress]::Parse((Resolve-DnsName $ComputerName -Type A).IPAddress),
                [SMBLibrary.SMBTransportType]::DirectTCPTransport
            )

            if (-not $connected) {
                return [PSCustomObject]@{
                    ComputerName = $ComputerName
                    Status = "ConnectionFailed"
                }
            }

            # Test each dialect
            $dialects = @(
                [SMBLibrary.SMB2Dialect]::SMB202,
                [SMBLibrary.SMB2Dialect]::SMB210,
                [SMBLibrary.SMB2Dialect]::SMB300,
                [SMBLibrary.SMB2Dialect]::SMB302,
                [SMBLibrary.SMB2Dialect]::SMB311
            )

            $results = foreach ($dialect in $dialects) {
                try {
                    # Negotiate with specific dialect
                    $negotiateResult = $client.Negotiate($dialect)

                    if ($negotiateResult -eq [SMBLibrary.NTStatus]::STATUS_SUCCESS) {
                        [PSCustomObject]@{
                            Dialect = $dialect.ToString()
                            Supported = $true
                            SigningEnabled = $client.SecurityMode -band [SMBLibrary.SMB2.SecurityMode]::SigningEnabled
                            SigningRequired = $client.SecurityMode -band [SMBLibrary.SMB2.SecurityMode]::SigningRequired
                        }
                    }
                }
                catch {
                    # Dialect not supported
                }
            }

            $client.Disconnect()

            # Determine overall security posture
            $bestDialect = $results | Sort-Object { $_.Dialect } -Descending | Select-Object -First 1

            return [PSCustomObject]@{
                ComputerName = $ComputerName
                Status = "Success"
                NegotiatedDialect = $bestDialect.Dialect
                SigningEnabled = $bestDialect.SigningEnabled
                SigningRequired = $bestDialect.SigningRequired
                AllDialects = $results
                Vulnerable = (-not $bestDialect.SigningRequired)
            }
        }
        catch {
            return [PSCustomObject]@{
                ComputerName = $ComputerName
                Status = "Error"
                Error = $_.Exception.Message
            }
        }
    }
}
```

### Invoke-NullSessionScan Implementation

```powershell
function Invoke-NullSessionScan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]$ComputerName,

        [Parameter()]
        [int]$TimeoutMs = 5000
    )

    process {
        if (-not (Initialize-ADScoutSMBLibrary)) {
            return [PSCustomObject]@{
                ComputerName = $ComputerName
                Status = "Skipped"
            }
        }

        $results = @{
            ComputerName = $ComputerName
            Status = "Success"
            NullSessionIPC = $false
            AnonymousUserEnum = $false
            AnonymousGroupEnum = $false
            AnonymousShareEnum = $false
        }

        try {
            $client = [SMBLibrary.Client.SMB2Client]::new()
            $connected = $client.Connect($ComputerName, [SMBLibrary.SMBTransportType]::DirectTCPTransport)

            if ($connected) {
                # Try anonymous login
                $loginStatus = $client.Login("", "", "")  # Empty credentials

                if ($loginStatus -eq [SMBLibrary.NTStatus]::STATUS_SUCCESS) {
                    $results.NullSessionIPC = $true

                    # Try to connect to IPC$
                    $ipcStatus = $client.TreeConnect("\\$ComputerName\IPC$", [ref]$null)

                    if ($ipcStatus -eq [SMBLibrary.NTStatus]::STATUS_SUCCESS) {
                        # Try SAMR enumeration via RPC
                        # This would use RPCForSMBLibrary
                        $results.AnonymousUserEnum = Test-SAMRAnonymous -Client $client
                        $results.AnonymousGroupEnum = Test-SAMRGroupAnonymous -Client $client
                    }

                    # Try share enumeration
                    $shares = $client.ListShares([ref]$null)
                    if ($shares) {
                        $results.AnonymousShareEnum = $true
                        $results.Shares = $shares
                    }
                }

                $client.Disconnect()
            }

            $results.Vulnerable = $results.NullSessionIPC -or
                                  $results.AnonymousUserEnum -or
                                  $results.AnonymousShareEnum
        }
        catch {
            $results.Status = "Error"
            $results.Error = $_.Exception.Message
        }

        [PSCustomObject]$results
    }
}
```

### Invoke-PetitPotamScan Implementation

```powershell
function Invoke-PetitPotamScan {
    <#
    .SYNOPSIS
        Tests for PetitPotam (CVE-2021-36942) vulnerability.

    .DESCRIPTION
        Safely tests if EFSRPC is accessible and vulnerable to PetitPotam coercion.
        Does NOT trigger actual coercion - only tests accessibility.

    .NOTES
        This is a SAFE detection check. It does not trigger authentication coercion.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]$ComputerName,

        [Parameter()]
        [int]$TimeoutMs = 5000
    )

    process {
        if (-not (Initialize-ADScoutSMBLibrary)) {
            return [PSCustomObject]@{
                ComputerName = $ComputerName
                Status = "Skipped"
            }
        }

        $result = @{
            ComputerName = $ComputerName
            Status = "Success"
            EFSRPCAccessible = $false
            NamedPipeAccessible = $false
            Vulnerable = $false
        }

        try {
            $client = [SMBLibrary.Client.SMB2Client]::new()
            $connected = $client.Connect($ComputerName, [SMBLibrary.SMBTransportType]::DirectTCPTransport)

            if ($connected) {
                # Login (try anonymous first, then null session)
                $loginStatus = $client.Login("", "", "")

                if ($loginStatus -eq [SMBLibrary.NTStatus]::STATUS_SUCCESS) {
                    # Connect to IPC$
                    $treeId = $null
                    $treeStatus = $client.TreeConnect("\\$ComputerName\IPC$", [ref]$treeId)

                    if ($treeStatus -eq [SMBLibrary.NTStatus]::STATUS_SUCCESS) {
                        # Try to open EFSRPC named pipes
                        $efsrpcPipes = @(
                            "\PIPE\efsrpc",
                            "\PIPE\lsarpc",      # Alternative path
                            "\PIPE\samr",        # Alternative path
                            "\PIPE\netlogon"     # Alternative path
                        )

                        foreach ($pipe in $efsrpcPipes) {
                            try {
                                $fileHandle = $null
                                $openStatus = $client.CreateFile(
                                    $pipe,
                                    [SMBLibrary.AccessMask]::GENERIC_READ -bor [SMBLibrary.AccessMask]::GENERIC_WRITE,
                                    [SMBLibrary.FileAttributes]::Normal,
                                    [SMBLibrary.ShareAccess]::Read -bor [SMBLibrary.ShareAccess]::Write,
                                    [SMBLibrary.CreateDisposition]::FILE_OPEN,
                                    [SMBLibrary.CreateOptions]::FILE_NON_DIRECTORY_FILE,
                                    [ref]$fileHandle
                                )

                                if ($openStatus -eq [SMBLibrary.NTStatus]::STATUS_SUCCESS) {
                                    $result.NamedPipeAccessible = $true
                                    $result.AccessiblePipe = $pipe

                                    # For EFSRPC specifically
                                    if ($pipe -eq "\PIPE\efsrpc") {
                                        $result.EFSRPCAccessible = $true
                                        $result.Vulnerable = $true
                                    }

                                    $client.CloseFile($fileHandle)
                                    break
                                }
                            }
                            catch {
                                # Pipe not accessible
                            }
                        }
                    }
                }

                $client.Disconnect()
            }
        }
        catch {
            $result.Status = "Error"
            $result.Error = $_.Exception.Message
        }

        [PSCustomObject]$result
    }
}
```

---

## GRACEFUL DEGRADATION

When DLLs are not available, rules should:

1. **Skip gracefully** - Don't crash, return "Skipped" status
2. **Log warning** - Inform user of missing capability
3. **Suggest action** - Tell user how to get the DLLs
4. **Continue scanning** - Don't block other rules

```powershell
# In rule ScriptBlock
if (-not (Initialize-ADScoutSMBLibrary)) {
    Write-Warning "SMB scanning unavailable. Install SMBLibrary for full coverage."
    Write-Warning "Download: https://github.com/TalAloni/SMBLibrary/releases"

    # Return empty results, not error
    return @()
}
```

---

## LIBRARY NOTICE FILE

Create `src/ADScout/Libraries/NOTICE.md`:

```markdown
# Third-Party Library Notices

## SMBLibrary

**License**: LGPL-3.0-or-later
**Source**: https://github.com/TalAloni/SMBLibrary
**Copyright**: (c) Tal Aloni 2014-2025

SMBLibrary is used for SMB protocol-level security scanning.
It is distributed as a separate DLL in compliance with LGPL requirements.

## RPCForSMBLibrary

**License**: LGPL-3.0
**Source**: https://github.com/vletoux/RPCForSMBLibrary
**Copyright**: (c) Vincent LE TOUX

RPCForSMBLibrary extends SMBLibrary with RPC protocol support.
It is distributed as a separate DLL in compliance with LGPL requirements.

---

These libraries are optional. AD-Scout functions without them but with
reduced protocol-level detection capabilities.

To use these libraries:
1. Download from the source repositories above
2. Place DLLs in this directory
3. Restart PowerShell session

AD-Scout will automatically load them when needed.
```

---

## GENERATION INSTRUCTIONS

1. Generate all scanner functions first (they're reusable)
2. Generate rules that use the scanners
3. Each scanner should be fully functional with SMBLibrary
4. Include proper error handling and timeouts
5. Add pipeline support for bulk scanning
6. Include progress reporting for long scans
7. Test with actual SMBLibrary if possible

## DATA FLOW

```
Rule ScriptBlock
    │
    ├── Check: Initialize-ADScoutSMBLibrary
    │   ├── Success: Continue
    │   └── Fail: Return empty, log warning
    │
    ├── For each DC in $ADData.DomainControllers
    │   └── Invoke-[Scanner] -ComputerName $dc.DNSHostName
    │       ├── Connect via SMBLibrary
    │       ├── Perform protocol check
    │       ├── Return structured result
    │       └── Handle errors gracefully
    │
    └── Filter results for violations
        └── Return findings to rule engine
```

Begin generating scanners and rules now.
```

---

## How to Use This Prompt

1. Start Claude session in `ad-scout/src/ADScout/Private/Scanners/`
2. Paste this prompt
3. Request:
   - "Generate all SMB scanners"
   - "Generate all coercion scanners"
   - "Generate the DLL-required rules"
4. Test with actual SMBLibrary DLL

## Priority Order

1. **Invoke-SMBSigningScan** - Most commonly needed
2. **Invoke-NullSessionScan** - Common vulnerability
3. **Invoke-PetitPotamScan** - Modern attack vector
4. **Invoke-SpoolerScan** - PrintNightmare prerequisite
5. **Invoke-ZerologonScan** - Critical vulnerability
6. **Invoke-CoercionScan** - Comprehensive coercion check
