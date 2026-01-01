# AD-Scout Rules Generation Prompt

> Use this prompt to generate, migrate, and expand the AD-Scout rule library.

---

## Prompt for Claude / AI Assistant

```
# Project: AD-Scout Rules Library Development

## Context

You are developing the rules library for AD-Scout, a PowerShell-native Active Directory security assessment framework. Your task is to create comprehensive security rules that detect misconfigurations, vulnerabilities, and attack vectors in Active Directory environments.

## Rule File Format

Each rule is a single `.ps1` file containing a hashtable with a scriptblock. Place rules in the appropriate category folder:

```
src/ADScout/Rules/
├── Anomalies/           # Configuration issues, security weaknesses
├── StaleObjects/        # Obsolete, inactive, outdated items
├── PrivilegedAccounts/  # Admin rights, delegation, permissions
├── Trusts/              # Domain/forest trust issues
├── Certificates/        # ADCS, PKI, certificate vulnerabilities (NEW)
├── Kerberos/            # Kerberos-specific attacks (NEW)
├── Authentication/      # Password, NTLM, credential issues (NEW)
└── Infrastructure/      # DC health, replication, services (NEW)
```

## Rule Template

```powershell
<#
.SYNOPSIS
    [One-line description]

.DESCRIPTION
    [Detailed security explanation]

.NOTES
    Rule ID    : [CAT]-[Name]
    Category   : [Category]
    Author     : AD-Scout Contributors
    Version    : 1.0.0
#>

@{
    # === IDENTITY ===
    Id          = "X-RuleName"
    Name        = "Human Readable Name"
    Category    = "Category"
    Model       = "SubCategory"
    Version     = "1.0.0"

    # === SCORING ===
    Computation = "PerDiscover"     # TriggerOnPresence | PerDiscover | TriggerOnThreshold | TriggerIfLessThan
    Points      = 5
    MaxPoints   = 100
    Severity    = "High"            # Critical | High | Medium | Low | Informational

    # === FRAMEWORK MAPPINGS ===
    MITRE       = @("T1078.002")    # ATT&CK Technique IDs
    CIS         = @("5.1.2")        # CIS Control IDs
    STIG        = @("V-8527")       # DISA STIG IDs
    ANSSI       = @("R36")          # ANSSI Recommendation IDs

    # === THE CHECK ===
    ScriptBlock = {
        param([Parameter(Mandatory)][hashtable]$ADData)

        # Return objects that VIOLATE the rule
        # These become finding details
        $ADData.Users | Where-Object {
            # Condition that identifies the security issue
        } | Select-Object SamAccountName, DistinguishedName
    }

    # === OUTPUT ===
    DetailProperties = @("SamAccountName", "DistinguishedName")

    # === REMEDIATION ===
    Remediation = {
        param($Finding)
        "# Remediation for $($Finding.SamAccountName)`nSet-ADUser -Identity '$($Finding.SamAccountName)' -PasswordNeverExpires `$false"
    }

    # === DOCUMENTATION ===
    Description = "Brief description for reports."
    TechnicalExplanation = "Detailed explanation of the vulnerability and attack vector."
    References = @("https://attack.mitre.org/...")
}
```

---

## MASTER RULE CHECKLIST

Generate rules for ALL of the following security checks. Each rule should be complete with proper scoring, framework mappings, and remediation guidance.

---

### CATEGORY: Anomalies (A-*)

#### Domain Controller Configuration
- [ ] A-AuditDC - Audit policies not configured on DCs
- [ ] A-AuditPolicyNotConfigured - Advanced audit policy gaps
- [ ] A-DCRefuseComputerPwdChange - DC refusing computer password changes
- [ ] A-DCRegistration - Improper DC DNS registration
- [ ] A-DCLdapSign - LDAP signing not required
- [ ] A-DCLdapChannelBinding - LDAP channel binding not enforced (2025+)
- [ ] A-DCBackupNotRecent - DC not backed up recently
- [ ] A-DCNtdsLocationDefault - NTDS.dit in default location
- [ ] A-DCSysvolLocationDefault - SYSVOL in default location

#### SMB/Network Configuration
- [ ] A-SMB1Enabled - SMBv1 protocol enabled
- [ ] A-SMB2SignatureNotEnabled - SMB signing not enabled
- [ ] A-SMB2SignatureNotRequired - SMB signing not required
- [ ] A-SMBNullSession - Null sessions allowed
- [ ] A-NetbiosEnabled - NetBIOS over TCP/IP enabled
- [ ] A-LLMNREnabled - LLMNR enabled (poisoning risk)
- [ ] A-mDNSEnabled - mDNS enabled
- [ ] A-WPADEnabled - WPAD enabled (proxy autodiscovery)
- [ ] A-WSUSHttpEnabled - WSUS using HTTP (not HTTPS)
- [ ] A-IPv6Enabled - IPv6 enabled without controls

#### DNS Security
- [ ] A-DnsZoneTransfer - Unrestricted DNS zone transfers
- [ ] A-DnsUnsecureUpdate - DNS allows unsecure dynamic updates
- [ ] A-DnsAdmin - Non-privileged users in DnsAdmins group
- [ ] A-DnsZoneNoRefresh - DNS scavenging not configured

#### Logging and Monitoring
- [ ] A-EventLogSizeInsufficient - Security log size too small
- [ ] A-EventLogRetentionInsufficient - Log retention too short
- [ ] A-NoEventForwarding - No centralized event forwarding
- [ ] A-CriticalAuditMissing - Missing critical audit categories
- [ ] A-ObjectAuditingDisabled - Object auditing not enabled

#### Print Spooler (PrintNightmare)
- [ ] A-SpoolerOnDC - Print Spooler running on DCs
- [ ] A-SpoolerNotPatched - PrintNightmare patches missing
- [ ] A-PointAndPrintUnsafe - Point and Print restrictions not set

#### Miscellaneous Anomalies
- [ ] A-RecycleBinDisabled - AD Recycle Bin not enabled
- [ ] A-TombstoneLifetimeLow - Tombstone lifetime too short
- [ ] A-FunctionalLevelLow - Domain/Forest functional level outdated
- [ ] A-SchemaVersionOutdated - AD schema not updated
- [ ] A-PreWin2000CompatAccess - Pre-Windows 2000 Compatible Access enabled
- [ ] A-AnonymousAccess - Anonymous LDAP access allowed
- [ ] A-GuestAccountEnabled - Guest account enabled
- [ ] A-DefaultAdminRenamed - Administrator not renamed (debatable)
- [ ] A-NoDefenderOnDC - No antivirus on domain controllers
- [ ] A-RemoteDesktopEnabled - RDP enabled on DCs without restrictions

---

### CATEGORY: StaleObjects (S-*)

#### User Accounts
- [ ] S-PwdNeverExpires - Password never expires (enabled accounts)
- [ ] S-PwdNotRequired - Password not required flag set
- [ ] S-PwdLastSetOld - Password not changed in 90+ days
- [ ] S-PwdLastSetVeryOld - Password not changed in 1+ year
- [ ] S-InactiveUser - User not logged in 90+ days
- [ ] S-InactiveUserPrivileged - Privileged user inactive
- [ ] S-DisabledUserWithPwd - Disabled account with recent password
- [ ] S-ExpiredUser - Account past expiration date but enabled
- [ ] S-LockedOutUser - Account locked out for extended period
- [ ] S-NeverLoggedOn - Account never logged on

#### Computer Accounts
- [ ] S-InactiveComputer - Computer not logged in 90+ days
- [ ] S-DCNotUpdated - DC not rebooted in 180+ days
- [ ] S-ComputerPwdOld - Computer password age excessive
- [ ] S-DuplicateComputer - Duplicate computer SIDs
- [ ] S-OrphanedComputer - Computer with no valid OS attribute

#### Operating Systems
- [ ] S-OS-Win2000 - Windows 2000 systems
- [ ] S-OS-Win2003 - Windows Server 2003 systems
- [ ] S-OS-WinXP - Windows XP systems
- [ ] S-OS-Vista - Windows Vista systems
- [ ] S-OS-Win7 - Windows 7 systems (EOL)
- [ ] S-OS-Win2008 - Windows Server 2008/2008 R2 (EOL)
- [ ] S-OS-Win2012 - Windows Server 2012/2012 R2 (EOL October 2023)
- [ ] S-OS-Unsupported - Any unsupported OS version
- [ ] S-DCObsoleteOS - Domain controller on obsolete OS

#### Groups
- [ ] S-EmptyGroup - Security groups with no members
- [ ] S-OrphanedGroup - Groups with broken SIDs
- [ ] S-UnusedGroup - Groups not referenced in ACLs

#### Vulnerabilities (Patch-Related)
- [ ] S-Vuln-MS14-068 - Kerberos PAC validation (unpatched)
- [ ] S-Vuln-MS17-010 - EternalBlue/WannaCry (unpatched)
- [ ] S-Vuln-CVE-2020-1472 - Zerologon (unpatched)
- [ ] S-Vuln-CVE-2021-1675 - PrintNightmare (unpatched)
- [ ] S-Vuln-CVE-2021-34527 - PrintNightmare RCE (unpatched)
- [ ] S-Vuln-CVE-2021-42278 - sAMAccountName spoofing
- [ ] S-Vuln-CVE-2021-42287 - noPac vulnerability
- [ ] S-Vuln-CVE-2022-26923 - Certifried (ADCS)

---

### CATEGORY: PrivilegedAccounts (P-*)

#### Group Membership
- [ ] P-DomainAdmins - Excessive Domain Admins members
- [ ] P-EnterpriseAdmins - Excessive Enterprise Admins members
- [ ] P-SchemaAdmins - Schema Admins with members (should be empty)
- [ ] P-Administrators - Excessive Administrators group members
- [ ] P-AccountOperators - Account Operators has members
- [ ] P-ServerOperators - Server Operators has members
- [ ] P-BackupOperators - Backup Operators security review
- [ ] P-PrintOperators - Print Operators has members
- [ ] P-DnsAdmins - DnsAdmins group abuse potential
- [ ] P-GPOCreators - Group Policy Creator Owners review
- [ ] P-ProtectedUsersEmpty - Protected Users group empty
- [ ] P-CriticalGroupNested - Critical groups with nested membership
- [ ] P-ServiceAccountInAdmins - Service accounts in admin groups

#### Kerberos Attacks
- [ ] P-Kerberoasting - SPNs on privileged accounts (roastable)
- [ ] P-Kerberoasting-Weak - SPNs with weak encryption (RC4)
- [ ] P-ASREPRoasting - Pre-auth not required (AS-REP roastable)
- [ ] P-ASREPRoasting-Privileged - Privileged accounts without pre-auth
- [ ] P-GoldenTicket-KRBTGT - KRBTGT password age > 180 days
- [ ] P-GoldenTicket-KRBTGT-Ancient - KRBTGT password age > 1 year

#### Delegation
- [ ] P-UnconstrainedDelegation - Unconstrained delegation enabled
- [ ] P-UnconstrainedDelegation-DC - Non-DC with unconstrained delegation
- [ ] P-ConstrainedDelegation-Sensitive - Delegation to sensitive services
- [ ] P-ConstrainedDelegation-AnyAuth - Protocol transition abuse
- [ ] P-RBCD-Unsafe - RBCD to sensitive computers
- [ ] P-T2A4D - Trusted to auth for delegation misconfigured
- [ ] P-DelegationPrivileged - Privileged accounts can be delegated
- [ ] P-DelegationNotProtected - Sensitive accounts without delegation protection

#### Permissions/ACLs
- [ ] P-DCSync - Non-admin with DCSync rights (Replicating Directory Changes)
- [ ] P-WriteDACL - Non-admin with WriteDACL on sensitive objects
- [ ] P-WriteOwner - Non-admin can take ownership of critical objects
- [ ] P-GenericAll - GenericAll on critical objects
- [ ] P-GenericWrite - GenericWrite on user/computer objects
- [ ] P-ResetPassword - Non-admin can reset privileged passwords
- [ ] P-AddMember - Non-admin can add to privileged groups
- [ ] P-AdminSDHolderModified - AdminSDHolder ACL modified
- [ ] P-GPOLinkRights - Non-admin can link GPOs
- [ ] P-GPOModifyRights - Non-admin can modify GPOs

#### Account Security
- [ ] P-AdminWithSPN - Admin accounts with SPNs (Kerberoastable)
- [ ] P-AdminPasswordOld - Admin password age > 1 year
- [ ] P-AdminPasswordNeverExpires - Admin with non-expiring password
- [ ] P-AdminNoSmartcard - Admin without smartcard requirement
- [ ] P-AdminNotProtectedUsers - Admins not in Protected Users
- [ ] P-InactiveAdmin - Inactive privileged accounts
- [ ] P-ServiceAccountPrivileged - Service account with admin rights
- [ ] P-MachineAccountQuota - MachineAccountQuota > 0

---

### CATEGORY: Trusts (T-*)

- [ ] T-SIDFiltering - SID filtering disabled on trusts
- [ ] T-SIDHistory - Accounts with SID history
- [ ] T-SIDHistoryDangerous - SID history contains privileged SIDs
- [ ] T-ExternalTrustUnsafe - External trust without SID filtering
- [ ] T-ForestTrustNoFiltering - Forest trust without selective auth
- [ ] T-TrustDownlevel - Trust using downlevel (NTLM) protocol
- [ ] T-TrustNotReciprocal - One-way trust security review
- [ ] T-TrustExpired - Trust relationship expired/broken
- [ ] T-TrustTooMany - Excessive trust relationships
- [ ] T-PAMTrust - PAM trust misconfiguration
- [ ] T-InboundTrustPrivileged - Inbound trust with privileged access

---

### CATEGORY: Certificates (C-*) - **NEW CATEGORY**

#### ADCS ESC Vulnerabilities
- [ ] C-ESC1-SAN - Template allows SAN specification + enrollee supplies subject
- [ ] C-ESC2-AnyPurpose - Template has Any Purpose or No EKU
- [ ] C-ESC3-EnrollmentAgent - Enrollment agent template abuse
- [ ] C-ESC4-TemplateACL - Vulnerable template ACLs (WriteDACL/Owner)
- [ ] C-ESC5-PKIObjectACL - Weak ACLs on PKI objects
- [ ] C-ESC6-EDITF - EDITF_ATTRIBUTESUBJECTALTNAME2 enabled
- [ ] C-ESC7-CAACL - Vulnerable CA access control
- [ ] C-ESC8-NTLMRelay - HTTP enrollment without EPA
- [ ] C-ESC9-NoSecurityExtension - CT_FLAG_NO_SECURITY_EXTENSION
- [ ] C-ESC10-WeakMapping - Weak certificate mapping (CVE-2022-26923)
- [ ] C-ESC11-EKUS - Dangerous EKU combinations
- [ ] C-ESC13-OIDGroupLink - issuance policy linked to group

#### Certificate Template Issues
- [ ] C-TemplateEnrollAll - Template allows Everyone/Auth Users to enroll
- [ ] C-TemplateNoApproval - Template without approval requirement
- [ ] C-TemplateNoSignature - Template without signature requirement
- [ ] C-TemplateVeryLong - Certificate validity excessively long (>2 years)
- [ ] C-TemplateDangerousEKU - Client Auth + dangerous settings
- [ ] C-TemplateSubjectNameFlag - ENROLLEE_SUPPLIES_SUBJECT flag
- [ ] C-TemplateExport - Private key exportable

#### CA Configuration
- [ ] C-CAWebEnrollmentHTTP - Web enrollment over HTTP
- [ ] C-CAAuditingDisabled - CA auditing not enabled
- [ ] C-CANoEPA - Extended Protection not enabled on CA
- [ ] C-CARootOnline - Root CA online (should be offline)
- [ ] C-CACertificateWeak - CA cert uses weak crypto (SHA1/MD5)
- [ ] C-CANTAuthCertificatesUnsafe - NTAuthCertificates object permissions
- [ ] C-CACRLExpired - Certificate Revocation List expired
- [ ] C-CAOCSPUnavailable - OCSP responder not configured

---

### CATEGORY: Kerberos (K-*) - **NEW CATEGORY**

- [ ] K-DESEncryption - DES encryption enabled
- [ ] K-RC4Encryption - RC4 encryption not disabled
- [ ] K-AES128Only - AES256 not enforced
- [ ] K-KerberosArmoringDisabled - Kerberos armoring (FAST) not enabled
- [ ] K-ClaimsNotEnabled - Claims not enabled
- [ ] K-CompoundAuthDisabled - Compound authentication disabled
- [ ] K-PreAuthDisabled - Accounts without pre-authentication (AS-REP)
- [ ] K-TicketLifetimeLong - TGT lifetime > 10 hours
- [ ] K-ServiceTicketLifetimeLong - Service ticket > 600 minutes
- [ ] K-RenewLifetimeLong - Ticket renewal > 7 days
- [ ] K-DelegationDefault - Default delegation settings unsafe
- [ ] K-S4U2SelfAbuse - S4U2Self abuse potential
- [ ] K-S4U2ProxyAbuse - S4U2Proxy abuse potential

---

### CATEGORY: Authentication (AUTH-*) - **NEW CATEGORY**

#### Password Policy
- [ ] AUTH-PwdLengthShort - Minimum password length < 14
- [ ] AUTH-PwdComplexityDisabled - Complexity requirement disabled
- [ ] AUTH-PwdHistoryLow - Password history < 24
- [ ] AUTH-PwdAgeLong - Maximum password age > 90 days
- [ ] AUTH-PwdAgeNone - Maximum password age = 0
- [ ] AUTH-LockoutDisabled - Account lockout disabled
- [ ] AUTH-LockoutThresholdHigh - Lockout threshold > 5
- [ ] AUTH-LockoutDurationShort - Lockout duration < 30 min
- [ ] AUTH-ReversibleEncryption - Reversible encryption enabled
- [ ] AUTH-FGPPNotUsed - No Fine-Grained Password Policies
- [ ] AUTH-FGPPWeaker - FGPP weaker than default policy

#### NTLM
- [ ] AUTH-NTLMv1Enabled - NTLMv1 not disabled
- [ ] AUTH-NTLMNotRestricted - NTLM not restricted to specific servers
- [ ] AUTH-LMHashStored - LM hash storage enabled
- [ ] AUTH-NTLMInboundAllowed - Inbound NTLM not audited/blocked
- [ ] AUTH-NTLMOutboundAllowed - Outbound NTLM not restricted
- [ ] AUTH-NTLMRelaySusceptible - Conditions allow NTLM relay

#### LAPS
- [ ] AUTH-LAPSNotDeployed - LAPS not deployed
- [ ] AUTH-LAPSPartialDeployment - LAPS not on all computers
- [ ] AUTH-LAPSPasswordAge - LAPS password age too long
- [ ] AUTH-LAPSLegacy - Using legacy LAPS (not Windows LAPS)
- [ ] AUTH-LAPSAclWeak - LAPS password readable by non-admins

#### Credential Protection
- [ ] AUTH-CredentialGuardDisabled - Credential Guard not enabled
- [ ] AUTH-LSAProtectionDisabled - LSA Protection not enabled
- [ ] AUTH-WDigestEnabled - WDigest authentication enabled
- [ ] AUTH-CredentialCaching - Excessive cached credentials

---

### CATEGORY: Infrastructure (I-*) - **NEW CATEGORY**

#### Domain Controllers
- [ ] I-DCReplicationFailure - DC replication failures
- [ ] I-DCReplicationLatency - Replication latency high
- [ ] I-DCNoDNS - DC without DNS server role
- [ ] I-DCNoGC - DC without Global Catalog
- [ ] I-DCTimeSkew - DC time synchronization issues
- [ ] I-DCSinglePoint - Single DC (no redundancy)
- [ ] I-DCFSMOSingle - All FSMO on single DC
- [ ] I-DCUSNRollback - USN rollback detected
- [ ] I-DCSysvolNotReplicating - SYSVOL not replicating
- [ ] I-DCJetDatabaseError - NTDS database errors

#### Sites and Subnets
- [ ] I-SiteMissing - Missing AD sites
- [ ] I-SubnetNotCovered - Subnets without site coverage
- [ ] I-SiteLinkCostDefault - Default site link costs
- [ ] I-SiteLinkReplicationLong - Site link replication interval long
- [ ] I-BridgeheadServerMissing - No bridgehead server defined

#### Azure AD / Hybrid
- [ ] I-AADConnectOutdated - Azure AD Connect version outdated
- [ ] I-AADConnectInsecure - Azure AD Connect server not hardened
- [ ] I-AADSyncPrivileged - AAD sync account overprivileged
- [ ] I-AADPasswordHash - Password hash sync security review
- [ ] I-AADPassthrough - Pass-through auth security review
- [ ] I-AADFederation - Federation configuration review
- [ ] I-AADConnectMultiple - Multiple AAD Connect instances
- [ ] I-EntraIDGuestAccess - Guest access settings review

---

### CATEGORY: Attack Vectors (AV-*) - **NEW CATEGORY**

#### Modern Attack Detection
- [ ] AV-ShadowCredentials - msDS-KeyCredentialLink abuse potential
- [ ] AV-ShadowCredentialsPresent - Unexpected KeyCredential values
- [ ] AV-GoldenGMAP - Golden GMSA attack potential
- [ ] AV-DiamondTicket - Diamond ticket prerequisites
- [ ] AV-SapphireTicket - Sapphire ticket prerequisites
- [ ] AV-PetitPotam - PetitPotam vulnerability (EFSRPC)
- [ ] AV-Coercer - Coercion attack vectors enabled
- [ ] AV-DFSCoerce - DFS coercion possible
- [ ] AV-PrinterBug - Printer bug (SpoolSample) exploitable
- [ ] AV-WebDAVCoerce - WebDAV coercion possible

#### Persistence Detection
- [ ] AV-AdminSDHolderBackdoor - AdminSDHolder modifications
- [ ] AV-SDPropBackdoor - SDProp abuse indicators
- [ ] AV-GPOPersistence - GPO-based persistence
- [ ] AV-ScheduledTaskPersistence - AD-based scheduled task abuse
- [ ] AV-SIDHistoryBackdoor - SID history used for persistence
- [ ] AV-TrustBackdoor - Trust abuse for persistence
- [ ] AV-SkeletonKey - Skeleton key indicators
- [ ] AV-DSRM - DSRM password abuse potential

#### Lateral Movement Conditions
- [ ] AV-LocalAdminReuse - Local admin password reuse
- [ ] AV-SessionHijack - Session hijacking conditions
- [ ] AV-TokenManipulation - Token manipulation prerequisites
- [ ] AV-OverpassTheHash - Overpass-the-hash conditions
- [ ] AV-PassTheTicket - Pass-the-ticket conditions

---

## COVERAGE GAP ANALYSIS

Based on comparison with Purple Knight, BloodHound, Tenable.ad, and other tools:

### Checks PingCastle Has That Others Miss
- Comprehensive GPO security analysis
- WSUS security configuration
- Detailed DNS zone security
- Historical vulnerability tracking (MS14-068, etc.)

### Checks Purple Knight Has That PingCastle Misses
- Real-time IoC detection
- Entra ID integration checks
- Okta federation security
- Some modern attack vectors (Shadow Credentials)

### Checks BloodHound Has That Others Miss
- Attack path visualization
- Complex multi-hop privilege escalation
- ADCS attack paths (ESC1-8)
- Relationship-based analysis

### Checks Tenable.ad Has That Others Miss
- Continuous monitoring
- Real-time change detection
- Modern credential attacks (Shadow Credentials, GMSA)
- Cloud sync security (Entra ID privileged sync)

### Checks That ALL Tools Should Have But Many Miss
1. **Shadow Credentials** - Few tools check msDS-KeyCredentialLink
2. **RBCD Abuse** - msDS-AllowedToActOnBehalfOfOtherIdentity
3. **ESC9-ESC11** - Newer ADCS vulnerabilities
4. **Diamond/Sapphire Tickets** - Post-Golden Ticket attacks
5. **Coercion Attacks** - PetitPotam, DFSCoerce, PrinterBug
6. **Windows Server 2025** - LDAP channel binding defaults
7. **Windows LAPS** - New LAPS vs legacy LAPS
8. **Delegated Managed Service Accounts (dMSA)** - New in 2025
9. **Cross-forest ADCS** - Certificate trust across forests
10. **OAuth/OIDC Misconfigurations** - Hybrid identity issues

---

## RULES TO ADD THAT ARE COMMONLY OVERLOOKED

These are security checks that most tools miss but represent real attack surfaces:

### Overlooked Authentication Checks
- [ ] AUTH-AdminSDHolderInterval - SDProp interval modified (non-default 60 min)
- [ ] AUTH-DomainControllerRefusePasswordChange - Refuse machine pwd change policy
- [ ] AUTH-NTLMMinClientSec - NTLM minimum client security not set
- [ ] AUTH-NTLMMinServerSec - NTLM minimum server security not set
- [ ] AUTH-RestrictNTLMDomain - Restrict NTLM in domain not configured
- [ ] AUTH-AuditNTLMDomain - Audit NTLM in domain not enabled

### Overlooked Privilege Checks
- [ ] P-ManagedServiceAccount - gMSA password retrievable by non-intended
- [ ] P-dMSALogon - dMSA logon rights misconfigured (2025+)
- [ ] P-ADMINSDHolderExclusion - Objects excluded from AdminSDHolder
- [ ] P-OperatorGroupRights - Operator groups can escalate
- [ ] P-CertPublishers - Cert Publishers group abuse
- [ ] P-RASandIASServers - RAS/IAS servers group membership
- [ ] P-TerminalServerUsers - Terminal Server License Servers

### Overlooked Infrastructure Checks
- [ ] I-RODCPasswordReplication - RODC password replication policy weak
- [ ] I-RODCKRBTGT - RODC KRBTGT compromised potential
- [ ] I-RODCAdminReplication - RODC replicating admin passwords
- [ ] I-VirtualDCSnapshot - Virtual DC snapshot protection
- [ ] I-ADFSConfiguration - ADFS security configuration
- [ ] I-EnterpriseRootCA - Enterprise Root CA in domain (should be offline)
- [ ] I-KDSRootKeyAge - KDS root key for gMSA age
- [ ] I-KDSRootKeyMultiple - Multiple KDS root keys

### Overlooked Attack Surface Checks
- [ ] AV-ComputerAttributeAbuse - Computer objects with user-writable attrs
- [ ] AV-ServicePrincipalAbuse - Orphaned or misconfigured SPNs
- [ ] AV-CriticalSystemObjects - Modifications to critical system objects
- [ ] AV-SchemaModification - Recent schema changes audit
- [ ] AV-ForestRootCompromise - Cross-forest attack paths
- [ ] AV-TierZeroAssets - Tier 0 assets not identified
- [ ] AV-NTAuthCertificatesModified - Recent NTAuthCertificates changes

### Overlooked Modern Environment Checks
- [ ] I-ContainerizedDC - DC running in container (unsupported)
- [ ] I-CloudDC - DC in cloud without proper hardening
- [ ] I-WindowsServer2025Features - New security features not enabled
- [ ] I-AppliedBaselinesMissing - No security baselines applied
- [ ] I-DevOpsServiceAccounts - CI/CD accounts with AD access

---

## FRAMEWORK COVERAGE REQUIREMENTS

Every rule must map to at least one framework. Use these references:

### MITRE ATT&CK Techniques (Common)
- T1003 - OS Credential Dumping
- T1078 - Valid Accounts
- T1087 - Account Discovery
- T1098 - Account Manipulation
- T1110 - Brute Force
- T1134 - Access Token Manipulation
- T1187 - Forced Authentication
- T1482 - Domain Trust Discovery
- T1484 - Domain Policy Modification
- T1550 - Use Alternate Authentication Material
- T1552 - Unsecured Credentials
- T1555 - Credentials from Password Stores
- T1556 - Modify Authentication Process
- T1557 - Adversary-in-the-Middle
- T1558 - Steal or Forge Kerberos Tickets

### CIS Controls v8
- Control 3 - Data Protection
- Control 4 - Secure Configuration
- Control 5 - Account Management
- Control 6 - Access Control Management
- Control 8 - Audit Log Management
- Control 12 - Network Infrastructure Management

### ANSSI Recommendations (French)
- R1-R89 (89 total recommendations)
- Key: R36 (Privileged access), R16 (Trust filtering)

---

## SCORING GUIDELINES

| Severity | Points | Criteria |
|----------|--------|----------|
| Critical | 50-100 | Direct path to domain compromise |
| High | 20-49 | Significant privilege escalation potential |
| Medium | 5-19 | Defense-in-depth weakness |
| Low | 1-4 | Best practice deviation |
| Info | 0 | Advisory only |

### Computation Types
- **TriggerOnPresence**: Fixed points if ANY instance found
- **PerDiscover**: Points × count of findings (with MaxPoints cap)
- **TriggerOnThreshold**: Points only if count >= threshold
- **TriggerIfLessThan**: Points if count < threshold (e.g., insufficient admins)

---

## RULES GENERATION INSTRUCTIONS

1. Generate rules in order of security impact (Critical first)
2. Each rule must be a complete, functional `.ps1` file
3. Include PowerShell code that actually queries AD (not pseudocode)
4. Provide realistic remediation commands
5. Map to frameworks where applicable
6. Use consistent naming: `[CATEGORY]-[Name].ps1`
7. Test scriptblocks for syntax errors
8. Consider PowerShell 5.1 and 7.x compatibility

## DATA SOURCES AVAILABLE

The `$ADData` hashtable passed to rules contains:

```powershell
$ADData = @{
    Domain = @{
        FQDN = "contoso.com"
        NetBIOS = "CONTOSO"
        SID = "S-1-5-21-..."
        FunctionalLevel = 7
        ForestFunctionalLevel = 7
    }
    Users = @(...)              # All user objects with properties
    Computers = @(...)          # All computer objects
    Groups = @(...)             # All groups with members
    DomainControllers = @(...)  # DC objects with OS, IPs, roles
    Trusts = @(...)             # Trust relationships
    GPOs = @(...)               # Group Policy Objects
    OUs = @(...)                # Organizational Units
    CertificateAuthorities = @(...) # ADCS CAs
    CertificateTemplates = @(...)   # Certificate templates
    Sites = @(...)              # AD Sites
    Subnets = @(...)            # AD Subnets
    PasswordPolicy = @{...}     # Default password policy
    FineGrainedPolicies = @(...)# FGPPs
    AdminSDHolder = @{...}      # AdminSDHolder ACL
    SchemaVersion = 87          # AD Schema version
    ForestRootDomain = "..."    # Forest root
}
```

Begin generating rules now, starting with Critical severity rules.
```

---

## How to Use This Prompt

1. Start a new Claude session in the `ad-scout/src/ADScout/Rules/` directory
2. Paste this prompt
3. Request rules by category or severity:
   - "Generate all Critical severity rules"
   - "Generate all Certificates (C-*) rules"
   - "Generate the top 20 most impactful rules"
4. Review and test each rule
5. Commit in batches

## Priority Order for Rule Development

1. **P-DCSync** - Most critical (direct domain compromise)
2. **C-ESC1 through C-ESC8** - ADCS attacks are common
3. **P-Kerberoasting** / **P-ASREPRoasting** - Very common attacks
4. **AV-ShadowCredentials** - Modern attack, rarely checked
5. **P-UnconstrainedDelegation** - Classic high-impact issue
6. **AUTH-LAPSNotDeployed** - Common gap
7. **A-SpoolerOnDC** - PrintNightmare prerequisite
8. **K-KRBTGT** - Golden ticket prevention
9. **S-OS-Unsupported** - EOL systems
10. **T-SIDFiltering** - Trust abuse

---

## Total Rule Count Target

| Category | Count | Status |
|----------|-------|--------|
| Anomalies (A-*) | ~45 | Migrate from PingCastle concepts |
| StaleObjects (S-*) | ~35 | Migrate from PingCastle concepts |
| PrivilegedAccounts (P-*) | ~40 | Migrate + expand |
| Trusts (T-*) | ~12 | Migrate from PingCastle concepts |
| Certificates (C-*) | ~25 | NEW - ADCS focus |
| Kerberos (K-*) | ~15 | NEW - Kerberos hardening |
| Authentication (AUTH-*) | ~25 | NEW - Password/NTLM/LAPS |
| Infrastructure (I-*) | ~25 | NEW - DC health/hybrid |
| AttackVectors (AV-*) | ~20 | NEW - Modern attacks |
| **TOTAL** | **~242** | Comprehensive coverage |

This exceeds PingCastle's 187 rules and addresses gaps identified in other tools.
