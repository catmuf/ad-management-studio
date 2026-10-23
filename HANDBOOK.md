# Active Directory Management Studio (v3.3.0 Enterprise)
## Enterprise SysAdmin Handbook & Operator Manual
### Complete Operational Reference Guide for Active Directory & LDAP Infrastructure

[📖 SysAdmin Handbook](HANDBOOK.md) | [🚀 Visual Operator Walkthrough](WALKTHROUGH.md) | [📁 Project README](README.md) | [📋 Changelog](CHANGELOG.md)

---

## Table of Contents

- [1. Executive Overview & Architectural Foundation](#1-executive-overview--architectural-foundation)
  - [1.1. Forest Health & Operations Dashboard (Default Light Presentation)](#11-forest-health--operations-dashboard-default-light-presentation)
  - [1.2. Key Architectural Pillars](#12-key-architectural-pillars)
- [2. Installation, Prerequisites & Launch Procedure](#2-installation-prerequisites--launch-procedure)
  - [Prerequisites](#prerequisites)
  - [Launching the Application](#launching-the-application)
- [3. Workspace Catalog (24 Enterprise Workspaces)](#3-workspace-catalog-24-enterprise-workspaces)
- [4. User Lifecycle & Attribute Management (Users Workspace)](#4-user-lifecycle--attribute-management-users-workspace)
  - [Key Operational Capabilities](#key-operational-capabilities)
  - [Light Theme Visual Presentation](#light-theme-visual-presentation)
- [5. Apache Directory Studio Parity: Object Studio & Specialized Editors](#5-apache-directory-studio-parity-object-studio--specialized-editors)
  - [5.1. Binary & Hex Dump Editor](#51-binary--hex-dump-editor)
  - [5.2. X.509 Certificate Inspector with Online Revocation Check](#52-x509-certificate-inspector-with-online-revocation-check)
  - [5.3. Photo / Thumbnail Cropper & Resizer](#53-photo--thumbnail-cropper--resizer)
  - [5.4. LDAP GeneralizedTime & FileTime Converter](#54-ldap-generalizedtime--filetime-converter)
  - [5.5. Salted Password Hasher](#55-salted-password-hasher)
- [6. SCIM 2.0 Cloud Identity Protocol Suite](#6-scim-20-cloud-identity-protocol-suite)
  - [RFC 7644 Query Filter Compiler](#rfc-7644-query-filter-compiler)
  - [Supported SCIM Operators & Schema Projections](#supported-scim-operators--schema-projections)
- [7. NetTools Parity: Security, Kerberos & Advanced Diagnostics](#7-nettools-parity-security-kerberos--advanced-diagnostics)
  - [7.1. 6-Way Effective Rights & ACL Security](#71-6-way-effective-rights--acl-security)
  - [7.2. Kerberos PAC Bloat & MaxTokenSize Calculator](#72-kerberos-pac-bloat--maxtokensize-calculator)
  - [7.3. Circular Group Loop Diagnostics](#73-circular-group-loop-diagnostics)
  - [7.4. 48 Enterprise Security Audit Reports](#74-48-enterprise-security-audit-reports)
  - [7.5. NetTools 7-Tier UNC Share & Port Matrix Diagnostics](#75-nettools-7-tier-unc-share--port-matrix-diagnostics)
- [8. Headless Automation CLI (`tools/ad-studio-cli.ps1`)](#8-headless-automation-cli-toolsad-studio-clips1)
  - [8.1. Primary Automation Modes (-Export, -ImportLDIF, -Audit, -QuerySQL)](#81-primary-automation-modes--export--importldif--audit--querysql)
  - [8.2. Identity Diagnostic Subcommands (-Command)](#82-identity-diagnostic-subcommands--command)
- [9. Troubleshooting & Logging Architecture](#9-troubleshooting--logging-architecture)
  - [Logging Format & ISO 8601 Millisecond Precision](#logging-format--iso-8601-millisecond-precision)
  - [PSScriptAnalyzer & Code Quality Compliance](#psscriptanalyzer--code-quality-compliance)
- [10. Companion Resources & Navigation](#10-companion-resources--navigation)

---

## 1. Executive Overview & Architectural Foundation

**Active Directory Management Studio** is an enterprise-grade administration and directory engineering suite built for Windows Server Systems Administrators, Identity Engineers, and Security Auditors. Implemented entirely in modern **PowerShell & WPF/XAML**, it consolidates everyday directory operations (Users, Groups, OUs, Computers) with deep low-level diagnostic engines, forensic analyzers, and protocol translators previously fragmented across specialized utilities like **Softerra LDAP Administrator**, **Apache Directory Studio**, and **NetTools**.

![Active Directory Overview & Health Dashboard](docs/images/01_dashboard_overview.png)

### 1.1. Forest Health & Operations Dashboard (Default Light Presentation)

The studio launches by default in **Light Theme** (`"Theme": "Light"` in `config.json`), designed from the ground up to maximize legibility and reduce eye fatigue under standard daytime office and administrative lighting conditions:

- **Surface & Background Palette**: Clean `#FFFFFF` elevated surface cards over a soft `#F8FAFC` viewport canvas, demarcated by subtle `#CBD5E1` border rules.
- **High-Contrast Typography**: Primary labels and metric values render in deep slate (`#0F172A`) and dark charcoal (`#1E293B`), ensuring crisp readability across high-DPI displays.
- **Real-Time Health KPI Tiles**:
  - **Total Users (`1,248`)**: Forest user account count.
  - **Active / Enabled (`1,180`)**: Healthy operational accounts ready for authentication.
  - **Disabled (`54`)**: Decommissioned or archived accounts.
  - **Locked Out (`14`)**: Accounts exceeding authentication failure thresholds (highlighted with an urgent crimson pill).
  - **Groups (`185`)** & **Computers (`320`)**: Domain inventory counts.
- **Active Directory Environment Card**: Displays live topology metadata, including the Primary Domain Controller Emulator (PDCe) role holder (`corp-dc01.contoso.local`), Default Naming Context (`DC=contoso,DC=local`), and verified protocol capabilities (LDAP v3 RFC 4511 & LDAPS Port 636).
- **Quick Launchpad**: 1-click administrative shortcuts directly navigate to **Directory Search**, **LDAP-SQL Console**, **Raw Attribute Editor**, and **Security Audits**.
- **Instant Theme Toggle**: Operators working in low-light NOC/SOC environments can switch between **Light Mode** and **Dark Mode** at any time via `Ctrl+T` or the top toolbar theme switch.

### 1.2. Key Architectural Pillars

1. **Dual-Mode Presentation Engine (Default Light Mode / Dark Mode)**:
   - High-contrast, accessibility-audited palettes engineered for both well-lit daytime jump boxes and low-eyestrain dark NOC consoles.
2. **Dual-Engine Directory Access**:
   - Leverages the RSAT `ActiveDirectory` PowerShell module when present on domain controllers and administrative workstations.
   - Gracefully falls back to pure .NET `System.DirectoryServices.Protocols` (S.DS.P) and ADSI interfaces when running on unmanaged client workstations without RSAT, ensuring zero-footprint portability.
3. **In-Process Single-Threaded Apartment (STA) Runspace Window Detachment**:
   - Workspaces and secondary diagnostic panes can be detached into independent, multi-monitor floating windows with zero latency and crash-free dock-back capabilities.
4. **RFC & Industry Standard Compliance**:
   - **RFC 4511**: LDAP v3 Core Protocol.
   - **RFC 4515**: LDAP Search Filter String Representation.
   - **RFC 2849**: LDAP Data Interchange Format (LDIF).
   - **RFC 2891**: Server Side Sorting & Virtual List View (VLV).
   - **RFC 7643 / RFC 7644**: SCIM 2.0 Core/Enterprise Schemas & Protocol.

---

## 2. Installation, Prerequisites & Launch Procedure

### Prerequisites
1. **Operating System**: Windows Server 2016, 2019, 2022, 2025, or Windows 10/11 (Pro, Enterprise, Education).
2. **PowerShell Engine**: Windows PowerShell 5.1 or PowerShell 7.2+ Core.
3. **Execution Policy**: Set to `RemoteSigned` or `Bypass` in the active process:
   ```powershell
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
   ```
4. **Network & Firewall Connectivity**:
   - **Port 389 (TCP/UDP)**: LDAP Standard Directory Access
   - **Port 636 (TCP)**: LDAPS (LDAP over SSL/TLS)
   - **Port 3268 / 3269 (TCP)**: Active Directory Global Catalog (GC / GC-SSL)
   - **Port 88 (TCP/UDP)**: Kerberos v5 Key Distribution Center (KDC)
   - **Port 445 (TCP)**: SMB / CIFS SYSVOL Access
   - **Port 53 (TCP/UDP)**: DNS SRV Locator Resolution
   - **Port 135 (TCP)**: RPC Endpoint Mapper

### Launching the Application
Execute the launch script from an elevated or standard administrative PowerShell prompt:
```powershell
pwsh -NoProfile -STA -File .\main.ps1
```
*(Windows PowerShell 5.1 operators can run `powershell.exe -NoProfile -STA -File .\main.ps1`).*

On startup, the studio performs automated environment discovery:
- Detects the current AD forest and domain hierarchy.
- Identifies the Primary Domain Controller Emulator (PDCe) and Global Catalog servers.
- Initializes the enterprise logging engine under `logs/YYYY-MM-DD.log`.

---

## 3. Workspace Catalog (24 Enterprise Workspaces)

The sidebar organizes 24 specialized workspaces into 4 functional domains:

| Category | Workspace | Purpose & Operational Capability | Shortcut / Access |
| :--- | :--- | :--- | :--- |
| **Directory Operations** | **Dashboard** | Forest-wide health KPIs, operational status badges, and quick-launch links. | `Ctrl+1` / Sidebar |
| | **Users** | User lifecycle provisioning, password management, account unlock, and attribute editing. | `Ctrl+2` / Sidebar |
| | **Groups** | Security and distribution group management, recursive member resolution. | `Ctrl+3` / Sidebar |
| | **Org. Units (OUs)** | Interactive hierarchical treeview, OU protection safeguards, container browsing. | `Ctrl+4` / Sidebar |
| | **Computers** | Workstation and server inventory, operating systems, and stale computer identification. | `Ctrl+5` / Sidebar |
| | **AD Recycle Bin** | Deleted object recovery, tombstone reanimation, and lifetime management. | Sidebar |
| **Softerra & Apache Studio** | **Directory Search** | Visual LDAP Filter Builder (AND/OR/NOT blocks), presets, and VLV paged queries. | `Ctrl+F` / Sidebar |
| | **LDAP-SQL Console** | ANSI-SQL query interface over Active Directory (`SELECT ... FROM SUBTREE WHERE ...`). | Sidebar |
| | **Raw Attribute Editor**| Multi-valued array manipulation, operational attributes, bitmask decoders. | Sidebar |
| | **HTML Dossier View** | Executive identity dossier rendering, responsive styling, print-ready reports. | Sidebar |
| | **Object Compare** | Side-by-side object attribute diffing, delta tracking, and sync scripting. | Sidebar |
| | **LDIF Studio** | RFC 2849 batch script generation, validation, and dry-run execution. | Sidebar |
| | **Security Audits** | 48 pre-packaged enterprise hygiene audit reports with HTML export. | Sidebar |
| | **Schema Browser** | Object class inheritance, attribute syntax definitions, and schema export. | Sidebar |
| | **Bulk Operations** | Mass batch updates, CSV import, attribute overriding across multiple objects. | Sidebar |
| | **Directory Basket** | Cross-OU object staging cart for batch moving, updating, and export. | `Ctrl+B` / Sidebar |
| **Identity & Standards** | **SCIM 2.0 Studio** | RFC 7644 SCIM query translation to native LDAP filters, RFC 7643 schema mapping. | Sidebar |
| | **Object Studio** | Specialized editors: Hex/Binary dump, X.509 certs, photo cropping, date conversion. | Context Menu / Toolbar |
| **Diagnostics & NetTools** | **Security & ACL Suite** | 6-Way Effective Rights matrix, DACL/SACL browser, 1-Click AdminSDHolder fix. | Sidebar |
| | **Kerberos Suite** | PAC Bloat & MaxTokenSize estimator (`1200 + 40d + 8s`), ticket cache inspector (`klist`). | Sidebar |
| | **Replication Suite** | Multi-DC replication metadata, USN vector sync, metadata forensics. | Sidebar |
| | **Diagnostics Toolbox**| Circular group loop DFS scanner, side-by-side group diff, lockout tracer. | Sidebar |
| | **Network Diagnostics**| 7-Tier UNC share diagnostic checker, 8-port DC latency matrix. | Sidebar |
| | **Connections** | Multi-profile directory manager, custom SSL ports, rootDSE discovery. | Top Toolbar / Sidebar |

---

## 4. User Lifecycle & Attribute Management (Users Workspace)

The **Users** workspace serves as the primary cockpit for identity lifecycle workflows.

![User Management Grid and Quick Attribute Inspector](docs/images/02_users_and_inspector.png)

### Key Operational Capabilities

1. **Live Search & Filter Chips**:
   - Filter directory users in real-time by Name, Username, Department, or Email.
   - Filter chips allow instant toggling between `All`, `Active`, `Disabled`, and `Locked` accounts.
2. **Quick Inspector Dossier (Right Pane)**:
   - Selecting any user immediately renders the Quick Inspector side-panel.
   - Displays display name, `sAMAccountName`, UPN, email, title, department, distinguished name (DN), and account status badge.
   - Quick Action buttons allow 1-click password reset, account unlocking, status toggle, and basket staging.
3. **Template Provisioning Engine**:
   - Create new accounts from structured templates (`New from Template...`).
   - Supports macro expansion: `%first.last%`, `%initials%`, `%company%`, `%department%`.
   - Automated conflict resolution appends numeric identifiers or middle initials if a username collision occurs.

### Light Theme Visual Presentation

In default Light Theme:
- The **DataGrid** renders alternating rows in crisp white (`#FFFFFF`) and subtle slate (`#F8FAFC`) with `#E2E8F0` gridlines.
- Selected records highlight with a clean sky blue accent (`#0284C7`), ensuring instant row identification.
- Status badges utilize vibrant, accessible pill styling: Emerald Green (`#10B981`) for active users and Crimson Red (`#EF4444`) for locked/disabled accounts.
- The **Quick Inspector** dossier surface uses pure `#FFFFFF` background with distinct icon buttons (`🔑 Reset Password`, `🔓 Unlock Account`, `⚡ Toggle Status`, `🛒 Add to Basket`).

---

## 5. Apache Directory Studio Parity: Object Studio & Specialized Editors

Active Directory Management Studio includes high-fidelity specialized editors matching and exceeding **Apache Directory Studio**.

### 5.1. Binary & Hex Dump Editor
For raw octet string attributes (e.g., `objectGUID`, `objectSid`, `userCertificate`, `schemaIDGUID`), the Hex Editor provides synchronized multi-pane inspection:

![Specialized Hex and Binary Attribute Editor](docs/images/03_specialized_editor_hex.png)

- **Synchronized 3-Column Inspection Pane**: Displays standard 16-byte hex dump offsets (`00000000`), spaced hex pairs, and printable ASCII decode.
- **Raw Hex Stream Editor**: Allows direct pasting or typing of raw hex pairs (`3082042E...`) with auto-reformatting.
- **Instant Previews**: Displays real-time ASCII decode and RFC 4648 Base64 strings.
- **Total Byte Counter**: Live badge indicates exact payload size (`Total Bytes: 1,074 bytes (0x0432)`).
- **Import / Export**: Supports saving binary attributes directly to `.bin` or loading external binary payloads.
- **Light Theme Presentation**: Formatted in a clean monospace font (`Consolas`) with high-contrast slate text on white background panels for error-free byte inspection.

### 5.2. X.509 Certificate Inspector with Online Revocation Check
When inspecting user certificates (`userCertificate`), domain controller certificates, or service credentials:

![X.509 Certificate Viewer with Online Revocation Check](docs/images/04_specialized_editor_cert.png)

- **Identification & Subject Breakdown**: Extracts Common Name (CN), Organizational Unit (OU), Domain Components (DC), and full Subject/Issuer DNs.
- **Validity Monitoring**: Displays `NotBefore`, `NotAfter`, and real-time days-remaining countdown badges (`VALID (Active: 443 days remaining)`).
- **Cryptographic Specifications**: Inspects Public Key type/size (e.g., `RSA 2048 bits`), Signature Algorithm (`sha256RSA`), Key Usage, and Subject Alternative Names (SANs).
- **Online Chain & Revocation Engine**: Executes live `X509Chain` building with online CRL and OCSP validation, confirming trusted root CA certification or surfacing revocation warnings.
- **Light Theme Presentation**: Property grid items are cleanly partitioned with high-contrast text and a prominent green validity badge.

### 5.3. Photo / Thumbnail Cropper & Resizer
Active Directory limits `thumbnailPhoto` to 100 KB (recommended 96x96 pixels):
- Load any JPEG, PNG, or BMP image.
- Center-crops the image to an exact 1:1 aspect ratio.
- High-quality bicubic downsampling resizes the image to 96x96 pixels and compresses it to < 10 KB for instant Outlook/Teams directory synchronization.

### 5.4. LDAP GeneralizedTime & FileTime Converter
- Bidirectional conversion between Windows FileTime (64-bit integer, e.g., `133100000000000000`) and LDAP GeneralizedTime strings (`YYYYMMDDhhmmss.0Z`).
- Displays local workstation time, UTC time, and relative duration ("4 days ago").

### 5.5. Salted Password Hasher
- Computes standard LDAP user password hashes: `{SSHA}`, `{SHA256}`, `{SSHA512}`.
- Includes candidate password verification tool to test plaintext passwords against stored hashes without modifying directory state.

---

## 6. SCIM 2.0 Cloud Identity Protocol Suite

Modern enterprise identity systems bridge on-premises Active Directory with cloud providers (Entra ID, Okta, Ping Identity) using **SCIM 2.0 (RFC 7643 / RFC 7644)**.

![SCIM 2.0 Query and Native LDAP Filter Studio](docs/images/05_scim_filter_studio.png)

### RFC 7644 Query Filter Compiler

The studio includes a high-performance Abstract Syntax Tree (AST) lexer and parser that compiles SCIM filter expressions into native RFC 4515 LDAP search filters:

```text
SCIM Expression:
userName sw "alex" and title pr and emails[type eq "work"].value ew "@contoso.com"

Compiled Native LDAP Filter:
(&(objectCategory=person)(objectClass=user)(sAMAccountName=alex*)(title=*)(mail=*@contoso.com))
```

### Supported SCIM Operators & Schema Projections

- **Relational Operators**: `eq` (Equal), `ne` (Not Equal), `co` (Contains), `sw` (Starts With), `ew` (Ends With), `pr` (Present / Attribute Exists), `gt`, `ge`, `lt`, `le`.
- **Complex Attributes**: Nested attribute filters (`emails[type eq "work" and primary eq true].value`).
- **Logical Grouping**: Parenthesized expressions with `and` / `or` / `not` operators.
- **RFC 7643 Schema Projections**:
  - `urn:ietf:params:scim:schemas:core:2.0:User` ➔ `sAMAccountName`, `displayName`, `mail`, `title`.
  - `urn:ietf:params:scim:schemas:extension:enterprise:2.0:User` ➔ `department`, `manager`, `employeeNumber`.
- **Light Theme Presentation**: Syntax-highlighted query editor with dark navy code blocks against white surface containers and instant millisecond execution telemetry.

---

## 7. NetTools Parity: Security, Kerberos & Advanced Diagnostics

### 7.1. 6-Way Effective Rights & ACL Security
Diagnosing Active Directory access control requires evaluating complex Discretionary Access Control Lists (DACLs), System Access Control Lists (SACLs), inheritance flags, and object type GUIDs.

![Access Control and 6-Way Effective Rights Matrix](docs/images/06_security_acl_6way.png)

- **DACL / SACL Table**: Displays all Access Control Entries (ACEs) with Trustee name, Access Type (Allow/Deny), Rights mask, Inheritance status, and Inherited Object Types.
- **6-Way Effective Rights Matrix**: Evaluates permissions across 6 distinct permission classes:
  1. `GenericAll` (Full Control)
  2. `ReadProperty` (Attribute Read)
  3. `WriteProperty` (Attribute Write)
  4. `CreateChild` (Object Creation)
  5. `DeleteChild` (Object Deletion)
  6. `ExtendedRight` (Password Reset, Send-As, Receive-As)
- **1-Click AdminSDHolder Orphan Remediation**:
  - Automatically identifies accounts where `adminCount=1` persists after leaving protected groups.
  - 1-click action clears `adminCount` and re-enables inheritance, restoring normal delegation.
- **Light Theme Presentation**: Resultant rights render with high-contrast emerald green `GRANTED` pills and clean slate borders.

### 7.2. Kerberos PAC Bloat & MaxTokenSize Calculator
Kerberos authentication tickets contain Privilege Attribute Certificate (PAC) buffers detailing all security group memberships. Excessive group nesting causes HTTP 400 Bad Request errors in IIS, SharePoint, and web SSO applications.

![Kerberos Token PAC Bloat Calculator](docs/images/07_kerberos_token_bloat.png)

- **Microsoft PAC Expansion Formula**:
  $$\text{TokenSize} = 1200 + 40d + 8s$$
  *(where $d$ is Domain Local/Universal groups and $s$ is Global groups and SID History entries).*
- **Real-Time Risk Gauge**:
  - Compares estimated token size against domain `MaxTokenSize` limits (12,000 bytes legacy / 48,000 bytes modern).
  - Categorizes risk into `Normal (OK)`, `Elevated Warning`, or `Critical HTTP 400 Risk`.
- **Roster of Contributing Groups**: Slices recursive group hierarchies to highlight which specific groups are contributing to token inflation.
- **Light Theme Presentation**: Key metrics are presented in elevated `#FFFFFF` stat boxes with a prominent `Normal (OK)` emerald status indicator.

### 7.3. Circular Group Loop Diagnostics
Circular group nesting (e.g. `Group A` $\in$ `Group B` $\in$ `Group C` $\in$ `Group A`) causes infinite loops in identity synchronization agents, token bloat, and LDAP search timeouts.

![Circular Group Nesting Loop Cycle Detector](docs/images/08_circular_groups_loop.png)

- **Depth-First Search (DFS) Cycle Detection**: Analyzes the entire domain group graph in seconds.
- **Visual Cycle Path**: Displays the complete loop path (`IT-Admins-Core ➔ DevOps-Infrastructure ➔ SecOps-Auditors ➔ IT-Admins-Core`).
- **1-Click Disconnect Action**: Breaks the recursive link safely with a single click (`Disconnect-CircularGroupReference`).
- **Light Theme Presentation**: Detected loops are highlighted with a high-visibility amber `LOOP DETECTED` badge and breadcrumb path arrows.

### 7.4. 48 Enterprise Security Audit Reports
Continuous security hygiene is vital to prevent privilege escalation and lateral movement.

![Enterprise Security and 48 Hygiene Audit Reports](docs/images/09_audit_reports_48.png)

The **Security Audits** workspace categorizes 48 operational reports:
- **Account Hygiene**: Inactive users (> 90 days), never logged on, disabled users in security groups.
- **Privileged Access**: `adminCount=1` with broken inheritance, Schema Admins, Enterprise Admins.
- **Kerberos & Delegation**: Unconstrained delegation servers (`TRUSTED_FOR_DELEGATION`), constrained delegation, AS-REP roastable accounts (`DONT_REQ_PREAUTH`).
- **Password Hygiene**: Passwords never expire, reversible encryption enabled, weak password policies.
- **Output Formats**: Exportable to CSV or executive-styled HTML reports for CISO compliance reviews.
- **Light Theme Presentation**: Category selector and days threshold slider feed into a clean slate DataGrid with finding count badges.

### 7.5. NetTools 7-Tier UNC Share & Port Matrix Diagnostics
Troubleshooting domain controller accessibility and file share synchronization across firewalls:

![NetTools 7-Tier UNC Share and DC Port Latency Diagnostics](docs/images/10_network_7tier_unc.png)

- **7-Tier Sequential UNC Share Diagnostics**:
  1. DNS A/AAAA Record Resolution
  2. ICMP Echo Latency Probe
  3. RPC Endpoint Mapper (Port 135)
  4. SMB Protocol Handshake (Port 445)
  5. `NetShareGetInfo` Share Enumeration
  6. Share ACL Permissions Validation
  7. File System Path Traversal & `GPT.INI` Read Verification
- **Domain Controller Port Matrix**: Probes ports 389, 636, 88, 445, 53, 3268, 3269, and 135 simultaneously, measuring latency in milliseconds.
- **Light Theme Presentation**: Sequential diagnostic steps render with individual `PASS` badges, millisecond latency readings, and detailed diagnostic notes.

---

## 8. Headless Automation CLI (`tools/ad-studio-cli.ps1`)

For unattended administration, CI/CD pipelines, and scheduled operational tasks, all core studio capabilities are accessible via `tools/ad-studio-cli.ps1`:

### 8.1. Primary Automation Modes (-Export, -ImportLDIF, -Audit, -QuerySQL)

```powershell
# 1. Export directory users to CSV
pwsh tools/ad-studio-cli.ps1 -Export -Filter '(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' -OutFile 'users.csv'

# 2. Export security groups to JSON
pwsh tools/ad-studio-cli.ps1 -Export -Filter '(&(objectClass=group)(groupType:1.2.840.113556.1.4.803:=2147483648))' -Format JSON -OutFile 'groups.json'

# 3. Simulate LDIF changes with Dry-Run safety validation
pwsh tools/ad-studio-cli.ps1 -ImportLDIF -InFile 'C:\scripts\bulk_depts.ldif' -DryRun

# 4. Execute automated domain hygiene audit and output styled HTML executive report
pwsh tools/ad-studio-cli.ps1 -Audit -Category All -OutReport 'domain_audit.html'

# 5. Execute ANSI-SQL query over Active Directory
pwsh tools/ad-studio-cli.ps1 -QuerySQL -Query "SELECT sAMAccountName, mail, department FROM 'DC=contoso,DC=local' WHERE objectClass = 'user'"
```

### 8.2. Identity Diagnostic Subcommands (-Command)

```powershell
# 1. Discover Domain Controllers via DNS SRV
pwsh tools/ad-studio-cli.ps1 -Command DiscoverDC -Domain contoso.local

# 2. Compile SCIM 2.0 query to native LDAP filter
pwsh tools/ad-studio-cli.ps1 -Command CompileScim -ScimFilter 'userName sw "john" and title pr'

# 3. Calculate Kerberos Token Size & PAC Bloat
pwsh tools/ad-studio-cli.ps1 -Command CalcTokenSize -Username alex.morgan

# 4. Scan Domain for Circular Group Loops
pwsh tools/ad-studio-cli.ps1 -Command ScanGroupCycles

# 5. Execute 7-Step UNC Share Diagnostic
pwsh tools/ad-studio-cli.ps1 -Command CheckUnc -Path "\\dc01.corp.local\SYSVOL\corp.local"
```

---

## 9. Troubleshooting & Logging Architecture

### Logging Format & ISO 8601 Millisecond Precision
All operations, protocol queries, warnings, and errors are written to:
`logs/YYYY-MM-DD.log`

Each log entry is timestamped with ISO 8601 millisecond precision:
```text
[2026-10-14 09:24:25.142] [INFO] [UI] Theme updated to Light Mode.
[2026-10-14 09:24:26.418] [INFO] [SCIM] Filter compiled: (&(objectCategory=person)(sAMAccountName=alex*))
[2026-10-14 09:24:28.019] [WARN] [SECURITY] Circular group reference detected in IT-Admins-Core.
```

### PSScriptAnalyzer & Code Quality Compliance
All scripts adhere to Microsoft PowerShell best practices:
- **Zero Unapproved Verbs**: All cmdlets use official PowerShell verbs (`Update-*`, `Initialize-*`, `Import-*`, `Invoke-*`, `Remove-*`, `Test-*`, `Disconnect-*`, `New-*`).
- **Backward-Compatible Global Aliases**: All legacy function names are preserved via `Set-Alias`.
- **Zero Empty Catch Blocks**: Suppressed errors include structured debug logs and context notes.
- **UTF-8 with BOM (`EF BB BF`)**: Preserved across all source scripts to guarantee cross-platform compatibility on Windows PowerShell 5.1 and PowerShell 7+.

---

## 10. Companion Resources & Navigation

- [🚀 Step-by-Step Operator Walkthrough (WALKTHROUGH.md)](WALKTHROUGH.md): Visual user guide with 10 end-to-end operational scenarios.
- [📁 Project Overview & Setup (README.md)](README.md): Quick start guide and architecture highlights.
- [🛠️ CLI Automation Engine (`tools/ad-studio-cli.ps1`)](tools/ad-studio-cli.ps1): Headless command-line interface.
