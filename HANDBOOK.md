# Active Directory Management Studio
## Professional SysAdmin Handbook & Operator Manual
### Enterprise LDAP & Directory Administration Guide

---

## 1. Executive Overview

**Active Directory Management Studio** is an enterprise-grade administration suite designed for Windows Server Systems Administrators, Security Engineers, and Directory Operators. Built in modern **PowerShell & WPF/XAML**, it unites standard Active Directory workflows (Users, Groups, OUs, Computers) with the deep diagnostic and low-level capabilities found in specialized LDAP management suites such as **Softerra LDAP Administrator 2026**.

### Core Architecture Highlights
- **Dual-Engine Directory Access**: Automatically utilizes the RSAT `ActiveDirectory` PowerShell module when available; gracefully falls back to native .NET `System.DirectoryServices.Protocols` (S.DS.P) and ADSI interfaces when running on workstations without RSAT.
- **Single Thread Apartment (STA) WPF Engine**: Hardware-accelerated presentation layer loaded safely into STA threads, preventing UI lockups and cross-thread exceptions.
- **Enterprise Dark-Mode Interface**: 15 dedicated operational workspaces grouped logically by Directory Operations, Softerra LDAP Tools, Analytics & Security, and System Infrastructure.
- **RFC Compliance**: Full support for RFC 4511 (LDAP v3), RFC 2849 (LDIF Format), and RFC 4517 (LDAP Syntaxes).

---

## 2. Quick-Start Guide

### Prerequisites
1. **Operating System**: Windows Server 2016 / 2019 / 2022 / 2025 or Windows 10 / 11 (Pro / Enterprise / Education).
2. **PowerShell Engine**: Windows PowerShell 5.1 or PowerShell 7.2+ Core.
3. **Execution Policy**: Set to `RemoteSigned` or `Bypass` for the local process:
   ```powershell
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
   ```
4. **Network & Ports**:
   - Port 389 (TCP/UDP) - LDAP Standard
   - Port 636 (TCP) - LDAPS (LDAP over SSL/TLS)
   - Port 3268 / 3269 (TCP) - Active Directory Global Catalog
   - Port 88 (TCP/UDP) - Kerberos v5 Authentication
   - Port 53 (TCP/UDP) - DNS Resolution

### Launching the Studio
```powershell
cd C:\Path\To\ad-management-studio
.\main.ps1
```
The application will inspect its execution thread, elevate to an STA runspace if required, discover the Active Directory context (Domain, Primary Domain Controller, Default Naming Context), and open the centralized workspace.

---

## 3. Workspace Navigation Reference

The sidebar categorizes the 17 functional workspaces into 4 distinct groups:

| Category | Workspace | Description & Scope |
| :--- | :--- | :--- |
| **Directory Operations** | **Dashboard** | Real-time health metrics, active connection telemetry, and drill-down KPI cards. |
| | **Users** | User lifecycle management, provisioning, password reset, account unlock, and OU mover. |
| | **Groups** | Security and distribution group management, scope configuration, and member rosters. |
| | **Org. Units (OUs)** | Hierarchical directory tree navigation, OU creation, accidental deletion safeguard, and object inspector. |
| | **Computers** | Domain workstation and server inventory, operating systems, versions, and logon tracking. |
| **Softerra & Apache LDAP Tools** | **Directory Search** | Visual LDAP Filter Builder (AND/OR/NOT blocks), administrative query presets, and multi-scope directory querying. |
| | **Directory Basket** | Cross-OU object staging cart for mass bulk updates, status toggling, OU moving, and CSV/LDIF export. |
| | **LDAP-SQL Console** | ANSI-SQL query interface over LDAP directory databases (`SELECT ... FROM ... WHERE ...`). |
| | **Attribute Editor** | Low-level raw attribute inspector with multi-valued array editors, UAC bitmask decoder, photo/cert editors, and operational attributes. |
| | **Object Compare** | Side-by-side object difference engine, attribute reconciliation, and diff exporter. |
| | **LDIF Studio** | RFC 2849 LDIF script editor, dry-run simulation engine, and live directory modifier. |
| **Analytics & Security**| **Security Audits** | Automated security posture audits (including AdminSDHolder/adminCount=1) with styled HTML executive reports. |
| | **Schema Browser** | Interactive catalog of Active Directory object classes and attribute syntaxes with OpenLDAP/LDIF export. |
| | **Bulk Operations** | Mass batch updates, attribute overrides, batch account status changes, and OU relocation. |
| **System & Diagnostics** | **Protocol Wire Log**| Live real-time LDAP request wire logger capturing timestamps, operations, base DNs, scopes, filters, server endpoints, and status. |
| | **Connections** | Multi-profile connection manager, custom ports, LDAPS SSL toggles, and live TCP/RootDSE diagnostics. |
| | **Settings** | Configuration manager for password policies, naming formats, and export delimiters. |

---

## 4. Deep-Dive: Softerra LDAP Feature Suite

### 4.1. Visual LDAP Filter Builder (Directory Search)

The **Directory Search** workspace eliminates the error-prone complexity of authoring raw LDAP filters while maintaining the full expressive power of LDAP v3 RFC 4515 syntax.

```
                      +-----------------------------+
                      |   Search Base (Root DN)     |
                      +--------------+--------------+
                                     |
               +---------------------+---------------------+
               |                                           |
     [Search Presets]                             [Condition Builder]
     - All Users                                  - Attribute: displayName
     - Locked Accounts                            - Operator:  starts with
     - Passwords Never Expire                     - Value:     John
     - SPN Service Accounts                                |
               |                                           |
               +---------------------+---------------------+
                                     |
                                     v
                       +---------------------------+
                       |    Raw LDAP Filter Box    |
                       | (&(objectClass=user)...)  |
                       +-------------+-------------+
                                     |
                                     v
                       +---------------------------+
                       |   Execute (Invoke-Ldap)   |
                       +---------------------------+
```

#### Search Scopes
1. **Subtree (Default)**: Searches the target Base DN and all nested child containers and OUs recursively.
2. **OneLevel**: Searches only immediate direct children of the target Base DN.
3. **Base**: Evaluates only the exact object specified by the Base DN.

#### Condition Builder Operators
- `=` (Exact match): Generates `(attribute=value)`
- `starts with` (Prefix): Generates `(attribute=value*)`
- `ends with` (Suffix): Generates `(attribute=*value)`
- `contains` (Substring): Generates `(attribute=*value*)`
- `* is present` (Presence): Generates `(attribute=*)`
- `!=` (Negation): Generates `(!(attribute=value))`

#### LDAP Filter Syntax Quick Reference
| Target Query | RFC 4515 LDAP Filter String |
| :--- | :--- |
| All Active Users | `(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))` |
| Disabled Users | `(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))` |
| Locked Accounts | `(&(objectCategory=person)(objectClass=user)(lockoutTime>=1))` |
| Passwords Never Expire | `(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))` |
| Empty Security Groups | `(&(objectCategory=group)(!member=*))` |
| Accounts with SPN (Kerberoasting targets) | `(&(servicePrincipalName=*)(!(objectClass=computer)))` |
| Nested Group Membership (Recursive) | `(memberOf:1.2.840.113556.1.4.1941:=CN=IT-Admins,OU=Groups,DC=corp,DC=example,DC=com)` |
| Domain Controllers | `(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))` |

---

### 4.2. LDAP-SQL Console

The **LDAP-SQL Console** provides SysAdmins with a familiar SQL dialect to query directory information without wrestling with complex parenthetical LDAP filters.

#### Grammar Specification
```sql
SELECT <attribute1>, <attribute2>, ... 
FROM [SUBTREE | ONELEVEL | BASE] 
WHERE <condition1> [AND <condition2> ...]
[LIMIT <n>]
```

#### SQL Operator Mapping
- `field = 'val'` $\rightarrow$ `(field=val)`
- `field != 'val'` $\rightarrow$ `(!(field=val))`
- `field LIKE 'val%'` $\rightarrow$ `(field=val*)`
- `field LIKE '%val%'` $\rightarrow$ `(field=*val*)`
- `field IS NULL` $\rightarrow$ `(!(field=*))`
- `field IS NOT NULL` $\rightarrow$ `(field=*)`

#### Example SQL Queries
```sql
-- Query 1: Find all users in Finance department
SELECT sAMAccountName, displayName, mail, title 
FROM SUBTREE 
WHERE objectClass = 'user' AND department = 'Finance'

-- Query 2: Retrieve all servers running Windows Server 2022
SELECT name, dNSHostName, operatingSystem, operatingSystemVersion 
FROM SUBTREE 
WHERE objectClass = 'computer' AND operatingSystem LIKE 'Windows Server 2022%'

-- Query 3: List privileged accounts with adminCount = 1
SELECT sAMAccountName, displayName, adminCount, lastLogonTimestamp 
FROM SUBTREE 
WHERE adminCount = '1'
```

---

### 4.3. Raw Attribute Editor & UAC Bitmask Decoder

The **Attribute Editor** displays every attribute attached to an object, including operational attributes (system-calculated metadata not returned by default searches).

```
+------------------------------------------------------------------------------------+
|  Attribute Name      | Value (Decoded)               | Type           | Flags      |
+----------------------+-------------------------------+----------------+------------+
| sAMAccountName       | jdoe                          | String         | Single     |
| userAccountControl   | 512 (0x0200: NORMAL_ACCOUNT)  | Integer        | Bitmask    |
| proxyAddresses       | smtp:jdoe@corp.example.com;.. | MultiValued    | Array [3]  |
| pwdLastSet           | 2026-09-18 14:22:01 UTC       | LargeInteger   | FileTime   |
| objectSid            | S-1-5-21-3829102-19283-1002   | OctetString    | SecurityID |
+------------------------------------------------------------------------------------+
```

#### Multi-Mode Editing Dialog
When double-clicking an attribute or clicking **Edit Value**:
1. **Mode 1: String / Scalar Editor**:
   - For standard strings, numbers, and dates. Includes a quick **Clear Value** button.
2. **Mode 2: Multi-Valued Array Editor**:
   - Displays all entries in a list (e.g. `memberOf`, `proxyAddresses`, `otherHomePhone`).
   - Supports adding new discrete values and removing selected entries without overwriting existing data.
3. **Mode 3: UAC Bitmask Editor**:
   - Interactive checkbox tree of all 18 standard Microsoft UserAccountControl flags.
   - Dynamically recomputes the decimal and hexadecimal bitwise sum in real time.
   - Built-in one-click presets:
     - *Normal User Account*: `512 (0x0200)`
     - *Disabled User Account*: `514 (0x0202)`
     - *Toggle Password Never Expires*: Adds/removes `65536 (0x10000)`

#### Microsoft UserAccountControl (UAC) Flag Matrix
| Hex Value | Decimal | Flag Identifier | Security Description |
| :--- | :--- | :--- | :--- |
| `0x0001` | 1 | `SCRIPT` | Logon script executed |
| `0x0002` | 2 | `ACCOUNTDISABLE` | The user account is disabled |
| `0x0008` | 8 | `HOMEDIR_REQUIRED` | Home folder is mandatory |
| `0x0010` | 16 | `LOCKOUT` | Account is currently locked out by policy |
| `0x0020` | 32 | `PASSWD_NOTREQD` | No password is required (High Risk!) |
| `0x0040` | 64 | `PASSWD_CANT_CHANGE` | User cannot change their password |
| `0x0200` | 512 | `NORMAL_ACCOUNT` | Standard typical user account |
| `0x0800` | 2048 | `INTERDOMAIN_TRUST_ACCOUNT` | Domain trust partner account |
| `0x1000` | 4096 | `WORKSTATION_TRUST_ACCOUNT` | Computer join account |
| `0x2000` | 8192 | `SERVER_TRUST_ACCOUNT` | Domain Controller computer account |
| `0x10000` | 65536 | `DONT_EXPIRE_PASSWORD` | Password does not age/expire |
| `0x40000` | 262144 | `SMARTCARD_REQUIRED` | Smartcard required for interactive logon |
| `0x80000` | 524288 | `TRUSTED_FOR_DELEGATION` | Account is trusted for Kerberos delegation |
| `0x100000` | 1048576 | `NOT_DELEGATED` | Sensitive account - cannot be delegated |
| `0x400000` | 4194304 | `DONT_REQ_PREAUTH` | Kerberos Pre-Authentication disabled (AS-REP target!) |

---

### 4.4. Object Compare & Diff Engine

The **Object Compare** tool reconciles differences between two directory objects (e.g. comparing a template user against a newly provisioned user, or comparing two Domain Controllers).

#### Reconciliation Status Badges
- 🟢 **Identical**: Attribute values match exactly in both objects.
- 🟡 **Different**: Both objects possess the attribute, but values differ.
- 🔴 **Only in Object A**: Attribute is populated in Object A, but absent or null in Object B.
- 🔵 **Only in Object B**: Attribute is populated in Object B, but absent or null in Object A.

SysAdmins can check **Show Differences Only** to instantly isolate drift and click **Export Diff to CSV** to document compliance audits.

---

### 4.5. RFC 2849 LDIF Studio

The **LDIF Studio** enables bulk directory transformations via standard LDAP Data Interchange Format scripts.

#### Safety Architecture: Two-Stage Execution
1. **Stage 1 (Dry-Run / Syntax Validation)**:
   - Verifies RFC 2849 syntax, directive markers (`changetype:`, `replace:`, `-`), and attribute delimiters.
   - Simulates modifications against directory schema without applying changes.
2. **Stage 2 (Live Execution)**:
   - Prompts for explicit SysAdmin confirmation.
   - Executes atomic modifications and outputs a real-time transaction log.

#### LDIF Template: Modifying an Account
```ldif
dn: CN=John Doe,OU=Users,DC=corp,DC=example,DC=com
changetype: modify
replace: department
department: Global Infrastructure
-
replace: title
title: Principal Systems Architect
-
replace: mail
mail: jdoe@corp.example.com
-
```

#### LDIF Template: Provisioning a New Account
```ldif
dn: CN=Alice Smith,OU=Engineering,DC=corp,DC=example,DC=com
changetype: add
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Alice Smith
givenName: Alice
sn: Smith
displayName: Alice Smith
sAMAccountName: asmith
userPrincipalName: asmith@corp.example.com
userAccountControl: 512
```

---

### 4.6. Directory Security Audits & Executive Reports

The **Security Audits** workspace automates standard directory health and vulnerability assessments.

#### Audit Categories
1. **Inactive Users**: Identifies accounts that have not logged on within a specified threshold (30, 60, 90, or 180 days).
2. **Passwords Never Expire**: Detects accounts with `DONT_EXPIRE_PASSWORD` enabled (`0x10000`).
3. **Locked Out Accounts**: Pinpoints accounts locked out due to invalid credential storms or brute-force attempts.
4. **Privileged Accounts (Admins)**: Audits accounts with `adminCount = 1` protected by AdminSDHolder.
5. **Empty Groups**: Identifies orphaned security groups with 0 members that clutter ACLs.
6. **Unprotected OUs**: Discovers Organizational Units missing the accidental deletion protection flag.
7. **Service Accounts (SPNs)**: Catalogs user accounts containing Service Principal Names (Kerberoasting attack surface).
8. **Inactive Computers**: Identifies stale computer accounts that haven't synchronized computer passwords with the domain.

#### Executive HTML Reports
Clicking **HTML Executive Report** compiles an interactive report complete with:
- Target Domain and Audit Category Header.
- Security Risk Severity rating (Critical, High, Medium, Low).
- Tabular findings with Distinguished Names and timestamps.
- Actionable **SysAdmin Remediation Steps**.

---

### 4.7. Active Directory Schema Browser

The **Schema Browser** queries the Schema Partition (`CN=Schema,CN=Configuration,DC=...`) to provide quick reference to:
- **Object Classes**:
  - Class Name, OID, Superior Classes, Class Type (*Structural*, *Abstract*, *Auxiliary*).
- **Attribute Types**:
  - Attribute Name, OID, Syntax (e.g. Unicode String, Integer, Generalized Time, Octet String), and Multi-Valued flag.

---

### 4.8. Connection Profiles & Live Diagnostics

Manage multiple Active Directory connection profiles (e.g. Production Forest, Lab Domain, DMZ Forest).

#### Live Diagnostic Metrics
- **Target Server**: Resolves FQDN and IP address via DNS.
- **Port Status**: Tests TCP socket connection on Port 389 (LDAP), 636 (LDAPS), or 3268 (GC).
- **Round-Trip Latency**: Measures precise millisecond response time.
- **RootDSE Verification**: Reads `defaultNamingContext`, `configurationNamingContext`, and `dnsHostName`.

---

### 4.9. Specialized Attribute Processors & Editors

The **Attribute Editor** modal (`AttributeEditDialog.xaml`) automatically routes attributes to specialized interactive processors based on LDAP syntax and attribute name:

1. **UserAccountControl (UAC) Bitmask Editor**:
   - Interactive checkbox grid covering key flags (`ACCOUNTDISABLE`, `LOCKOUT`, `DONT_EXPIRE_PASSWORD`, `SMARTCARD_REQUIRED`, `TRUSTED_FOR_DELEGATION`, etc.).
   - Live recalculation of Decimal, Hexadecimal, and Bitmask values with safe single-click toggling.
2. **Photo & Avatar Editor (`jpegPhoto`, `thumbnailPhoto`)**:
   - Renders image previews directly from raw byte arrays.
   - Provides **Import Photo** (JPEG/PNG with file size telemetry) and **Export Photo** to disk.
3. **X.509 Digital Certificate Viewer (`userCertificate`, `cACertificate`)**:
   - Parses DER/ASN.1 byte stream into a `[System.Security.Cryptography.X509Certificates.X509Certificate2]` object.
   - Displays Subject, Issuer, Serial Number, Thumbprint, and Validity Period.
   - Integrates with the native Windows Certificate Details viewer (`X509Certificate2UI.DisplayStore`).
4. **Hex & Binary Viewer**:
   - Byte-level hexadecimal dump with ASCII inspection pane and raw binary export.

---

### 4.10. Directory Basket (Cross-OU Object Staging Cart)

The **Directory Basket** (`NavBasket`) enables staged multi-object operations across disparate Organizational Units and object types:
- **Staging**: Click **🧺 Add to Basket** from Users, Groups, Computers, or Directory Search results grids.
- **Batch Attribute Override**: Bulk apply an attribute name/value pair across all staged objects.
- **Batch Status Toggle**: Instantly enable or disable all staged user accounts.
- **Batch OU Relocation**: Relocate all staged objects to a selected destination OU in a single operation.
- **Cart Export**: Export staged objects directly to CSV or RFC 2849 LDIF.

---

### 4.11. Operational Attributes & Live Protocol Request Logger

1. **Operational Attributes Toggle**:
   - In the **Attribute Editor**, the **Show Operational Attributes** checkbox requests server-managed constructed attributes (`canonicalName`, `createTimeStamp`, `modifyTimeStamp`, `structuralObjectClass`, `subschemaSubentry`) via explicit ADSI cache refresh.
2. **Protocol Wire Request Log (`NavRequestLog`)**:
   - Captures live LDAP transactions in real-time.
   - Logs timestamp, operation name (`Search`, `Modify`, `LdifImport`, `SchemaExport`), Base DN, Scope, LDAP Filter, Target Server, Latency (ms), and Status.
   - Provides text filtering, details inspection pane, clipboard export, and clear log.

---

### 4.12. Schema Definition Exporter

In the **Schema Browser**, administrators can export Active Directory classes and attribute definitions to standard formats:
- **Export to OpenLDAP (`.schema`)**: Generates RFC 4512 compliant `objectclass` and `attributetype` definitions compatible with OpenLDAP server configurations.
- **Export to RFC 2849 LDIF (`.ldif`)**: Generates schema definitions ready for directory ingestion or backup.

---

### 4.13. Headless Automation CLI (`tools/ad-studio-cli.ps1`)

The standalone command-line engine enables headless unattended operation for CI/CD pipelines, automated security assessments, and scheduled tasks:

```powershell
# Export directory objects to CSV/JSON/LDIF
.\tools\ad-studio-cli.ps1 -Export -Filter "(objectClass=user)" -Format CSV -OutFile "C:\exports\users.csv"

# Validate or execute an RFC 2849 LDIF script
.\tools\ad-studio-cli.ps1 -ImportLDIF -InFile "C:\scripts\bulk_depts.ldif" -DryRun
.\tools\ad-studio-cli.ps1 -ImportLDIF -InFile "C:\scripts\bulk_depts.ldif"

# Run security & hygiene audit and export executive HTML report
.\tools\ad-studio-cli.ps1 -Audit -Category All -OutReport "C:\reports\security_audit.html"

# Run LDAP-SQL query
.\tools\ad-studio-cli.ps1 -QuerySQL -Query "SELECT sAMAccountName, mail FROM 'DC=example,DC=com' WHERE objectClass = 'user'"
```

---

## 5. Standard Directory Administration Workflows

### 5.1. Provisioning a New User
1. Navigate to **Users** and click **➕ New User**.
2. Enter **First Name** and **Last Name**. Click **Suggest** to auto-generate the username and UPN based on configured company policy (e.g. `first.last`).
3. Set optional contact and organizational properties (Department, Title, Employee ID).
4. Password is generated automatically with 16 cryptographically strong characters (`New-SecurePassword`).
5. Select the target **Organizational Unit** and click **Create User**.

### 5.2. Resetting a User Password
1. Select the user in the **Users** grid and click **🔑 Reset PW**.
2. Either accept the automatically generated secure password or enter a custom one.
3. Ensure **Require password change at next logon** is selected.
4. Check **Unlock Account** if the user was locked out.
5. Click **Confirm Reset**.

### 5.3. Managing Group Membership
1. Navigate to **Groups**, select the desired group, and click **👥 Manage Members**.
2. View existing members in the right panel.
3. Search for new members in the search box, select the target user, and click **➕ Add Member**.
4. To remove, select an existing member and click **➖ Remove Member**.

### 5.4. Moving Objects Across OUs
1. Select a user or computer in their respective grid.
2. Click **📂 Move OU**.
3. Select the target OU from the dropdown tree and click **Confirm Move**.

---

## 6. Security, Privacy & Enterprise Hardening

### Credentials & SSO
- **Default Authentication**: Active Directory Management Studio utilizes current Windows session tokens (Kerberos Single Sign-On). No plaintext passwords are saved to disk.
- **Privacy Protections**: The application never transmits telemetry outside the local network. Custom domain names and server configurations remain exclusively on the local machine.

### Accidental Deletion Protection
All OUs created through the studio have the `ProtectedFromAccidentalDeletion` flag enabled by default. When an administrator requests OU deletion, the studio prompts for confirmation and executes an explicit unprotection step before removing the container.

---

## 7. Troubleshooting Matrix

| Issue | Root Cause | Solution |
| :--- | :--- | :--- |
| **"Not Connected to AD"** | Workstation is not domain-joined or DC is unreachable. | Use **Connections** tab to specify a DC IP and verify TCP Port 389 is open through firewalls. |
| **"RSAT Module Not Found"** | `RSAT-AD-PowerShell` is not installed on Windows 10/11. | No action required: The studio automatically activates ADSI / .NET fallback mode. To enable full RSAT, run: `Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0`. |
| **"Access Denied (0x5)"** | Current Windows user lacks permission for the requested action. | Run PowerShell as an account in `Domain Admins`, `Account Operators`, or with delegated OU permissions. |
| **"Constraint Violation (0x13)"** | Password does not meet domain password policy (complexity, length, or history). | Adjust password length in **Settings** or ensure password contains uppercase, lowercase, numbers, and symbols. |
| **"Invalid Attribute Syntax"** | Data entered does not match attribute schema (e.g. invalid date or GUID). | Use the **Raw Attribute Editor** to inspect the expected syntax and count. |

---

## 8. License & Attribution

- **Project**: Active Directory Management Studio
- **Author**: Catmuf (`catmuf@gmail.com`)
- **Repository**: [github.com/catmuf/ad-management-studio](https://github.com/catmuf/ad-management-studio.git)
- **Documentation**: [github.com/catmuf/ad-management-studio/wiki](https://github.com/catmuf/ad-management-studio/wiki)
- **License**: MIT License - Free for enterprise, commercial, and personal administration.
