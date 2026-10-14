# Active Directory Management Studio
### Enterprise Directory Management & Softerra LDAP Administrator Suite

A modern, high-performance administration suite built with **PowerShell & WPF/XAML** for managing Microsoft Active Directory and LDAP environments. Engineered for Systems Administrators, Security Engineers, and Directory Operators who require both daily standard administration and advanced low-level directory tooling.

![Platform](https://img.shields.io/badge/Platform-Windows%20Server%20%7C%20Windows%2010%2F11-blue)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1%20%7C%207%2B-blue)
![Architecture](https://img.shields.io/badge/UI-WPF%20%2F%20XAML-green)
![LDAP](https://img.shields.io/badge/LDAP-RFC%204511%20%7C%20RFC%202849-orange)
[![Handbook](https://img.shields.io/badge/Manual-SysAdmin%20Handbook-purple)](HANDBOOK.md)
[![Walkthrough](https://img.shields.io/badge/Guide-Visual%20Walkthrough-blue)](WALKTHROUGH.md)
[![Wiki](https://img.shields.io/badge/Documentation-Wiki-orange)](https://github.com/catmuf/ad-management-studio/wiki)

---

## ⚡ Key Highlights & Capabilities

### 🛠️ Softerra LDAP & Apache Directory Studio Feature Equivalence
- **Visual LDAP Filter Builder**: Construct complex RFC 4515 LDAP search filters visually with AND/OR/NOT condition blocks and presets for locked accounts, disabled users, empty groups, Kerberos SPNs, and recursive nested memberships (`1.2.840.113556.1.4.1941`).
- **Directory Basket**: Cross-OU object staging cart for performing staged bulk attribute updates, status toggling, OU migrations, and CSV/LDIF exports.
- **Specialized Attribute Processors**: Dedicated editors for `userAccountControl` bitmask flags, Photo/Avatar JPEG/PNG import/export, X.509 Digital Certificates (native Windows viewer integration), Hex/Binary viewer, and operational attributes.
- **LDAP-SQL Console**: Query directory objects using familiar ANSI-SQL grammar (`SELECT ... FROM ... WHERE ...`) with instant export to CSV, JSON, and LDIF.
- **Protocol Wire Request Logger**: Live real-time LDAP protocol request and latency monitor with search filter, details inspector, and clipboard export.
- **Object Compare & Diff**: Attribute-by-attribute side-by-side comparison between any two directory objects with difference isolation and drift reports.
- **RFC 2849 LDIF Studio**: In-app editor for LDIF import/export scripts featuring a two-stage safety model (Dry-Run simulation before live execution).
- **Security Audits & Executive Reports**: Automated security posture audits (including AdminSDHolder/adminCount=1) with styled HTML executive reports and remediation advice.
- **AD Schema Browser & Exporter**: Browse Active Directory classes and syntaxes, and export schema definitions to OpenLDAP (`.schema`) and RFC 2849 LDIF.
- **Headless Automation CLI (`tools/ad-studio-cli.ps1`)**: Unattended command-line engine for exports, LDIF execution, scheduled hygiene audits, and LDAP-SQL queries.
- **Connection Profiles & Diagnostics**: Multi-domain / multi-controller profiles, custom ports (389, 636 LDAPS, 3268 GC), and real-time TCP socket, latency, and RootDSE diagnostics.

### 👥 Complete Active Directory Lifecycle Operations
- **Users**: Account provisioning, templates, password reset, unlock, enable/disable, and OU relocation.
- **Groups**: Security and distribution group management, scopes (Global, Universal, Domain Local), and interactive member rosters.
- **Organizational Units (OUs)**: Hierarchical directory tree navigation, OU creation, accidental deletion safeguard, and contained object inspection.
- **Computers**: Domain workstation and server inventory, operating systems, versions, and logon tracking.
- **Dashboard**: Live directory health KPI cards with interactive drill-down navigation and PDC latency telemetry.

---

## 📖 Documentation & Guides

- Consult the [**SysAdmin Handbook (HANDBOOK.md)**](HANDBOOK.md) for technical architecture, RFC compliance, schema references, and CLI automation.
- Follow the [**Visual Operator Walkthrough (WALKTHROUGH.md)**](WALKTHROUGH.md) for 10 step-by-step real-world scenarios illustrated with Light theme screenshots.

---

## 🚀 Quick Start

### Prerequisites
- **Windows Server (2016-2025)** or **Windows 10/11**
- **Windows PowerShell 5.1** or **PowerShell 7.2+**
- Active Directory domain connection (RSAT module or native ADSI fallback)

### Launching the Application
```powershell
# Clone the repository
git clone git@github.com:catmuf/ad-management-studio.git
cd ad-management-studio

# Launch Active Directory Management Studio in STA mode
.\main.ps1

# Run headless automation CLI
.\tools\ad-studio-cli.ps1 -Audit -Category All -OutReport "audit.html"
```

---

## 📁 Repository Structure

```
ad-management-studio/
├── main.ps1                   # Application entrypoint & STA launcher
├── HANDBOOK.md                # Comprehensive SysAdmin Handbook & Technical Architecture
├── WALKTHROUGH.md             # Step-by-step Visual Operator Walkthrough (10 Scenarios)
├── README.md                  # Project overview and quick start
├── config.json                # Application configuration & connection profiles
├── docs/
│   └── images/                # 10 High-resolution Light theme application screenshots
├── tools/
│   ├── ad-studio-cli.ps1      # Headless automation CLI (export, LDIF, audit, SQL, diagnostics)
│   └── Capture-AppScreenshots.ps1 # Automated WPF Light theme screen capture engine
├── Modules/
│   ├── ADService.psm1         # LDAP engine, RSAT/ADSI bridge, SQL, LDIF, Compare, 48 Audits
│   ├── AclService.psm1        # 6-Way Effective Rights matrix, DACL/SACL, AdminSDHolder
│   ├── KerberosService.psm1   # PAC Bloat formula, MaxTokenSize, ticket cache inspector
│   ├── DiagnosticService.psm1 # DFS circular group loop detector, lockout tracer, group diff
│   ├── NetworkService.psm1    # 7-Tier sequential UNC share verifier, 8-port DC latency matrix
│   ├── ScimFilterService.psm1 # Bidirectional RFC 7644 SCIM to RFC 4515 LDAP filter compiler
│   ├── ScimService.psm1       # SCIM 2.0 Core/Enterprise schema models and bulk processing
│   ├── SpecializedEditorService.psm1 # Hex/Binary dump, X.509 certs, photo cropping, date/hash
│   ├── TemplateService.psm1   # Provisioning templates, macro expansions, collision resolution
│   ├── ValidationService.psm1 # UAC bitmask, LargeInteger, GUID, SID, LDAP filter validation
│   ├── ExportService.psm1     # CSV, JSON, LDIF, and HTML Executive Report exporter
│   ├── ConfigService.psm1     # Settings persistence, Profiles, and RootDSE discovery
│   ├── GpoService.psm1        # GPO SYSVOL consistency and versioning checker
│   └── LoggingService.psm1    # ISO 8601 millisecond logger (logs/YYYY-MM-DD.log)
├── Views/
│   ├── MainWindow.xaml        # Central workspace (24 workspaces, Light/Dark theme, telemetry)
│   ├── SpecializedEditorDialog.xaml # Hex dump, X.509 CRL/OCSP cert, photo, timestamp, hasher
│   ├── AclBrowserDialog.xaml  # Advanced ACL browser and 6-Way Effective Rights modal
│   ├── GpoExplorerDialog.xaml # GPO consistency and policy explorer modal
│   ├── AttributeEditDialog.xaml # Multi-mode attribute editor
│   ├── ColumnChooserDialog.xaml # DataGrid dynamic column customizer modal
│   ├── ConnectionDialog.xaml  # Connection profile modal with live TCP diagnostics
│   ├── UserDialog.xaml        # User provisioning and modification modal
│   ├── UserDetailDialog.xaml  # User inspection and group membership viewer
│   ├── PasswordDialog.xaml    # Password reset and generator modal
│   ├── GroupDialog.xaml       # Group creation and settings modal
│   ├── MemberDialog.xaml      # Group membership manager modal
│   ├── OUDialog.xaml          # Organizational Unit creation modal
│   └── MoveDialog.xaml        # Object OU mover modal
└── tests/                     # Automated Pester/PowerShell test suites (265+ assertions)
```

---

## ⚙️ Configuration Reference

Application settings and profiles are stored in `config.json`:

```json
{
  "Domain": {
    "AutoDetect": true,
    "DomainName": "",
    "DomainController": "",
    "SearchBase": ""
  },
  "UI": {
    "Theme": "Light",
    "AutoRefresh": false,
    "RefreshIntervalSeconds": 60,
    "PageSize": 500
  },
  "Defaults": {
    "PasswordLength": 16,
    "PasswordRequireChange": true,
    "UsernameFormat": "first.last",
    "ExportDelimiter": ";"
  },
  "Profiles": []
}
```

---

## 🛡️ Security & Privacy Notice

- **Authentication**: Uses Windows Single Sign-On (Kerberos / NTLM). No credentials are saved in plaintext.
- **Zero Telemetry**: All queries run strictly between your administrative workstation and your configured Domain Controllers.
- **Safe Defaults**: All created Organizational Units are protected against accidental deletion by default.

---

## 📄 License & Attribution

- **Author**: Catmuf (`catmuf@gmail.com`)
- **License**: MIT License
- **Documentation**: [SysAdmin Handbook](HANDBOOK.md) | [Visual Walkthrough](WALKTHROUGH.md) | [Project Wiki](https://github.com/catmuf/ad-management-studio/wiki)
