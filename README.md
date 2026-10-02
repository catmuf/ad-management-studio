# Active Directory Management Studio
### Enterprise Directory Management & Softerra LDAP Administrator Suite

A modern, high-performance administration suite built with **PowerShell & WPF/XAML** for managing Microsoft Active Directory and LDAP environments. Engineered for Systems Administrators, Security Engineers, and Directory Operators who require both daily standard administration and advanced low-level directory tooling.

![Platform](https://img.shields.io/badge/Platform-Windows%20Server%20%7C%20Windows%2010%2F11-blue)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1%20%7C%207%2B-blue)
![Architecture](https://img.shields.io/badge/UI-WPF%20%2F%20XAML-green)
![LDAP](https://img.shields.io/badge/LDAP-RFC%204511%20%7C%20RFC%202849-orange)
[![Handbook](https://img.shields.io/badge/Manual-SysAdmin%20Handbook-purple)](HANDBOOK.md)
[![Wiki](https://img.shields.io/badge/Documentation-Wiki-orange)](https://github.com/catmuf/ad-management-studio/wiki)

---

## ⚡ Key Highlights & Capabilities

### 🛠️ Softerra LDAP Administrator 2026 Feature Equivalence
- **Visual LDAP Filter Builder**: Construct complex RFC 4515 LDAP search filters visually with presets for locked accounts, disabled users, empty groups, Kerberos SPNs, and recursive nested memberships (`1.2.840.113556.1.4.1941`).
- **LDAP-SQL Console**: Query directory objects using familiar ANSI-SQL grammar (`SELECT ... FROM ... WHERE ...`) with instant export to CSV, JSON, and LDIF.
- **Raw Attribute Editor & UAC Bitmask Decoder**: Inspect and modify single-valued, multi-valued arrays, and `userAccountControl` bitmask flags with live computed hex/dec values.
- **Object Compare & Diff**: Attribute-by-attribute side-by-side comparison between any two directory objects with difference isolation and drift reports.
- **RFC 2849 LDIF Studio**: In-app editor for LDIF import/export scripts featuring a two-stage safety model (Dry-Run simulation before live execution).
- **Security Audits & Executive Reports**: 8 automated security posture audits with styled HTML executive reports and remediation advice.
- **AD Schema Browser**: Browse Active Directory object classes and attribute syntaxes directly from the schema partition.
- **Bulk Operations Engine**: Mass batch updates, attribute overrides, status toggling, and OU migrations.
- **Connection Profiles & Diagnostics**: Multi-domain / multi-controller profiles, custom ports (389, 636 LDAPS, 3268 GC), and real-time TCP socket, latency, and RootDSE diagnostics.

### 👥 Complete Active Directory Lifecycle Operations
- **Users**: Account provisioning, templates, password reset, unlock, enable/disable, and OU relocation.
- **Groups**: Security and distribution group management, scopes (Global, Universal, Domain Local), and interactive member rosters.
- **Organizational Units (OUs)**: Hierarchical directory tree navigation, OU creation, accidental deletion safeguard, and contained object inspection.
- **Computers**: Domain workstation and server inventory, operating systems, versions, and logon tracking.
- **Dashboard**: Live directory health KPI cards with interactive drill-down navigation and PDC latency telemetry.

---

## 📖 SysAdmin Handbook

For detailed guides, LDAP filter recipes, SQL grammar, and UAC bitmask tables, consult the comprehensive [**SysAdmin Handbook (HANDBOOK.md)**](HANDBOOK.md).

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
```

---

## 📁 Repository Structure

```
ad-management-studio/
├── main.ps1                   # Application entrypoint & STA launcher
├── HANDBOOK.md                # Comprehensive SysAdmin Handbook & Operator Manual
├── config.json                # Application configuration & connection profiles
├── Modules/
│   ├── ADService.psm1         # LDAP engine, RSAT/ADSI bridge, SQL, LDIF, Compare, Audits
│   ├── ValidationService.psm1 # UAC bitmask, LargeInteger, GUID, SID, LDAP filter validation
│   ├── ExportService.psm1     # CSV, JSON, LDIF, and HTML Executive Report exporter
│   └── ConfigService.psm1     # Settings persistence, Profiles, and RootDSE discovery
├── Views/
│   ├── MainWindow.xaml        # Central workspace (15 panels, dark-mode, telemetry ribbon)
│   ├── AttributeEditDialog.xaml# Multi-mode attribute editor (Scalar, Multi-Valued, UAC)
│   ├── ConnectionDialog.xaml  # Connection profile modal with live TCP diagnostics
│   ├── UserDialog.xaml        # User provisioning and modification modal
│   ├── UserDetailDialog.xaml  # User inspection and group membership viewer
│   ├── PasswordDialog.xaml    # Password reset and generator modal
│   ├── GroupDialog.xaml       # Group creation and settings modal
│   ├── MemberDialog.xaml      # Group membership manager modal
│   ├── OUDialog.xaml          # Organizational Unit creation modal
│   └── MoveDialog.xaml        # Object OU mover modal
└── README.md                  # Project overview
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
    "Theme": "Dark",
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
- **Documentation**: [Project Wiki](https://github.com/catmuf/ad-management-studio/wiki) | [SysAdmin Handbook](HANDBOOK.md)
