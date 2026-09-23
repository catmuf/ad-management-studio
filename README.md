# Active Directory Management Studio

A modern, high-performance PowerShell application built with **WPF (Windows Presentation Foundation) & XAML** for managing Microsoft Windows Server Active Directory environments.

![Platform](https://img.shields.io/badge/Platform-Windows%20Server%20%7C%20Windows%2010%2F11-blue)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1%20%7C%207%2B-blue)
![Architecture](https://img.shields.io/badge/UI-WPF%20%2F%20XAML-green)

---

## ✨ Features

### 👥 User Management
- **Instant Search & Filter**: Real-time search across Name, SamAccountName, Email, Employee ID, Title, and Description.
- **Account Status Filtering**: Quick filter chips for *All*, *Active*, *Disabled*, and *Locked Out* accounts.
- **OU Scope Filtering**: Filter directory search results by selected Organizational Unit or across the entire domain.
- **Full User Lifecycle**:
  - **Create User**: Multi-tab dialog covering profile details, UPN, auto-generated usernames, cryptographically secure password generation, organizational attributes, and target OU placement.
  - **Edit User**: Modify existing user properties, job titles, department, office, contact details, and employee IDs.
  - **Inspect / View Details**: Comprehensive user inspector showing account metadata, SID, GUID, creation/modification timestamps, logon statistics, and group memberships.
  - **Reset Password**: Reset account password with 1-click password generation, complexity validation, unlock toggle, and "must change at next logon" options.
  - **Unlock Account**: Instantly unlock accounts locked by failed logon attempts.
  - **Enable / Disable**: Toggle account status with safety prompts and color-coded status badges.
  - **Move OU**: Move users between Organizational Units.
  - **Delete User**: Permanent account deletion protected by explicit confirmation prompts.
  - **Export to CSV**: Export user inventories to CSV/Excel with UTF-8 encoding and customizable delimiters.

### 🛡️ Group Management
- **Browse & Search Groups**: List security and distribution groups across all scopes (*Global*, *Universal*, *Domain Local*).
- **Create & Delete Groups**: Create new security or distribution groups in any target OU.
- **Membership Management**:
  - View real-time group members.
  - Search domain principals to add members.
  - Remove members with confirmation.
- **Export Groups**: Export group lists to CSV.

### 📁 Organizational Unit (OU) Management
- **Directory Tree Explorer**: Hierarchical, interactive TreeView of the entire domain OU structure.
- **OU Object Inspection**: Click on any OU to view all contained users and groups.
- **Create OU**: Create child OUs with custom descriptions and accidental deletion protection.
- **Delete OU**: Safe deletion with safeguards for accidental deletion flags.

### 📊 Health Dashboard & Quick Audits
- Real-time directory KPI summary cards:
  - Total Users, Active Users, Disabled Users, Locked Accounts, Total Groups, and Total OUs.
- Interactive cards: Clicking any card instantly filters the relevant view (e.g. click *Locked Accounts* to immediately view and unlock locked users).

---

## 🚀 Getting Started

### Prerequisites
1. **Windows PowerShell 5.1** or **PowerShell 7+** on Windows Server (2016/2019/2022/2025) or Windows 10/11.
2. Active Directory PowerShell module (`RSAT-AD-PowerShell`).
3. Domain member computer or Domain Controller with appropriate administrative permissions.

### Running the Application

Simply launch `main.ps1`:

```powershell
# From PowerShell
.\main.ps1
```

Alternatively, right-click `main.ps1` and select **Run with PowerShell**.

---

## 📁 Project Architecture

```
user-management/
├── main.ps1                   # Application entrypoint & STA launcher
├── config.json                # Application configuration & domain settings
├── Modules/
│   ├── ADService.psm1         # Active Directory data operations (Users, Groups, OUs, Stats)
│   ├── ValidationService.psm1 # Password complexity, random generator, email & username sanitization
│   ├── ExportService.psm1     # CSV/Excel export engine
│   └── ConfigService.psm1     # JSON settings persistence & domain auto-discovery
├── Views/
│   ├── MainWindow.xaml        # Main window layout (Header, Sidebar, Tab panels, Status bar)
│   ├── UserDialog.xaml        # User creation and modification modal
│   ├── UserDetailDialog.xaml  # User inspection and group membership viewer
│   ├── PasswordDialog.xaml    # Password reset and generator modal
│   ├── GroupDialog.xaml       # Group creation and settings modal
│   ├── MemberDialog.xaml      # Group membership manager modal
│   ├── OUDialog.xaml          # Organizational Unit creation modal
│   └── MoveDialog.xaml        # Object OU mover modal
└── README.md                  # Documentation
```

---

## ⚙️ Configuration

Settings can be managed directly in the application's **Settings** tab or in `config.json`:

```json
{
  "Domain": {
    "AutoDetect": true,
    "DomainName": "vielcahp.com",
    "DomainController": "",
    "SearchBase": "",
    "DisableOU": ""
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
    "ExportDelimiter": ";",
    "ExportPath": ""
  }
}
```
