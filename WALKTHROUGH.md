# Active Directory Management Studio - Walkthrough & Summary

## 🌟 Executive Summary
The legacy PowerShell Active Directory management tool has been completely redesigned and modernized from the ground up into **Active Directory Management Studio** — a high-performance Windows Server administration suite featuring a modern **WPF (Windows Presentation Foundation) & XAML** interface.

The application replaces dated 1990s-style fixed-dialog Windows Forms scripts, hardcoded pixel coordinates, missing CSV dependencies, and domain-specific text files with a clean, responsive, modular architecture providing complete management of **Users, Groups, and entire Organizational Unit (OU) hierarchies**.

---

## 🛠️ Key Improvements & Features

### 1. Modern User Interface (WPF / XAML)
- **Windows 11 / Slate Dark Aesthetic**: High-contrast, polished dark theme with crisp typography (`Segoe UI`), smooth card containers, and visual status badges (Active [Green], Disabled [Red], Locked [Orange]).
- **Responsive & DPI Aware**: Fluid layout using WPF Grids and DockPanels that automatically scales across monitors and screen resolutions.
- **Top Header & Domain Telemetry**: Live indicators showing the connected domain (`vielcahp.com`), active Domain Controller (`VS-DC-01.vielcahp.com`), connection status dot, and global refresh.
- **Sidebar Navigation**: Dedicated views for **Dashboard**, **Users**, **Groups**, **Org. Units (OUs)**, and **Settings**.

---

### 2. User Lifecycle Management
- **Search & Live Filtering**: Instant search across Display Name, Username (`SamAccountName`), Email, Employee ID, Title, and Description.
- **Filter Chips**: Filter by *All Statuses*, *Active Only*, *Disabled Only*, and *Locked Only*.
- **OU Scope Filtering**: Restrict searches to specific OUs or across the entire domain.
- **User Actions**:
  - **➕ New User**: Tabbed modal with profile fields, auto-generated username suggestions based on configurable naming conventions, cryptographically secure password generation, organizational roles, and target OU placement.
  - **✏️ Edit User**: Update existing personal, contact, and organizational fields.
  - **👁️ User Details**: Comprehensive inspector showing full object metadata (SID, GUID, creation date, modification date, last logon, password last set, and full list of group memberships).
  - **🔑 Reset Password**: Quick password reset with 1-click password generation, copy-to-clipboard, "must change at next logon", and unlock toggles.
  - **🔓 Unlock Account**: Instantly unlock accounts locked by password failure limits.
  - **⚡ Enable / Disable**: Toggle user state with safety confirmation prompts.
  - **📂 Move OU**: Transfer users to any other OU in the domain.
  - **🗑️ Delete User**: Permanent deletion protected by double confirmation modals.
  - **📤 Export to CSV**: Export filtered or complete user listings to UTF-8 CSV with custom delimiters (semicolon or comma).

---

### 3. Complete Group Management (Newly Added)
- **Group Browser**: View all security and distribution groups across all scopes (*Global*, *Universal*, *Domain Local*).
- **Group Actions**:
  - **➕ New Group**: Create groups in any OU with custom scope and category.
  - **👥 Manage Members**: Two-pane membership manager allowing administrators to view current members, search directory users, and add or remove members with 1 click.
  - **🗑️ Delete Group**: Safe group deletion with confirmation prompt.
  - **📤 Export Groups**: Export group inventories to CSV.

---

### 4. Interactive OU Hierarchy Explorer (Newly Added)
- **Recursive Directory Tree**: Interactive `TreeView` displaying the real Active Directory domain root and all nested Organizational Units.
- **OU Object Inspector**: Selecting any OU node immediately displays:
  - OU Canonical Name & Distinguished Name
  - Protection Status (*Protected from accidental deletion* badge)
  - DataGrid of all users and groups residing directly inside that OU.
- **➕ New OU**: Create new child OUs with custom descriptions and accidental deletion protection.
- **🗑️ Delete OU**: Safe deletion that can toggle protection upon explicit confirmation.

---

### 5. Dashboard & Quick Audits
- **KPI Summary Cards**:
  - **Total Users**: Real-time count of all registered directory accounts.
  - **Active Users**: Clickable card that switches to the Users tab with *Active Only* filtered.
  - **Disabled Users**: Clickable card that switches to the Users tab with *Disabled Only* filtered.
  - **Locked Out Accounts**: Clickable card that highlights locked accounts for quick unlocking.
  - **Total Groups**: Clickable card navigating to Group Management.
  - **Total OUs**: Clickable card navigating to the OU Tree Explorer.
- **Quick Action Bar**: 1-click triggers for New User, New Group, New OU, and Export.

---

## 📁 Clean & Modular Code Structure

All legacy monolithic WinForms scripts (`view*.ps1`) and hardcoded hospital text files have been cleanly retired and replaced:

```
user-management/
├── main.ps1                   # Application launcher and STA runner
├── config.json                # Modern JSON configuration
├── README.md                  # Detailed documentation and usage instructions
├── Modules/
│   ├── ADService.psm1         # Pure Active Directory data engine (CRUD for Users, Groups, OUs)
│   ├── ValidationService.psm1 # Password complexity, random generator, email/ID regex
│   ├── ExportService.psm1     # CSV/Excel export engine
│   └── ConfigService.psm1     # JSON configuration and domain auto-discovery
└── Views/
    ├── MainWindow.xaml        # App shell (Header, Sidebar, Dashboard, Users, Groups, OUs, Settings)
    ├── UserDialog.xaml        # Create / Edit User modal
    ├── UserDetailDialog.xaml  # User details & group memberships inspector
    ├── PasswordDialog.xaml    # Password reset & generator modal
    ├── GroupDialog.xaml       # Group creation modal
    ├── MemberDialog.xaml      # Group membership manager modal
    ├── OUDialog.xaml          # Organizational Unit creation modal
    └── MoveDialog.xaml        # Object OU mover modal
```

---

## 🧪 Verification & Results

Both **PowerShell 7 (`pwsh`)** and **Windows PowerShell 5.1 (`powershell.exe`)** were tested against the live domain:

| Test Case | Method | Result |
| :--- | :--- | :--- |
| **PowerShell Syntax & AST** | `[Language.Parser]::ParseFile()` on all `.psm1` and `.ps1` files | **Passed** (0 errors) |
| **XAML Schema Validation** | `[XamlReader]::Parse()` on all 8 `.xaml` files | **Passed** (All valid) |
| **Active Directory Integration** | Queried `vielcahp.com` via `ADService.psm1` | **Passed** (Found 284 Users, 575 Groups, 34 OUs) |
| **Dashboard KPI Metrics** | Executed `Get-ADDashboardStats` | **Passed** (284 Total, 120 Active, 164 Disabled, 0 Locked) |
| **Password Security** | `New-SecurePassword` + `Test-PasswordComplexity` | **Passed** (Score 4/4 complexity) |
| **Dual Runtime Compatibility** | Tested startup script on WinPS 5.1 and pwsh 7 | **Passed** (100% compatible) |

---

## 🚀 How to Run
In PowerShell:
```powershell
.\main.ps1
```
Or right-click `main.ps1` in Windows Explorer and select **Run with PowerShell**.
