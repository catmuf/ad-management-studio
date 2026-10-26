# Active Directory Management Studio (v3.4.0 Enterprise)
## Step-by-Step Operator Walkthrough & Visual User Guide
### Real-World Scenarios, Identity Workflows & Diagnostic Demonstrations

[📖 SysAdmin Handbook](HANDBOOK.md) | [🚀 Visual Operator Walkthrough](WALKTHROUGH.md) | [📁 Project README](README.md) | [📋 Changelog](CHANGELOG.md)

---

## Table of Contents

- [Introduction & Guide Objectives](#introduction--guide-objectives)
- [Scenario 1: Domain Health Assessment & Global KPI Dashboard](#scenario-1-domain-health-assessment--global-kpi-dashboard)
- [Scenario 2: User Lifecycle Management & Quick Attribute Inspector](#scenario-2-user-lifecycle-management--quick-attribute-inspector)
- [Scenario 3: Low-Level Attribute Engineering: Binary & Hex Dump Editor](#scenario-3-low-level-attribute-engineering-binary--hex-dump-editor)
- [Scenario 4: Cryptographic Auditing: X.509 Certificate Inspector](#scenario-4-cryptographic-auditing-x509-certificate-inspector)
- [Scenario 5: Cloud Identity Integration: SCIM 2.0 Query & Filter Studio](#scenario-5-cloud-identity-integration-scim-20-query--filter-studio)
- [Scenario 6: Access Control & Permissions: 6-Way Effective Rights](#scenario-6-access-control--permissions-6-way-effective-rights)
- [Scenario 7: Kerberos Authentication & PAC Bloat Troubleshooting](#scenario-7-kerberos-authentication--pac-bloat-troubleshooting)
- [Scenario 8: Forensic Graph Analysis: Circular Group Loop Detection](#scenario-8-forensic-graph-analysis-circular-group-loop-detection)
- [Scenario 9: Enterprise Security Posture & 48 Hygiene Audit Reports](#scenario-9-enterprise-security-posture--48-hygiene-audit-reports)
- [Scenario 10: Infrastructure Diagnostics: NetTools 7-Tier UNC Share Checker](#scenario-10-infrastructure-diagnostics-nettools-7-tier-unc-share-checker)
- [Scenario 11: Enterprise Directory Search, RFC 2696 Paging & Multi-Identity Dossier Tabs](#scenario-11-enterprise-directory-search-rfc-2696-paging--multi-identity-dossier-tabs)
- [Scenario 12: Competitor Parity Forensics: Omnibar 2.0, Client IP LPM Resolver, Group Member Diff & Duplicate SPNs](#scenario-12-competitor-parity-forensics-omnibar-20-client-ip-lpm-resolver-group-member-diff--duplicate-spns)
- [Conclusion & Best Practices](#conclusion--best-practices)

---

## Introduction & Guide Objectives

This Walkthrough provides step-by-step guidance for Systems Administrators, Directory Engineers, and Security Auditors. Every scenario is grounded with visual illustrations captured from the application in its factory default **Light Theme** presentation mode (`"Theme": "Light"` in `config.json`).

Light Theme provides an accessibility-audited, high-contrast palette featuring clean `#FFFFFF` surface cards, soft `#F8FAFC` background canvas, `#CBD5E1` border rules, and deep slate `#0F172A` typography. This ensures crystal-clear visibility when analyzing dense directory grids, raw hex streams, and complex permission matrices under standard daytime office lighting.

Each tutorial guides the operator from initial problem identification through investigation, diagnostic evaluation, and resolution.

---

## Scenario 1: Domain Health Assessment & Global KPI Dashboard

### Objective
Assess forest-wide Active Directory health, monitor key identity metrics, verify Domain Controller (DC) connectivity, and access quick-launch administrative tools.

![Active Directory Overview & Health Dashboard](docs/images/01_dashboard_overview.png)

### Step-by-Step Walkthrough
1. **Launch the Studio**:
   ```powershell
   pwsh -NoProfile -STA -File .\main.ps1
   ```
   The application initializes with sub-second streaming launch and loads directly into the default **Light Theme** presentation.
2. **Inspect the Active Directory Overview & Health View**:
   - The top KPI ribbon surfaces key directory metrics at a glance:
     * **Total Users**: Forest user account count (`1,248`).
     * **Active / Enabled**: Operational accounts ready for authentication (`1,180`).
     * **Disabled**: Decommissioned or archived accounts (`54`).
     * **Locked Out**: Accounts exceeding authentication failure thresholds (`14`).
     * **Groups**: Security and distribution groups (`185`).
     * **Computers**: Workstation and server inventory (`320`).
     * **Org. Units (OUs)**: Container hierarchy count.
3. **Review the Active Directory Environment Card**:
   - Confirms the Primary DC Emulator (PDCe) role holder (`corp-dc01.contoso.local`).
   - Confirms the Default Naming Context (`DC=contoso,DC=local`).
   - Verifies LDAP protocol capabilities (LDAP v3 RFC 4511 & LDAPS Port 636).
4. **Use Quick Launchpad**:
   - Click any quick-action card to jump directly to **Directory Search**, **LDAP-SQL Console**, **Raw Attribute Editor**, or **Security Audits**.
5. **Theme, Sidebar & Layout Controls**:
   - The top toolbar displays current session credentials and elevation status (`ELEVATED (ADMIN)`).
   - Operators can toggle between Light and Dark mode using `Ctrl+T` or the theme selector icon.
   - Press `Ctrl+B` or click the sidebar toggle button to collapse or expand the navigation menu for an expansive workspace view.

---

## Scenario 2: User Lifecycle Management & Quick Attribute Inspector

### Objective
Locate a user account, review identity properties via the slide-out Quick Inspector, unlock a locked user, and provision a new account using template macros.

![User Management Grid and Quick Attribute Inspector](docs/images/02_users_and_inspector.png)

### Step-by-Step Walkthrough
1. **Navigate to the Users Workspace**:
   - Click **Users** on the left navigation sidebar or press `Ctrl+2`.
2. **Search and Filter Accounts**:
   - In the search bar, type `alex.morgan` or a department name such as `IT Infrastructure`.
   - Click filter chips (`All`, `Active`, `Disabled`, `Locked`) to immediately isolate accounts requiring administrative intervention.
3. **Inspect Account via Quick Inspector Pane**:
   - Click on `Alex Morgan` in the data grid.
   - The slide-out right-hand dossier pane (`Quick Inspector`) instantly renders on a clean white `#FFFFFF` surface:
     * **Display Name**: `Alex Morgan`
     * **Username (`sAMAccountName`)**: `alex.morgan`
     * **Email**: `alex.morgan@contoso.com`
     * **Job Title**: `Senior Systems Architect`
     * **Department**: `IT Infrastructure`
     * **Full Distinguished Name (DN)**: `CN=Alex Morgan,OU=Engineers,OU=Staff,DC=contoso,DC=local`
4. **Execute Quick Actions**:
   - **🔑 Reset Password**: Prompts for a secure compliant password with option to force change at next logon.
   - **🔓 Unlock Account**: Immediately clears `lockoutTime` across domain controllers.
   - **⚡ Toggle Status**: Enables or disables the account, adjusting `userAccountControl` bitmask flags.
   - **🛒 Add to Basket**: Stages the object in the Directory Basket for multi-OU batch moves or bulk attribute updates.
5. **Light Theme Visual Note**:
   - High-contrast alternating rows (`#FFFFFF` and `#F8FAFC`) with emerald green status pills make active accounts instantly distinguishable from locked or disabled accounts.

---

## Scenario 3: Low-Level Attribute Engineering: Binary & Hex Dump Editor

### Objective
Inspect raw binary attribute data (e.g. `userCertificate`, `objectGUID`, `objectSid`), modify hex byte streams, and preview decoded ASCII and Base64 representations matching **Apache Directory Studio**.

![Specialized Hex and Binary Attribute Editor](docs/images/03_specialized_editor_hex.png)

### Step-by-Step Walkthrough
1. **Open Object Studio**:
   - Select any directory object in the **Users** or **Raw Attribute Editor** workspace.
   - Click **Specialized Editors** or double-click any binary attribute row.
2. **Inspect the Synchronized Hex Dump**:
   - Select the **Hex / Binary Editor** tab.
   - The top pane displays a synchronized 3-column dump in high-contrast monospace formatting:
     * **Column 1**: Memory offset addresses (`00000000`, `00000010`, `00000020`...).
     * **Column 2**: Formatted 16-byte spaced hex pairs (`30 82 04 2E 30 82 03 16...`).
     * **Column 3**: Decoded printable ASCII character representation (`0...0..........;`).
3. **Edit via Raw Hex Stream Editor**:
   - Paste or edit raw hex strings into the lower text area.
   - Click **🔄 Format / Sync Dump** to re-align offsets and calculate byte lengths.
4. **Inspect Live Previews**:
   - View instant **ASCII Preview** and **Base64 Preview** (`MIIELjCCAxag...`).
   - Check the **Total Bytes** indicator badge (`Total Bytes: 1,074 bytes (0x0432)`).
5. **Save or Export**:
   - Click **💾 Export File...** to save raw binary payloads to disk, or click **💾 Apply / Save Value** to write changes back to Active Directory.

---

## Scenario 4: Cryptographic Auditing: X.509 Certificate Inspector

### Objective
Audit a digital certificate stored in Active Directory, verify cryptographic strength, inspect validity periods, and perform a real-time online CRL/OCSP revocation check.

![X.509 Certificate Viewer with Online Revocation Check](docs/images/04_specialized_editor_cert.png)

### Step-by-Step Walkthrough
1. **Open Certificate in Object Studio**:
   - Open the Specialized Editor dialog for an account with a `userCertificate` attribute or a Domain Controller object.
   - Select the **📜 X.509 Certificate** tab.
2. **Review Identification & Subject Hierarchy**:
   - **Subject (CN)**: `corp-dc01.ad.contoso.com`
   - **Full Subject DN**: `CN=corp-dc01.ad.contoso.com, OU=Domain Controllers, DC=contoso, DC=local`
   - **Issuer (CN)**: `Contoso Enterprise Root CA`
   - **Serial Number**: `3BA4F891C2D0491EB6A51102FFE4902A`
3. **Verify Cryptographic Parameters**:
   - **Public Key**: `RSA 2048 bits`
   - **Signature Algorithm**: `sha256RSA`
   - **Key Usage**: Server Authentication (`1.3.6.1.5.5.7.3.1`) & Client Authentication (`1.3.6.1.5.5.7.3.2`).
   - **Subject Alternative Names (SAN)**: `DNS:corp-dc01.ad.contoso.com, DNS:dc01.contoso.local`
4. **Perform Live Revocation Check**:
   - Click **🔍 Check Revocation (X509Chain)**.
   - The studio queries local Certificate Revocation Lists (CRLs) and Online Certificate Status Protocol (OCSP) responders:
     * **Status**: `VALID (Active: 443 days remaining)`
     * **Revocation Status**: `ONLINE (CRL and OCSP validated)`
     * **Chain Trust**: Confirmed complete trusted root chain to `Contoso Enterprise Root CA`.

---

## Scenario 5: Cloud Identity Integration: SCIM 2.0 Query & Filter Studio

### Objective
Test and translate cloud identity expressions (Entra ID / Okta SCIM 2.0) into native Active Directory LDAP search filters using RFC 7644 compilation.

![SCIM 2.0 Query and Native LDAP Filter Studio](docs/images/05_scim_filter_studio.png)

### Step-by-Step Walkthrough
1. **Navigate to SCIM Studio**:
   - Click **SCIM 2.0 Studio** (or **LDAP-SQL Console**) on the sidebar.
2. **Formulate a Cloud SCIM 2.0 Filter**:
   - In the query input, enter a standard RFC 7644 filter expression:
     ```text
     userName sw "alex" and title pr and emails[type eq "work"].value ew "@contoso.com"
     ```
3. **Compile to Native LDAP Syntax**:
   - Click **⚡ Compile SCIM Filter** or execute query.
   - The studio lexes, parses, and translates the expression to RFC 4515 LDAP syntax:
     ```text
     (&(objectCategory=person)(objectClass=user)(sAMAccountName=alex*)(title=*)(mail=*@contoso.com))
     ```
4. **Inspect Schema Projections**:
   - Review attribute mappings between SCIM Core (`urn:ietf:params:scim:schemas:core:2.0:User`) and Enterprise extensions (`urn:ietf:params:scim:schemas:extension:enterprise:2.0:User`).
5. **Review Execution Results**:
   - View matching directory objects returned with sub-second response times (`1 Object Matched in 4.2ms [VLV Page 1/1]`).

---

## Scenario 6: Access Control & Permissions: 6-Way Effective Rights

### Objective
Diagnose complex Active Directory permissions on a sensitive OU or User, calculate 6-Way Effective Rights, and remediate lingering `adminCount=1` AdminSDHolder orphans.

![Access Control and 6-Way Effective Rights Matrix](docs/images/06_security_acl_6way.png)

### Step-by-Step Walkthrough
1. **Navigate to the Security & ACL Suite**:
   - Click **Security & ACL Suite** on the sidebar.
2. **Select Target Object & Trustee**:
   - Target Object: `CN=Alex Morgan,OU=Engineers,OU=Staff,DC=contoso,DC=local`
   - Trustee: `CONTOSO\Domain Admins`
   - Click **Inspect ACL**.
3. **Review Access Control Entries (DACL)**:
   - Evaluates direct vs. inherited permissions from parent OUs.
   - Inspects ACE types (`Allow`/`Deny`), trustees, Active Directory rights masks, and inheritance flags.
4. **Calculate 6-Way Effective Rights**:
   - Click **⚡ Calculate Effective**.
   - The matrix calculates resultant permissions across 6 core classes, displayed with emerald green `GRANTED` badges:
     * `GenericAll (Full Control)`: **GRANTED**
     * `ReadProperty (All)`: **GRANTED**
     * `WriteProperty (All)`: **GRANTED**
     * `ResetPassword`: **GRANTED**
     * `ChangePassword`: **GRANTED**
     * `DeleteChild`: **GRANTED**
5. **Remediate AdminSDHolder Orphans**:
   - If an account was previously in Domain Admins, Active Directory leaves inheritance disabled.
   - Switch to the **⚠️ AdminSDHolder Orphans** tab.
   - Click **🛡️ Re-enable Inheritance & Clear adminCount** to restore automated OU delegation with 1 click.

---

## Scenario 7: Kerberos Authentication & PAC Bloat Troubleshooting

### Objective
Investigate user authentication failures and HTTP 400 Bad Request errors caused by Kerberos Token Bloat from deep security group nesting.

![Kerberos Token PAC Bloat Calculator](docs/images/07_kerberos_token_bloat.png)

### Step-by-Step Walkthrough
1. **Navigate to the Kerberos Suite**:
   - Click **Kerberos Suite** on the sidebar.
   - Select the **🧮 MaxTokenSize & PAC Bloat** tab.
2. **Specify Target User**:
   - Enter username: `alex.morgan`
   - Click **🧮 Calculate Token Size**.
3. **Analyze Token Metrics & PAC Formula**:
   - Evaluates Microsoft's PAC Expansion Formula:
     $$\text{TokenSize} = 1200 + 40d + 8s$$
   - Surfaces real-time values:
     * **Estimated PAC Size**: `18,240 Bytes`
     * **Domain / Universal Groups ($d$)**: `68`
     * **Global / SID History Groups ($s$)**: `74`
     * **HTTP 400 Risk Level**: `Normal (OK)` (Safe below 48,000 bytes).
4. **Identify Contributing Groups**:
   - The lower grid lists all contributing transitive groups (`Domain Admins`, `Enterprise Admins`, `Cloud-Platform-Architects`).
   - Group nesting can be pruned directly from the list to reduce token footprint.

---

## Scenario 8: Forensic Graph Analysis: Circular Group Loop Detection

### Objective
Scan Active Directory for circular group nesting loops (infinite recursive loops) and break cyclic references to prevent identity sync failures.

![Circular Group Nesting Loop Cycle Detector](docs/images/08_circular_groups_loop.png)

### Step-by-Step Walkthrough
1. **Navigate to Diagnostics Toolbox**:
   - Click **Diagnostics Toolbox** on the sidebar.
   - Select the **🔄 Circular Group Loops** tab.
2. **Execute Forest-Wide Cycle Scan**:
   - Click **⚡ Scan Entire Domain**.
   - The engine traverses the entire group membership graph using Depth-First Search (DFS).
3. **Inspect Detected Loops**:
   - High-contrast amber badges highlight detected cyclic loops:
     * **Status**: `LOOP DETECTED`
     * **Root Group**: `IT-Admins-Core`
     * **Cycle Path**: `IT-Admins-Core ➔ DevOps-Infrastructure ➔ SecOps-Auditors ➔ IT-Admins-Core`
     * **Depth**: `3`
     * **Severity**: `CRITICAL`
4. **Break Cyclic Reference**:
   - Click **Disconnect Reference** on the finding row.
   - The studio executes `Disconnect-CircularGroupReference`, safely severing the loop while preserving valid parent-child relationships.

---

## Scenario 9: Enterprise Security Posture & 48 Hygiene Audit Reports

### Objective
Execute automated compliance audits, identify stale/unprotected accounts, and export an executive HTML security report for audit compliance.

![Enterprise Security and 48 Hygiene Audit Reports](docs/images/09_audit_reports_48.png)

### Step-by-Step Walkthrough
1. **Navigate to Audit Reports**:
   - Click **Security Audits** on the sidebar and select the **Audit Reports** tab.
2. **Select Audit Category & Threshold**:
   - Category: `Inactive Users`
   - Days Threshold: `90 Days`
   - Click **🛡️ Run Audit**.
3. **Review Audit Findings**:
   - Displays all matching accounts with last logon timestamps, department, and expiration details.
   - Summary badge displays: `Audit Complete: Found 28 stale inactive user accounts (> 90 days without interactive logon)`.
4. **Generate Executive Compliance Reports**:
   - Click **📄 HTML Executive Report** to generate a styled, print-ready dossier.
   - Click **📤 Export CSV** for spreadsheet ingestion into SIEM or compliance portals.

---

## Scenario 10: Infrastructure Diagnostics: NetTools 7-Tier UNC Share Checker

### Objective
Diagnose network accessibility to domain controller file shares (`SYSVOL` / `NETLOGON`) through firewalls and verify port response latencies.

![NetTools 7-Tier UNC Share and DC Port Latency Diagnostics](docs/images/10_network_7tier_unc.png)

### Step-by-Step Walkthrough
1. **Navigate to Network Diagnostics**:
   - Click **Network Diagnostics** on the sidebar.
   - Select the **📁 7-Step UNC Share Checker** tab.
2. **Enter Target Share Path**:
   - Target: `\\dc01.corp.local\SYSVOL\corp.local`
   - Click **⚡ Run 7-Step Test**.
3. **Monitor Sequential Diagnostic Stages**:
   - **Step 1: DNS Resolution**: Resolves A/AAAA records to IP (`10.0.1.10`) [1.2 ms] - `PASS`
   - **Step 2: ICMP Ping**: Confirms IP routing and latency [0.8 ms] - `PASS`
   - **Step 3: RPC Endpoint Mapper**: Probes TCP port 135 [1.5 ms] - `PASS`
   - **Step 4: SMB Protocol Port**: Negotiates SMB 3.1.1 on TCP port 445 [2.1 ms] - `PASS`
   - **Step 5: NetShareGetInfo**: Validates share existence and disk type [3.4 ms] - `PASS`
   - **Step 6: Share Permissions**: Confirms Read/Execute permissions [2.8 ms] - `PASS`
   - **Step 7: Path Traversal & Read**: Confirms access to policy folder and `GPT.INI` [1.9 ms] - `PASS`
4. **DC Locator Port Matrix**:
   - Switch to **📡 DC Resolution & Port Profiles** to inspect live socket response times across ports 389, 636, 88, 445, 53, 3268, and 135.

---

## Scenario 11: Enterprise Directory Search, RFC 2696 Paging & Multi-Identity Dossier Tabs

### Objective
Query large Active Directory containers exceeding the default 1,000-object `MaxPageSize` limit without data truncation using RFC 2696 Simple Paged Results, inspect large group memberships via RFC 3268 incremental range retrieval, and open concurrent multi-user HTML identity dossiers across dedicated workspace tabs with automatic deduplication.

### Step-by-Step Walkthrough
1. **Navigate to Directory Search**:
   - Press `Ctrl+F` or click **Directory Search** on the sidebar.
   - The search view opens in **Simple Search** mode with an intuitive search bar and an expand/collapse toggle for advanced filters.
2. **Execute Large Subtree Query (Bypassing MaxPageSize = 1000)**:
   - In the Search Base field, specify root DN: `DC=contoso,DC=local`.
   - In the Attribute filter combobox (`CmbFilterAttr`), filter by `sAMAccountName` (consolidated virtualized input).
   - Enter filter criteria: `(&(objectCategory=person)(objectClass=user))`.
   - Click **⚡ Search** (`F5`).
   - The directory engine leverages RFC 2696 Simple Paged Results (`DirectorySearcher.PageSize = 1000`), paging sequentially across LDAP result sets.
   - All matching records (e.g. `1,248` user objects) are retrieved without truncation at 1,000.
3. **Inspect Large Group Memberships (RFC 3268 Range Retrieval)**:
   - Query a global or universal security group with extensive membership (e.g., `All-Corporate-Employees` with 3,500 members).
   - When viewing group attributes or member rosters, the engine automatically issues incremental range requests (`member;range=0-1499`, `member;range=1500-2999`, `member;range=3000-*`), successfully assembling all 3,500 member DNs without attribute omission.
4. **Open Concurrent HTML Identity Dossier Tabs**:
   - In the Users grid or search results, right-click `Alice Smith` and select **View HTML Dossier (In-App)**.
   - A dedicated tab opens in the workspace titled `Dossier: Alice Smith`.
   - Switch back to the search results or Users tab, right-click `Bob Jones`, and select **View HTML Dossier (In-App)**.
   - A second tab opens titled `Dossier: Bob Jones`. The previous tab `Dossier: Alice Smith` remains intact.
   - Right-click `Charlie Brown` and select **View HTML Dossier (In-App)** to open a third tab `Dossier: Charlie Brown`.
5. **Demonstrate Smart Tab Deduplication**:
   - Return to the user list and select **View HTML Dossier (In-App)** for `Alice Smith` again.
   - The studio immediately refocuses the existing `Dossier: Alice Smith` tab instead of opening a redundant duplicate tab.
6. **In-Tab Address Bar Navigation & Template Switching**:
   - In the active dossier tab address bar (`TxtHtmlViewDN`), enter `CN=Diana Prince,OU=Staff,DC=contoso,DC=local` and click **Go**. The active tab navigates in-place to Diana Prince's dossier and updates the tab header to `Dossier: Diana Prince`.
   - Use the template dropdown to switch between **Modern**, **Classic**, **Compact**, and **Security Audit** templates.
   - Press `Ctrl+Shift+P` to open the Windows print/PDF dialog for compliance documentation.

---

## Scenario 12: Competitor Parity Forensics: Omnibar 2.0, Client IP LPM Resolver, Group Member Diff & Duplicate SPNs

### Objective
Leverage advanced forensic tools inspired by Softerra LDAP Administrator 2026, Apache Directory Studio, and NetTools to execute command palette actions via Omnibar 2.0 (`Ctrl+K`), resolve client IP site affinity using Longest Prefix Match (LPM), perform 3-way Venn group membership diffing, scan for Kerberos duplicate SPNs, and inspect interactive directory breadcrumbs.

### Step-by-Step Walkthrough
1. **Omnibar 2.0 Command Palette (`Ctrl+K`)**:
   - Press `Ctrl+K` from anywhere in the application. The global search bar gains focus and selects all text.
   - Type `>` to switch to Command Mode. The popup immediately lists all registered command palette actions with descriptions and badges.
   - Type `> Repl` and press **Enter**. The application instantly transitions to the **Replication Suite** viewport.
   - Press `Ctrl+K`, type `> Toggle Dark Mode`, and press **Enter** to switch application theme on the fly.
2. **Interactive Directory Breadcrumbs**:
   - Navigate to the **Users** management grid and click any user (e.g. `CN=Alice Smith,OU=Engineering,OU=HQ,DC=corp,DC=local`).
   - Look directly above the viewport: the **Directory Breadcrumb Bar** renders clickable badges:
     `🏢 Directory Root` › `🌐 corp.local` › `📁 HQ` › `📁 Engineering` › `👤 Alice Smith`
   - Clicking `📁 HQ` navigates directly to the OUs tree view focused on the HQ container.
3. **Live Status Bar Telemetry**:
   - Look at the bottom status bar right corner.
   - The **Latency Badge** (`⚡ 14 ms`) displays real-time execution duration of the last Active Directory query.
   - The **Memory Badge** (`📊 42.8 MB`) tracks live managed process memory allocation.
4. **Client IP Site & Subnet Resolver (LPM)**:
   - In the **Replication Suite**, switch to the **🌐 Client IP Site Resolver** tab.
   - In the IPv4 address input, enter `10.10.15.42` (or click the quick sample button `10.10.15.42`).
   - Click **🔍 Resolve Site & DCs**.
   - The resolution engine evaluates all candidate AD Subnets (`10.0.0.0/8`, `10.10.0.0/16`, `10.10.15.0/24`) and applies **Longest Prefix Match (LPM)**:
     - Winning Subnet: `10.10.15.0/24` (Prefix `/24` wins over `/16` and `/8`).
     - Winning Site: `HQ-Floor2`.
     - Target DCs: `DC01-HQ-FLOOR2, DC02-HQ-FLOOR2`.
     - The candidate table highlights `10.10.15.0/24` as `★ Best LPM Match` and flags broader subnets as `Shadowed`.
5. **Group Member Diff Engine (3-Way Venn)**:
   - Navigate to the **Diagnostics Toolbox** and select the **👥 Group Member Diff** tab.
   - In Group A, enter `Domain Admins`; in Group B, enter `Enterprise Admins`.
   - Optionally check `Recursive Principals` to expand nested group members.
   - Click **⚖️ Compare Group Members**.
   - The summary ribbon displays the 3-way Venn tally:
     - `Both: 2` (Green badge)
     - `Only in A: 2` (Blue badge)
     - `Only in B: 2` (Red badge)
   - The DataGrid lists all distinct principals with explicit checkboxes `In Group A` and `In Group B`, Venn category badges, and export to CSV via **📤 Export CSV**.
6. **Kerberos Duplicate SPN Scanner**:
   - Navigate to the **Kerberos Suite** and select the **🔑 Duplicate SPN Scanner** tab.
   - Click **🔍 Scan Duplicate SPNs**.
   - The scanner sweeps all directory user and computer accounts with `servicePrincipalName=*`, grouping colliding SPN registrations.
   - For any conflicting SPN (e.g. `MSSQLSvc/sqlprod01.corp.local:1433`), the row details conflicting accounts (`svc_sqlprod (User), SQLPROD01$ (Computer)`) and provides exact `setspn -D` remediation syntax.

---

## Conclusion & Best Practices

1. **Light Theme for Precision**: The default high-contrast Light Theme guarantees optimal readability when analyzing fine-grained ACL matrices, cryptographic keys, and dense hex streams.
2. **Leverage Staged Basket Moves**: When moving users or groups between OUs, stage them in the **Directory Basket** (`Ctrl+Shift+B`) first to preview changes before committing.
3. **Verify LDIF Diffs**: Always review dry-run diffs in **LDIF Studio** before committing batch schema or attribute updates.
4. **Automate with CLI**: Repetitive diagnostic sweeps (circular group scans, Kerberos token calculations, health audits) can be scheduled using `tools/ad-studio-cli.ps1`.
5. **Technical Architecture Reference**: For deep protocol specifications, RFC compliance mappings, and schema definitions, consult the [**Enterprise SysAdmin Handbook (HANDBOOK.md)**](HANDBOOK.md).
