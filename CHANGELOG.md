# Changelog
All notable changes to **Active Directory Management Studio** are documented in this file.
The project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) and [Conventional Commits](https://www.conventionalcommits.org/).

---

## [v3.2.0] - 2026-10-20

### 🚀 Major Architectural Milestones
- **Enterprise Parity Suite**: Achieved complete operational equivalence with **Softerra LDAP Administrator**, **Apache Directory Studio**, and **NetTools** (79+ specialized capabilities across 24 administrative panels).
- **In-Process Multi-Instance Architecture**: Independent window detachment with zero latency, simultaneous instances, cross-window drag-and-drop, and seamless dock-back.
- **WPF / Modern Light & Dark Themes**: High-contrast, accessibility-audited palettes with custom styling, dynamic theme switching, and real-time HTML technical dossiers.
- **Active Directory Auto-Discovery & Health**: Automated DNS SRV locator detection, multi-DC replication topology matrix, and real-time TCP/ICMP ping latency diagnostics.
- **SemVer Standardization & Release Automation**: Standardized all branding to Semantic Versioning (`v3.2.0 Enterprise`), regenerated all 19 application screenshots, and automated historical changelog publishing for GitHub Releases.

### ✨ Features & Enhancements (33 commits)
- [`691f29f`](https://github.com/catmuf/ad-management-studio/commit/691f29fc1226ad05e6b757964a0b100ce392423d) - feat(connections): add auto-detection of Active Directory connections with sortable ping latency *(2026-10-19)*
- [`9a94499`](https://github.com/catmuf/ad-management-studio/commit/9a944990015ab4a6b631b0b62dd058311f1430ef) - feat(ui): add Global Search label and consolidate top header into Quick Tools dropdown *(2026-10-19)*
- [`39892e0`](https://github.com/catmuf/ad-management-studio/commit/39892e03f2bc6735054da86d456b59648b58be13) - feat(ui): add native horizontal menu bar and high-value competitor feature parity *(2026-10-19)*
- [`d232145`](https://github.com/catmuf/ad-management-studio/commit/d232145d3efbee88f520c6f5d42d649585a9a2f0) - feat: in-process simultaneous multi-instance detached windows with dock-back *(2026-10-14)*
- [`d74a31c`](https://github.com/catmuf/ad-management-studio/commit/d74a31cbac311bd4f602513685066b0e9e697985) - feat(stability): harden core operations, diagnostics and eliminate recursive event loops *(2026-10-14)*
- [`b50eb23`](https://github.com/catmuf/ad-management-studio/commit/b50eb239116e4cd32a91b219f094cf4044a1a11c) - feat(qa): eliminate PSScriptAnalyzer warnings, integrate light theme visual guide and screenshots *(2026-10-14)*
- [`15944a8`](https://github.com/catmuf/ad-management-studio/commit/15944a8e18e96793640d8a261edff671ab12a98c) - feat: implement Softerra, Apache Studio, SCIM 2.0, and NetTools parity suites *(2026-10-14)*
- [`5353d4d`](https://github.com/catmuf/ad-management-studio/commit/5353d4d2531897d434a127512a693e6d0cf0340b) - feat: implement YYYY-MM-DD_HH-mm log file naming convention *(2026-10-14)*
- [`5e81af1`](https://github.com/catmuf/ad-management-studio/commit/5e81af169058265d275f198c81b27a59f7a3ae95) - feat: add comprehensive application error logging service and logs directory *(2026-10-13)*
- [`bf31740`](https://github.com/catmuf/ad-management-studio/commit/bf317409c21f43cdb466a45aa7e8486e6774bb2b) - Enable simultaneous multi-instance detached windows under same section *(2026-10-13)*
- [`34e3bb3`](https://github.com/catmuf/ad-management-studio/commit/34e3bb38d2627250853abd46c9d79e929c845338) - feat(parity): implement advanced forensic tools, value editors, and directory engines *(2026-10-13)*
- [`f0ab844`](https://github.com/catmuf/ad-management-studio/commit/f0ab8445ef7ee9ec7ccad2d01886e324f3b1408e) - feat: implement advanced identity, schema hierarchy, SDProp trigger and headless CLI automation *(2026-10-13)*
- [`dbdb096`](https://github.com/catmuf/ad-management-studio/commit/dbdb096284abf5bb2b00c9102c5cc68d0580ea5b) - feat(workspace): add tab drag-and-drop reordering, multi-instance tabs, and independent multi-window launch *(2026-10-08)*
- [`c7ecf3b`](https://github.com/catmuf/ad-management-studio/commit/c7ecf3bbf38462da8c338d8bd65e61b476651063) - feat(workspace): add persistent header button and menu to switch workspace and window layout *(2026-10-08)*
- [`46aa438`](https://github.com/catmuf/ad-management-studio/commit/46aa438351266e486c0ec0207f52539e06be8bcc) - feat(workspace): add in-window multi-tabs, detached multi-windows, and single-window mode *(2026-10-08)*
- [`38f0b90`](https://github.com/catmuf/ad-management-studio/commit/38f0b90c05644a45409952670291fdd807bd8e6b) - feat: complete Phase A-F implementation for 100% NetTools feature parity *(2026-10-08)*
- [`83319e5`](https://github.com/catmuf/ad-management-studio/commit/83319e5ba1d63be6a79bf1c5f961742c9d9d088e) - feat: implement NetTools competitor parity and advanced diagnostics suite *(2026-10-08)*
- [`442d254`](https://github.com/catmuf/ad-management-studio/commit/442d254dc4377e5178f400bce4fea1e464c9223f) - feat: add Light Mode appearance option and in-app HTML dossier view *(2026-10-08)*
- [`347b6fd`](https://github.com/catmuf/ad-management-studio/commit/347b6fd768229f788f9a9e55b95de3ea480b7de0) - feat: implement Softerra gallery parity features (omnibar, rename, LDIF outline, schema inspector, custom reports) *(2026-10-07)*
- [`e7552c6`](https://github.com/catmuf/ad-management-studio/commit/e7552c6eae59d5cb1f5da15c54189aa1e76c292b) - feat(parity): implement enterprise competitor parity features, diagnostics & encoding hardening *(2026-10-07)*
- [`1ea6727`](https://github.com/catmuf/ad-management-studio/commit/1ea67276ae166a08ef6b18e9783329cb584a1e37) - feat: implement SCIM 2.0 cloud export, search query history, object template wizards, dynamic attribute tokens, and 15 security audit categories *(2026-10-07)*
- [`7bb6393`](https://github.com/catmuf/ad-management-studio/commit/7bb6393898f10aacbb436be8a337e37518e404df) - feat: complete External Tools manager, HTML Dossier report card, DSML v2 XML export, FGPP calculator, NDNC partitions, and UI layout fixes *(2026-10-07)*
- [`2b79cea`](https://github.com/catmuf/ad-management-studio/commit/2b79cea8658c1c1d29efc0d4605f300b47400d32) - Implement Active Directory Recycle Bin, Server Monitor telemetry, enhanced LDAP-SQL, and advanced directory tooling *(2026-10-07)*
- [`9c943d8`](https://github.com/catmuf/ad-management-studio/commit/9c943d8808c4af9c98fb756d43ae4ce8a75b9ba9) - feat: achieve feature parity with Softerra LDAP Administrator and Apache Directory Studio *(2026-10-07)*
- [`96b3f1f`](https://github.com/catmuf/ad-management-studio/commit/96b3f1f56ee189183b940ef9ff729c8689e9eeef) - feat: open Manage Members window on double clicking a group row *(2026-10-06)*
- [`e956b31`](https://github.com/catmuf/ad-management-studio/commit/e956b310d1309e1c121a1f071400d035ce11de0f) - feat: add dynamic table column chooser across all tables, fix groups filters and live search *(2026-10-06)*
- [`767eede`](https://github.com/catmuf/ad-management-studio/commit/767eede786f7f9737bb216e48f30f38cd09fca6d) - feat(search): enable direct inline real-time search and selection in attribute dropdown menu *(2026-10-05)*
- [`53e6031`](https://github.com/catmuf/ad-management-studio/commit/53e60318cc81b3badc42a6f6b3095b6f372e1fbf) - feat(search): add live attribute search and dynamic outcome display to Directory Search *(2026-10-05)*
- [`14883bc`](https://github.com/catmuf/ad-management-studio/commit/14883bc690c5da6059865d2297ac3d3db83c47aa) - feat(search): populate comprehensive and live schema attributes in directory search *(2026-10-05)*
- [`bd6c6b0`](https://github.com/catmuf/ad-management-studio/commit/bd6c6b0f657c5d64e618c86b806793267e59f67a) - feat(app): wire Softerra LDAP suite controller logic, event handlers, and dialogs in main.ps1 *(2026-10-02)*
- [`29012b6`](https://github.com/catmuf/ad-management-studio/commit/29012b635cb9b62d588e2ea1bcab9a3c910194c5) - feat(ui): redesign interface into professional SysAdmin edition with Softerra suite panels *(2026-10-02)*
- [`e79c6ed`](https://github.com/catmuf/ad-management-studio/commit/e79c6eda79e284308022fa40fdbbfa2156ab7773) - feat(core): add Softerra LDAP suite engines and service modules *(2026-10-02)*
- [`0422fe6`](https://github.com/catmuf/ad-management-studio/commit/0422fe653496a7cf7ce8e63f2351d5ed29efe00c) - feat: complete overhaul to Active Directory Management Studio *(2026-09-23)*

### 🐛 Bug Fixes & UX Hardening (41 commits)
- [`29916e1`](https://github.com/catmuf/ad-management-studio/commit/29916e17f71d272895b96b4f4d52abcbdf6bd6c0) - fix(ui): align search bar controls, separate prefix icon, and sync placeholder across tabs *(2026-10-19)*
- [`0761bc1`](https://github.com/catmuf/ad-management-studio/commit/0761bc13bd9ba9993e48adb220b7b3046b1e78bb) - Fix duplicate connection profiles in active profile dropdown and configured profiles list *(2026-10-15)*
- [`b4b67e2`](https://github.com/catmuf/ad-management-studio/commit/b4b67e21771712247f240b31f53a2577cc36869e) - Fix blank view on second search in omnibar and preserve multi-dossier tabs *(2026-10-15)*
- [`cd015f0`](https://github.com/catmuf/ad-management-studio/commit/cd015f031a1021357a79b5154f78160e41652fc5) - Fix Users context menu parity across tabs and auto-render HTML dossier from search *(2026-10-15)*
- [`d67470c`](https://github.com/catmuf/ad-management-studio/commit/d67470c5ebfb8d908fe27caba80652179392b36b) - fix(search-ui): expand global omnibar results, link to HTML dossier, and resolve tab dock errors *(2026-10-14)*
- [`c76455a`](https://github.com/catmuf/ad-management-studio/commit/c76455a1495cabfc0a9e7cba82ab9f993d126dd3) - fix(pssa): resolve all PSScriptAnalyzer errors and warnings across workspace *(2026-10-14)*
- [`a63d5ea`](https://github.com/catmuf/ad-management-studio/commit/a63d5ea20fec1cf0cb03ae3639356c7c3d0eaf97) - fix: in-process multi-instance window detachment with zero latency and crash-free dock-back *(2026-10-13)*
- [`2d24144`](https://github.com/catmuf/ad-management-studio/commit/2d24144aaa6ce1f67313674a98a5384f888834f0) - Fix Column Chooser theme styling, multi-instance tab detachment, and console suppression *(2026-10-13)*
- [`f1d9f06`](https://github.com/catmuf/ad-management-studio/commit/f1d9f067a77d66e4728cae63b814b0b361b7f9d9) - fix(ui): isolate hand cursor to tab headers and restore arrow cursor on content blocks *(2026-10-13)*
- [`5b8510e`](https://github.com/catmuf/ad-management-studio/commit/5b8510e198e2730692bf97168983a8497bcf6a02) - fix(ui): eliminate tab and menu hover flashing by scoping triggers to unselected states *(2026-10-13)*
- [`dd7568f`](https://github.com/catmuf/ad-management-studio/commit/dd7568f9f95fce7c44f962f8e3ed2467520cc3fc) - fix: resolve unapproved verb warning and Save-AppConfig cmdlet reference *(2026-10-13)*
- [`3cca1f4`](https://github.com/catmuf/ad-management-studio/commit/3cca1f45f20c2e5275b380d0ba9afab67a5854ba) - fix: declare outcome badge state properties and guard strict variable access *(2026-10-13)*
- [`18bf0c5`](https://github.com/catmuf/ad-management-studio/commit/18bf0c5c7903ab8a15591c551e219a8926161a26) - fix: make directory search outcome badge legible across light and dark themes *(2026-10-13)*
- [`3b8defa`](https://github.com/catmuf/ad-management-studio/commit/3b8defaac1c49a66f848c12306a0528bc3434d8e) - Fix PanelConnections Grid.RowDefinitions to prevent DNS SRV card overlapping profile manager and diagnostics *(2026-10-08)*
- [`a844120`](https://github.com/catmuf/ad-management-studio/commit/a844120621e35a30010be6d452f10501c9575a23) - Fix OU directory tree hierarchy text contrast and styling in light mode *(2026-10-08)*
- [`de45945`](https://github.com/catmuf/ad-management-studio/commit/de4594563ff836ea8a793dc49c8e26ff2f4868d3) - Fix dark mode contrast and color overlap on controls and tables *(2026-10-08)*
- [`3de6805`](https://github.com/catmuf/ad-management-studio/commit/3de680525817344ed9c0d9df51a9e812b86e67d4) - Fix tab selection and panel detachment ArgumentNullException *(2026-10-08)*
- [`0459a78`](https://github.com/catmuf/ad-management-studio/commit/0459a78da85ad0c09c7906fde720e3f063a293c7) - fix(layout): make top app bar responsive with adaptive button sizing to prevent cutoff in restored window mode *(2026-10-08)*
- [`8d3693f`](https://github.com/catmuf/ad-management-studio/commit/8d3693f01826e5deb2f2aca6e23681cdc81c08dc) - fix(acl): resolve ItemsSource exception on CmbDelegationScope and harden module parameter bindings *(2026-10-08)*
- [`58c4664`](https://github.com/catmuf/ad-management-studio/commit/58c4664adcf6a1c2465e9e101b93cc7b60951236) - fix(htmlview): harmonize Print Dossier button contrast and fallback styles for Light and Dark modes *(2026-10-08)*
- [`cd81f8a`](https://github.com/catmuf/ad-management-studio/commit/cd81f8ace97db4419ec7788c4865e436265b1520) - fix(htmlview): resolve Render Error by replacing non-existent Get-ADUsersQuick with multi-attribute AD directory search *(2026-10-08)*
- [`ed44a28`](https://github.com/catmuf/ad-management-studio/commit/ed44a28dcf22b79d8ca6e46474e32d71d8fdb830) - fix(theme): harmonize Light Mode theming for User Details and modal dialogs, and fix ListGroups ItemsSource exception *(2026-10-08)*
- [`776c609`](https://github.com/catmuf/ad-management-studio/commit/776c6091b06eb80c20df62fdca2fe0b35f8f8ae9) - fix(search): resolve SetValueInvocationException on single results and harmonize Light Mode contrast *(2026-10-08)*
- [`84d0715`](https://github.com/catmuf/ad-management-studio/commit/84d0715fc39726690c427526788870fc268e0636) - fix(theme): harmonize Light Mode UI controls, backgrounds, and ComboBox popups *(2026-10-08)*
- [`267357a`](https://github.com/catmuf/ad-management-studio/commit/267357ab75039b9d2cd7f17147fe7aa749c3461e) - fix(xaml): resolve case sensitivity on VerticalAlignment attribute in search paging bar *(2026-10-07)*
- [`8d33bec`](https://github.com/catmuf/ad-management-studio/commit/8d33bec5b5970c5885b3d8c34f1caae5bc8faf47) - fix: safely initialize ExternalTools collection to prevent state creation failure *(2026-10-07)*
- [`8518e29`](https://github.com/catmuf/ad-management-studio/commit/8518e29c4bd49e4a077d5f8f920119ce40633f93) - fix: wire TreeOUs context menu and enhance RFC 4515 LDAP search escaping in Raw Attribute Editor *(2026-10-07)*
- [`ef95c76`](https://github.com/catmuf/ad-management-studio/commit/ef95c769b9d5431448b80880d6e2af59b58f5937) - fix(ui): eliminate button text clipping in Directory Search and toolbars *(2026-10-07)*
- [`628d823`](https://github.com/catmuf/ad-management-studio/commit/628d823d500496879149740397c0cf434bf89d76) - fix(ui): improve OU hierarchy tree folder icon visibility and contrast *(2026-10-07)*
- [`7a834fd`](https://github.com/catmuf/ad-management-studio/commit/7a834fdec6c92654a99b883c5a9f9482836aab8c) - fix: replace unsupported stethoscope emoji with universally supported diagnostic icon *(2026-10-06)*
- [`36eb106`](https://github.com/catmuf/ad-management-studio/commit/36eb106220f6d2cb027b5d65a9f2a49a17c0ccbf) - fix: resolve Filter-ComboAttributes scoping error in dropdown closures *(2026-10-06)*
- [`1d15f87`](https://github.com/catmuf/ad-management-studio/commit/1d15f87ca7b6d004395f42dfb3fb48a08fba1fb8) - fix: make all toolbars, panels, and dialogs responsive with WrapPanels and scrollability *(2026-10-06)*
- [`7940128`](https://github.com/catmuf/ad-management-studio/commit/79401288b658e0ffee7e78e8ca043b5ffa7704ce) - fix: resolve empty rows in group member search and display logon usernames *(2026-10-06)*
- [`c757d00`](https://github.com/catmuf/ad-management-studio/commit/c757d00603942d1cfec8ff575337358e0d78c8a5) - fix: resolve AllScopeUsers property error and eliminate nested array in AD object grids *(2026-10-06)*
- [`aba6c61`](https://github.com/catmuf/ad-management-studio/commit/aba6c614c7238f502ab37bb30a245e9b338c71c4) - fix(users): resolve search filtering, single-result grid binding, and add live instant search *(2026-10-05)*
- [`24b9c9c`](https://github.com/catmuf/ad-management-studio/commit/24b9c9c0dbdd7c62b5a3b9620783bbd9ab5c3756) - fix(ui): expand AD server selection field and remove Top App Bar clipping *(2026-10-05)*
- [`ae8c94e`](https://github.com/catmuf/ad-management-studio/commit/ae8c94e4894adfdcb86b73b79214dba1be1ff20a) - fix(sql): dynamically generate DataGrid columns and bind structured records for LDAP-SQL query results *(2026-10-05)*
- [`613af27`](https://github.com/catmuf/ad-management-studio/commit/613af27215c36ef5fe3f508f0b47f95fce5e95cf) - fix(search): fix real-time dropdown filtering, auto-select matched attribute, and prevent popup collision *(2026-10-05)*
- [`d94b52c`](https://github.com/catmuf/ad-management-studio/commit/d94b52c9d5d0d8ea8bb3ea8e20737548280729f6) - fix(search): fix dropdown real-time attribute filtering by removing focus check and using scoped filter function *(2026-10-05)*
- [`6bae15a`](https://github.com/catmuf/ad-management-studio/commit/6bae15a9bd77eb29fc398a932892d1489b6b7a2f) - fix(ui): dark mode combobox styling, regex directory search, and OU object browsing *(2026-10-05)*
- [`6100fe7`](https://github.com/catmuf/ad-management-studio/commit/6100fe7ba6233acb95e17e768d30c89f6fb88146) - fix(ui,core): resolve UI bindings, module parameter mismatches, and encoding issues *(2026-10-05)*

### ⚡ Performance & Engine Optimizations (1 commits)
- [`ab0c97a`](https://github.com/catmuf/ad-management-studio/commit/ab0c97a9fc8304c7c40f4ed3a7a35a839e451c42) - perf: optimize startup with lazy loading, NameScope indexing, and DataGrid UI virtualization *(2026-10-19)*

### 📚 Documentation & Visual Guides (3 commits)
- [`33c4c91`](https://github.com/catmuf/ad-management-studio/commit/33c4c914b9ae3a6be2243e5757b411f443f8303f) - docs: overhaul README with 19 visual demonstration galleries and native menu reference *(2026-10-19)*
- [`9100df3`](https://github.com/catmuf/ad-management-studio/commit/9100df39ad529ca54c1729d98824ee74d7706d65) - docs: add comprehensive SysAdmin Handbook and update README with Softerra LDAP suite guide *(2026-10-02)*
- [`62d738d`](https://github.com/catmuf/ad-management-studio/commit/62d738da2da6178d2fda08afaf6bad5a5bb7a19e) - docs: add wiki references to README and configure .gitignore *(2026-10-02)*

### 🛡️ Refactoring, Stability & Quality Assurance (0 commits)


### 📦 Initial Project Genesis (3 commits)
- [`3b526d6`](https://github.com/catmuf/ad-management-studio/commit/3b526d6aac28cdaf4f1321393048377ac7347f8b) - Upload project *(2024-08-27)*
- [`4d2ed03`](https://github.com/catmuf/ad-management-studio/commit/4d2ed03e4d6112e59e7ea781b69f9e897402a086) - Update README.md *(2024-08-27)*
- [`cc155ca`](https://github.com/catmuf/ad-management-studio/commit/cc155ca57bcd7816c5b60459c8d79a1759b5d515) - Initial commit *(2024-08-27)*

---

## Commit Statistics Since Inception
- **Total Commits Documented**: 81
- **First Commit**: [\cc155ca\](https://github.com/catmuf/ad-management-studio/commit/cc155ca) *(2024-08-27)*
- **Latest Commit**: [\$(                                                                                [0].ShortHash)\](https://github.com/catmuf/ad-management-studio/commit/691f29fc1226ad05e6b757964a0b100ce392423d) *(2026-10-19)*
- **Target Release Version**: v3.2.0 (Enterprise Edition)