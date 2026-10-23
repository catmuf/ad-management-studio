# Changelog
All notable changes to **Active Directory Management Studio** are documented in this file.
The project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) and [Conventional Commits](https://www.conventionalcommits.org/).

---

## 📊 Complete Commit-to-Version Reference Table (All 109 Commits)

| # | Version | Commit | Date | Subject |
| :---: | :---: | :---: | :---: | :--- |
| 109 | **v3.4.0** | [`a0f4eb4`](https://github.com/catmuf/ad-management-studio/commit/a0f4eb4cad5d16de5bf8e1dbf4301eddebf434d5) | 2026-10-23 | feat(html-view): support multi-instance tabs, deduplication, and in-tab address navigation for HTML dossiers |
| 108 | **v3.4.0** | [`7af88b4`](https://github.com/catmuf/ad-management-studio/commit/7af88b40e9ff97dcaf6cb44f65c601d24c644f88) | 2026-10-23 | fix(runtime): resolve Show-ObjectHtmlView closure scope, COM maxPwdAge cast, and DateTime parsing in audit service |
| 107 | **v3.4.0** | [`dcb0ae9`](https://github.com/catmuf/ad-management-studio/commit/dcb0ae9382a847be78410eaa386787459555b600) | 2026-10-23 | feat(ad-query): implement RFC 2696 LDAP paging, RFC 3268 range retrieval, and streamed exports |
| 106 | **v3.4.0** | [`da403e8`](https://github.com/catmuf/ad-management-studio/commit/da403e84623d6a96e6980e98a84ac36645b0641d) | 2026-10-23 | refactor(search): consolidate attribute search into CmbFilterAttr and remove redundant TxtSearchAttrFilter |
| 105 | **v3.3.0** | [`fbe83e9`](https://github.com/catmuf/ad-management-studio/commit/fbe83e996c46bfc0369931d8c61289937ae19889) | 2026-10-23 | docs(release): add Release History & Version Milestones section to README and sync changelog |
| 104 | **v3.3.0** | [`0580d9a`](https://github.com/catmuf/ad-management-studio/commit/0580d9a347ee2955bcfcb48736a2cab881c8dc88) | 2026-10-23 | docs: update documentation, handbook, walkthrough, and changelog for v3.3.0 |
| 103 | **v3.3.0** | [`69561ba`](https://github.com/catmuf/ad-management-studio/commit/69561babc534670916a6c27ccf1542e46a464959) | 2026-10-23 | fix(adservice): prevent DirectoryEntry referral hangs via reflection dispose and filter benign referral probes |
| 102 | **v3.3.0** | [`f5188aa`](https://github.com/catmuf/ad-management-studio/commit/f5188aa8e5603a90a0d889d1fb1336fa5aec0921) | 2026-10-23 | fix(htmlview): export Set-SafeBrowserHtml and panel actions to global scope for secondary tab closures |
| 101 | **v3.3.0** | [`c55bd4a`](https://github.com/catmuf/ad-management-studio/commit/c55bd4ab0c2b47642d2bb34e4288abf92fdab0f3) | 2026-10-23 | fix(resilience): resolve backtick parameter breakages, add DWM composition quota fallback and throttle dispatcher errors |
| 100 | **v3.3.0** | [`8dc606d`](https://github.com/catmuf/ad-management-studio/commit/8dc606de51dbc8901c9db2ad706a0b16dfc70e19) | 2026-10-23 | docs(release): sync v3.3.0 release notes and historical changelog |
| 99 | **v3.3.0** | [`47fbe72`](https://github.com/catmuf/ad-management-studio/commit/47fbe72ccd3133194c4e2743ed447262f707d64c) | 2026-10-23 | feat(release): standardize SemVer v3.3.0, update documentation, and prepare release |
| 98 | **v3.3.0** | [`c9113ec`](https://github.com/catmuf/ad-management-studio/commit/c9113ec961428a4ef2ae4e29b50dcaebf762551d) | 2026-10-22 | fix(connections): lock page scroll and enable internal horizontal scrollbar on active connections table |
| 97 | **v3.3.0** | [`4b45df4`](https://github.com/catmuf/ad-management-studio/commit/4b45df4367d251c1ae36aa92787351bab4a69522) | 2026-10-22 | fix(connections): add horizontal scrollbar to table and preserve bottom panels during expand view |
| 96 | **v3.3.0** | [`46ab639`](https://github.com/catmuf/ad-management-studio/commit/46ab6392858b23d3ec6a1eddea4dbf67d07b91c6) | 2026-10-22 | perf(search): debounce attribute quick filter, virtualize combobox and prevent UI freeze on backspace |
| 95 | **v3.3.0** | [`4355905`](https://github.com/catmuf/ad-management-studio/commit/43559054451e43075a787e0ed8233eb9c41ddefc) | 2026-10-22 | feat(search): add simple search mode with collapsible advanced filters and arrow toggle |
| 94 | **v3.3.0** | [`a0b75bb`](https://github.com/catmuf/ad-management-studio/commit/a0b75bb4bfe13a2d0000afee2f544e7472ef7b44) | 2026-10-22 | feat(connections): expand DC table height and add expand/compact view toggle |
| 93 | **v3.3.0** | [`fd856c6`](https://github.com/catmuf/ad-management-studio/commit/fd856c67a70ef4b22e2b20ddfff480a78d31bd45) | 2026-10-22 | fix(theme,dialog): resolve light mode unreadable text and input styling in connection dialog |
| 92 | **v3.3.0** | [`a6648d9`](https://github.com/catmuf/ad-management-studio/commit/a6648d915e8b987eb204dca40fe703676d5ad4a4) | 2026-10-22 | feat(workspace,tabs): set default startup tabs and add optional session saving in settings |
| 91 | **v3.3.0** | [`2437a94`](https://github.com/catmuf/ad-management-studio/commit/2437a9484a32d6a59a5378924519e1f5c9c1038b) | 2026-10-22 | refactor(scripts): decompose ADService into specialized JIT modules, fix ADSI handle leaks, optimize loops, and clean static analysis |
| 90 | **v3.3.0** | [`e2ed4db`](https://github.com/catmuf/ad-management-studio/commit/e2ed4dba6d25efec239611fc53887315090425cb) | 2026-10-22 | perf(launch,xaml): optimize startup loading to sub-second via direct XAML streaming and lazy RSAT |
| 89 | **v3.3.0** | [`c2598cc`](https://github.com/catmuf/ad-management-studio/commit/c2598cceb934367283f0241809d952fe8c38c68d) | 2026-10-21 | feat(connections,datagrid): remove redundant ping sort buttons, add sort arrow indicators, and convert domain input to live connection search box |
| 88 | **v3.3.0** | [`1af9a29`](https://github.com/catmuf/ad-management-studio/commit/1af9a29071a84513ebfa2a109109358bd2cf66e0) | 2026-10-21 | fix(connections): fix catch block syntax in Invoke-ADConnectionsAutoDetect |
| 87 | **v3.3.0** | [`063d13e`](https://github.com/catmuf/ad-management-studio/commit/063d13e1eabada23ec35292575ef1b9bbbd55a92) | 2026-10-21 | fix(audit,connections): resolve profile deletion overload and eliminate audit report freeze |
| 86 | **v3.3.0** | [`039fac1`](https://github.com/catmuf/ad-management-studio/commit/039fac1e48452eb306e29c6d8bf1a43a0b29fe73) | 2026-10-20 | feat(ui): add button and keyboard shortcut (Ctrl+B) to toggle sidebar menu |
| 85 | **v3.3.0** | [`8dc5387`](https://github.com/catmuf/ad-management-studio/commit/8dc53874f0b3c63504b2bd978d58ee39fe0bba1c) | 2026-10-20 | perf(core,ui): optimize DataGrid pixel scrolling, omnibar debouncing, live filtering, and module loading |
| 84 | **v3.3.0** | [`ed3270d`](https://github.com/catmuf/ad-management-studio/commit/ed3270d8a2ec4a0abe544498da5660379a499502) | 2026-10-20 | ci(release): automate synchronization of all 10 historical releases via GitHub Actions |
| 83 | **v3.3.0** | [`ed38733`](https://github.com/catmuf/ad-management-studio/commit/ed387332013c4b7ff10e5fe059b86a439fb73807) | 2026-10-20 | docs(releases): map all 82 historical commits across 10 Semantic Version releases |
| 82 | **v3.2.0** | [`ee7d53a`](https://github.com/catmuf/ad-management-studio/commit/ee7d53a9032aa1a8f876d747ccc291c65364fdf6) | 2026-10-20 | feat(release): standardize SemVer v3.2.0, regenerate screenshots, and automate historical changelog |
| 81 | **v3.2.0** | [`691f29f`](https://github.com/catmuf/ad-management-studio/commit/691f29fc1226ad05e6b757964a0b100ce392423d) | 2026-10-19 | feat(connections): add auto-detection of Active Directory connections with sortable ping latency |
| 80 | **v3.2.0** | [`29916e1`](https://github.com/catmuf/ad-management-studio/commit/29916e17f71d272895b96b4f4d52abcbdf6bd6c0) | 2026-10-19 | fix(ui): align search bar controls, separate prefix icon, and sync placeholder across tabs |
| 79 | **v3.2.0** | [`ab0c97a`](https://github.com/catmuf/ad-management-studio/commit/ab0c97a9fc8304c7c40f4ed3a7a35a839e451c42) | 2026-10-19 | perf: optimize startup with lazy loading, NameScope indexing, and DataGrid UI virtualization |
| 78 | **v3.2.0** | [`9a94499`](https://github.com/catmuf/ad-management-studio/commit/9a944990015ab4a6b631b0b62dd058311f1430ef) | 2026-10-19 | feat(ui): add Global Search label and consolidate top header into Quick Tools dropdown |
| 77 | **v3.2.0** | [`33c4c91`](https://github.com/catmuf/ad-management-studio/commit/33c4c914b9ae3a6be2243e5757b411f443f8303f) | 2026-10-19 | docs: overhaul README with 19 visual demonstration galleries and native menu reference |
| 76 | **v3.2.0** | [`39892e0`](https://github.com/catmuf/ad-management-studio/commit/39892e03f2bc6735054da86d456b59648b58be13) | 2026-10-19 | feat(ui): add native horizontal menu bar and high-value competitor feature parity |
| 75 | **v3.1.0** | [`0761bc1`](https://github.com/catmuf/ad-management-studio/commit/0761bc13bd9ba9993e48adb220b7b3046b1e78bb) | 2026-10-15 | Fix duplicate connection profiles in active profile dropdown and configured profiles list |
| 74 | **v3.1.0** | [`b4b67e2`](https://github.com/catmuf/ad-management-studio/commit/b4b67e21771712247f240b31f53a2577cc36869e) | 2026-10-15 | Fix blank view on second search in omnibar and preserve multi-dossier tabs |
| 73 | **v3.1.0** | [`cd015f0`](https://github.com/catmuf/ad-management-studio/commit/cd015f031a1021357a79b5154f78160e41652fc5) | 2026-10-15 | Fix Users context menu parity across tabs and auto-render HTML dossier from search |
| 72 | **v3.1.0** | [`d232145`](https://github.com/catmuf/ad-management-studio/commit/d232145d3efbee88f520c6f5d42d649585a9a2f0) | 2026-10-14 | feat: in-process simultaneous multi-instance detached windows with dock-back |
| 71 | **v3.1.0** | [`d74a31c`](https://github.com/catmuf/ad-management-studio/commit/d74a31cbac311bd4f602513685066b0e9e697985) | 2026-10-14 | feat(stability): harden core operations, diagnostics and eliminate recursive event loops |
| 70 | **v3.1.0** | [`d67470c`](https://github.com/catmuf/ad-management-studio/commit/d67470c5ebfb8d908fe27caba80652179392b36b) | 2026-10-14 | fix(search-ui): expand global omnibar results, link to HTML dossier, and resolve tab dock errors |
| 69 | **v3.1.0** | [`c76455a`](https://github.com/catmuf/ad-management-studio/commit/c76455a1495cabfc0a9e7cba82ab9f993d126dd3) | 2026-10-14 | fix(pssa): resolve all PSScriptAnalyzer errors and warnings across workspace |
| 68 | **v3.1.0** | [`b50eb23`](https://github.com/catmuf/ad-management-studio/commit/b50eb239116e4cd32a91b219f094cf4044a1a11c) | 2026-10-14 | feat(qa): eliminate PSScriptAnalyzer warnings, integrate light theme visual guide and screenshots |
| 67 | **v3.1.0** | [`15944a8`](https://github.com/catmuf/ad-management-studio/commit/15944a8e18e96793640d8a261edff671ab12a98c) | 2026-10-14 | feat: implement Softerra, Apache Studio, SCIM 2.0, and NetTools parity suites |
| 66 | **v3.1.0** | [`5353d4d`](https://github.com/catmuf/ad-management-studio/commit/5353d4d2531897d434a127512a693e6d0cf0340b) | 2026-10-14 | feat: implement YYYY-MM-DD_HH-mm log file naming convention |
| 65 | **v3.0.0** | [`5e81af1`](https://github.com/catmuf/ad-management-studio/commit/5e81af169058265d275f198c81b27a59f7a3ae95) | 2026-10-13 | feat: add comprehensive application error logging service and logs directory |
| 64 | **v3.0.0** | [`a63d5ea`](https://github.com/catmuf/ad-management-studio/commit/a63d5ea20fec1cf0cb03ae3639356c7c3d0eaf97) | 2026-10-13 | fix: in-process multi-instance window detachment with zero latency and crash-free dock-back |
| 63 | **v3.0.0** | [`bf31740`](https://github.com/catmuf/ad-management-studio/commit/bf317409c21f43cdb466a45aa7e8486e6774bb2b) | 2026-10-13 | Enable simultaneous multi-instance detached windows under same section |
| 62 | **v3.0.0** | [`2d24144`](https://github.com/catmuf/ad-management-studio/commit/2d24144aaa6ce1f67313674a98a5384f888834f0) | 2026-10-13 | Fix Column Chooser theme styling, multi-instance tab detachment, and console suppression |
| 61 | **v3.0.0** | [`f1d9f06`](https://github.com/catmuf/ad-management-studio/commit/f1d9f067a77d66e4728cae63b814b0b361b7f9d9) | 2026-10-13 | fix(ui): isolate hand cursor to tab headers and restore arrow cursor on content blocks |
| 60 | **v3.0.0** | [`5b8510e`](https://github.com/catmuf/ad-management-studio/commit/5b8510e198e2730692bf97168983a8497bcf6a02) | 2026-10-13 | fix(ui): eliminate tab and menu hover flashing by scoping triggers to unselected states |
| 59 | **v3.0.0** | [`dd7568f`](https://github.com/catmuf/ad-management-studio/commit/dd7568f9f95fce7c44f962f8e3ed2467520cc3fc) | 2026-10-13 | fix: resolve unapproved verb warning and Save-AppConfig cmdlet reference |
| 58 | **v3.0.0** | [`34e3bb3`](https://github.com/catmuf/ad-management-studio/commit/34e3bb38d2627250853abd46c9d79e929c845338) | 2026-10-13 | feat(parity): implement advanced forensic tools, value editors, and directory engines |
| 57 | **v3.0.0** | [`f0ab844`](https://github.com/catmuf/ad-management-studio/commit/f0ab8445ef7ee9ec7ccad2d01886e324f3b1408e) | 2026-10-13 | feat: implement advanced identity, schema hierarchy, SDProp trigger and headless CLI automation |
| 56 | **v3.0.0** | [`3cca1f4`](https://github.com/catmuf/ad-management-studio/commit/3cca1f45f20c2e5275b380d0ba9afab67a5854ba) | 2026-10-13 | fix: declare outcome badge state properties and guard strict variable access |
| 55 | **v3.0.0** | [`18bf0c5`](https://github.com/catmuf/ad-management-studio/commit/18bf0c5c7903ab8a15591c551e219a8926161a26) | 2026-10-13 | fix: make directory search outcome badge legible across light and dark themes |
| 54 | **v2.4.0** | [`3b8defa`](https://github.com/catmuf/ad-management-studio/commit/3b8defaac1c49a66f848c12306a0528bc3434d8e) | 2026-10-08 | Fix PanelConnections Grid.RowDefinitions to prevent DNS SRV card overlapping profile manager and diagnostics |
| 53 | **v2.4.0** | [`a844120`](https://github.com/catmuf/ad-management-studio/commit/a844120621e35a30010be6d452f10501c9575a23) | 2026-10-08 | Fix OU directory tree hierarchy text contrast and styling in light mode |
| 52 | **v2.4.0** | [`de45945`](https://github.com/catmuf/ad-management-studio/commit/de4594563ff836ea8a793dc49c8e26ff2f4868d3) | 2026-10-08 | Fix dark mode contrast and color overlap on controls and tables |
| 51 | **v2.4.0** | [`dbdb096`](https://github.com/catmuf/ad-management-studio/commit/dbdb096284abf5bb2b00c9102c5cc68d0580ea5b) | 2026-10-08 | feat(workspace): add tab drag-and-drop reordering, multi-instance tabs, and independent multi-window launch |
| 50 | **v2.4.0** | [`c7ecf3b`](https://github.com/catmuf/ad-management-studio/commit/c7ecf3bbf38462da8c338d8bd65e61b476651063) | 2026-10-08 | feat(workspace): add persistent header button and menu to switch workspace and window layout |
| 49 | **v2.4.0** | [`3de6805`](https://github.com/catmuf/ad-management-studio/commit/3de680525817344ed9c0d9df51a9e812b86e67d4) | 2026-10-08 | Fix tab selection and panel detachment ArgumentNullException |
| 48 | **v2.4.0** | [`46aa438`](https://github.com/catmuf/ad-management-studio/commit/46aa438351266e486c0ec0207f52539e06be8bcc) | 2026-10-08 | feat(workspace): add in-window multi-tabs, detached multi-windows, and single-window mode |
| 47 | **v2.4.0** | [`0459a78`](https://github.com/catmuf/ad-management-studio/commit/0459a78da85ad0c09c7906fde720e3f063a293c7) | 2026-10-08 | fix(layout): make top app bar responsive with adaptive button sizing to prevent cutoff in restored window mode |
| 46 | **v2.4.0** | [`8d3693f`](https://github.com/catmuf/ad-management-studio/commit/8d3693f01826e5deb2f2aca6e23681cdc81c08dc) | 2026-10-08 | fix(acl): resolve ItemsSource exception on CmbDelegationScope and harden module parameter bindings |
| 45 | **v2.4.0** | [`38f0b90`](https://github.com/catmuf/ad-management-studio/commit/38f0b90c05644a45409952670291fdd807bd8e6b) | 2026-10-08 | feat: complete Phase A-F implementation for 100% NetTools feature parity |
| 44 | **v2.4.0** | [`83319e5`](https://github.com/catmuf/ad-management-studio/commit/83319e5ba1d63be6a79bf1c5f961742c9d9d088e) | 2026-10-08 | feat: implement NetTools competitor parity and advanced diagnostics suite |
| 43 | **v2.4.0** | [`58c4664`](https://github.com/catmuf/ad-management-studio/commit/58c4664adcf6a1c2465e9e101b93cc7b60951236) | 2026-10-08 | fix(htmlview): harmonize Print Dossier button contrast and fallback styles for Light and Dark modes |
| 42 | **v2.4.0** | [`cd81f8a`](https://github.com/catmuf/ad-management-studio/commit/cd81f8ace97db4419ec7788c4865e436265b1520) | 2026-10-08 | fix(htmlview): resolve Render Error by replacing non-existent Get-ADUsersQuick with multi-attribute AD directory search |
| 41 | **v2.4.0** | [`ed44a28`](https://github.com/catmuf/ad-management-studio/commit/ed44a28dcf22b79d8ca6e46474e32d71d8fdb830) | 2026-10-08 | fix(theme): harmonize Light Mode theming for User Details and modal dialogs, and fix ListGroups ItemsSource exception |
| 40 | **v2.4.0** | [`776c609`](https://github.com/catmuf/ad-management-studio/commit/776c6091b06eb80c20df62fdca2fe0b35f8f8ae9) | 2026-10-08 | fix(search): resolve SetValueInvocationException on single results and harmonize Light Mode contrast |
| 39 | **v2.4.0** | [`84d0715`](https://github.com/catmuf/ad-management-studio/commit/84d0715fc39726690c427526788870fc268e0636) | 2026-10-08 | fix(theme): harmonize Light Mode UI controls, backgrounds, and ComboBox popups |
| 38 | **v2.4.0** | [`442d254`](https://github.com/catmuf/ad-management-studio/commit/442d254dc4377e5178f400bce4fea1e464c9223f) | 2026-10-08 | feat: add Light Mode appearance option and in-app HTML dossier view |
| 37 | **v2.3.0** | [`347b6fd`](https://github.com/catmuf/ad-management-studio/commit/347b6fd768229f788f9a9e55b95de3ea480b7de0) | 2026-10-07 | feat: implement Softerra gallery parity features (omnibar, rename, LDIF outline, schema inspector, custom reports) |
| 36 | **v2.3.0** | [`267357a`](https://github.com/catmuf/ad-management-studio/commit/267357ab75039b9d2cd7f17147fe7aa749c3461e) | 2026-10-07 | fix(xaml): resolve case sensitivity on VerticalAlignment attribute in search paging bar |
| 35 | **v2.3.0** | [`e7552c6`](https://github.com/catmuf/ad-management-studio/commit/e7552c6eae59d5cb1f5da15c54189aa1e76c292b) | 2026-10-07 | feat(parity): implement enterprise competitor parity features, diagnostics & encoding hardening |
| 34 | **v2.3.0** | [`1ea6727`](https://github.com/catmuf/ad-management-studio/commit/1ea67276ae166a08ef6b18e9783329cb584a1e37) | 2026-10-07 | feat: implement SCIM 2.0 cloud export, search query history, object template wizards, dynamic attribute tokens, and 15 security audit categories |
| 33 | **v2.3.0** | [`8d33bec`](https://github.com/catmuf/ad-management-studio/commit/8d33bec5b5970c5885b3d8c34f1caae5bc8faf47) | 2026-10-07 | fix: safely initialize ExternalTools collection to prevent state creation failure |
| 32 | **v2.3.0** | [`8518e29`](https://github.com/catmuf/ad-management-studio/commit/8518e29c4bd49e4a077d5f8f920119ce40633f93) | 2026-10-07 | fix: wire TreeOUs context menu and enhance RFC 4515 LDAP search escaping in Raw Attribute Editor |
| 31 | **v2.3.0** | [`7bb6393`](https://github.com/catmuf/ad-management-studio/commit/7bb6393898f10aacbb436be8a337e37518e404df) | 2026-10-07 | feat: complete External Tools manager, HTML Dossier report card, DSML v2 XML export, FGPP calculator, NDNC partitions, and UI layout fixes |
| 30 | **v2.3.0** | [`2b79cea`](https://github.com/catmuf/ad-management-studio/commit/2b79cea8658c1c1d29efc0d4605f300b47400d32) | 2026-10-07 | Implement Active Directory Recycle Bin, Server Monitor telemetry, enhanced LDAP-SQL, and advanced directory tooling |
| 29 | **v2.3.0** | [`ef95c76`](https://github.com/catmuf/ad-management-studio/commit/ef95c769b9d5431448b80880d6e2af59b58f5937) | 2026-10-07 | fix(ui): eliminate button text clipping in Directory Search and toolbars |
| 28 | **v2.3.0** | [`9c943d8`](https://github.com/catmuf/ad-management-studio/commit/9c943d8808c4af9c98fb756d43ae4ce8a75b9ba9) | 2026-10-07 | feat: achieve feature parity with Softerra LDAP Administrator and Apache Directory Studio |
| 27 | **v2.3.0** | [`628d823`](https://github.com/catmuf/ad-management-studio/commit/628d823d500496879149740397c0cf434bf89d76) | 2026-10-07 | fix(ui): improve OU hierarchy tree folder icon visibility and contrast |
| 26 | **v2.2.0** | [`7a834fd`](https://github.com/catmuf/ad-management-studio/commit/7a834fdec6c92654a99b883c5a9f9482836aab8c) | 2026-10-06 | fix: replace unsupported stethoscope emoji with universally supported diagnostic icon |
| 25 | **v2.2.0** | [`36eb106`](https://github.com/catmuf/ad-management-studio/commit/36eb106220f6d2cb027b5d65a9f2a49a17c0ccbf) | 2026-10-06 | fix: resolve Filter-ComboAttributes scoping error in dropdown closures |
| 24 | **v2.2.0** | [`1d15f87`](https://github.com/catmuf/ad-management-studio/commit/1d15f87ca7b6d004395f42dfb3fb48a08fba1fb8) | 2026-10-06 | fix: make all toolbars, panels, and dialogs responsive with WrapPanels and scrollability |
| 23 | **v2.2.0** | [`96b3f1f`](https://github.com/catmuf/ad-management-studio/commit/96b3f1f56ee189183b940ef9ff729c8689e9eeef) | 2026-10-06 | feat: open Manage Members window on double clicking a group row |
| 22 | **v2.2.0** | [`7940128`](https://github.com/catmuf/ad-management-studio/commit/79401288b658e0ffee7e78e8ca043b5ffa7704ce) | 2026-10-06 | fix: resolve empty rows in group member search and display logon usernames |
| 21 | **v2.2.0** | [`c757d00`](https://github.com/catmuf/ad-management-studio/commit/c757d00603942d1cfec8ff575337358e0d78c8a5) | 2026-10-06 | fix: resolve AllScopeUsers property error and eliminate nested array in AD object grids |
| 20 | **v2.2.0** | [`e956b31`](https://github.com/catmuf/ad-management-studio/commit/e956b310d1309e1c121a1f071400d035ce11de0f) | 2026-10-06 | feat: add dynamic table column chooser across all tables, fix groups filters and live search |
| 19 | **v2.1.0** | [`aba6c61`](https://github.com/catmuf/ad-management-studio/commit/aba6c614c7238f502ab37bb30a245e9b338c71c4) | 2026-10-05 | fix(users): resolve search filtering, single-result grid binding, and add live instant search |
| 18 | **v2.1.0** | [`24b9c9c`](https://github.com/catmuf/ad-management-studio/commit/24b9c9c0dbdd7c62b5a3b9620783bbd9ab5c3756) | 2026-10-05 | fix(ui): expand AD server selection field and remove Top App Bar clipping |
| 17 | **v2.1.0** | [`ae8c94e`](https://github.com/catmuf/ad-management-studio/commit/ae8c94e4894adfdcb86b73b79214dba1be1ff20a) | 2026-10-05 | fix(sql): dynamically generate DataGrid columns and bind structured records for LDAP-SQL query results |
| 16 | **v2.1.0** | [`613af27`](https://github.com/catmuf/ad-management-studio/commit/613af27215c36ef5fe3f508f0b47f95fce5e95cf) | 2026-10-05 | fix(search): fix real-time dropdown filtering, auto-select matched attribute, and prevent popup collision |
| 15 | **v2.1.0** | [`d94b52c`](https://github.com/catmuf/ad-management-studio/commit/d94b52c9d5d0d8ea8bb3ea8e20737548280729f6) | 2026-10-05 | fix(search): fix dropdown real-time attribute filtering by removing focus check and using scoped filter function |
| 14 | **v2.1.0** | [`767eede`](https://github.com/catmuf/ad-management-studio/commit/767eede786f7f9737bb216e48f30f38cd09fca6d) | 2026-10-05 | feat(search): enable direct inline real-time search and selection in attribute dropdown menu |
| 13 | **v2.1.0** | [`53e6031`](https://github.com/catmuf/ad-management-studio/commit/53e60318cc81b3badc42a6f6b3095b6f372e1fbf) | 2026-10-05 | feat(search): add live attribute search and dynamic outcome display to Directory Search |
| 12 | **v2.1.0** | [`14883bc`](https://github.com/catmuf/ad-management-studio/commit/14883bc690c5da6059865d2297ac3d3db83c47aa) | 2026-10-05 | feat(search): populate comprehensive and live schema attributes in directory search |
| 11 | **v2.1.0** | [`6bae15a`](https://github.com/catmuf/ad-management-studio/commit/6bae15a9bd77eb29fc398a932892d1489b6b7a2f) | 2026-10-05 | fix(ui): dark mode combobox styling, regex directory search, and OU object browsing |
| 10 | **v2.1.0** | [`6100fe7`](https://github.com/catmuf/ad-management-studio/commit/6100fe7ba6233acb95e17e768d30c89f6fb88146) | 2026-10-05 | fix(ui,core): resolve UI bindings, module parameter mismatches, and encoding issues |
| 9 | **v2.0.0** | [`9100df3`](https://github.com/catmuf/ad-management-studio/commit/9100df39ad529ca54c1729d98824ee74d7706d65) | 2026-10-02 | docs: add comprehensive SysAdmin Handbook and update README with Softerra LDAP suite guide |
| 8 | **v2.0.0** | [`bd6c6b0`](https://github.com/catmuf/ad-management-studio/commit/bd6c6b0f657c5d64e618c86b806793267e59f67a) | 2026-10-02 | feat(app): wire Softerra LDAP suite controller logic, event handlers, and dialogs in main.ps1 |
| 7 | **v2.0.0** | [`29012b6`](https://github.com/catmuf/ad-management-studio/commit/29012b635cb9b62d588e2ea1bcab9a3c910194c5) | 2026-10-02 | feat(ui): redesign interface into professional SysAdmin edition with Softerra suite panels |
| 6 | **v2.0.0** | [`e79c6ed`](https://github.com/catmuf/ad-management-studio/commit/e79c6eda79e284308022fa40fdbbfa2156ab7773) | 2026-10-02 | feat(core): add Softerra LDAP suite engines and service modules |
| 5 | **v2.0.0** | [`62d738d`](https://github.com/catmuf/ad-management-studio/commit/62d738da2da6178d2fda08afaf6bad5a5bb7a19e) | 2026-10-02 | docs: add wiki references to README and configure .gitignore |
| 4 | **v1.0.0** | [`0422fe6`](https://github.com/catmuf/ad-management-studio/commit/0422fe653496a7cf7ce8e63f2351d5ed29efe00c) | 2026-09-23 | feat: complete overhaul to Active Directory Management Studio |
| 3 | **v0.1.0** | [`3b526d6`](https://github.com/catmuf/ad-management-studio/commit/3b526d6aac28cdaf4f1321393048377ac7347f8b) | 2024-08-27 | Upload project |
| 2 | **v0.1.0** | [`4d2ed03`](https://github.com/catmuf/ad-management-studio/commit/4d2ed03e4d6112e59e7ea781b69f9e897402a086) | 2024-08-27 | Update README.md |
| 1 | **v0.1.0** | [`cc155ca`](https://github.com/catmuf/ad-management-studio/commit/cc155ca57bcd7816c5b60459c8d79a1759b5d515) | 2024-08-27 | Initial commit |

---

## 🚀 Detailed Release History by Version

### [v3.4.0] - 2026-10-23
#### RFC 2696 Paging, RFC 3268 Range Retrieval & Multi-Instance Dossier Tabs

Implements RFC 2696 LDAP Simple Paged Results to bypass the 1,000-object MaxPageSize limit, RFC 3268 incremental range retrieval (member;range=0-1499) for large Active Directory groups, memory-safe streamed exports, multi-instance HTML identity dossier tabs with deduplication and in-tab address navigation, consolidated attribute search in Directory Search, and runtime fixes for COM maxPwdAge and DateTime parsing in security audits.

- **Release Commit Range**: [`da403e8`](https://github.com/catmuf/ad-management-studio/commit/da403e8) .. [`a0f4eb4`](https://github.com/catmuf/ad-management-studio/commit/a0f4eb4)
- **Commits in Release**: 4
- **Dedicated Release Notes**: [docs/releases/v3.4.0.md](docs/releases/v3.4.0.md)

##### ✨ Features & Capabilities (2)
- [`a0f4eb4`](https://github.com/catmuf/ad-management-studio/commit/a0f4eb4cad5d16de5bf8e1dbf4301eddebf434d5) - feat(html-view): support multi-instance tabs, deduplication, and in-tab address navigation for HTML dossiers *(2026-10-23)*
- [`dcb0ae9`](https://github.com/catmuf/ad-management-studio/commit/dcb0ae9382a847be78410eaa386787459555b600) - feat(ad-query): implement RFC 2696 LDAP paging, RFC 3268 range retrieval, and streamed exports *(2026-10-23)*

##### 🐛 Bug Fixes & UX Hardening (1)
- [`7af88b4`](https://github.com/catmuf/ad-management-studio/commit/7af88b40e9ff97dcaf6cb44f65c601d24c644f88) - fix(runtime): resolve Show-ObjectHtmlView closure scope, COM maxPwdAge cast, and DateTime parsing in audit service *(2026-10-23)*

##### 🛡️ Stability & Code Quality (1)
- [`da403e8`](https://github.com/catmuf/ad-management-studio/commit/da403e84623d6a96e6980e98a84ac36645b0641d) - refactor(search): consolidate attribute search into CmbFilterAttr and remove redundant TxtSearchAttrFilter *(2026-10-23)*

---

### [v3.3.0] - 2026-10-23
#### Simple Search Mode, Sub-Second Startup, Active Connection Controls & Architecture Hardening

Delivers sub-second application startup via direct XAML streaming and lazy RSAT loading, simple directory search mode with collapsible advanced filters and arrow toggle, active connection management enhancements (expandable DC table, sort arrows, live filter, internal horizontal scrolling), sidebar toggle button and Ctrl+B shortcut, configurable default startup tabs with session state saving, combobox virtualization with debouncing, light mode connection dialog fixes, architectural JIT decomposition of ADService, DirectoryEntry referral hang prevention, and DWM composition quota fallback resilience.

- **Release Commit Range**: [`ed38733`](https://github.com/catmuf/ad-management-studio/commit/ed38733) .. [`fbe83e9`](https://github.com/catmuf/ad-management-studio/commit/fbe83e9)
- **Commits in Release**: 23
- **Dedicated Release Notes**: [docs/releases/v3.3.0.md](docs/releases/v3.3.0.md)

##### ✨ Features & Capabilities (6)
- [`47fbe72`](https://github.com/catmuf/ad-management-studio/commit/47fbe72ccd3133194c4e2743ed447262f707d64c) - feat(release): standardize SemVer v3.3.0, update documentation, and prepare release *(2026-10-23)*
- [`4355905`](https://github.com/catmuf/ad-management-studio/commit/43559054451e43075a787e0ed8233eb9c41ddefc) - feat(search): add simple search mode with collapsible advanced filters and arrow toggle *(2026-10-22)*
- [`a0b75bb`](https://github.com/catmuf/ad-management-studio/commit/a0b75bb4bfe13a2d0000afee2f544e7472ef7b44) - feat(connections): expand DC table height and add expand/compact view toggle *(2026-10-22)*
- [`a6648d9`](https://github.com/catmuf/ad-management-studio/commit/a6648d915e8b987eb204dca40fe703676d5ad4a4) - feat(workspace,tabs): set default startup tabs and add optional session saving in settings *(2026-10-22)*
- [`c2598cc`](https://github.com/catmuf/ad-management-studio/commit/c2598cceb934367283f0241809d952fe8c38c68d) - feat(connections,datagrid): remove redundant ping sort buttons, add sort arrow indicators, and convert domain input to live connection search box *(2026-10-21)*
- [`039fac1`](https://github.com/catmuf/ad-management-studio/commit/039fac1e48452eb306e29c6d8bf1a43a0b29fe73) - feat(ui): add button and keyboard shortcut (Ctrl+B) to toggle sidebar menu *(2026-10-20)*

##### 🐛 Bug Fixes & UX Hardening (8)
- [`69561ba`](https://github.com/catmuf/ad-management-studio/commit/69561babc534670916a6c27ccf1542e46a464959) - fix(adservice): prevent DirectoryEntry referral hangs via reflection dispose and filter benign referral probes *(2026-10-23)*
- [`f5188aa`](https://github.com/catmuf/ad-management-studio/commit/f5188aa8e5603a90a0d889d1fb1336fa5aec0921) - fix(htmlview): export Set-SafeBrowserHtml and panel actions to global scope for secondary tab closures *(2026-10-23)*
- [`c55bd4a`](https://github.com/catmuf/ad-management-studio/commit/c55bd4ab0c2b47642d2bb34e4288abf92fdab0f3) - fix(resilience): resolve backtick parameter breakages, add DWM composition quota fallback and throttle dispatcher errors *(2026-10-23)*
- [`c9113ec`](https://github.com/catmuf/ad-management-studio/commit/c9113ec961428a4ef2ae4e29b50dcaebf762551d) - fix(connections): lock page scroll and enable internal horizontal scrollbar on active connections table *(2026-10-22)*
- [`4b45df4`](https://github.com/catmuf/ad-management-studio/commit/4b45df4367d251c1ae36aa92787351bab4a69522) - fix(connections): add horizontal scrollbar to table and preserve bottom panels during expand view *(2026-10-22)*
- [`fd856c6`](https://github.com/catmuf/ad-management-studio/commit/fd856c67a70ef4b22e2b20ddfff480a78d31bd45) - fix(theme,dialog): resolve light mode unreadable text and input styling in connection dialog *(2026-10-22)*
- [`1af9a29`](https://github.com/catmuf/ad-management-studio/commit/1af9a29071a84513ebfa2a109109358bd2cf66e0) - fix(connections): fix catch block syntax in Invoke-ADConnectionsAutoDetect *(2026-10-21)*
- [`063d13e`](https://github.com/catmuf/ad-management-studio/commit/063d13e1eabada23ec35292575ef1b9bbbd55a92) - fix(audit,connections): resolve profile deletion overload and eliminate audit report freeze *(2026-10-21)*

##### ⚡ Performance & Engine Optimizations (3)
- [`46ab639`](https://github.com/catmuf/ad-management-studio/commit/46ab6392858b23d3ec6a1eddea4dbf67d07b91c6) - perf(search): debounce attribute quick filter, virtualize combobox and prevent UI freeze on backspace *(2026-10-22)*
- [`e2ed4db`](https://github.com/catmuf/ad-management-studio/commit/e2ed4dba6d25efec239611fc53887315090425cb) - perf(launch,xaml): optimize startup loading to sub-second via direct XAML streaming and lazy RSAT *(2026-10-22)*
- [`8dc5387`](https://github.com/catmuf/ad-management-studio/commit/8dc53874f0b3c63504b2bd978d58ee39fe0bba1c) - perf(core,ui): optimize DataGrid pixel scrolling, omnibar debouncing, live filtering, and module loading *(2026-10-20)*

##### 📚 Documentation & Visual Guides (4)
- [`fbe83e9`](https://github.com/catmuf/ad-management-studio/commit/fbe83e996c46bfc0369931d8c61289937ae19889) - docs(release): add Release History & Version Milestones section to README and sync changelog *(2026-10-23)*
- [`0580d9a`](https://github.com/catmuf/ad-management-studio/commit/0580d9a347ee2955bcfcb48736a2cab881c8dc88) - docs: update documentation, handbook, walkthrough, and changelog for v3.3.0 *(2026-10-23)*
- [`8dc606d`](https://github.com/catmuf/ad-management-studio/commit/8dc606de51dbc8901c9db2ad706a0b16dfc70e19) - docs(release): sync v3.3.0 release notes and historical changelog *(2026-10-23)*
- [`ed38733`](https://github.com/catmuf/ad-management-studio/commit/ed387332013c4b7ff10e5fe059b86a439fb73807) - docs(releases): map all 82 historical commits across 10 Semantic Version releases *(2026-10-20)*

##### 🛡️ Stability & Code Quality (1)
- [`2437a94`](https://github.com/catmuf/ad-management-studio/commit/2437a9484a32d6a59a5378924519e1f5c9c1038b) - refactor(scripts): decompose ADService into specialized JIT modules, fix ADSI handle leaks, optimize loops, and clean static analysis *(2026-10-22)*

##### 📦 Maintenance & Setup (1)
- [`ed3270d`](https://github.com/catmuf/ad-management-studio/commit/ed3270d8a2ec4a0abe544498da5660379a499502) - ci(release): automate synchronization of all 10 historical releases via GitHub Actions *(2026-10-20)*

---

### [v3.2.0] - 2026-10-20
#### Native Menu Bar, AD Auto-Detect, Ping Latency & SemVer Standardization

Introduces native Windows horizontal menu bar (11 top-level menus, live checkmarks), Quick Tools dropdown, startup performance optimization via DataGrid UI virtualization and NameScope indexing, search bar alignment & sync, automated DNS SRV domain controller auto-detection with sortable ping latency measurements, standard SemVer v3.2.0 branding, and 19 regenerated application screenshots.

- **Release Commit Range**: [`39892e0`](https://github.com/catmuf/ad-management-studio/commit/39892e0) .. [`ee7d53a`](https://github.com/catmuf/ad-management-studio/commit/ee7d53a)
- **Commits in Release**: 7
- **Dedicated Release Notes**: [docs/releases/v3.2.0.md](docs/releases/v3.2.0.md)

##### ✨ Features & Capabilities (4)
- [`ee7d53a`](https://github.com/catmuf/ad-management-studio/commit/ee7d53a9032aa1a8f876d747ccc291c65364fdf6) - feat(release): standardize SemVer v3.2.0, regenerate screenshots, and automate historical changelog *(2026-10-20)*
- [`691f29f`](https://github.com/catmuf/ad-management-studio/commit/691f29fc1226ad05e6b757964a0b100ce392423d) - feat(connections): add auto-detection of Active Directory connections with sortable ping latency *(2026-10-19)*
- [`9a94499`](https://github.com/catmuf/ad-management-studio/commit/9a944990015ab4a6b631b0b62dd058311f1430ef) - feat(ui): add Global Search label and consolidate top header into Quick Tools dropdown *(2026-10-19)*
- [`39892e0`](https://github.com/catmuf/ad-management-studio/commit/39892e03f2bc6735054da86d456b59648b58be13) - feat(ui): add native horizontal menu bar and high-value competitor feature parity *(2026-10-19)*

##### 🐛 Bug Fixes & UX Hardening (1)
- [`29916e1`](https://github.com/catmuf/ad-management-studio/commit/29916e17f71d272895b96b4f4d52abcbdf6bd6c0) - fix(ui): align search bar controls, separate prefix icon, and sync placeholder across tabs *(2026-10-19)*

##### ⚡ Performance & Engine Optimizations (1)
- [`ab0c97a`](https://github.com/catmuf/ad-management-studio/commit/ab0c97a9fc8304c7c40f4ed3a7a35a839e451c42) - perf: optimize startup with lazy loading, NameScope indexing, and DataGrid UI virtualization *(2026-10-19)*

##### 📚 Documentation & Visual Guides (1)
- [`33c4c91`](https://github.com/catmuf/ad-management-studio/commit/33c4c914b9ae3a6be2243e5757b411f443f8303f) - docs: overhaul README with 19 visual demonstration galleries and native menu reference *(2026-10-19)*

---

### [v3.1.0] - 2026-10-15
#### Platform Hardening, PSSA Compliance & Multi-Dossier Tabs

Deep stability hardening across all 24 administrative panels, recursive event loop elimination, 100% PSScriptAnalyzer compliance, ISO 8601 millisecond logging, multi-dossier tab preservation during navigation, and connection profile deduplication.

- **Release Commit Range**: [`5353d4d`](https://github.com/catmuf/ad-management-studio/commit/5353d4d) .. [`0761bc1`](https://github.com/catmuf/ad-management-studio/commit/0761bc1)
- **Commits in Release**: 10
- **Dedicated Release Notes**: [docs/releases/v3.1.0.md](docs/releases/v3.1.0.md)

##### ✨ Features & Capabilities (5)
- [`d232145`](https://github.com/catmuf/ad-management-studio/commit/d232145d3efbee88f520c6f5d42d649585a9a2f0) - feat: in-process simultaneous multi-instance detached windows with dock-back *(2026-10-14)*
- [`d74a31c`](https://github.com/catmuf/ad-management-studio/commit/d74a31cbac311bd4f602513685066b0e9e697985) - feat(stability): harden core operations, diagnostics and eliminate recursive event loops *(2026-10-14)*
- [`b50eb23`](https://github.com/catmuf/ad-management-studio/commit/b50eb239116e4cd32a91b219f094cf4044a1a11c) - feat(qa): eliminate PSScriptAnalyzer warnings, integrate light theme visual guide and screenshots *(2026-10-14)*
- [`15944a8`](https://github.com/catmuf/ad-management-studio/commit/15944a8e18e96793640d8a261edff671ab12a98c) - feat: implement Softerra, Apache Studio, SCIM 2.0, and NetTools parity suites *(2026-10-14)*
- [`5353d4d`](https://github.com/catmuf/ad-management-studio/commit/5353d4d2531897d434a127512a693e6d0cf0340b) - feat: implement YYYY-MM-DD_HH-mm log file naming convention *(2026-10-14)*

##### 🐛 Bug Fixes & UX Hardening (5)
- [`0761bc1`](https://github.com/catmuf/ad-management-studio/commit/0761bc13bd9ba9993e48adb220b7b3046b1e78bb) - Fix duplicate connection profiles in active profile dropdown and configured profiles list *(2026-10-15)*
- [`b4b67e2`](https://github.com/catmuf/ad-management-studio/commit/b4b67e21771712247f240b31f53a2577cc36869e) - Fix blank view on second search in omnibar and preserve multi-dossier tabs *(2026-10-15)*
- [`cd015f0`](https://github.com/catmuf/ad-management-studio/commit/cd015f031a1021357a79b5154f78160e41652fc5) - Fix Users context menu parity across tabs and auto-render HTML dossier from search *(2026-10-15)*
- [`d67470c`](https://github.com/catmuf/ad-management-studio/commit/d67470c5ebfb8d908fe27caba80652179392b36b) - fix(search-ui): expand global omnibar results, link to HTML dossier, and resolve tab dock errors *(2026-10-14)*
- [`c76455a`](https://github.com/catmuf/ad-management-studio/commit/c76455a1495cabfc0a9e7cba82ab9f993d126dd3) - fix(pssa): resolve all PSScriptAnalyzer errors and warnings across workspace *(2026-10-14)*

---

### [v3.0.0] - 2026-10-13
#### Multi-Instance Detached Windows & Headless Automation CLI

Architectural breakthrough with in-process simultaneous multi-instance detached windows, crash-free zero-latency dock-back, headless automation CLI (tools/ad-studio-cli.ps1) with 5 command modes, structured error logging service, and advanced identity / SDProp trigger engine.

- **Release Commit Range**: [`18bf0c5`](https://github.com/catmuf/ad-management-studio/commit/18bf0c5) .. [`5e81af1`](https://github.com/catmuf/ad-management-studio/commit/5e81af1)
- **Commits in Release**: 11
- **Dedicated Release Notes**: [docs/releases/v3.0.0.md](docs/releases/v3.0.0.md)

##### ✨ Features & Capabilities (4)
- [`5e81af1`](https://github.com/catmuf/ad-management-studio/commit/5e81af169058265d275f198c81b27a59f7a3ae95) - feat: add comprehensive application error logging service and logs directory *(2026-10-13)*
- [`bf31740`](https://github.com/catmuf/ad-management-studio/commit/bf317409c21f43cdb466a45aa7e8486e6774bb2b) - Enable simultaneous multi-instance detached windows under same section *(2026-10-13)*
- [`34e3bb3`](https://github.com/catmuf/ad-management-studio/commit/34e3bb38d2627250853abd46c9d79e929c845338) - feat(parity): implement advanced forensic tools, value editors, and directory engines *(2026-10-13)*
- [`f0ab844`](https://github.com/catmuf/ad-management-studio/commit/f0ab8445ef7ee9ec7ccad2d01886e324f3b1408e) - feat: implement advanced identity, schema hierarchy, SDProp trigger and headless CLI automation *(2026-10-13)*

##### 🐛 Bug Fixes & UX Hardening (7)
- [`a63d5ea`](https://github.com/catmuf/ad-management-studio/commit/a63d5ea20fec1cf0cb03ae3639356c7c3d0eaf97) - fix: in-process multi-instance window detachment with zero latency and crash-free dock-back *(2026-10-13)*
- [`2d24144`](https://github.com/catmuf/ad-management-studio/commit/2d24144aaa6ce1f67313674a98a5384f888834f0) - Fix Column Chooser theme styling, multi-instance tab detachment, and console suppression *(2026-10-13)*
- [`f1d9f06`](https://github.com/catmuf/ad-management-studio/commit/f1d9f067a77d66e4728cae63b814b0b361b7f9d9) - fix(ui): isolate hand cursor to tab headers and restore arrow cursor on content blocks *(2026-10-13)*
- [`5b8510e`](https://github.com/catmuf/ad-management-studio/commit/5b8510e198e2730692bf97168983a8497bcf6a02) - fix(ui): eliminate tab and menu hover flashing by scoping triggers to unselected states *(2026-10-13)*
- [`dd7568f`](https://github.com/catmuf/ad-management-studio/commit/dd7568f9f95fce7c44f962f8e3ed2467520cc3fc) - fix: resolve unapproved verb warning and Save-AppConfig cmdlet reference *(2026-10-13)*
- [`3cca1f4`](https://github.com/catmuf/ad-management-studio/commit/3cca1f45f20c2e5275b380d0ba9afab67a5854ba) - fix: declare outcome badge state properties and guard strict variable access *(2026-10-13)*
- [`18bf0c5`](https://github.com/catmuf/ad-management-studio/commit/18bf0c5c7903ab8a15591c551e219a8926161a26) - fix: make directory search outcome badge legible across light and dark themes *(2026-10-13)*

---

### [v2.4.0] - 2026-10-08
#### Light Theme, In-App HTML Technical Dossier & NetTools Suite

Introduces high-contrast accessibility-audited Light Theme, rich in-app HTML technical identity dossier, complete 16-module NetTools diagnostic parity (Effective Rights, Token Bloat, Replication Suite, 7-Tier UNC diagnostics), and in-window tab drag-and-drop workspace manager.

- **Release Commit Range**: [`442d254`](https://github.com/catmuf/ad-management-studio/commit/442d254) .. [`3b8defa`](https://github.com/catmuf/ad-management-studio/commit/3b8defa)
- **Commits in Release**: 17
- **Dedicated Release Notes**: [docs/releases/v2.4.0.md](docs/releases/v2.4.0.md)

##### ✨ Features & Capabilities (6)
- [`dbdb096`](https://github.com/catmuf/ad-management-studio/commit/dbdb096284abf5bb2b00c9102c5cc68d0580ea5b) - feat(workspace): add tab drag-and-drop reordering, multi-instance tabs, and independent multi-window launch *(2026-10-08)*
- [`c7ecf3b`](https://github.com/catmuf/ad-management-studio/commit/c7ecf3bbf38462da8c338d8bd65e61b476651063) - feat(workspace): add persistent header button and menu to switch workspace and window layout *(2026-10-08)*
- [`46aa438`](https://github.com/catmuf/ad-management-studio/commit/46aa438351266e486c0ec0207f52539e06be8bcc) - feat(workspace): add in-window multi-tabs, detached multi-windows, and single-window mode *(2026-10-08)*
- [`38f0b90`](https://github.com/catmuf/ad-management-studio/commit/38f0b90c05644a45409952670291fdd807bd8e6b) - feat: complete Phase A-F implementation for 100% NetTools feature parity *(2026-10-08)*
- [`83319e5`](https://github.com/catmuf/ad-management-studio/commit/83319e5ba1d63be6a79bf1c5f961742c9d9d088e) - feat: implement NetTools competitor parity and advanced diagnostics suite *(2026-10-08)*
- [`442d254`](https://github.com/catmuf/ad-management-studio/commit/442d254dc4377e5178f400bce4fea1e464c9223f) - feat: add Light Mode appearance option and in-app HTML dossier view *(2026-10-08)*

##### 🐛 Bug Fixes & UX Hardening (11)
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

---

### [v2.3.0] - 2026-10-07
#### Enterprise Parity, SCIM 2.0 Cloud Export & Security Audits

Achieves deep parity with Softerra LDAP Administrator and Apache Directory Studio, adding SCIM 2.0 cloud export, Active Directory Recycle Bin, Server Monitor telemetry, 15 security audit categories (48 reports), LDIF Document Outline tree, and schema class/attribute inspector.

- **Release Commit Range**: [`628d823`](https://github.com/catmuf/ad-management-studio/commit/628d823) .. [`347b6fd`](https://github.com/catmuf/ad-management-studio/commit/347b6fd)
- **Commits in Release**: 11
- **Dedicated Release Notes**: [docs/releases/v2.3.0.md](docs/releases/v2.3.0.md)

##### ✨ Features & Capabilities (6)
- [`347b6fd`](https://github.com/catmuf/ad-management-studio/commit/347b6fd768229f788f9a9e55b95de3ea480b7de0) - feat: implement Softerra gallery parity features (omnibar, rename, LDIF outline, schema inspector, custom reports) *(2026-10-07)*
- [`e7552c6`](https://github.com/catmuf/ad-management-studio/commit/e7552c6eae59d5cb1f5da15c54189aa1e76c292b) - feat(parity): implement enterprise competitor parity features, diagnostics & encoding hardening *(2026-10-07)*
- [`1ea6727`](https://github.com/catmuf/ad-management-studio/commit/1ea67276ae166a08ef6b18e9783329cb584a1e37) - feat: implement SCIM 2.0 cloud export, search query history, object template wizards, dynamic attribute tokens, and 15 security audit categories *(2026-10-07)*
- [`7bb6393`](https://github.com/catmuf/ad-management-studio/commit/7bb6393898f10aacbb436be8a337e37518e404df) - feat: complete External Tools manager, HTML Dossier report card, DSML v2 XML export, FGPP calculator, NDNC partitions, and UI layout fixes *(2026-10-07)*
- [`2b79cea`](https://github.com/catmuf/ad-management-studio/commit/2b79cea8658c1c1d29efc0d4605f300b47400d32) - Implement Active Directory Recycle Bin, Server Monitor telemetry, enhanced LDAP-SQL, and advanced directory tooling *(2026-10-07)*
- [`9c943d8`](https://github.com/catmuf/ad-management-studio/commit/9c943d8808c4af9c98fb756d43ae4ce8a75b9ba9) - feat: achieve feature parity with Softerra LDAP Administrator and Apache Directory Studio *(2026-10-07)*

##### 🐛 Bug Fixes & UX Hardening (5)
- [`267357a`](https://github.com/catmuf/ad-management-studio/commit/267357ab75039b9d2cd7f17147fe7aa749c3461e) - fix(xaml): resolve case sensitivity on VerticalAlignment attribute in search paging bar *(2026-10-07)*
- [`8d33bec`](https://github.com/catmuf/ad-management-studio/commit/8d33bec5b5970c5885b3d8c34f1caae5bc8faf47) - fix: safely initialize ExternalTools collection to prevent state creation failure *(2026-10-07)*
- [`8518e29`](https://github.com/catmuf/ad-management-studio/commit/8518e29c4bd49e4a077d5f8f920119ce40633f93) - fix: wire TreeOUs context menu and enhance RFC 4515 LDAP search escaping in Raw Attribute Editor *(2026-10-07)*
- [`ef95c76`](https://github.com/catmuf/ad-management-studio/commit/ef95c769b9d5431448b80880d6e2af59b58f5937) - fix(ui): eliminate button text clipping in Directory Search and toolbars *(2026-10-07)*
- [`628d823`](https://github.com/catmuf/ad-management-studio/commit/628d823d500496879149740397c0cf434bf89d76) - fix(ui): improve OU hierarchy tree folder icon visibility and contrast *(2026-10-07)*

---

### [v2.2.0] - 2026-10-06
#### Dynamic Column Chooser, Member Manager & Responsive UI

Adds dynamic table column chooser across all directory grids, dedicated group membership manager dialog (search, add, remove, transitive toggle), responsive toolbars with WrapPanels, and universal UI contrast improvements.

- **Release Commit Range**: [`e956b31`](https://github.com/catmuf/ad-management-studio/commit/e956b31) .. [`7a834fd`](https://github.com/catmuf/ad-management-studio/commit/7a834fd)
- **Commits in Release**: 7
- **Dedicated Release Notes**: [docs/releases/v2.2.0.md](docs/releases/v2.2.0.md)

##### ✨ Features & Capabilities (2)
- [`96b3f1f`](https://github.com/catmuf/ad-management-studio/commit/96b3f1f56ee189183b940ef9ff729c8689e9eeef) - feat: open Manage Members window on double clicking a group row *(2026-10-06)*
- [`e956b31`](https://github.com/catmuf/ad-management-studio/commit/e956b310d1309e1c121a1f071400d035ce11de0f) - feat: add dynamic table column chooser across all tables, fix groups filters and live search *(2026-10-06)*

##### 🐛 Bug Fixes & UX Hardening (5)
- [`7a834fd`](https://github.com/catmuf/ad-management-studio/commit/7a834fdec6c92654a99b883c5a9f9482836aab8c) - fix: replace unsupported stethoscope emoji with universally supported diagnostic icon *(2026-10-06)*
- [`36eb106`](https://github.com/catmuf/ad-management-studio/commit/36eb106220f6d2cb027b5d65a9f2a49a17c0ccbf) - fix: resolve Filter-ComboAttributes scoping error in dropdown closures *(2026-10-06)*
- [`1d15f87`](https://github.com/catmuf/ad-management-studio/commit/1d15f87ca7b6d004395f42dfb3fb48a08fba1fb8) - fix: make all toolbars, panels, and dialogs responsive with WrapPanels and scrollability *(2026-10-06)*
- [`7940128`](https://github.com/catmuf/ad-management-studio/commit/79401288b658e0ffee7e78e8ca043b5ffa7704ce) - fix: resolve empty rows in group member search and display logon usernames *(2026-10-06)*
- [`c757d00`](https://github.com/catmuf/ad-management-studio/commit/c757d00603942d1cfec8ff575337358e0d78c8a5) - fix: resolve AllScopeUsers property error and eliminate nested array in AD object grids *(2026-10-06)*

---

### [v2.1.0] - 2026-10-05
#### Interactive Search, Live Schema & Dynamic LDAP-SQL Grid

Introduces real-time inline attribute dropdown search and filtering, live Active Directory schema attribute population, dynamic DataGrid column generation for ANSI LDAP-SQL results, and instant client-side user account filtering.

- **Release Commit Range**: [`6100fe7`](https://github.com/catmuf/ad-management-studio/commit/6100fe7) .. [`aba6c61`](https://github.com/catmuf/ad-management-studio/commit/aba6c61)
- **Commits in Release**: 10
- **Dedicated Release Notes**: [docs/releases/v2.1.0.md](docs/releases/v2.1.0.md)

##### ✨ Features & Capabilities (3)
- [`767eede`](https://github.com/catmuf/ad-management-studio/commit/767eede786f7f9737bb216e48f30f38cd09fca6d) - feat(search): enable direct inline real-time search and selection in attribute dropdown menu *(2026-10-05)*
- [`53e6031`](https://github.com/catmuf/ad-management-studio/commit/53e60318cc81b3badc42a6f6b3095b6f372e1fbf) - feat(search): add live attribute search and dynamic outcome display to Directory Search *(2026-10-05)*
- [`14883bc`](https://github.com/catmuf/ad-management-studio/commit/14883bc690c5da6059865d2297ac3d3db83c47aa) - feat(search): populate comprehensive and live schema attributes in directory search *(2026-10-05)*

##### 🐛 Bug Fixes & UX Hardening (7)
- [`aba6c61`](https://github.com/catmuf/ad-management-studio/commit/aba6c614c7238f502ab37bb30a245e9b338c71c4) - fix(users): resolve search filtering, single-result grid binding, and add live instant search *(2026-10-05)*
- [`24b9c9c`](https://github.com/catmuf/ad-management-studio/commit/24b9c9c0dbdd7c62b5a3b9620783bbd9ab5c3756) - fix(ui): expand AD server selection field and remove Top App Bar clipping *(2026-10-05)*
- [`ae8c94e`](https://github.com/catmuf/ad-management-studio/commit/ae8c94e4894adfdcb86b73b79214dba1be1ff20a) - fix(sql): dynamically generate DataGrid columns and bind structured records for LDAP-SQL query results *(2026-10-05)*
- [`613af27`](https://github.com/catmuf/ad-management-studio/commit/613af27215c36ef5fe3f508f0b47f95fce5e95cf) - fix(search): fix real-time dropdown filtering, auto-select matched attribute, and prevent popup collision *(2026-10-05)*
- [`d94b52c`](https://github.com/catmuf/ad-management-studio/commit/d94b52c9d5d0d8ea8bb3ea8e20737548280729f6) - fix(search): fix dropdown real-time attribute filtering by removing focus check and using scoped filter function *(2026-10-05)*
- [`6bae15a`](https://github.com/catmuf/ad-management-studio/commit/6bae15a9bd77eb29fc398a932892d1489b6b7a2f) - fix(ui): dark mode combobox styling, regex directory search, and OU object browsing *(2026-10-05)*
- [`6100fe7`](https://github.com/catmuf/ad-management-studio/commit/6100fe7ba6233acb95e17e768d30c89f6fb88146) - fix(ui,core): resolve UI bindings, module parameter mismatches, and encoding issues *(2026-10-05)*

---

### [v2.0.0] - 2026-10-02
#### Professional SysAdmin Edition & Softerra Core Engines

Major overhaul of the interface into a professional SysAdmin edition, integrating dedicated Softerra LDAP engines and service modules, dialog controllers in main.ps1, and the comprehensive SysAdmin Handbook.

- **Release Commit Range**: [`62d738d`](https://github.com/catmuf/ad-management-studio/commit/62d738d) .. [`9100df3`](https://github.com/catmuf/ad-management-studio/commit/9100df3)
- **Commits in Release**: 5
- **Dedicated Release Notes**: [docs/releases/v2.0.0.md](docs/releases/v2.0.0.md)

##### ✨ Features & Capabilities (3)
- [`bd6c6b0`](https://github.com/catmuf/ad-management-studio/commit/bd6c6b0f657c5d64e618c86b806793267e59f67a) - feat(app): wire Softerra LDAP suite controller logic, event handlers, and dialogs in main.ps1 *(2026-10-02)*
- [`29012b6`](https://github.com/catmuf/ad-management-studio/commit/29012b635cb9b62d588e2ea1bcab9a3c910194c5) - feat(ui): redesign interface into professional SysAdmin edition with Softerra suite panels *(2026-10-02)*
- [`e79c6ed`](https://github.com/catmuf/ad-management-studio/commit/e79c6eda79e284308022fa40fdbbfa2156ab7773) - feat(core): add Softerra LDAP suite engines and service modules *(2026-10-02)*

##### 📚 Documentation & Visual Guides (2)
- [`9100df3`](https://github.com/catmuf/ad-management-studio/commit/9100df39ad529ca54c1729d98824ee74d7706d65) - docs: add comprehensive SysAdmin Handbook and update README with Softerra LDAP suite guide *(2026-10-02)*
- [`62d738d`](https://github.com/catmuf/ad-management-studio/commit/62d738da2da6178d2fda08afaf6bad5a5bb7a19e) - docs: add wiki references to README and configure .gitignore *(2026-10-02)*

---

### [v1.0.0] - 2026-09-23
#### Complete Overhaul to Active Directory Management Studio

Foundation release completely refactoring the legacy project into Active Directory Management Studio with modern PowerShell and WPF/XAML architecture.

- **Release Commit Range**: [`0422fe6`](https://github.com/catmuf/ad-management-studio/commit/0422fe6) .. [`0422fe6`](https://github.com/catmuf/ad-management-studio/commit/0422fe6)
- **Commits in Release**: 1
- **Dedicated Release Notes**: [docs/releases/v1.0.0.md](docs/releases/v1.0.0.md)

##### ✨ Features & Capabilities (1)
- [`0422fe6`](https://github.com/catmuf/ad-management-studio/commit/0422fe653496a7cf7ce8e63f2351d5ed29efe00c) - feat: complete overhaul to Active Directory Management Studio *(2026-09-23)*

---

### [v0.1.0] - 2024-08-27
#### Initial Project Genesis & Legacy Core

Initial repository creation, baseline user management PowerShell scripts, and project configuration.

- **Release Commit Range**: [`cc155ca`](https://github.com/catmuf/ad-management-studio/commit/cc155ca) .. [`3b526d6`](https://github.com/catmuf/ad-management-studio/commit/3b526d6)
- **Commits in Release**: 3
- **Dedicated Release Notes**: [docs/releases/v0.1.0.md](docs/releases/v0.1.0.md)

##### 📦 Maintenance & Setup (3)
- [`3b526d6`](https://github.com/catmuf/ad-management-studio/commit/3b526d6aac28cdaf4f1321393048377ac7347f8b) - Upload project *(2024-08-27)*
- [`4d2ed03`](https://github.com/catmuf/ad-management-studio/commit/4d2ed03e4d6112e59e7ea781b69f9e897402a086) - Update README.md *(2024-08-27)*
- [`cc155ca`](https://github.com/catmuf/ad-management-studio/commit/cc155ca57bcd7816c5b60459c8d79a1759b5d515) - Initial commit *(2024-08-27)*

---
