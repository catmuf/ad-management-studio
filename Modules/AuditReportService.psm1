<#
.SYNOPSIS
    Active Directory Security Hygiene & Audit Reporting Service Module
.DESCRIPTION
    Provides automated directory security posture scans across 40+ security benchmarks:
    inactive accounts, non-expiring passwords, stale objects, privileged accounts,
    unprotected OUs, password policies, empty groups, and pre-Windows 2000 compatibility.
#>

# Ensure ADService and ValidationService are available
if (-not (Get-Command Invoke-LdapQuery -ErrorAction SilentlyContinue)) {
    Import-Module (Join-Path $PSScriptRoot "ADService.psm1") -DisableNameChecking -ErrorAction SilentlyContinue
}
if (-not (Get-Module -Name ValidationService -ErrorAction SilentlyContinue)) {
    Import-Module (Join-Path $PSScriptRoot "ValidationService.psm1") -DisableNameChecking -Global -ErrorAction SilentlyContinue
}
if (-not (Get-Command Convert-DNToOUPath -ErrorAction SilentlyContinue)) {
    Import-Module (Join-Path $PSScriptRoot "ADService.psm1") -DisableNameChecking -ErrorAction SilentlyContinue
}

function Get-ADSecurityAuditReport {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [Alias("AuditType", "Type")]
        [string]$Category = "InactiveUsers",

        [Parameter(Mandatory = $false)]
        [Alias("InactiveDays")]
        [int]$Days = 90,

        [Parameter(Mandatory = $false)]
        [string]$Server = ""
    )

    $results = New-Object System.Collections.Generic.List[PSCustomObject]
    $summary = [ordered]@{}

    $normalizedCategory = switch -Regex ($Category) {
        '^(Inactive|Stale)User|InactiveAccount'           { "InactiveUsers" }
        'NeverExpire|NoPasswordExpiry'                    { "PasswordsNeverExpire" }
        'ExpiringSoon|SoonExpire|ExpiredPassword'         { "PasswordExpiringSoon" }
        'ExpiredAccount'                                  { "ExpiredAccounts" }
        'Disabled'                                        { "DisabledAccounts" }
        'NotReq|PasswordNotRequired'                      { "PasswordNotRequired" }
        'Locked'                                          { "LockedAccounts" }
        'Privileged|DomainAdmin|AdminUser|AdminAccount'   { "PrivilegedAccounts" }
        'EmptyGroup'                                      { "EmptyGroups" }
        'UnprotectedOU'                                   { "UnprotectedOUs" }
        'ServiceAccount|SPN'                              { "ServiceAccounts" }
        'InactiveComputer|StaleComputer'                  { "InactiveComputers" }
        'RecentlyCreated|RecentUser'                      { "RecentlyCreated" }
        'IncompleteProfile|MissingField'                  { "IncompleteProfiles" }
        'AdminCount'                                      { "AdminCount" }
        'PasswordSettings|PSO|FineGrained'                { "PasswordSettingsObjects" }
        'Circular|GroupCycle'                             { "CircularGroupMemberships" }
        'Orphan|Orphaned'                                 { "OrphanedAccounts" }
        'NeverLogged|NeverLogon'                          { "NeverLoggedInUsers" }
        'PreWin2000|PreWindows'                           { "PreWin2000Compatible" }
        'Tombstone|DeletedObject'                         { "TombstonedDeletedObjects" }
        default                                           { $Category }
    }

    switch ($normalizedCategory) {
        "InactiveUsers" {
            $cutoff = (Get-Date).AddDays(-$Days)
            $query = Invoke-LdapQuery -Filter "(&(objectCategory=person)(objectClass=user))" `
                -PropertiesToLoad @('sAMAccountName', 'displayName', 'department', 'lastLogonTimestamp', 'lastLogon', 'userAccountControl', 'distinguishedName') `
                -PageSize 500 -Server $Server

            $totalEvaluated = 0
            if ($query -and $query.Results) {
                $totalEvaluated = $query.Results.Count
                foreach ($r in $query.Results) {
                    $uac = if ($r.userAccountControl) { [int]$r.userAccountControl } else { 0 }
                    $status = if ($uac -band 2) { "Disabled" } else { "Active" }

                    $dt = $null
                    $lastLogStr = "Never"
                    $rawTime = if ($r.lastLogonTimestamp) { $r.lastLogonTimestamp } else { $r.lastLogon }
                    if ($rawTime) {
                        $parsedDateStr = ConvertFrom-ADLargeInteger -Value $rawTime
                        if ($parsedDateStr -and $parsedDateStr -ne "Never") {
                            try {
                                $dt = [DateTime]$parsedDateStr
                                $lastLogStr = $dt.ToString("yyyy-MM-dd HH:mm")
                            } catch { $dt = $null }
                        }
                    }

                    $isInactive = $false
                    if (-not $dt) {
                        $isInactive = $true
                    } elseif ($dt -lt $cutoff) {
                        $isInactive = $true
                    }

                    if ($isInactive) {
                        $daysDiff = if ($dt) { "$([int]((Get-Date) - $dt).TotalDays) days" } else { "Never Logged On" }
                        $results.Add([PSCustomObject]@{
                            SamAccountName    = "$($r.sAMAccountName)"
                            DisplayName       = if ($r.displayName) { "$($r.displayName)" } else { "$($r.sAMAccountName)" }
                            Department        = if ($r.department) { "$($r.department)" } else { "" }
                            LastLogon         = $lastLogStr
                            Status            = $status
                            DaysInactive      = $daysDiff
                            DistinguishedName = "$($r.DistinguishedName)"
                        })
                    }
                }
            }
            $summary["Total Evaluated"] = $totalEvaluated
            $summary["Inactive Accounts"] = $results.Count
            $summary["Cutoff Threshold"] = "$Days Days"
        }

        "PasswordsNeverExpire" {
            $query = Invoke-LdapQuery -Filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))" -PropertiesToLoad @('sAMAccountName', 'displayName', 'mail', 'pwdLastSet', 'userAccountControl', 'distinguishedName') -Server $Server
            foreach ($r in $query.Results) {
                $results.Add([PSCustomObject]@{
                    SamAccountName    = $r.sAMAccountName
                    DisplayName       = $r.displayName
                    Email             = $r.mail
                    PasswordLastSet   = ConvertFrom-ADLargeInteger -Value $r.pwdLastSet
                    UAC               = $r.userAccountControl
                    DistinguishedName = $r.DistinguishedName
                })
            }
            $summary["Total Affected"] = $results.Count
            $summary["Policy Risk"] = "High (Non-compliant with regular rotation)"
        }

        "LockedAccounts" {
            $query = Invoke-LdapQuery -Filter "(&(objectCategory=person)(objectClass=user)(lockoutTime>=1))" -PropertiesToLoad @('sAMAccountName', 'displayName', 'mail', 'lockoutTime', 'badPwdCount', 'distinguishedName') -Server $Server
            foreach ($r in $query.Results) {
                $results.Add([PSCustomObject]@{
                    SamAccountName    = $r.sAMAccountName
                    DisplayName       = $r.displayName
                    LockoutTime       = ConvertFrom-ADLargeInteger -Value $r.lockoutTime
                    BadPasswordCount  = $r.badPwdCount
                    Email             = $r.mail
                    DistinguishedName = $r.DistinguishedName
                })
            }
            $summary["Locked Accounts"] = $results.Count
            $summary["Action Required"] = if ($results.Count -gt 0) { "Immediate Review / Unlock" } else { "None" }
        }

        "PrivilegedAccounts" {
            $privGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators", "Account Operators")
            $seenUsers = New-Object System.Collections.Generic.HashSet[string]
            
            foreach ($grp in $privGroups) {
                try {
                    $members = Get-ADGroupMembersList -GroupName $grp -ErrorAction Stop
                    foreach ($m in $members) {
                        if ($m.ObjectClass -ne "group" -and -not $seenUsers.Contains($m.SamAccountName)) {
                            [void]$seenUsers.Add($m.SamAccountName)
                            $results.Add([PSCustomObject]@{
                                SamAccountName    = $m.SamAccountName
                                DisplayName       = $m.DisplayName
                                PrivilegedRole    = $grp
                                Email             = $m.Email
                                Status            = if ($m.Enabled) { "Active" } else { "Disabled" }
                                DistinguishedName = $m.DistinguishedName
                            })
                        }
                    }
                }
                catch {
                    $null = $_ # Group might not exist in this domain or language
                }
            }

            # Supplement with users flagged with adminCount=1
            try {
                $query = Invoke-LdapQuery -Filter "(&(objectCategory=person)(objectClass=user)(adminCount=1))" -PropertiesToLoad @('sAMAccountName', 'displayName', 'mail', 'userAccountControl', 'distinguishedName') -Server $Server
                foreach ($r in $query.Results) {
                    if ($r.sAMAccountName -and -not $seenUsers.Contains($r.sAMAccountName)) {
                        [void]$seenUsers.Add($r.sAMAccountName)
                        $uac = if ($r.userAccountControl) { [int]$r.userAccountControl } else { 0 }
                        $results.Add([PSCustomObject]@{
                            SamAccountName    = $r.sAMAccountName
                            DisplayName       = $r.displayName
                            PrivilegedRole    = "AdminSDHolder (adminCount=1)"
                            Email             = $r.mail
                            Status            = if (($uac -band 2) -eq 0) { "Active" } else { "Disabled" }
                            DistinguishedName = $r.DistinguishedName
                        })
                    }
                }
            }
            catch { $null = $_ <# Suppress unhandled exception #> }

            $summary["Privileged Accounts"] = $results.Count
            $summary["Groups Monitored"] = $privGroups -join ", "
        }

        "EmptyGroups" {
            $groups = Get-ADGroupsList
            foreach ($g in $groups) {
                $mList = Get-ADGroupMembersList -GroupName $g.SamAccountName
                if ($mList.Count -eq 0) {
                    $results.Add([PSCustomObject]@{
                        GroupName         = $g.Name
                        SamAccountName    = $g.SamAccountName
                        GroupScope        = $g.GroupScope
                        GroupCategory     = $g.GroupCategory
                        OUPath            = $g.OUPath
                        DistinguishedName = $g.DistinguishedName
                    })
                }
            }
            $summary["Total Groups"] = $groups.Count
            $summary["Empty Groups"] = $results.Count
        }

        "UnprotectedOUs" {
            $ous = Get-ADOUFlatList
            foreach ($ou in $ous) {
                if (-not $ou.ProtectedFromAccidentalDeletion) {
                    $results.Add([PSCustomObject]@{
                        Name              = $ou.Name
                        DistinguishedName = $ou.DistinguishedName
                        Description       = $ou.Description
                        ProtectionStatus  = "Unprotected"
                    })
                }
            }
            $summary["Total OUs"] = $ous.Count
            $summary["Unprotected OUs"] = $results.Count
        }

        "ServiceAccounts" {
            $query = Invoke-LdapQuery -Filter "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))" -PropertiesToLoad @('sAMAccountName', 'displayName', 'servicePrincipalName', 'userAccountControl', 'distinguishedName') -Server $Server
            foreach ($r in $query.Results) {
                $spns = $r.servicePrincipalName
                $spnStr = if ($spns -is [array]) { $spns -join "; " } else { "$spns" }
                $results.Add([PSCustomObject]@{
                    SamAccountName    = $r.sAMAccountName
                    DisplayName       = $r.displayName
                    SPNCount          = if ($spns -is [array]) { $spns.Count } else { 1 }
                    SPNs              = $spnStr
                    DistinguishedName = $r.DistinguishedName
                })
            }
            $summary["Service Accounts (SPNs)"] = $results.Count
        }

        "InactiveComputers" {
            $cutoff = (Get-Date).AddDays(-$Days)
            $query = Invoke-LdapQuery -Filter "(objectClass=computer)" -PropertiesToLoad @('name', 'operatingSystem', 'operatingSystemVersion', 'lastLogonTimestamp', 'userAccountControl', 'distinguishedName') -Server $Server
            foreach ($r in $query.Results) {
                $lastLogonStr = ConvertFrom-ADLargeInteger -Value $r.lastLogonTimestamp
                $isInactive = $false
                if ($lastLogonStr -eq "Never") {
                    $isInactive = $true
                } else {
                    try {
                        $dt = [DateTime]$lastLogonStr
                        if ($dt -lt $cutoff) { $isInactive = $true }
                    } catch { $null = $_ <# Suppress unhandled exception #> }
                }

                if ($isInactive) {
                    $results.Add([PSCustomObject]@{
                        ComputerName      = $r.name
                        OperatingSystem   = $r.operatingSystem
                        OSVersion         = $r.operatingSystemVersion
                        LastLogon         = $lastLogonStr
                        DistinguishedName = $r.DistinguishedName
                    })
                }
            }
            $summary["Total Inactive Computers"] = $results.Count
            $summary["Threshold"] = "$Days Days"
        }

        "AdminCount" {
            $query = Invoke-LdapQuery -Filter "(&(objectCategory=person)(objectClass=user)(adminCount=1))" -PropertiesToLoad @('sAMAccountName', 'displayName', 'mail', 'adminCount', 'userAccountControl', 'distinguishedName') -Server $Server
            foreach ($r in $query.Results) {
                $results.Add([PSCustomObject]@{
                    SamAccountName    = $r.sAMAccountName
                    DisplayName       = $r.displayName
                    Email             = $r.mail
                    AdminCount        = $r.adminCount
                    DistinguishedName = $r.DistinguishedName
                })
            }
            $summary["AdminCount=1 Accounts"] = $results.Count
            $summary["SDProp Flag"] = "adminCount=1 (Protected by AdminSDHolder)"
        }

        "PasswordExpiringSoon" {
            $defaultMaxAgeDays = 90
            try {
                $rootDse = [System.DirectoryServices.DirectoryEntry]"LDAP://RootDSE"
                $domainEntry = [System.DirectoryServices.DirectoryEntry]"LDAP://$($rootDse.defaultNamingContext)"
                $maxPwdAgeTicks = [int64]$domainEntry.Properties['maxPwdAge'].Value
                if ($maxPwdAgeTicks -lt 0) {
                    $ts = [TimeSpan]::FromTicks(-$maxPwdAgeTicks)
                    if ($ts.TotalDays -gt 0) { $defaultMaxAgeDays = [int]$ts.TotalDays }
                }
            } catch { $null = $_ <# Suppress unhandled exception #> }

            $cutoffExpiry = (Get-Date).AddDays($Days)
            $query = Invoke-LdapQuery -Filter "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=65536))(!(userAccountControl:1.2.840.113556.1.4.803:=2))(pwdLastSet>=1))" -PropertiesToLoad @('sAMAccountName', 'displayName', 'mail', 'pwdLastSet', 'distinguishedName') -Server $Server
            foreach ($r in $query.Results) {
                $lastSetStr = ConvertFrom-ADLargeInteger -Value $r.pwdLastSet
                try {
                    $lastSetDate = [DateTime]$lastSetStr
                    $expiryDate = $lastSetDate.AddDays($defaultMaxAgeDays)
                    $remaining = [int]($expiryDate - (Get-Date)).TotalDays
                    if ($expiryDate -le $cutoffExpiry) {
                        $results.Add([PSCustomObject]@{
                            SamAccountName    = $r.sAMAccountName
                            DisplayName       = $r.displayName
                            Email             = $r.mail
                            PasswordLastSet   = $lastSetDate.ToString("yyyy-MM-dd HH:mm")
                            ExpiresOn         = $expiryDate.ToString("yyyy-MM-dd")
                            DaysRemaining     = if ($remaining -lt 0) { "EXPIRED ($([Math]::Abs($remaining)) days ago)" } else { "$remaining days" }
                            DistinguishedName = $r.DistinguishedName
                        })
                    }
                } catch { $null = $_ <# Suppress unhandled exception #> }
            }
            $summary["Policy Max Age"] = "$defaultMaxAgeDays Days"
            $summary["Accounts Expiring Soon"] = $results.Count
            $summary["Expiring Within"] = "$Days Days"
        }

        "PasswordNotRequired" {
            $query = Invoke-LdapQuery -Filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))" -PropertiesToLoad @('sAMAccountName', 'displayName', 'mail', 'userAccountControl', 'distinguishedName') -Server $Server
            foreach ($r in $query.Results) {
                $results.Add([PSCustomObject]@{
                    SamAccountName    = $r.sAMAccountName
                    DisplayName       = $r.displayName
                    Email             = $r.mail
                    UAC               = $r.userAccountControl
                    PolicyRisk        = "Critical (PASSWD_NOTREQD set)"
                    DistinguishedName = $r.DistinguishedName
                })
            }
            $summary["Total Affected"] = $results.Count
            $summary["Risk Rating"] = "CRITICAL (Vulnerable to blank passwords)"
        }

        "RecentlyCreated" {
            $cutoff = (Get-Date).AddDays(-$Days)
            $query = Invoke-LdapQuery -Filter "(&(objectCategory=person)(objectClass=user))" -PropertiesToLoad @('sAMAccountName', 'displayName', 'mail', 'whenCreated', 'department', 'distinguishedName') -Server $Server
            foreach ($r in $query.Results) {
                if ($r.whenCreated -is [DateTime] -and $r.whenCreated -ge $cutoff) {
                    $results.Add([PSCustomObject]@{
                        SamAccountName    = $r.sAMAccountName
                        DisplayName       = $r.displayName
                        Email             = $r.mail
                        Department        = $r.department
                        CreatedDate       = $r.whenCreated.ToString("yyyy-MM-dd HH:mm")
                        AgeInDays         = [int]((Get-Date) - $r.whenCreated).TotalDays
                        DistinguishedName = $r.DistinguishedName
                    })
                }
            }
            $summary["Recently Created Users"] = $results.Count
            $summary["Period Window"] = "Past $Days Days"
        }

        "IncompleteProfiles" {
            $query = Invoke-LdapQuery -Filter "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))" -PropertiesToLoad @('sAMAccountName', 'displayName', 'mail', 'department', 'telephoneNumber', 'title', 'distinguishedName') -Server $Server
            foreach ($r in $query.Results) {
                $missing = @()
                if (-not $r.mail) { $missing += "Email" }
                if (-not $r.department) { $missing += "Department" }
                if (-not $r.telephoneNumber) { $missing += "Phone" }
                if (-not $r.title) { $missing += "Title" }
                if ($missing.Count -gt 0) {
                    $results.Add([PSCustomObject]@{
                        SamAccountName    = $r.sAMAccountName
                        DisplayName       = $r.displayName
                        MissingFields     = $missing -join ", "
                        MissingCount      = $missing.Count
                        DistinguishedName = $r.DistinguishedName
                    })
                }
            }
            $summary["Incomplete Profiles"] = $results.Count
            $summary["Criteria"] = "Active users missing Mail, Department, Phone or Title"
        }

        "PasswordSettingsObjects" {
            $psos = Get-ADPasswordSettingsObjects -Server $Server
            foreach ($p in $psos) {
                $results.Add([PSCustomObject]@{
                    Name              = $p.Name
                    Precedence        = $p.Precedence
                    MinPasswordLength = $p.MinPasswordLength
                    Complexity        = if ($p.ComplexityEnabled) { "Required" } else { "None" }
                    MaxPasswordAge    = $p.MaxPasswordAge
                    LockoutThreshold  = if ($p.LockoutThreshold -eq 0) { "No Lockout" } else { "$($p.LockoutThreshold) attempts" }
                    LockoutDuration   = $p.LockoutDuration
                    AppliesToCount    = $p.AppliesToCount
                    DistinguishedName = $p.DistinguishedName
                })
            }
            $summary["Total PSOs"] = $psos.Count
            $summary["Status"] = if ($psos.Count -gt 0) { "Active Fine-Grained Policies Found" } else { "No Custom PSOs (Domain Default Policy Active)" }
        }

        "CircularGroupMemberships" {
            $allGroups = Get-ADGroupsList
            $groupMap = @{}
            foreach ($g in $allGroups) { $groupMap[$g.DistinguishedName] = $g }
            $visited = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            $recStack = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            $cyclesDetected = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

            function Test-GroupCycle ($currDN, $path) {
                [void]$visited.Add($currDN)
                [void]$recStack.Add($currDN)

                $grpItem = $groupMap[$currDN]
                if ($grpItem) {
                    $members = Get-ADGroupMembersList -GroupName ($grpItem.SamAccountName)
                    foreach ($m in $members) {
                        if ($m.ObjectClass -eq "group" -and $m.DistinguishedName) {
                            if ($recStack.Contains($m.DistinguishedName)) {
                                $cycleKey = "$currDN -> $($m.DistinguishedName)"
                                if (-not $cyclesDetected.Contains($cycleKey)) {
                                    [void]$cyclesDetected.Add($cycleKey)
                                    $results.Add([PSCustomObject]@{
                                        GroupA            = $grpItem.Name
                                        GroupB            = $m.Name
                                        CycleDescription  = "Circular nesting: '$($grpItem.Name)' contains '$($m.Name)', which loops back"
                                        DistinguishedName = $currDN
                                    })
                                }
                            } elseif (-not $visited.Contains($m.DistinguishedName)) {
                                Test-GroupCycle -currDN $m.DistinguishedName -path "$path -> $($m.Name)"
                            }
                        }
                    }
                }
                [void]$recStack.Remove($currDN)
            }
            Set-Alias -Name Check-Cycle -Value Test-GroupCycle

            foreach ($g in $allGroups) {
                if (-not $visited.Contains($g.DistinguishedName)) {
                    Test-GroupCycle -currDN $g.DistinguishedName -path $g.Name
                }
            }
            $summary["Total Groups Checked"] = $allGroups.Count
            $summary["Circular Loops Found"] = $results.Count
            $summary["Risk Rating"] = if ($results.Count -gt 0) { "High (Can cause token expansion recursion/crashes)" } else { "Clean" }
        }

        "OrphanedAccounts" {
            $query = Invoke-LdapQuery -Filter "(&(objectCategory=person)(objectClass=user))" `
                -PropertiesToLoad @('sAMAccountName', 'displayName', 'department', 'manager', 'distinguishedName') `
                -PageSize 500 -Server $Server

            $userDns = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            $totalEvaluated = 0
            if ($query -and $query.Results) {
                $totalEvaluated = $query.Results.Count
                foreach ($u in $query.Results) {
                    if ($u.DistinguishedName) { [void]$userDns.Add($u.DistinguishedName) }
                }

                foreach ($u in $query.Results) {
                    $isOrphan = $false
                    $orphanReason = @()
                    if ($u.manager -and -not $userDns.Contains($u.manager)) {
                        $isOrphan = $true
                        $orphanReason += "Manager reference '$($u.manager)' does not exist"
                    }
                    if ($isOrphan) {
                        $results.Add([PSCustomObject]@{
                            SamAccountName    = "$($u.sAMAccountName)"
                            DisplayName       = if ($u.displayName) { "$($u.displayName)" } else { "$($u.sAMAccountName)" }
                            Department        = "$($u.department)"
                            Reason            = $orphanReason -join "; "
                            DistinguishedName = "$($u.DistinguishedName)"
                        })
                    }
                }
            }
            $summary["Total Evaluated"] = $totalEvaluated
            $summary["Orphaned Accounts"] = $results.Count
        }

        "NeverLoggedInUsers" {
            $query = Invoke-LdapQuery -Filter "(&(objectCategory=person)(objectClass=user)(!(lastLogonTimestamp=*))(!(lastLogon=*)))" `
                -PropertiesToLoad @('sAMAccountName', 'displayName', 'department', 'userAccountControl', 'whenCreated', 'distinguishedName') `
                -PageSize 500 -Server $Server

            $totalEvaluated = 0
            if ($query -and $query.Results) {
                $totalEvaluated = $query.Results.Count
                foreach ($u in $query.Results) {
                    $uac = if ($u.userAccountControl) { [int]$u.userAccountControl } else { 0 }
                    $status = if ($uac -band 2) { "Disabled" } else { "Active" }
                    $createdStr = if ($u.whenCreated) { ConvertFrom-ADLargeInteger -Value $u.whenCreated } else { "" }
                    $results.Add([PSCustomObject]@{
                        SamAccountName    = "$($u.sAMAccountName)"
                        DisplayName       = if ($u.displayName) { "$($u.displayName)" } else { "$($u.sAMAccountName)" }
                        Department        = "$($u.department)"
                        Status            = $status
                        CreatedDate       = $createdStr
                        DistinguishedName = "$($u.DistinguishedName)"
                    })
                }
            }
            $summary["Total Evaluated"] = $totalEvaluated
            $summary["Never Logged In"] = $results.Count
        }

        "PreWin2000Compatible" {
            $members = @()
            try {
                $members = Get-ADGroupMembersList -GroupName "Pre-Windows 2000 Compatible Access" -ErrorAction Stop
            }
            catch { $null = $_ <# Suppress unhandled exception #> }
            foreach ($m in $members) {
                $results.Add([PSCustomObject]@{
                    PrincipalName     = $m.Name
                    SamAccountName    = $m.SamAccountName
                    ObjectClass       = $m.ObjectClass
                    SecurityRisk      = "Broad anonymous/unauthenticated read access permitted"
                    DistinguishedName = $m.DistinguishedName
                })
            }
            $summary["Group Members"] = $results.Count
            $summary["Recommendation"] = "Remove Everyone and Anonymous Logon from this legacy group"
        }

        "TombstonedDeletedObjects" {
            $deleted = Get-ADDeletedObjects -Server $Server
            foreach ($d in $deleted) {
                $results.Add([PSCustomObject]@{
                    Name              = $d.Name
                    ObjectClass       = $d.ObjectClass
                    WhenDeleted       = $d.WhenChanged
                    LastKnownParent   = $d.LastKnownParent
                    DistinguishedName = $d.DistinguishedName
                })
            }
            $summary["Tombstoned Objects"] = $deleted.Count
        }

        "ExpiredAccounts" {
            $nowFileTime = (Get-Date).ToFileTimeUtc()
            $query = Invoke-LdapQuery -Filter "(&(objectCategory=person)(objectClass=user)(accountExpires>=1)(accountExpires<=$nowFileTime))" -PropertiesToLoad @('sAMAccountName', 'displayName', 'mail', 'accountExpires', 'distinguishedName') -Server $Server
            foreach ($r in $query.Results) {
                $expVal = [int64]$r.accountExpires
                if ($expVal -gt 0 -and $expVal -ne 9223372036854775807) {
                    $expDate = [DateTime]::FromFileTimeUtc($expVal)
                    $results.Add([PSCustomObject]@{
                        SamAccountName    = $r.sAMAccountName
                        DisplayName       = $r.displayName
                        Email             = $r.mail
                        ExpirationDate    = $expDate.ToString("yyyy-MM-dd HH:mm")
                        DaysExpired       = [int]((Get-Date) - $expDate).TotalDays
                        DistinguishedName = $r.DistinguishedName
                    })
                }
            }
            $summary["Expired Accounts"] = $results.Count
            $summary["Action Required"] = "Disable or delete expired employee/contractor accounts"
        }

        "DisabledAccounts" {
            $query = Invoke-LdapQuery -Filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))" `
                -PropertiesToLoad @('sAMAccountName', 'displayName', 'department', 'mail', 'distinguishedName') `
                -PageSize 500 -Server $Server

            $totalCount = 0
            if ($query -and $query.Results) {
                $totalCount = $query.Results.Count
                foreach ($u in $query.Results) {
                    $ou = Convert-DNToOUPath -DistinguishedName $u.DistinguishedName
                    $results.Add([PSCustomObject]@{
                        SamAccountName    = "$($u.sAMAccountName)"
                        DisplayName       = if ($u.displayName) { "$($u.displayName)" } else { "$($u.sAMAccountName)" }
                        Department        = "$($u.department)"
                        Email             = "$($u.mail)"
                        OUPath            = $ou
                        DistinguishedName = "$($u.DistinguishedName)"
                    })
                }
            }
            $summary["Disabled Accounts"] = $totalCount
        }

        Default {
            $query = Invoke-LdapQuery -Filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))" `
                -PropertiesToLoad @('sAMAccountName', 'displayName', 'department', 'mail', 'distinguishedName') `
                -PageSize 500 -Server $Server

            $totalCount = 0
            if ($query -and $query.Results) {
                $totalCount = $query.Results.Count
                foreach ($u in $query.Results) {
                    $ou = Convert-DNToOUPath -DistinguishedName $u.DistinguishedName
                    $results.Add([PSCustomObject]@{
                        SamAccountName    = "$($u.sAMAccountName)"
                        DisplayName       = if ($u.displayName) { "$($u.displayName)" } else { "$($u.sAMAccountName)" }
                        Department        = "$($u.department)"
                        Email             = "$($u.mail)"
                        OUPath            = $ou
                        DistinguishedName = "$($u.DistinguishedName)"
                    })
                }
            }
            $summary["Disabled Accounts"] = $totalCount
        }
    }

    $title = switch ($normalizedCategory) {
        "InactiveUsers"            { "Inactive User Accounts" }
        "PasswordsNeverExpire"     { "Accounts with Passwords that Never Expire" }
        "PasswordExpiringSoon"     { "Accounts with Passwords Expiring Soon" }
        "ExpiredAccounts"          { "Expired User and Contractor Accounts" }
        "PasswordNotRequired"      { "Accounts with Password Not Required (PASSWD_NOTREQD)" }
        "RecentlyCreated"          { "Recently Created Active Directory Accounts" }
        "IncompleteProfiles"       { "User Accounts with Incomplete Directory Profiles" }
        "PasswordSettingsObjects"  { "Fine-Grained Password Policies (Password Settings Objects - PSO)" }
        "PrivilegedAccounts"       { "Privileged and Administrative Accounts" }
        "EmptyGroups"              { "Empty Security and Distribution Groups" }
        "UnprotectedOUs"           { "Organizational Units Unprotected from Deletion" }
        "LockedAccounts"           { "Locked Out User Accounts" }
        "DisabledAccounts"         { "Disabled User Accounts" }
        "ServiceAccounts"          { "Configured Service Accounts with SPNs" }
        "InactiveComputers"        { "Inactive Domain Computer Objects" }
        "AdminCount"               { "Accounts with AdminCount=1 (AdminSDHolder Protected)" }
        "CircularGroupMemberships" { "Circular Group Memberships (Nesting Loop Detection)" }
        "OrphanedAccounts"         { "Orphaned Accounts (Missing Manager References)" }
        "NeverLoggedInUsers"       { "User Accounts That Have Never Logged In" }
        "PreWin2000Compatible"     { "Pre-Windows 2000 Compatible Access Permissions" }
        "TombstonedDeletedObjects" { "Tombstoned / Deleted Directory Objects in Recycle Bin" }
        default                    { "$Category Audit" }
    }
    $desc = switch ($normalizedCategory) {
        "InactiveUsers"            { "Users who have not logged in within the last $Days days." }
        "PasswordsNeverExpire"     { "User accounts configured with DONT_EXPIRE_PASSWORD flag." }
        "PasswordExpiringSoon"     { "Accounts whose password will expire within the next $Days days." }
        "ExpiredAccounts"          { "Accounts that have exceeded their configured expiration timestamp." }
        "PasswordNotRequired"      { "High-risk accounts where blank or empty passwords are permitted by policy." }
        "RecentlyCreated"          { "User accounts provisioned within the past $Days days." }
        "IncompleteProfiles"       { "Active user accounts missing essential organizational attributes." }
        "PasswordSettingsObjects"  { "Fine-Grained Password Policies configured in the domain with precedence and lockout thresholds." }
        "PrivilegedAccounts"       { "Members of high-privilege built-in Active Directory security groups." }
        "EmptyGroups"              { "Groups containing zero members that may be candidates for cleanup." }
        "UnprotectedOUs"           { "Organizational Units without accidental deletion protection enabled." }
        "LockedAccounts"           { "Accounts currently locked out due to invalid logon attempts." }
        "DisabledAccounts"         { "User accounts marked as disabled." }
        "ServiceAccounts"          { "Accounts with registered Service Principal Names (SPNs)." }
        "InactiveComputers"        { "Computers with no logon activity in the last $Days days." }
        "AdminCount"               { "User accounts flagged with adminCount=1 whose ACL inheritance is managed by AdminSDHolder." }
        "CircularGroupMemberships" { "Active Directory security or distribution groups nested in circular loops." }
        "OrphanedAccounts"         { "Active user accounts pointing to deleted or non-existent manager DNs." }
        "NeverLoggedInUsers"       { "Accounts that have never logged on to the domain." }
        "PreWin2000Compatible"     { "Identifies members of the legacy Pre-Windows 2000 group that may grant excessive anonymous access." }
        "TombstonedDeletedObjects" { "Objects residing in the Deleted Objects container awaiting tombstone lifetime expiration." }
        default                    { "Security and hygiene audit results for $Category." }
    }

    return [PSCustomObject]@{
        Category     = $normalizedCategory
        AuditType    = $normalizedCategory
        Title        = $title
        Description  = $desc
        SummaryStats = $summary
        Results      = $results
        Findings     = $results
        Count        = $results.Count
        Success      = $true
    }
}


function Get-AD40SecurityAuditReports {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [Alias("Get-ADSecurityAudits40", "Get-SecurityAuditCatalog")]
    param (
        [string]$Category = "",
        [string]$ReportId = "",
        [string]$Severity = "",
        [switch]$Execute,
        [int]$Days = 90,
        [string]$Server = "",
        [System.Collections.IEnumerable]$MockData = $null
    )
    $null = $Days

    $definitions = @(
        # --- 1. Account Security (11) ---
        [PSCustomObject]@{
            Id          = "SEC-PASS-NEVER-EXPIRE"
            Category    = "Account Security"
            Severity    = "Critical"
            Name        = "Passwords Configured to Never Expire"
            Description = "Identifies accounts with the DONT_EXPIRE_PASSWORD flag enabled, which bypasses password aging policies."
            LdapFilter  = "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))"
            Remediation = "Remove the DONT_EXPIRE_PASSWORD flag (UAC bit 0x10000) and enforce domain password rotation policies."
            Evaluate    = { param($u) if ($u.userAccountControl) { ([int64]$u.userAccountControl -band 65536) -ne 0 } elseif ($null -ne $u.PasswordNeverExpires) { [bool]$u.PasswordNeverExpires } else { $false } }
        },
        [PSCustomObject]@{
            Id          = "SEC-PASS-NOT-REQUIRED"
            Category    = "Account Security"
            Severity    = "High"
            Name        = "Password Not Required Permitted"
            Description = "Accounts where the PASSWD_NOTREQD flag allows blank or empty passwords."
            LdapFilter  = "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))"
            Remediation = "Remove the PASSWD_NOTREQD flag (UAC bit 0x20) and assign strong passwords."
            Evaluate    = { param($u) if ($u.userAccountControl) { ([int64]$u.userAccountControl -band 32) -ne 0 } else { $false } }
        },
        [PSCustomObject]@{
            Id          = "SEC-PASS-PLAINTEXT"
            Category    = "Account Security"
            Severity    = "Critical"
            Name        = "Store Password Using Reversible Encryption"
            Description = "Accounts configured to store passwords using reversible encryption, effectively storing plaintext-equivalent credentials."
            LdapFilter  = "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=128))"
            Remediation = "Clear the ENCRYPTED_TEXT_PWD_ALLOWED flag (UAC bit 0x80) and force password reset."
            Evaluate    = { param($u) if ($u.userAccountControl) { ([int64]$u.userAccountControl -band 128) -ne 0 } else { $false } }
        },
        [PSCustomObject]@{
            Id          = "SEC-KERB-NO-PREAUTH"
            Category    = "Account Security"
            Severity    = "High"
            Name        = "Kerberos Pre-Authentication Disabled (AS-REP Roasting)"
            Description = "Accounts vulnerable to AS-REP Roasting due to the DONT_REQ_PREAUTH flag."
            LdapFilter  = "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"
            Remediation = "Enable Kerberos pre-authentication by removing the DONT_REQ_PREAUTH flag (UAC bit 0x400000)."
            Evaluate    = { param($u) if ($u.userAccountControl) { ([int64]$u.userAccountControl -band 4194304) -ne 0 } else { $false } }
        },
        [PSCustomObject]@{
            Id          = "SEC-KERBEROASTABLE-USERS"
            Category    = "Account Security"
            Severity    = "High"
            Name        = "Kerberoastable User Accounts with SPN"
            Description = "Standard user accounts with registered Service Principal Names (SPNs) susceptible to offline ticket cracking."
            LdapFilter  = "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
            Remediation = "Migrate user SPNs to Group Managed Service Accounts (gMSA) or enforce 25+ character AES-encrypted passwords."
            Evaluate    = { param($u) if ($u.servicePrincipalName -or $u.SPN) { $true } else { $false } }
        },
        [PSCustomObject]@{
            Id          = "SEC-DES-ENCRYPTION"
            Category    = "Account Security"
            Severity    = "Medium"
            Name        = "DES Encryption Only Enabled"
            Description = "Accounts restricted to legacy 56-bit DES encryption keys."
            LdapFilter  = "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2097152))"
            Remediation = "Disable DES encryption flag (UAC bit 0x200000) and configure AES-128/256 Kerberos encryption."
            Evaluate    = { param($u) if ($u.userAccountControl) { ([int64]$u.userAccountControl -band 2097152) -ne 0 } else { $false } }
        },
        [PSCustomObject]@{
            Id          = "SEC-UNCONSTRAINED-DELEGATION"
            Category    = "Account Security"
            Severity    = "Critical"
            Name        = "User Accounts with Unconstrained Kerberos Delegation"
            Description = "Users configured with TRUSTED_FOR_DELEGATION flag capable of harvesting TGTs."
            LdapFilter  = "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=524288))"
            Remediation = "Migrate to Resource-Based Constrained Delegation (RBCD) and remove unconstrained delegation flag."
            Evaluate    = { param($u) if ($u.userAccountControl) { ([int64]$u.userAccountControl -band 524288) -ne 0 } else { $false } }
        },
        [PSCustomObject]@{
            Id          = "SEC-ADMINCOUNT-PROTECTED"
            Category    = "Account Security"
            Severity    = "High"
            Name        = "Accounts Flagged by AdminSDHolder (adminCount = 1)"
            Description = "Accounts with adminCount=1 where ACL inheritance is stripped by AdminSDHolder."
            LdapFilter  = "(&(objectCategory=person)(objectClass=user)(adminCount=1))"
            Remediation = "Review if the account is still privileged. If de-privileged, reset adminCount to 0 and re-enable ACL inheritance."
            Evaluate    = { param($u) if ($u.adminCount -eq 1 -or $u.AdminCount -eq 1) { $true } else { $false } }
        },
        [PSCustomObject]@{
            Id          = "SEC-SID-HISTORY"
            Category    = "Account Security"
            Severity    = "High"
            Name        = "Accounts with Populated sIDHistory"
            Description = "Accounts containing migrated sIDHistory attributes that can grant unexpected historical access."
            LdapFilter  = "(&(objectCategory=person)(objectClass=user)(sIDHistory=*))"
            Remediation = "Audit and purge obsolete sIDHistory values post-migration."
            Evaluate    = { param($u) if ($u.sIDHistory) { $true } else { $false } }
        },
        [PSCustomObject]@{
            Id          = "SEC-NOT-DELEGATED"
            Category    = "Account Security"
            Severity    = "High"
            Name        = "Sensitive Administrative Accounts Without Delegation Protection"
            Description = "High-privilege accounts (adminCount=1) lacking the NOT_DELEGATED flag (0x100000)."
            LdapFilter  = "(&(objectCategory=person)(objectClass=user)(adminCount=1)(!(userAccountControl:1.2.840.113556.1.4.803:=1048576)))"
            Remediation = "Enable 'Account is sensitive and cannot be delegated' on all administrative users."
            Evaluate    = { param($u) if (($u.adminCount -eq 1) -and (([int64]$u.userAccountControl -band 1048576) -eq 0)) { $true } else { $false } }
        },
        [PSCustomObject]@{
            Id          = "SEC-PREWIN2000-ACCESS"
            Category    = "Account Security"
            Severity    = "Medium"
            Name        = "Pre-Windows 2000 Compatible Access Group Hygiene"
            Description = "Memberships in the Pre-Windows 2000 Compatible Access group that may expose directory metadata to anonymous users."
            LdapFilter  = "(&(objectCategory=group)(cn=Pre-Windows 2000 Compatible Access)(member=*))"
            Remediation = "Remove 'Everyone' and 'Anonymous Logon' from Pre-Windows 2000 Compatible Access group."
            Evaluate    = { param($u) if ($u.Name -like "*Pre-Windows 2000*" -or $u.cn -like "*Pre-Windows 2000*") { $true } else { $false } }
        },

        # --- 2. Account Lifecycle (10) ---
        [PSCustomObject]@{
            Id          = "LIFE-INACTIVE-90"
            Category    = "Account Lifecycle"
            Severity    = "Medium"
            Name        = "Inactive Accounts (No Logon in 90+ Days)"
            Description = "Accounts with no recorded logon activity within the last 90 days."
            LdapFilter  = "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
            Remediation = "Verify account ownership with management; disable and deprovision inactive users."
            Evaluate    = { param($u) if ($u.DaysInactive -and [int]($u.DaysInactive -replace '\D') -ge 90) { $true } elseif ($u.LastLogon -eq "Never") { $true } else { $false } }
        },
        [PSCustomObject]@{
            Id          = "LIFE-DORMANT-180"
            Category    = "Account Lifecycle"
            Severity    = "High"
            Name        = "Dormant Accounts (No Logon in 180+ Days)"
            Description = "Accounts dormant for over 6 months."
            LdapFilter  = "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
            Remediation = "Disable immediately and schedule for automated archive."
            Evaluate    = { param($u) if ($u.DaysInactive -and [int]($u.DaysInactive -replace '\D') -ge 180) { $true } else { $false } }
        },
        [PSCustomObject]@{
            Id          = "LIFE-NEVER-LOGGED-IN"
            Category    = "Account Lifecycle"
            Severity    = "Medium"
            Name        = "Accounts That Have Never Logged In"
            Description = "Provisioned accounts where logon count is 0 or lastLogonTimestamp is missing."
            LdapFilter  = "(&(objectCategory=person)(objectClass=user)(!(lastLogonTimestamp=*))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
            Remediation = "Contact account requester; disable unutilized accounts."
            Evaluate    = { param($u) if ($u.LastLogon -eq "Never" -or [string]::IsNullOrEmpty("$($u.LastLogon)")) { $true } else { $false } }
        },
        [PSCustomObject]@{
            Id          = "LIFE-EXPIRED-ACCOUNTS"
            Category    = "Account Lifecycle"
            Severity    = "Medium"
            Name        = "Expired User Accounts Past Expiration Date"
            Description = "Accounts whose accountExpires attribute is in the past."
            LdapFilter  = "(&(objectCategory=person)(objectClass=user)(!(accountExpires=0))(!(accountExpires=9223372036854775807)))"
            Remediation = "Disable expired accounts and deprovision assigned access rights."
            Evaluate    = { param($u) if ($u.AccountExpires -and $u.AccountExpires -ne "Never" -and [DateTime]$u.AccountExpires -lt (Get-Date)) { $true } else { $false } }
        },
        [PSCustomObject]@{
            Id          = "LIFE-PASSWORD-EXPIRING-SOON"
            Category    = "Account Lifecycle"
            Severity    = "Low"
            Name        = "Passwords Expiring Within 14 Days"
            Description = "Accounts approaching password expiration cutoff."
            LdapFilter  = "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=65536)))"
            Remediation = "Send automated self-service password reset reminder notification."
            Evaluate    = { param($u) if ($u.PasswordExpires -and [DateTime]$u.PasswordExpires -lt (Get-Date).AddDays(14)) { $true } else { $false } }
        },
        [PSCustomObject]@{
            Id          = "LIFE-PASSWORD-STALE-365"
            Category    = "Account Lifecycle"
            Severity    = "High"
            Name        = "Passwords Not Changed in Over 365 Days"
            Description = "Accounts with static credentials unchanged for over a year."
            LdapFilter  = "(&(objectCategory=person)(objectClass=user)(pwdLastSet<=`$oneYearAgo))"
            Remediation = "Force password change at next logon (pwdLastSet = 0)."
            Evaluate    = { param($u) if ($u.PasswordAgeDays -and [int]$u.PasswordAgeDays -ge 365) { $true } else { $false } }
        },
        [PSCustomObject]@{
            Id          = "LIFE-DISABLED-WITH-GROUPS"
            Category    = "Account Lifecycle"
            Severity    = "Medium"
            Name        = "Disabled Accounts Retaining Group Memberships"
            Description = "Disabled accounts that still belong to security groups other than Domain Users."
            LdapFilter  = "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2)(memberOf=*))"
            Remediation = "Strip all group memberships from deprovisioned user accounts."
            Evaluate    = { param($u) if (([int64]$u.userAccountControl -band 2) -ne 0 -and $u.MemberOf) { $true } else { $false } }
        },
        [PSCustomObject]@{
            Id          = "LIFE-ORPHANED-NO-MANAGER"
            Category    = "Account Lifecycle"
            Severity    = "Low"
            Name        = "Orphaned Accounts Without Assigned Manager"
            Description = "Active employees with missing or unresolvable manager attribute."
            LdapFilter  = "(&(objectCategory=person)(objectClass=user)(!(manager=*))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
            Remediation = "Populate the manager DN to ensure approval workflows and access reviews function."
            Evaluate    = { param($u) if (-not $u.Manager -or $u.Manager -eq "None") { $true } else { $false } }
        },
        [PSCustomObject]@{
            Id          = "LIFE-RECENTLY-PROVISIONED"
            Category    = "Account Lifecycle"
            Severity    = "Informational"
            Name        = "Accounts Provisioned Within Last 30 Days"
            Description = "Audit log of recently created accounts for onboarding verification."
            LdapFilter  = "(&(objectCategory=person)(objectClass=user)(whenCreated>=`$thirtyDaysAgo))"
            Remediation = "Verify onboarding compliance and mandatory security awareness training."
            Evaluate    = { param($u) if ($u.WhenCreated -and [DateTime]$u.WhenCreated -ge (Get-Date).AddDays(-30)) { $true } else { $false } }
        },
        [PSCustomObject]@{
            Id          = "LIFE-INCOMPLETE-PROFILE"
            Category    = "Account Lifecycle"
            Severity    = "Low"
            Name        = "Active Accounts Missing Email or Department"
            Description = "Active accounts lacking essential directory metadata."
            LdapFilter  = "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(|(!(mail=*))(!(department=*))))"
            Remediation = "Synchronize missing metadata from HR source of truth."
            Evaluate    = { param($u) if (-not $u.Mail -or -not $u.Department) { $true } else { $false } }
        },

        # --- 3. Group Hygiene (9) ---
        [PSCustomObject]@{
            Id          = "GRP-EMPTY-SECURITY"
            Category    = "Group Hygiene"
            Severity    = "Low"
            Name        = "Empty Security Groups (0 Members)"
            Description = "Security groups containing zero members."
            LdapFilter  = "(&(objectCategory=group)(!(member=*)))"
            Remediation = "Review if group is obsolete and delete unneeded security principals."
            Evaluate    = { param($g) if ($g.MemberCount -eq 0 -or (-not $g.Members -and -not $g.member)) { $true } else { $false } }
        },
        [PSCustomObject]@{
            Id          = "GRP-CIRCULAR-NESTING"
            Category    = "Group Hygiene"
            Severity    = "High"
            Name        = "Circular Group Nesting Loops"
            Description = "Groups nested in an infinite loop that degrade token size and LSASS evaluation."
            LdapFilter  = "(&(objectCategory=group)(memberOf=*))"
            Remediation = "Break the cycle by removing the reciprocal group membership."
            Evaluate    = { param($g) if ($g.IsCircular -or $g.CircularLoop) { $true } else { $false } }
        },
        [PSCustomObject]@{
            Id          = "GRP-DEEP-NESTING"
            Category    = "Group Hygiene"
            Severity    = "Medium"
            Name        = "Deeply Nested Groups (> 3 Levels)"
            Description = "Groups nested deeper than 3 hierarchy levels causing token bloat."
            LdapFilter  = "(&(objectCategory=group)(memberOf=*))"
            Remediation = "Flatten group architecture into role-based or AGDLP structure."
            Evaluate    = { param($g) if ($g.NestingDepth -and [int]$g.NestingDepth -gt 3) { $true } else { $false } }
        },
        [PSCustomObject]@{
            Id          = "GRP-PRIVILEGED-MEMBERS"
            Category    = "Group Hygiene"
            Severity    = "Critical"
            Name        = "Members of Built-in High-Privilege Groups"
            Description = "Accounts assigned to Domain Admins, Enterprise Admins, or Schema Admins."
            LdapFilter  = "(|(cn=Domain Admins)(cn=Enterprise Admins)(cn=Schema Admins)(cn=Administrators))"
            Remediation = "Enforce Tiered Administration (Tier 0); minimize permanent membership."
            Evaluate    = { param($g) if ($g.GroupName -match '(?i)Domain Admins|Enterprise Admins|Schema Admins|Administrators') { $true } else { $false } }
        },
        [PSCustomObject]@{
            Id          = "GRP-LARGE-GROUPS"
            Category    = "Group Hygiene"
            Severity    = "Medium"
            Name        = "Excessively Large Groups (> 5,000 Members)"
            Description = "Large groups that generate extensive replication traffic and slow Kerberos ticket issuance."
            LdapFilter  = "(&(objectCategory=group)(member=*))"
            Remediation = "Segment into dynamic departmental or location-specific groups."
            Evaluate    = { param($g) if ($g.MemberCount -and [int]$g.MemberCount -gt 5000) { $true } else { $false } }
        },
        [PSCustomObject]@{
            Id          = "GRP-ORPHANED-NO-OWNER"
            Category    = "Group Hygiene"
            Severity    = "Low"
            Name        = "Security Groups Without Owner (managedBy is null)"
            Description = "Unowned groups lacking a designated business custodian."
            LdapFilter  = "(&(objectCategory=group)(!(managedBy=*)))"
            Remediation = "Assign an accountable owner in the managedBy attribute."
            Evaluate    = { param($g) if (-not $g.ManagedBy -or $g.ManagedBy -eq "None") { $true } else { $false } }
        },
        [PSCustomObject]@{
            Id          = "GRP-PRIMARY-GROUP-NONSTANDARD"
            Category    = "Group Hygiene"
            Severity    = "Medium"
            Name        = "Accounts with Non-Default PrimaryGroupID"
            Description = "Accounts whose primaryGroupID is not 513 (Domain Users), often used for privilege concealment."
            LdapFilter  = "(&(objectCategory=person)(objectClass=user)(!(primaryGroupID=513)))"
            Remediation = "Reset primaryGroupID back to 513."
            Evaluate    = { param($u) if ($u.primaryGroupID -and [int]$u.primaryGroupID -ne 513) { $true } else { $false } }
        },
        [PSCustomObject]@{
            Id          = "GRP-DISTRIBUTION-EXTERNAL"
            Category    = "Group Hygiene"
            Severity    = "Medium"
            Name        = "Distribution Groups Allowing Unauthenticated External Senders"
            Description = "Distribution lists vulnerable to external email spoofing."
            LdapFilter  = "(&(objectCategory=group)(msExchRequireAuthToSendTo=FALSE))"
            Remediation = "Require sender authentication on all internal distribution groups."
            Evaluate    = { param($g) if ($g.RequireAuthToSend -eq $false) { $true } else { $false } }
        },
        [PSCustomObject]@{
            Id          = "GRP-FOREIGN-SECURITY-PRINCIPALS"
            Category    = "Group Hygiene"
            Severity    = "Medium"
            Name        = "Groups Containing Foreign Security Principals (Cross-Forest SIDs)"
            Description = "Groups with members from external domains or trusts."
            LdapFilter  = "(&(objectCategory=group)(member=*ForeignSecurityPrincipals*))"
            Remediation = "Review cross-forest trust delegations and audit external SIDs."
            Evaluate    = { param($g) if ($g.Members -match 'ForeignSecurityPrincipals') { $true } else { $false } }
        },

        # --- 4. Computer Health (9) ---
        [PSCustomObject]@{
            Id          = "COMP-INACTIVE-90"
            Category    = "Computer Health"
            Severity    = "Medium"
            Name        = "Inactive Computer Accounts (No Activity in 90+ Days)"
            Description = "Workstation and server accounts inactive for over 90 days."
            LdapFilter  = "(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
            Remediation = "Disable inactive computer objects and de-allocate disk/IP resources."
            Evaluate    = { param($c) if ($c.DaysInactive -and [int]($c.DaysInactive -replace '\D') -ge 90) { $true } else { $false } }
        },
        [PSCustomObject]@{
            Id          = "COMP-OBSOLETE-OS"
            Category    = "Computer Health"
            Severity    = "High"
            Name        = "Computers Running Obsolete / Unsupported Operating Systems"
            Description = "Systems running Windows XP, 7, 2003, 2008, or 2012 past end of life."
            LdapFilter  = "(&(objectCategory=computer)(|(operatingSystem=*XP*)(operatingSystem=*2003*)(operatingSystem=*Windows 7*)(operatingSystem=*2008*)(operatingSystem=*2012*)))"
            Remediation = "Upgrade or isolate obsolete operating systems behind firewall segmentation."
            Evaluate    = { param($c) if ($c.OperatingSystem -match '(?i)XP|2003|Windows 7|2008|2012') { $true } else { $false } }
        },
        [PSCustomObject]@{
            Id          = "COMP-UNCONSTRAINED-DELEGATION"
            Category    = "Computer Health"
            Severity    = "Critical"
            Name        = "Computers with Unconstrained Kerberos Delegation"
            Description = "Non-domain controller computer accounts configured with unconstrained delegation."
            LdapFilter  = "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))"
            Remediation = "Convert to Resource-Based Constrained Delegation (RBCD)."
            Evaluate    = { param($c) if (([int64]$c.userAccountControl -band 524288) -ne 0 -and (([int64]$c.userAccountControl -band 8192) -eq 0)) { $true } else { $false } }
        },
        [PSCustomObject]@{
            Id          = "COMP-MISSING-LAPS"
            Category    = "Computer Health"
            Severity    = "High"
            Name        = "Computers Missing LAPS Password (ms-Mcs-AdmPwd is null)"
            Description = "Endpoints without Windows Local Administrator Password Solution configured."
            LdapFilter  = "(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(`ms-Mcs-AdmPwd`=*))(!(`msLAPS-Password`=*)))"
            Remediation = "Deploy Windows LAPS GPO and verify schema extension permissions."
            Evaluate    = { param($c) if (-not $c.'ms-Mcs-AdmPwd' -and -not $c.'msLAPS-Password' -and -not $c.LAPSConfigured) { $true } else { $false } }
        },
        [PSCustomObject]@{
            Id          = "COMP-MISSING-BITLOCKER"
            Category    = "Computer Health"
            Severity    = "High"
            Name        = "Computers Missing BitLocker Recovery Keys in AD"
            Description = "Client computers without BitLocker TPM recovery secrets backed up in the directory."
            LdapFilter  = "(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
            Remediation = "Enforce BitLocker escrow via Group Policy or Intune configuration."
            Evaluate    = { param($c) if (-not $c.BitLockerKeysEscrowed -or $c.HasBitLocker -eq $false) { $true } else { $false } }
        },
        [PSCustomObject]@{
            Id          = "COMP-STALE-DCS"
            Category    = "Computer Health"
            Severity    = "Critical"
            Name        = "Stale or Unreachable Domain Controllers"
            Description = "Domain controllers failing replication or showing stale logon heartbeats."
            LdapFilter  = "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))"
            Remediation = "Verify dcdiag, repadmin replication status, and demote failed servers cleanly."
            Evaluate    = { param($c) if ($c.IsDC -and $c.ReplicationFailing) { $true } else { $false } }
        },
        [PSCustomObject]@{
            Id          = "COMP-DISABLED-ACCOUNTS"
            Category    = "Computer Health"
            Severity    = "Low"
            Name        = "Disabled Computer Accounts Awaiting Cleanup"
            Description = "Deprovisioned computers retained in active containers."
            LdapFilter  = "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=2))"
            Remediation = "Move to a Disabled OU or delete computer objects after 30 days."
            Evaluate    = { param($c) if (([int64]$c.userAccountControl -band 2) -ne 0) { $true } else { $false } }
        },
        [PSCustomObject]@{
            Id          = "COMP-MISSING-SPN"
            Category    = "Computer Health"
            Severity    = "Medium"
            Name        = "Computers Missing Default HOST Service Principal Names"
            Description = "Computers lacking default HOST/hostname SPNs breaking Kerberos authentication."
            LdapFilter  = "(&(objectCategory=computer)(!(servicePrincipalName=*HOST*))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
            Remediation = "Register required HOST and RestrictedKrbHost SPNs using setspn."
            Evaluate    = { param($c) if (-not $c.servicePrincipalName -or $c.servicePrincipalName -notmatch 'HOST') { $true } else { $false } }
        },
        [PSCustomObject]@{
            Id          = "COMP-PREWIN2000-NAMES"
            Category    = "Computer Health"
            Severity    = "Low"
            Name        = "Computers with Non-Standard Pre-Windows 2000 Names"
            Description = "Computer accounts missing trailing $ in sAMAccountName."
            LdapFilter  = "(&(objectCategory=computer)(!(sAMAccountName=*`$)))"
            Remediation = "Correct computer sAMAccountName format to comply with NetBIOS standards."
            Evaluate    = { param($c) if ($c.sAMAccountName -and -not $c.sAMAccountName.EndsWith('$')) { $true } else { $false } }
        },

        # --- 5. PKI & Certificates (9) ---
        [PSCustomObject]@{
            Id          = "PKI-USER-CERT-EXPIRED"
            Category    = "PKI/Certificates"
            Severity    = "High"
            Name        = "User Accounts with Expired Certificates in userCertificate"
            Description = "Accounts publishing expired X.509 certificates in directory attributes."
            LdapFilter  = "(&(objectCategory=person)(objectClass=user)(userCertificate=*))"
            Remediation = "Purge expired X.509 certs from userCertificate attribute."
            Evaluate    = { param($u) if ($u.userCertificate -and ($u.CertExpired -or $u.CertificateExpired)) { $true } else { $false } }
        },
        [PSCustomObject]@{
            Id          = "PKI-ALT-SECURITY-IDENTITIES"
            Category    = "PKI/Certificates"
            Severity    = "Medium"
            Name        = "Accounts Configured with AltSecurityIdentities Mappings"
            Description = "Accounts with X.509 certificate mappings in altSecurityIdentities."
            LdapFilter  = "(&(objectCategory=person)(objectClass=user)(altSecurityIdentities=*))"
            Remediation = "Audit altSecurityIdentities for unauthorized UPN or Issuer/Subject mappings."
            Evaluate    = { param($u) if ($u.altSecurityIdentities) { $true } else { $false } }
        },
        [PSCustomObject]@{
            Id          = "PKI-ESC1-TEMPLATE-RISK"
            Category    = "PKI/Certificates"
            Severity    = "Critical"
            Name        = "ESC1 Vulnerable Certificate Templates (Client Auth + Enrollee Supplies SAN)"
            Description = "Templates permitting unprivileged enrollees to specify arbitrary SAN identities."
            LdapFilter  = "(&(objectCategory=pKICertificateTemplate)(msPKI-Certificate-Name-Flag:1.2.840.113556.1.4.803:=1))"
            Remediation = "Remove CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT and require manager approval."
            Evaluate    = { param($t) if ($t.IsESC1Vulnerable -or ($t.EnrolleeSuppliesSubject -and $t.ClientAuthentication)) { $true } else { $false } }
        },
        [PSCustomObject]@{
            Id          = "PKI-ESC2-TEMPLATE-RISK"
            Category    = "PKI/Certificates"
            Severity    = "High"
            Name        = "ESC2 Certificate Templates (Any Purpose EKU or Missing EKU)"
            Description = "Templates with Any Purpose EKU or zero EKUs allowing subordinate CA impersonation."
            LdapFilter  = "(&(objectCategory=pKICertificateTemplate)(!(pKIExtendedKeyUsage=*)))"
            Remediation = "Restrict EKUs to explicit issuance requirements; do not use blank or Any Purpose."
            Evaluate    = { param($t) if ($t.IsESC2Vulnerable -or -not $t.pKIExtendedKeyUsage) { $true } else { $false } }
        },
        [PSCustomObject]@{
            Id          = "PKI-WEAK-RSA-KEYS"
            Category    = "PKI/Certificates"
            Severity    = "High"
            Name        = "Certificates with Weak Keys (< 2048-bit RSA)"
            Description = "Certificates signed with RSA 1024-bit or weaker keys."
            LdapFilter  = "(&(objectCategory=pKICertificateTemplate)(msPKI-Minimal-Key-Size<2048))"
            Remediation = "Increase template minimum key size to at least 2048 or 4096 bits."
            Evaluate    = { param($t) if ($t.KeySize -and [int]$t.KeySize -lt 2048) { $true } else { $false } }
        },
        [PSCustomObject]@{
            Id          = "PKI-MISSING-NTAUTH"
            Category    = "PKI/Certificates"
            Severity    = "High"
            Name        = "Missing or Incomplete NTAuthStore Enterprise CA Certificates"
            Description = "Missing CA certificates in the NTAuthCertificates container causing smart card logon failures."
            LdapFilter  = "(&(objectCategory=certificationAuthority))"
            Remediation = "Publish all issuing CAs to NTAuthStore using certutil -dspublish."
            Evaluate    = { param($c) if ($c.NTAuthMissing) { $true } else { $false } }
        },
        [PSCustomObject]@{
            Id          = "PKI-ENROLLMENT-AGENT-RESTRICTION"
            Category    = "PKI/Certificates"
            Severity    = "High"
            Name        = "Restricted Enrollment Agent Templates with Broad Permissions"
            Description = "Enrollment agent certificates allowed without restrictive enrollment agent constraints."
            LdapFilter  = "(&(objectCategory=pKICertificateTemplate)(pKIExtendedKeyUsage=1.3.6.1.4.1.311.20.2.1))"
            Remediation = "Restrict enrollment agent issuance to designated security officers."
            Evaluate    = { param($t) if ($t.IsEnrollmentAgent -and -not $t.HasRestrictions) { $true } else { $false } }
        },
        [PSCustomObject]@{
            Id          = "PKI-UNAUTHENTICATED-AUTOENROLL"
            Category    = "PKI/Certificates"
            Severity    = "Medium"
            Name        = "Certificate Autoenrollment Active for Inactive Accounts"
            Description = "Inactive accounts continuing to automatically renew certificates."
            LdapFilter  = "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(userCertificate=*))"
            Remediation = "Revoke autoenrollment permissions for dormant user populations."
            Evaluate    = { param($u) if ($u.DaysInactive -and [int]($u.DaysInactive -replace '\D') -gt 90 -and $u.userCertificate) { $true } else { $false } }
        },
        [PSCustomObject]@{
            Id          = "PKI-SMARTCARD-NO-EXPIRY"
            Category    = "PKI/Certificates"
            Severity    = "Critical"
            Name        = "Smart Card Required Accounts with Passwords Set to Never Expire"
            Description = "SMARTCARD_REQUIRED accounts where DONT_EXPIRE_PASSWORD flag was also set, leaving long-lived static NTLM hashes."
            LdapFilter  = "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=262144)(userAccountControl:1.2.840.113556.1.4.803:=65536))"
            Remediation = "Enforce regular password rotation even on smart card accounts or expire NTLM hash."
            Evaluate    = { param($u) if (([int64]$u.userAccountControl -band 262144) -ne 0 -and ([int64]$u.userAccountControl -band 65536) -ne 0) { $true } else { $false } }
        }
    )

    # Filter definitions if requested
    $filtered = $definitions
    if ($Category) {
        $filtered = @($filtered | Where-Object { $_.Category -ieq $Category })
    }
    if ($ReportId) {
        $filtered = @($filtered | Where-Object { $_.Id -ieq $ReportId })
    }
    if ($Severity) {
        $filtered = @($filtered | Where-Object { $_.Severity -ieq $Severity })
    }

    if (-not $Execute) {
        return $filtered
    }

    # Execute Audits
    $executionResults = New-Object System.Collections.Generic.List[PSCustomObject]
    foreach ($def in $filtered) {
        $findings = @()
        $totalEvaluated = 0

        if ($MockData -ne $null) {
            $totalEvaluated = @($MockData).Count
            $findings = @($MockData | Where-Object { & $def.Evaluate $_ })
        } else {
            try {
                $queryRes = Invoke-LdapQuery -Filter $def.LdapFilter -Server $Server
                $findings = $queryRes.Results
                $totalEvaluated = $findings.Count
            } catch {
                $findings = @()
            }
        }

        $compliantCount = [Math]::Max(0, $totalEvaluated - $findings.Count)
        $compliancePct = if ($totalEvaluated -gt 0) {
            [Math]::Round(($compliantCount / $totalEvaluated) * 100, 1)
        } else {
            100.0
        }

        $executionResults.Add([PSCustomObject]@{
            ReportId         = $def.Id
            Category         = $def.Category
            Name             = $def.Name
            Severity         = $def.Severity
            Description      = $def.Description
            Remediation      = $def.Remediation
            LdapFilter       = $def.LdapFilter
            Count            = $findings.Count
            Findings         = @($findings)
            TotalEvaluated   = $totalEvaluated
            CompliantPercent = $compliancePct
        })
    }

    return @($executionResults)
}


Set-Alias -Name Get-ADSecurityAudits40 -Value Get-AD40SecurityAuditReports -Scope Global
Set-Alias -Name Get-SecurityAuditCatalog -Value Get-AD40SecurityAuditReports -Scope Global

Export-ModuleMember -Function Get-ADSecurityAuditReport, Get-AD40SecurityAuditReports -Alias Get-ADSecurityAudits40, Get-SecurityAuditCatalog
