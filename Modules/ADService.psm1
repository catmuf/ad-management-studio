<#
.SYNOPSIS
    ActiveDirectory Service module for Active Directory Management Studio.
.DESCRIPTION
    Provides comprehensive, resilient Active Directory operations for Users, Groups,
    and Organizational Units with UI-optimized data models and robust error handling.
#>

# Ensure ActiveDirectory module is loaded
if (-not (Get-Module -Name ActiveDirectory -ErrorAction SilentlyContinue)) {
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
    }
    catch {
        Write-Warning "ActiveDirectory module could not be imported: $_"
    }
}

# Ensure ValidationService is loaded for LDAP/UAC/FileTime converters
$valServicePath = Join-Path $PSScriptRoot "ValidationService.psm1"
if (Test-Path $valServicePath) {
    Import-Module $valServicePath -Global -Force -ErrorAction SilentlyContinue
}

#region Helper Functions
function Convert-DNToOUPath {
    param ([string]$DistinguishedName)
    if ([string]::IsNullOrEmpty($DistinguishedName)) { return "" }
    
    # Extract the parent OU part
    $parts = $DistinguishedName -split '(?<!\\),'
    $ouParts = @()
    foreach ($p in $parts) {
        if ($p -match '^OU=(.*)$') {
            $ouParts += $matches[1]
        }
    }
    if ($ouParts.Count -gt 0) {
        [array]::Reverse($ouParts)
        return $ouParts -join ' / '
    }
    return "Domain Root"
}

function Format-ADUserRecord {
    param ($User)
    
    $isLocked = $false
    try {
        $isLocked = [bool]$User.LockedOut
    } catch { $isLocked = $false }

    $isEnabled = [bool]$User.Enabled

    $statusBadge = "Active"
    $statusColor = "#107C41" # Green
    if (-not $isEnabled) {
        $statusBadge = "Disabled"
        $statusColor = "#D13438" # Red
    } elseif ($isLocked) {
        $statusBadge = "Locked"
        $statusColor = "#FF8C00" # Orange
    }

    $ouPath = Convert-DNToOUPath -DistinguishedName $User.DistinguishedName

    [PSCustomObject]@{
        SamAccountName     = $User.SamAccountName
        DisplayName        = if ($User.DisplayName) { $User.DisplayName } else { "$($User.GivenName) $($User.Surname)".Trim() }
        GivenName          = $User.GivenName
        Surname            = $User.Surname
        UserPrincipalName  = $User.UserPrincipalName
        Mail               = $User.Mail
        Title              = $User.Title
        Department         = $User.Department
        Office             = $User.Office
        Company            = $User.Company
        EmployeeID         = $User.EmployeeID
        Description        = $User.Description
        Enabled            = $isEnabled
        LockedOut          = $isLocked
        StatusBadge        = $statusBadge
        StatusColor        = $statusColor
        DistinguishedName  = $User.DistinguishedName
        OUPath             = $ouPath
        ObjectGUID         = $User.ObjectGUID.ToString()
        SID                = $User.SID.Value
        LastLogonDate      = if ($User.LastLogonDate) { $User.LastLogonDate.ToString("yyyy-MM-dd HH:mm") } else { "Never" }
        PasswordLastSet    = if ($User.PasswordLastSet) { $User.PasswordLastSet.ToString("yyyy-MM-dd HH:mm") } else { "Never" }
        WhenCreated        = if ($User.WhenCreated) { $User.WhenCreated.ToString("yyyy-MM-dd HH:mm") } else { "" }
        WhenChanged        = if ($User.WhenChanged) { $User.WhenChanged.ToString("yyyy-MM-dd HH:mm") } else { "" }
        RawUser            = $User
    }
}
#endregion

#region User Operations
function Get-ADUsersList {
    [CmdletBinding()]
    param (
        [string]$SearchText = "",
        [string]$StatusFilter = "All", # "All", "Active", "Disabled", "Locked"
        [string]$SearchBase = "",
        [int]$Limit = 1000
    )

    $props = @(
        'DisplayName', 'GivenName', 'Surname', 'SamAccountName', 'UserPrincipalName',
        'Mail', 'Title', 'Department', 'Office', 'Company', 'EmployeeID',
        'Description', 'Enabled', 'LockedOut', 'DistinguishedName', 'ObjectGUID',
        'SID', 'LastLogonDate', 'PasswordLastSet', 'WhenCreated', 'WhenChanged'
    )

    $filter = "*"
    if (-not [string]::IsNullOrWhiteSpace($SearchText)) {
        $st = $SearchText.Trim()
        $filter = "(anr -like `"*$st*`") -or (SamAccountName -like `"*$st*`") -or (EmployeeID -like `"*$st*`") -or (Description -like `"*$st*`") -or (Mail -like `"*$st*`")"
    }

    $params = @{
        Properties = $props
        Filter     = $filter
    }

    if (-not [string]::IsNullOrWhiteSpace($SearchBase)) {
        $params['SearchBase'] = $SearchBase
    }

    if ($Limit -gt 0) {
        $params['ResultSetSize'] = $Limit
    }

    try {
        $rawUsers = Get-ADUser @params -ErrorAction Stop
        
        $results = [System.Collections.Generic.List[PSCustomObject]]::new()
        foreach ($u in $rawUsers) {
            $formatted = Format-ADUserRecord -User $u
            
            # Apply status filter
            $include = $true
            switch ($StatusFilter) {
                "Active"   { if (-not $formatted.Enabled -or $formatted.LockedOut) { $include = $false } }
                "Disabled" { if ($formatted.Enabled) { $include = $false } }
                "Locked"   { if (-not $formatted.LockedOut) { $include = $false } }
            }

            if ($include) {
                $results.Add($formatted)
            }
        }

        return $results
    }
    catch {
        Write-Error "Error querying AD users: $_"
        return @()
    }
}

function Get-ADUserDetail {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Identity
    )

    try {
        $user = Get-ADUser -Identity $Identity -Properties * -ErrorAction Stop
        $formatted = Format-ADUserRecord -User $user

        # Get group memberships
        $groups = @()
        if ($user.MemberOf) {
            foreach ($gDN in $user.MemberOf) {
                # Format friendly group name from DN
                if ($gDN -match '^CN=([^,]+)') {
                    $groups += [PSCustomObject]@{
                        Name              = $matches[1]
                        DistinguishedName = $gDN
                    }
                }
            }
        }
        $sortedGroups = $groups | Sort-Object Name

        return [PSCustomObject]@{
            User      = $formatted
            Groups    = $sortedGroups
            RawObject = $user
        }
    }
    catch {
        Write-Error "Failed to get user detail for '$Identity': $_"
        return $null
    }
}

function Test-ADUsernameExists {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$SamAccountName
    )

    try {
        $existing = Get-ADUser -Filter { SamAccountName -eq $SamAccountName } -ErrorAction SilentlyContinue
        return ($null -ne $existing)
    }
    catch {
        return $false
    }
}

function New-ADUserItem {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$FirstName,

        [Parameter(Mandatory = $true)]
        [string]$LastName,

        [Parameter(Mandatory = $true)]
        [string]$SamAccountName,

        [Parameter(Mandatory = $true)]
        [string]$UserPrincipalName,

        [Parameter(Mandatory = $true)]
        [System.Security.SecureString]$Password,

        [Parameter(Mandatory = $true)]
        [string]$Path,

        [string]$DisplayName = "",
        [string]$Email = "",
        [string]$Description = "",
        [string]$Office = "",
        [string]$Title = "",
        [string]$Department = "",
        [string]$Company = "",
        [string]$EmployeeID = "",
        [string]$ScriptPath = "",
        [bool]$Enabled = $true,
        [bool]$MustChangePassword = $true,
        [bool]$PasswordNeverExpires = $false,
        [string[]]$GroupDNs = @()
    )

    if ([string]::IsNullOrWhiteSpace($DisplayName)) {
        $DisplayName = "$FirstName $LastName".Trim()
    }

    $params = @{
        Name                  = $DisplayName
        GivenName             = $FirstName
        Surname               = $LastName
        DisplayName           = $DisplayName
        SamAccountName        = $SamAccountName
        UserPrincipalName     = $UserPrincipalName
        AccountPassword       = $Password
        Path                  = $Path
        Enabled               = $Enabled
        ChangePasswordAtLogon = $MustChangePassword
        PasswordNeverExpires  = $PasswordNeverExpires
    }

    if ($Email)        { $params['EmailAddress'] = $Email }
    if ($Description)  { $params['Description']  = $Description }
    if ($Office)       { $params['Office']       = $Office }
    if ($Title)        { $params['Title']        = $Title }
    if ($Department)   { $params['Department']   = $Department }
    if ($Company)      { $params['Company']      = $Company }
    if ($EmployeeID)   { $params['EmployeeID']   = $EmployeeID }
    if ($ScriptPath)   { $params['ScriptPath']   = $ScriptPath }

    try {
        New-ADUser @params -ErrorAction Stop
        
        # Add to groups if specified
        if ($GroupDNs -and $GroupDNs.Count -gt 0) {
            foreach ($g in $GroupDNs) {
                try {
                    Add-ADGroupMember -Identity $g -Members $SamAccountName -ErrorAction SilentlyContinue
                } catch {
                    Write-Warning "Could not add user '$SamAccountName' to group '$g': $_"
                }
            }
        }

        return [PSCustomObject]@{
            Success = $true
            Message = "User '$DisplayName' ($SamAccountName) created successfully."
        }
    }
    catch {
        return [PSCustomObject]@{
            Success = $false
            Message = "Failed to create user: $($_.Exception.Message)"
        }
    }
}

function Set-ADUserItem {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Identity,

        [string]$FirstName,
        [string]$LastName,
        [string]$DisplayName,
        [string]$Email,
        [string]$Description,
        [string]$Office,
        [string]$Title,
        [string]$Department,
        [string]$Company,
        [string]$EmployeeID
    )

    $params = @{
        Identity = $Identity
    }

    if ($PSBoundParameters.ContainsKey('FirstName'))   { $params['GivenName'] = $FirstName }
    if ($PSBoundParameters.ContainsKey('LastName'))    { $params['Surname'] = $LastName }
    if ($PSBoundParameters.ContainsKey('DisplayName')) { $params['DisplayName'] = $DisplayName }
    if ($PSBoundParameters.ContainsKey('Email'))       { $params['EmailAddress'] = $Email }
    if ($PSBoundParameters.ContainsKey('Description')) { $params['Description'] = $Description }
    if ($PSBoundParameters.ContainsKey('Office'))      { $params['Office'] = $Office }
    if ($PSBoundParameters.ContainsKey('Title'))       { $params['Title'] = $Title }
    if ($PSBoundParameters.ContainsKey('Department'))  { $params['Department'] = $Department }
    if ($PSBoundParameters.ContainsKey('Company'))     { $params['Company'] = $Company }
    if ($PSBoundParameters.ContainsKey('EmployeeID'))  { $params['EmployeeID'] = $EmployeeID }

    try {
        Set-ADUser @params -ErrorAction Stop
        return [PSCustomObject]@{
            Success = $true
            Message = "User '$Identity' updated successfully."
        }
    }
    catch {
        return [PSCustomObject]@{
            Success = $false
            Message = "Failed to update user: $($_.Exception.Message)"
        }
    }
}

function Remove-ADUserItem {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Identity
    )

    try {
        Remove-ADUser -Identity $Identity -Confirm:$false -ErrorAction Stop
        return [PSCustomObject]@{
            Success = $true
            Message = "User '$Identity' deleted successfully."
        }
    }
    catch {
        return [PSCustomObject]@{
            Success = $false
            Message = "Failed to delete user: $($_.Exception.Message)"
        }
    }
}

function Set-ADUserPassword {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Identity,

        [Parameter(Mandatory = $true)]
        [System.Security.SecureString]$NewPassword,

        [bool]$MustChangePassword = $false,
        [bool]$Unlock = $true
    )

    try {
        Set-ADAccountPassword -Identity $Identity -NewPassword $NewPassword -Reset -ErrorAction Stop
        
        if ($MustChangePassword) {
            Set-ADUser -Identity $Identity -ChangePasswordAtLogon $true -ErrorAction SilentlyContinue
        }

        if ($Unlock) {
            Unlock-ADAccount -Identity $Identity -ErrorAction SilentlyContinue
        }

        return [PSCustomObject]@{
            Success = $true
            Message = "Password for '$Identity' reset successfully."
        }
    }
    catch {
        return [PSCustomObject]@{
            Success = $false
            Message = "Failed to reset password: $($_.Exception.Message)"
        }
    }
}

function Set-ADUserStatus {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Identity,

        [Parameter(Mandatory = $true)]
        [bool]$Enable
    )

    try {
        if ($Enable) {
            Enable-ADAccount -Identity $Identity -ErrorAction Stop
            $verb = "enabled"
        } else {
            Disable-ADAccount -Identity $Identity -ErrorAction Stop
            $verb = "disabled"
        }

        return [PSCustomObject]@{
            Success = $true
            Message = "Account '$Identity' has been $verb."
        }
    }
    catch {
        return [PSCustomObject]@{
            Success = $false
            Message = "Failed to change account status: $($_.Exception.Message)"
        }
    }
}

function Unlock-ADUserAccount {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Identity
    )

    try {
        Unlock-ADAccount -Identity $Identity -ErrorAction Stop
        return [PSCustomObject]@{
            Success = $true
            Message = "Account '$Identity' was unlocked successfully."
        }
    }
    catch {
        return [PSCustomObject]@{
            Success = $false
            Message = "Failed to unlock account: $($_.Exception.Message)"
        }
    }
}

function Move-ADPrincipal {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Identity,

        [Parameter(Mandatory = $true)]
        [string]$TargetPath
    )

    try {
        Move-ADObject -Identity $Identity -TargetPath $TargetPath -ErrorAction Stop
        return [PSCustomObject]@{
            Success = $true
            Message = "Object successfully moved to '$TargetPath'."
        }
    }
    catch {
        return [PSCustomObject]@{
            Success = $false
            Message = "Failed to move object: $($_.Exception.Message)"
        }
    }
}
#endregion

#region Group Operations
function Get-ADGroupsList {
    [CmdletBinding()]
    param (
        [string]$SearchText = "",
        [string]$CategoryFilter = "All", # "All", "Security", "Distribution"
        [string]$ScopeFilter = "All",    # "All", "Global", "Universal", "DomainLocal"
        [string]$SearchBase = "",
        [int]$Limit = 1000
    )

    $props = @('Name', 'SamAccountName', 'GroupCategory', 'GroupScope', 'Description', 'DistinguishedName', 'ObjectGUID', 'Members')

    $filter = "*"
    if (-not [string]::IsNullOrWhiteSpace($SearchText)) {
        $st = $SearchText.Trim()
        $filter = "(Name -like `"*$st*`") -or (SamAccountName -like `"*$st*`") -or (Description -like `"*$st*`")"
    }

    $params = @{
        Properties = $props
        Filter     = $filter
    }

    if (-not [string]::IsNullOrWhiteSpace($SearchBase)) {
        $params['SearchBase'] = $SearchBase
    }

    if ($Limit -gt 0) {
        $params['ResultSetSize'] = $Limit
    }

    try {
        $rawGroups = Get-ADGroup @params -ErrorAction Stop
        $results = [System.Collections.Generic.List[PSCustomObject]]::new()

        foreach ($g in $rawGroups) {
            $include = $true

            if ($CategoryFilter -ne "All" -and $g.GroupCategory.ToString() -ne $CategoryFilter) {
                $include = $false
            }
            if ($ScopeFilter -ne "All" -and $g.GroupScope.ToString() -ne $ScopeFilter) {
                $include = $false
            }

            if ($include) {
                $memberCount = if ($g.Members) { $g.Members.Count } else { 0 }
                $ouPath = Convert-DNToOUPath -DistinguishedName $g.DistinguishedName

                $results.Add([PSCustomObject]@{
                    Name              = $g.Name
                    SamAccountName    = $g.SamAccountName
                    GroupCategory     = $g.GroupCategory.ToString()
                    GroupScope        = $g.GroupScope.ToString()
                    Description       = $g.Description
                    MemberCount       = $memberCount
                    OUPath            = $ouPath
                    DistinguishedName = $g.DistinguishedName
                    ObjectGUID        = $g.ObjectGUID.ToString()
                })
            }
        }

        return $results
    }
    catch {
        Write-Error "Error querying AD groups: $_"
        return @()
    }
}

function Get-ADGroupMembersList {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Identity
    )

    try {
        $members = Get-ADGroupMember -Identity $Identity -ErrorAction Stop
        $results = @()
        foreach ($m in $members) {
            $results += [PSCustomObject]@{
                Name              = $m.name
                SamAccountName    = $m.SamAccountName
                ObjectClass       = $m.objectClass
                DistinguishedName = $m.distinguishedName
                SID               = $m.SID.Value
            }
        }
        return $results | Sort-Object Name
    }
    catch {
        Write-Error "Failed to get members of group '$Identity': $_"
        return @()
    }
}

function New-ADGroupItem {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$SamAccountName,

        [Parameter(Mandatory = $true)]
        [string]$Path,

        [ValidateSet("Global", "Universal", "DomainLocal")]
        [string]$GroupScope = "Global",

        [ValidateSet("Security", "Distribution")]
        [string]$GroupCategory = "Security",

        [string]$Description = ""
    )

    $params = @{
        Name           = $Name
        SamAccountName = $SamAccountName
        GroupScope     = $GroupScope
        GroupCategory  = $GroupCategory
        Path           = $Path
    }

    if ($Description) { $params['Description'] = $Description }

    try {
        New-ADGroup @params -ErrorAction Stop
        return [PSCustomObject]@{
            Success = $true
            Message = "Group '$Name' created successfully."
        }
    }
    catch {
        return [PSCustomObject]@{
            Success = $false
            Message = "Failed to create group: $($_.Exception.Message)"
        }
    }
}

function Remove-ADGroupItem {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Identity
    )

    try {
        Remove-ADGroup -Identity $Identity -Confirm:$false -ErrorAction Stop
        return [PSCustomObject]@{
            Success = $true
            Message = "Group '$Identity' deleted successfully."
        }
    }
    catch {
        return [PSCustomObject]@{
            Success = $false
            Message = "Failed to delete group: $($_.Exception.Message)"
        }
    }
}

function Add-ADPrincipalToGroup {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$GroupIdentity,

        [Parameter(Mandatory = $true)]
        [string]$MemberIdentity
    )

    try {
        Add-ADGroupMember -Identity $GroupIdentity -Members $MemberIdentity -ErrorAction Stop
        return [PSCustomObject]@{
            Success = $true
            Message = "Member '$MemberIdentity' added to group '$GroupIdentity'."
        }
    }
    catch {
        return [PSCustomObject]@{
            Success = $false
            Message = "Failed to add member to group: $($_.Exception.Message)"
        }
    }
}

function Remove-ADPrincipalFromGroup {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$GroupIdentity,

        [Parameter(Mandatory = $true)]
        [string]$MemberIdentity
    )

    try {
        Remove-ADGroupMember -Identity $GroupIdentity -Members $MemberIdentity -Confirm:$false -ErrorAction Stop
        return [PSCustomObject]@{
            Success = $true
            Message = "Member '$MemberIdentity' removed from group '$GroupIdentity'."
        }
    }
    catch {
        return [PSCustomObject]@{
            Success = $false
            Message = "Failed to remove member from group: $($_.Exception.Message)"
        }
    }
}
#endregion

#region Organizational Unit (OU) Operations
function Get-ADOUTree {
    [CmdletBinding()]
    param (
        [string]$Server = ""
    )

    try {
        $adDomain = if ($Server) { Get-ADDomain -Server $Server } else { Get-ADDomain }
        $rootDN = $adDomain.DistinguishedName
        $rootName = $adDomain.DNSRoot

        # Fetch all OUs in the domain
        $ouParams = @{
            Filter     = '*'
            Properties = @('Name', 'Description', 'ProtectedFromAccidentalDeletion', 'CanonicalName', 'DistinguishedName')
        }
        if ($Server) { $ouParams['Server'] = $Server }

        $allOUs = Get-ADOrganizationalUnit @ouParams | Sort-Object CanonicalName

        # Root Tree Node
        $rootNode = [PSCustomObject]@{
            Name              = $rootName
            DisplayName       = "$rootName (Domain Root)"
            DistinguishedName = $rootDN
            CanonicalName     = "$rootName/"
            Description       = "Active Directory Domain Root"
            IsProtected       = $true
            Children          = [System.Collections.Generic.List[PSCustomObject]]::new()
            Depth             = 0
        }

        # Map nodes by DistinguishedName for easy hierarchy building
        $nodeMap = [System.Collections.Generic.Dictionary[string, PSCustomObject]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $nodeMap[$rootDN] = $rootNode

        # Create nodes
        foreach ($ou in $allOUs) {
            $node = [PSCustomObject]@{
                Name              = $ou.Name
                DisplayName       = $ou.Name
                DistinguishedName = $ou.DistinguishedName
                CanonicalName     = $ou.CanonicalName
                Description       = $ou.Description
                IsProtected       = [bool]$ou.ProtectedFromAccidentalDeletion
                Children          = [System.Collections.Generic.List[PSCustomObject]]::new()
                Depth             = 1
            }
            $nodeMap[$ou.DistinguishedName] = $node
        }

        # Wire up hierarchy: find parent of each OU
        foreach ($ou in $allOUs) {
            $dn = $ou.DistinguishedName
            $node = $nodeMap[$dn]

            # Parent DN is everything after the first comma
            $parentDN = ($dn -split '(?<!\\),', 2)[1]

            if ($nodeMap.ContainsKey($parentDN)) {
                $parentNode = $nodeMap[$parentDN]
                $node.Depth = $parentNode.Depth + 1
                $parentNode.Children.Add($node)
            }
            else {
                # Fallback to root
                $rootNode.Children.Add($node)
            }
        }

        return $rootNode
    }
    catch {
        Write-Error "Failed to build OU Tree: $_"
        return $null
    }
}

function Get-ADOUFlatList {
    [CmdletBinding()]
    param ()

    try {
        $allOUs = Get-ADOrganizationalUnit -Filter * -Properties Description, ProtectedFromAccidentalDeletion, CanonicalName | 
                  Sort-Object CanonicalName

        $list = [System.Collections.Generic.List[PSCustomObject]]::new()

        foreach ($ou in $allOUs) {
            $cleanCanonical = ($ou.CanonicalName -split '/', 2)[1]
            if ([string]::IsNullOrEmpty($cleanCanonical)) {
                $cleanCanonical = $ou.Name
            }
            
            $depth = ($ou.CanonicalName -split '/').Count - 2
            if ($depth -lt 0) { $depth = 0 }
            $indent = "  " * $depth

            $list.Add([PSCustomObject]@{
                Name              = $ou.Name
                DisplayName       = "$indent$cleanCanonical"
                PathString        = $cleanCanonical
                DistinguishedName = $ou.DistinguishedName
                Description       = $ou.Description
                IsProtected       = [bool]$ou.ProtectedFromAccidentalDeletion
            })
        }

        return $list
    }
    catch {
        Write-Error "Failed to list OUs: $_"
        return @()
    }
}

function New-ADOrganizationalUnitItem {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$Path,

        [string]$Description = "",
        [bool]$Protected = $true
    )

    $params = @{
        Name                            = $Name
        Path                            = $Path
        ProtectedFromAccidentalDeletion = $Protected
    }
    if ($Description) { $params['Description'] = $Description }

    try {
        New-ADOrganizationalUnit @params -ErrorAction Stop
        return [PSCustomObject]@{
            Success = $true
            Message = "Organizational Unit '$Name' created successfully."
        }
    }
    catch {
        return [PSCustomObject]@{
            Success = $false
            Message = "Failed to create OU: $($_.Exception.Message)"
        }
    }
}

function Remove-ADOrganizationalUnitItem {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Identity,

        [bool]$UnprotectFirst = $true
    )

    try {
        if ($UnprotectFirst) {
            Set-ADOrganizationalUnit -Identity $Identity -ProtectedFromAccidentalDeletion $false -ErrorAction Stop
        }

        Remove-ADOrganizationalUnit -Identity $Identity -Recursive -Confirm:$false -ErrorAction Stop

        return [PSCustomObject]@{
            Success = $true
            Message = "Organizational Unit deleted successfully."
        }
    }
    catch {
        return [PSCustomObject]@{
            Success = $false
            Message = "Failed to delete OU: $($_.Exception.Message)"
        }
    }
}
#endregion

#region Dashboard Metrics
function Get-ADDashboardStats {
    [CmdletBinding()]
    param ()

    $stats = [PSCustomObject]@{
        TotalUsers    = 0
        ActiveUsers   = 0
        DisabledUsers = 0
        LockedUsers   = 0
        TotalGroups   = 0
        TotalOUs      = 0
        DomainName    = ""
        PDC           = ""
    }

    try {
        $dom = Get-ADDomain -ErrorAction Stop
        $stats.DomainName = $dom.DNSRoot
        $stats.PDC        = $dom.PDCEmulator

        $users = Get-ADUser -Filter * -Properties Enabled, LockedOut -ResultSetSize 5000 -ErrorAction Stop
        $stats.TotalUsers = $users.Count

        $disabledCount = 0
        $lockedCount   = 0
        foreach ($u in $users) {
            if (-not $u.Enabled) {
                $disabledCount++
            }
            if ($u.LockedOut) {
                $lockedCount++
            }
        }

        $stats.DisabledUsers = $disabledCount
        $stats.LockedUsers   = $lockedCount
        $stats.ActiveUsers   = $users.Count - $disabledCount

        $stats.TotalGroups = (Get-ADGroup -Filter * -ResultSetSize 5000).Count
        $stats.TotalOUs    = (Get-ADOrganizationalUnit -Filter *).Count
    }
    catch {
        Write-Warning "Could not fetch complete dashboard stats: $_"
    }

    return $stats
}
#endregion

#region Softerra LDAP Suite Engine

function Invoke-LdapQuery {
    [CmdletBinding()]
    param (
        [string]$Filter = "(objectClass=*)",
        [string]$SearchBase = "",
        [Alias("SearchScope")]
        [System.DirectoryServices.SearchScope]$Scope = [System.DirectoryServices.SearchScope]::Subtree,
        [string[]]$PropertiesToLoad = @(),
        [int]$PageSize = 1000,
        [int]$SizeLimit = 0,
        [string]$Server = ""
    )

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $results = New-Object System.Collections.Generic.List[PSCustomObject]
    $baseDn = $SearchBase
    $errorMessage = ""

    try {
        if ([string]::IsNullOrWhiteSpace($baseDn)) {
            $rootDse = [System.DirectoryServices.DirectoryEntry]"LDAP://RootDSE"
            $baseDn = $rootDse.defaultNamingContext
        }

        $ldapPath = if ($Server) { "LDAP://$Server/$baseDn" } else { "LDAP://$baseDn" }
        $entry = New-Object System.DirectoryServices.DirectoryEntry($ldapPath)
        $searcher = New-Object System.DirectoryServices.DirectorySearcher($entry)
        $searcher.Filter = $Filter
        $searcher.SearchScope = $Scope
        $searcher.PageSize = $PageSize
        $searcher.SizeLimit = $SizeLimit

        if ($PropertiesToLoad -and $PropertiesToLoad.Count -gt 0) {
            foreach ($prop in $PropertiesToLoad) {
                if ($prop -ne "*") { [void]$searcher.PropertiesToLoad.Add($prop) }
            }
        }

        $searchResult = $searcher.FindAll()
        foreach ($res in $searchResult) {
            $propHash = [ordered]@{}
            $propHash['DistinguishedName'] = $res.Path -replace '^LDAP://[^/]+/', '' -replace '^LDAP://', ''
            
            foreach ($propName in $res.Properties.PropertyNames) {
                $vals = $res.Properties[$propName]
                if ($vals.Count -eq 1) {
                    $val = $vals[0]
                    if ($propName -eq 'objectsid' -and $val -is [byte[]]) {
                        $propHash[$propName] = (New-Object System.Security.Principal.SecurityIdentifier($val, 0)).Value
                    }
                    elseif ($propName -eq 'objectguid' -and $val -is [byte[]]) {
                        $propHash[$propName] = (New-Object System.Guid(,$val)).ToString()
                    }
                    else {
                        $propHash[$propName] = $val
                    }
                }
                elseif ($vals.Count -gt 1) {
                    $propHash[$propName] = @($vals)
                }
            }

            if ($propHash['samaccountname']) { $propHash['SamAccountName'] = $propHash['samaccountname'] }
            if ($propHash['displayname'])    { $propHash['DisplayName'] = $propHash['displayname'] }
            if ($propHash['objectclass'])    { 
                $classes = $propHash['objectclass']
                $propHash['ObjectClass'] = if ($classes -is [array]) { $classes[-1] } else { $classes }
            }

            $results.Add([PSCustomObject]$propHash)
        }
    }
    catch {
        $errorMessage = $_.Exception.Message
        Write-Warning "LDAP Search failed: $_"
    }
    finally {
        $sw.Stop()
    }

    return [PSCustomObject]@{
        Success             = ([string]::IsNullOrEmpty($errorMessage))
        Error               = $errorMessage
        Results             = $results
        Count               = $results.Count
        ElapsedMilliseconds = $sw.ElapsedMilliseconds
        Filter              = $Filter
        SearchBase          = $baseDn
    }
}

function Get-ADObjectRawAttributes {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$DistinguishedName,
        [string]$Server = ""
    )

    $attrList = New-Object System.Collections.Generic.List[PSCustomObject]

    try {
        $ldapPath = if ($Server) { "LDAP://$Server/$DistinguishedName" } else { "LDAP://$DistinguishedName" }
        $entry = New-Object System.DirectoryServices.DirectoryEntry($ldapPath)
        
        $operationalAttrs = @(
            'canonicalName', 'createTimeStamp', 'modifyTimeStamp',
            'pwdLastSet', 'lastLogon', 'lastLogonTimestamp', 'badPasswordTime', 'lockoutTime',
            'accountExpires', 'msDS-UserPasswordExpiryTimeComputed', 'tokenGroups',
            'objectSid', 'objectGUID', 'userAccountControl', 'whenCreated', 'whenChanged',
            'distinguishedName', 'sAMAccountName', 'userPrincipalName'
        )

        try {
            $entry.RefreshCache($operationalAttrs)
        } catch {}

        $opSet = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($op in $operationalAttrs) { [void]$opSet.Add($op) }

        foreach ($propName in $entry.Properties.PropertyNames) {
            $propValues = $entry.Properties[$propName]
            $valCount = $propValues.Count
            $isMulti = ($valCount -gt 1)
            $isOp = $opSet.Contains($propName)

            $displayVal = ""
            $typeStr = "String"
            $rawValue = $null

            if ($valCount -eq 0) {
                $displayVal = "<not set>"
                $typeStr = "Empty"
            }
            elseif ($valCount -eq 1) {
                $firstVal = $propValues[0]
                $rawValue = $firstVal

                if ($propName -eq "userAccountControl") {
                    $uacInt = [int64]$firstVal
                    $decoded = ConvertFrom-UACFlags -UAC $uacInt
                    $displayVal = "$uacInt ($($decoded.ActiveFlags))"
                    $typeStr = "Bitmask (UAC)"
                }
                elseif ($propName -match '^(pwdLastSet|lastLogon|lastLogonTimestamp|badPasswordTime|lockoutTime|accountExpires)$') {
                    $displayVal = ConvertFrom-ADLargeInteger -Value $firstVal
                    $typeStr = "LargeInteger (DateTime)"
                }
                elseif ($propName -match '^(whenCreated|whenChanged|createTimeStamp|modifyTimeStamp)$') {
                    if ($firstVal -is [DateTime]) {
                        $displayVal = $firstVal.ToString("yyyy-MM-dd HH:mm:ss")
                    } else {
                        $displayVal = "$firstVal"
                    }
                    $typeStr = "GeneralizedTime"
                }
                elseif ($propName -eq "objectSid" -or ($firstVal -is [byte[]] -and $propName -match 'sid')) {
                    $displayVal = ConvertFrom-ADSid -Value $firstVal
                    $typeStr = "SecurityIdentifier (SID)"
                }
                elseif ($propName -eq "objectGUID" -or ($firstVal -is [byte[]] -and $firstVal.Length -eq 16 -and $propName -match 'guid')) {
                    $displayVal = ConvertFrom-ADGuid -Value $firstVal
                    $typeStr = "Guid (128-bit)"
                }
                elseif ($firstVal -is [byte[]]) {
                    $hex = ($firstVal | Select-Object -First 32 | ForEach-Object { $_.ToString("X2") }) -join " "
                    $displayVal = "Binary ($($firstVal.Length) bytes): $hex" + $(if ($firstVal.Length -gt 32) { "..." } else { "" })
                    $typeStr = "OctetString (Binary)"
                }
                elseif ($firstVal -is [bool]) {
                    $displayVal = if ($firstVal) { "TRUE" } else { "FALSE" }
                    $typeStr = "Boolean"
                }
                else {
                    $displayVal = "$firstVal"
                    $typeStr = $firstVal.GetType().Name
                }
            }
            else {
                $vals = @($propValues)
                $rawValue = $vals
                $typeStr = "Multi-Valued ($valCount values)"
                $displayVal = ($vals | Select-Object -First 5 | ForEach-Object { "$_" }) -join "; "
                if ($valCount -gt 5) { $displayVal += "; ... (+$($valCount - 5) more)" }
            }

            $attrList.Add([PSCustomObject]@{
                Name          = $propName
                Value         = $displayVal
                RawValue      = $rawValue
                Type          = $typeStr
                Count         = $valCount
                IsMultiValued = $isMulti
                IsOperational = $isOp
            })
        }
    }
    catch {
        Write-Warning "Could not retrieve raw attributes for ${DistinguishedName}: $_"
    }

    return $attrList | Sort-Object Name
}

function Set-ADObjectRawAttribute {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$DistinguishedName,
        [Parameter(Mandatory = $true)]
        [string]$AttributeName,
        [Parameter(Mandatory = $true)]
        $NewValue,
        [string]$Server = ""
    )

    try {
        $ldapPath = if ($Server) { "LDAP://$Server/$DistinguishedName" } else { "LDAP://$DistinguishedName" }
        $entry = New-Object System.DirectoryServices.DirectoryEntry($ldapPath)
        
        if ($null -eq $NewValue -or [string]::IsNullOrEmpty("$NewValue")) {
            $entry.Properties[$AttributeName].Clear()
        }
        elseif ($NewValue -is [array]) {
            $entry.Properties[$AttributeName].Value = $NewValue
        }
        else {
            $entry.Properties[$AttributeName].Value = $NewValue
        }

        $entry.CommitChanges()
        return [PSCustomObject]@{ Success = $true; Message = "Attribute '$AttributeName' successfully updated." }
    }
    catch {
        return [PSCustomObject]@{ Success = $false; Message = "Failed to update attribute '$AttributeName': $_" }
    }
}

function Add-ADObjectRawAttributeValue {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$DistinguishedName,
        [Parameter(Mandatory = $true)]
        [string]$AttributeName,
        [Parameter(Mandatory = $true)]
        [string]$ValueToAdd,
        [string]$Server = ""
    )

    try {
        $ldapPath = if ($Server) { "LDAP://$Server/$DistinguishedName" } else { "LDAP://$DistinguishedName" }
        $entry = New-Object System.DirectoryServices.DirectoryEntry($ldapPath)
        [void]$entry.Properties[$AttributeName].Add($ValueToAdd)
        $entry.CommitChanges()
        return [PSCustomObject]@{ Success = $true; Message = "Value added to '$AttributeName'." }
    }
    catch {
        return [PSCustomObject]@{ Success = $false; Message = "Failed to add value to '$AttributeName': $_" }
    }
}

function Remove-ADObjectRawAttributeValue {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$DistinguishedName,
        [Parameter(Mandatory = $true)]
        [string]$AttributeName,
        [Parameter(Mandatory = $true)]
        [string]$ValueToRemove,
        [string]$Server = ""
    )

    try {
        $ldapPath = if ($Server) { "LDAP://$Server/$DistinguishedName" } else { "LDAP://$DistinguishedName" }
        $entry = New-Object System.DirectoryServices.DirectoryEntry($ldapPath)
        [void]$entry.Properties[$AttributeName].Remove($ValueToRemove)
        $entry.CommitChanges()
        return [PSCustomObject]@{ Success = $true; Message = "Value removed from '$AttributeName'." }
    }
    catch {
        return [PSCustomObject]@{ Success = $false; Message = "Failed to remove value from '$AttributeName': $_" }
    }
}

function Clear-ADObjectRawAttribute {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$DistinguishedName,
        [Parameter(Mandatory = $true)]
        [string]$AttributeName,
        [string]$Server = ""
    )

    try {
        $ldapPath = if ($Server) { "LDAP://$Server/$DistinguishedName" } else { "LDAP://$DistinguishedName" }
        $entry = New-Object System.DirectoryServices.DirectoryEntry($ldapPath)
        $entry.Properties[$AttributeName].Clear()
        $entry.CommitChanges()
        return [PSCustomObject]@{ Success = $true; Message = "Attribute '$AttributeName' cleared." }
    }
    catch {
        return [PSCustomObject]@{ Success = $false; Message = "Failed to clear attribute '$AttributeName': $_" }
    }
}

function Invoke-LdapSqlQuery {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [Alias("Query")]
        [string]$SqlQuery,
        [string]$DefaultSearchBase = "",
        [string]$Server = ""
    )

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $cleanQuery = $SqlQuery.Trim() -replace '\s+', ' '

    $selectPattern = '(?i)^SELECT\s+(.+?)\s+FROM\s+(.+?)(?:\s+WHERE\s+(.+?))?(?:\s+ORDER\s+BY\s+(.+?))?$'
    
    if (-not ($cleanQuery -match $selectPattern)) {
        if ($cleanQuery.StartsWith('(')) {
            return Invoke-LdapQuery -Filter $cleanQuery -SearchBase $DefaultSearchBase -Server $Server
        }
        return [PSCustomObject]@{
            Success             = $false
            Results             = @()
            Count               = 0
            ElapsedMilliseconds = 0
            Message             = "Invalid query format. Example: SELECT sAMAccountName, mail FROM 'OU=IT,...' WHERE objectClass = 'user'"
        }
    }

    $colsPart  = $matches[1].Trim()
    $fromPart  = $matches[2].Trim().Trim("'", '"')
    $wherePart = if ($matches[3]) { $matches[3].Trim() } else { "" }
    $orderPart = if ($matches[4]) { $matches[4].Trim() } else { "" }

    $propsToLoad = @()
    if ($colsPart -ne "*") {
        $propsToLoad = ($colsPart -split ',') | ForEach-Object { $_.Trim() }
    }

    $scope = [System.DirectoryServices.SearchScope]::Subtree
    $baseDn = $DefaultSearchBase

    if ($fromPart -match '^(?i)SUBTREE$') {
        $scope = [System.DirectoryServices.SearchScope]::Subtree
    }
    elseif ($fromPart -match '^(?i)ONELEVEL$') {
        $scope = [System.DirectoryServices.SearchScope]::OneLevel
    }
    elseif ($fromPart -match '^(?i)BASE$') {
        $scope = [System.DirectoryServices.SearchScope]::Base
    }
    elseif ($fromPart) {
        $baseDn = $fromPart
    }

    $ldapFilter = "(objectClass=*)"
    if ($wherePart) {
        if ($wherePart.StartsWith('(')) {
            $ldapFilter = $wherePart
        }
        else {
            $conditions = $wherePart -split '(?i)\s+AND\s+'
            $filterItems = @()
            foreach ($cond in $conditions) {
                if ($cond -match "^(\w+)\s*=\s*'?(.*?)'?$") {
                    $filterItems += "($($matches[1])=$($matches[2]))"
                }
                elseif ($cond -match "^(\w+)\s*!=\s*'?(.*?)'?$") {
                    $filterItems += "(!($($matches[1])=$($matches[2])))"
                }
                elseif ($cond -match "^(\w+)\s+IS\s+NOT\s+NULL$") {
                    $filterItems += "($($matches[1])=*)"
                }
                elseif ($cond -match "^(\w+)\s+IS\s+NULL$") {
                    $filterItems += "(!($($matches[1])=*))"
                }
                elseif ($cond -match "^(\w+)\s+LIKE\s+'?(.*?)'?$") {
                    $pattern = $matches[2] -replace '%', '*'
                    $filterItems += "($($matches[1])=$pattern)"
                }
                else {
                    $filterItems += "($cond)"
                }
            }

            if ($filterItems.Count -gt 1) {
                $ldapFilter = "(&" + ($filterItems -join "") + ")"
            }
            elseif ($filterItems.Count -eq 1) {
                $ldapFilter = $filterItems[0]
            }
        }
    }

    $queryResult = Invoke-LdapQuery -Filter $ldapFilter -SearchBase $baseDn -Scope $scope -PropertiesToLoad $propsToLoad -Server $Server

    $finalResults = $queryResult.Results
    if ($orderPart -and $finalResults.Count -gt 0) {
        $orderCol = ($orderPart -split '\s+')[0].Trim()
        $finalResults = $finalResults | Sort-Object -Property $orderCol
    }

    $sw.Stop()
    return [PSCustomObject]@{
        Success             = $true
        Results             = $finalResults
        Count               = $finalResults.Count
        ElapsedMilliseconds = $sw.ElapsedMilliseconds
        Filter              = $ldapFilter
        SearchBase          = $baseDn
        PropertiesLoaded    = if ($propsToLoad.Count -gt 0) { $propsToLoad -join ", " } else { "*" }
    }
}

function Invoke-LdifImport {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$LdifContent,
        [Alias("DryRun")]
        [switch]$ValidateOnly,
        [string]$Server = ""
    )

    $log = New-Object System.Collections.Generic.List[string]
    $entries = $LdifContent -split '(?m)^\s*$' | Where-Object { $_.Trim() }

    $successCount = 0
    $errorCount = 0

    [void]$log.Add("=== LDIF Execution Started $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ===")
    if ($ValidateOnly) { [void]$log.Add("MODE: Validation / Dry-Run (No changes written)") }

    foreach ($entryBlock in $entries) {
        $lines = @($entryBlock -split '\r?\n') | Where-Object { 
            $str = "$($_)".Trim()
            $str.Length -gt 0 -and -not $str.StartsWith('#')
        }
        if (-not $lines -or $lines.Count -eq 0) { continue }

        # Find the line starting with dn:
        $dnIndex = -1
        for ($k = 0; $k -lt $lines.Count; $k++) {
            if ("$($lines[$k])".Trim() -match '^dn:\s*(.+)$') {
                $dnIndex = $k
                break
            }
        }

        if ($dnIndex -eq -1) {
            # Skip header blocks like version: 1 without failing
            continue
        }

        $dnLine = "$($lines[$dnIndex])".Trim()
        [void]($dnLine -match '^dn:\s*(.+)$')
        $dn = $matches[1].Trim()
        $changeType = "add"

        $attrs = [ordered]@{}
        $subOps = New-Object System.Collections.Generic.List[PSCustomObject]
        $currentOp = $null

        for ($i = $dnIndex + 1; $i -lt $lines.Count; $i++) {
            $line = $lines[$i].Trim()
            if ($line -match '^changetype:\s*(.+)$') {
                $changeType = $matches[1].Trim().ToLower()
            }
            elseif ($changeType -eq "modify") {
                if ($line -match '^(add|replace|delete):\s*(.+)$') {
                    $currentOp = [PSCustomObject]@{
                        Action = $matches[1].ToLower()
                        Attribute = $matches[2].Trim()
                        Values = New-Object System.Collections.Generic.List[string]
                    }
                    $subOps.Add($currentOp)
                }
                elseif ($line -match '^-\s*$') {
                    $currentOp = $null
                }
                elseif ($currentOp -and $line -match '^(\w+):\s*(.*)$') {
                    [void]$currentOp.Values.Add($matches[2].Trim())
                }
            }
            else {
                if ($line -match '^(\w+):\s*(.*)$') {
                    $attr = $matches[1].Trim()
                    $val = $matches[2].Trim()
                    if (-not $attrs.Contains($attr)) {
                        $attrs[$attr] = New-Object System.Collections.Generic.List[string]
                    }
                    [void]$attrs[$attr].Add($val)
                }
            }
        }

        [void]$log.Add("Processing DN: $dn [changetype: $changeType]")

        if ($ValidateOnly) {
            [void]$log.Add("  [DRY-RUN] Verified structure for $dn ($changeType)")
            $successCount++
            continue
        }

        try {
            $ldapPath = if ($Server) { "LDAP://$Server/$dn" } else { "LDAP://$dn" }

            switch ($changeType) {
                "delete" {
                    $entry = New-Object System.DirectoryServices.DirectoryEntry($ldapPath)
                    $parent = $entry.Parent
                    $parent.Children.Remove($entry)
                    $parent.CommitChanges()
                    [void]$log.Add("  SUCCESS: Deleted object $dn")
                    $successCount++
                }
                "modify" {
                    $entry = New-Object System.DirectoryServices.DirectoryEntry($ldapPath)
                    foreach ($op in $subOps) {
                        $attrName = $op.Attribute
                        switch ($op.Action) {
                            "add" {
                                foreach ($v in $op.Values) { [void]$entry.Properties[$attrName].Add($v) }
                            }
                            "replace" {
                                $entry.Properties[$attrName].Clear()
                                foreach ($v in $op.Values) { [void]$entry.Properties[$attrName].Add($v) }
                            }
                            "delete" {
                                if ($op.Values.Count -eq 0) {
                                    $entry.Properties[$attrName].Clear()
                                } else {
                                    foreach ($v in $op.Values) { [void]$entry.Properties[$attrName].Remove($v) }
                                }
                            }
                        }
                    }
                    $entry.CommitChanges()
                    [void]$log.Add("  SUCCESS: Modified object $dn")
                    $successCount++
                }
                "add" {
                    $leafParts = $dn -split '(?<!\\),', 2
                    $leaf = $leafParts[0]
                    $parentDn = $leafParts[1]

                    $parentPath = if ($Server) { "LDAP://$Server/$parentDn" } else { "LDAP://$parentDn" }
                    $parentEntry = New-Object System.DirectoryServices.DirectoryEntry($parentPath)
                    $objClass = if ($attrs.Contains("objectClass")) { $attrs["objectClass"][0] } else { "user" }
                    
                    $newChild = $parentEntry.Children.Add($leaf, $objClass)
                    foreach ($k in $attrs.Keys) {
                        if ($k -ne "objectClass") {
                            foreach ($v in $attrs[$k]) {
                                [void]$newChild.Properties[$k].Add($v)
                            }
                        }
                    }
                    $newChild.CommitChanges()
                    [void]$log.Add("  SUCCESS: Created object $dn")
                    $successCount++
                }
                Default {
                    [void]$log.Add("  WARNING: Unsupported changetype '$changeType' for $dn")
                    $errorCount++
                }
            }
        }
        catch {
            [void]$log.Add("  FAILED: Error on ${dn}: $_")
            $errorCount++
        }
    }

    [void]$log.Add("=== Execution Summary: $successCount Succeeded, $errorCount Failed ===")

    return [PSCustomObject]@{
        Success        = ($errorCount -eq 0)
        SuccessCount   = $successCount
        FailureCount   = $errorCount
        ErrorCount     = $errorCount
        TotalProcessed = ($successCount + $errorCount)
        Log            = @($log)
        LogText        = ($log -join "`r`n")
    }
}

function Compare-ADObjects {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [Alias("ObjectA")]
        [string]$ObjectADN,
        [Parameter(Mandatory = $true)]
        [Alias("ObjectB")]
        [string]$ObjectBDN,
        [string]$Server = ""
    )

    $attrsA = Get-ADObjectRawAttributes -DistinguishedName $ObjectADN -Server $Server
    $attrsB = Get-ADObjectRawAttributes -DistinguishedName $ObjectBDN -Server $Server

    $mapA = @{}
    foreach ($a in $attrsA) { $mapA[$a.Name] = $a }

    $mapB = @{}
    foreach ($b in $attrsB) { $mapB[$b.Name] = $b }

    $allNames = New-Object System.Collections.Generic.SortedSet[string]([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($k in $mapA.Keys) { [void]$allNames.Add($k) }
    foreach ($k in $mapB.Keys) { [void]$allNames.Add($k) }

    $diffRows = New-Object System.Collections.Generic.List[PSCustomObject]

    foreach ($name in $allNames) {
        $hasA = $mapA.ContainsKey($name)
        $hasB = $mapB.ContainsKey($name)

        $valA = if ($hasA) { $mapA[$name].Value } else { "<not present>" }
        $valB = if ($hasB) { $mapB[$name].Value } else { "<not present>" }

        $status = ""
        $displayStatus = ""

        if ($hasA -and -not $hasB) {
            $status = "OnlyInA"
            $displayStatus = "Only in Left"
        }
        elseif (-not $hasA -and $hasB) {
            $status = "OnlyInB"
            $displayStatus = "Only in Right"
        }
        elseif ($valA -eq $valB) {
            $status = "Identical"
            $displayStatus = "Identical"
        }
        else {
            $status = "Different"
            $displayStatus = "Different"
        }

        $diffRows.Add([PSCustomObject]@{
            Attribute     = $name
            ValueA        = $valA
            ValueB        = $valB
            Status        = $status
            DisplayStatus = $displayStatus
            IsDifferent   = ($status -ne "Identical")
        })
    }

    $diffCount = ($diffRows | Where-Object { $_.IsDifferent }).Count
    return [PSCustomObject]@{
        Success                 = $true
        ObjectA                 = $ObjectADN
        ObjectB                 = $ObjectBDN
        Comparisons             = $diffRows
        DifferencesCount        = $diffCount
        TotalAttributesCompared = $diffRows.Count
    }
}

function Get-ADSecurityAuditReport {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [ValidateSet("InactiveUsers", "PasswordsNeverExpire", "PasswordNeverExpires", "PasswordExpiringSoon", "PrivilegedAccounts", "EmptyGroups", "UnprotectedOUs", "LockedAccounts", "LockedOutUsers", "DisabledAccounts", "ServiceAccounts", "InactiveComputers")]
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

    switch ($Category) {
        "InactiveUsers" {
            $cutoff = (Get-Date).AddDays(-$Days)
            $users = Get-ADUsersList
            foreach ($u in $users) {
                $lastLog = $u.LastLogon
                $isInactive = $false
                if ($lastLog -eq "Never" -or [string]::IsNullOrEmpty($lastLog)) {
                    $isInactive = $true
                } else {
                    $dt = $null
                    if ([DateTime]::TryParse($lastLog, [ref]$dt)) {
                        if ($dt -lt $cutoff) { $isInactive = $true }
                    }
                }

                if ($isInactive) {
                    $results.Add([PSCustomObject]@{
                        SamAccountName    = $u.SamAccountName
                        DisplayName       = $u.DisplayName
                        Department        = $u.Department
                        LastLogon         = $u.LastLogon
                        Status            = $u.Status
                        DaysInactive      = if ($u.LastLogon -eq "Never") { "Never Logged On" } else { "$([int]((Get-Date) - $dt).TotalDays) days" }
                        DistinguishedName = $u.DistinguishedName
                    })
                }
            }
            $summary["Total Evaluated"] = $users.Count
            $summary["Inactive Accounts"] = $results.Count
            $summary["Cutoff Threshold"] = "$Days Days"
        }

        { $_ -in "PasswordsNeverExpire", "PasswordNeverExpires" } {
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

        { $_ -in "LockedAccounts", "LockedOutUsers" } {
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
                $members = Get-ADGroupMembersList -GroupName $grp
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
                    $dt = $null
                    if ([DateTime]::TryParse($lastLogonStr, [ref]$dt)) {
                        if ($dt -lt $cutoff) { $isInactive = $true }
                    }
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

        Default {
            $users = Get-ADUsersList -FilterStatus "Disabled"
            foreach ($u in $users) {
                $results.Add([PSCustomObject]@{
                    SamAccountName    = $u.SamAccountName
                    DisplayName       = $u.DisplayName
                    Department        = $u.Department
                    Email             = $u.Email
                    OUPath            = $u.OUPath
                    DistinguishedName = $u.DistinguishedName
                })
            }
            $summary["Disabled Accounts"] = $results.Count
        }
    }

    $title = switch ($Category) {
        "InactiveUsers"                                          { "Inactive User Accounts" }
        { $_ -in "PasswordsNeverExpire", "PasswordNeverExpires" } { "Accounts with Passwords that Never Expire" }
        "PasswordExpiringSoon"                                   { "Accounts with Passwords Expiring Soon" }
        "PrivilegedAccounts"                                     { "Privileged and Administrative Accounts" }
        "EmptyGroups"                                            { "Empty Security and Distribution Groups" }
        "UnprotectedOUs"                                         { "Organizational Units Unprotected from Deletion" }
        { $_ -in "LockedAccounts", "LockedOutUsers" }             { "Locked Out User Accounts" }
        "DisabledAccounts"                                       { "Disabled User Accounts" }
        "ServiceAccounts"                                        { "Configured Service Accounts with SPNs" }
        "InactiveComputers"                                      { "Inactive Domain Computer Objects" }
        default                                                  { "$Category Audit" }
    }
    $desc = switch ($Category) {
        "InactiveUsers"                                          { "Users who have not logged in within the last $Days days." }
        { $_ -in "PasswordsNeverExpire", "PasswordNeverExpires" } { "User accounts configured with DONT_EXPIRE_PASSWORD flag." }
        "PasswordExpiringSoon"                                   { "Accounts whose password will expire within the next $Days days." }
        "PrivilegedAccounts"                                     { "Members of high-privilege built-in Active Directory security groups." }
        "EmptyGroups"                                            { "Groups containing zero members that may be candidates for cleanup." }
        "UnprotectedOUs"                                         { "Organizational Units without accidental deletion protection enabled." }
        { $_ -in "LockedAccounts", "LockedOutUsers" }             { "Accounts currently locked out due to invalid logon attempts." }
        "DisabledAccounts"                                       { "User accounts marked as disabled." }
        "ServiceAccounts"                                        { "Accounts with registered Service Principal Names (SPNs)." }
        "InactiveComputers"                                      { "Computers with no logon activity in the last $Days days." }
        default                                                  { "Security and hygiene audit results for $Category." }
    }

    return [PSCustomObject]@{
        Category     = $Category
        AuditType    = $Category
        Title        = $title
        Description  = $desc
        SummaryStats = $summary
        Results      = $results
        Findings     = $results
        Count        = $results.Count
    }
}

function Get-ADSchemaClasses {
    [CmdletBinding()]
    param (
        [string]$Server = ""
    )

    $rootDse = [System.DirectoryServices.DirectoryEntry]"LDAP://RootDSE"
    $schemaNC = $rootDse.schemaNamingContext
    
    $query = Invoke-LdapQuery -Filter "(objectClass=classSchema)" -SearchBase $schemaNC -PropertiesToLoad @('ldapDisplayName', 'subClassOf', 'mustContain', 'mayContain', 'systemMustContain', 'systemMayContain', 'governsID', 'objectClassCategory') -Server $Server
    
    $classes = New-Object System.Collections.Generic.List[PSCustomObject]
    foreach ($r in $query.Results) {
        $must = @()
        if ($r.mustContain) { $must += $r.mustContain }
        if ($r.systemMustContain) { $must += $r.systemMustContain }

        $may = @()
        if ($r.mayContain) { $may += $r.mayContain }
        if ($r.systemMayContain) { $may += $r.systemMayContain }

        $classes.Add([PSCustomObject]@{
            Name              = $r.ldapDisplayName
            SubClassOf        = $r.subClassOf
            OID               = $r.governsID
            MandatoryCount    = $must.Count
            OptionalCount     = $may.Count
            MandatoryAttrs    = $must -join ", "
            OptionalAttrs     = $may -join ", "
            DistinguishedName = $r.DistinguishedName
        })
    }

    return $classes | Sort-Object Name
}

function Get-ADSchemaAttributes {
    [CmdletBinding()]
    param (
        [string]$Server = ""
    )

    $rootDse = [System.DirectoryServices.DirectoryEntry]"LDAP://RootDSE"
    $schemaNC = $rootDse.schemaNamingContext

    $query = Invoke-LdapQuery -Filter "(objectClass=attributeSchema)" -SearchBase $schemaNC -PropertiesToLoad @('ldapDisplayName', 'attributeSyntax', 'isSingleValued', 'attributeID', 'systemFlags', 'isMemberOfPartialAttributeSet') -Server $Server

    $attrs = New-Object System.Collections.Generic.List[PSCustomObject]
    foreach ($r in $query.Results) {
        $attrs.Add([PSCustomObject]@{
            Name              = $r.ldapDisplayName
            OID               = $r.attributeID
            Syntax            = $r.attributeSyntax
            IsSingleValued    = [bool]$r.isSingleValued
            InGlobalCatalog   = [bool]$r.isMemberOfPartialAttributeSet
            DistinguishedName = $r.DistinguishedName
        })
    }

    return $attrs | Sort-Object Name
}

function Get-ADComputersList {
    [CmdletBinding()]
    param (
        [Alias("SearchText")]
        [string]$SearchFilter = "*",
        [int]$Limit = 500,
        [string]$Server = ""
    )

    $queryFilter = if ($SearchFilter -and $SearchFilter -ne "*") {
        "(&(objectClass=computer)(|(name=*$SearchFilter*)(operatingSystem=*$SearchFilter*)))"
    } else {
        "(objectClass=computer)"
    }

    $query = Invoke-LdapQuery -Filter $queryFilter -PropertiesToLoad @('name', 'dNSHostName', 'operatingSystem', 'operatingSystemVersion', 'lastLogonTimestamp', 'userAccountControl', 'whenCreated', 'distinguishedName') -Server $Server

    $list = New-Object System.Collections.Generic.List[PSCustomObject]
    foreach ($r in $query.Results) {
        $uac = [int64]$r.userAccountControl
        $isDisabled = (($uac -band 2) -eq 2)
        $list.Add([PSCustomObject]@{
            Name              = $r.name
            DNSHostName       = $r.dNSHostName
            OperatingSystem   = $r.operatingSystem
            OSVersion         = $r.operatingSystemVersion
            LastLogon         = ConvertFrom-ADLargeInteger -Value $r.lastLogonTimestamp
            Created           = if ($r.whenCreated -is [DateTime]) { $r.whenCreated.ToString("yyyy-MM-dd") } else { "$($r.whenCreated)" }
            Status            = if ($isDisabled) { "Disabled" } else { "Enabled" }
            IsEnabled         = -not $isDisabled
            DistinguishedName = $r.DistinguishedName
            OUPath            = Convert-DNToOUPath -DistinguishedName $r.DistinguishedName
        })
    }

    $sorted = $list | Sort-Object Name
    if ($Limit -gt 0) {
        return $sorted | Select-Object -First $Limit
    } else {
        return $sorted
    }
}

function Test-ADConnectionDiagnostic {
    [CmdletBinding()]
    param (
        [string]$Server = "",
        [int]$Port = 389,
        [int]$TimeoutMs = 3000
    )

    $diag = [ordered]@{
        Server         = $Server
        Port           = $Port
        DnsResolved    = $false
        IpAddress      = ""
        TcpPortOpen    = $false
        LatencyMs      = 0
        RootDseQueried = $false
        DomainNamingNC = ""
        ErrorMessage   = ""
    }

    $sw = [System.Diagnostics.Stopwatch]::StartNew()

    try {
        $targetHost = if ($Server) { $Server } else {
            $rootDse = [System.DirectoryServices.DirectoryEntry]"LDAP://RootDSE"
            $rootDse.dnsHostName
        }
        $diag['Server'] = $targetHost

        $ipEntry = [System.Net.Dns]::GetHostEntry($targetHost)
        if ($ipEntry -and $ipEntry.AddressList.Count -gt 0) {
            $diag['DnsResolved'] = $true
            $diag['IpAddress'] = $ipEntry.AddressList[0].ToString()
        }

        $tcp = New-Object System.Net.Sockets.TcpClient
        $connectAsync = $tcp.BeginConnect($targetHost, $Port, $null, $null)
        $success = $connectAsync.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
        if ($success -and $tcp.Connected) {
            $tcp.EndConnect($connectAsync)
            $tcp.Close()
            $diag['TcpPortOpen'] = $true
        } else {
            $diag['ErrorMessage'] = "Connection to port $Port timed out (${TimeoutMs} ms)."
        }

        $dsePath = if ($targetHost) { "LDAP://$targetHost`:$Port/RootDSE" } else { "LDAP://RootDSE" }
        $dse = New-Object System.DirectoryServices.DirectoryEntry($dsePath)
        if ($dse.defaultNamingContext) {
            $diag['RootDseQueried'] = $true
            $diag['DomainNamingNC'] = $dse.defaultNamingContext
        }
    }
    catch {
        $diag['ErrorMessage'] = $_.Exception.Message
    }
    finally {
        $sw.Stop()
        $diag['LatencyMs'] = $sw.ElapsedMilliseconds
    }

    $isOpen = [bool]$diag['TcpPortOpen']
    $hasError = -not [string]::IsNullOrEmpty($diag['ErrorMessage'])
    return [PSCustomObject]@{
        Success              = ($isOpen -and -not $hasError)
        PortOpen             = $isOpen
        TcpPortOpen          = $isOpen
        IPAddress            = $diag['IpAddress']
        DefaultNamingContext = $diag['DomainNamingNC']
        DomainNamingNC       = $diag['DomainNamingNC']
        Server               = $diag['Server']
        Port                 = $diag['Port']
        DnsResolved          = $diag['DnsResolved']
        LatencyMs            = $diag['LatencyMs']
        RootDseQueried       = $diag['RootDseQueried']
        ErrorMessage         = $diag['ErrorMessage']
    }
}

function Invoke-ADBulkUpdate {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [Alias("Objects", "TargetObjects")]
        $DistinguishedNames,
        [string]$AttributeName,
        $NewValue,
        [ValidateSet("SetAttribute", "Set Attribute", "Enable", "Disable", "Unlock", "RequirePasswordChange", "MoveOU")]
        [string]$Operation = "SetAttribute",
        [string]$TargetOU = "",
        [string]$Server = ""
    )

    $cleanOp = ($Operation -replace '\s+', '')
    $dnList = New-Object System.Collections.Generic.List[string]

    if ($DistinguishedNames -is [System.Collections.IEnumerable] -and $DistinguishedNames -isnot [string]) {
        foreach ($item in $DistinguishedNames) {
            if ($null -eq $item) { continue }
            if ($item -is [string]) {
                if ($item.Trim()) { [void]$dnList.Add($item.Trim()) }
            } elseif ($item.DistinguishedName) {
                [void]$dnList.Add("$($item.DistinguishedName)".Trim())
            } elseif ($item.dn) {
                [void]$dnList.Add("$($item.dn)".Trim())
            } else {
                [void]$dnList.Add("$item".Trim())
            }
        }
    } elseif ($DistinguishedNames -is [string]) {
        if ($DistinguishedNames.Trim()) { [void]$dnList.Add($DistinguishedNames.Trim()) }
    }

    $results = New-Object System.Collections.Generic.List[PSCustomObject]
    $log = New-Object System.Collections.Generic.List[string]
    $successCount = 0
    $errorCount = 0

    foreach ($dn in $dnList) {
        $res = [ordered]@{
            DistinguishedName = $dn
            Success           = $false
            Message           = ""
        }

        try {
            switch ($cleanOp) {
                "SetAttribute" {
                    $upd = Set-ADObjectRawAttribute -DistinguishedName $dn -AttributeName $AttributeName -NewValue $NewValue -Server $Server
                    $res['Success'] = $upd.Success
                    $res['Message'] = $upd.Message
                }
                "Enable" {
                    $entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$dn")
                    $uac = [int64]$entry.Properties['userAccountControl'].Value
                    $entry.Properties['userAccountControl'].Value = ($uac -band (-bnot 2))
                    $entry.CommitChanges()
                    $res['Success'] = $true
                    $res['Message'] = "Account enabled."
                }
                "Disable" {
                    $entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$dn")
                    $uac = [int64]$entry.Properties['userAccountControl'].Value
                    $entry.Properties['userAccountControl'].Value = ($uac -bor 2)
                    $entry.CommitChanges()
                    $res['Success'] = $true
                    $res['Message'] = "Account disabled."
                }
                "Unlock" {
                    $entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$dn")
                    $entry.Properties['lockoutTime'].Value = 0
                    $entry.CommitChanges()
                    $res['Success'] = $true
                    $res['Message'] = "Account unlocked."
                }
                "RequirePasswordChange" {
                    $entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$dn")
                    $entry.Properties['pwdLastSet'].Value = 0
                    $entry.CommitChanges()
                    $res['Success'] = $true
                    $res['Message'] = "Password change required at next logon."
                }
                "MoveOU" {
                    if (-not $TargetOU) { throw "Target OU was not provided." }
                    $mov = Move-ADPrincipal -Identity $dn -TargetOU $TargetOU
                    $res['Success'] = $mov.Success
                    $res['Message'] = $mov.Message
                }
                default {
                    throw "Unsupported operation '$Operation'."
                }
            }

            if ($res['Success']) {
                $successCount++
                [void]$log.Add("[SUCCESS] $dn : $($res['Message'])")
            } else {
                $errorCount++
                [void]$log.Add("[FAILED]  $dn : $($res['Message'])")
            }
        }
        catch {
            $res['Success'] = $false
            $res['Message'] = $_.Exception.Message
            $errorCount++
            [void]$log.Add("[ERROR]   $dn : $($_.Exception.Message)")
        }

        $results.Add([PSCustomObject]$res)
    }

    return [PSCustomObject]@{
        Total        = $dnList.Count
        TotalCount   = $dnList.Count
        SuccessCount = $successCount
        FailureCount = $errorCount
        ErrorCount   = $errorCount
        Details      = $results
        Log          = @($log)
    }
}
#endregion

Export-ModuleMember -Function `
    Get-ADUsersList, Get-ADUserDetail, Test-ADUsernameExists, New-ADUserItem, Set-ADUserItem, `
    Remove-ADUserItem, Set-ADUserPassword, Set-ADUserStatus, Unlock-ADUserAccount, Move-ADPrincipal, `
    Get-ADGroupsList, Get-ADGroupMembersList, New-ADGroupItem, Remove-ADGroupItem, `
    Add-ADPrincipalToGroup, Remove-ADPrincipalFromGroup, `
    Get-ADOUTree, Get-ADOUFlatList, New-ADOrganizationalUnitItem, Remove-ADOrganizationalUnitItem, `
    Get-ADDashboardStats, `
    Invoke-LdapQuery, Get-ADObjectRawAttributes, Set-ADObjectRawAttribute, Add-ADObjectRawAttributeValue, `
    Remove-ADObjectRawAttributeValue, Clear-ADObjectRawAttribute, Invoke-LdapSqlQuery, Invoke-LdifImport, `
    Compare-ADObjects, Get-ADSecurityAuditReport, Get-ADSchemaClasses, Get-ADSchemaAttributes, `
    Get-ADComputersList, Test-ADConnectionDiagnostic, Invoke-ADBulkUpdate

