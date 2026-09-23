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

Export-ModuleMember -Function `
    Get-ADUsersList, Get-ADUserDetail, Test-ADUsernameExists, New-ADUserItem, Set-ADUserItem, `
    Remove-ADUserItem, Set-ADUserPassword, Set-ADUserStatus, Unlock-ADUserAccount, Move-ADPrincipal, `
    Get-ADGroupsList, Get-ADGroupMembersList, New-ADGroupItem, Remove-ADGroupItem, `
    Add-ADPrincipalToGroup, Remove-ADPrincipalFromGroup, `
    Get-ADOUTree, Get-ADOUFlatList, New-ADOrganizationalUnitItem, Remove-ADOrganizationalUnitItem, `
    Get-ADDashboardStats
