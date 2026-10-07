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
function Remove-DiacriticsText {
    param ([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return "" }
    $norm = $Text.Normalize([System.Text.NormalizationForm]::FormD)
    $sb = [System.Text.StringBuilder]::new()
    foreach ($c in $norm.ToCharArray()) {
        if ([System.Globalization.CharUnicodeInfo]::GetUnicodeCategory($c) -ne [System.Globalization.UnicodeCategory]::NonSpacingMark) {
            [void]$sb.Append($c)
        }
    }
    return $sb.ToString().Normalize([System.Text.NormalizationForm]::FormC)
}

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

    $resolvedDisplayName = if ($User.DisplayName -and -not [string]::IsNullOrWhiteSpace($User.DisplayName)) {
        $User.DisplayName.Trim()
    } elseif (-not [string]::IsNullOrWhiteSpace("$($User.GivenName) $($User.Surname)".Trim())) {
        "$($User.GivenName) $($User.Surname)".Trim()
    } elseif ($User.Name -and -not [string]::IsNullOrWhiteSpace($User.Name)) {
        $User.Name.Trim()
    } else {
        $User.SamAccountName
    }

    $userName = if ($User.Name -and -not [string]::IsNullOrWhiteSpace($User.Name)) {
        $User.Name.Trim()
    } else {
        $resolvedDisplayName
    }

    [PSCustomObject]@{
        Name               = $userName
        SamAccountName     = $User.SamAccountName
        DisplayName        = $resolvedDisplayName
        GivenName          = $User.GivenName
        Surname            = $User.Surname
        UserPrincipalName  = $User.UserPrincipalName
        Mail               = $User.Mail
        Email              = if ($User.Mail) { $User.Mail } else { $User.UserPrincipalName }
        Title              = $User.Title
        Department         = $User.Department
        Office             = $User.Office
        Company            = $User.Company
        EmployeeID         = $User.EmployeeID
        Description        = $User.Description
        TelephoneNumber    = if ($User.telephoneNumber) { $User.telephoneNumber } else { "" }
        Mobile             = if ($User.mobile) { $User.mobile } else { "" }
        Manager            = if ($User.manager) { ($User.manager -replace '^CN=([^,]+).*', '$1') } else { "" }
        StreetAddress      = if ($User.streetAddress) { $User.streetAddress } else { "" }
        City               = if ($User.l) { $User.l } else { "" }
        State              = if ($User.st) { $User.st } else { "" }
        PostalCode         = if ($User.postalCode) { $User.postalCode } else { "" }
        Country            = if ($User.co) { $User.co } else { "" }
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
        [Alias("FilterStatus")]
        [string]$StatusFilter = "All", # "All", "Active", "Disabled", "Locked"
        [string]$SearchBase = "",
        [int]$Limit = 1000
    )

    $props = @(
        'DisplayName', 'GivenName', 'Surname', 'SamAccountName', 'UserPrincipalName',
        'Mail', 'Title', 'Department', 'Office', 'Company', 'EmployeeID',
        'Description', 'Enabled', 'LockedOut', 'DistinguishedName', 'ObjectGUID',
        'SID', 'LastLogonDate', 'PasswordLastSet', 'WhenCreated', 'WhenChanged',
        'telephoneNumber', 'mobile', 'manager', 'streetAddress', 'l', 'st', 'postalCode', 'co'
    )

    $filter = "*"
    if (-not [string]::IsNullOrWhiteSpace($SearchText)) {
        $cleanText = $SearchText.Trim()
        $safeTerm = $cleanText.Replace("'", "''")
        $asciiTerm = (Remove-DiacriticsText $safeTerm)

        $terms = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        [void]$terms.Add($safeTerm)
        if ($asciiTerm -and $asciiTerm -ne $safeTerm) {
            [void]$terms.Add($asciiTerm)
        }

        $orClauses = [System.Collections.Generic.List[string]]::new()
        $searchAttrs = @('DisplayName', 'Name', 'GivenName', 'Surname', 'SamAccountName', 'UserPrincipalName', 'Mail', 'Title', 'Department', 'Office', 'Description', 'EmployeeID')

        foreach ($term in $terms) {
            foreach ($attr in $searchAttrs) {
                $orClauses.Add("($attr -like `"*$term*`")")
            }

            $words = $term -split '\s+' | Where-Object { $_ }
            if ($words.Count -ge 2) {
                $w1 = $words[0]
                $w2 = $words[1]
                $orClauses.Add("((GivenName -like `"*$w1*`") -and (Surname -like `"*$w2*`"))")
                $orClauses.Add("((GivenName -like `"*$w2*`") -and (Surname -like `"*$w1*`"))")
                $orClauses.Add("((DisplayName -like `"*$w1*`") -and (DisplayName -like `"*$w2*`"))")
            }
        }

        $filter = ($orClauses -join " -or ")
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

        return @($results)
    }
    catch {
        Write-Warning "Direct AD filter failed, attempting fallback search: $_"
        try {
            $fallbackParams = @{
                Properties = $props
                Filter     = "*"
            }
            if (-not [string]::IsNullOrWhiteSpace($SearchBase)) {
                $fallbackParams['SearchBase'] = $SearchBase
            }
            if ($Limit -gt 0) {
                $fallbackParams['ResultSetSize'] = [Math]::Max($Limit, 500)
            }
            $allRaw = Get-ADUser @fallbackParams -ErrorAction Stop
            $results = [System.Collections.Generic.List[PSCustomObject]]::new()
            $cleanQuery = if ($SearchText) { $SearchText.Trim() } else { "" }
            $cleanAscii = Remove-DiacriticsText $cleanQuery

            foreach ($u in $allRaw) {
                $formatted = Format-ADUserRecord -User $u
                $include = $true
                switch ($StatusFilter) {
                    "Active"   { if (-not $formatted.Enabled -or $formatted.LockedOut) { $include = $false } }
                    "Disabled" { if ($formatted.Enabled) { $include = $false } }
                    "Locked"   { if (-not $formatted.LockedOut) { $include = $false } }
                }

                if ($include -and $cleanQuery) {
                    $composite = "$($formatted.DisplayName) $($formatted.GivenName) $($formatted.Surname) $($formatted.SamAccountName) $($formatted.Department) $($formatted.Title) $($formatted.Office) $($formatted.Description) $($formatted.Mail) $($formatted.Email) $($formatted.EmployeeID)"
                    $asciiComp = Remove-DiacriticsText $composite
                    if ($composite -notmatch [regex]::Escape($cleanQuery) -and $asciiComp -notmatch [regex]::Escape($cleanAscii)) {
                        $include = $false
                    }
                }

                if ($include) {
                    $results.Add($formatted)
                }
            }
            return @($results)
        }
        catch {
            Write-Error "Error querying AD users: $_"
            return @()
        }
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

    $props = @('Name', 'SamAccountName', 'GroupCategory', 'GroupScope', 'Description', 'DistinguishedName', 'ObjectGUID', 'Members', 'mail', 'whenCreated', 'whenChanged', 'SID', 'managedBy', 'info')

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
                    Description       = if ($g.Description) { $g.Description } else { "" }
                    MemberCount       = $memberCount
                    Mail              = if ($g.mail) { $g.mail } else { "" }
                    WhenCreated       = if ($g.whenCreated) { $g.whenCreated.ToString("yyyy-MM-dd HH:mm") } else { "" }
                    WhenChanged       = if ($g.whenChanged) { $g.whenChanged.ToString("yyyy-MM-dd HH:mm") } else { "" }
                    SID               = if ($g.SID) { $g.SID.Value } else { "" }
                    ManagedBy         = if ($g.managedBy) { ($g.managedBy -replace '^CN=([^,]+).*', '$1') } else { "" }
                    Info              = if ($g.info) { $g.info } else { "" }
                    OUPath            = $ouPath
                    DistinguishedName = $g.DistinguishedName
                    ObjectGUID        = $g.ObjectGUID.ToString()
                    RawGroup          = $g
                })
            }
        }

        return @($results)
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
        [Alias("GroupName", "Group")]
        [string]$Identity
    )

    try {
        $members = Get-ADGroupMember -Identity $Identity -ErrorAction Stop
        $results = @()
        foreach ($m in $members) {
            $mName = if ($m.name -and -not [string]::IsNullOrWhiteSpace($m.name)) { $m.name } else { $m.SamAccountName }
            $results += [PSCustomObject]@{
                Name              = $mName
                DisplayName       = $mName
                SamAccountName    = $m.SamAccountName
                ObjectClass       = $m.objectClass
                DistinguishedName = $m.distinguishedName
                SID               = if ($m.SID) { $m.SID.Value } else { "" }
            }
        }
        return @($results | Sort-Object Name)
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

function Get-ADObjectsInOU {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$SearchBase,

        [ValidateSet("OneLevel", "Subtree", "Base")]
        [string]$SearchScope = "OneLevel",

        [string]$Server = ""
    )

    if ([string]::IsNullOrWhiteSpace($SearchBase)) {
        return @()
    }

    try {
        $filter = "(|(objectClass=user)(objectClass=group)(objectClass=computer)(objectClass=organizationalUnit)(objectClass=contact)(objectClass=container))"
        $props = @('objectClass', 'name', 'sAMAccountName', 'userAccountControl', 'groupType', 'distinguishedName', 'description', 'mail', 'whenCreated', 'whenChanged')
        
        $searchParams = @{
            LDAPFilter  = $filter
            SearchBase  = $SearchBase
            SearchScope = $SearchScope
            Properties  = $props
        }
        if ($Server) { $searchParams['Server'] = $Server }

        $rawObjects = Get-ADObject @searchParams -ErrorAction Stop

        $results = [System.Collections.Generic.List[PSCustomObject]]::new()
        foreach ($obj in $rawObjects) {
            # Skip the SearchBase itself if returned in Base/Subtree
            if ($obj.DistinguishedName -eq $SearchBase) { continue }

            $objClass = $obj.ObjectClass
            $friendlyType = switch ($objClass) {
                'user' {
                    if ($obj.ObjectClass -contains 'user' -and -not ($obj.ObjectClass -contains 'computer')) { "User" }
                    else { "Computer" }
                }
                'computer' { "Computer" }
                'group'    { "Group" }
                'organizationalUnit' { "OU" }
                'contact'  { "Contact" }
                'container'{ "Container" }
                default    { 
                    if ($obj.ObjectClass -is [array]) { $obj.ObjectClass[0] } else { [string]$obj.ObjectClass }
                }
            }

            # Determine status based on type
            $status = "Active"
            if ($friendlyType -in @('User', 'Computer')) {
                if ($obj.userAccountControl) {
                    $uac = [int64]$obj.userAccountControl
                    if (($uac -band 2) -ne 0) { $status = "Disabled" }
                    elseif (($uac -band 16) -ne 0) { $status = "Locked" }
                }
            } elseif ($friendlyType -eq 'Group') {
                if ($obj.groupType) {
                    $gt = [int64]$obj.groupType
                    $status = if (($gt -band 0x80000000) -ne 0) { "Security" } else { "Distribution" }
                } else {
                    $status = "Group"
                }
            } elseif ($friendlyType -eq 'OU') {
                $status = "OU"
            } else {
                $status = "Normal"
            }

            $results.Add([PSCustomObject]@{
                ObjectClass       = $friendlyType
                Name              = if ($obj.Name) { $obj.Name } else { "" }
                SamAccountName    = if ($obj.sAMAccountName) { $obj.sAMAccountName } else { "-" }
                Status            = $status
                DistinguishedName = $obj.DistinguishedName
                Description       = if ($obj.Description) { $obj.Description } else { "" }
                Mail              = if ($obj.mail) { $obj.mail } else { "" }
                WhenCreated       = if ($obj.whenCreated) { $obj.whenCreated.ToString("yyyy-MM-dd HH:mm") } else { "" }
                WhenChanged       = if ($obj.whenChanged) { $obj.whenChanged.ToString("yyyy-MM-dd HH:mm") } else { "" }
                RawObject         = $obj
            })
        }

        # Sort by ObjectClass priority (OU first, then Groups, Users, Computers, etc.), then by Name
        $sorted = $results | Sort-Object @{
            Expression = {
                switch ($_.ObjectClass) {
                    'OU'        { 1 }
                    'Group'     { 2 }
                    'User'      { 3 }
                    'Computer'  { 4 }
                    'Contact'   { 5 }
                    default     { 6 }
                }
            }
        }, Name

        return @($sorted)
    }
    catch {
        Write-Error "Failed to query objects in OU '$SearchBase': $_"
        return @()
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
        [string]$Server = "",
        [switch]$IncludeOperational
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
            'distinguishedName', 'sAMAccountName', 'userPrincipalName',
            'subschemaSubentry', 'structuralObjectClass', 'allowedAttributes', 'allowedAttributesEffective',
            'dSCorePropagationData', 'msDS-SupportedEncryptionTypes', 'msDS-KeyVersionNumber'
        )

        if ($IncludeOperational) {
            try {
                $entry.RefreshCache($operationalAttrs)
            } catch {}
        }

        $purelyOperational = @(
            'canonicalName', 'createTimeStamp', 'modifyTimeStamp',
            'pwdLastSet', 'lastLogon', 'lastLogonTimestamp', 'badPasswordTime', 'lockoutTime',
            'accountExpires', 'msDS-UserPasswordExpiryTimeComputed', 'tokenGroups',
            'whenCreated', 'whenChanged', 'subschemaSubentry', 'structuralObjectClass',
            'allowedAttributes', 'allowedAttributesEffective', 'dSCorePropagationData',
            'msDS-SupportedEncryptionTypes', 'msDS-KeyVersionNumber'
        )
        $pureOpSet = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($p in $purelyOperational) { [void]$pureOpSet.Add($p) }

        foreach ($propName in $entry.Properties.PropertyNames) {
            $isOp = $pureOpSet.Contains($propName)
            if (-not $IncludeOperational -and $isOp) { continue }
            $propValues = $entry.Properties[$propName]

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
        
        if ($null -eq $NewValue) {
            $entry.Properties[$AttributeName].Clear()
        }
        elseif ($NewValue -is [byte[]]) {
            if ($NewValue.Length -eq 0) {
                $entry.Properties[$AttributeName].Clear()
            } else {
                $entry.Properties[$AttributeName].Value = $NewValue
            }
        }
        elseif ([string]::IsNullOrEmpty("$NewValue")) {
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

    # Helper: Convert SQL WHERE string to LDAP filter
    $convertWhereToLdap = {
        param([string]$wherePart)
        if (-not $wherePart) { return "(objectClass=*)" }
        if ($wherePart.StartsWith('(')) { return $wherePart }

        $conditions = $wherePart -split '(?i)\s+AND\s+'
        $filterItems = @()
        foreach ($cond in $conditions) {
            $cond = $cond.Trim()
            if ($cond -match '(?i)BITWISE_AND\((\w+),\s*(\d+)\)\s*=\s*\d+') {
                $filterItems += "($($matches[1]):1.2.840.113556.1.4.803:=$($matches[2]))"
            }
            elseif ($cond -match '(?i)BITWISE_OR\((\w+),\s*(\d+)\)\s*=\s*\d+') {
                $filterItems += "($($matches[1]):1.2.840.113556.1.4.804:=$($matches[2]))"
            }
            elseif ($cond -match "^(\w+)\s*=\s*'?(.*?)'?$") {
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
            return "(&" + ($filterItems -join "") + ")"
        }
        elseif ($filterItems.Count -eq 1) {
            return $filterItems[0]
        }
        return "(objectClass=*)"
    }

    # 1. UPDATE Statement
    if ($cleanQuery -match '(?i)^UPDATE\s+(.+?)\s+SET\s+(.+?)(?:\s+WHERE\s+(.+?))?$') {
        $fromPart  = $matches[1].Trim().Trim("'", '"')
        $setPart   = $matches[2].Trim()
        $wherePart = if ($matches[3]) { $matches[3].Trim() } else { "" }

        $baseDn = if ($fromPart -match '^(?i)(SUBTREE|ONELEVEL|BASE)$' -or -not $fromPart) { $DefaultSearchBase } else { $fromPart }
        $ldapFilter = & $convertWhereToLdap $wherePart

        $queryResult = Invoke-LdapQuery -Filter $ldapFilter -SearchBase $baseDn -PropertiesToLoad @('distinguishedName') -Server $Server
        $targets = $queryResult.Results

        # Parse SET clauses (e.g. attr1='val1', attr2='val2')
        $setPairs = @{}
        $setClauses = $setPart -split ',\s*(?=[a-zA-Z0-9_\-]+(\s*)=)'
        foreach ($clause in $setClauses) {
            if ($clause -match "^\s*([a-zA-Z0-9_\-]+)\s*=\s*'?(.*?)'?\s*$") {
                $setPairs[$matches[1]] = $matches[2]
            }
        }

        $updatedCount = 0
        $updateLogs = New-Object System.Collections.Generic.List[string]
        foreach ($t in $targets) {
            $dn = $t.DistinguishedName
            $allOk = $true
            foreach ($attr in $setPairs.Keys) {
                $upd = Set-ADObjectRawAttribute -DistinguishedName $dn -AttributeName $attr -NewValue $setPairs[$attr] -Server $Server
                if (-not $upd.Success) {
                    $allOk = $false
                    $updateLogs.Add("[FAIL] $dn ($attr): $($upd.Message)")
                }
            }
            if ($allOk) {
                $updatedCount++
                $updateLogs.Add("[SUCCESS] $dn updated")
            }
        }

        $sw.Stop()
        return [PSCustomObject]@{
            Success             = $true
            Operation           = "UPDATE"
            RowsAffected        = $updatedCount
            Count               = $updatedCount
            Results             = $updateLogs
            ElapsedMilliseconds = $sw.ElapsedMilliseconds
            Filter              = $ldapFilter
            SearchBase          = $baseDn
            Message             = "UPDATE executed successfully: $updatedCount object(s) updated."
        }
    }

    # 2. DELETE Statement
    if ($cleanQuery -match '(?i)^DELETE\s+FROM\s+(.+?)(?:\s+WHERE\s+(.+?))?$') {
        $fromPart  = $matches[1].Trim().Trim("'", '"')
        $wherePart = if ($matches[2]) { $matches[2].Trim() } else { "" }

        $baseDn = if ($fromPart -match '^(?i)(SUBTREE|ONELEVEL|BASE)$' -or -not $fromPart) { $DefaultSearchBase } else { $fromPart }
        $ldapFilter = & $convertWhereToLdap $wherePart

        $queryResult = Invoke-LdapQuery -Filter $ldapFilter -SearchBase $baseDn -PropertiesToLoad @('distinguishedName') -Server $Server
        $targets = $queryResult.Results

        $deletedCount = 0
        $deleteLogs = New-Object System.Collections.Generic.List[string]
        foreach ($t in $targets) {
            $dn = $t.DistinguishedName
            try {
                $ldapPath = if ($Server) { "LDAP://$Server/$dn" } else { "LDAP://$dn" }
                $entry = New-Object System.DirectoryServices.DirectoryEntry($ldapPath)
                $entry.DeleteObject(0)
                $deletedCount++
                $deleteLogs.Add("[SUCCESS] $dn deleted")
            }
            catch {
                $deleteLogs.Add("[FAIL] $($dn): $($_.Exception.Message)")
            }
        }

        $sw.Stop()
        return [PSCustomObject]@{
            Success             = $true
            Operation           = "DELETE"
            RowsAffected        = $deletedCount
            Count               = $deletedCount
            Results             = $deleteLogs
            ElapsedMilliseconds = $sw.ElapsedMilliseconds
            Filter              = $ldapFilter
            SearchBase          = $baseDn
            Message             = "DELETE executed: $deletedCount object(s) removed."
        }
    }

    # 3. SELECT Statement
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

    $ldapFilter = & $convertWhereToLdap $wherePart
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
            $users = Get-ADUsersList
            foreach ($u in $users) {
                $lastLog = $u.LastLogon
                $isInactive = $false
                if ($lastLog -eq "Never" -or [string]::IsNullOrEmpty($lastLog)) {
                    $isInactive = $true
                } else {
                    try {
                        $dt = [DateTime]$lastLog
                        if ($dt -lt $cutoff) { $isInactive = $true }
                    } catch {}
                }

                if ($isInactive) {
                    $results.Add([PSCustomObject]@{
                        SamAccountName    = $u.SamAccountName
                        DisplayName       = $u.DisplayName
                        Department        = $u.Department
                        LastLogon         = $u.LastLogon
                        Status            = $u.Status
                        DaysInactive      = if ($u.LastLogon -eq "Never" -or -not $dt) { "Never Logged On" } else { "$([int]((Get-Date) - $dt).TotalDays) days" }
                        DistinguishedName = $u.DistinguishedName
                    })
                }
            }
            $summary["Total Evaluated"] = $users.Count
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
                    # Group might not exist in this domain or language
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
            catch {}

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
                    } catch {}
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
            } catch {}

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
                } catch {}
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

            function Check-Cycle ($currDN, $path) {
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
                                Check-Cycle -currDN $m.DistinguishedName -path "$path -> $($m.Name)"
                            }
                        }
                    }
                }
                [void]$recStack.Remove($currDN)
            }

            foreach ($g in $allGroups) {
                if (-not $visited.Contains($g.DistinguishedName)) {
                    Check-Cycle -currDN $g.DistinguishedName -path $g.Name
                }
            }
            $summary["Total Groups Checked"] = $allGroups.Count
            $summary["Circular Loops Found"] = $results.Count
            $summary["Risk Rating"] = if ($results.Count -gt 0) { "High (Can cause token expansion recursion/crashes)" } else { "Clean" }
        }

        "OrphanedAccounts" {
            $allUsers = Get-ADUsersList
            $userDns = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($u in $allUsers) { if ($u.DistinguishedName) { [void]$userDns.Add($u.DistinguishedName) } }

            foreach ($u in $allUsers) {
                $isOrphan = $false
                $orphanReason = @()
                if ($u.Manager -and -not $userDns.Contains($u.Manager)) {
                    $isOrphan = $true
                    $orphanReason += "Manager reference '$($u.Manager)' does not exist"
                }
                if ($isOrphan) {
                    $results.Add([PSCustomObject]@{
                        SamAccountName    = $u.SamAccountName
                        DisplayName       = $u.DisplayName
                        Department        = $u.Department
                        Reason            = $orphanReason -join "; "
                        DistinguishedName = $u.DistinguishedName
                    })
                }
            }
            $summary["Total Evaluated"] = $allUsers.Count
            $summary["Orphaned Accounts"] = $results.Count
        }

        "NeverLoggedInUsers" {
            $cutoff = (Get-Date).AddDays(-$Days)
            $users = Get-ADUsersList
            foreach ($u in $users) {
                if ($u.LastLogon -eq "Never" -or [string]::IsNullOrEmpty($u.LastLogon)) {
                    $results.Add([PSCustomObject]@{
                        SamAccountName    = $u.SamAccountName
                        DisplayName       = $u.DisplayName
                        Department        = $u.Department
                        Status            = $u.Status
                        CreatedDate       = $u.WhenCreated
                        DistinguishedName = $u.DistinguishedName
                    })
                }
            }
            $summary["Total Evaluated"] = $users.Count
            $summary["Never Logged In"] = $results.Count
        }

        "PreWin2000Compatible" {
            $members = @()
            try {
                $members = Get-ADGroupMembersList -GroupName "Pre-Windows 2000 Compatible Access" -ErrorAction Stop
            }
            catch {}
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
            $users = Get-ADUsersList -StatusFilter "Disabled"
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

        Default {
            $users = Get-ADUsersList -StatusFilter "Disabled"
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

    $syntaxMap = @{
        "2.5.5.1"  = "DN / Distinguished Name"
        "2.5.5.2"  = "OID / Object Identifier"
        "2.5.5.3"  = "Case Exact String"
        "2.5.5.4"  = "Case Ignore String / Teletex"
        "2.5.5.5"  = "Printable String"
        "2.5.5.6"  = "Numeric String"
        "2.5.5.7"  = "DN with Binary (OR-Name)"
        "2.5.5.8"  = "Boolean"
        "2.5.5.9"  = "Integer"
        "2.5.5.10" = "Octet String / Binary"
        "2.5.5.11" = "GeneralizedTime"
        "2.5.5.12" = "Unicode String (DirectoryString)"
        "2.5.5.13" = "Presentation Address"
        "2.5.5.14" = "DN with String"
        "2.5.5.15" = "NT Security Descriptor (Binary)"
        "2.5.5.16" = "LargeInteger / FileTime (64-bit)"
        "2.5.5.17" = "Security Identifier (SID)"
    }

    $rootDse = [System.DirectoryServices.DirectoryEntry]"LDAP://RootDSE"
    $schemaNC = $rootDse.schemaNamingContext

    $query = Invoke-LdapQuery -Filter "(objectClass=attributeSchema)" -SearchBase $schemaNC -PropertiesToLoad @('ldapDisplayName', 'attributeSyntax', 'isSingleValued', 'attributeID', 'systemFlags', 'isMemberOfPartialAttributeSet') -Server $Server

    $attrs = New-Object System.Collections.Generic.List[PSCustomObject]
    foreach ($r in $query.Results) {
        $synOid = "$($r.attributeSyntax)"
        $synDesc = if ($syntaxMap.ContainsKey($synOid)) { $syntaxMap[$synOid] } else { $synOid }

        $attrs.Add([PSCustomObject]@{
            Name              = $r.ldapDisplayName
            OID               = $r.attributeID
            Syntax            = $synOid
            SyntaxName        = $synDesc
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

    $query = Invoke-LdapQuery -Filter $queryFilter -PropertiesToLoad @('name', 'dNSHostName', 'operatingSystem', 'operatingSystemVersion', 'lastLogonTimestamp', 'userAccountControl', 'whenCreated', 'whenChanged', 'distinguishedName', 'description', 'ipv4Address', 'samAccountName', 'objectGUID') -Server $Server

    $list = New-Object System.Collections.Generic.List[PSCustomObject]
    foreach ($r in $query.Results) {
        $uac = [int64]$r.userAccountControl
        $isDisabled = (($uac -band 2) -eq 2)
        $list.Add([PSCustomObject]@{
            Name              = $r.name
            DNSHostName       = if ($r.dNSHostName) { $r.dNSHostName } else { "" }
            OperatingSystem   = if ($r.operatingSystem) { $r.operatingSystem } else { "" }
            OSVersion         = if ($r.operatingSystemVersion) { $r.operatingSystemVersion } else { "" }
            Description       = if ($r.description) { $r.description } else { "" }
            IPv4Address       = if ($r.ipv4Address) { $r.ipv4Address } else { "" }
            SamAccountName    = if ($r.samAccountName) { $r.samAccountName } else { "" }
            LastLogon         = ConvertFrom-ADLargeInteger -Value $r.lastLogonTimestamp
            Created           = if ($r.whenCreated -is [DateTime]) { $r.whenCreated.ToString("yyyy-MM-dd HH:mm") } else { "$($r.whenCreated)" }
            WhenCreated       = if ($r.whenCreated -is [DateTime]) { $r.whenCreated.ToString("yyyy-MM-dd HH:mm") } else { "$($r.whenCreated)" }
            WhenChanged       = if ($r.whenChanged -is [DateTime]) { $r.whenChanged.ToString("yyyy-MM-dd HH:mm") } else { "$($r.whenChanged)" }
            Status            = if ($isDisabled) { "Disabled" } else { "Enabled" }
            IsEnabled         = -not $isDisabled
            DistinguishedName = $r.DistinguishedName
            OUPath            = Convert-DNToOUPath -DistinguishedName $r.DistinguishedName
            RawComputer       = $r
        })
    }

    $sorted = @($list | Sort-Object Name)
    if ($Limit -gt 0) {
        return @($sorted | Select-Object -First $Limit)
    } else {
        return @($sorted)
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
                    $targetVal = $NewValue
                    if ($targetVal -is [string] -and $targetVal -match '%(\w+)%') {
                        try {
                            $ldapObjPath = if ($Server) { "LDAP://$Server/$dn" } else { "LDAP://$dn" }
                            $objEntry = New-Object System.DirectoryServices.DirectoryEntry($ldapObjPath)
                            $targetVal = [regex]::Replace($targetVal, '%(\w+)%', {
                                param($m)
                                $prop = $m.Groups[1].Value
                                if ($objEntry.Properties[$prop].Value) {
                                    return "$($objEntry.Properties[$prop].Value)"
                                }
                                return ""
                            })
                        } catch {}
                    }
                    $upd = Set-ADObjectRawAttribute -DistinguishedName $dn -AttributeName $AttributeName -NewValue $targetVal -Server $Server
                    $res['Success'] = $upd.Success
                    $res['Message'] = if ($targetVal -ne $NewValue) { "$($upd.Message) [Resolved: '$targetVal']" } else { $upd.Message }
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

#region Active Directory Recycle Bin & Server Telemetry
function Get-ADDeletedObjects {
    [CmdletBinding()]
    param (
        [string]$SearchFilter = "*",
        [int]$Limit = 300,
        [string]$Server = ""
    )

    $results = New-Object System.Collections.Generic.List[PSCustomObject]

    try {
        if (Get-Command Get-ADObject -ErrorAction SilentlyContinue) {
            $adParams = @{
                Filter = "isDeleted -eq `$true"
                IncludeDeletedObjects = $true
                Properties = @('isDeleted', 'lastKnownParent', 'whenChanged', 'objectClass', 'sAMAccountName', 'distinguishedName', 'name')
                ErrorAction = 'Stop'
            }
            if ($Server) { $adParams['Server'] = $Server }

            $adObjects = Get-ADObject @adParams
            foreach ($o in $adObjects) {
                if ($SearchFilter -and $SearchFilter -ne "*") {
                    $matchText = "$($o.Name) $($o.sAMAccountName) $($o.objectClass) $($o.DistinguishedName)"
                    if ($matchText -notmatch [regex]::Escape($SearchFilter)) { continue }
                }
                $results.Add([PSCustomObject]@{
                    ObjectClass       = $o.ObjectClass
                    Name              = $o.Name
                    SamAccountName    = if ($o.sAMAccountName) { $o.sAMAccountName } else { "" }
                    WhenChanged       = if ($o.whenChanged -is [DateTime]) { $o.whenChanged.ToString("yyyy-MM-dd HH:mm:ss") } else { "$($o.whenChanged)" }
                    LastKnownParent   = if ($o.lastKnownParent) { $o.lastKnownParent } else { "Unknown" }
                    DistinguishedName = $o.DistinguishedName
                    IsRecycled        = [bool]$o.isDeleted
                })
                if ($Limit -gt 0 -and $results.Count -ge $Limit) { break }
            }
            return @($results)
        }
    } catch {}

    # Fallback to ADSI with Tombstone enabled
    try {
        $rootDse = if ($Server) {
            New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Server/RootDSE")
        } else {
            New-Object System.DirectoryServices.DirectoryEntry("LDAP://RootDSE")
        }
        $defaultNC = $rootDse.defaultNamingContext
        $deletedDn = "CN=Deleted Objects,$defaultNC"
        $delEntry = if ($Server) {
            New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Server/$deletedDn")
        } else {
            New-Object System.DirectoryServices.DirectoryEntry("LDAP://$deletedDn")
        }

        $searcher = New-Object System.DirectoryServices.DirectorySearcher($delEntry)
        $searcher.Tombstone = $true
        $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
        $searcher.PageSize = 250
        $searcher.PropertiesToLoad.AddRange(@('name', 'sAMAccountName', 'objectClass', 'lastKnownParent', 'whenChanged', 'distinguishedName', 'isDeleted'))

        if ($SearchFilter -and $SearchFilter -ne "*") {
            $searcher.Filter = "(&(isDeleted=TRUE)(|(name=*$SearchFilter*)(sAMAccountName=*$SearchFilter*)))"
        } else {
            $searcher.Filter = "(isDeleted=TRUE)"
        }

        $found = $searcher.FindAll()
        foreach ($sr in $found) {
            $p = $sr.Properties
            $name = if ($p['name'].Count -gt 0) { $p['name'][0] } else { "" }
            $sam = if ($p['samaccountname'].Count -gt 0) { $p['samaccountname'][0] } else { "" }
            $cls = if ($p['objectclass'].Count -gt 0) { $p['objectclass'][$p['objectclass'].Count - 1] } else { "" }
            $lkp = if ($p['lastknownparent'].Count -gt 0) { $p['lastknownparent'][0] } else { "" }
            $wc = if ($p['whenchanged'].Count -gt 0) { 
                $dtVal = $p['whenchanged'][0]
                if ($dtVal -is [DateTime]) { $dtVal.ToString("yyyy-MM-dd HH:mm:ss") } else { "$dtVal" }
            } else { "" }
            $dn = if ($p['distinguishedname'].Count -gt 0) { $p['distinguishedname'][0] } else { $sr.Path -replace '^LDAP://[^/]+/', '' }

            $results.Add([PSCustomObject]@{
                ObjectClass       = $cls
                Name              = $name
                SamAccountName    = $sam
                WhenChanged       = $wc
                LastKnownParent   = if ($lkp) { $lkp } else { "Unknown" }
                DistinguishedName = $dn
                IsRecycled        = $true
            })
            if ($Limit -gt 0 -and $results.Count -ge $Limit) { break }
        }
    } catch {
        Write-Warning "Failed to query AD Recycle Bin / Deleted Objects: $_"
    }

    return @($results)
}

function Restore-ADDeletedObject {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Identity,
        [string]$TargetOU = "",
        [string]$Server = ""
    )

    try {
        if (Get-Command Restore-ADObject -ErrorAction SilentlyContinue) {
            $params = @{
                Identity    = $Identity
                ErrorAction = 'Stop'
            }
            if ($Server) { $params['Server'] = $Server }
            if ($TargetOU) { $params['TargetPath'] = $TargetOU }

            Restore-ADObject @params
            return [PSCustomObject]@{
                Success = $true
                Message = "Object successfully restored from Active Directory Recycle Bin."
            }
        }
    } catch {
        return [PSCustomObject]@{
            Success = $false
            Message = "Restore failed via RSAT: $($_.Exception.Message)"
        }
    }

    # ADSI fallback
    try {
        $ldapPath = if ($Server) { "LDAP://$Server/$Identity" } else { "LDAP://$Identity" }
        $entry = New-Object System.DirectoryServices.DirectoryEntry($ldapPath)
        
        $destOU = $TargetOU
        if (-not $destOU) {
            $destOU = "$($entry.Properties['lastKnownParent'].Value)"
        }
        if (-not $destOU) {
            return [PSCustomObject]@{
                Success = $false
                Message = "Cannot determine target container. Please specify TargetOU."
            }
        }

        # Clean RDN from 0x0ADEL:guid
        $currentName = "$($entry.Properties['name'].Value)"
        $cleanName = ($currentName -replace '(?i)\x0ADEL:.*$', '') -replace '(?i)\nDEL:.*$', ''
        if (-not $cleanName) { $cleanName = $currentName }

        $parentPath = if ($Server) { "LDAP://$Server/$destOU" } else { "LDAP://$destOU" }
        $targetParent = New-Object System.DirectoryServices.DirectoryEntry($parentPath)
        
        $entry.MoveTo($targetParent, "CN=$cleanName")
        return [PSCustomObject]@{
            Success = $true
            Message = "Object reanimated and moved to $destOU."
        }
    } catch {
        return [PSCustomObject]@{
            Success = $false
            Message = "ADSI reanimation failed: $($_.Exception.Message)"
        }
    }
}

function Get-ADServerTelemetry {
    [CmdletBinding()]
    param (
        [string]$Server = ""
    )

    $dsePath = if ($Server) { "LDAP://$Server/RootDSE" } else { "LDAP://RootDSE" }
    $entry = New-Object System.DirectoryServices.DirectoryEntry($dsePath)

    $rfcControlsMap = @{
        "1.2.840.113556.1.4.319"  = "LDAP_PAGED_RESULT_OID_STRING (RFC 2696 - Paged Results)"
        "1.2.840.113556.1.4.473"  = "LDAP_SERVER_RESP_SORT_OID (RFC 2891 - Server-Side Sort)"
        "1.2.840.113556.1.4.474"  = "LDAP_SERVER_SORT_OID (RFC 2891 - Sort Request)"
        "1.2.840.113556.1.4.417"  = "LDAP_SERVER_SHOW_DELETED_OID (Show Deleted Objects / Tombstones)"
        "1.2.840.113556.1.4.2064" = "LDAP_SERVER_SHOW_RECYCLED_OID (Show Recycled Objects in Bin)"
        "1.2.840.113556.1.4.2065" = "LDAP_SERVER_DONT_ENFORCE_LIMITS_OID (Bypass Search Limits)"
        "2.16.840.1.113730.3.4.9"  = "LDAP_CONTROL_VLVREQUEST (RFC 2891 - Virtual List View)"
        "1.2.840.113556.1.4.1413" = "LDAP_SERVER_PERMISSIVE_MODIFY_OID (Permissive Modify)"
        "1.2.840.113556.1.4.841"  = "LDAP_SERVER_DIRSYNC_OID (Directory Synchronization / Incremental)"
        "1.2.840.113556.1.4.529"  = "LDAP_SERVER_EXTENDED_DN_OID (Extended GUID/SID DN)"
        "1.2.840.113556.1.4.801"  = "LDAP_SERVER_SD_FLAGS_OID (Security Descriptor Flags)"
        "1.2.840.113556.1.4.1338" = "LDAP_SERVER_VERIFY_NAME_OID (Cross-Domain Name Verification)"
        "1.2.840.113556.1.4.1339" = "LDAP_SERVER_DOMAIN_SCOPE_OID (Disable Referral Generation)"
        "1.2.840.113556.1.4.1340" = "LDAP_SERVER_SEARCH_OPTIONS_OID (Phantoms & Tombstone Flags)"
    }

    $funcLevelMap = @{
        0 = "Windows 2000"
        1 = "Windows Server 2003 Mixed"
        2 = "Windows Server 2003"
        3 = "Windows Server 2008"
        4 = "Windows Server 2008 R2"
        5 = "Windows Server 2012"
        6 = "Windows Server 2012 R2"
        7 = "Windows Server 2016 / 2019 / 2022 / 2025"
    }

    $dnsHost = "$($entry.Properties['dnsHostName'].Value)"
    $serviceName = "$($entry.Properties['ldapServiceName'].Value)"
    $isGC = "$($entry.Properties['isGlobalCatalogReady'].Value)"
    $dfLevel = $entry.Properties['domainControllerFunctionality'].Value
    $ffLevel = $entry.Properties['forestFunctionality'].Value

    $domainLevelStr = if ($funcLevelMap.ContainsKey([int]$dfLevel)) { $funcLevelMap[[int]$dfLevel] } else { "Level $dfLevel" }
    $forestLevelStr = if ($funcLevelMap.ContainsKey([int]$ffLevel)) { $funcLevelMap[[int]$ffLevel] } else { "Level $ffLevel" }

    # Server Time & Skew
    $serverTimeStr = "$($entry.Properties['currentTime'].Value)"
    $localUtc = [DateTime]::UtcNow
    $skewMs = 0
    $parsedServerUtc = $null

    if ($serverTimeStr -match '^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})') {
        $yr = [int]$matches[1]; $mo = [int]$matches[2]; $dy = [int]$matches[3]
        $hr = [int]$matches[4]; $mn = [int]$matches[5]; $sc = [int]$matches[6]
        $parsedServerUtc = New-Object DateTime($yr, $mo, $dy, $hr, $mn, $sc, [DateTimeKind]::Utc)
        $skewMs = [int]($localUtc - $parsedServerUtc).TotalMilliseconds
    }

    $namingContexts = @($entry.Properties['namingContexts'])
    $saslMechanisms = @($entry.Properties['supportedSASLMechanisms'])
    $supportedControlsRaw = @($entry.Properties['supportedControl'])

    $annotatedControls = New-Object System.Collections.Generic.List[string]
    foreach ($ctrl in $supportedControlsRaw) {
        $oid = "$ctrl".Trim()
        if ($rfcControlsMap.ContainsKey($oid)) {
            $annotatedControls.Add("$oid - $($rfcControlsMap[$oid])")
        } else {
            $annotatedControls.Add("$oid")
        }
    }

    return [PSCustomObject]@{
        DnsHostName             = $dnsHost
        LdapServiceName         = $serviceName
        DomainFunctionalLevel   = $domainLevelStr
        ForestFunctionalLevel   = $forestLevelStr
        IsGlobalCatalog         = if ($isGC -eq "TRUE") { "Yes (GC Operational)" } else { "No / Standard DC" }
        ServerTimeUtc           = if ($parsedServerUtc) { $parsedServerUtc.ToString("yyyy-MM-dd HH:mm:ss 'UTC'") } else { $serverTimeStr }
        LocalTimeUtc            = $localUtc.ToString("yyyy-MM-dd HH:mm:ss 'UTC'")
        TimeSkewMs              = $skewMs
        NamingContexts          = $namingContexts
        SupportedSASLMechanisms = $saslMechanisms
        SupportedControls       = @($annotatedControls)
        DefaultNamingContext    = "$($entry.Properties['defaultNamingContext'].Value)"
    }
}
#endregion

#region 17. Fine-Grained Password Policies (PSO) & Partitions Engine
function Get-ADPasswordSettingsObjects {
    [CmdletBinding()]
    param (
        [string]$Server = ""
    )

    $results = New-Object System.Collections.Generic.List[PSCustomObject]
    try {
        $rootDse = if ($Server) { [System.DirectoryServices.DirectoryEntry]"LDAP://$Server/RootDSE" } else { [System.DirectoryServices.DirectoryEntry]"LDAP://RootDSE" }
        $defaultNC = "$($rootDse.defaultNamingContext)"
        $psoContainer = "CN=Password Settings Container,CN=System,$defaultNC"

        $query = Invoke-LdapQuery -Filter "(objectClass=msDS-PasswordSettings)" -SearchBase $psoContainer -Scope Subtree `
            -PropertiesToLoad @(
                'cn', 'msDS-PasswordSettingsPrecedence', 'msDS-PasswordComplexityEnabled',
                'msDS-PasswordReversibleEncryptionEnabled', 'msDS-PasswordHistoryLength',
                'msDS-MinimumPasswordLength', 'msDS-MinimumPasswordAge', 'msDS-MaximumPasswordAge',
                'msDS-LockoutThreshold', 'msDS-LockoutObservationWindow', 'msDS-LockoutDuration',
                'msDS-PSOAppliesTo', 'distinguishedName'
            ) -Server $Server

        foreach ($r in $query.Results) {
            $maxAgeDays = "Never"
            if ($r.'msDS-MaximumPasswordAge') {
                $ticks = [Math]::Abs([int64]$r.'msDS-MaximumPasswordAge')
                $maxAgeDays = "$([Math]::Round($ticks / (10000000 * 86400), 1)) days"
            }
            $minAgeDays = "0 days"
            if ($r.'msDS-MinimumPasswordAge') {
                $ticks = [Math]::Abs([int64]$r.'msDS-MinimumPasswordAge')
                $minAgeDays = "$([Math]::Round($ticks / (10000000 * 86400), 1)) days"
            }
            $lockoutDur = "30 mins"
            if ($r.'msDS-LockoutDuration') {
                $ticks = [Math]::Abs([int64]$r.'msDS-LockoutDuration')
                $lockoutDur = "$([Math]::Round($ticks / (10000000 * 60), 0)) mins"
            }

            $appliesTo = @()
            if ($r.'msDS-PSOAppliesTo') {
                if ($r.'msDS-PSOAppliesTo' -is [System.Collections.IEnumerable] -and $r.'msDS-PSOAppliesTo' -isnot [string]) {
                    $appliesTo = @($r.'msDS-PSOAppliesTo')
                } else {
                    $appliesTo = @("$($r.'msDS-PSOAppliesTo')")
                }
            }

            $results.Add([PSCustomObject]@{
                Name                  = "$($r.cn)"
                Precedence            = [int]$r.'msDS-PasswordSettingsPrecedence'
                ComplexityEnabled     = [bool]$r.'msDS-PasswordComplexityEnabled'
                ReversibleEncryption  = [bool]$r.'msDS-PasswordReversibleEncryptionEnabled'
                MinPasswordLength     = [int]$r.'msDS-MinimumPasswordLength'
                PasswordHistoryLength = [int]$r.'msDS-PasswordHistoryLength'
                MaxPasswordAge        = $maxAgeDays
                MinPasswordAge        = $minAgeDays
                LockoutThreshold      = [int]$r.'msDS-LockoutThreshold'
                LockoutDuration       = $lockoutDur
                AppliesTo             = $appliesTo
                AppliesToCount        = $appliesTo.Count
                DistinguishedName     = "$($r.DistinguishedName)"
            })
        }
    }
    catch {
        Write-Warning "Could not query Password Settings Objects: $_"
    }

    return @($results | Sort-Object Precedence)
}

function Get-ADUserEffectivePasswordPolicy {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$UserIdentity,
        [string]$Server = ""
    )

    try {
        $filter = if ($UserIdentity -match '^CN=' -or $UserIdentity -match '^cn=') {
            "(distinguishedName=$UserIdentity)"
        } else {
            "(sAMAccountName=$UserIdentity)"
        }

        $userQuery = Invoke-LdapQuery -Filter $filter -PropertiesToLoad @('sAMAccountName', 'distinguishedName', 'msDS-ResultantPSO', 'userAccountControl') -Server $Server
        $userObj = $userQuery.Results | Select-Object -First 1

        if (-not $userObj) {
            return [PSCustomObject]@{
                UserFound = $false
                Message   = "User '$UserIdentity' was not found in directory."
            }
        }

        $resultantPSO = "$($userObj.'msDS-ResultantPSO')"

        if (-not [string]::IsNullOrWhiteSpace($resultantPSO)) {
            $psos = Get-ADPasswordSettingsObjects -Server $Server
            $matchedPso = $psos | Where-Object { $_.DistinguishedName -ieq $resultantPSO } | Select-Object -First 1
            if ($matchedPso) {
                return [PSCustomObject]@{
                    UserFound         = $true
                    SamAccountName    = $userObj.sAMAccountName
                    DistinguishedName = $userObj.DistinguishedName
                    PolicySource      = "Fine-Grained Password Settings Object (PSO)"
                    PolicyName        = $matchedPso.Name
                    Precedence        = $matchedPso.Precedence
                    MinPasswordLength = $matchedPso.MinPasswordLength
                    ComplexityEnabled = $matchedPso.ComplexityEnabled
                    HistoryLength     = $matchedPso.PasswordHistoryLength
                    MaxPasswordAge    = $matchedPso.MaxPasswordAge
                    MinPasswordAge    = $matchedPso.MinPasswordAge
                    LockoutThreshold  = $matchedPso.LockoutThreshold
                    LockoutDuration   = $matchedPso.LockoutDuration
                    PSOName           = $matchedPso.Name
                    PSODN             = $resultantPSO
                }
            }
        }

        $rootDse = if ($Server) { [System.DirectoryServices.DirectoryEntry]"LDAP://$Server/RootDSE" } else { [System.DirectoryServices.DirectoryEntry]"LDAP://RootDSE" }
        $defaultNC = "$($rootDse.defaultNamingContext)"
        $domainEntry = [System.DirectoryServices.DirectoryEntry]"LDAP://$defaultNC"

        $minLen = if ($domainEntry.Properties['minPwdLength'].Value) { [int]$domainEntry.Properties['minPwdLength'].Value } else { 7 }
        $histLen = if ($domainEntry.Properties['pwdHistoryLength'].Value) { [int]$domainEntry.Properties['pwdHistoryLength'].Value } else { 24 }
        $lockThresh = if ($domainEntry.Properties['lockoutThreshold'].Value) { [int]$domainEntry.Properties['lockoutThreshold'].Value } else { 0 }

        $maxAgeDays = "42 days"
        if ($domainEntry.Properties['maxPwdAge'].Value) {
            $ticks = [Math]::Abs([int64]$domainEntry.Properties['maxPwdAge'].Value)
            $maxAgeDays = "$([Math]::Round($ticks / (10000000 * 86400), 1)) days"
        }

        $lockDur = "30 mins"
        if ($domainEntry.Properties['lockoutDuration'].Value) {
            $ticks = [Math]::Abs([int64]$domainEntry.Properties['lockoutDuration'].Value)
            $lockDur = "$([Math]::Round($ticks / (10000000 * 60), 0)) mins"
        }

        return [PSCustomObject]@{
            UserFound         = $true
            SamAccountName    = $userObj.sAMAccountName
            DistinguishedName = $userObj.DistinguishedName
            PolicySource      = "Default Domain Password Policy"
            PolicyName        = "Domain Default Policy ($defaultNC)"
            Precedence        = "N/A (Domain-wide)"
            MinPasswordLength = $minLen
            ComplexityEnabled = $true
            HistoryLength     = $histLen
            MaxPasswordAge    = $maxAgeDays
            MinPasswordAge    = "1 days"
            LockoutThreshold  = $lockThresh
            LockoutDuration   = $lockDur
            PSOName           = "None (Default Domain Policy)"
            PSODN             = ""
        }
    }
    catch {
        return [PSCustomObject]@{
            UserFound = $false
            Message   = "Failed to calculate effective password policy: $_"
        }
    }
}

function Get-ADDirectoryPartitions {
    [CmdletBinding()]
    param (
        [string]$Server = ""
    )

    $partitions = New-Object System.Collections.Generic.List[PSCustomObject]
    try {
        $rootDse = if ($Server) { [System.DirectoryServices.DirectoryEntry]"LDAP://$Server/RootDSE" } else { [System.DirectoryServices.DirectoryEntry]"LDAP://RootDSE" }
        $configNC = "$($rootDse.configurationNamingContext)"
        $defaultNC = "$($rootDse.defaultNamingContext)"
        $schemaNC = "$($rootDse.schemaNamingContext)"

        $partitionsContainer = "CN=Partitions,$configNC"
        $query = Invoke-LdapQuery -Filter "(objectClass=crossRef)" -SearchBase $partitionsContainer -Scope OneLevel `
            -PropertiesToLoad @('cn', 'nCName', 'dnsRoot', 'systemFlags', 'msDS-NC-Replica-Locations', 'distinguishedName') -Server $Server

        foreach ($r in $query.Results) {
            $ncName = "$($r.nCName)"
            $sysFlags = if ($r.systemFlags) { [int]$r.systemFlags } else { 0 }

            $pType = "Application Partition (NDNC)"
            if ($ncName -ieq $defaultNC) {
                $pType = "Domain Naming Context"
            } elseif ($ncName -ieq $configNC) {
                $pType = "Configuration Naming Context"
            } elseif ($ncName -ieq $schemaNC) {
                $pType = "Schema Naming Context"
            } elseif ($ncName -match 'ForestDnsZones') {
                $pType = "Forest DNS Application Partition"
            } elseif ($ncName -match 'DomainDnsZones') {
                $pType = "Domain DNS Application Partition"
            }

            $replicas = @()
            if ($r.'msDS-NC-Replica-Locations') {
                if ($r.'msDS-NC-Replica-Locations' -is [System.Collections.IEnumerable] -and $r.'msDS-NC-Replica-Locations' -isnot [string]) {
                    $replicas = @($r.'msDS-NC-Replica-Locations')
                } else {
                    $replicas = @("$($r.'msDS-NC-Replica-Locations')")
                }
            }

            $partitions.Add([PSCustomObject]@{
                Name              = "$($r.cn)"
                PartitionType     = $pType
                NamingContextDN   = $ncName
                DnsRoot           = "$($r.dnsRoot)"
                SystemFlags       = $sysFlags
                ReplicaCount      = $replicas.Count
                Replicas          = ($replicas | ForEach-Object { if ($_ -match '^CN=([^,]+)') { $matches[1] } else { $_ } }) -join ", "
                DistinguishedName = "$($r.DistinguishedName)"
            })
        }
    }
    catch {
        Write-Warning "Could not enumerate directory partitions: $_"
    }

    return @($partitions)
}

function New-ADDirectoryPartition {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$PartitionDN,

        [Parameter(Mandatory = $false)]
        [string]$Server = ""
    )

    try {
        if (Get-Command New-ADDirectoryServerPartition -ErrorAction SilentlyContinue) {
            $params = @{ DistinguishedName = $PartitionDN }
            if ($Server) { $params['Server'] = $Server }
            New-ADDirectoryServerPartition @params
            return [PSCustomObject]@{
                Success = $true
                DN      = $PartitionDN
                Message = "Application directory partition '$PartitionDN' created successfully via RSAT."
            }
        }

        $rootDse = if ($Server) { [System.DirectoryServices.DirectoryEntry]"LDAP://$Server/RootDSE" } else { [System.DirectoryServices.DirectoryEntry]"LDAP://RootDSE" }
        $configNC = "$($rootDse.configurationNamingContext)"
        $partitionsContainer = [System.DirectoryServices.DirectoryEntry]"LDAP://CN=Partitions,$configNC"

        $cn = ($PartitionDN -split ',')[0] -replace '^DC=', ''
        $newCrossRef = $partitionsContainer.Children.Add("CN=$cn", "crossRef")
        $newCrossRef.Properties['nCName'].Value = $PartitionDN
        $newCrossRef.Properties['dnsRoot'].Value = "$cn.$($rootDse.dnsHostName)"
        $newCrossRef.Properties['systemFlags'].Value = 5
        $newCrossRef.CommitChanges()

        return [PSCustomObject]@{
            Success = $true
            DN      = $PartitionDN
            Message = "Application directory partition crossRef created successfully at 'CN=$cn,CN=Partitions,$configNC'."
        }
    }
    catch {
        return [PSCustomObject]@{
            Success = $false
            DN      = $PartitionDN
            Message = "Failed to create application partition: $_"
        }
    }
}
#endregion

Export-ModuleMember -Function `
    Remove-DiacriticsText, `
    Get-ADUsersList, Get-ADUserDetail, Test-ADUsernameExists, New-ADUserItem, Set-ADUserItem, `
    Remove-ADUserItem, Set-ADUserPassword, Set-ADUserStatus, Unlock-ADUserAccount, Move-ADPrincipal, `
    Get-ADGroupsList, Get-ADGroupMembersList, New-ADGroupItem, Remove-ADGroupItem, `
    Add-ADPrincipalToGroup, Remove-ADPrincipalFromGroup, `
    Get-ADOUTree, Get-ADOUFlatList, New-ADOrganizationalUnitItem, Remove-ADOrganizationalUnitItem, Get-ADObjectsInOU, `
    Get-ADDashboardStats, `
    Invoke-LdapQuery, Get-ADObjectRawAttributes, Set-ADObjectRawAttribute, Add-ADObjectRawAttributeValue, `
    Remove-ADObjectRawAttributeValue, Clear-ADObjectRawAttribute, Invoke-LdapSqlQuery, Invoke-LdifImport, `
    Compare-ADObjects, Get-ADSecurityAuditReport, Get-ADSchemaClasses, Get-ADSchemaAttributes, `
    Get-ADComputersList, Test-ADConnectionDiagnostic, Invoke-ADBulkUpdate, `
    Get-ADDeletedObjects, Restore-ADDeletedObject, Get-ADServerTelemetry, `
    Get-ADPasswordSettingsObjects, Get-ADUserEffectivePasswordPolicy, `
    Get-ADDirectoryPartitions, New-ADDirectoryPartition



