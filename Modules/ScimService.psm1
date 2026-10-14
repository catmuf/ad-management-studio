<#
.SYNOPSIS
    ScimService module for Active Directory Management Studio.
.DESCRIPTION
    Provides SCIM 2.0 object mapping (RFC 7643), reverse AD attribute translation,
    RFC 7644 Section 3.7 bulk operations processing with bulkId cross-referencing and
    failOnErrors thresholds, and RFC 7643 schema and resource type definitions.
#>

function Get-ADObjectAttributeValue {
    param (
        [object]$Object,
        [string[]]$PropertyNames,
        [object]$DefaultValue = $null
    )

    if ($null -eq $Object) { return $DefaultValue }

    foreach ($prop in $PropertyNames) {
        if ($Object -is [System.Collections.IDictionary]) {
            foreach ($key in $Object.Keys) {
                if ("$key" -ieq $prop) {
                    $val = $Object[$key]
                    if ($null -ne $val -and "$val" -ne "") { return $val }
                }
            }
        }
        else {
            $p = $Object.PSObject.Properties[$prop]
            if ($null -ne $p -and $null -ne $p.Value -and "$($p.Value)" -ne "") {
                return $p.Value
            }
        }
    }

    return $DefaultValue
}

function Convert-ADObjectToScimJson {
    <#
    .SYNOPSIS
        Maps an Active Directory object to standard SCIM 2.0 JSON.
    .DESCRIPTION
        Converts AD User or Group objects to standard SCIM 2.0 JSON format compliant with
        RFC 7643 (core User, Enterprise User extension, and core Group schemas).
    .EXAMPLE
        Convert-ADObjectToScimJson -ADObject $adUser
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [object]$ADObject,

        [ValidateSet('Auto', 'User', 'Group')]
        [string]$ResourceType = 'Auto',

        [string]$BaseUrl = "",

        [switch]$Compress
    )

    # Detect whether object is User or Group
    $objectClass = Get-ADObjectAttributeValue -Object $ADObject -PropertyNames @('objectClass', 'ObjectClass') -DefaultValue @()
    $isGroup = $false
    if ($ResourceType -ieq 'Group') {
        $isGroup = $true
    }
    elseif ($ResourceType -ieq 'Auto') {
        if ($objectClass -is [System.Collections.IEnumerable] -and "$objectClass" -match 'group') {
            $isGroup = $true
        }
        elseif (Get-ADObjectAttributeValue -Object $ADObject -PropertyNames @('groupType', 'GroupScope', 'GroupCategory')) {
            $isGroup = $true
        }
    }

    # Extract ID / objectGUID
    $guidRaw = Get-ADObjectAttributeValue -Object $ADObject -PropertyNames @('objectGUID', 'Guid', 'id', 'Id')
    $idStr = $null
    if ($null -ne $guidRaw) {
        if ($guidRaw -is [byte[]]) {
            $idStr = ([Guid]::new($guidRaw)).ToString()
        }
        elseif ($guidRaw -is [System.Guid]) {
            $idStr = $guidRaw.ToString()
        }
        else {
            $idStr = "$guidRaw"
        }
    }
    if ([string]::IsNullOrWhiteSpace($idStr)) {
        $idStr = [Guid]::NewGuid().ToString()
    }

    $whenCreated = Get-ADObjectAttributeValue -Object $ADObject -PropertyNames @('whenCreated', 'Created', 'createTimeStamp')
    $whenChanged = Get-ADObjectAttributeValue -Object $ADObject -PropertyNames @('whenChanged', 'Modified', 'modifyTimeStamp')

    $createdIso = if ($whenCreated) {
        if ($whenCreated -is [System.DateTime]) { $whenCreated.ToString("yyyy-MM-ddTHH:mm:ssZ") } else { "$whenCreated" }
    } else { (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ") }

    $changedIso = if ($whenChanged) {
        if ($whenChanged -is [System.DateTime]) { $whenChanged.ToString("yyyy-MM-ddTHH:mm:ssZ") } else { "$whenChanged" }
    } else { (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ") }

    if ($isGroup) {
        # --- GROUP OBJECT ---
        $displayName = Get-ADObjectAttributeValue -Object $ADObject -PropertyNames @('displayName', 'cn', 'Name', 'sAMAccountName')
        $membersRaw = Get-ADObjectAttributeValue -Object $ADObject -PropertyNames @('member', 'members', 'Members') -DefaultValue @()
        
        $membersList = [System.Collections.Generic.List[object]]::new()
        if ($null -ne $membersRaw) {
            foreach ($m in @($membersRaw)) {
                $mStr = "$m"
                $mDisplay = $null
                if ($mStr -match '^CN=([^,]+)') { $mDisplay = $matches[1] }
                $membersList.Add([ordered]@{
                    value   = $mStr
                    display = $mDisplay
                    type    = "User"
                })
            }
        }

        $groupLocation = if ($BaseUrl) { "$($BaseUrl.TrimEnd('/'))/Groups/$idStr" } else { "/Groups/$idStr" }
        $scimGroup = [ordered]@{
            schemas     = @("urn:ietf:params:scim:schemas:core:2.0:Group")
            id          = $idStr
            displayName = "$displayName"
            members     = @($membersList)
            meta        = [ordered]@{
                resourceType = "Group"
                created      = $createdIso
                lastModified = $changedIso
                location     = $groupLocation
            }
        }

        if ($Compress) {
            return (ConvertTo-Json -InputObject $scimGroup -Compress -Depth 15)
        }
        return (ConvertTo-Json -InputObject $scimGroup -Depth 15)
    }

    # --- USER OBJECT ---
    $userName = Get-ADObjectAttributeValue -Object $ADObject -PropertyNames @('sAMAccountName', 'userName', 'userPrincipalName')
    $externalId = Get-ADObjectAttributeValue -Object $ADObject -PropertyNames @('employeeID', 'externalId', 'employeeNumber')
    $displayName = Get-ADObjectAttributeValue -Object $ADObject -PropertyNames @('displayName', 'name', 'cn')
    $nickName = Get-ADObjectAttributeValue -Object $ADObject -PropertyNames @('mailNickname', 'nickName')
    $title = Get-ADObjectAttributeValue -Object $ADObject -PropertyNames @('title', 'Title')
    $userType = Get-ADObjectAttributeValue -Object $ADObject -PropertyNames @('employeeType', 'userType')
    $profileUrl = Get-ADObjectAttributeValue -Object $ADObject -PropertyNames @('wWWHomePage', 'profileUrl')

    # Active status
    $active = $true
    $enabledVal = Get-ADObjectAttributeValue -Object $ADObject -PropertyNames @('Enabled', 'enabled')
    $uacVal = Get-ADObjectAttributeValue -Object $ADObject -PropertyNames @('userAccountControl')
    $activeVal = Get-ADObjectAttributeValue -Object $ADObject -PropertyNames @('active', 'Active')

    if ($null -ne $enabledVal) {
        $active = [bool]$enabledVal
    }
    elseif ($null -ne $uacVal) {
        $uacInt = [int]$uacVal
        $active = (($uacInt -band 2) -eq 0)
    }
    elseif ($null -ne $activeVal) {
        $active = [bool]$activeVal
    }

    # Name complex attribute
    $givenName = Get-ADObjectAttributeValue -Object $ADObject -PropertyNames @('givenName', 'FirstName')
    $sn = Get-ADObjectAttributeValue -Object $ADObject -PropertyNames @('sn', 'Surname', 'LastName')
    $middleName = Get-ADObjectAttributeValue -Object $ADObject -PropertyNames @('middleName', 'Middle')
    $honorific = Get-ADObjectAttributeValue -Object $ADObject -PropertyNames @('personalTitle', 'honorificPrefix')

    $nameObj = [ordered]@{}
    if ($sn) { $nameObj['familyName'] = "$sn" }
    if ($givenName) { $nameObj['givenName'] = "$givenName" }
    if ($middleName) { $nameObj['middleName'] = "$middleName" }
    if ($honorific) { $nameObj['honorificPrefix'] = "$honorific" }
    $formatted = if ($displayName) { "$displayName" } elseif ($givenName -and $sn) { "$givenName $sn" } else { $null }
    if ($formatted) { $nameObj['formatted'] = $formatted }

    # Emails
    $emailsList = [System.Collections.Generic.List[object]]::new()
    $mail = Get-ADObjectAttributeValue -Object $ADObject -PropertyNames @('mail', 'EmailAddress')
    if ($mail) {
        $emailsList.Add([ordered]@{
            value   = "$mail"
            type    = "work"
            primary = $true
        })
    }
    $otherMail = Get-ADObjectAttributeValue -Object $ADObject -PropertyNames @('otherMailbox')
    if ($otherMail) {
        foreach ($om in @($otherMail)) {
            if ("$om" -ne "$mail") {
                $emailsList.Add([ordered]@{
                    value   = "$om"
                    type    = "other"
                    primary = $false
                })
            }
        }
    }

    # Phone numbers
    $phonesList = [System.Collections.Generic.List[object]]::new()
    $workPhone = Get-ADObjectAttributeValue -Object $ADObject -PropertyNames @('telephoneNumber', 'OfficePhone')
    if ($workPhone) {
        $phonesList.Add([ordered]@{
            value   = "$workPhone"
            type    = "work"
            primary = $true
        })
    }
    $mobile = Get-ADObjectAttributeValue -Object $ADObject -PropertyNames @('mobile', 'MobilePhone')
    if ($mobile) {
        $phonesList.Add([ordered]@{
            value   = "$mobile"
            type    = "mobile"
            primary = $false
        })
    }
    $fax = Get-ADObjectAttributeValue -Object $ADObject -PropertyNames @('facsimileTelephoneNumber', 'Fax')
    if ($fax) {
        $phonesList.Add([ordered]@{
            value   = "$fax"
            type    = "fax"
            primary = $false
        })
    }
    $homePhone = Get-ADObjectAttributeValue -Object $ADObject -PropertyNames @('homePhone')
    if ($homePhone) {
        $phonesList.Add([ordered]@{
            value   = "$homePhone"
            type    = "home"
            primary = $false
        })
    }

    # Addresses
    $addrList = [System.Collections.Generic.List[object]]::new()
    $street = Get-ADObjectAttributeValue -Object $ADObject -PropertyNames @('streetAddress', 'Street')
    $locality = Get-ADObjectAttributeValue -Object $ADObject -PropertyNames @('l', 'City', 'Locality')
    $region = Get-ADObjectAttributeValue -Object $ADObject -PropertyNames @('st', 'State', 'Region')
    $postalCode = Get-ADObjectAttributeValue -Object $ADObject -PropertyNames @('postalCode', 'PostalCode')
    $country = Get-ADObjectAttributeValue -Object $ADObject -PropertyNames @('co', 'c', 'Country')
    $postalAddress = Get-ADObjectAttributeValue -Object $ADObject -PropertyNames @('postalAddress')

    if ($street -or $locality -or $region -or $postalCode -or $country -or $postalAddress) {
        $addrObj = [ordered]@{
            type    = "work"
            primary = $true
        }
        if ($street) { $addrObj['streetAddress'] = "$street" }
        if ($locality) { $addrObj['locality'] = "$locality" }
        if ($region) { $addrObj['region'] = "$region" }
        if ($postalCode) { $addrObj['postalCode'] = "$postalCode" }
        if ($country) { $addrObj['country'] = "$country" }
        $formattedAddr = if ($postalAddress) { "$postalAddress" } else {
            $addrParts = @($street, $locality, "$region $postalCode".Trim(), $country) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
            $addrParts -join ", "
        }
        if ($formattedAddr) { $addrObj['formatted'] = $formattedAddr }
        $addrList.Add($addrObj)
    }

    # Enterprise User Extension
    $empNum = Get-ADObjectAttributeValue -Object $ADObject -PropertyNames @('employeeNumber')
    $costCenter = Get-ADObjectAttributeValue -Object $ADObject -PropertyNames @('costCenter', 'extensionAttribute1', 'departmentNumber')
    $organization = Get-ADObjectAttributeValue -Object $ADObject -PropertyNames @('company', 'organization')
    $division = Get-ADObjectAttributeValue -Object $ADObject -PropertyNames @('division')
    $department = Get-ADObjectAttributeValue -Object $ADObject -PropertyNames @('department')
    $manager = Get-ADObjectAttributeValue -Object $ADObject -PropertyNames @('manager')

    $enterprise = [ordered]@{}
    if ($empNum) { $enterprise['employeeNumber'] = "$empNum" }
    if ($costCenter) { $enterprise['costCenter'] = "$costCenter" }
    if ($organization) { $enterprise['organization'] = "$organization" }
    if ($division) { $enterprise['division'] = "$division" }
    if ($department) { $enterprise['department'] = "$department" }
    if ($manager) {
        $mgrDisplay = $null
        if ("$manager" -match '^CN=([^,]+)') { $mgrDisplay = $matches[1] }
        $enterprise['manager'] = [ordered]@{
            value       = "$manager"
            displayName = $mgrDisplay
        }
    }

    # Groups membership
    $memberOf = Get-ADObjectAttributeValue -Object $ADObject -PropertyNames @('memberOf', 'MemberOf') -DefaultValue @()
    $groupsList = [System.Collections.Generic.List[object]]::new()
    if ($memberOf) {
        foreach ($grp in @($memberOf)) {
            $grpStr = "$grp"
            $grpDisplay = $null
            if ($grpStr -match '^CN=([^,]+)') { $grpDisplay = $matches[1] }
            $groupsList.Add([ordered]@{
                value   = $grpStr
                display = $grpDisplay
                type    = "direct"
            })
        }
    }

    # Schemas array
    $schemas = [System.Collections.Generic.List[string]]::new()
    $schemas.Add("urn:ietf:params:scim:schemas:core:2.0:User")
    if ($enterprise.Count -gt 0) {
        $schemas.Add("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User")
    }

    $userLocation = if ($BaseUrl) { "$($BaseUrl.TrimEnd('/'))/Users/$idStr" } else { "/Users/$idStr" }
    $scimUser = [ordered]@{
        schemas     = @($schemas)
        id          = $idStr
    }
    if ($externalId) { $scimUser['externalId'] = "$externalId" }
    if ($userName) { $scimUser['userName'] = "$userName" }
    if ($nameObj.Count -gt 0) { $scimUser['name'] = $nameObj }
    if ($displayName) { $scimUser['displayName'] = "$displayName" }
    if ($nickName) { $scimUser['nickName'] = "$nickName" }
    if ($profileUrl) { $scimUser['profileUrl'] = "$profileUrl" }
    if ($title) { $scimUser['title'] = "$title" }
    if ($userType) { $scimUser['userType'] = "$userType" }
    $scimUser['active'] = $active

    if ($emailsList.Count -gt 0) { $scimUser['emails'] = @($emailsList) }
    if ($phonesList.Count -gt 0) { $scimUser['phoneNumbers'] = @($phonesList) }
    if ($addrList.Count -gt 0) { $scimUser['addresses'] = @($addrList) }
    if ($groupsList.Count -gt 0) { $scimUser['groups'] = @($groupsList) }

    if ($enterprise.Count -gt 0) {
        $scimUser['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User'] = $enterprise
    }

    $scimUser['meta'] = [ordered]@{
        resourceType = "User"
        created      = $createdIso
        lastModified = $changedIso
        location     = $userLocation
    }

    if ($Compress) {
        return (ConvertTo-Json -InputObject $scimUser -Compress -Depth 15)
    }
    return (ConvertTo-Json -InputObject $scimUser -Depth 15)
}

function Convert-ScimJsonToADAttributes {
    <#
    .SYNOPSIS
        Translates incoming SCIM 2.0 JSON into an Active Directory attribute hashtable.
    .DESCRIPTION
        Parses SCIM User or Group JSON payload and maps all standard and enterprise extension
        attributes into an AD attribute hashtable suitable for New-ADUser, Set-ADUser, etc.
    .EXAMPLE
        $adAttrs = Convert-ScimJsonToADAttributes -ScimJson $scimUserJson
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [object]$ScimJson,

        [switch]$IncludeExtendedAttributes
    )

    $obj = $ScimJson
    if ($ScimJson -is [string]) {
        $obj = ConvertFrom-Json -InputObject $ScimJson
    }

    $adAttrs = [ordered]@{}

    function Get-ObjVal ($source, [string]$prop) {
        if ($null -eq $source) { return $null }
        if ($source -is [System.Collections.IDictionary]) {
            foreach ($k in $source.Keys) {
                if ("$k" -ieq $prop) { return $source[$k] }
            }
        }
        elseif ($source.PSObject) {
            $p = $source.PSObject.Properties[$prop]
            if ($null -ne $p) { return $p.Value }
        }
        return $null
    }

    # Detect if Group schema
    $schemas = Get-ObjVal $obj 'schemas'
    $isGroup = $false
    if ($null -ne $schemas) {
        foreach ($s in @($schemas)) {
            if ("$s" -match 'Group') { $isGroup = $true }
        }
    }

    if ($isGroup) {
        $displayName = Get-ObjVal $obj 'displayName'
        if ($displayName) {
            $adAttrs['cn'] = "$displayName"
            $adAttrs['displayName'] = "$displayName"
            $adAttrs['sAMAccountName'] = "$displayName"
        }
        $members = Get-ObjVal $obj 'members'
        if ($null -ne $members) {
            $memList = [System.Collections.Generic.List[string]]::new()
            foreach ($m in @($members)) {
                $val = Get-ObjVal $m 'value'
                if ($val) { $memList.Add("$val") }
                elseif ($m -is [string]) { $memList.Add("$m") }
            }
            if ($memList.Count -gt 0) {
                $adAttrs['member'] = @($memList)
            }
        }
        return [hashtable]$adAttrs
    }

    # User Attributes
    $userName = Get-ObjVal $obj 'userName'
    if ($userName) {
        $adAttrs['sAMAccountName'] = "$userName"
        $adAttrs['userPrincipalName'] = "$userName"
    }

    $displayName = Get-ObjVal $obj 'displayName'
    if ($displayName) {
        $adAttrs['displayName'] = "$displayName"
    }

    $title = Get-ObjVal $obj 'title'
    if ($title) { $adAttrs['title'] = "$title" }

    $userType = Get-ObjVal $obj 'userType'
    if ($userType) { $adAttrs['employeeType'] = "$userType" }

    $externalId = Get-ObjVal $obj 'externalId'
    if ($externalId) { $adAttrs['employeeID'] = "$externalId" }

    # Name complex
    $name = Get-ObjVal $obj 'name'
    if ($name) {
        $given = Get-ObjVal $name 'givenName'
        $family = Get-ObjVal $name 'familyName'
        $middle = Get-ObjVal $name 'middleName'
        $formatted = Get-ObjVal $name 'formatted'

        if ($given) { $adAttrs['givenName'] = "$given" }
        if ($family) { $adAttrs['sn'] = "$family" }
        if ($middle) { $adAttrs['middleName'] = "$middle" }
        if ($formatted -and ($null -eq $adAttrs['displayName'])) {
            $adAttrs['displayName'] = "$formatted"
        }
    }

    # Emails
    $emails = Get-ObjVal $obj 'emails'
    if ($null -ne $emails) {
        $primaryEmail = $null
        $otherEmails = [System.Collections.Generic.List[string]]::new()
        foreach ($e in @($emails)) {
            $eval = Get-ObjVal $e 'value'
            $isPri = Get-ObjVal $e 'primary'
            if ($eval) {
                if ($isPri -eq $true -or ($null -eq $primaryEmail)) {
                    $primaryEmail = "$eval"
                } else {
                    $otherEmails.Add("$eval")
                }
            }
        }
        if ($primaryEmail) {
            $adAttrs['mail'] = $primaryEmail
            $currentUpn = if ($adAttrs['userPrincipalName']) { "$($adAttrs['userPrincipalName'])" } else { "" }
            if ($currentUpn -notmatch '@') {
                $adAttrs['userPrincipalName'] = $primaryEmail
            }
        }
        if ($otherEmails.Count -gt 0) {
            $adAttrs['otherMailbox'] = @($otherEmails)
        }
    }

    # Phone numbers
    $phones = Get-ObjVal $obj 'phoneNumbers'
    if ($null -ne $phones) {
        foreach ($p in @($phones)) {
            $pval = Get-ObjVal $p 'value'
            $ptype = Get-ObjVal $p 'type'
            if ($pval) {
                if ($ptype -ieq 'mobile') {
                    $adAttrs['mobile'] = "$pval"
                }
                elseif ($ptype -ieq 'fax') {
                    $adAttrs['facsimileTelephoneNumber'] = "$pval"
                }
                elseif ($ptype -ieq 'work' -or ($null -eq $adAttrs['telephoneNumber'])) {
                    $adAttrs['telephoneNumber'] = "$pval"
                }
            }
        }
    }

    # Addresses
    $addresses = Get-ObjVal $obj 'addresses'
    if ($null -ne $addresses) {
        foreach ($addr in @($addresses)) {
            $street = Get-ObjVal $addr 'streetAddress'
            $loc = Get-ObjVal $addr 'locality'
            $reg = Get-ObjVal $addr 'region'
            $postal = Get-ObjVal $addr 'postalCode'
            $country = Get-ObjVal $addr 'country'

            if ($street) { $adAttrs['streetAddress'] = "$street" }
            if ($loc) { $adAttrs['l'] = "$loc" }
            if ($reg) { $adAttrs['st'] = "$reg" }
            if ($postal) { $adAttrs['postalCode'] = "$postal" }
            if ($country) {
                $adAttrs['c'] = "$country"
                $adAttrs['co'] = "$country"
            }
            break # Use first/primary address
        }
    }

    # Active / Account Control
    $activeVal = Get-ObjVal $obj 'active'
    if ($null -ne $activeVal) {
        $isActive = [bool]$activeVal
        $adAttrs['Enabled'] = $isActive
        if ($isActive) {
            $adAttrs['userAccountControl'] = 512 # NORMAL_ACCOUNT
        } else {
            $adAttrs['userAccountControl'] = 514 # ACCOUNTDISABLE | NORMAL_ACCOUNT
        }
    }

    # Enterprise User Extension
    $entKey = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
    $ent = Get-ObjVal $obj $entKey
    if ($null -eq $ent) {
        # Check flat or alternative names
        $ent = Get-ObjVal $obj 'enterprise'
    }

    if ($ent) {
        $empNum = Get-ObjVal $ent 'employeeNumber'
        $costCenter = Get-ObjVal $ent 'costCenter'
        $org = Get-ObjVal $ent 'organization'
        $div = Get-ObjVal $ent 'division'
        $dept = Get-ObjVal $ent 'department'
        $mgr = Get-ObjVal $ent 'manager'

        if ($empNum) { $adAttrs['employeeNumber'] = "$empNum" }
        if ($costCenter) { $adAttrs['costCenter'] = "$costCenter" }
        if ($org) { $adAttrs['company'] = "$org" }
        if ($div) { $adAttrs['division'] = "$div" }
        if ($dept) { $adAttrs['department'] = "$dept" }
        if ($mgr) {
            $mgrVal = Get-ObjVal $mgr 'value'
            if ($mgrVal) { $adAttrs['manager'] = "$mgrVal" }
            elseif ($mgr -is [string]) { $adAttrs['manager'] = "$mgr" }
        }
    }

    # Check top-level department/company fallbacks
    $topDept = Get-ObjVal $obj 'department'
    if ($topDept -and ($null -eq $adAttrs['department'])) { $adAttrs['department'] = "$topDept" }

    $topOrg = Get-ObjVal $obj 'organization'
    if ($topOrg -and ($null -eq $adAttrs['company'])) { $adAttrs['company'] = "$topOrg" }

    return [hashtable]$adAttrs
}

function Resolve-BulkIdReferences {
    param (
        [object]$Target,
        [hashtable]$BulkIdMap
    )

    if ($null -eq $Target -or $BulkIdMap.Count -eq 0) { return $Target }

    if ($Target -is [string]) {
        $str = $Target
        foreach ($bulkId in $BulkIdMap.Keys) {
            $refToken = "bulkId:$bulkId"
            if ($str.Contains($refToken)) {
                $str = $str.Replace($refToken, $BulkIdMap[$bulkId])
            }
        }
        return $str
    }

    if ($Target -is [System.Collections.IDictionary]) {
        $newDict = [ordered]@{}
        foreach ($k in $Target.Keys) {
            $newDict[$k] = Resolve-BulkIdReferences -Target $Target[$k] -BulkIdMap $BulkIdMap
        }
        return $newDict
    }

    if ($Target -is [System.Collections.IEnumerable] -and $Target -isnot [string]) {
        $newList = [System.Collections.Generic.List[object]]::new()
        foreach ($item in $Target) {
            $newList.Add((Resolve-BulkIdReferences -Target $item -BulkIdMap $BulkIdMap))
        }
        return @($newList)
    }

    if ($Target.PSObject) {
        $newObj = [ordered]@{}
        foreach ($p in $Target.PSObject.Properties) {
            $newObj[$p.Name] = Resolve-BulkIdReferences -Target $p.Value -BulkIdMap $BulkIdMap
        }
        return [PSCustomObject]$newObj
    }

    return $Target
}

function Invoke-ScimBulkOperations {
    <#
    .SYNOPSIS
        Processes SCIM 2.0 Bulk Operations according to RFC 7644 Section 3.7.
    .DESCRIPTION
        Executes a sequence of SCIM operations supporting bulkId cross-referencing between operations,
        failOnErrors error abortion thresholds, and simulation mode for safe dry-run execution.
    .EXAMPLE
        Invoke-ScimBulkOperations -BulkPayload $bulkJson -SimulationMode
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [object]$BulkPayload,

        [int]$FailOnErrors = -1,

        [switch]$SimulationMode,

        [scriptblock]$OperationHandler = $null,

        [switch]$AsJson = $false
    )

    $payload = $BulkPayload
    if ($BulkPayload -is [string]) {
        $payload = ConvertFrom-Json -InputObject $BulkPayload
    }

    # Validate Schemas
    $schemas = if ($payload.schemas) { @($payload.schemas) } else { @() }
    $expectedSchema = "urn:ietf:params:scim:api:messages:2.0:BulkRequest"
    if ($schemas.Count -gt 0 -and $schemas -notcontains $expectedSchema) {
        Write-Warning "Payload schemas did not explicitly declare '$expectedSchema'."
    }

    # Determine failOnErrors limit
    $maxErrors = [int]::MaxValue
    if ($FailOnErrors -gt 0) {
        $maxErrors = $FailOnErrors
    }
    elseif ($null -ne $payload.failOnErrors) {
        $maxErrors = [int]$payload.failOnErrors
    }

    $bulkIdMap = @{}
    $bulkIdLocationMap = @{}
    $responseOperations = [System.Collections.Generic.List[object]]::new()
    $errorCount = 0
    $aborted = $false

    $operations = if ($payload.Operations) { @($payload.Operations) } else { @() }

    foreach ($op in $operations) {
        if ($aborted) {
            # RFC 7644 Section 3.7.3: Halt execution when failOnErrors threshold exceeded
            break
        }

        # Resolve bulkId in Path
        $path = "$($op.path)"
        foreach ($bId in $bulkIdMap.Keys) {
            $refToken = "bulkId:$bId"
            if ($path.Contains($refToken)) {
                $path = $path.Replace($refToken, $bulkIdMap[$bId])
            }
        }

        # Resolve bulkId inside Data
        $data = $op.data
        if ($null -ne $data) {
            $data = Resolve-BulkIdReferences -Target $data -BulkIdMap $bulkIdMap
        }

        $method = "$($op.method)".ToUpperInvariant()
        $opBulkId = if ($op.bulkId) { "$($op.bulkId)" } else { $null }

        $status = "200"
        $location = $null
        $respBody = $null

        if ($null -ne $OperationHandler) {
            # Delegate to custom operation handler
            try {
                $execContext = [PSCustomObject]@{
                    Method         = $method
                    Path           = $path
                    BulkId         = $opBulkId
                    Data           = $data
                    SimulationMode = [bool]$SimulationMode
                }
                $handlerResult = & $OperationHandler $execContext
                if ($handlerResult.Status) { $status = "$($handlerResult.Status)" }
                if ($handlerResult.Location) { $location = "$($handlerResult.Location)" }
                if ($handlerResult.Response) { $respBody = $handlerResult.Response }
                if ($handlerResult.Id -and $opBulkId) {
                    $bulkIdMap[$opBulkId] = "$($handlerResult.Id)"
                    $bulkIdLocationMap[$opBulkId] = if ($location) { $location } else { "$path/$($handlerResult.Id)" }
                }
            }
            catch {
                $status = "500"
                $respBody = [ordered]@{
                    schemas  = @("urn:ietf:params:scim:api:messages:2.0:Error")
                    scimType = "internalError"
                    detail   = $_.Exception.Message
                    status   = "500"
                }
            }
        }
        else {
            # Built-in RFC 7644 Simulation / Standard Processor
            switch ($method) {
                'POST' {
                    # Create Resource
                    $newId = [Guid]::NewGuid().ToString()
                    $location = "$path/$newId"
                    if ($opBulkId) {
                        $bulkIdMap[$opBulkId] = $newId
                        $bulkIdLocationMap[$opBulkId] = $location
                    }
                    $status = "201"
                    $respBody = [ordered]@{
                        id       = $newId
                        meta     = [ordered]@{
                            resourceType = if ($path -match 'Group') { "Group" } else { "User" }
                            location     = $location
                            version      = 'W/"1"'
                        }
                    }
                    if ($data) {
                        # Echo back populated resource data
                        if ($data -is [System.Collections.IDictionary]) {
                            foreach ($k in $data.Keys) { $respBody[$k] = $data[$k] }
                        }
                        elseif ($data.PSObject) {
                            foreach ($p in $data.PSObject.Properties) { $respBody[$p.Name] = $p.Value }
                        }
                        $respBody['id'] = $newId
                    }
                }
                'PUT' {
                    $status = "200"
                    $location = $path
                    $respBody = [ordered]@{
                        meta = [ordered]@{
                            location = $path
                            version  = 'W/"2"'
                        }
                    }
                }
                'PATCH' {
                    $status = "200"
                    $location = $path
                    $respBody = [ordered]@{
                        meta = [ordered]@{
                            location = $path
                            version  = 'W/"2"'
                        }
                    }
                }
                'DELETE' {
                    $status = "204"
                    $location = $path
                    $respBody = $null
                }
                default {
                    $status = "405"
                    $respBody = [ordered]@{
                        schemas  = @("urn:ietf:params:scim:api:messages:2.0:Error")
                        scimType = "invalidValue"
                        detail   = "HTTP method '$method' not permitted in bulk operations."
                        status   = "405"
                    }
                }
            }
        }

        # Build response item
        $opResp = [ordered]@{
            method = $op.method
            status = $status
        }
        if ($opBulkId) { $opResp['bulkId'] = $opBulkId }
        if ($location) { $opResp['location'] = $location }
        if ($respBody) { $opResp['response'] = $respBody }

        $responseOperations.Add($opResp)

        # Evaluate error threshold
        $stCode = 0
        if ([int]::TryParse($status, [ref]$stCode)) {
            if ($stCode -ge 400) {
                $errorCount++
                if ($errorCount -ge $maxErrors) {
                    $aborted = $true
                }
            }
        }
    }

    $bulkResponse = [ordered]@{
        schemas    = @("urn:ietf:params:scim:api:messages:2.0:BulkResponse")
        Operations = @($responseOperations)
    }

    if ($AsJson) {
        return (ConvertTo-Json -InputObject $bulkResponse -Depth 20)
    }
    return [PSCustomObject]$bulkResponse
}

function Get-ScimSchemaDefinition {
    <#
    .SYNOPSIS
        Returns standard SCIM 2.0 /Schemas and /ResourceTypes definitions.
    .DESCRIPTION
        Provides RFC 7643 schema definitions for User, Group, and Enterprise User extension,
        as well as endpoint resource type specifications.
    .EXAMPLE
        Get-ScimSchemaDefinition -Type All -AsJson
    #>
    [CmdletBinding()]
    param (
        [ValidateSet('All', 'User', 'Group', 'EnterpriseUser', 'ResourceTypes', 'Schemas')]
        [string]$Type = 'All',

        [switch]$AsJson
    )

    $userSchema = [ordered]@{
        id          = "urn:ietf:params:scim:schemas:core:2.0:User"
        name        = "User"
        description = "User Account"
        attributes  = @(
            [ordered]@{ name = "userName"; type = "string"; multiValued = $false; required = $true; caseExact = $false; mutability = "readWrite"; returned = "default"; uniqueness = "server" },
            [ordered]@{ name = "name"; type = "complex"; multiValued = $false; required = $false; subAttributes = @(
                [ordered]@{ name = "formatted"; type = "string"; multiValued = $false; mutability = "readWrite" },
                [ordered]@{ name = "familyName"; type = "string"; multiValued = $false; mutability = "readWrite" },
                [ordered]@{ name = "givenName"; type = "string"; multiValued = $false; mutability = "readWrite" },
                [ordered]@{ name = "middleName"; type = "string"; multiValued = $false; mutability = "readWrite" },
                [ordered]@{ name = "honorificPrefix"; type = "string"; multiValued = $false; mutability = "readWrite" }
            )},
            [ordered]@{ name = "displayName"; type = "string"; multiValued = $false; required = $false; mutability = "readWrite" },
            [ordered]@{ name = "nickName"; type = "string"; multiValued = $false; required = $false; mutability = "readWrite" },
            [ordered]@{ name = "profileUrl"; type = "reference"; multiValued = $false; required = $false; mutability = "readWrite" },
            [ordered]@{ name = "title"; type = "string"; multiValued = $false; required = $false; mutability = "readWrite" },
            [ordered]@{ name = "userType"; type = "string"; multiValued = $false; required = $false; mutability = "readWrite" },
            [ordered]@{ name = "preferredLanguage"; type = "string"; multiValued = $false; required = $false; mutability = "readWrite" },
            [ordered]@{ name = "locale"; type = "string"; multiValued = $false; required = $false; mutability = "readWrite" },
            [ordered]@{ name = "timezone"; type = "string"; multiValued = $false; required = $false; mutability = "readWrite" },
            [ordered]@{ name = "active"; type = "boolean"; multiValued = $false; required = $false; mutability = "readWrite" },
            [ordered]@{ name = "emails"; type = "complex"; multiValued = $true; required = $false; subAttributes = @(
                [ordered]@{ name = "value"; type = "string"; multiValued = $false; mutability = "readWrite" },
                [ordered]@{ name = "type"; type = "string"; multiValued = $false; mutability = "readWrite" },
                [ordered]@{ name = "primary"; type = "boolean"; multiValued = $false; mutability = "readWrite" }
            )},
            [ordered]@{ name = "phoneNumbers"; type = "complex"; multiValued = $true; required = $false; subAttributes = @(
                [ordered]@{ name = "value"; type = "string"; multiValued = $false; mutability = "readWrite" },
                [ordered]@{ name = "type"; type = "string"; multiValued = $false; mutability = "readWrite" },
                [ordered]@{ name = "primary"; type = "boolean"; multiValued = $false; mutability = "readWrite" }
            )},
            [ordered]@{ name = "addresses"; type = "complex"; multiValued = $true; required = $false; subAttributes = @(
                [ordered]@{ name = "formatted"; type = "string"; multiValued = $false; mutability = "readWrite" },
                [ordered]@{ name = "streetAddress"; type = "string"; multiValued = $false; mutability = "readWrite" },
                [ordered]@{ name = "locality"; type = "string"; multiValued = $false; mutability = "readWrite" },
                [ordered]@{ name = "region"; type = "string"; multiValued = $false; mutability = "readWrite" },
                [ordered]@{ name = "postalCode"; type = "string"; multiValued = $false; mutability = "readWrite" },
                [ordered]@{ name = "country"; type = "string"; multiValued = $false; mutability = "readWrite" },
                [ordered]@{ name = "type"; type = "string"; multiValued = $false; mutability = "readWrite" }
            )},
            [ordered]@{ name = "groups"; type = "complex"; multiValued = $true; mutability = "readOnly"; subAttributes = @(
                [ordered]@{ name = "value"; type = "string"; multiValued = $false; mutability = "readOnly" },
                [ordered]@{ name = "display"; type = "string"; multiValued = $false; mutability = "readOnly" },
                [ordered]@{ name = "type"; type = "string"; multiValued = $false; mutability = "readOnly" }
            )}
        )
    }

    $groupSchema = [ordered]@{
        id          = "urn:ietf:params:scim:schemas:core:2.0:Group"
        name        = "Group"
        description = "Group"
        attributes  = @(
            [ordered]@{ name = "displayName"; type = "string"; multiValued = $false; required = $true; mutability = "readWrite" },
            [ordered]@{ name = "members"; type = "complex"; multiValued = $true; required = $false; mutability = "readWrite"; subAttributes = @(
                [ordered]@{ name = "value"; type = "string"; multiValued = $false; mutability = "readWrite" },
                [ordered]@{ name = "display"; type = "string"; multiValued = $false; mutability = "readWrite" },
                [ordered]@{ name = "type"; type = "string"; multiValued = $false; mutability = "readWrite" }
            )}
        )
    }

    $enterpriseSchema = [ordered]@{
        id          = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
        name        = "EnterpriseUser"
        description = "Enterprise User Extension"
        attributes  = @(
            [ordered]@{ name = "employeeNumber"; type = "string"; multiValued = $false; mutability = "readWrite" },
            [ordered]@{ name = "costCenter"; type = "string"; multiValued = $false; mutability = "readWrite" },
            [ordered]@{ name = "organization"; type = "string"; multiValued = $false; mutability = "readWrite" },
            [ordered]@{ name = "division"; type = "string"; multiValued = $false; mutability = "readWrite" },
            [ordered]@{ name = "department"; type = "string"; multiValued = $false; mutability = "readWrite" },
            [ordered]@{ name = "manager"; type = "complex"; multiValued = $false; mutability = "readWrite"; subAttributes = @(
                [ordered]@{ name = "value"; type = "string"; multiValued = $false; mutability = "readWrite" },
                [ordered]@{ name = "displayName"; type = "string"; multiValued = $false; mutability = "readWrite" }
            )}
        )
    }

    $resourceTypes = @(
        [ordered]@{
            id               = "User"
            name             = "User"
            endpoint         = "/Users"
            description      = "User Account"
            schema           = "urn:ietf:params:scim:schemas:core:2.0:User"
            schemaExtensions = @(
                [ordered]@{
                    schema   = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
                    required = $false
                }
            )
        },
        [ordered]@{
            id          = "Group"
            name        = "Group"
            endpoint    = "/Groups"
            description = "Group"
            schema      = "urn:ietf:params:scim:schemas:core:2.0:Group"
        }
    )

    $result = switch ($Type) {
        'User'           { $userSchema }
        'Group'          { $groupSchema }
        'EnterpriseUser' { $enterpriseSchema }
        'Schemas'        { @($userSchema, $groupSchema, $enterpriseSchema) }
        'ResourceTypes'  { $resourceTypes }
        'All'            {
            [ordered]@{
                Schemas       = @($userSchema, $groupSchema, $enterpriseSchema)
                ResourceTypes = $resourceTypes
            }
        }
    }

    if ($AsJson) {
        return (ConvertTo-Json -InputObject $result -Depth 15)
    }
    return $result
}

Export-ModuleMember -Function `
    Convert-ADObjectToScimJson, `
    Convert-ScimJsonToADAttributes, `
    Invoke-ScimBulkOperations, `
    Get-ScimSchemaDefinition
