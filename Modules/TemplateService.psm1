<#
.SYNOPSIS
    TemplateService module for Active Directory Management Studio.
.DESCRIPTION
    Provides automated directory provisioning macro substitution, account name conflict resolution,
    and provisioning profile persistence.
#>

function Invoke-TemplateSubstitution {
    [CmdletBinding()]
    [Alias("Substitute-Template")]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [Alias("TemplateString")]
        [string]$Template,

        [Parameter(Mandatory = $true, Position = 1)]
        [psobject]$Attributes
    )

    $null = $Attributes

    if ([string]::IsNullOrEmpty($Template)) {
        return ""
    }

    # Match all %...% macro expressions
    $evaluator = {
        param([System.Text.RegularExpressions.Match]$match)
        $inner = $match.Groups[1].Value.Trim()
        if (-not $inner) { return "" }

        # Parse colon-separated tokens
        $tokens = $inner -split ':'
        $modifiers = New-Object System.Collections.Generic.List[string]
        $attrToken = $null
        $count = $null
        $substrStart = $null
        $substrLen = $null

        $i = 0
        while ($i -lt $tokens.Count) {
            $t = $tokens[$i].Trim()
            if ($t -ieq 'lower') {
                $modifiers.Add('lower')
            }
            elseif ($t -ieq 'upper') {
                $modifiers.Add('upper')
            }
            elseif ($t -ieq 'initial') {
                $modifiers.Add('initial')
                if ($null -eq $count) { $count = 1 }
            }
            elseif ($t -match '^(?i)substr(?:ing)?$') {
                $modifiers.Add('substr')
                if ($i + 1 -lt $tokens.Count -and $tokens[$i + 1] -match '^\d+$') {
                    $i++
                    $substrStart = [int]$tokens[$i]
                    if ($i + 1 -lt $tokens.Count -and $tokens[$i + 1] -match '^\d+$') {
                        $i++
                        $substrLen = [int]$tokens[$i]
                    }
                }
            }
            elseif ($t -match '^substr:(\d+)(?::(\d+))?$') {
                $modifiers.Add('substr')
                $substrStart = [int]$matches[1]
                if ($matches[2]) { $substrLen = [int]$matches[2] }
            }
            elseif ($t -match '^(\d+)$') {
                $count = [int]$matches[1]
            }
            else {
                # Attribute name, possibly with .count suffix (e.g. givenName.1)
                if ($t -match '^([a-zA-Z0-9_\-]+)\.(\d+)$') {
                    $attrToken = $matches[1]
                    if ($null -eq $count) { $count = [int]$matches[2] }
                } else {
                    $attrToken = $t
                }
            }
            $i++
        }

        # Retrieve attribute value from Attributes object / hashtable
        $rawVal = $null
        if ($attrToken) {
            if ($Attributes -is [System.Collections.IDictionary]) {
                foreach ($k in $Attributes.Keys) {
                    if ($k -ieq $attrToken) {
                        $rawVal = $Attributes[$k]
                        break
                    }
                }
            }
            elseif ($Attributes -is [PSObject] -and $Attributes.PSObject.Properties[$attrToken]) {
                $rawVal = $Attributes.PSObject.Properties[$attrToken].Value
            }
        }

        $strVal = if ($null -ne $rawVal) { [string]$rawVal } else { "" }

        # Apply substring or count slice
        if ($null -ne $substrStart) {
            $startIdx = if ($substrStart -gt 0) { $substrStart - 1 } else { 0 }
            if ($startIdx -ge $strVal.Length) {
                $strVal = ""
            } else {
                if ($null -ne $substrLen -and $substrLen -gt 0) {
                    $takeLen = [Math]::Min($substrLen, $strVal.Length - $startIdx)
                    $strVal = $strVal.Substring($startIdx, $takeLen)
                } else {
                    $strVal = $strVal.Substring($startIdx)
                }
            }
        }
        elseif ($null -ne $count -and $count -gt 0) {
            if ($strVal.Length -gt $count) {
                $strVal = $strVal.Substring(0, $count)
            }
        }

        # Apply casing modifiers
        if ($modifiers.Contains('lower')) {
            $strVal = $strVal.ToLowerInvariant()
        }
        if ($modifiers.Contains('upper')) {
            $strVal = $strVal.ToUpperInvariant()
        }

        return $strVal
    }

    return [regex]::Replace($Template, '%([^%]+)%', $evaluator)
}

function Resolve-AccountNameConflict {
    [CmdletBinding()]
    [Alias("Resolve-ADNameCollision")]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Candidate,

        [ValidateSet("sAMAccountName", "userPrincipalName", "cn", "name", "mail")]
        [string]$AttributeName = "sAMAccountName",

        [string]$Server = "",

        [scriptblock]$ExistsPredicate = $null,

        [int]$MaxAttempts = 100
    )

    $null = $Server
    $null = $ExistsPredicate

    if ([string]::IsNullOrWhiteSpace($Candidate)) {
        return $Candidate
    }

    $atIdx = $Candidate.IndexOf('@')
    if ($atIdx -ge 0) {
        $basePrefix   = $Candidate.Substring(0, $atIdx)
        $domainSuffix = $Candidate.Substring($atIdx)
    } else {
        $basePrefix   = $Candidate
        $domainSuffix = ""
    }

    # Internal existence check logic
    $checkExists = {
        param([string]$name)
        if ($ExistsPredicate) {
            return [bool](& $ExistsPredicate $name $AttributeName)
        }

        try {
            if (Get-Command Get-ADUser -ErrorAction SilentlyContinue) {
                $filter = if ($AttributeName -ieq "userPrincipalName") {
                    "UserPrincipalName -eq '$name'"
                } elseif ($AttributeName -ieq "mail") {
                    "mail -eq '$name'"
                } else {
                    "sAMAccountName -eq '$name'"
                }
                $params = @{ Filter = $filter; ErrorAction = 'SilentlyContinue' }
                if ($Server) { $params['Server'] = $Server }
                $found = Get-ADUser @params
                if ($found) { return $true }
            }
        } catch {
            $null = $_ # Suppress AD user lookup errors during collision check fallback
        }

        try {
            if (Get-Command Invoke-LdapQuery -ErrorAction SilentlyContinue) {
                $filter = "(&(objectCategory=person)(objectClass=user)($AttributeName=$name))"
                $res = Invoke-LdapQuery -Filter $filter -PropertiesToLoad @($AttributeName) -Server $Server
                if ($res -and $res.Count -gt 0) { return $true }
            }
        } catch {
            $null = $_ # Suppress LDAP query errors during collision check fallback
        }

        return $false
    }

    # Clamp sAMAccountName to Active Directory 20-character maximum
    if ($AttributeName -ieq "sAMAccountName" -and -not $domainSuffix -and $basePrefix.Length -gt 20) {
        $basePrefix = $basePrefix.Substring(0, 20)
    }

    # If original candidate does not conflict, return it directly
    $originalCandidate = "$basePrefix$domainSuffix"
    if (-not (& $checkExists $originalCandidate)) {
        return $originalCandidate
    }

    # Incrementally try candidate1, candidate2, ...
    for ($i = 1; $i -le $MaxAttempts; $i++) {
        $numStr = "$i"
        if ($domainSuffix) {
            $testCandidate = "$basePrefix$numStr$domainSuffix"
        } else {
            # Active Directory sAMAccountName hard limit: 20 characters
            $maxBaseLen = 20 - $numStr.Length
            $trimmedBase = if ($basePrefix.Length -gt $maxBaseLen) {
                $basePrefix.Substring(0, $maxBaseLen)
            } else {
                $basePrefix
            }
            $testCandidate = "$trimmedBase$numStr"
        }

        if (-not (& $checkExists $testCandidate)) {
            return $testCandidate
        }
    }

    # Fallback with timestamp-based discriminator if all iterations collide
    $epochSuffix = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds().ToString().Substring(4)
    if ($domainSuffix) {
        return "$basePrefix$epochSuffix$domainSuffix"
    } else {
        $maxBaseLen = 20 - $epochSuffix.Length
        $trimmedBase = if ($basePrefix.Length -gt $maxBaseLen) { $basePrefix.Substring(0, $maxBaseLen) } else { $basePrefix }
        return "$trimmedBase$epochSuffix"
    }
}

function Get-ADProvisioningTemplates {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [Alias("Get-ProvisioningProfiles")]
    param (
        [string]$Id = "",
        [string]$Name = "",
        [string]$ConfigPath = "$PSScriptRoot\..\config.json"
    )

    $defaultTemplates = @(
        [PSCustomObject]@{
            Id                        = "standard-employee"
            Name                      = "Standard Corporate Employee"
            Description               = "Default provisioning template for full-time corporate staff"
            TargetOU                  = "OU=Users,DC=corp,DC=local"
            SamAccountNamePattern     = "%lower:givenName.1%%lower:sn%"
            UserPrincipalNamePattern  = "%lower:sAMAccountName%@corp.local"
            DisplayNamePattern        = "%givenName% %sn%"
            CommonNamePattern         = "%givenName% %sn%"
            EmailPattern              = "%lower:givenName%.%lower:sn%@corp.local"
            Department                = "Corporate"
            DefaultGroups             = @("Domain Users")
            PasswordNeverExpires      = $false
            MustChangePasswordAtLogon = $true
            AccountDisabled           = $false
        },
        [PSCustomObject]@{
            Id                        = "external-contractor"
            Name                      = "External Contractor"
            Description               = "Provisioning profile for external contractors and vendors"
            TargetOU                  = "OU=Contractors,DC=corp,DC=local"
            SamAccountNamePattern     = "c-%lower:givenName.1%%lower:sn%"
            UserPrincipalNamePattern  = "%lower:sAMAccountName%@corp.local"
            DisplayNamePattern        = "%givenName% %sn% (Contractor)"
            CommonNamePattern         = "%givenName% %sn% (Contractor)"
            EmailPattern              = "%lower:givenName%.%lower:sn%@corp.local"
            Department                = "External"
            DefaultGroups             = @("Domain Users", "Contractor-Access")
            PasswordNeverExpires      = $false
            MustChangePasswordAtLogon = $true
            AccountDisabled           = $false
        },
        [PSCustomObject]@{
            Id                        = "it-administrator"
            Name                      = "IT Administrator"
            Description               = "Provisioning profile for IT administration personnel"
            TargetOU                  = "OU=Admin,DC=corp,DC=local"
            SamAccountNamePattern     = "adm-%lower:givenName.1%%lower:sn%"
            UserPrincipalNamePattern  = "%lower:sAMAccountName%@corp.local"
            DisplayNamePattern        = "%givenName% %sn% (Admin)"
            CommonNamePattern         = "%givenName% %sn% (Admin)"
            EmailPattern              = "%lower:givenName%.%lower:sn%@corp.local"
            Department                = "Information Technology"
            DefaultGroups             = @("Domain Users", "IT-Support")
            PasswordNeverExpires      = $false
            MustChangePasswordAtLogon = $true
            AccountDisabled           = $false
        }
    )

    if (Test-Path $ConfigPath) {
        try {
            $json = Get-Content -Path $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
            if ($json.ProvisioningTemplates -and @($json.ProvisioningTemplates).Count -gt 0) {
                $templates = @($json.ProvisioningTemplates)
                if ($Id) {
                    $templates = @($templates | Where-Object { $_.Id -ieq $Id })
                }
                if ($Name) {
                    $templates = @($templates | Where-Object { $_.Name -like "*$Name*" })
                }
                return ,@($templates)
            }
        } catch {
            Write-Warning "Failed to load ProvisioningTemplates from $($ConfigPath): $_"
        }
    }

    $res = $defaultTemplates
    if ($Id) {
        $res = @($res | Where-Object { $_.Id -ieq $Id })
    }
    if ($Name) {
        $res = @($res | Where-Object { $_.Name -like "*$Name*" })
    }
    return ,@($res)
}

function Save-ADProvisioningTemplates {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [Alias("Set-ProvisioningProfiles")]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [psobject]$Templates,

        [string]$ConfigPath = "$PSScriptRoot\..\config.json"
    )

    try {
        $config = if (Test-Path $ConfigPath) {
            Get-Content -Path $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
        } else {
            [PSCustomObject]@{}
        }

        $templateList = @($Templates)
        if (-not $config.PSObject.Properties['ProvisioningTemplates']) {
            $config | Add-Member -MemberType NoteProperty -Name "ProvisioningTemplates" -Value $templateList -Force
        } else {
            $config.ProvisioningTemplates = $templateList
        }

        $json = $config | ConvertTo-Json -Depth 6
        $utf8WithBom = New-Object System.Text.UTF8Encoding($true)
        [System.IO.File]::WriteAllText($ConfigPath, $json, $utf8WithBom)
        return $true
    }
    catch {
        Write-Error "Failed to save ProvisioningTemplates to $($ConfigPath): $_"
        return $false
    }
}

function New-ADProvisioningProfile {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Id,
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [string]$Description = "",
        [string]$TargetOU = "",
        [string]$SamAccountNamePattern = "%lower:givenName.1%%lower:sn%",
        [string]$UserPrincipalNamePattern = "%lower:sAMAccountName%@corp.local",
        [string]$DisplayNamePattern = "%givenName% %sn%",
        [string]$CommonNamePattern = "%givenName% %sn%",
        [string]$EmailPattern = "%lower:givenName%.%lower:sn%@corp.local",
        [string]$Department = "",
        [string[]]$DefaultGroups = @("Domain Users"),
        [bool]$PasswordNeverExpires = $false,
        [bool]$MustChangePasswordAtLogon = $true,
        [bool]$AccountDisabled = $false
    )

    return [PSCustomObject]@{
        Id                        = $Id
        Name                      = $Name
        Description               = $Description
        TargetOU                  = $TargetOU
        SamAccountNamePattern     = $SamAccountNamePattern
        UserPrincipalNamePattern  = $UserPrincipalNamePattern
        DisplayNamePattern        = $DisplayNamePattern
        CommonNamePattern         = $CommonNamePattern
        EmailPattern              = $EmailPattern
        Department                = $Department
        DefaultGroups             = $DefaultGroups
        PasswordNeverExpires      = $PasswordNeverExpires
        MustChangePasswordAtLogon = $MustChangePasswordAtLogon
        AccountDisabled           = $AccountDisabled
    }
}

function Invoke-ADObjectProvisioningPlan {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [psobject]$Template,

        [Parameter(Mandatory = $true)]
        [psobject]$UserInput,

        [scriptblock]$ExistsPredicate = $null,
        [string]$Server = ""
    )

    # Clone user attributes
    $attrs = [ordered]@{}
    if ($UserInput -is [System.Collections.IDictionary]) {
        foreach ($k in $UserInput.Keys) { $attrs[$k] = $UserInput[$k] }
    } elseif ($UserInput -is [PSObject]) {
        foreach ($p in $UserInput.PSObject.Properties) { $attrs[$p.Name] = $p.Value }
    }

    # 1. Generate sAMAccountName
    $rawSam = Invoke-TemplateSubstitution -Template $Template.SamAccountNamePattern -Attributes $attrs
    $resolvedSam = Resolve-AccountNameConflict -Candidate $rawSam -AttributeName "sAMAccountName" -Server $Server -ExistsPredicate $ExistsPredicate
    $attrs['sAMAccountName'] = $resolvedSam

    # 2. Generate UserPrincipalName
    $rawUpn = Invoke-TemplateSubstitution -Template $Template.UserPrincipalNamePattern -Attributes $attrs
    $resolvedUpn = Resolve-AccountNameConflict -Candidate $rawUpn -AttributeName "userPrincipalName" -Server $Server -ExistsPredicate $ExistsPredicate
    $attrs['userPrincipalName'] = $resolvedUpn

    # 3. Generate DisplayName and CN
    $displayName = Invoke-TemplateSubstitution -Template $Template.DisplayNamePattern -Attributes $attrs
    $cn = if ($Template.CommonNamePattern) {
        Invoke-TemplateSubstitution -Template $Template.CommonNamePattern -Attributes $attrs
    } else {
        $displayName
    }

    # 4. Generate Mail
    $mail = if ($Template.EmailPattern) {
        Invoke-TemplateSubstitution -Template $Template.EmailPattern -Attributes $attrs
    } else {
        ""
    }

    $targetOU = if ($attrs['TargetOU']) { $attrs['TargetOU'] } else { $Template.TargetOU }

    return [PSCustomObject]@{
        SamAccountName            = $resolvedSam
        UserPrincipalName         = $resolvedUpn
        DisplayName               = $displayName
        CommonName                = $cn
        DistinguishedName         = if ($targetOU) { "CN=$cn,$targetOU" } else { "CN=$cn" }
        TargetOU                  = $targetOU
        Mail                      = $mail
        Department                = if ($attrs['Department']) { $attrs['Department'] } else { $Template.Department }
        DefaultGroups             = $Template.DefaultGroups
        PasswordNeverExpires      = $Template.PasswordNeverExpires
        MustChangePasswordAtLogon = $Template.MustChangePasswordAtLogon
        AccountDisabled           = $Template.AccountDisabled
        TemplateId                = $Template.Id
        TemplateName              = $Template.Name
    }
}

Export-ModuleMember -Function `
    Invoke-TemplateSubstitution, `
    Resolve-AccountNameConflict, `
    Get-ADProvisioningTemplates, `
    Save-ADProvisioningTemplates, `
    New-ADProvisioningProfile, `
    Invoke-ADObjectProvisioningPlan `
    -Alias `
    Substitute-Template, `
    Resolve-ADNameCollision, `
    Get-ProvisioningProfiles, `
    Set-ProvisioningProfiles
