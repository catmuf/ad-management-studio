<#
.SYNOPSIS
    ValidationService module for Active Directory Management Studio.
.DESCRIPTION
    Provides input sanitization, diacritic removal, password complexity validation,
    cryptographic password generation, and username formatters.
#>

function Remove-Diacritics {
    [CmdletBinding()]
    param (
        [string]$Text
    )

    if ([string]::IsNullOrEmpty($Text)) { return "" }

    $normalized = $Text.Normalize([System.Text.NormalizationForm]::FormD)
    $sb = New-Object System.Text.StringBuilder

    foreach ($char in $normalized.ToCharArray()) {
        $category = [System.Globalization.CharUnicodeInfo]::GetUnicodeCategory($char)
        if ($category -ne [System.Globalization.UnicodeCategory]::NonSpacingMark) {
            [void]$sb.Append($char)
        }
    }

    $result = $sb.ToString().Normalize([System.Text.NormalizationForm]::FormC)
    # Special character replacements using portable character codes
    $nSmall = [char]0x00F1; $nCap = [char]0x00D1
    $cSmall = [char]0x00E7; $cCap = [char]0x00C7
    $result = $result -replace $nSmall, 'n' -replace $nCap, 'N' -replace $cSmall, 'c' -replace $cCap, 'C'
    return $result
}

function New-SecurePassword {
    [CmdletBinding()]
    param (
        [int]$Length = 16,
        [switch]$IncludeSpecial = $true
    )

    if ($Length -lt 12) { $Length = 12 }

    $upper = "ABCDEFGHJKLMNPQRSTUVWXYZ" # Exclude I, O to prevent confusion
    $lower = "abcdefghijkmnopqrstuvwxyz" # Exclude l to prevent confusion
    $digits = "23456789"                # Exclude 0, 1
    $symbols = "!@#$%^&*()_+-=[]{};:,.<>?"

    $allChars = $upper + $lower + $digits
    if ($IncludeSpecial) { $allChars += $symbols }

    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $bytes = New-Object byte[]($Length)

    # Ensure at least 1 upper, 1 lower, 1 digit, and 1 symbol
    $charList = New-Object System.Collections.Generic.List[char]
    
    $byte4 = New-Object byte[](4)
    $rng.GetBytes($byte4)
    $charList.Add($upper[$byte4[0] % $upper.Length])
    $charList.Add($lower[$byte4[1] % $lower.Length])
    $charList.Add($digits[$byte4[2] % $digits.Length])
    if ($IncludeSpecial) {
        $charList.Add($symbols[$byte4[3] % $symbols.Length])
    } else {
        $charList.Add($upper[$byte4[3] % $upper.Length])
    }

    # Fill the remaining
    $remainingLength = $Length - $charList.Count
    $remainingBytes = New-Object byte[]($remainingLength)
    $rng.GetBytes($remainingBytes)

    for ($i = 0; $i -lt $remainingLength; $i++) {
        $idx = $remainingBytes[$i] % $allChars.Length
        $charList.Add($allChars[$idx])
    }

    # Shuffle the characters using Fisher-Yates
    $shuffleBytes = New-Object byte[]($charList.Count)
    $rng.GetBytes($shuffleBytes)
    for ($i = $charList.Count - 1; $i -gt 0; $i--) {
        $swapIdx = $shuffleBytes[$i] % ($i + 1)
        $temp = $charList[$i]
        $charList[$i] = $charList[$swapIdx]
        $charList[$swapIdx] = $temp
    }

    return -join $charList
}

function Test-PasswordComplexity {
    [CmdletBinding()]
    param (
        [string]$Password,
        [int]$MinLength = 10
    )

    $result = [PSCustomObject]@{
        IsValid      = $false
        LengthValid  = $false
        HasUpper     = $false
        HasLower     = $false
        HasDigit     = $false
        HasSpecial   = $false
        Score        = 0
        Message      = ""
    }

    if ([string]::IsNullOrEmpty($Password)) {
        $result.Message = "Password cannot be empty."
        return $result
    }

    if ($Password.Length -ge $MinLength) {
        $result.LengthValid = $true
    }

    if ($Password -cmatch '[A-Z]') { $result.HasUpper = $true; $result.Score++ }
    if ($Password -cmatch '[a-z]') { $result.HasLower = $true; $result.Score++ }
    if ($Password -match '\d')     { $result.HasDigit = $true; $result.Score++ }
    if ($Password -match '[^a-zA-Z0-9]') { $result.HasSpecial = $true; $result.Score++ }

    if ($result.LengthValid -and $result.Score -ge 3) {
        $result.IsValid = $true
        $result.Message = "Password meets complexity requirements."
    }
    else {
        $reasons = @()
        if (-not $result.LengthValid) { $reasons += "Minimum $MinLength characters" }
        if ($result.Score -lt 3) { $reasons += "Must contain at least 3 of: Uppercase, Lowercase, Number, Symbol" }
        $result.Message = $reasons -join ". "
    }

    return $result
}

function Get-SuggestedUsername {
    [CmdletBinding()]
    param (
        [string]$FirstName,
        [string]$LastName,
        [string]$Format = "first.last" # options: "first.last", "flast", "firstl", "lastf"
    )

    $cleanFirst = (Remove-Diacritics -Text $FirstName).Trim().ToLower() -replace '[^a-z0-9]', ''
    $cleanLast = (Remove-Diacritics -Text $LastName).Trim().ToLower() -replace '\s+', '.' -replace '[^a-z0-9.]', ''
    
    # If last name has spaces or multiple parts, take first word or joined
    $firstLastPart = ($cleanLast -split '\.')[0]

    if ([string]::IsNullOrEmpty($cleanFirst) -and [string]::IsNullOrEmpty($cleanLast)) {
        return ""
    }

    switch ($Format) {
        "flast" {
            $f = if ($cleanFirst.Length -gt 0) { $cleanFirst.Substring(0, 1) } else { "" }
            return "$f$firstLastPart"
        }
        "firstl" {
            $l = if ($cleanLast.Length -gt 0) { $cleanLast.Substring(0, 1) } else { "" }
            return "$cleanFirst$l"
        }
        "lastf" {
            $f = if ($cleanFirst.Length -gt 0) { $cleanFirst.Substring(0, 1) } else { "" }
            return "$firstLastPart$f"
        }
        Default { # "first.last"
            if ($cleanFirst -and $firstLastPart) {
                return "$cleanFirst.$firstLastPart"
            }
            elseif ($cleanFirst) {
                return $cleanFirst
            }
            else {
                return $cleanLast
            }
        }
    }
}

function Test-ValidEmailAddress {
    [CmdletBinding()]
    param (
        [string]$Email
    )

    if ([string]::IsNullOrWhiteSpace($Email)) { return $true } # Empty is allowed if optional
    return ($Email -match '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
}

function Test-SpanishID {
    [CmdletBinding()]
    param (
        [string]$ID
    )

    if ([string]::IsNullOrWhiteSpace($ID)) { return $true }
    $clean = $ID.Trim().ToUpper()

    # DNI: 8 digits + 1 letter, or NIE: X/Y/Z + 7 digits + 1 letter
    return ($clean -match '^\d{8}[A-Z]$' -or $clean -match '^[XYZ]\d{7}[A-Z]$')
}

# UAC Flag definitions (RFC / Microsoft AD spec)
$script:UAC_FLAGS = [ordered]@{
    "SCRIPT"                          = 0x0001
    "ACCOUNTDISABLE"                  = 0x0002
    "HOMEDIR_REQUIRED"                = 0x0008
    "LOCKOUT"                         = 0x0010
    "PASSWD_NOTREQD"                  = 0x0020
    "PASSWD_CANT_CHANGE"              = 0x0040
    "ENCRYPTED_TEXT_PWD_ALLOWED"      = 0x0080
    "TEMP_DUPLICATE_ACCOUNT"          = 0x0100
    "NORMAL_ACCOUNT"                  = 0x0200
    "INTERDOMAIN_TRUST_ACCOUNT"       = 0x0800
    "WORKSTATION_TRUST_ACCOUNT"       = 0x1000
    "SERVER_TRUST_ACCOUNT"            = 0x2000
    "DONT_EXPIRE_PASSWORD"            = 0x10000
    "MNS_LOGON_ACCOUNT"               = 0x20000
    "SMARTCARD_REQUIRED"              = 0x40000
    "TRUSTED_FOR_DELEGATION"          = 0x80000
    "NOT_DELEGATED"                   = 0x100000
    "USE_DES_KEY_ONLY"                = 0x200000
    "DONT_REQ_PREAUTH"                = 0x400000
    "PASSWORD_EXPIRED"                = 0x800000
    "TRUSTED_TO_AUTH_FOR_DELEGATION"  = 0x1000000
    "PARTIAL_SECRETS_ACCOUNT"         = 0x4000000
}

function ConvertFrom-UACFlags {
    [CmdletBinding()]
    param (
        [Alias("UACValue")]
        [int64]$UAC
    )

    $active = New-Object System.Collections.Generic.List[string]
    $details = [ordered]@{}
    $allFlags = New-Object System.Collections.Generic.List[PSCustomObject]

    foreach ($key in $script:UAC_FLAGS.Keys) {
        $val = $script:UAC_FLAGS[$key]
        $isSet = (($UAC -band $val) -eq $val)
        $details[$key] = $isSet
        if ($isSet) {
            $active.Add($key)
        }
        $allFlags.Add([PSCustomObject]@{
            Name    = $key
            Value   = $val
            Hex     = ("0x{0:X4}" -f $val)
            Enabled = $isSet
        })
    }

    return [PSCustomObject]@{
        RawValue    = $UAC
        ActiveFlags = $active -join ", "
        FlagList    = $active
        Flags       = $details
        AllFlags    = $allFlags
    }
}

function ConvertTo-UACFlags {
    [CmdletBinding()]
    param (
        [string[]]$Flags
    )

    $uac = 0
    foreach ($flag in $Flags) {
        if ($script:UAC_FLAGS.Contains($flag)) {
            $uac = $uac -bor $script:UAC_FLAGS[$flag]
        }
    }
    return $uac
}

function ConvertFrom-ADLargeInteger {
    [CmdletBinding()]
    param (
        $Value
    )

    if ($null -eq $Value) { return "Not Set" }
    
    # Handle IADsLargeInteger COM object or 64-bit int
    $int64Val = 0
    if ($Value -is [int64] -or $Value -is [int] -or $Value -is [double] -or $Value -is [string]) {
        if (-not [int64]::TryParse($Value.ToString(), [ref]$int64Val)) {
            return $Value.ToString()
        }
    }
    elseif ($Value.GetType().Name -match 'LargeInteger|IADsLargeInteger') {
        $high = [int64]$Value.HighPart
        $low = [int64]$Value.LowPart
        if ($low -lt 0) { $low += [int64]4294967296 }
        $int64Val = ($high -shl 32) + $low
    }

    if ($int64Val -eq 0 -or $int64Val -eq 9223372036854775807 -or $int64Val -eq -1) {
        return "Never"
    }

    try {
        $dt = [DateTime]::FromFileTime($int64Val)
        return $dt.ToString("yyyy-MM-dd HH:mm:ss")
    }
    catch {
        return $int64Val.ToString()
    }
}

function ConvertTo-ADLargeInteger {
    [CmdletBinding()]
    param (
        [DateTime]$DateTime
    )
    return $DateTime.ToFileTime()
}

function ConvertFrom-ADSid {
    [CmdletBinding()]
    param (
        $Value
    )
    if ($null -eq $Value) { return "" }
    if ($Value -is [byte[]]) {
        try {
            $sid = New-Object System.Security.Principal.SecurityIdentifier($Value, 0)
            return $sid.Value
        }
        catch {
            return ($Value | ForEach-Object { $_.ToString("X2") }) -join ""
        }
    }
    return $Value.ToString()
}

function ConvertFrom-ADGuid {
    [CmdletBinding()]
    param (
        $Value
    )
    if ($null -eq $Value) { return "" }
    if ($Value -is [byte[]]) {
        try {
            $guid = New-Object System.Guid(,$Value)
            return $guid.ToString()
        }
        catch {
            return ($Value | ForEach-Object { $_.ToString("X2") }) -join ""
        }
    }
    return $Value.ToString()
}

function Test-LdapFilter {
    [CmdletBinding()]
    param (
        [string]$Filter
    )

    $result = [PSCustomObject]@{
        IsValid = $false
        Message = ""
        Filter  = $Filter
    }

    if ([string]::IsNullOrWhiteSpace($Filter)) {
        $result.Message = "Filter cannot be empty."
        return $result
    }

    $trimmed = $Filter.Trim()
    if (-not ($trimmed.StartsWith("(") -and $trimmed.EndsWith(")"))) {
        $result.Message = "LDAP filter must be enclosed in parentheses (e.g. (objectClass=user))."
        return $result
    }

    # Count matching parentheses & check logical operator syntax
    $openCount = 0
    $chars = $trimmed.ToCharArray()
    for ($i = 0; $i -lt $chars.Length; $i++) {
        $char = $chars[$i]
        if ($char -eq '(') {
            $openCount++
            # Next character check if logical operator (&, |, !)
            if ($i + 1 -lt $chars.Length) {
                $next = $chars[$i + 1]
                if ($next -in @('&', '|', '!')) {
                    if ($i + 2 -lt $chars.Length -and $chars[$i + 2] -ne '(') {
                        $result.Message = "Logical operator '$next' at position $($i + 1) must be immediately followed by '('."
                        return $result
                    }
                }
            }
        }
        elseif ($char -eq ')') { 
            $openCount-- 
            if ($openCount -lt 0) {
                $result.Message = "Mismatched parentheses: closing parenthesis without matching opening."
                return $result
            }
        }
    }

    if ($openCount -ne 0) {
        $result.Message = "Mismatched parentheses: $openCount unclosed '(' found."
        return $result
    }

    # Verify that leaf filters contain a valid comparison operator (=, ~=, >=, <=, :=)
    if ($trimmed -notmatch '[=~><:]') {
        $result.Message = "Invalid LDAP filter: no comparison operator (=, >=, <=, ~=, :=) found."
        return $result
    }

    $result.IsValid = $true
    $result.Message = "Filter syntax is valid according to RFC 4515 standards."
    return $result
}

function Convert-LdapFilterToHumanText {
    [CmdletBinding()]
    param (
        [string]$Filter
    )

    if ([string]::IsNullOrWhiteSpace($Filter)) { return "No filter specified (all directory objects)" }

    $f = $Filter.Trim()
    if ($f -eq "(objectClass=*)" -or $f -eq "(objectCategory=*)") { return "All directory objects" }
    if ($f -match "objectClass=user.*adminCount=1" -or $f -match "adminCount=1") { return "Privileged / administrative accounts protected by AdminSDHolder" }
    if ($f -match "objectClass=user.*userAccountControl.*2\)") { return "Disabled user accounts" }
    if ($f -match "objectClass=user.*!.*userAccountControl.*2\)") { return "Active (enabled) user accounts" }
    if ($f -match "userAccountControl.*65536") { return "Accounts with passwords that never expire (DONT_EXPIRE_PASSWORD)" }
    if ($f -match "lockoutTime.*1") { return "Accounts locked out due to failed logon attempts" }
    if ($f -match "objectClass=group.*!.*member=\*") { return "Empty security or distribution groups (0 members)" }
    if ($f -match "servicePrincipalName=\*") { return "Service accounts with registered Service Principal Names (SPNs)" }
    if ($f -match "objectClass=computer") { return "Domain computer objects" }
    if ($f -match "objectClass=group") { return "Active Directory security and distribution groups" }
    if ($f -match "objectClass=user") { return "Active Directory user accounts" }
    if ($f -match "objectClass=organizationalUnit") { return "Organizational Units (OUs)" }

    # Fallback readable extraction
    $parts = @()
    $matchesObj = [regex]::Matches($f, '\(([^()&|!]+)\)')
    foreach ($m in $matchesObj) {
        $val = $m.Groups[1].Value
        if ($val -match '^([a-zA-Z0-9_\-]+)\s*(=|>=|<=|~=)\s*(.+)$') {
            $attr = $matches[1]
            $op = switch ($matches[2]) {
                "="  { "is" }
                ">=" { "is greater than or equal to" }
                "<=" { "is less than or equal to" }
                "~=" { "sounds like / approx" }
                default { "matches" }
            }
            $valPart = $matches[3]
            $parts += "$attr $op '$valPart'"
        }
    }

    if ($parts.Count -gt 0) {
        $joiner = if ($f -match '^\(\|\(') { " OR " } else { " AND " }
        return "Find objects where: " + ($parts -join $joiner)
    }

    return "Custom LDAP query: $Filter"
}

function Test-LdifSyntax {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false, Position = 0)]
        [Alias("LdifContent")]
        [string]$Content
    )

    $result = [PSCustomObject]@{
        IsValid    = $false
        EntryCount = 0
        ErrorCount = 0
        Errors     = @()
        Message    = ""
    }

    if ([string]::IsNullOrWhiteSpace($Content)) {
        $result.Message = "LDIF content is empty."
        return $result
    }

    $lines = $Content -split '\r?\n'
    $hasDn = $false
    $count = 0
    $errors = [System.Collections.Generic.List[string]]::new()
    $lineNum = 0

    foreach ($line in $lines) {
        $lineNum++
        $t = $line.Trim()
        if ([string]::IsNullOrWhiteSpace($t) -or $t.StartsWith("#")) { continue }

        if ($t -match '^dn:\s*(.+)$') {
            $hasDn = $true
            $count++
            $dnVal = $matches[1]
            if ($dnVal -notmatch '=') {
                $errors.Add("Line ${lineNum}: Malformed DN '$dnVal' - must contain attribute=value components.")
            }
        }
        elseif ($t -match '^changetype:\s*(.+)$') {
            $ct = $matches[1].ToLower().Trim()
            if ($ct -notin @('add', 'modify', 'delete', 'moddn', 'modrdn')) {
                $errors.Add("Line ${lineNum}: Unknown changetype '$ct'. Expected add, modify, delete, moddn, or modrdn.")
            }
        }
        elseif ($t -match '^([a-zA-Z0-9_\-]+)(:?:\s*.+)$') {
            # Valid attribute line
        }
        elseif ($t -eq "-") {
            # Valid modification separator
        }
        else {
            $errors.Add("Line ${lineNum}: Syntax error - unrecognized LDIF statement '$t'.")
        }
    }

    if (-not $hasDn) {
        $result.Message = "No 'dn:' entry definitions found in LDIF document."
        return $result
    }

    if ($errors.Count -gt 0) {
        $result.IsValid = $false
        $result.ErrorCount = $errors.Count
        $result.Errors = @($errors)
        $result.Message = "LDIF syntax verification failed with $($errors.Count) error(s)."
        return $result
    }

    $result.IsValid = $true
    $result.EntryCount = $count
    $result.Message = "Valid RFC 2849 LDIF format with $count verified record(s)."
    return $result
}

function Test-ADSamAccountName {
    [CmdletBinding()]
    param (
        [string]$SamAccountName
    )
    $res = [PSCustomObject]@{
        IsValid = $false
        Message = ""
    }
    if ([string]::IsNullOrWhiteSpace($SamAccountName)) {
        $res.Message = "sAMAccountName cannot be empty."
        return $res
    }
    if ($SamAccountName.Length -gt 20) {
        $res.Message = "sAMAccountName cannot exceed 20 characters."
        return $res
    }
    if ($SamAccountName -match '["/\\\[\]:;|=,+*?<>]') {
        $res.Message = "sAMAccountName contains illegal characters."
        return $res
    }
    $res.IsValid = $true
    $res.Message = "Valid sAMAccountName."
    return $res
}

function Test-ADEmail {
    [CmdletBinding()]
    param (
        [string]$Email
    )
    $valid = (Test-ValidEmailAddress -Email $Email)
    return [PSCustomObject]@{
        IsValid = $valid
        Message = if ($valid) { "Valid email address." } else { "Invalid email address format." }
    }
}

function Test-ADPasswordComplexity {
    [CmdletBinding()]
    param (
        [string]$Password,
        [int]$MinLength = 10
    )
    return (Test-PasswordComplexity -Password $Password -MinLength $MinLength)
}

Export-ModuleMember -Function `
    Remove-Diacritics, `
    New-SecurePassword, `
    Test-PasswordComplexity, `
    Get-SuggestedUsername, `
    Test-ValidEmailAddress, `
    Test-SpanishID, `
    ConvertFrom-UACFlags, `
    ConvertTo-UACFlags, `
    ConvertFrom-ADLargeInteger, `
    ConvertTo-ADLargeInteger, `
    ConvertFrom-ADSid, `
    ConvertFrom-ADGuid, `
    Test-LdapFilter, `
    Convert-LdapFilterToHumanText, `
    Test-LdifSyntax, `
    Test-ADSamAccountName, `
    Test-ADEmail, `
    Test-ADPasswordComplexity

