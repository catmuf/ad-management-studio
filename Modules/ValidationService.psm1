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

Export-ModuleMember -Function Remove-Diacritics, New-SecurePassword, Test-PasswordComplexity, Get-SuggestedUsername, Test-ValidEmailAddress, Test-SpanishID
