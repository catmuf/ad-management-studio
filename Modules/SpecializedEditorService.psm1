<#
.SYNOPSIS
    SpecializedEditorService module for Active Directory & LDAP Management Studio.
.DESCRIPTION
    Provides specialized attribute & value editors matching Apache Directory Studio parity:
    - Hex / Binary editor with synchronized dump and parser
    - X.509 Certificate viewer with ASN.1 extraction, SAN parsing, and X509Chain revocation checking
    - LDAP GeneralizedTime and Windows FileTime 64-bit bidirectional converters
    - Cryptographic LDAP password hashing (SSHA, SSHA-512, SHA-256, MD5) and verification
    - Image and thumbnailPhoto inspector, validator, and 96x96 px / <100KB resize/crop engine
#>

# Ensure required cryptography, drawing, and imaging assemblies are loaded
Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue
Add-Type -AssemblyName System.Drawing -ErrorAction SilentlyContinue

function Format-BinaryHexDump {
    <#
    .SYNOPSIS
        Converts a byte array into structured hex dump rows with offset, hex bytes, and ASCII character dump.
    .DESCRIPTION
        Converts [byte[]] into structured rows with 8-character hex Offset (00000000, 00000010...),
        16 hex bytes with spacing and column alignment, and ASCII character dump (printable chars as-is, non-printable as '.').
    .PARAMETER Bytes
        The input byte array to format.
    .PARAMETER BytesPerLine
        Number of bytes per row (default 16).
    .PARAMETER AsText
        If set, returns the formatted dump as a multiline string.
    .OUTPUTS
        Array of PSCustomObject with Offset, Hex, HexView, Ascii, Text, and Bytes, or multiline string.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false, Position=0, ValueFromPipeline=$true)]
        [byte[]]$Bytes,

        [int]$BytesPerLine = 16,

        [switch]$AsText
    )

    if ($null -eq $Bytes -or $Bytes.Length -eq 0) {
        if ($AsText) { return "" }
        return @()
    }

    if ($BytesPerLine -le 0) { $BytesPerLine = 16 }

    $rows = New-Object System.Collections.Generic.List[psobject]
    $textLines = New-Object System.Collections.Generic.List[string]

    $total = $Bytes.Length
    for ($i = 0; $i -lt $total; $i += $BytesPerLine) {
        $chunkSize = [Math]::Min($BytesPerLine, $total - $i)
        $chunk = New-Object byte[]($chunkSize)
        [Array]::Copy($Bytes, $i, $chunk, 0, $chunkSize)

        $offsetStr = ("{0:X8}" -f $i)

        # Build hex part
        $hexList = New-Object System.Collections.Generic.List[string]
        for ($j = 0; $j -lt $chunkSize; $j++) {
            $hexList.Add(("{0:X2}" -f $chunk[$j]))
        }

        # Format hex with mid-line separator
        $hexDisplay = ""
        if ($BytesPerLine -eq 16) {
            $hexFirstHalf = @()
            $hexSecondHalf = @()
            if ($chunkSize -le 8) {
                $hexFirstHalf = $hexList.ToArray()
            } else {
                $hexFirstHalf = $hexList.GetRange(0, 8).ToArray()
                $hexSecondHalf = $hexList.GetRange(8, $chunkSize - 8).ToArray()
            }

            $hexFirstStr = ($hexFirstHalf -join " ")
            $hexSecondStr = ($hexSecondHalf -join " ")

            $padFirst = 8 * 3 - 1
            $padSecond = 8 * 3 - 1
            $hexCol1 = $hexFirstStr.PadRight($padFirst, ' ')
            $hexCol2 = if ($hexSecondStr.Length -gt 0) { $hexSecondStr.PadRight($padSecond, ' ') } else { "".PadRight($padSecond, ' ') }
            $hexDisplay = "$hexCol1  $hexCol2"
        } else {
            $hexDisplay = ($hexList -join " ")
        }

        # Build ASCII part
        $asciiChars = New-Object char[]($chunkSize)
        for ($j = 0; $j -lt $chunkSize; $j++) {
            $b = $chunk[$j]
            if ($b -ge 32 -and $b -le 126) {
                $asciiChars[$j] = [char]$b
            } else {
                $asciiChars[$j] = [char]46 # '.'
            }
        }
        $asciiStr = New-Object string(,$asciiChars)

        $lineText = "$offsetStr  $hexDisplay  |$asciiStr|"

        $row = [PSCustomObject]@{
            Offset   = $offsetStr
            Hex      = ($hexList -join " ")
            HexView  = $hexDisplay
            Ascii    = $asciiStr
            Text     = $lineText
            Bytes    = $chunk
        }
        $rows.Add($row)
        $textLines.Add($lineText)
    }

    if ($AsText) {
        return ($textLines -join "`r`n")
    }

    return ,$rows.ToArray()
}

function Convert-HexStringToByteArray {
    <#
    .SYNOPSIS
        Converts formatted or contiguous hex string back into [byte[]].
    .DESCRIPTION
        Parses contiguous hex strings, space-separated, hyphen-separated, C-style 0x prefixes,
        or full hex dump output lines (with offsets and ASCII pipes) into a clean [byte[]].
    .PARAMETER HexString
        The hex string to convert.
    .OUTPUTS
        [byte[]] containing the decoded bytes.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false, Position=0, ValueFromPipeline=$true)]
        [string]$HexString
    )

    if ([string]::IsNullOrWhiteSpace($HexString)) {
        return [byte[]]@()
    }

    $lines = $HexString -split "[\r\n]+"
    $cleanSb = New-Object System.Text.StringBuilder

    foreach ($rawLine in $lines) {
        $line = $rawLine.Trim()
        if ([string]::IsNullOrWhiteSpace($line)) { continue }

        # Strip ASCII dump enclosed in pipes '|...|'
        if ($line -match '^(.*?)\|(.*?)\|$') {
            $line = $Matches[1]
        }

        # Strip leading hex offset like '00000000:' or '00000000  '
        if ($line -match '^[0-9A-Fa-f]{4,8}[:\s]\s*(.*)$') {
            $line = $Matches[1]
        }

        # Strip '0x' prefixes
        $line = $line -replace '0x', ''

        # Strip common delimiters (spaces, commas, hyphens, colons, semicolons)
        $line = $line -replace '[\s,\-\:;]', ''

        [void]$cleanSb.Append($line)
    }

    $clean = $cleanSb.ToString()

    if ($clean.Length -eq 0) {
        return [byte[]]@()
    }

    if ($clean -notmatch '^[0-9A-Fa-f]+$') {
        throw [System.ArgumentException]"Hex string contains non-hexadecimal characters: '$clean'"
    }

    if ($clean.Length % 2 -ne 0) {
        throw [System.ArgumentException]"Hex string must have an even number of digits (found $($clean.Length))."
    }

    $byteCount = [int]($clean.Length / 2)
    $result = New-Object byte[]($byteCount)

    for ($i = 0; $i -lt $byteCount; $i++) {
        $result[$i] = [Convert]::ToByte($clean.Substring($i * 2, 2), 16)
    }

    return ,$result
}

function Get-X509CertificateMetadata {
    <#
    .SYNOPSIS
        Parses DER/Base64/PEM certificates and extracts complete X.509 metadata.
    .DESCRIPTION
        Parses DER byte arrays or Base64/PEM strings, extracts Subject, Issuer, SerialNumber,
        NotBefore, NotAfter, Thumbprint, KeyUsage, SAN, and checks revocation status via
        System.Security.Cryptography.X509Certificates.X509Chain.
    .PARAMETER CertificateInput
        An X509Certificate2 instance, raw byte array, PEM string, or Base64 string.
    .PARAMETER CheckRevocation
        If set, performs online revocation checking via CRL / OCSP.
    .PARAMETER RevocationMode
        Revocation checking mode: 'NoCheck', 'Online', or 'Offline'. Defaults to 'NoCheck'.
    .OUTPUTS
        PSCustomObject with parsed X.509 fields and revocation evaluation.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [object]$CertificateInput,

        [switch]$CheckRevocation,

        [ValidateSet('NoCheck', 'Online', 'Offline')]
        [string]$RevocationMode = 'NoCheck'
    )

    $cert = $null

    if ($CertificateInput -is [System.Security.Cryptography.X509Certificates.X509Certificate2]) {
        $cert = $CertificateInput
    }
    elseif ($CertificateInput -is [byte[]]) {
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(,$CertificateInput)
    }
    elseif ($CertificateInput -is [string]) {
        $str = $CertificateInput.Trim()
        if ($str -match '-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----') {
            $base64 = $Matches[1] -replace '\s', ''
            $rawBytes = [Convert]::FromBase64String($base64)
            $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(,$rawBytes)
        }
        elseif (Test-Path -Path $str -PathType Leaf -ErrorAction SilentlyContinue) {
            $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($str)
        }
        elseif ($str -match '^[A-Za-z0-9+/=\s]+$' -and ($str -notmatch '^[0-9A-Fa-f\s-]+$')) {
            $rawBytes = [Convert]::FromBase64String(($str -replace '\s', ''))
            $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(,$rawBytes)
        }
        else {
            $rawBytes = Convert-HexStringToByteArray -HexString $str
            $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(,$rawBytes)
        }
    }
    else {
        throw [System.ArgumentException]"Unsupported certificate input type: $(if ($CertificateInput) { $CertificateInput.GetType().FullName } else { 'null' })"
    }

    if ($null -eq $cert) {
        throw [System.InvalidOperationException]"Failed to parse certificate."
    }

    # Extract Common Name helper
    $getCN = {
        param([string]$dn)
        if ($dn -match '(?:^|,\s*)CN=([^,]+)') { return $Matches[1].Trim() }
        return $dn
    }

    $subjectCN = & $getCN $cert.Subject
    $issuerCN = & $getCN $cert.Issuer

    # Compute SHA-256 thumbprint
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $sha256Bytes = $sha256.ComputeHash($cert.RawData)
    $thumbprintSha256 = -join ($sha256Bytes | ForEach-Object { "{0:X2}" -f $_ })

    # Extract Key Usage (OID 2.5.29.15)
    $keyUsageList = New-Object System.Collections.Generic.List[string]
    $kuExt = $cert.Extensions | Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension] -or $_.Oid.Value -eq "2.5.29.15" }
    if ($kuExt) {
        if ($kuExt -is [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]) {
            $keyUsageList.Add($kuExt.KeyUsages.ToString())
        } else {
            $keyUsageList.Add($kuExt.Format($false))
        }
    }

    # Extract Enhanced Key Usage (OID 2.5.29.37)
    $enhancedKeyUsageList = New-Object System.Collections.Generic.List[string]
    $ekuExt = $cert.Extensions | Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension] -or $_.Oid.Value -eq "2.5.29.37" }
    if ($ekuExt) {
        if ($ekuExt -is [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]) {
            foreach ($oid in $ekuExt.EnhancedKeyUsages) {
                $ekuVal = if ($oid.FriendlyName) { "$($oid.FriendlyName) ($($oid.Value))" } else { $oid.Value }
                $enhancedKeyUsageList.Add($ekuVal)
            }
        } else {
            $enhancedKeyUsageList.Add($ekuExt.Format($false))
        }
    }

    # Extract Subject Alternative Name (SAN - OID 2.5.29.17)
    $sanList = New-Object System.Collections.Generic.List[string]
    $sanExt = $cert.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.17" }
    if ($sanExt) {
        $formattedSan = $sanExt.Format($true)
        $sanLines = $formattedSan -split "[\r\n]+"
        foreach ($sLine in $sanLines) {
            $trimmed = $sLine.Trim()
            if ([string]::IsNullOrWhiteSpace($trimmed)) { continue }
            if ($trimmed -match '=') {
                $parts = $trimmed -split '=', 2
                $sanList.Add($parts[1].Trim())
            } else {
                $sanList.Add($trimmed)
            }
        }
    }

    # Key size & algorithm
    $keySize = 0
    try {
        if ($cert.PublicKey -and $cert.PublicKey.Key) {
            $keySize = $cert.PublicKey.Key.KeySize
        }
    } catch {
        # PublicKey.Key can throw in certain environments where key provider is CNG
    }

    # Validity calculations
    $now = [DateTime]::Now
    $isValidNow = ($cert.NotBefore -le $now) -and ($cert.NotAfter -ge $now)
    $daysRemaining = [Math]::Round(($cert.NotAfter - $now).TotalDays, 1)

    # Revocation Checking via System.Security.Cryptography.X509Certificates.X509Chain
    $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
    $chain.ChainPolicy.RevocationFlag = [System.Security.Cryptography.X509Certificates.X509RevocationFlag]::EntireChain

    $shouldCheckRevocation = $CheckRevocation -or ($RevocationMode -ne 'NoCheck')
    if ($shouldCheckRevocation) {
        if ($RevocationMode -eq 'Offline') {
            $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::Offline
        } else {
            $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::Online
        }
        $chain.ChainPolicy.UrlRetrievalTimeout = [TimeSpan]::FromSeconds(3)
    } else {
        $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
    }

    $isChainValid = $false
    try {
        $isChainValid = $chain.Build($cert)
    } catch {
        # ignore chain exceptions
    }

    $revocationStatus = "Not Checked"
    $chainStatuses = New-Object System.Collections.Generic.List[string]

    if ($chain.ChainStatus) {
        foreach ($st in $chain.ChainStatus) {
            $chainStatuses.Add("$($st.Status): $($st.StatusInformation.Trim())")
        }
    }

    if ($shouldCheckRevocation) {
        $isRevoked = ($chain.ChainStatus | Where-Object { ($_.Status -band [System.Security.Cryptography.X509Certificates.X509ChainStatusFlags]::Revoked) -ne 0 }).Count -gt 0
        $isUnknown = ($chain.ChainStatus | Where-Object { ($_.Status -band [System.Security.Cryptography.X509Certificates.X509ChainStatusFlags]::RevocationStatusUnknown) -ne 0 -or ($_.Status -band [System.Security.Cryptography.X509Certificates.X509ChainStatusFlags]::OfflineRevocation) -ne 0 }).Count -gt 0

        if ($isRevoked) {
            $revocationStatus = "Revoked"
        } elseif ($isUnknown) {
            $revocationStatus = "Revocation Status Unknown (CRL offline or unreachable)"
        } else {
            $revocationStatus = "Valid / Not Revoked"
        }
    }

    $isSelfSigned = ($cert.Subject -eq $cert.Issuer)

    return [PSCustomObject]@{
        Subject                = $cert.Subject
        SubjectCN              = $subjectCN
        Issuer                 = $cert.Issuer
        IssuerCN               = $issuerCN
        SerialNumber           = $cert.SerialNumber
        NotBefore              = $cert.NotBefore
        NotAfter               = $cert.NotAfter
        IsValidNow             = $isValidNow
        DaysUntilExpiration    = $daysRemaining
        Thumbprint             = $cert.Thumbprint
        ThumbprintSHA256       = $thumbprintSha256
        SignatureAlgorithm     = $cert.SignatureAlgorithm.FriendlyName
        PublicKeyAlgorithm     = if ($cert.PublicKey -and $cert.PublicKey.Oid) { $cert.PublicKey.Oid.FriendlyName } else { "Unknown" }
        KeySize                = $keySize
        Version                = $cert.Version
        KeyUsage               = ($keyUsageList -join ", ")
        EnhancedKeyUsage       = ($enhancedKeyUsageList -join ", ")
        SubjectAlternativeNames= ($sanList -join ", ")
        SanList                = $sanList.ToArray()
        IsSelfSigned           = $isSelfSigned
        HasPrivateKey          = $cert.HasPrivateKey
        RevocationStatus       = $revocationStatus
        IsChainValid           = $isChainValid
        ChainStatuses          = $chainStatuses.ToArray()
        RawCertificate         = $cert
        RawBytes               = $cert.RawData
        Base64                 = [Convert]::ToBase64String($cert.RawData)
    }
}

function Convert-GeneralizedTimeToDateTime {
    <#
    .SYNOPSIS
        Converts LDAP GeneralizedTime string into [DateTime].
    .DESCRIPTION
        Converts LDAP GeneralizedTime (e.g. 'YYYYMMDDhhmmss.0Z') into [DateTime] (UTC by default, or Local if -ToLocal).
    .PARAMETER GeneralizedTime
        The GeneralizedTime string to convert.
    .PARAMETER ToLocal
        If set, returns the datetime converted to the local system timezone.
    .OUTPUTS
        [DateTime] object in UTC or local timezone.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [string]$GeneralizedTime,

        [switch]$ToLocal
    )

    if ([string]::IsNullOrWhiteSpace($GeneralizedTime)) { return $null }
    $gt = $GeneralizedTime.Trim()

    $formats = @(
        "yyyyMMddHHmmss.0\Z",
        "yyyyMMddHHmmss.f\Z",
        "yyyyMMddHHmmss.ff\Z",
        "yyyyMMddHHmmss.fff\Z",
        "yyyyMMddHHmmss.ffff\Z",
        "yyyyMMddHHmmss\Z",
        "yyyyMMddHHmm\Z",
        "yyyyMMddHH\Z",
        "yyyyMMddHHmmss.0",
        "yyyyMMddHHmmss"
    )
    $dt = [DateTime]::MinValue
    $style = [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal

    if ([DateTime]::TryParseExact($gt, $formats, [System.Globalization.CultureInfo]::InvariantCulture, $style, [ref]$dt)) {
        if ($ToLocal) { return $dt.ToLocalTime() }
        return [DateTime]::SpecifyKind($dt, [System.DateTimeKind]::Utc)
    }

    # Regex fallback for offsets like +0200, -0500, or +01:00
    if ($gt -match '^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})?(\d{2})?(?:\.(\d+))?(?:(Z)|([+-])(\d{2})(?::?(\d{2}))?)?$') {
        $year   = [int]$Matches[1]
        $month  = [int]$Matches[2]
        $day    = [int]$Matches[3]
        $hour   = [int]$Matches[4]
        $min    = if ($Matches[5]) { [int]$Matches[5] } else { 0 }
        $sec    = if ($Matches[6]) { [int]$Matches[6] } else { 0 }
        $ms     = if ($Matches[7]) { [int]($Matches[7].PadRight(3, '0').Substring(0, 3)) } else { 0 }

        $utcDt = New-Object DateTime($year, $month, $day, $hour, $min, $sec, $ms, [System.DateTimeKind]::Utc)
        if ($Matches[9]) {
            $sign = if ($Matches[9] -eq '+') { -1 } else { 1 }
            $offH = [int]$Matches[10]
            $offM = if ($Matches[11]) { [int]$Matches[11] } else { 0 }
            $utcDt = $utcDt.AddHours($sign * $offH).AddMinutes($sign * $offM)
        }
        if ($ToLocal) { return $utcDt.ToLocalTime() }
        return $utcDt
    }

    throw [System.ArgumentException]"Invalid LDAP GeneralizedTime format: '$GeneralizedTime'"
}

function Convert-DateTimeToGeneralizedTime {
    <#
    .SYNOPSIS
        Converts [DateTime] into LDAP GeneralizedTime string.
    .DESCRIPTION
        Converts [DateTime] into standard LDAP GeneralizedTime (e.g. 'YYYYMMDDhhmmss.0Z').
    .PARAMETER DateTime
        The DateTime object to convert.
    .PARAMETER OmitFraction
        If set, omits the .0 subsecond fraction ('YYYYMMDDhhmmssZ').
    .OUTPUTS
        [string] formatted as LDAP GeneralizedTime.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [DateTime]$DateTime,

        [switch]$OmitFraction
    )

    $utc = $DateTime.ToUniversalTime()
    if ($OmitFraction) {
        return $utc.ToString("yyyyMMddHHmmss\Z", [System.Globalization.CultureInfo]::InvariantCulture)
    } else {
        return $utc.ToString("yyyyMMddHHmmss.0\Z", [System.Globalization.CultureInfo]::InvariantCulture)
    }
}

function Convert-FileTimeToDateTime {
    <#
    .SYNOPSIS
        Converts a 64-bit Windows FileTime integer into [DateTime].
    .DESCRIPTION
        Converts 64-bit Windows FileTime integer (e.g. pwdLastSet, accountExpires) into [DateTime].
        Handles special values such as 0 and 0x7FFFFFFFFFFFFFFF (Never Expires).
    .PARAMETER FileTime
        64-bit FileTime integer (long, int, or string representation).
    .PARAMETER ToLocal
        If set, converts to local timezone.
    .OUTPUTS
        [DateTime] representing the FileTime value.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [object]$FileTime,

        [switch]$ToLocal
    )

    $val = 0L
    if ($FileTime -is [long] -or $FileTime -is [int]) {
        $val = [long]$FileTime
    } elseif ($FileTime -is [string]) {
        if (-not [long]::TryParse($FileTime.Trim(), [ref]$val)) {
            throw [System.ArgumentException]"Cannot parse '$FileTime' as a 64-bit FileTime integer."
        }
    } else {
        # Support AD LargeInteger COM object
        if ($FileTime.GetType().GetProperty("HighPart") -and $FileTime.GetType().GetProperty("LowPart")) {
            $high = [long]$FileTime.HighPart
            $low = [long]$FileTime.LowPart
            if ($low -lt 0) { $low = $low + 4294967296L }
            $val = ($high -shl 32) -bor $low
        } else {
            $val = [long]$FileTime
        }
    }

    if ($val -eq 0) {
        $epoch = [DateTime]::SpecifyKind([DateTime]::new(1601, 1, 1, 0, 0, 0), [System.DateTimeKind]::Utc)
        if ($ToLocal) { return $epoch.ToLocalTime() }
        return $epoch
    }

    # AD Never Expires value: 0x7FFFFFFFFFFFFFFF = 9223372036854775807
    if ($val -ge 2650467743990000000L -or $val -eq [long]::MaxValue) {
        return [DateTime]::MaxValue
    }

    if ($val -lt 0) {
        throw [System.ArgumentOutOfRangeException]"FileTime cannot be negative: $val"
    }

    $dt = [DateTime]::FromFileTimeUtc($val)
    if ($ToLocal) { return $dt.ToLocalTime() }
    return $dt
}

function Convert-DateTimeToFileTime {
    <#
    .SYNOPSIS
        Converts [DateTime] into a 64-bit Windows FileTime integer.
    .DESCRIPTION
        Converts [DateTime] into 64-bit Windows FileTime (100-ns intervals since 1601-01-01 UTC).
    .PARAMETER DateTime
        The DateTime to convert.
    .OUTPUTS
        [long] 64-bit FileTime integer.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [DateTime]$DateTime
    )

    if ($DateTime -eq [DateTime]::MaxValue) {
        return [long]::MaxValue
    }
    if ($DateTime -le [DateTime]::new(1601, 1, 1)) {
        return 0L
    }

    return $DateTime.ToUniversalTime().ToFileTimeUtc()
}

function New-LdapPasswordHash {
    <#
    .SYNOPSIS
        Generates RFC 2307 compliant LDAP password hashes with cryptographic salt.
    .DESCRIPTION
        Generates SSHA, SSHA-512, SHA-256, and MD5 hashes with cryptographic salt for userPassword.
    .PARAMETER Password
        Cleartext password to hash.
    .PARAMETER Algorithm
        Hash algorithm: SSHA, SSHA-512, SSHA-256, SMD5, SHA-256, or MD5. Defaults to SSHA.
    .PARAMETER Salt
        Optional specific byte array to use as salt. If omitted, cryptographically strong salt is generated.
    .PARAMETER SaltLength
        Length of generated salt in bytes (default 8).
    .PARAMETER NoSalt
        If set, generates unsalted hash (e.g. {SHA256}, {MD5}, {SHA}).
    .OUTPUTS
        [string] formatted LDAP password hash with scheme prefix (e.g. '{SSHA}abc...').
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, Position=0)]
        [string]$Password,

        [ValidateSet('SSHA', 'SSHA-512', 'SSHA512', 'SSHA-256', 'SSHA256', 'SHA-256', 'SHA256', 'SMD5', 'MD5', 'SHA')]
        [string]$Algorithm = 'SSHA',

        [byte[]]$Salt,

        [int]$SaltLength = 8,

        [switch]$NoSalt
    )

    $pwdBytes = [System.Text.Encoding]::UTF8.GetBytes($Password)
    $algoNormalized = $Algorithm.ToUpper().Replace("-", "")
    $useSalt = (-not $NoSalt)

    if ($NoSalt) {
        $saltBytes = [byte[]]@()
    } else {
        if ($null -ne $Salt -and $Salt.Length -gt 0) {
            $saltBytes = $Salt
        } else {
            if ($SaltLength -lt 4) { $SaltLength = 4 }
            $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
            $saltBytes = New-Object byte[]($SaltLength)
            $rng.GetBytes($saltBytes)
        }
    }

    $payload = New-Object byte[]($pwdBytes.Length + $saltBytes.Length)
    [Array]::Copy($pwdBytes, 0, $payload, 0, $pwdBytes.Length)
    if ($saltBytes.Length -gt 0) {
        [Array]::Copy($saltBytes, 0, $payload, $pwdBytes.Length, $saltBytes.Length)
    }

    $digest = $null
    $prefix = ""

    switch ($algoNormalized) {
        'SSHA' {
            $hasher = [System.Security.Cryptography.SHA1]::Create()
            $digest = $hasher.ComputeHash($payload)
            $prefix = "{SSHA}"
        }
        'SHA' {
            $hasher = [System.Security.Cryptography.SHA1]::Create()
            $digest = $hasher.ComputeHash($payload)
            $prefix = if ($useSalt) { "{SSHA}" } else { "{SHA}" }
        }
        'SSHA512' {
            $hasher = [System.Security.Cryptography.SHA512]::Create()
            $digest = $hasher.ComputeHash($payload)
            $prefix = "{SSHA512}"
        }
        'SSHA256' {
            $hasher = [System.Security.Cryptography.SHA256]::Create()
            $digest = $hasher.ComputeHash($payload)
            $prefix = "{SSHA256}"
        }
        'SHA256' {
            $hasher = [System.Security.Cryptography.SHA256]::Create()
            $digest = $hasher.ComputeHash($payload)
            $prefix = if ($useSalt) { "{SSHA256}" } else { "{SHA256}" }
        }
        'SMD5' {
            $hasher = [System.Security.Cryptography.MD5]::Create()
            $digest = $hasher.ComputeHash($payload)
            $prefix = "{SMD5}"
        }
        'MD5' {
            $hasher = [System.Security.Cryptography.MD5]::Create()
            $digest = $hasher.ComputeHash($payload)
            $prefix = if ($useSalt) { "{SMD5}" } else { "{MD5}" }
        }
        default {
            $hasher = [System.Security.Cryptography.SHA1]::Create()
            $digest = $hasher.ComputeHash($payload)
            $prefix = "{SSHA}"
        }
    }

    $combined = New-Object byte[]($digest.Length + $saltBytes.Length)
    [Array]::Copy($digest, 0, $combined, 0, $digest.Length)
    if ($saltBytes.Length -gt 0) {
        [Array]::Copy($saltBytes, 0, $combined, $digest.Length, $saltBytes.Length)
    }

    $b64 = [Convert]::ToBase64String($combined)
    return "$prefix$b64"
}

function Test-LdapPasswordHash {
    <#
    .SYNOPSIS
        Verifies cleartext password against a salted LDAP password hash.
    .DESCRIPTION
        Parses LDAP hash schemes ({SSHA}, {SSHA512}, {SSHA256}, {SMD5}, {MD5}, {SHA256}, etc.),
        extracts salt and digest, and verifies password match in constant time.
    .PARAMETER Password
        The cleartext password to verify.
    .PARAMETER Hash
        The LDAP password hash string to verify against.
    .OUTPUTS
        [bool] True if password matches hash, False otherwise.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, Position=0)]
        [string]$Password,

        [Parameter(Mandatory=$true, Position=1)]
        [string]$Hash
    )

    if ([string]::IsNullOrEmpty($Hash)) { return $false }
    $h = $Hash.Trim()

    if ($h -notmatch '^\{([A-Za-z0-9_-]+)\}(.*)$') {
        return ($Password -eq $h)
    }

    $scheme = $Matches[1].ToUpper().Replace("-", "")
    $dataStr = $Matches[2].Trim()

    $digestLength = 0
    $hasher = $null

    switch ($scheme) {
        { $_ -in 'SSHA', 'SHA', 'SHA1' } {
            $digestLength = 20
            $hasher = [System.Security.Cryptography.SHA1]::Create()
        }
        { $_ -in 'SSHA256', 'SHA256' } {
            $digestLength = 32
            $hasher = [System.Security.Cryptography.SHA256]::Create()
        }
        { $_ -in 'SSHA512', 'SHA512' } {
            $digestLength = 64
            $hasher = [System.Security.Cryptography.SHA512]::Create()
        }
        { $_ -in 'SMD5', 'MD5' } {
            $digestLength = 16
            $hasher = [System.Security.Cryptography.MD5]::Create()
        }
        'CLEARTEXT' {
            return ($Password -eq $dataStr)
        }
        default {
            return $false
        }
    }

    $rawBytes = $null
    try {
        $rawBytes = [Convert]::FromBase64String($dataStr)
    } catch {
        try {
            $rawBytes = Convert-HexStringToByteArray -HexString $dataStr
        } catch {
            return $false
        }
    }

    if ($null -eq $rawBytes -or $rawBytes.Length -lt $digestLength) {
        return $false
    }

    $storedDigest = New-Object byte[]($digestLength)
    [Array]::Copy($rawBytes, 0, $storedDigest, 0, $digestLength)

    $saltLength = $rawBytes.Length - $digestLength
    $saltBytes = New-Object byte[]($saltLength)
    if ($saltLength -gt 0) {
        [Array]::Copy($rawBytes, $digestLength, $saltBytes, 0, $saltLength)
    }

    $pwdBytes = [System.Text.Encoding]::UTF8.GetBytes($Password)
    $payload = New-Object byte[]($pwdBytes.Length + $saltBytes.Length)
    [Array]::Copy($pwdBytes, 0, $payload, 0, $pwdBytes.Length)
    if ($saltLength -gt 0) {
        [Array]::Copy($saltBytes, 0, $payload, $pwdBytes.Length, $saltLength)
    }

    $computedDigest = $hasher.ComputeHash($payload)

    if ($storedDigest.Length -ne $computedDigest.Length) { return $false }
    $diff = 0
    for ($i = 0; $i -lt $storedDigest.Length; $i++) {
        $diff = $diff -bor ($storedDigest[$i] -bxor $computedDigest[$i])
    }

    return ($diff -eq 0)
}

function Format-ThumbnailPhotoImage {
    <#
    .SYNOPSIS
        Inspects image byte arrays (thumbnailPhoto, jpegPhoto), validates image format, dimensions,
        and provides helper to resize/crop to AD recommended 96x96 pixels and <100KB.
    .DESCRIPTION
        Detects image magic bytes (JPEG, PNG, GIF, BMP), reads dimensions and size, checks AD guidelines
        (<=96x96 px, <100 KB), and provides high-quality center-cropping and resizing.
    .PARAMETER ImageInput
        Byte array, image file path, Base64 string, or hex string.
    .PARAMETER Resize
        If set, forces resize and square crop to the target dimensions.
    .PARAMETER TargetWidth
        Target width in pixels (default 96).
    .PARAMETER TargetHeight
        Target height in pixels (default 96).
    .PARAMETER JpegQuality
        JPEG compression quality between 1 and 100 (default 85).
    .PARAMETER PassThruBytes
        If set, returns only the processed [byte[]] instead of the metadata object.
    .OUTPUTS
        PSCustomObject with validation and processed image bytes, or raw [byte[]].
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [object]$ImageInput,

        [switch]$Resize,

        [int]$TargetWidth = 96,

        [int]$TargetHeight = 96,

        [int]$JpegQuality = 85,

        [switch]$PassThruBytes
    )

    $bytes = $null
    if ($ImageInput -is [byte[]]) {
        $bytes = $ImageInput
    } elseif ($ImageInput -is [string]) {
        if (Test-Path -Path $ImageInput -PathType Leaf -ErrorAction SilentlyContinue) {
            $bytes = [System.IO.File]::ReadAllBytes($ImageInput)
        } else {
            try {
                $bytes = [Convert]::FromBase64String($ImageInput.Trim())
            } catch {
                $bytes = Convert-HexStringToByteArray -HexString $ImageInput
            }
        }
    }

    if ($null -eq $bytes -or $bytes.Length -eq 0) {
        throw [System.ArgumentException]"Image input byte array is empty or null."
    }

    # Detect format from magic bytes
    $format = "Unknown"
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xD8 -and $bytes[2] -eq 0xFF) {
        $format = "JPEG"
    } elseif ($bytes.Length -ge 8 -and $bytes[0] -eq 0x89 -and $bytes[1] -eq 0x50 -and $bytes[2] -eq 0x4E -and $bytes[3] -eq 0x47) {
        $format = "PNG"
    } elseif ($bytes.Length -ge 4 -and $bytes[0] -eq 0x47 -and $bytes[1] -eq 0x49 -and $bytes[2] -eq 0x46 -and $bytes[3] -eq 0x38) {
        $format = "GIF"
    } elseif ($bytes.Length -ge 2 -and $bytes[0] -eq 0x42 -and $bytes[1] -eq 0x4D) {
        $format = "BMP"
    }

    Add-Type -AssemblyName System.Drawing -ErrorAction SilentlyContinue

    $inMs = New-Object System.IO.MemoryStream(,$bytes)
    $origImg = $null
    $width = 0
    $height = 0
    $isValid = $false
    $errorMessage = $null

    try {
        $origImg = [System.Drawing.Image]::FromStream($inMs)
        $width = $origImg.Width
        $height = $origImg.Height
        $isValid = $true
    } catch {
        $isValid = $false
        $errorMessage = $_.Exception.Message
    }

    $sizeBytes = $bytes.Length
    $sizeKB = [Math]::Round($sizeBytes / 1KB, 2)
    $maxRecommendedBytes = 102400 # 100 KB
    $isAdCompliant = ($isValid -and $width -le 96 -and $height -le 96 -and $sizeBytes -le $maxRecommendedBytes)

    $processedBytes = $null
    $processedWidth = $width
    $processedHeight = $height
    $processedSize = $sizeBytes

    if ($isValid -and ($Resize -or ($width -ne $TargetWidth -or $height -ne $TargetHeight -or $sizeBytes -gt $maxRecommendedBytes))) {
        try {
            $side = [Math]::Min($origImg.Width, $origImg.Height)
            $cropX = [int][Math]::Floor(($origImg.Width - $side) / 2)
            $cropY = [int][Math]::Floor(($origImg.Height - $side) / 2)
            $srcRect = New-Object System.Drawing.Rectangle($cropX, $cropY, $side, $side)

            $dstBmp = New-Object System.Drawing.Bitmap($TargetWidth, $TargetHeight, [System.Drawing.Imaging.PixelFormat]::Format24bppRgb)
            $dstBmp.SetResolution(96.0, 96.0)

            $g = [System.Drawing.Graphics]::FromImage($dstBmp)
            $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
            $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
            $g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
            $g.CompositingQuality = [System.Drawing.Drawing2D.CompositingQuality]::HighQuality

            $dstRect = New-Object System.Drawing.Rectangle(0, 0, $TargetWidth, $TargetHeight)
            $g.DrawImage($origImg, $dstRect, $srcRect, [System.Drawing.GraphicsUnit]::Pixel)
            $g.Dispose()

            $outMs = New-Object System.IO.MemoryStream
            $jpegCodec = [System.Drawing.Imaging.ImageCodecInfo]::GetImageEncoders() | Where-Object { $_.MimeType -eq "image/jpeg" }
            $encParams = New-Object System.Drawing.Imaging.EncoderParameters(1)
            $encParams.Param[0] = New-Object System.Drawing.Imaging.EncoderParameter([System.Drawing.Imaging.Encoder]::Quality, [long]$JpegQuality)

            $dstBmp.Save($outMs, $jpegCodec, $encParams)
            $processedBytes = $outMs.ToArray()
            $processedWidth = $TargetWidth
            $processedHeight = $TargetHeight
            $processedSize = $processedBytes.Length

            $outMs.Close()
            $dstBmp.Dispose()
        } catch {
            $processedBytes = $bytes
        }
    } else {
        $processedBytes = $bytes
    }

    if ($origImg) { $origImg.Dispose() }
    if ($inMs) { $inMs.Close() }

    if ($PassThruBytes) {
        return ,$processedBytes
    }

    $recommendation = if ($isAdCompliant) {
        "Compliant: Meets Active Directory thumbnailPhoto guidelines (<=96x96, <100 KB)."
    } else {
        "Non-compliant: Resizing/cropping to 96x96 pixels JPEG (<100 KB) recommended for AD thumbnailPhoto."
    }

    return [PSCustomObject]@{
        IsValid              = $isValid
        Format               = $format
        Width                = $width
        Height               = $height
        SizeBytes            = $sizeBytes
        SizeKB               = $sizeKB
        IsAdCompliant        = $isAdCompliant
        Recommendation       = $recommendation
        ErrorMessage         = $errorMessage
        ProcessedBytes       = $processedBytes
        ProcessedWidth       = $processedWidth
        ProcessedHeight      = $processedHeight
        ProcessedSizeBytes   = $processedSize
        ProcessedSizeKB      = [Math]::Round($processedSize / 1KB, 2)
    }
}

Export-ModuleMember -Function `
    Format-BinaryHexDump, `
    Convert-HexStringToByteArray, `
    Get-X509CertificateMetadata, `
    Convert-GeneralizedTimeToDateTime, `
    Convert-DateTimeToGeneralizedTime, `
    Convert-FileTimeToDateTime, `
    Convert-DateTimeToFileTime, `
    New-LdapPasswordHash, `
    Test-LdapPasswordHash, `
    Format-ThumbnailPhotoImage
