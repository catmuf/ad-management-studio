<#
.SYNOPSIS
    Unit and integration test suite for SpecializedEditorService and SpecializedEditorDialog.
.DESCRIPTION
    Validates Apache Directory Studio parity:
    - Format-BinaryHexDump and Convert-HexStringToByteArray
    - Get-X509CertificateMetadata with X509Chain revocation checking
    - Convert-GeneralizedTimeToDateTime & Convert-DateTimeToGeneralizedTime
    - Convert-FileTimeToDateTime & Convert-DateTimeToFileTime
    - New-LdapPasswordHash & Test-LdapPasswordHash
    - Format-ThumbnailPhotoImage inspection, validation, and 96x96 px resizing
    - Views/SpecializedEditorDialog.xaml parsing and TabControl structure verification
#>

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingBrokenHashAlgorithms', '')]
[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectRoot = Split-Path -Parent $scriptDir

# Assemblies required for WPF & Cryptography
Add-Type -AssemblyName PresentationFramework -ErrorAction SilentlyContinue
Add-Type -AssemblyName PresentationCore -ErrorAction SilentlyContinue
Add-Type -AssemblyName WindowsBase -ErrorAction SilentlyContinue
Add-Type -AssemblyName System.Drawing -ErrorAction SilentlyContinue
Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue

# Import Service Module
$modulePath = Join-Path $projectRoot "Modules\SpecializedEditorService.psm1"
if (-not (Test-Path $modulePath)) {
    Write-Error "SpecializedEditorService module not found at: $modulePath"
    exit 1
}

Import-Module $modulePath -Force

$passCount = 0
$failCount = 0

function Assert-Test {
    param(
        [string]$Name,
        [scriptblock]$TestBlock
    )

    try {
        $result = & $TestBlock
        if ($result -eq $true) {
            Write-Host "  [PASS] $Name" -ForegroundColor Green
            $script:passCount++
        } else {
            Write-Host "  [FAIL] $Name (Assertion evaluated to false)" -ForegroundColor Red
            $script:failCount++
        }
    } catch {
        Write-Host "  [FAIL] $Name (Exception: $($_.Exception.Message))" -ForegroundColor Red
        $script:failCount++
    }
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Running SpecializedEditorService & Dialog Test Suite      " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# -----------------------------------------------------------------------------
# 1. Binary Hex Dump & Converter Tests
# -----------------------------------------------------------------------------
Write-Host "`n[1/7] Testing Format-BinaryHexDump & Convert-HexStringToByteArray..." -ForegroundColor Yellow

Assert-Test "Format-BinaryHexDump handles empty or null input" {
    $r1 = Format-BinaryHexDump -Bytes @()
    $r2 = Format-BinaryHexDump -Bytes $null -AsText
    ($r1.Count -eq 0) -and ($r2 -eq "")
}

Assert-Test "Format-BinaryHexDump produces correct structured rows & offsets" {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes("0123456789ABCDEF0123456789ABCDEFEXTRA")
    $rows = Format-BinaryHexDump -Bytes $bytes
    ($rows.Count -eq 3) -and 
    ($rows[0].Offset -eq "00000000") -and 
    ($rows[1].Offset -eq "00000010") -and 
    ($rows[2].Offset -eq "00000020") -and 
    ($rows[0].Ascii -eq "0123456789ABCDEF") -and 
    ($rows[2].Ascii -eq "EXTRA")
}

Assert-Test "Format-BinaryHexDump replaces non-printable characters with '.'" {
    $raw = [byte[]]@(0x00, 0x01, 0x1F, 0x41, 0x42, 0x7F, 0x80, 0xFF)
    $rows = Format-BinaryHexDump -Bytes $raw
    $rows[0].Ascii -eq "...AB..."
}

Assert-Test "Format-BinaryHexDump -AsText returns multiline string" {
    $raw = [byte[]]@(0x41, 0x42, 0x43, 0x44)
    $text = Format-BinaryHexDump -Bytes $raw -AsText
    $text -like "00000000  41 42 43 44*|ABCD|"
}

Assert-Test "Convert-HexStringToByteArray parses contiguous, spaced, and hyphenated hex" {
    $b1 = Convert-HexStringToByteArray -HexString "48656C6C6F"
    $b2 = Convert-HexStringToByteArray -HexString "48 65 6c 6C 6F"
    $b3 = Convert-HexStringToByteArray -HexString "48-65-6C-6C-6F"
    $b4 = Convert-HexStringToByteArray -HexString "0x48, 0x65, 0x6C, 0x6C, 0x6F"

    $s1 = [System.Text.Encoding]::UTF8.GetString($b1)
    $s2 = [System.Text.Encoding]::UTF8.GetString($b2)
    $s3 = [System.Text.Encoding]::UTF8.GetString($b3)
    $s4 = [System.Text.Encoding]::UTF8.GetString($b4)

    ($s1 -eq "Hello") -and ($s2 -eq "Hello") -and ($s3 -eq "Hello") -and ($s4 -eq "Hello")
}

Assert-Test "Convert-HexStringToByteArray strips offset and pipe ASCII dumps" {
    $dumpLine = "00000000  48 65 6C 6C 6F 21  |Hello!|"
    $parsed = Convert-HexStringToByteArray -HexString $dumpLine
    [System.Text.Encoding]::UTF8.GetString($parsed) -eq "Hello!"
}

Assert-Test "Convert-HexStringToByteArray roundtrips with Format-BinaryHexDump" {
    $orig = [System.Text.Encoding]::UTF8.GetBytes("ApacheDirectoryStudioParityRoundtripTest!#@123")
    $dump = Format-BinaryHexDump -Bytes $orig
    $hexStream = ($dump.Hex -join " ")
    $restored = Convert-HexStringToByteArray -HexString $hexStream
    [System.Text.Encoding]::UTF8.GetString($restored) -eq [System.Text.Encoding]::UTF8.GetString($orig)
}

Assert-Test "Convert-HexStringToByteArray validates invalid chars and odd lengths" {
    $threwInvalid = $false
    try { Convert-HexStringToByteArray -HexString "48656Z" } catch { $threwInvalid = $true }

    $threwOdd = $false
    try { Convert-HexStringToByteArray -HexString "48656" } catch { $threwOdd = $true }

    $threwInvalid -and $threwOdd
}

# -----------------------------------------------------------------------------
# 2. X.509 Certificate Metadata & Revocation Tests
# -----------------------------------------------------------------------------
Write-Host "`n[2/7] Testing Get-X509CertificateMetadata..." -ForegroundColor Yellow

# Generate an in-memory X.509 Certificate with SAN and KeyUsage for testing
$testRsa = [System.Security.Cryptography.RSA]::Create(2048)
$certReq = New-Object System.Security.Cryptography.X509Certificates.CertificateRequest(
    "CN=Directory Test Subject, OU=Identity, DC=contoso, DC=local",
    $testRsa,
    [System.Security.Cryptography.HashAlgorithmName]::SHA256,
    [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
)

$sanBuilder = New-Object System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder
$sanBuilder.AddDnsName("ldap.contoso.local")
$sanBuilder.AddEmailAddress("admin@contoso.local")
$certReq.CertificateExtensions.Add($sanBuilder.Build())

$ku = New-Object System.Security.Cryptography.X509Certificates.X509KeyUsageExtension(
    ([System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature -bor 
     [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyEncipherment),
    $false
)
$certReq.CertificateExtensions.Add($ku)

$testCert = $certReq.CreateSelfSigned([DateTimeOffset]::Now.AddDays(-2), [DateTimeOffset]::Now.AddDays(180))

Assert-Test "Get-X509CertificateMetadata extracts Subject, Issuer, and SerialNumber" {
    $meta = Get-X509CertificateMetadata -CertificateInput $testCert.RawData
    ($meta.SubjectCN -eq "Directory Test Subject") -and 
    ($meta.IssuerCN -eq "Directory Test Subject") -and 
    (-not [string]::IsNullOrEmpty($meta.SerialNumber)) -and
    ($meta.IsSelfSigned -eq $true)
}

Assert-Test "Get-X509CertificateMetadata extracts Validity and Expiration" {
    $meta = Get-X509CertificateMetadata -CertificateInput $testCert
    ($meta.IsValidNow -eq $true) -and ($meta.DaysUntilExpiration -gt 170)
}

Assert-Test "Get-X509CertificateMetadata extracts SHA-1 and SHA-256 Thumbprints" {
    $meta = Get-X509CertificateMetadata -CertificateInput $testCert.RawData
    ($meta.Thumbprint -eq $testCert.Thumbprint) -and 
    ($meta.ThumbprintSHA256.Length -eq 64)
}

Assert-Test "Get-X509CertificateMetadata extracts SAN (Subject Alternative Names)" {
    $meta = Get-X509CertificateMetadata -CertificateInput $testCert
    ($meta.SubjectAlternativeNames -like "*ldap.contoso.local*") -and 
    ($meta.SubjectAlternativeNames -like "*admin@contoso.local*")
}

Assert-Test "Get-X509CertificateMetadata checks Revocation via X509Chain" {
    $meta = Get-X509CertificateMetadata -CertificateInput $testCert -CheckRevocation
    (-not [string]::IsNullOrEmpty($meta.RevocationStatus)) -and 
    ($null -ne $meta.ChainStatuses)
}

Assert-Test "Get-X509CertificateMetadata accepts Base64 encoded certificate" {
    $b64 = [Convert]::ToBase64String($testCert.RawData)
    $meta = Get-X509CertificateMetadata -CertificateInput $b64
    $meta.SubjectCN -eq "Directory Test Subject"
}

# -----------------------------------------------------------------------------
# 3. LDAP GeneralizedTime Converter Tests
# -----------------------------------------------------------------------------
Write-Host "`n[3/7] Testing GeneralizedTime Converters..." -ForegroundColor Yellow

Assert-Test "Convert-GeneralizedTimeToDateTime parses standard LDAP GeneralizedTime" {
    $dt = Convert-GeneralizedTimeToDateTime -GeneralizedTime "20261014082416.0Z"
    ($dt.Year -eq 2026) -and ($dt.Month -eq 10) -and ($dt.Day -eq 14) -and 
    ($dt.Hour -eq 8) -and ($dt.Minute -eq 24) -and ($dt.Second -eq 16) -and 
    ($dt.Kind -eq [System.DateTimeKind]::Utc)
}

Assert-Test "Convert-GeneralizedTimeToDateTime parses GeneralizedTime without fraction" {
    $dt = Convert-GeneralizedTimeToDateTime -GeneralizedTime "20261014082416Z"
    ($dt.Year -eq 2026) -and ($dt.Hour -eq 8) -and ($dt.Second -eq 16)
}

Assert-Test "Convert-GeneralizedTimeToDateTime handles timezone offset (+0200)" {
    $dt = Convert-GeneralizedTimeToDateTime -GeneralizedTime "20261014102416+0200"
    # 10:24:16 +0200 should be 08:24:16 UTC
    ($dt.Year -eq 2026) -and ($dt.Hour -eq 8) -and ($dt.Minute -eq 24)
}

Assert-Test "Convert-DateTimeToGeneralizedTime produces correct LDAP string" {
    $dt = New-Object DateTime(2026, 10, 14, 8, 24, 16, [System.DateTimeKind]::Utc)
    $gt = Convert-DateTimeToGeneralizedTime -DateTime $dt
    $gt -eq "20261014082416.0Z"
}

Assert-Test "GeneralizedTime roundtrips losslessly" {
    $original = New-Object DateTime(2026, 5, 20, 14, 30, 45, [System.DateTimeKind]::Utc)
    $gt = Convert-DateTimeToGeneralizedTime -DateTime $original
    $restored = Convert-GeneralizedTimeToDateTime -GeneralizedTime $gt
    $original -eq $restored
}

# -----------------------------------------------------------------------------
# 4. Windows FileTime Converter Tests
# -----------------------------------------------------------------------------
Write-Host "`n[4/7] Testing FileTime Converters..." -ForegroundColor Yellow

Assert-Test "Convert-FileTimeToDateTime parses 64-bit integer FileTime" {
    $ft = 133732622560000000L
    $dt = Convert-FileTimeToDateTime -FileTime $ft
    ($dt.Year -eq 2024) -and ($dt.Month -eq 10) -and ($dt.Day -eq 13)
}

Assert-Test "Convert-DateTimeToFileTime produces accurate 64-bit FileTime" {
    $dt = New-Object DateTime(2024, 10, 13, 3, 4, 16, [System.DateTimeKind]::Utc)
    $ft = Convert-DateTimeToFileTime -DateTime $dt
    $ft -eq 133732622560000000L
}

Assert-Test "Convert-FileTimeToDateTime handles special values 0 and Never Expires" {
    $epoch = Convert-FileTimeToDateTime -FileTime 0L
    $never = Convert-FileTimeToDateTime -FileTime 9223372036854775807L

    ($epoch.Year -eq 1601) -and ($never -eq [DateTime]::MaxValue)
}

Assert-Test "FileTime roundtrips losslessly" {
    $now = [DateTime]::UtcNow
    $ft = Convert-DateTimeToFileTime -DateTime $now
    $restored = Convert-FileTimeToDateTime -FileTime $ft
    # FileTime precision is 100ns ticks, compare ticks
    [Math]::Abs(($now - $restored).TotalMilliseconds) -lt 1.0
}

# -----------------------------------------------------------------------------
# 5. LDAP Password Hashing & Verification Tests
# -----------------------------------------------------------------------------
Write-Host "`n[5/7] Testing New-LdapPasswordHash & Test-LdapPasswordHash..." -ForegroundColor Yellow

Assert-Test "New-LdapPasswordHash generates valid SSHA hash with prefix" {
    $hash = New-LdapPasswordHash -Password "SecretPass123!" -Algorithm SSHA
    $hash -like "{SSHA}*"
}

Assert-Test "New-LdapPasswordHash generates valid SSHA-512 hash with prefix" {
    $hash = New-LdapPasswordHash -Password "SecretPass123!" -Algorithm SSHA-512
    $hash -like "{SSHA512}*"
}

Assert-Test "New-LdapPasswordHash generates valid SSHA-256 hash with prefix" {
    $hash = New-LdapPasswordHash -Password "SecretPass123!" -Algorithm SSHA-256
    $hash -like "{SSHA256}*"
}

Assert-Test "New-LdapPasswordHash generates valid SMD5 hash with prefix" {
    $hash = New-LdapPasswordHash -Password "SecretPass123!" -Algorithm SMD5
    $hash -like "{SMD5}*"
}

Assert-Test "New-LdapPasswordHash generates unsalted SHA-256 and MD5 hashes" {
    $hSha256 = New-LdapPasswordHash -Password "SecretPass123!" -Algorithm SHA-256 -NoSalt
    $hMd5 = New-LdapPasswordHash -Password "SecretPass123!" -Algorithm MD5 -NoSalt

    ($hSha256 -like "{SHA256}*") -and ($hMd5 -like "{MD5}*")
}

Assert-Test "Test-LdapPasswordHash verifies matching passwords across all algorithms" {
    $password = "DirectoryStudio#2026!"
    $allOk = $true

    foreach ($algo in @("SSHA", "SSHA-512", "SSHA-256", "SMD5", "SHA-256", "MD5")) {
        $hash = New-LdapPasswordHash -Password $password -Algorithm $algo
        $match = Test-LdapPasswordHash -Password $password -Hash $hash
        if (-not $match) { $allOk = $false }
    }

    $allOk
}

Assert-Test "Test-LdapPasswordHash rejects incorrect passwords" {
    $password = "CorrectPassword123"
    $wrongPassword = "WrongPassword456"
    $allRejected = $true

    foreach ($algo in @("SSHA", "SSHA-512", "SSHA-256", "SMD5")) {
        $hash = New-LdapPasswordHash -Password $password -Algorithm $algo
        $match = Test-LdapPasswordHash -Password $wrongPassword -Hash $hash
        if ($match) { $allRejected = $false }
    }

    $allRejected
}

# -----------------------------------------------------------------------------
# 6. Thumbnail Photo & Image Inspector Tests
# -----------------------------------------------------------------------------
Write-Host "`n[6/7] Testing Format-ThumbnailPhotoImage..." -ForegroundColor Yellow

# Create test 250x180 PNG image
$bmp = New-Object System.Drawing.Bitmap 250, 180
$ms = New-Object System.IO.MemoryStream
$bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
$pngBytes = $ms.ToArray()
$ms.Close()
$bmp.Dispose()

Assert-Test "Format-ThumbnailPhotoImage detects format and evaluates non-compliance" {
    $info = Format-ThumbnailPhotoImage -ImageInput $pngBytes
    ($info.IsValid -eq $true) -and 
    ($info.Format -eq "PNG") -and 
    ($info.Width -eq 250) -and 
    ($info.Height -eq 180) -and 
    ($info.IsAdCompliant -eq $false)
}

Assert-Test "Format-ThumbnailPhotoImage resizes and crops image to AD 96x96 JPEG" {
    $info = Format-ThumbnailPhotoImage -ImageInput $pngBytes -Resize
    ($info.ProcessedWidth -eq 96) -and 
    ($info.ProcessedHeight -eq 96) -and 
    ($info.ProcessedSizeBytes -lt 102400) -and 
    ($info.ProcessedBytes.Length -gt 0)
}

# Create test 96x96 JPEG image
$bmp96 = New-Object System.Drawing.Bitmap 96, 96
$ms96 = New-Object System.IO.MemoryStream
$bmp96.Save($ms96, [System.Drawing.Imaging.ImageFormat]::Jpeg)
$jpg96Bytes = $ms96.ToArray()
$ms96.Close()
$bmp96.Dispose()

Assert-Test "Format-ThumbnailPhotoImage recognizes already compliant 96x96 JPEG" {
    $info = Format-ThumbnailPhotoImage -ImageInput $jpg96Bytes
    ($info.IsAdCompliant -eq $true) -and 
    ($info.Format -eq "JPEG") -and 
    ($info.Width -eq 96) -and 
    ($info.Height -eq 96)
}

# -----------------------------------------------------------------------------
# 7. XAML Dialog Parsing & TabControl Structure Tests
# -----------------------------------------------------------------------------
Write-Host "`n[7/7] Testing Views/SpecializedEditorDialog.xaml Structure & Parsing..." -ForegroundColor Yellow

$xamlPath = Join-Path $projectRoot "Views\SpecializedEditorDialog.xaml"

Assert-Test "Views/SpecializedEditorDialog.xaml exists" {
    Test-Path $xamlPath
}

Assert-Test "SpecializedEditorDialog.xaml parses successfully via XamlReader" {
    $xamlContent = [System.IO.File]::ReadAllText($xamlPath, [System.Text.Encoding]::UTF8)
    $parsedWindow = [System.Windows.Markup.XamlReader]::Parse($xamlContent)
    $null -ne $parsedWindow -and ($parsedWindow -is [System.Windows.Window])
}

Assert-Test "SpecializedEditorDialog contains TabControl with all 5 specialized tabs" {
    $xamlContent = [System.IO.File]::ReadAllText($xamlPath, [System.Text.Encoding]::UTF8)
    $window = [System.Windows.Markup.XamlReader]::Parse($xamlContent)

    $tabCtrl = $window.FindName("TabControlEditors")
    $hasTabCtrl = ($null -ne $tabCtrl)

    $tab1 = $window.FindName("TabHexEditor")
    $tab2 = $window.FindName("TabCertViewer")
    $tab3 = $window.FindName("TabPhotoViewer")
    $tab4 = $window.FindName("TabDatePicker")
    $tab5 = $window.FindName("TabPasswordHash")

    $hasTabCtrl -and 
    ($null -ne $tab1) -and 
    ($null -ne $tab2) -and 
    ($null -ne $tab3) -and 
    ($null -ne $tab4) -and 
    ($null -ne $tab5)
}

Assert-Test "SpecializedEditorDialog contains all required interactive controls" {
    $xamlContent = [System.IO.File]::ReadAllText($xamlPath, [System.Text.Encoding]::UTF8)
    $window = [System.Windows.Markup.XamlReader]::Parse($xamlContent)

    # Key controls from Tab 1 to 5
    $cHex = $window.FindName("TxtHexDumpView")
    $cHexInput = $window.FindName("TxtHexRawInput")
    $cCertSubject = $window.FindName("TxtCertSubject")
    $cCertRev = $window.FindName("BtnCertRevocation")
    $cPhoto = $window.FindName("ImgPhotoPreview")
    $cPhotoResize = $window.FindName("BtnPhotoResize")
    $cDate = $window.FindName("DpDate")
    $cGt = $window.FindName("TxtGeneralizedTime")
    $cFt = $window.FindName("TxtFileTime")
    $cPwd = $window.FindName("TxtPasswordPlain")
    $cAlgo = $window.FindName("CmbPasswordAlgorithm")
    $cVerify = $window.FindName("BtnVerifyPassword")
    $cApply = $window.FindName("BtnApplyValue")

    ($null -ne $cHex) -and ($null -ne $cHexInput) -and 
    ($null -ne $cCertSubject) -and ($null -ne $cCertRev) -and 
    ($null -ne $cPhoto) -and ($null -ne $cPhotoResize) -and 
    ($null -ne $cDate) -and ($null -ne $cGt) -and ($null -ne $cFt) -and 
    ($null -ne $cPwd) -and ($null -ne $cAlgo) -and ($null -ne $cVerify) -and 
    ($null -ne $cApply)
}

# -----------------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------------
Write-Host "`n==========================================================" -ForegroundColor Cyan
Write-Host " Test Execution Completed" -ForegroundColor Cyan
Write-Host " Passed: $script:passCount" -ForegroundColor Green
Write-Host " Failed: $script:failCount" -ForegroundColor $(if ($script:failCount -eq 0) { "Green" } else { "Red" })
Write-Host "==========================================================" -ForegroundColor Cyan

if ($script:failCount -gt 0) {
    exit 1
} else {
    exit 0
}
