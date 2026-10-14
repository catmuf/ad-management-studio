<#
.SYNOPSIS
    ScimFilterService module for Active Directory Management Studio.
.DESCRIPTION
    Provides bidirectional translation between SCIM 2.0 filter expressions (RFC 7644 Section 3.4.2.2)
    and RFC 4515 LDAP search filters, as well as strict SCIM 2.0 syntax validation and diagnostics.
#>

$script:DefaultScimToLdapMap = @{
    'userName'                                                           = 'sAMAccountName'
    'id'                                                                 = 'objectGUID'
    'externalId'                                                         = 'employeeID'
    'name.familyName'                                                    = 'sn'
    'name.givenName'                                                     = 'givenName'
    'name.middleName'                                                    = 'middleName'
    'name.honorificPrefix'                                               = 'personalTitle'
    'name.formatted'                                                     = 'displayName'
    'familyName'                                                         = 'sn'
    'givenName'                                                          = 'givenName'
    'middleName'                                                         = 'middleName'
    'displayName'                                                        = 'displayName'
    'nickName'                                                           = 'mailNickname'
    'profileUrl'                                                         = 'wWWHomePage'
    'title'                                                              = 'title'
    'userType'                                                           = 'employeeType'
    'preferredLanguage'                                                  = 'preferredLanguage'
    'department'                                                         = 'department'
    'company'                                                            = 'company'
    'organization'                                                       = 'company'
    'division'                                                           = 'division'
    'costCenter'                                                         = 'costCenter'
    'employeeNumber'                                                     = 'employeeNumber'
    'manager'                                                            = 'manager'
    'manager.value'                                                      = 'manager'
    'mail'                                                               = 'mail'
    'emails'                                                             = 'mail'
    'emails.value'                                                       = 'mail'
    'telephoneNumber'                                                    = 'telephoneNumber'
    'phoneNumbers'                                                       = 'telephoneNumber'
    'phoneNumbers.value'                                                 = 'telephoneNumber'
    'streetAddress'                                                      = 'streetAddress'
    'locality'                                                           = 'l'
    'region'                                                             = 'st'
    'postalCode'                                                         = 'postalCode'
    'country'                                                            = 'c'
    'addresses.streetAddress'                                            = 'streetAddress'
    'addresses.locality'                                                 = 'l'
    'addresses.region'                                                   = 'st'
    'addresses.postalCode'                                               = 'postalCode'
    'addresses.country'                                                  = 'c'
    'members'                                                            = 'member'
    'members.value'                                                      = 'member'
    'meta.created'                                                       = 'whenCreated'
    'meta.lastModified'                                                  = 'whenChanged'
    'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:employeeNumber' = 'employeeNumber'
    'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:costCenter'     = 'costCenter'
    'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:organization'   = 'company'
    'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:division'       = 'division'
    'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department'     = 'department'
    'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:manager'        = 'manager'
    'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:manager.value'  = 'manager'
}

$script:DefaultLdapToScimMap = @{
    'samaccountname'          = 'userName'
    'userprincipalname'       = 'userName'
    'objectguid'              = 'id'
    'employeeid'              = 'externalId'
    'sn'                      = 'name.familyName'
    'givenname'               = 'name.givenName'
    'middlename'              = 'name.middleName'
    'displayname'             = 'displayName'
    'mailnickname'            = 'nickName'
    'title'                   = 'title'
    'employeetype'            = 'userType'
    'department'              = 'department'
    'company'                 = 'organization'
    'division'                = 'division'
    'costcenter'              = 'costCenter'
    'employeenumber'          = 'employeeNumber'
    'manager'                 = 'manager'
    'mail'                    = 'emails'
    'telephonenumber'         = 'phoneNumbers.value'
    'mobile'                  = 'phoneNumbers.value'
    'streetaddress'           = 'addresses.streetAddress'
    'l'                       = 'addresses.locality'
    'st'                      = 'addresses.region'
    'postalcode'              = 'addresses.postalCode'
    'c'                       = 'addresses.country'
    'co'                      = 'addresses.country'
    'member'                  = 'members.value'
    'whencreated'             = 'meta.created'
    'whenchanged'             = 'meta.lastModified'
}

function Tokenize-ScimFilter {
    [CmdletBinding()]
    param (
        [string]$Filter
    )

    $tokens = [System.Collections.Generic.List[object]]::new()
    if ([string]::IsNullOrWhiteSpace($Filter)) {
        return $tokens
    }

    $len = $Filter.Length
    $i = 0

    while ($i -lt $len) {
        $ch = $Filter[$i]

        # Whitespace
        if ([char]::IsWhiteSpace($ch)) {
            $i++
            continue
        }

        # Parentheses
        if ($ch -eq '(') {
            $tokens.Add([PSCustomObject]@{ Type = 'LPAREN'; Value = '('; Position = $i })
            $i++
            continue
        }
        if ($ch -eq ')') {
            $tokens.Add([PSCustomObject]@{ Type = 'RPAREN'; Value = ')'; Position = $i })
            $i++
            continue
        }

        # Brackets
        if ($ch -eq '[') {
            $tokens.Add([PSCustomObject]@{ Type = 'LBRACKET'; Value = '['; Position = $i })
            $i++
            continue
        }
        if ($ch -eq ']') {
            $tokens.Add([PSCustomObject]@{ Type = 'RBRACKET'; Value = ']'; Position = $i })
            $i++
            continue
        }

        # String literal: "..."
        if ($ch -eq '"') {
            $startPos = $i
            $i++ # skip open quote
            $sb = New-Object System.Text.StringBuilder
            $closed = $false

            while ($i -lt $len) {
                $c = $Filter[$i]
                if ($c -eq '\') {
                    if ($i + 1 -lt $len) {
                        $next = $Filter[$i + 1]
                        if ($next -eq '"' -or $next -eq '\') {
                            [void]$sb.Append($next)
                            $i += 2
                            continue
                        }
                    }
                    [void]$sb.Append($c)
                    $i++
                }
                elseif ($c -eq '"') {
                    $closed = $true
                    $i++ # skip closing quote
                    break
                }
                else {
                    [void]$sb.Append($c)
                    $i++
                }
            }

            if (-not $closed) {
                throw "Unterminated string literal starting at position $startPos."
            }

            $tokens.Add([PSCustomObject]@{
                Type     = 'STRING'
                Value    = $sb.ToString()
                Position = $startPos
            })
            continue
        }

        # Words, Operators, Identifiers, Numbers
        $startPos = $i
        $sbWord = New-Object System.Text.StringBuilder

        while ($i -lt $len) {
            $c = $Filter[$i]
            if ([char]::IsWhiteSpace($c) -or $c -eq '(' -or $c -eq ')' -or $c -eq '[' -or $c -eq ']' -or $c -eq '"') {
                break
            }
            [void]$sbWord.Append($c)
            $i++
        }

        $word = $sbWord.ToString()
        $wordLower = $word.ToLowerInvariant()

        if ($wordLower -eq 'and') {
            $tokens.Add([PSCustomObject]@{ Type = 'AND'; Value = 'and'; Position = $startPos })
        }
        elseif ($wordLower -eq 'or') {
            $tokens.Add([PSCustomObject]@{ Type = 'OR'; Value = 'or'; Position = $startPos })
        }
        elseif ($wordLower -eq 'not') {
            $tokens.Add([PSCustomObject]@{ Type = 'NOT'; Value = 'not'; Position = $startPos })
        }
        elseif ($wordLower -eq 'pr') {
            $tokens.Add([PSCustomObject]@{ Type = 'PR'; Value = 'pr'; Position = $startPos })
        }
        elseif ($wordLower -in @('eq', 'ne', 'co', 'sw', 'ew', 'gt', 'ge', 'lt', 'le')) {
            $tokens.Add([PSCustomObject]@{ Type = 'COMPARE'; Value = $wordLower; Position = $startPos })
        }
        elseif ($wordLower -eq 'true') {
            $tokens.Add([PSCustomObject]@{ Type = 'BOOLEAN'; Value = $true; Position = $startPos })
        }
        elseif ($wordLower -eq 'false') {
            $tokens.Add([PSCustomObject]@{ Type = 'BOOLEAN'; Value = $false; Position = $startPos })
        }
        elseif ($wordLower -eq 'null') {
            $tokens.Add([PSCustomObject]@{ Type = 'NULL'; Value = $null; Position = $startPos })
        }
        else {
            # Check if number
            $numVal = 0
            $doubleVal = 0.0
            if ([int]::TryParse($word, [ref]$numVal)) {
                $tokens.Add([PSCustomObject]@{ Type = 'NUMBER'; Value = $numVal; Position = $startPos })
            }
            elseif ([double]::TryParse($word, [System.Globalization.NumberStyles]::Any, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$doubleVal)) {
                $tokens.Add([PSCustomObject]@{ Type = 'NUMBER'; Value = $doubleVal; Position = $startPos })
            }
            else {
                # Attribute name or path
                $tokens.Add([PSCustomObject]@{ Type = 'ATTR'; Value = $word; Position = $startPos })
            }
        }
    }

    return $tokens
}

function Parse-ScimTokens {
    [CmdletBinding()]
    param (
        [System.Collections.Generic.List[object]]$Tokens
    )

    $state = [PSCustomObject]@{
        Index  = 0
        Tokens = $Tokens
        Count  = $Tokens.Count
    }

    function Peek-Token ($s) {
        if ($s.Index -lt $s.Count) { return $s.Tokens[$s.Index] }
        return $null
    }

    function Consume-Token ($s) {
        if ($s.Index -lt $s.Count) {
            $t = $s.Tokens[$s.Index]
            $s.Index++
            return $t
        }
        return $null
    }

    function Expect-Token ($s, [string]$ExpectedType, [string]$Description) {
        $tok = Consume-Token $s
        if ($null -eq $tok -or $tok.Type -ne $ExpectedType) {
            $pos = if ($tok) { $tok.Position } else { "end of filter" }
            $found = if ($tok) { "'$($tok.Value)' ($($tok.Type))" } else { "end of filter" }
            throw "Expected $Description at position $pos, but found $found."
        }
        return $tok
    }

    function Parse-OrExpr ($s) {
        $left = Parse-AndExpr $s
        $next = Peek-Token $s
        while ($null -ne $next -and $next.Type -eq 'OR') {
            [void](Consume-Token $s)
            $right = Parse-AndExpr $s
            $left = [PSCustomObject]@{
                Type  = 'Or'
                Left  = $left
                Right = $right
            }
            $next = Peek-Token $s
        }
        return $left
    }

    function Parse-AndExpr ($s) {
        $left = Parse-NotExpr $s
        $next = Peek-Token $s
        while ($null -ne $next -and $next.Type -eq 'AND') {
            [void](Consume-Token $s)
            $right = Parse-NotExpr $s
            $left = [PSCustomObject]@{
                Type  = 'And'
                Left  = $left
                Right = $right
            }
            $next = Peek-Token $s
        }
        return $left
    }

    function Parse-NotExpr ($s) {
        $tok = Peek-Token $s
        if ($null -ne $tok -and $tok.Type -eq 'NOT') {
            [void](Consume-Token $s)
            $child = Parse-PrimaryExpr $s
            return [PSCustomObject]@{
                Type  = 'Not'
                Child = $child
            }
        }
        return Parse-PrimaryExpr $s
    }

    function Parse-PrimaryExpr ($s) {
        $tok = Peek-Token $s
        if ($null -eq $tok) {
            throw "Unexpected end of filter expression."
        }

        # Parenthesized group
        if ($tok.Type -eq 'LPAREN') {
            [void](Consume-Token $s)
            $inner = Parse-OrExpr $s
            [void](Expect-Token $s 'RPAREN' "closing parenthesis ')'")
            return [PSCustomObject]@{
                Type  = 'Group'
                Child = $inner
            }
        }

        # Attribute or ValuePath
        if ($tok.Type -eq 'ATTR') {
            $attrTok = Consume-Token $s
            $attr = $attrTok.Value
            $next = Peek-Token $s

            if ($null -eq $next) {
                throw "Unexpected end of filter after attribute '$attr' at position $($attrTok.Position)."
            }

            # ValuePath: attr[subfilter]
            if ($next.Type -eq 'LBRACKET') {
                [void](Consume-Token $s)
                $subFilter = Parse-OrExpr $s
                [void](Expect-Token $s 'RBRACKET' "closing bracket ']'")
                return [PSCustomObject]@{
                    Type      = 'ValuePath'
                    Attribute = $attr
                    Filter    = $subFilter
                }
            }

            # Present operator: attr pr
            if ($next.Type -eq 'PR') {
                [void](Consume-Token $s)
                return [PSCustomObject]@{
                    Type      = 'Present'
                    Attribute = $attr
                }
            }

            # Comparison operator: attr op value
            if ($next.Type -eq 'COMPARE') {
                $opTok = Consume-Token $s
                $valTok = Consume-Token $s
                if ($null -eq $valTok) {
                    throw "Expected comparison value after operator '$($opTok.Value)' at position $($opTok.Position)."
                }
                if ($valTok.Type -notin @('STRING', 'NUMBER', 'BOOLEAN', 'NULL', 'ATTR')) {
                    throw "Invalid comparison value '$($valTok.Value)' of type $($valTok.Type) at position $($valTok.Position)."
                }
                return [PSCustomObject]@{
                    Type      = 'Comparison'
                    Attribute = $attr
                    Operator  = $opTok.Value
                    Value     = $valTok.Value
                    ValueType = $valTok.Type
                }
            }

            throw "Expected comparison operator (eq, ne, co, sw, ew, pr, gt, ge, lt, le) or value path '[...]' after attribute '$attr' at position $($next.Position), found '$($next.Value)'."
        }

        throw "Unexpected token '$($tok.Value)' ($($tok.Type)) at position $($tok.Position)."
    }

    $ast = Parse-OrExpr $state
    if ($state.Index -lt $state.Count) {
        $remaining = $state.Tokens[$state.Index]
        throw "Unexpected token '$($remaining.Value)' ($($remaining.Type)) at position $($remaining.Position) after complete expression."
    }

    return $ast
}

function Test-ScimFilterSyntax {
    <#
    .SYNOPSIS
        Validates SCIM 2.0 filter syntax according to RFC 7644 Section 3.4.2.2.
    .DESCRIPTION
        Returns an object detailing whether the filter is syntactically valid,
        along with precise error diagnostics and position offset if invalid.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false, Position = 0)]
        [string]$Filter
    )

    $result = [PSCustomObject]@{
        IsValid  = $false
        Error    = $null
        Position = -1
        Message  = ""
        Tokens   = $null
    }

    if ([string]::IsNullOrWhiteSpace($Filter)) {
        $result.Error = "SCIM filter expression cannot be empty or whitespace."
        $result.Message = $result.Error
        $result.Position = 0
        return $result
    }

    try {
        $tokens = Tokenize-ScimFilter -Filter $Filter
        if ($tokens.Count -eq 0) {
            $result.Error = "No tokens parsed from filter expression."
            $result.Message = $result.Error
            $result.Position = 0
            return $result
        }
        $ast = Parse-ScimTokens -Tokens $tokens

        $result.IsValid = $true
        $result.Message = "Valid SCIM 2.0 filter expression."
        $result.Tokens  = @($tokens)
        return $result
    }
    catch {
        $errMsg = $_.Exception.Message
        $pos = -1
        if ($errMsg -match 'position\s+(\d+)') {
            $pos = [int]$matches[1]
        }
        $result.IsValid  = $false
        $result.Error    = $errMsg
        $result.Position = $pos
        $result.Message  = "Syntax error: $errMsg"
        return $result
    }
}

function Get-LdapAttributeName {
    param (
        [string]$ScimAttr,
        [hashtable]$CustomMapping
    )

    if ($CustomMapping -and $CustomMapping.ContainsKey($ScimAttr)) {
        return $CustomMapping[$ScimAttr]
    }

    # Match case-insensitively in default map
    foreach ($key in $script:DefaultScimToLdapMap.Keys) {
        if ($key -ieq $ScimAttr) {
            return $script:DefaultScimToLdapMap[$key]
        }
    }

    # If starts with enterprise URN prefix, strip and retry
    $prefix = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:"
    if ($ScimAttr.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        $shortAttr = $ScimAttr.Substring($prefix.Length)
        foreach ($key in $script:DefaultScimToLdapMap.Keys) {
            if ($key -ieq $shortAttr) {
                return $script:DefaultScimToLdapMap[$key]
            }
        }
        return $shortAttr
    }

    # If dot-notation e.g. name.familyName -> sn
    if ($ScimAttr -match '\.([^\.]+)$') {
        $leaf = $matches[1]
        foreach ($key in $script:DefaultScimToLdapMap.Keys) {
            if ($key -ieq $leaf) {
                return $script:DefaultScimToLdapMap[$key]
            }
        }
    }

    return $ScimAttr
}

function Escape-LdapFilterValue {
    param ([object]$Value)

    if ($null -eq $Value) { return "" }
    $str = "$Value"
    # RFC 4515 escape characters: \ * ( ) NUL
    $sb = New-Object System.Text.StringBuilder
    foreach ($char in $str.ToCharArray()) {
        switch ($char) {
            '\' { [void]$sb.Append('\5c') }
            '(' { [void]$sb.Append('\28') }
            ')' { [void]$sb.Append('\29') }
            default { [void]$sb.Append($char) }
        }
    }
    return $sb.ToString()
}

function Flatten-AstNodes {
    param (
        [object]$Node,
        [string]$TargetType
    )
    if ($null -eq $Node) { return @() }
    if ($Node.Type -eq $TargetType) {
        $left = @(Flatten-AstNodes -Node $Node.Left -TargetType $TargetType)
        $right = @(Flatten-AstNodes -Node $Node.Right -TargetType $TargetType)
        return @($left + $right)
    }
    return @($Node)
}

function Convert-AstNodeToLdap {
    param (
        [object]$Node,
        [hashtable]$Mapping
    )

    if ($null -eq $Node) { return "" }

    switch ($Node.Type) {
        'Group' {
            return (Convert-AstNodeToLdap -Node $Node.Child -Mapping $Mapping)
        }
        'Not' {
            # Check for special 'not (active eq true)' -> (userAccountControl:1.2.840.113556.1.4.803:=2)
            $inner = $Node.Child
            while ($inner.Type -eq 'Group') { $inner = $inner.Child }

            if ($inner.Type -eq 'Comparison' -and $inner.Attribute -ieq 'active') {
                $isTrue = ($inner.Value -eq $true -or "$($inner.Value)" -ieq 'true')
                if (($inner.Operator -ieq 'eq' -and $isTrue) -or ($inner.Operator -ieq 'ne' -and -not $isTrue)) {
                    return "(userAccountControl:1.2.840.113556.1.4.803:=2)"
                }
                else {
                    return "(! (userAccountControl:1.2.840.113556.1.4.803:=2))"
                }
            }

            if ($inner.Type -eq 'Present' -and $inner.Attribute -ieq 'active') {
                return "(!(userAccountControl=*))"
            }

            $childLdap = Convert-AstNodeToLdap -Node $Node.Child -Mapping $Mapping
            if ($childLdap -match '^\(!\s*(.+)\)$') {
                return "($($matches[1]))"
            }
            return "(!${childLdap})"
        }
        'Comparison' {
            if ($Node.Attribute -ieq 'active') {
                $isTrue = ($Node.Value -eq $true -or "$($Node.Value)" -ieq 'true')
                if (($Node.Operator -ieq 'eq' -and $isTrue) -or ($Node.Operator -ieq 'ne' -and -not $isTrue)) {
                    return "(! (userAccountControl:1.2.840.113556.1.4.803:=2))"
                }
                else {
                    return "(userAccountControl:1.2.840.113556.1.4.803:=2)"
                }
            }

            $ldapAttr = Get-LdapAttributeName -ScimAttr $Node.Attribute -CustomMapping $Mapping
            $val = Escape-LdapFilterValue $Node.Value

            switch ($Node.Operator.ToLowerInvariant()) {
                'eq' { return "(${ldapAttr}=${val})" }
                'ne' { return "(!(${ldapAttr}=${val}))" }
                'co' { return "(${ldapAttr}=*${val}*)" }
                'sw' { return "(${ldapAttr}=${val}*)" }
                'ew' { return "(${ldapAttr}=*${val})" }
                'ge' { return "(${ldapAttr}>=${val})" }
                'gt' { return "(${ldapAttr}>=${val})" }
                'le' { return "(${ldapAttr}<=${val})" }
                'lt' { return "(${ldapAttr}<=${val})" }
                default { throw "Unsupported comparison operator '$($Node.Operator)'." }
            }
        }
        'Present' {
            if ($Node.Attribute -ieq 'active') {
                return "(userAccountControl=*)"
            }
            $ldapAttr = Get-LdapAttributeName -ScimAttr $Node.Attribute -CustomMapping $Mapping
            return "(${ldapAttr}=*)"
        }
        'ValuePath' {
            # Examples:
            # emails[type eq "work" and value ew "@corp.com"] -> (&(mail=*@corp.com))
            $parent = $Node.Attribute.ToLowerInvariant()
            $inner = $Node.Filter

            $subNodes = if ($inner.Type -eq 'And') { Flatten-AstNodes -Node $inner -TargetType 'And' } else { @($inner) }
            
            $targetAttr = $null
            $conditions = [System.Collections.Generic.List[string]]::new()

            if ($parent -eq 'emails' -or $parent -eq 'email') {
                $targetAttr = 'mail'
                foreach ($sn in $subNodes) {
                    if ($sn.Type -eq 'Comparison') {
                        if ($sn.Attribute -ieq 'type') {
                            if ($sn.Value -ieq 'work') { $targetAttr = 'mail' }
                            elseif ($sn.Value -ieq 'home' -or $sn.Value -ieq 'other') { $targetAttr = 'otherMailbox' }
                        }
                        elseif ($sn.Attribute -ieq 'value') {
                            $val = Escape-LdapFilterValue $sn.Value
                            switch ($sn.Operator.ToLowerInvariant()) {
                                'eq' { $conditions.Add("${targetAttr}=${val}") }
                                'ne' { $conditions.Add("!(${targetAttr}=${val})") }
                                'co' { $conditions.Add("${targetAttr}=*${val}*") }
                                'sw' { $conditions.Add("${targetAttr}=${val}*") }
                                'ew' { $conditions.Add("${targetAttr}=*${val}") }
                            }
                        }
                    }
                    elseif ($sn.Type -eq 'Present' -and $sn.Attribute -ieq 'value') {
                        $conditions.Add("${targetAttr}=*")
                    }
                }
            }
            elseif ($parent -eq 'phonenumbers' -or $parent -eq 'phonenumber') {
                $targetAttr = 'telephoneNumber'
                foreach ($sn in $subNodes) {
                    if ($sn.Type -eq 'Comparison') {
                        if ($sn.Attribute -ieq 'type') {
                            if ($sn.Value -ieq 'mobile') { $targetAttr = 'mobile' }
                            elseif ($sn.Value -ieq 'fax') { $targetAttr = 'facsimileTelephoneNumber' }
                            elseif ($sn.Value -ieq 'work') { $targetAttr = 'telephoneNumber' }
                        }
                        elseif ($sn.Attribute -ieq 'value') {
                            $val = Escape-LdapFilterValue $sn.Value
                            switch ($sn.Operator.ToLowerInvariant()) {
                                'eq' { $conditions.Add("${targetAttr}=${val}") }
                                'ne' { $conditions.Add("!(${targetAttr}=${val})") }
                                'co' { $conditions.Add("${targetAttr}=*${val}*") }
                                'sw' { $conditions.Add("${targetAttr}=${val}*") }
                                'ew' { $conditions.Add("${targetAttr}=*${val}") }
                            }
                        }
                    }
                }
            }
            elseif ($parent -eq 'addresses' -or $parent -eq 'address') {
                foreach ($sn in $subNodes) {
                    if ($sn.Type -eq 'Comparison') {
                        $adAttr = Get-LdapAttributeName -ScimAttr "addresses.$($sn.Attribute)" -CustomMapping $Mapping
                        $val = Escape-LdapFilterValue $sn.Value
                        switch ($sn.Operator.ToLowerInvariant()) {
                            'eq' { $conditions.Add("${adAttr}=${val}") }
                            'ne' { $conditions.Add("!(${adAttr}=${val})") }
                            'co' { $conditions.Add("${adAttr}=*${val}*") }
                            'sw' { $conditions.Add("${adAttr}=${val}*") }
                            'ew' { $conditions.Add("${adAttr}=*${val}") }
                        }
                    }
                }
            }
            elseif ($parent -eq 'members') {
                foreach ($sn in $subNodes) {
                    if ($sn.Type -eq 'Comparison' -and ($sn.Attribute -ieq 'value' -or $sn.Attribute -ieq 'display')) {
                        $val = Escape-LdapFilterValue $sn.Value
                        $conditions.Add("member=${val}")
                    }
                }
            }

            if ($conditions.Count -eq 0) {
                return (Convert-AstNodeToLdap -Node $Node.Filter -Mapping $Mapping)
            }

            $filterParts = @($conditions | ForEach-Object { "($_)" })
            return "(&" + ($filterParts -join "") + ")"
        }
        'And' {
            $children = Flatten-AstNodes -Node $Node -TargetType 'And'
            $childLdap = @($children | ForEach-Object { Convert-AstNodeToLdap -Node $_ -Mapping $Mapping })
            return "(&" + ($childLdap -join "") + ")"
        }
        'Or' {
            $children = Flatten-AstNodes -Node $Node -TargetType 'Or'
            $childLdap = @($children | ForEach-Object { Convert-AstNodeToLdap -Node $_ -Mapping $Mapping })
            return "(|" + ($childLdap -join "") + ")"
        }
    }

    throw "Unrecognized AST node type '$($Node.Type)'."
}

function Convert-ScimFilterToLdapFilter {
    <#
    .SYNOPSIS
        Translates a SCIM 2.0 filter expression (RFC 7644 Section 3.4.2.2) to an RFC 4515 LDAP filter.
    .DESCRIPTION
        Converts SCIM comparison, present, logical, and nested value path expressions into
        Active Directory RFC 4515 LDAP search filters.
    .EXAMPLE
        Convert-ScimFilterToLdapFilter 'userName eq "john"'
        # Output: (sAMAccountName=john)
    .EXAMPLE
        Convert-ScimFilterToLdapFilter 'emails[type eq "work" and value ew "@corp.com"]'
        # Output: (&(mail=*@corp.com))
    .EXAMPLE
        Convert-ScimFilterToLdapFilter 'not (active eq true)'
        # Output: (userAccountControl:1.2.840.113556.1.4.803:=2)
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [string]$Filter,

        [hashtable]$AttributeMapping = @{}
    )

    if ([string]::IsNullOrWhiteSpace($Filter)) {
        throw "Filter expression cannot be empty."
    }

    $tokens = Tokenize-ScimFilter -Filter $Filter
    if ($tokens.Count -eq 0) {
        throw "No valid tokens found in filter '$Filter'."
    }

    $ast = Parse-ScimTokens -Tokens $tokens
    $ldap = Convert-AstNodeToLdap -Node $ast -Mapping $AttributeMapping
    return $ldap
}

# --- LDAP to SCIM Inverse Translation ---

function Split-LdapFilterComponents {
    param ([string]$InnerContent)

    $components = [System.Collections.Generic.List[string]]::new()
    $depth = 0
    $start = -1
    $len = $InnerContent.Length

    for ($i = 0; $i -lt $len; $i++) {
        $ch = $InnerContent[$i]
        if ($ch -eq '(') {
            if ($depth -eq 0) {
                $start = $i
            }
            $depth++
        }
        elseif ($ch -eq ')') {
            $depth--
            if ($depth -eq 0 -and $start -ge 0) {
                $components.Add($InnerContent.Substring($start, $i - $start + 1))
                $start = -1
            }
        }
    }

    return @($components)
}

function Parse-LdapFilterTree {
    param ([string]$Filter)

    $trimmed = $Filter.Trim()
    if (-not $trimmed.StartsWith('(') -or -not $trimmed.EndsWith(')')) {
        throw "Invalid LDAP filter: expression must start with '(' and end with ')'."
    }

    $inner = $trimmed.Substring(1, $trimmed.Length - 2).Trim()

    # Logical AND: (& (c1) (c2) ...)
    if ($inner.StartsWith('&')) {
        $rest = $inner.Substring(1).Trim()
        $subFilters = [string[]](Split-LdapFilterComponents -InnerContent $rest)
        $childAsts = [System.Collections.Generic.List[object]]::new()
        foreach ($sf in $subFilters) {
            $childAsts.Add((Parse-LdapFilterTree -Filter $sf))
        }
        return [PSCustomObject]@{
            Type     = 'And'
            Children = @($childAsts)
        }
    }

    # Logical OR: (| (c1) (c2) ...)
    if ($inner.StartsWith('|')) {
        $rest = $inner.Substring(1).Trim()
        $subFilters = [string[]](Split-LdapFilterComponents -InnerContent $rest)
        $childAsts = [System.Collections.Generic.List[object]]::new()
        foreach ($sf in $subFilters) {
            $childAsts.Add((Parse-LdapFilterTree -Filter $sf))
        }
        return [PSCustomObject]@{
            Type     = 'Or'
            Children = @($childAsts)
        }
    }

    # Logical NOT: (! (c1))
    if ($inner.StartsWith('!')) {
        $rest = $inner.Substring(1).Trim()
        $subFilters = [string[]](Split-LdapFilterComponents -InnerContent $rest)
        if ($subFilters.Length -eq 0) {
            throw "Invalid LDAP NOT filter: missing child filter."
        }
        return [PSCustomObject]@{
            Type  = 'Not'
            Child = (Parse-LdapFilterTree -Filter $subFilters[0])
        }
    }

    # Extensible matching rule, e.g. userAccountControl:1.2.840.113556.1.4.803:=2
    if ($inner -match '^([a-zA-Z0-9_\-]+)(?::dn)?(?::([0-9\.]+))?:=(.*)$') {
        return [PSCustomObject]@{
            Type  = 'Extensible'
            Attr  = $matches[1]
            Rule  = $matches[2]
            Value = $matches[3]
        }
    }

    # Comparison / Present leaf filter
    if ($inner -match '^([a-zA-Z0-9_\.\-]+)\s*([=~><]=|[=~><])\s*(.*)$') {
        return [PSCustomObject]@{
            Type  = 'Leaf'
            Attr  = $matches[1]
            Op    = $matches[2]
            Value = $matches[3]
        }
    }

    throw "Unrecognized LDAP filter component '$inner'."
}

function Get-ScimAttributeName {
    param (
        [string]$LdapAttr,
        [hashtable]$CustomMapping
    )

    if ($CustomMapping -and $CustomMapping.ContainsKey($LdapAttr)) {
        return $CustomMapping[$LdapAttr]
    }

    $lower = $LdapAttr.ToLowerInvariant()
    if ($script:DefaultLdapToScimMap.ContainsKey($lower)) {
        return $script:DefaultLdapToScimMap[$lower]
    }

    return $LdapAttr
}

function Convert-LdapAstNodeToScim {
    param (
        [object]$Node,
        [hashtable]$Mapping
    )

    if ($null -eq $Node) { return "" }

    switch ($Node.Type) {
        'Extensible' {
            if ($Node.Attr -ieq 'userAccountControl' -and $Node.Value -eq '2') {
                return 'not (active eq true)'
            }
            return "$($Node.Attr) eq ""$($Node.Value)"""
        }
        'Not' {
            # Check for (! (userAccountControl:1.2.840.113556.1.4.803:=2)) -> active eq true
            $inner = $Node.Child
            if ($inner.Type -eq 'Extensible' -and $inner.Attr -ieq 'userAccountControl' -and $inner.Value -eq '2') {
                return 'active eq true'
            }
            if ($inner.Type -eq 'Leaf' -and $inner.Attr -ieq 'userAccountControl') {
                return 'not (active eq true)'
            }

            $childScim = Convert-LdapAstNodeToScim -Node $inner -Mapping $Mapping
            return "not (${childScim})"
        }
        'And' {
            # Special case: single child inside (&(mail=*@corp.com))
            if ($Node.Children.Count -eq 1) {
                $child = $Node.Children[0]
                if ($child.Type -eq 'Leaf' -and $child.Attr -ieq 'mail') {
                    $val = $child.Value
                    if ($val.StartsWith('*') -and $val.Length -gt 1) {
                        $target = $val.Substring(1)
                        return "emails[type eq ""work"" and value ew ""${target}""]"
                    }
                    elseif ($val.EndsWith('*') -and $val.Length -gt 1) {
                        $target = $val.Substring(0, $val.Length - 1)
                        return "emails[type eq ""work"" and value sw ""${target}""]"
                    }
                    else {
                        return "emails[type eq ""work"" and value eq ""${val}""]"
                    }
                }
                return (Convert-LdapAstNodeToScim -Node $child -Mapping $Mapping)
            }

            $parts = [System.Collections.Generic.List[string]]::new()
            foreach ($c in $Node.Children) {
                $sc = Convert-LdapAstNodeToScim -Node $c -Mapping $Mapping
                if ($c.Type -eq 'Or') {
                    $parts.Add("(${sc})")
                }
                else {
                    $parts.Add($sc)
                }
            }
            return ($parts -join " and ")
        }
        'Or' {
            $parts = [System.Collections.Generic.List[string]]::new()
            foreach ($c in $Node.Children) {
                $sc = Convert-LdapAstNodeToScim -Node $c -Mapping $Mapping
                $parts.Add($sc)
            }
            return ($parts -join " or ")
        }
        'Leaf' {
            $scimAttr = Get-ScimAttributeName -LdapAttr $Node.Attr -CustomMapping $Mapping
            $val = $Node.Value

            # Present check: attr=*
            if ($val -eq '*') {
                return "${scimAttr} pr"
            }

            # Contains check: attr=*val*
            if ($val.StartsWith('*') -and $val.EndsWith('*') -and $val.Length -gt 2) {
                $innerVal = $val.Substring(1, $val.Length - 2)
                return "${scimAttr} co ""${innerVal}"""
            }

            # StartsWith check: attr=val*
            if ($val.EndsWith('*') -and $val.Length -gt 1) {
                $innerVal = $val.Substring(0, $val.Length - 1)
                return "${scimAttr} sw ""${innerVal}"""
            }

            # EndsWith check: attr=*val
            if ($val.StartsWith('*') -and $val.Length -gt 1) {
                $innerVal = $val.Substring(1)
                return "${scimAttr} ew ""${innerVal}"""
            }

            # Comparison operators
            switch ($Node.Op) {
                '>=' { return "${scimAttr} ge ""${val}""" }
                '<=' { return "${scimAttr} le ""${val}""" }
                '='  { return "${scimAttr} eq ""${val}""" }
                default { return "${scimAttr} eq ""${val}""" }
            }
        }
    }

    throw "Unrecognized LDAP AST node type '$($Node.Type)'."
}

function Convert-LdapFilterToScimFilter {
    <#
    .SYNOPSIS
        Translates an RFC 4515 LDAP search filter to a SCIM 2.0 filter expression (RFC 7644 Section 3.4.2.2).
    .DESCRIPTION
        Performs inverse translation from standard Active Directory / LDAP filters back
        into standard SCIM 2.0 filter expressions.
    .EXAMPLE
        Convert-LdapFilterToScimFilter '(sAMAccountName=john)'
        # Output: userName eq "john"
    .EXAMPLE
        Convert-LdapFilterToScimFilter '(&(mail=*@corp.com))'
        # Output: emails[type eq "work" and value ew "@corp.com"]
    .EXAMPLE
        Convert-LdapFilterToScimFilter '(userAccountControl:1.2.840.113556.1.4.803:=2)'
        # Output: not (active eq true)
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [string]$Filter,

        [hashtable]$AttributeMapping = @{}
    )

    if ([string]::IsNullOrWhiteSpace($Filter)) {
        throw "LDAP filter expression cannot be empty."
    }

    $ast = Parse-LdapFilterTree -Filter $Filter
    $scim = Convert-LdapAstNodeToScim -Node $ast -Mapping $AttributeMapping
    return $scim
}

Export-ModuleMember -Function `
    Convert-ScimFilterToLdapFilter, `
    Convert-LdapFilterToScimFilter, `
    Test-ScimFilterSyntax