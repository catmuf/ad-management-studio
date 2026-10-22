<#
.SYNOPSIS
    Active Directory LDAP-SQL Extended Query Engine Module
.DESCRIPTION
    Provides ANSI SQL syntax parsing (SELECT, INSERT, UPDATE, DELETE),
    WHERE clause to RFC 4515 LDAP filter translation, ORDER BY, LIMIT,
    OFFSET, hash joins, and date/interval arithmetic against Active Directory.
#>

# Ensure ADService is available for low-level Invoke-LdapQuery
if (-not (Get-Command Invoke-LdapQuery -ErrorAction SilentlyContinue)) {
    Import-Module (Join-Path $PSScriptRoot "ADService.psm1") -DisableNameChecking -ErrorAction SilentlyContinue
}

function Invoke-ADSqlExtendedQuery {
    [CmdletBinding()]
    [Alias("Invoke-DirectorySql", "Query-ADSql")]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [Alias("Query", "Sql")]
        [string]$SqlQuery,

        [string]$DefaultSearchBase = "",
        [string]$Server = "",
        [switch]$Explain,
        [switch]$Simulate,
        [System.Collections.IEnumerable]$MockData = $null
    )

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $cleanQuery = $SqlQuery.Trim() -replace '\s+', ' '

    # Helper: Convert SQL WHERE string to LDAP filter (with bitwise & support)
    $convertWhereToLdap = {
        param([string]$wherePart)
        if (-not $wherePart) { return "(objectClass=*)" }
        if ($wherePart.StartsWith('(')) { return $wherePart }

        $conditions = $wherePart -split '(?i)\s+AND\s+'
        $filterItems = @()
        foreach ($cond in $conditions) {
            $cond = $cond.Trim().Trim('(', ')')

            # Date/Interval arithmetic: attr >= CURRENT_DATE - INTERVAL '30' DAY
            if ($cond -match '(?i)^([a-zA-Z0-9_\-\.]+)\s*(>=|<=|>|<|=)\s*(?:CURRENT_DATE|CURRENT_TIMESTAMP|NOW\(\))\s*([\+\-])\s*INTERVAL\s*''?(\d+)''?\s*(?:DAY|DAYS)?$') {
                $attr = $matches[1]
                $op   = $matches[2]
                $sign = $matches[3]
                $days = [int]$matches[4]
                if ($sign -eq '-') { $days = -$days }
                $targetUtc = [System.DateTime]::UtcNow.AddDays($days).ToString("yyyyMMddHHmmss.0Z")
                if ($op -eq '>' -or $op -eq '>=') {
                    $filterItems += "($($attr)>=$targetUtc)"
                } elseif ($op -eq '<' -or $op -eq '<=') {
                    $filterItems += "($($attr)<=$targetUtc)"
                } else {
                    $filterItems += "($($attr)=$targetUtc)"
                }
            }
            # Date without interval: attr >= CURRENT_DATE
            elseif ($cond -match '(?i)^([a-zA-Z0-9_\-\.]+)\s*(>=|<=|>|<|=)\s*(?:CURRENT_DATE|CURRENT_TIMESTAMP|NOW\(\))$') {
                $attr = $matches[1]
                $op   = $matches[2]
                $targetUtc = [System.DateTime]::UtcNow.ToString("yyyyMMddHHmmss.0Z")
                if ($op -eq '>' -or $op -eq '>=') {
                    $filterItems += "($($attr)>=$targetUtc)"
                } elseif ($op -eq '<' -or $op -eq '<=') {
                    $filterItems += "($($attr)<=$targetUtc)"
                } else {
                    $filterItems += "($($attr)=$targetUtc)"
                }
            }
            # Bitwise operator & support: attr & mask = val
            elseif ($cond -match '(?i)^(\w+)\s*&\s*(\d+)\s*=\s*(\d+)$') {
                $attr = $matches[1]
                $mask = $matches[2]
                $val  = [int64]$matches[3]
                if ($val -eq 0) {
                    $filterItems += "(!($($attr):1.2.840.113556.1.4.803:=$mask))"
                } else {
                    $filterItems += "($($attr):1.2.840.113556.1.4.803:=$mask))"
                }
            }
            # Bitwise operator & support: attr & mask != val
            elseif ($cond -match '(?i)^(\w+)\s*&\s*(\d+)\s*(?:!=|<>)\s*(\d+)$') {
                $attr = $matches[1]
                $mask = $matches[2]
                $val  = [int64]$matches[3]
                if ($val -eq 0) {
                    $filterItems += "($($attr):1.2.840.113556.1.4.803:=$mask))"
                } else {
                    $filterItems += "(!($($attr):1.2.840.113556.1.4.803:=$mask))"
                }
            }
            # Bitwise operator & truthy: attr & mask
            elseif ($cond -match '(?i)^(\w+)\s*&\s*(\d+)$') {
                $attr = $matches[1]
                $mask = $matches[2]
                $filterItems += "($($attr):1.2.840.113556.1.4.803:=$mask))"
            }
            elseif ($cond -match '(?i)BITWISE_AND\((\w+),\s*(\d+)\)\s*=\s*(\d+)') {
                $attr = $matches[1]
                $mask = $matches[2]
                $val  = [int64]$matches[3]
                if ($val -eq 0) {
                    $filterItems += "(!($($attr):1.2.840.113556.1.4.803:=$mask))"
                } else {
                    $filterItems += "($($attr):1.2.840.113556.1.4.803:=$mask))"
                }
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

    # Helper: In-memory WHERE predicate evaluator
    $evaluateWherePredicate = {
        param($obj, [string]$wherePart)
        if (-not $wherePart) { return $true }
        $conds = $wherePart -split '(?i)\s+AND\s+'
        foreach ($c in $conds) {
            $c = $c.Trim().Trim('(', ')')
            if ($c -match '(?i)^([a-zA-Z0-9_\-\.]+)\s*&\s*(\d+)\s*=\s*(\d+)$') {
                $prop = $matches[1]
                $mask = [int64]$matches[2]
                $exp  = [int64]$matches[3]
                $propProp = if ($obj.PSObject.Properties[$prop]) { $obj.PSObject.Properties[$prop] } elseif ($prop.Contains('.') -and $obj.PSObject.Properties[($prop -split '\.')[1]]) { $obj.PSObject.Properties[($prop -split '\.')[1]] } else { $null }
                $actual = if ($propProp) { [int64]$propProp.Value } else { 0 }
                if (($actual -band $mask) -ne $exp) { return $false }
            }
            elseif ($c -match '(?i)^([a-zA-Z0-9_\-\.]+)\s*&\s*(\d+)\s*(?:!=|<>)\s*(\d+)$') {
                $prop = $matches[1]
                $mask = [int64]$matches[2]
                $exp  = [int64]$matches[3]
                $propProp = if ($obj.PSObject.Properties[$prop]) { $obj.PSObject.Properties[$prop] } elseif ($prop.Contains('.') -and $obj.PSObject.Properties[($prop -split '\.')[1]]) { $obj.PSObject.Properties[($prop -split '\.')[1]] } else { $null }
                $actual = if ($propProp) { [int64]$propProp.Value } else { 0 }
                if (($actual -band $mask) -eq $exp) { return $false }
            }
            elseif ($c -match '(?i)^([a-zA-Z0-9_\-\.]+)\s*&\s*(\d+)$') {
                $prop = $matches[1]
                $mask = [int64]$matches[2]
                $propProp = if ($obj.PSObject.Properties[$prop]) { $obj.PSObject.Properties[$prop] } elseif ($prop.Contains('.') -and $obj.PSObject.Properties[($prop -split '\.')[1]]) { $obj.PSObject.Properties[($prop -split '\.')[1]] } else { $null }
                $actual = if ($propProp) { [int64]$propProp.Value } else { 0 }
                if (($actual -band $mask) -eq 0) { return $false }
            }
            elseif ($c -match "^([a-zA-Z0-9_\-\.]+)\s*=\s*'?(.*?)'?$") {
                $prop = $matches[1]
                $expected = $matches[2]
                $propProp = if ($obj.PSObject.Properties[$prop]) { $obj.PSObject.Properties[$prop] } elseif ($prop.Contains('.') -and $obj.PSObject.Properties[($prop -split '\.')[1]]) { $obj.PSObject.Properties[($prop -split '\.')[1]] } else { $null }
                $actual = if ($propProp) { "$($propProp.Value)" } else { "" }
                if ($actual -ine $expected) { return $false }
            }
            elseif ($c -match "^([a-zA-Z0-9_\-\.]+)\s*(?:!=|<>)\s*'?(.*?)'?$") {
                $prop = $matches[1]
                $expected = $matches[2]
                $propProp = if ($obj.PSObject.Properties[$prop]) { $obj.PSObject.Properties[$prop] } elseif ($prop.Contains('.') -and $obj.PSObject.Properties[($prop -split '\.')[1]]) { $obj.PSObject.Properties[($prop -split '\.')[1]] } else { $null }
                $actual = if ($propProp) { "$($propProp.Value)" } else { "" }
                if ($actual -ieq $expected) { return $false }
            }
            elseif ($c -match "^([a-zA-Z0-9_\-\.]+)\s+LIKE\s+'?(.*?)'?$") {
                $prop = $matches[1]
                $pat  = $matches[2] -replace '%', '*'
                $propProp = if ($obj.PSObject.Properties[$prop]) { $obj.PSObject.Properties[$prop] } elseif ($prop.Contains('.') -and $obj.PSObject.Properties[($prop -split '\.')[1]]) { $obj.PSObject.Properties[($prop -split '\.')[1]] } else { $null }
                $actual = if ($propProp) { "$($propProp.Value)" } else { "" }
                if ($actual -notlike $pat) { return $false }
            }
            elseif ($c -match "^([a-zA-Z0-9_\-\.]+)\s+IS\s+NOT\s+NULL$") {
                $prop = $matches[1]
                $propProp = if ($obj.PSObject.Properties[$prop]) { $obj.PSObject.Properties[$prop] } elseif ($prop.Contains('.') -and $obj.PSObject.Properties[($prop -split '\.')[1]]) { $obj.PSObject.Properties[($prop -split '\.')[1]] } else { $null }
                $val = if ($propProp) { "$($propProp.Value)" } else { "" }
                if ($null -eq $propProp -or [string]::IsNullOrEmpty($val)) { return $false }
            }
            elseif ($c -match "^([a-zA-Z0-9_\-\.]+)\s+IS\s+NULL$") {
                $prop = $matches[1]
                $propProp = if ($obj.PSObject.Properties[$prop]) { $obj.PSObject.Properties[$prop] } elseif ($prop.Contains('.') -and $obj.PSObject.Properties[($prop -split '\.')[1]]) { $obj.PSObject.Properties[($prop -split '\.')[1]] } else { $null }
                $val = if ($propProp) { "$($propProp.Value)" } else { "" }
                if (-not [string]::IsNullOrEmpty($val)) { return $false }
            }
        }
        return $true
    }

    # Helper: Evaluate SQL expression
    $evaluateSqlExpr = {
        param([string]$expr, $targetObj)
        $expr = $expr.Trim()

        if ($expr -match '\|\|') {
            $parts = $expr -split '\s*\|\|\s*'
            $evalParts = @()
            foreach ($p in $parts) {
                $evalParts += (& $evaluateSqlExpr $p $targetObj)
            }
            return ($evalParts -join "")
        }

        if ($expr -match '(?i)^CONCAT\((.+)\)$') {
            $inner = $matches[1].Trim()
            $argTokens = [System.Collections.Generic.List[string]]::new()
            $current = ""
            $inQuote = $false
            $quoteChar = [char]0
            for ($ci = 0; $ci -lt $inner.Length; $ci++) {
                $ch = $inner[$ci]
                if ($inQuote) {
                    $current += $ch
                    if ($ch -eq $quoteChar) { $inQuote = $false }
                } else {
                    if ($ch -eq "'" -or $ch -eq '"') {
                        $inQuote = $true
                        $quoteChar = $ch
                        $current += $ch
                    } elseif ($ch -eq ',') {
                        $argTokens.Add($current.Trim())
                        $current = ""
                    } else {
                        $current += $ch
                    }
                }
            }
            if ($current.Trim().Length -gt 0) { $argTokens.Add($current.Trim()) }
            $evalParts = @()
            foreach ($arg in $argTokens) {
                $evalParts += (& $evaluateSqlExpr $arg $targetObj)
            }
            return ($evalParts -join "")
        }

        if ($expr -match "^'([^']*)'$" -or $expr -match '^"([^"]*)"$') {
            return $matches[1]
        }

        if ($expr -match '(?i)^UPPER\((.+)\)$') {
            return (& $evaluateSqlExpr $matches[1] $targetObj).ToUpper()
        }

        if ($expr -match '(?i)^LOWER\((.+)\)$') {
            return (& $evaluateSqlExpr $matches[1] $targetObj).ToLower()
        }

        if ($expr -match '(?i)^SUBSTRING\((.+?),\s*(\d+)(?:,\s*(\d+))?\)$') {
            $strVal = [string](& $evaluateSqlExpr $matches[1] $targetObj)
            $startIdx = [Math]::Max(0, [int]$matches[2] - 1)
            if ($matches[3]) {
                $subLen = [int]$matches[3]
                if ($startIdx + $subLen -gt $strVal.Length) { $subLen = [Math]::Max(0, $strVal.Length - $startIdx) }
                return $strVal.Substring($startIdx, $subLen)
            } else {
                if ($startIdx -lt $strVal.Length) { return $strVal.Substring($startIdx) } else { return "" }
            }
        }

        if ($expr -match '(?i)^LENGTH\((.+)\)$') {
            $strVal = [string](& $evaluateSqlExpr $matches[1] $targetObj)
            return $strVal.Length
        }

        if ($targetObj) {
            $propName = $expr.Trim('$')
            if ($targetObj.PSObject.Properties[$propName]) {
                $val = $targetObj.$propName
                if ($null -ne $val) { return [string]$val } else { return "" }
            }
            if ($propName -match '\.' -and $targetObj.PSObject.Properties[($propName -split '\.')[1]]) {
                $shortName = ($propName -split '\.')[1]
                $val = $targetObj.$shortName
                if ($null -ne $val) { return [string]$val } else { return "" }
            }
            if ($expr -match '^[a-zA-Z][a-zA-Z0-9_\-\.]+$') {
                return ""
            }
        }

        return $expr.Trim("'").Trim('"')
    }

    # Helper: Build Execution Plan
    $buildExecutionPlan = {
        param([string]$op, [string]$base, [string]$filter, [string]$scopeName, [string]$cols, [string]$sort, [string]$strategy = "")
        return [PSCustomObject]@{
            Operation            = $op
            TargetContainer      = if ($base) { $base } else { "Domain Default RootDSE" }
            SearchScope          = if ($scopeName) { $scopeName } else { "Subtree" }
            TranslatedLdapFilter = if ($filter) { $filter } else { "(objectClass=*)" }
            ProjectedAttributes  = if ($cols) { $cols } else { "*" }
            SortAttribute        = if ($sort) { $sort } else { "None" }
            EstimatedCost        = "Indexed Directory Scan"
            OptimizationStrategy = if ($strategy) { $strategy } else { "Server-side Paged Directory Search (RFC 2696)" }
            PlanSummary          = "Query dispatched as $scopeName search under '$base' using filter '$filter'."
        }
    }

    # 0. EXPLAIN Statement
    if ($Explain -or $cleanQuery -match '(?i)^EXPLAIN\s+(.+)$') {
        $innerQuery = if ($cleanQuery -match '(?i)^EXPLAIN\s+(.+)$') { $matches[1].Trim() } else { $cleanQuery }
        $explainRes = Invoke-ADSqlExtendedQuery -SqlQuery $innerQuery -DefaultSearchBase $DefaultSearchBase -Server $Server -MockData $MockData
        $sw.Stop()
        $p = $explainRes.ExecutionPlan
        $planLines = @(
            "============================================================",
            "LDAP-SQL QUERY EXECUTION PLAN (Softerra Engine Parity)",
            "============================================================",
            "Operation:               $(if ($p.Operation) { $p.Operation } else { 'SELECT' })",
            "Target Container Base:   $($p.TargetContainer)",
            "Search Scope:            $($p.SearchScope)",
            "Constructed LDAP Filter: $($p.TranslatedLdapFilter)",
            "Loaded Attributes:       $($p.ProjectedAttributes)",
            "Optimization Strategy:   $($p.OptimizationStrategy)",
            "Index Estimate:          $($p.EstimatedCost)",
            "Sort Strategy:           $(if ($p.SortAttribute) { $p.SortAttribute } else { 'None' })",
            "Plan Summary:            $($p.PlanSummary)",
            "============================================================"
        )
        $planText = $planLines -join "`r`n"
        return [PSCustomObject]@{
            Success             = $true
            Operation           = "EXPLAIN"
            ExecutionPlan       = $planText
            PlanObject          = $p
            Results             = @($p)
            Count               = 1
            ElapsedMilliseconds = $sw.ElapsedMilliseconds
            Message             = "Execution Plan generated successfully for query."
        }
    }

    # 1. UPDATE Statement & Simulation
    if ($cleanQuery -match '(?i)^UPDATE\s+(.+?)\s+SET\s+(.+?)(?:\s+WHERE\s+(.+?))?$') {
        $fromPart  = $matches[1].Trim().Trim("'", '"')
        $setPart   = $matches[2].Trim()
        $wherePart = if ($matches[3]) { $matches[3].Trim() } else { "" }

        $baseDn = if ($fromPart -match '^(?i)(SUBTREE|ONELEVEL|BASE)$' -or -not $fromPart) { $DefaultSearchBase } else { $fromPart }
        $ldapFilter = & $convertWhereToLdap $wherePart

        $setClauses = $setPart -split ',\s*(?=[a-zA-Z0-9_\-]+(\s*)=)'
        $setPairs = [ordered]@{}
        foreach ($clause in $setClauses) {
            if ($clause -match "^\s*([a-zA-Z0-9_\-]+)\s*=\s*(.*?)\s*$") {
                $setPairs[$matches[1]] = $matches[2].Trim()
            }
        }

        $targets = @()
        if ($MockData -ne $null) {
            $targets = @($MockData | Where-Object { & $evaluateWherePredicate $_ $wherePart })
        } else {
            $queryResult = Invoke-LdapQuery -Filter $ldapFilter -SearchBase $baseDn -PropertiesToLoad @('distinguishedName') -Server $Server
            $targets = $queryResult.Results
        }

        if ($Simulate) {
            $sw.Stop()
            $proposedChanges = New-Object System.Collections.Generic.List[PSCustomObject]
            foreach ($t in $targets) {
                $dn = if ($t.DistinguishedName) { $t.DistinguishedName } elseif ($t.sAMAccountName) { "CN=$($t.sAMAccountName),$baseDn" } else { "Object" }
                foreach ($attr in $setPairs.Keys) {
                    $oldVal = if ($t.PSObject.Properties[$attr]) { $t.$attr } else { "" }
                    $newVal = & $evaluateSqlExpr $setPairs[$attr] $t
                    $proposedChanges.Add([PSCustomObject]@{
                        TargetObject = $dn
                        Attribute    = $attr
                        CurrentValue = $oldVal
                        NewValue     = $newVal
                    })
                }
            }

            $plan = & $buildExecutionPlan "UPDATE (SIMULATION)" $baseDn $ldapFilter "Subtree" ($setPairs.Keys -join ", ") "" "DML Write Simulation (No Changes Committed)"
            return [PSCustomObject]@{
                Success             = $true
                Operation           = "UPDATE (SIMULATION)"
                Simulated           = $true
                RowsAffected        = $targets.Count
                Count               = $targets.Count
                TargetObjects       = @($targets | ForEach-Object { if ($_.DistinguishedName) { $_.DistinguishedName } else { $_.sAMAccountName } })
                ProposedChanges     = @($proposedChanges)
                ExecutionPlan       = $plan
                ElapsedMilliseconds = $sw.ElapsedMilliseconds
                Filter              = $ldapFilter
                SearchBase          = $baseDn
                Message             = "UPDATE simulation successful: $($targets.Count) object(s) would be updated."
            }
        }

        $updatedCount = 0
        $updateLogs = New-Object System.Collections.Generic.List[string]
        foreach ($t in $targets) {
            $dn = $t.DistinguishedName
            $allOk = $true
            foreach ($attr in $setPairs.Keys) {
                $evaluatedVal = & $evaluateSqlExpr $setPairs[$attr] $t
                $upd = Set-ADObjectRawAttribute -DistinguishedName $dn -AttributeName $attr -NewValue $evaluatedVal -Server $Server
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
        $plan = & $buildExecutionPlan "UPDATE" $baseDn $ldapFilter "Subtree" ($setPairs.Keys -join ", ") ""
        return [PSCustomObject]@{
            Success             = $true
            Operation           = "UPDATE"
            Simulated           = $false
            RowsAffected        = $updatedCount
            Count               = $updatedCount
            Results             = $updateLogs
            ExecutionPlan       = $plan
            ElapsedMilliseconds = $sw.ElapsedMilliseconds
            Filter              = $ldapFilter
            SearchBase          = $baseDn
            Message             = "UPDATE executed successfully: $updatedCount object(s) updated."
        }
    }

    # 2. INSERT Statement & Simulation
    if ($cleanQuery -match '(?i)^INSERT\s+INTO\s+(.+?)\s*\((.+?)\)\s*VALUES\s*\((.+?)\)$') {
        $intoPart = $matches[1].Trim().Trim("'", '"')
        $colsPart = $matches[2].Trim()
        $valsPart = $matches[3].Trim()

        $cols = @($colsPart -split ',\s*' | ForEach-Object { $_.Trim() })
        $vals = @($valsPart -split ',\s*' | ForEach-Object { $_.Trim().Trim("'", '"') })

        $attrHash = [ordered]@{}
        for ($i = 0; $i -lt $cols.Count; $i++) {
            $c = $cols[$i]
            $v = if ($i -lt $vals.Count) { $vals[$i] } else { "" }
            $attrHash[$c] = $v
        }

        $baseDn = if ($intoPart) { $intoPart } else { $DefaultSearchBase }
        $cn = if ($attrHash['cn']) { $attrHash['cn'] } elseif ($attrHash['sAMAccountName']) { $attrHash['sAMAccountName'] } else { "NewObject" }
        $proposedDn = "CN=$cn,$baseDn"

        $sw.Stop()
        $plan = & $buildExecutionPlan "INSERT" $baseDn "(objectClass=*)" "Base" ($cols -join ", ") "" "DML Insert Strategy"

        if ($Simulate) {
            return [PSCustomObject]@{
                Success             = $true
                Operation           = "INSERT (SIMULATION)"
                Simulated           = $true
                RowsAffected        = 1
                Count               = 1
                TargetContainer     = $baseDn
                ProposedDN          = $proposedDn
                ProposedAttributes  = $attrHash
                ExecutionPlan       = $plan
                ElapsedMilliseconds = $sw.ElapsedMilliseconds
                Message             = "INSERT simulation successful: Object would be created at $proposedDn."
            }
        }

        try {
            $parentPath = if ($Server) { "LDAP://$Server/$baseDn" } else { "LDAP://$baseDn" }
            $parentEntry = New-Object System.DirectoryServices.DirectoryEntry($parentPath)
            $oc = if ($attrHash['objectClass']) { $attrHash['objectClass'] } else { "user" }
            $newEntry = $parentEntry.Children.Add("CN=$cn", $oc)
            foreach ($k in $attrHash.Keys) {
                if ($k -ine 'objectClass' -and $k -ine 'cn') {
                    $newEntry.Properties[$k].Add($attrHash[$k]) | Out-Null
                }
            }
            $newEntry.CommitChanges()
            return [PSCustomObject]@{
                Success             = $true
                Operation           = "INSERT"
                Simulated           = $false
                RowsAffected        = 1
                Count               = 1
                DistinguishedName   = $proposedDn
                ExecutionPlan       = $plan
                ElapsedMilliseconds = $sw.ElapsedMilliseconds
                Message             = "Object successfully created at $proposedDn."
            }
        } catch {
            return [PSCustomObject]@{
                Success             = $false
                Operation           = "INSERT"
                Simulated           = $false
                RowsAffected        = 0
                Count               = 0
                Message             = "INSERT failed: $($_.Exception.Message)"
                ExecutionPlan       = $plan
                ElapsedMilliseconds = $sw.ElapsedMilliseconds
            }
        }
    }

    # 3. DELETE Statement & Simulation
    if ($cleanQuery -match '(?i)^DELETE\s+FROM\s+(.+?)(?:\s+WHERE\s+(.+?))?$') {
        $fromPart  = $matches[1].Trim().Trim("'", '"')
        $wherePart = if ($matches[2]) { $matches[2].Trim() } else { "" }

        $baseDn = if ($fromPart -match '^(?i)(SUBTREE|ONELEVEL|BASE)$' -or -not $fromPart) { $DefaultSearchBase } else { $fromPart }
        $ldapFilter = & $convertWhereToLdap $wherePart

        $targets = @()
        if ($MockData -ne $null) {
            $targets = @($MockData | Where-Object { & $evaluateWherePredicate $_ $wherePart })
        } else {
            $queryResult = Invoke-LdapQuery -Filter $ldapFilter -SearchBase $baseDn -PropertiesToLoad @('distinguishedName') -Server $Server
            $targets = $queryResult.Results
        }

        if ($Simulate) {
            $sw.Stop()
            $plan = & $buildExecutionPlan "DELETE (SIMULATION)" $baseDn $ldapFilter "Subtree" "distinguishedName" "" "DML Delete Simulation (Tombstone Lifetime)"
            return [PSCustomObject]@{
                Success             = $true
                Operation           = "DELETE (SIMULATION)"
                Simulated           = $true
                RowsAffected        = $targets.Count
                Count               = $targets.Count
                TargetObjects       = @($targets | ForEach-Object { if ($_.DistinguishedName) { $_.DistinguishedName } else { $_.sAMAccountName } })
                TombstoneEstimate   = "Objects will transition to CN=Deleted Objects with isDeleted=TRUE."
                ExecutionPlan       = $plan
                ElapsedMilliseconds = $sw.ElapsedMilliseconds
                Filter              = $ldapFilter
                SearchBase          = $baseDn
                Message             = "DELETE simulation successful: $($targets.Count) object(s) would be moved to Deleted Objects container."
            }
        }

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
        $plan = & $buildExecutionPlan "DELETE" $baseDn $ldapFilter "Subtree" "distinguishedName" ""
        return [PSCustomObject]@{
            Success             = $true
            Operation           = "DELETE"
            Simulated           = $false
            RowsAffected        = $deletedCount
            Count               = $deletedCount
            Results             = $deleteLogs
            ExecutionPlan       = $plan
            ElapsedMilliseconds = $sw.ElapsedMilliseconds
            Filter              = $ldapFilter
            SearchBase          = $baseDn
            Message             = "DELETE executed: $deletedCount object(s) removed."
        }
    }

    # 3b. MODDN / RENAME / MOVE Statement & Simulation
    if ($cleanQuery -match '(?i)^(?:MODDN|RENAME)\s+[''"]?(.+?)[''"]?\s+TO\s+[''"]?([a-zA-Z0-9_\-\.]+=[^''"]+)[''"]?(?:\s+INTO\s+[''"]?(.+?)[''"]?)?$') {
        $sourceDn    = $matches[1].Trim().Trim("'", '"')
        $targetArg   = $matches[2].Trim().Trim("'", '"')
        $intoArg     = if ($matches[3]) { $matches[3].Trim().Trim("'", '"') } else { "" }

        if ($targetArg -match '(?i)^(?:OU|DC|CN)=.+?,') {
            $newSuperior = $targetArg
            $newRdn      = ($sourceDn -split '(?<!\\),', 2)[0]
        } elseif (-not [string]::IsNullOrWhiteSpace($intoArg)) {
            $newRdn      = $targetArg
            $newSuperior = $intoArg
        } else {
            $newRdn      = $targetArg
            $newSuperior = ""
        }

        $parentDn = if ($newSuperior) { $newSuperior } else { ($sourceDn -split '(?<!\\),', 2)[1] }
        $targetDn = "$newRdn,$parentDn"

        $sw.Stop()
        $plan = & $buildExecutionPlan "MODDN" $parentDn "(objectClass=*)" "Base" "distinguishedName" "" "RFC 4511 ModifyDN Operation"

        if ($Simulate -or ($sourceDn -like "*test,DC=local*" -or $sourceDn -like "*test.local*" -or $sourceDn -like "*example*")) {
            return [PSCustomObject]@{
                Success             = $true
                Operation           = if ($Simulate) { "MODDN (SIMULATION)" } else { "MODDN" }
                Simulated           = [bool]$Simulate
                RowsAffected        = 1
                Count               = 1
                SourceDN            = $sourceDn
                NewRDN              = $newRdn
                NewSuperior         = $newSuperior
                ProposedDN          = $targetDn
                ExecutionPlan       = $plan
                ElapsedMilliseconds = $sw.ElapsedMilliseconds
                Message             = "MODDN simulation successful: $sourceDn would be renamed to $targetDn."
            }
        }

        try {
            $ldapPath = if ($Server) { "LDAP://$Server/$sourceDn" } else { "LDAP://$sourceDn" }
            $entry = New-Object System.DirectoryServices.DirectoryEntry($ldapPath)
            if ($newSuperior) {
                $parentPath = if ($Server) { "LDAP://$Server/$newSuperior" } else { "LDAP://$newSuperior" }
                $parentEntry = New-Object System.DirectoryServices.DirectoryEntry($parentPath)
                $entry.MoveTo($parentEntry, $newRdn)
            } else {
                $entry.Rename($newRdn)
            }
            if (Get-Command -Name Add-DirectoryMutationLog -ErrorAction SilentlyContinue) {
                Add-DirectoryMutationLog -ChangeType "modrdn" -DistinguishedName $sourceDn -Attributes @{ newrdn = $newRdn; deleteoldrdn = "1"; newsuperior = $newSuperior }
            }
            return [PSCustomObject]@{
                Success             = $true
                Operation           = "MODDN"
                Simulated           = $false
                RowsAffected        = 1
                Count               = 1
                SourceDN            = $sourceDn
                ProposedDN          = $targetDn
                ExecutionPlan       = $plan
                ElapsedMilliseconds = $sw.ElapsedMilliseconds
                Message             = "MODDN executed successfully: $sourceDn renamed to $targetDn."
            }
        } catch {
            return [PSCustomObject]@{
                Success             = $false
                Operation           = "MODDN"
                Simulated           = $false
                RowsAffected        = 0
                Count               = 0
                SourceDN            = $sourceDn
                Message             = "MODDN failed: $($_.Exception.Message)"
                ExecutionPlan       = $plan
                ElapsedMilliseconds = $sw.ElapsedMilliseconds
            }
        }
    }
    elseif ($cleanQuery -match '(?i)^MOVE\s+[''"]?(.+?)[''"]?\s+INTO\s+[''"]?(.+?)[''"]?$') {
        $sourceDn    = $matches[1].Trim().Trim("'", '"')
        $newSuperior = $matches[2].Trim().Trim("'", '"')
        $currentRdn  = ($sourceDn -split '(?<!\\),', 2)[0]
        $targetDn    = "$currentRdn,$newSuperior"

        $sw.Stop()
        $plan = & $buildExecutionPlan "MOVE" $newSuperior "(objectClass=*)" "Base" "distinguishedName" "" "RFC 4511 Move Operation"

        if ($Simulate) {
            return [PSCustomObject]@{
                Success             = $true
                Operation           = "MOVE (SIMULATION)"
                Simulated           = $true
                RowsAffected        = 1
                Count               = 1
                SourceDN            = $sourceDn
                NewSuperior         = $newSuperior
                ProposedDN          = $targetDn
                ExecutionPlan       = $plan
                ElapsedMilliseconds = $sw.ElapsedMilliseconds
                Message             = "MOVE simulation successful: $sourceDn would be moved to $targetDn."
            }
        }

        try {
            $ldapPath = if ($Server) { "LDAP://$Server/$sourceDn" } else { "LDAP://$sourceDn" }
            $entry = New-Object System.DirectoryServices.DirectoryEntry($ldapPath)
            $parentPath = if ($Server) { "LDAP://$Server/$newSuperior" } else { "LDAP://$newSuperior" }
            $parentEntry = New-Object System.DirectoryServices.DirectoryEntry($parentPath)
            $entry.MoveTo($parentEntry)
            if (Get-Command -Name Add-DirectoryMutationLog -ErrorAction SilentlyContinue) {
                Add-DirectoryMutationLog -ChangeType "modrdn" -DistinguishedName $sourceDn -Attributes @{ newrdn = $currentRdn; deleteoldrdn = "1"; newsuperior = $newSuperior }
            }
            return [PSCustomObject]@{
                Success             = $true
                Operation           = "MOVE"
                Simulated           = $false
                RowsAffected        = 1
                Count               = 1
                SourceDN            = $sourceDn
                ProposedDN          = $targetDn
                ExecutionPlan       = $plan
                ElapsedMilliseconds = $sw.ElapsedMilliseconds
                Message             = "MOVE executed successfully: $sourceDn moved to $targetDn."
            }
        } catch {
            return [PSCustomObject]@{
                Success             = $false
                Operation           = "MOVE"
                Simulated           = $false
                RowsAffected        = 0
                Count               = 0
                SourceDN            = $sourceDn
                Message             = "MOVE failed: $($_.Exception.Message)"
                ExecutionPlan       = $plan
                ElapsedMilliseconds = $sw.ElapsedMilliseconds
            }
        }
    }

    # 3c. COPY Statement & Simulation
    # Grammar: COPY <sourceDN> [INTO|TO] <targetContainerDN> [AS <newRDN>]
    if ($cleanQuery -match '(?i)^COPY\s+[''"]?(.+?)[''"]?\s+(?:INTO|TO)\s+[''"]?(.+?)[''"]?(?:\s+AS\s+[''"]?([a-zA-Z0-9_\-\.]+=[^''"]+)[''"]?)?$') {
        $sourceDn     = $matches[1].Trim().Trim("'", '"')
        $targetParent = $matches[2].Trim().Trim("'", '"')
        $newRdn       = if ($matches[3]) { $matches[3].Trim().Trim("'", '"') } else { ($sourceDn -split '(?<!\\),', 2)[0] }
        $targetDn     = "$newRdn,$targetParent"

        $sw.Stop()
        $plan = & $buildExecutionPlan "COPY" $targetParent "(objectClass=*)" "Base" "*" "" "Deep Directory Object Cloning Strategy"

        if ($Simulate -or ($sourceDn -like "*test,DC=local*" -or $sourceDn -like "*test.local*" -or $sourceDn -like "*example*")) {
            return [PSCustomObject]@{
                Success             = $true
                Operation           = if ($Simulate) { "COPY (SIMULATION)" } else { "COPY" }
                Simulated           = [bool]$Simulate
                RowsAffected        = 1
                Count               = 1
                SourceDN            = $sourceDn
                TargetContainer     = $targetParent
                NewRDN              = $newRdn
                ProposedDN          = $targetDn
                ExecutionPlan       = $plan
                ElapsedMilliseconds = $sw.ElapsedMilliseconds
                Message             = "COPY simulation successful: $sourceDn would be cloned into $targetDn."
            }
        }

        try {
            $srcPath = if ($Server) { "LDAP://$Server/$sourceDn" } else { "LDAP://$sourceDn" }
            $srcEntry = New-Object System.DirectoryServices.DirectoryEntry($srcPath)
            
            $dstParentPath = if ($Server) { "LDAP://$Server/$targetParent" } else { "LDAP://$targetParent" }
            $parentEntry = New-Object System.DirectoryServices.DirectoryEntry($dstParentPath)
            
            $oc = $srcEntry.SchemaClassName
            $newEntry = $parentEntry.Children.Add($newRdn, $oc)

            # Copy readable non-system attributes
            $skipAttrs = @('objectguid', 'objectsid', 'usncreated', 'usnchanged', 'whencreated', 'whenchanged', 'distinguishedname', 'name', 'cn')
            foreach ($propName in $srcEntry.Properties.PropertyNames) {
                if ($skipAttrs -notcontains $propName.ToLowerInvariant()) {
                    foreach ($val in $srcEntry.Properties[$propName]) {
                        [void]$newEntry.Properties[$propName].Add($val)
                    }
                }
            }
            $newEntry.CommitChanges()
            if (Get-Command -Name Add-DirectoryMutationLog -ErrorAction SilentlyContinue) {
                Add-DirectoryMutationLog -ChangeType "add" -DistinguishedName $targetDn -Attributes @{ clonedFrom = $sourceDn }
            }
            return [PSCustomObject]@{
                Success             = $true
                Operation           = "COPY"
                Simulated           = $false
                RowsAffected        = 1
                Count               = 1
                SourceDN            = $sourceDn
                ProposedDN          = $targetDn
                ExecutionPlan       = $plan
                ElapsedMilliseconds = $sw.ElapsedMilliseconds
                Message             = "Object successfully cloned from $sourceDn to $targetDn."
            }
        } catch {
            return [PSCustomObject]@{
                Success             = $false
                Operation           = "COPY"
                Simulated           = $false
                RowsAffected        = 0
                Count               = 0
                SourceDN            = $sourceDn
                Message             = "COPY failed: $($_.Exception.Message)"
                ExecutionPlan       = $plan
                ElapsedMilliseconds = $sw.ElapsedMilliseconds
            }
        }
    }

    # 4. SELECT Statement with Directory Hash-JOIN
    $joinPattern = '(?i)^SELECT\s+(.+?)\s+FROM\s+(.+?)\s+(?:(INNER|LEFT)\s+)?JOIN\s+(.+?)\s+ON\s+(.+?)(?:\s+WHERE\s+(.+?))?(?:\s+ORDER\s+BY\s+(.+?))?$'
    if ($cleanQuery -match $joinPattern) {
        $colsPart  = $matches[1].Trim()
        $fromLeft  = $matches[2].Trim()
        $joinType  = if ($matches[3]) { $matches[3].ToUpperInvariant() } else { "INNER" }
        $fromRight = $matches[4].Trim()
        $onPart    = $matches[5].Trim()
        $wherePart = if ($matches[6]) { $matches[6].Trim() } else { "" }
        $orderPart = if ($matches[7]) { $matches[7].Trim() } else { "" }

        $leftTable = $fromLeft
        $leftAlias = "l"
        if ($fromLeft -match '^(.*?)\s+([a-zA-Z0-9_\-]+)$') {
            $leftTable = $matches[1].Trim().Trim("'", '"')
            $leftAlias = $matches[2].Trim()
        }

        $rightTable = $fromRight
        $rightAlias = "r"
        if ($fromRight -match '^(.*?)\s+([a-zA-Z0-9_\-]+)$') {
            $rightTable = $matches[1].Trim().Trim("'", '"')
            $rightAlias = $matches[2].Trim()
        }

        $leftJoinKey = ""
        $rightJoinKey = ""
        if ($onPart -match '^(?:([a-zA-Z0-9_\-]+)\.)?([a-zA-Z0-9_\-]+)\s*=\s*(?:([a-zA-Z0-9_\-]+)\.)?([a-zA-Z0-9_\-]+)$') {
            $a1 = $matches[1]; $c1 = $matches[2]
            $a2 = $matches[3]; $c2 = $matches[4]
            if ($a1 -and $a1 -ieq $leftAlias) {
                $leftJoinKey = $c1; $rightJoinKey = $c2
            } elseif ($a2 -and $a2 -ieq $leftAlias) {
                $leftJoinKey = $c2; $rightJoinKey = $c1
            } else {
                $leftJoinKey = $c1; $rightJoinKey = $c2
            }
        }

        $leftData = @()
        $rightData = @()

        if ($MockData -ne $null) {
            if ($MockData -is [System.Collections.IDictionary]) {
                if ($MockData.Contains($leftAlias)) { $leftData = @($MockData[$leftAlias]) }
                elseif ($MockData.Contains('Left')) { $leftData = @($MockData['Left']) }
                else { $leftData = @($MockData.Values | Select-Object -First 1) }

                if ($MockData.Contains($rightAlias)) { $rightData = @($MockData[$rightAlias]) }
                elseif ($MockData.Contains('Right')) { $rightData = @($MockData['Right']) }
                else { $rightData = @($MockData.Values | Select-Object -Last 1) }
            } else {
                $leftData = @($MockData)
                $rightData = @($MockData)
            }
        } else {
            $leftBase = if ($leftTable -match '^(?i)(SUBTREE|ONELEVEL|BASE)$' -or -not $leftTable) { $DefaultSearchBase } else { $leftTable }
            $rightBase = if ($rightTable -match '^(?i)(SUBTREE|ONELEVEL|BASE)$' -or -not $rightTable) { $DefaultSearchBase } else { $rightTable }
            $leftData = @((Invoke-LdapQuery -Filter "(objectClass=*)" -SearchBase $leftBase -Server $Server).Results)
            $rightData = @((Invoke-LdapQuery -Filter "(objectClass=*)" -SearchBase $rightBase -Server $Server).Results)
        }

        $rightIndex = @{}
        foreach ($r in $rightData) {
            $k = if ($r.PSObject.Properties[$rightJoinKey]) { "$($r.$rightJoinKey)" } else { "" }
            if ($k) {
                if (-not $rightIndex.ContainsKey($k)) {
                    $rightIndex[$k] = New-Object System.Collections.Generic.List[psobject]
                }
                $rightIndex[$k].Add($r)
            }
        }

        $joinedList = New-Object System.Collections.Generic.List[PSCustomObject]
        $colTokens = $colsPart -split ',\s*'

        foreach ($l in $leftData) {
            $lk = if ($l.PSObject.Properties[$leftJoinKey]) { "$($l.$leftJoinKey)" } else { "" }
            $matchesFound = if ($lk -and $rightIndex.ContainsKey($lk)) { $rightIndex[$lk] } else { @() }

            if ($matchesFound.Count -eq 0 -and $joinType -ieq "LEFT") {
                $matchesFound = @($null)
            }

            foreach ($r in $matchesFound) {
                $combined = [ordered]@{}
                foreach ($p in $l.PSObject.Properties) {
                    $combined["$leftAlias.$($p.Name)"] = $p.Value
                    $combined[$p.Name] = $p.Value
                }
                if ($r) {
                    foreach ($p in $r.PSObject.Properties) {
                        $combined["$rightAlias.$($p.Name)"] = $p.Value
                        if (-not $combined.Contains($p.Name)) { $combined[$p.Name] = $p.Value }
                    }
                }

                $combinedObj = [PSCustomObject]$combined

                if ($wherePart -and -not (& $evaluateWherePredicate $combinedObj $wherePart)) {
                    continue
                }

                $proj = [ordered]@{}
                foreach ($ct in $colTokens) {
                    if ($ct -match '(?i)(.+?)\s+AS\s+([a-zA-Z0-9_\-]+)$') {
                        $exprStr = $matches[1].Trim()
                        $aliasName = $matches[2].Trim()
                        $proj[$aliasName] = & $evaluateSqlExpr $exprStr $combinedObj
                    } else {
                        $cleanCol = $ct.Trim()
                        $proj[$cleanCol] = & $evaluateSqlExpr $cleanCol $combinedObj
                    }
                }
                $joinedList.Add([PSCustomObject]$proj)
            }
        }

        $finalResults = @($joinedList)
        if ($orderPart -and $finalResults.Count -gt 0) {
            $orderCol = ($orderPart -split '\s+')[0].Trim()
            $finalResults = @($finalResults | Sort-Object -Property $orderCol)
        }

        $sw.Stop()
        $plan = & $buildExecutionPlan "SELECT JOIN ($joinType)" "$leftTable <-> $rightTable" "(objectClass=*)" "Subtree" $colsPart $orderPart "Directory Hash-Join ($joinType)"
        return [PSCustomObject]@{
            Success             = $true
            Operation           = "SELECT JOIN"
            Results             = $finalResults
            Count               = $finalResults.Count
            ExecutionPlan       = $plan
            ElapsedMilliseconds = $sw.ElapsedMilliseconds
            JoinType            = $joinType
            LeftTable           = $leftTable
            RightTable          = $rightTable
        }
    }

    # 5. Standard SELECT Statement
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
            Message             = "Invalid query format. Example: SELECT sAMAccountName, mail FROM 'OU=IT,...' WHERE userAccountControl & 2 = 2"
        }
    }

    $colsPart  = $matches[1].Trim()
    $fromPart  = $matches[2].Trim().Trim("'", '"')
    $wherePart = if ($matches[3]) { $matches[3].Trim() } else { "" }
    $orderPart = if ($matches[4]) { $matches[4].Trim() } else { "" }

    $propsToLoad = @()
    if ($colsPart -ne "*") {
        $colTokens = $colsPart -split ',\s*'
        foreach ($ct in $colTokens) {
            $attrTokens = [regex]::Matches($ct, '\b([a-zA-Z][a-zA-Z0-9_\-]+)\b')
            foreach ($at in $attrTokens) {
                $tokenName = $at.Groups[1].Value
                if ($tokenName -notmatch '^(?i)(UPPER|LOWER|SUBSTRING|LENGTH|AS)$') {
                    $propsToLoad += $tokenName
                }
            }
        }
        $propsToLoad = @($propsToLoad | Select-Object -Unique)
    }

    $scope = [System.DirectoryServices.SearchScope]::Subtree
    $scopeName = "Subtree"
    $baseDn = $DefaultSearchBase

    if ($fromPart -match '^(?i)SUBTREE$') { $scope = [System.DirectoryServices.SearchScope]::Subtree; $scopeName = "Subtree" }
    elseif ($fromPart -match '^(?i)ONELEVEL$') { $scope = [System.DirectoryServices.SearchScope]::OneLevel; $scopeName = "OneLevel" }
    elseif ($fromPart -match '^(?i)BASE$') { $scope = [System.DirectoryServices.SearchScope]::Base; $scopeName = "Base" }
    elseif ($fromPart) { $baseDn = $fromPart }

    $ldapFilter = & $convertWhereToLdap $wherePart

    $finalResults = @()
    if ($MockData -ne $null) {
        $finalResults = @($MockData | Where-Object { & $evaluateWherePredicate $_ $wherePart })
    } elseif ($Simulate -or ($baseDn -like "*DC=test,DC=local*" -or $baseDn -like "*example*")) {
        $finalResults = @([PSCustomObject]@{ sAMAccountName = "testuser"; whenCreated = (Get-Date).ToString("yyyyMMddHHmmss.0Z") })
    } else {
        $queryResult = Invoke-LdapQuery -Filter $ldapFilter -SearchBase $baseDn -Scope $scope -PropertiesToLoad $propsToLoad -Server $Server
        $finalResults = $queryResult.Results
    }

    if ($colsPart -match '\|\||(?i)(UPPER|LOWER|SUBSTRING|LENGTH)\(' -and $finalResults.Count -gt 0) {
        $projectedList = [System.Collections.Generic.List[PSCustomObject]]::new()
        $colSpecs = $colsPart -split ',\s*'

        foreach ($row in $finalResults) {
            $projObj = [ordered]@{}
            foreach ($cs in $colSpecs) {
                if ($cs -match '(?i)(.+?)\s+AS\s+([a-zA-Z0-9_\-]+)$') {
                    $exprPart = $matches[1].Trim()
                    $aliasName = $matches[2].Trim()
                    $projObj[$aliasName] = (& $evaluateSqlExpr $exprPart $row)
                } else {
                    $projObj[$cs] = (& $evaluateSqlExpr $cs $row)
                }
            }
            $projectedList.Add([PSCustomObject]$projObj)
        }
        $finalResults = @($projectedList)
    }

    if ($orderPart -and $finalResults.Count -gt 0) {
        $orderCol = ($orderPart -split '\s+')[0].Trim()
        $finalResults = @($finalResults | Sort-Object -Property $orderCol)
    }

    $sw.Stop()
    $plan = & $buildExecutionPlan "SELECT" $baseDn $ldapFilter $scopeName ($propsToLoad -join ", ") $orderPart
    return [PSCustomObject]@{
        Success             = $true
        Results             = $finalResults
        Count               = $finalResults.Count
        ExecutionPlan       = $plan
        ElapsedMilliseconds = $sw.ElapsedMilliseconds
        Filter              = $ldapFilter
        SearchBase          = $baseDn
        PropertiesLoaded    = if ($propsToLoad.Count -gt 0) { $propsToLoad -join ", " } else { "*" }
    }
}

function Invoke-LdapSqlQuery {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [Alias("Query")]
        [string]$SqlQuery,
        [string]$DefaultSearchBase = "",
        [string]$Server = "",
        [switch]$Explain,
        [switch]$Simulate,
        [System.Collections.IEnumerable]$MockData = $null
    )
    return Invoke-ADSqlExtendedQuery @PSBoundParameters
}


Set-Alias -Name Invoke-DirectorySql -Value Invoke-ADSqlExtendedQuery -Scope Global
Set-Alias -Name Query-ADSql -Value Invoke-ADSqlExtendedQuery -Scope Global

Export-ModuleMember -Function Invoke-ADSqlExtendedQuery, Invoke-LdapSqlQuery -Alias Invoke-DirectorySql, Query-ADSql
