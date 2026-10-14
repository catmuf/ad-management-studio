@{
    IncludeDefaultRules = $true

    # Strict Rules Enforced
    Rules = @{
        PSUseApprovedVerbs = @{
            Enable = $true
        }
        PSAvoidUsingEmptyCatchBlock = @{
            Enable = $true
        }
        PSPossibleIncorrectComparisonWithNull = @{
            Enable = $true
        }
        PSAvoidAssignmentToAutomaticVariable = @{
            Enable = $true
        }
        PSAvoidUsingInvokeExpression = @{
            Enable = $true
        }
    }

    # Excluded style rules that conflict with AD domain modeling or CLI/test outputs
    ExcludeRules = @(
        'PSAvoidUsingWriteHost',
        'PSUseSingularNouns',
        'PSUseShouldProcessForStateChangingFunctions',
        'PSAvoidUsingPositionalParameters',
        'PSUseOutputTypeCorrectly'
    )
}
