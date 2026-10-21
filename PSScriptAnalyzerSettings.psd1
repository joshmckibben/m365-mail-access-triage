@{
    Severity     = @('Error', 'Warning')

    # Interactive analyst script: Write-Host is the UI. The helpers are small inline functions inside
    # one pasted script block, not a module's public API, so the cmdlet-design rules don't apply.
    ExcludeRules = @(
        'PSAvoidUsingWriteHost'
        'PSUseApprovedVerbs'
        'PSUseShouldProcessForStateChangingFunctions'
        'PSUseSingularNouns'
    )

    Rules        = @{
        PSUseCompatibleSyntax = @{
            Enable         = $true
            TargetVersions = @('5.1', '7.2')
        }
    }
}
