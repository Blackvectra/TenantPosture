# PSScriptAnalyzerSecurity.psd1
# TenantPosture
# Author: Matthew Levorson
#
# The security rules of PSScriptAnalyzer, run by tools/Invoke-TPSecurityAnalysis.ps1
# (the "PowerShell Security Analysis" CI job) at every severity. Any finding
# fails the build. PSScriptAnalyzerSettings.psd1 also runs these rules, but
# that job fails on Error severity only and these are Warnings, so they were
# reported and never stopped a merge.
#
# Data only; read by Invoke-ScriptAnalyzer -Settings.
@{
    IncludeRules = @(
        # Runs a string as code.
        'PSAvoidUsingInvokeExpression',
        # Credentials in plain text or in the wrong type.
        'PSAvoidUsingPlainTextForPassword',
        'PSAvoidUsingConvertToSecureStringWithPlainText',
        'PSUsePSCredentialType',
        'PSAvoidUsingUsernameAndPasswordParams',
        # Remoting and web requests that send credentials unprotected.
        'PSAvoidUsingAllowUnencryptedAuthentication',
        # MD5 and SHA-1 used as hash algorithms.
        'PSAvoidUsingBrokenHashAlgorithms',
        # A computer name fixed in code: a target the operator did not choose.
        'PSAvoidUsingComputerNameHardcoded'
    )

    Severity = @('Error', 'Warning', 'Information')
}
