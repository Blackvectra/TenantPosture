#Requires -Version 7.0
#
# TP.MicrosoftChanges.Tests.ps1
# TenantPosture
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Pins Config/microsoft-changes.json, the sourced catalog of upcoming
# Microsoft changes behind the onboarding report section "Coming Microsoft
# changes (2026-2027)". The file is reference data: it creates no finding and
# moves no score, so what it can get wrong is its own content. Every entry must
# carry a date in a known shape and a known qualifier, a source on an official
# Microsoft host, and only control ids that exist; and the dates must sit in
# the window the inclusionRule states, measured from the file's own
# sourceRetrieved, so a change that has already happened is never presented as
# coming.
#
# Data keys: none. Reads Config/microsoft-changes.json and Config/controls.json.

Describe 'Microsoft changes catalog (Config/microsoft-changes.json)' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        $script:Path = Join-Path $script:RepoRoot 'Config/microsoft-changes.json'
        $script:Catalog = Get-Content -LiteralPath $script:Path -Raw | ConvertFrom-Json -ErrorAction Stop
        $script:Changes = @($script:Catalog.changes)

        $controls = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Config/controls.json') -Raw | ConvertFrom-Json
        $rows = if ($controls -is [array]) { $controls } elseif ($controls.PSObject.Properties['controls']) { $controls.controls } else { $controls.Controls }
        $script:ControlIds = [System.Collections.Generic.HashSet[string]]::new([string[]]@($rows | ForEach-Object { $_.ControlId }), [System.StringComparer]::Ordinal)

        $script:AllowedQualifiers = @('On', 'By', 'Starting', 'Expected')
        $script:AllowedHosts = @('learn.microsoft.com', 'techcommunity.microsoft.com', 'www.microsoft.com')
        $script:Required = @('Id', 'Title', 'Date', 'DateQualifier', 'Summary', 'Impact', 'RelatedControls', 'SourceUrl', 'SourceTitle')
        $script:WindowEnd = [datetime]::new(2027, 12, 31)

        # The first and last day a Date value covers: a full date covers
        # itself, a YYYY-MM month covers the whole month.
        function script:Get-ChangeDateRange {
            param([string]$Value)
            $inv = [cultureinfo]::InvariantCulture
            $d = [datetime]::MinValue
            if ($Value -cmatch '\A\d{4}-\d{2}-\d{2}\z') {
                if ([datetime]::TryParseExact($Value, 'yyyy-MM-dd', $inv, [System.Globalization.DateTimeStyles]::None, [ref]$d)) { return @($d, $d) }
            } elseif ($Value -cmatch '\A\d{4}-\d{2}\z') {
                if ([datetime]::TryParseExact($Value, 'yyyy-MM', $inv, [System.Globalization.DateTimeStyles]::None, [ref]$d)) { return @($d, $d.AddMonths(1).AddDays(-1)) }
            }
            return $null
        }
    }

    It 'has the top-level fields' {
        foreach ($k in 'version', 'sourceRetrieved', 'purpose', 'inclusionRule', 'changes') {
            $script:Catalog.PSObject.Properties[$k] | Should -Not -BeNullOrEmpty -Because "the catalog must carry '$k'"
        }
        $script:Catalog.sourceRetrieved | Should -Match '\A\d{4}-\d{2}-\d{2}\z'
        $script:Changes.Count | Should -BeGreaterThan 0
    }

    It 'states the window it applies in its inclusion rule' {
        $script:Catalog.inclusionRule | Should -Match 'sourceRetrieved'
        $script:Catalog.inclusionRule | Should -Match '2027-12-31'
    }

    It 'every entry carries every required field, non-empty' {
        foreach ($c in $script:Changes) {
            foreach ($k in $script:Required) {
                $prop = $c.PSObject.Properties[$k]
                $prop | Should -Not -BeNullOrEmpty -Because "entry '$($c.Id)' must carry '$k'"
                if ($k -ne 'RelatedControls') {
                    [string]$prop.Value | Should -Not -BeNullOrEmpty -Because "entry '$($c.Id)' has an empty '$k'"
                }
            }
            ($c.RelatedControls -is [array]) | Should -BeTrue -Because "entry '$($c.Id)' must carry RelatedControls as an array (empty when no control judges the setting)"
        }
    }

    It 'every Id is a short kebab-case id and no Id repeats' {
        foreach ($c in $script:Changes) {
            $c.Id | Should -MatchExactly '\A[a-z0-9]+(-[a-z0-9]+)*\z'
        }
        $dupes = @($script:Changes | Group-Object Id | Where-Object Count -gt 1 | ForEach-Object Name)
        $dupes | Should -BeNullOrEmpty
    }

    It 'every Date is YYYY-MM-DD or YYYY-MM and a real date' {
        foreach ($c in $script:Changes) {
            Get-ChangeDateRange -Value ([string]$c.Date) | Should -Not -BeNullOrEmpty -Because "entry '$($c.Id)' has Date '$($c.Date)'"
        }
    }

    It 'every DateQualifier is one of the allowed values' {
        foreach ($c in $script:Changes) {
            $c.DateQualifier | Should -BeIn $script:AllowedQualifiers -Because "entry '$($c.Id)'"
        }
    }

    It 'every date falls on or after sourceRetrieved and no later than 2027-12-31' {
        $retrieved = (Get-ChangeDateRange -Value ([string]$script:Catalog.sourceRetrieved))[0]
        foreach ($c in $script:Changes) {
            $range = Get-ChangeDateRange -Value ([string]$c.Date)
            $range[1] | Should -BeGreaterOrEqual $retrieved -Because "entry '$($c.Id)' ($($c.Date)) is already in the past as of sourceRetrieved"
            $range[0] | Should -BeLessOrEqual $script:WindowEnd -Because "entry '$($c.Id)' ($($c.Date)) is past the window"
        }
    }

    It 'entries are listed in date order' {
        $starts = @($script:Changes | ForEach-Object { (Get-ChangeDateRange -Value ([string]$_.Date))[0] })
        for ($i = 1; $i -lt $starts.Count; $i++) {
            $starts[$i] | Should -BeGreaterOrEqual $starts[$i - 1] -Because "entry '$($script:Changes[$i].Id)' is out of order"
        }
    }

    It 'every SourceUrl is https on an official Microsoft host' {
        foreach ($c in $script:Changes) {
            $u = $null
            [uri]::TryCreate([string]$c.SourceUrl, [UriKind]::Absolute, [ref]$u) | Should -BeTrue -Because "entry '$($c.Id)'"
            $u.Scheme | Should -BeExactly 'https'
            $u.Host | Should -BeIn $script:AllowedHosts -Because "entry '$($c.Id)' cites $($u.Host)"
            $u.UserInfo | Should -BeNullOrEmpty
            $u.IsDefaultPort | Should -BeTrue
        }
    }

    It 'every RelatedControls entry is a control in controls.json, listed once' {
        foreach ($c in $script:Changes) {
            $ids = @($c.RelatedControls | Where-Object { $null -ne $_ })
            foreach ($id in $ids) {
                $script:ControlIds.Contains([string]$id) | Should -BeTrue -Because "entry '$($c.Id)' names '$id', which controls.json does not define"
            }
            @($ids | Select-Object -Unique).Count | Should -Be $ids.Count -Because "entry '$($c.Id)' repeats a control"
        }
    }
}
