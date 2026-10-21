#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

# Each scenario runs the script the way an analyst does: its text pasted into a fresh console
# (emulated with Invoke-Expression in a new pwsh process). Every tenant / UI cmdlet is a stub that
# records its calls, so tests can assert exactly what would have been created in the tenant.

BeforeAll {
    . (Join-Path $PSScriptRoot 'New-FakeAuditExport.ps1')
    $script:ScriptPath = Join-Path $PSScriptRoot '..' 'Invoke-MailAccessTriage.ps1'
    # The console the script is "pasted" into. CI also sets TRIAGE_TEST_SHELL=powershell.exe to cover Windows PowerShell 5.1.
    $script:Pwsh = if ($env:TRIAGE_TEST_SHELL) { $env:TRIAGE_TEST_SHELL } else { (Get-Process -Id $PID).Path }

    function Invoke-Triage {
        param(
            [Parameter(Mandatory)][string]$CsvPath,
            [string[]]$SelectIPs = @($script:BadIP),
            [string[]]$Answers = @(),
            [string]$ExoTenant = $script:FakeTenant,
            [string]$IppsTenant = $script:FakeTenant,
            [string]$PreConnectedTenant = ''
        )

        $outRoot = Join-Path $TestDrive ([guid]::NewGuid().ToString())
        $resultFile = Join-Path $TestDrive "$([guid]::NewGuid()).json"
        $harness = Join-Path $TestDrive "$([guid]::NewGuid()).ps1"
        $answersLiteral = ($Answers | ForEach-Object { "'" + ($_ -replace "'", "''") + "'" }) -join ', '
        $selectLiteral = ($SelectIPs | ForEach-Object { "'$_'" }) -join ', '

        @"
`$env:M365TRIAGE_OUTROOT = '$outRoot'
`$global:Answers   = [System.Collections.Generic.List[string]]::new([string[]]@($answersLiteral))
`$global:Prompts   = [System.Collections.Generic.List[string]]::new()
`$global:Calls     = [System.Collections.Generic.List[object]]::new()
`$global:Conn      = [System.Collections.Generic.List[object]]::new()
`$global:Cases     = [System.Collections.Generic.List[string]]::new()
`$global:SelectIPs = @($selectLiteral)
`$global:ExoTenant = '$ExoTenant'
`$global:IppsTenant = '$IppsTenant'

function global:Log([string]`$Name, [hashtable]`$Params) { `$global:Calls.Add([pscustomobject]@{ Name = `$Name; Params = `$Params }) }

function global:Read-Host { param([Parameter(Position = 0)]`$Prompt)
    `$global:Prompts.Add("`$Prompt")
    if (`$global:Answers.Count -eq 0) { throw "Unexpected prompt: `$Prompt" }
    `$a = `$global:Answers[0]; `$global:Answers.RemoveAt(0); `$a }
function global:Out-GridView { param([Parameter(ValueFromPipeline)]`$InputObject, `$Title, [switch]`$PassThru)
    begin { `$all = [System.Collections.Generic.List[object]]::new() }
    process { `$all.Add(`$InputObject) }
    end { `$all | Where-Object { `$global:SelectIPs -contains `$_.IP } } }
function global:Get-ConnectionInformation { [CmdletBinding()] param() `$global:Conn.ToArray() }
function global:Connect-ExchangeOnline { param(`$ShowBanner, `$UserPrincipalName, [switch]`$DisableWAM)
    Log 'Connect-ExchangeOnline' `$PSBoundParameters
    `$global:Conn.Add([pscustomobject]@{ ConnectionId = [guid]::NewGuid().ToString(); State = 'Connected'; IsEopSession = `$false; TenantID = `$global:ExoTenant; UserPrincipalName = `$UserPrincipalName }) }
function global:Connect-IPPSSession { param(`$ShowBanner, `$UserPrincipalName, [switch]`$DisableWAM, [switch]`$EnableSearchOnlySession)
    Log 'Connect-IPPSSession' `$PSBoundParameters
    `$global:Conn.Add([pscustomobject]@{ ConnectionId = [guid]::NewGuid().ToString(); State = 'Connected'; IsEopSession = `$true; TenantID = `$global:IppsTenant; UserPrincipalName = `$UserPrincipalName }) }
function global:Disconnect-ExchangeOnline { [CmdletBinding(SupportsShouldProcess)] param(`$ConnectionId)
    Log 'Disconnect-ExchangeOnline' @{ ConnectionId = `$ConnectionId }
    `$keep = @(`$global:Conn | Where-Object ConnectionId -ne `$ConnectionId); `$global:Conn.Clear(); `$keep | ForEach-Object { `$global:Conn.Add(`$_) } }
function global:Get-MailboxFolderStatistics { param(`$Identity)
    Log 'Get-MailboxFolderStatistics' @{ Identity = `$Identity }
    [pscustomobject]@{ FolderPath = '/Inbox'; FolderId = [Convert]::ToBase64String([byte[]](0..59)); ItemsInFolder = 42 } }
function global:Get-ComplianceCase { [CmdletBinding()] param(`$Identity)
    if (`$global:Cases -contains `$Identity) { [pscustomobject]@{ Name = `$Identity } } else { throw "Case `$Identity couldn't be found" } }
function global:New-ComplianceCase { param(`$Name) Log 'New-ComplianceCase' @{ Name = `$Name }; `$global:Cases.Add(`$Name) }
function global:New-ComplianceSearch { param(`$Name, `$Case, `$ExchangeLocation, `$ContentMatchQuery) Log 'New-ComplianceSearch' `$PSBoundParameters }
function global:Start-ComplianceSearch { param(`$Identity) Log 'Start-ComplianceSearch' @{ Identity = `$Identity } }
function global:Get-ComplianceSearch { [CmdletBinding()] param(`$Identity, `$Case)
    [pscustomobject]@{ Name = `$Identity; Status = 'Completed'; Items = 3; Size = 1024; Errors = `$null } }
function global:Set-Clipboard { param(`$Value) `$global:Clipboard = `$Value }
function global:Start-Sleep { param(`$Seconds) }
function global:Invoke-Item { param(`$Path) }

if ('$PreConnectedTenant') {
    `$global:Conn.Add([pscustomobject]@{ ConnectionId = 'stale-session'; State = 'Connected'; IsEopSession = `$false; TenantID = '$PreConnectedTenant'; UserPrincipalName = 'admin@other-client.example' })
}

`$err = `$null
try { Invoke-Expression (Get-Content -LiteralPath '$($script:ScriptPath)' -Raw) *>&1 | Out-String | Set-Variable -Name Console -Scope Global }
catch { `$err = `$_.Exception.Message }

`$outDir = Get-ChildItem -LiteralPath '$outRoot' -Directory -ErrorAction SilentlyContinue | Select-Object -First 1
[pscustomobject]@{
    Error      = `$err
    Console    = `$global:Console
    Calls      = @(`$global:Calls | ForEach-Object { [pscustomobject]@{ Name = `$_.Name; Params = `$_.Params } })
    Prompts    = @(`$global:Prompts)
    Unanswered = `$global:Answers.Count
    Clipboard  = `$global:Clipboard
    OutDir     = if (`$outDir) { `$outDir.FullName } else { `$null }
    EapAfter   = "`$ErrorActionPreference"
    Leaked     = @('run', 'AdminUpn', 'CaseName', 'events', 'badSet' | Where-Object { Get-Variable -Name `$_ -Scope Global -ErrorAction SilentlyContinue })
} | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath '$resultFile'
"@ | Set-Content -LiteralPath $harness -Encoding utf8

        & $script:Pwsh -NoProfile -NonInteractive -Command ". '$harness'" | Out-Null
        $r = Get-Content -LiteralPath $resultFile -Raw | ConvertFrom-Json
        $r | Add-Member -NotePropertyName CallNames -NotePropertyValue @($r.Calls | ForEach-Object Name)
        $r
    }

    function Import-Out([object]$Result, [string]$Name) {
        $p = Join-Path $Result.OutDir $Name
        if (Test-Path -LiteralPath $p) { @(Import-Csv -LiteralPath $p) } else { @() }
    }

    $script:HappyAnswers = { param($csv) @($csv, 'y', 'TEST-CASE', 'admin@contoso.example') }
}

Describe 'Happy path (pasted into a console)' {
    BeforeAll {
        $csv = Join-Path $TestDrive 'audit.csv'
        New-FakeAuditExport -Path $csv
        $script:R = Invoke-Triage -CsvPath $csv -Answers (& $script:HappyAnswers $csv)
    }

    It 'Completes without error and answers every prompt' {
        $R.Error | Should -BeNullOrEmpty
        $R.Unanswered | Should -Be 0
    }

    It 'Leaves nothing behind in the console session' {
        $R.EapAfter | Should -Be 'Continue'
        @($R.Leaked) | Should -BeNullOrEmpty
    }

    It 'Lists bad-IP Bind messages once each, excluding legitimate IPs and duplicate records' {
        $items = Import-Out $R 'accessed_items.csv'
        $ids = @($items | Where-Object InternetMessageId | ForEach-Object InternetMessageId | Sort-Object)
        $ids | Should -Be @('<msg1@contoso.example>', '<msg2@contoso.example>', '<msg3@contoso.example>')
        @($items | Where-Object AccessType -eq 'Sync').Count | Should -Be 1
    }

    It 'Copies the IPs (not "(none)") to the clipboard and ip_list.txt before the grid, in grid order' {
        $expected = @((Import-Out $R 'ip_summary.csv') | Where-Object IP -ne '(none)' | ForEach-Object IP)
        $expected | Should -Contain $script:BadIP
        @($R.Clipboard -split "\r?\n") | Should -Be $expected
        @(Get-Content (Join-Path $R.OutDir 'ip_list.txt')) | Should -Be $expected
        $R.Console | Should -Match 'Copied \d+ IPs to the clipboard'
    }

    It 'Normalises IPv6 with a port and IPv4 with a port' {
        $ips = (Import-Out $R 'ip_summary.csv').IP
        $ips | Should -Contain '2001:db8::1'
        $ips | Should -Not -Contain "$($script:BadIP):51234"
    }

    It 'Converts the Sync folder to the documented folderid (bytes 23..46 as hex)' {
        $expected = -join ((23..46) | ForEach-Object { ([byte]$_).ToString('X2') })
        $sync = Import-Out $R 'sync_folders.csv'
        $sync[0].FolderQueryId | Should -Be $expected
        $sync[0].Source | Should -Be 'EXO path match'
    }

    It 'Signs in with the prompted admin UPN and -DisableWAM, and IPPS with -EnableSearchOnlySession' {
        $exo = $R.Calls | Where-Object Name -eq 'Connect-ExchangeOnline'
        $exo.Params.UserPrincipalName | Should -Be 'admin@contoso.example'
        $exo.Params.DisableWAM | Should -BeTrue
        $ipps = $R.Calls | Where-Object Name -eq 'Connect-IPPSSession'
        $ipps.Params.EnableSearchOnlySession | Should -BeTrue
        $ipps.Params.UserPrincipalName | Should -Be 'admin@contoso.example'
    }

    It 'Creates one case and a Bind + Sync search scoped to the victim mailbox' {
        @($R.CallNames | Where-Object { $_ -eq 'New-ComplianceCase' }).Count | Should -Be 1
        $searches = @($R.Calls | Where-Object Name -eq 'New-ComplianceSearch')
        $searches.Count | Should -Be 2
        $searches.Params.Case | Sort-Object -Unique | Should -Be 'TEST-CASE'
        $searches.Params.ExchangeLocation | Sort-Object -Unique | Should -Be $script:Victim
        ($searches | Where-Object { $_.Params.Name -like '*_Bind_01' }).Params.ContentMatchQuery | Should -Match 'InternetMessageId:"<msg1@contoso.example>"'
        @($R.CallNames | Where-Object { $_ -eq 'Start-ComplianceSearch' }).Count | Should -Be 2
    }

    It 'Makes no tenant changes other than the case and searches' {
        $allowed = 'Connect-ExchangeOnline', 'Connect-IPPSSession', 'Disconnect-ExchangeOnline', 'Get-MailboxFolderStatistics',
                   'New-ComplianceCase', 'New-ComplianceSearch', 'Start-ComplianceSearch'
        @($R.CallNames | Where-Object { $allowed -notcontains $_ }) | Should -BeNullOrEmpty
    }

    It 'Reports bad-IP OneDrive downloads' {
        $files = Import-Out $R 'files_accessed.csv'
        $files.Count | Should -Be 1
        $files[0].FileName | Should -Be 'Q3 invoices.xlsx'
    }

    It 'Flags the device registered during the attack, and drops admin-only noise' {
        $entra = Import-Out $R 'entra_changes.csv'
        $entra.Operation | Should -Not -Contain 'Update user.'
        $attackDevice = @($entra | Where-Object { $_.Category -eq 'Device' -and $_.InAttackWindow -eq 'True' })
        $attackDevice.Count | Should -Be 1
        $attackDevice[0].Targets | Should -Be 'DESKTOP-ATTACKER'
        @($entra | Where-Object { $_.Category -eq 'Device' -and $_.InAttackWindow -eq 'False' }).Count | Should -Be 1
        @($entra | Where-Object Category -eq 'MFA').Count | Should -Be 1
        $R.Console | Should -Match 'DEVICE activity in the attack window'
    }
}

Describe 'Tenant safety' {
    It 'Stops before creating anything when the Purview sign-in is for another tenant' {
        $csv = Join-Path $TestDrive 'audit-wrong.csv'
        New-FakeAuditExport -Path $csv
        $r = Invoke-Triage -CsvPath $csv -Answers (& $script:HappyAnswers $csv) -IppsTenant '22222222-2222-2222-2222-222222222222'
        $r.Error | Should -Match 'WRONG TENANT'
        $r.CallNames | Should -Not -Contain 'New-ComplianceCase'
        $r.CallNames | Should -Not -Contain 'New-ComplianceSearch'
        $r.CallNames | Should -Contain 'Disconnect-ExchangeOnline'
    }

    It 'Stops at the first connection when Exchange Online is signed in to another tenant' {
        $csv = Join-Path $TestDrive 'audit-wrong-exo.csv'
        New-FakeAuditExport -Path $csv
        $r = Invoke-Triage -CsvPath $csv -Answers (& $script:HappyAnswers $csv) -ExoTenant '22222222-2222-2222-2222-222222222222'
        $r.Error | Should -Match 'WRONG TENANT'
        $r.CallNames | Should -Not -Contain 'Get-MailboxFolderStatistics'
        $r.CallNames | Should -Not -Contain 'New-ComplianceCase'
    }

    It 'Disconnects a leftover session from another client instead of reusing it' {
        $csv = Join-Path $TestDrive 'audit-stale.csv'
        New-FakeAuditExport -Path $csv
        $r = Invoke-Triage -CsvPath $csv -Answers (& $script:HappyAnswers $csv) -PreConnectedTenant '33333333-3333-3333-3333-333333333333'
        $r.Error | Should -BeNullOrEmpty
        ($r.Calls | Where-Object Name -eq 'Disconnect-ExchangeOnline').Params.ConnectionId | Should -Contain 'stale-session'
        $r.CallNames | Should -Contain 'New-ComplianceCase'
    }

    It 'Refuses an export that mixes tenants' {
        $csv = Join-Path $TestDrive 'audit-mixed.csv'
        New-FakeAuditExport -Path $csv -MixedTenants
        $r = Invoke-Triage -CsvPath $csv -Answers @($csv)
        $r.Error | Should -Match 'tenants'
        @($r.Calls) | Should -BeNullOrEmpty
    }

    It 'Doesn''t carry the admin UPN over to the next run in the same console' {
        $csv = Join-Path $TestDrive 'audit-two-runs.csv'
        New-FakeAuditExport -Path $csv
        $r = Invoke-Triage -CsvPath $csv -Answers (& $script:HappyAnswers $csv)
        @($r.Leaked) | Should -Not -Contain 'run'
        @($r.Prompts | Where-Object { $_ -eq 'Admin UPN' }).Count | Should -Be 1
    }
}

Describe 'Analyst guard rails' {
    # Declining searches still connects to Exchange Online to turn Sync folders into folderid: queries,
    # so these runs are asked for the admin account.
    It 'Removes (none) from the bad IPs unless the analyst confirms it' {
        $csv = Join-Path $TestDrive 'audit-none.csv'
        New-FakeAuditExport -Path $csv
        $r = Invoke-Triage -CsvPath $csv -SelectIPs @($script:BadIP, '(none)') -Answers @($csv, 'n', 'n', 'admin@contoso.example')
        $r.Error | Should -BeNullOrEmpty
        $activity = Import-Out $r 'badip_all_activity.csv'
        $activity.IP | Should -Not -Contain '(none)'
        $r.Console | Should -Match "'\(none\)' removed"
    }

    It 'Warns clearly, and makes no tenant calls, when the export has no MailItemsAccessed and searches are declined' {
        $csv = Join-Path $TestDrive 'audit-nomia.csv'
        New-FakeAuditExport -Path $csv -NoMailItemsAccessed
        $r = Invoke-Triage -CsvPath $csv -Answers @($csv, 'n')
        $r.Error | Should -BeNullOrEmpty
        $r.Console | Should -Match 'No MailItemsAccessed events'
        $r.Console | Should -Match 'NOT evidence that no mail was read'
        Get-Content (Join-Path $r.OutDir 'run_summary.txt') -Raw | Should -Match 'NONE - mail access may not be logged'
        @($r.Calls) | Should -BeNullOrEmpty
    }

    It 'Re-prompts for a CSV path that doesn''t exist, and strips quotes' {
        $csv = Join-Path $TestDrive 'audit-quotes.csv'
        New-FakeAuditExport -Path $csv
        $r = Invoke-Triage -CsvPath $csv -Answers @('C:\nope\missing.csv', "`"$csv`"", 'n', 'admin@contoso.example')
        $r.Error | Should -BeNullOrEmpty
        @($r.Prompts | Where-Object { $_ -eq 'Audit CSV path' }).Count | Should -Be 2
    }
}
