#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

# Same approach as Invoke-MailAccessTriage.Tests.ps1: each scenario pastes the script into a fresh console
# process with recording stubs. Search-UnifiedAuditLog is a stub over a fake record set that honours the
# IP filter, the time window, paging (small pages, repeated records) and the 50,000-result session cap.
# All addresses are reserved / fictional (example domains, TEST-NET IPs).

BeforeAll {
    $script:ScriptPath = Join-Path $PSScriptRoot '..' 'Invoke-TenantIPSweep.ps1'
    $script:Pwsh = if ($env:TRIAGE_TEST_SHELL) { $env:TRIAGE_TEST_SHELL } else { (Get-Process -Id $PID).Path }

    $script:Tenant = '11111111-1111-1111-1111-111111111111'
    $script:Bad1 = '203.0.113.10'
    $script:Bad2 = '198.51.100.77'
    $script:FirstSeen = (Get-Date).ToUniversalTime().Date.AddDays(-5)

    # A fake UAL record. MatchIp is what the stub's server-side IP filter matches on; ClientIP is what
    # the record itself says (normally the same - different only to test the mismatch flag).
    function New-UalRecord {
        param([string]$User, [string]$Operation, [string]$Workload, [datetime]$TimeUtc, [string]$MatchIp, [string]$ClientIP = $MatchIp, [hashtable]$Extra = @{})
        $id = [guid]::NewGuid().ToString()
        $data = [ordered]@{ Id = $id; CreationTime = $TimeUtc.ToString('yyyy-MM-ddTHH:mm:ss'); Operation = $Operation; Workload = $Workload; UserId = $User; OrganizationId = $script:Tenant }
        $ipField = if ($Workload -eq 'Exchange' -and $Operation -eq 'MailItemsAccessed') { 'ClientIPAddress' } else { 'ClientIP' }
        $data[$ipField] = $ClientIP
        foreach ($k in $Extra.Keys) { $data[$k] = $Extra[$k] }
        [pscustomobject]@{
            MatchIp = $MatchIp; TimeUtc = $TimeUtc.ToString('o')
            Identity = $id; CreationDate = $TimeUtc.ToString('o'); RecordType = $Workload; Operations = $Operation; UserIds = $User
            AuditData = ($data | ConvertTo-Json -Depth 6 -Compress)
        }
    }

    function New-StandardData {
        $t = $script:FirstSeen.AddHours(9)
        @(
            New-UalRecord 'alex@contoso.example'  'MailItemsAccessed' 'Exchange' $t $script:Bad1
            New-UalRecord 'bob@contoso.example'   'UserLoggedIn' 'AzureActiveDirectory' $t.AddDays(1) $script:Bad1
            New-UalRecord 'bob@contoso.example'   'MailItemsAccessed' 'Exchange' $t.AddDays(1).AddMinutes(5) $script:Bad2 -ClientIP "$($script:Bad2):51234"
            New-UalRecord 'carol@contoso.example' 'UserLoginFailed' 'AzureActiveDirectory' $t.AddDays(2) $script:Bad2 -Extra @{ LogonError = 'InvalidUserNameOrPassword' }
            New-UalRecord 'erin@contoso.example'  'FileAccessed' 'SharePoint' $t.AddDays(2) $script:Bad1 -ClientIP '192.0.2.99'
            New-UalRecord 'alex@contoso.example'  'MailItemsAccessed' 'Exchange' $script:FirstSeen.AddDays(-30) $script:Bad1   # before the window
            New-UalRecord 'dave@contoso.example'  'UserLoggedIn' 'AzureActiveDirectory' $t '192.0.2.50'                         # not a bad IP
        )
    }

    function Invoke-Sweep {
        param(
            [string[]]$Answers,
            [object[]]$Data = (New-StandardData),
            [string[]]$AcceptedDomains = @('contoso.example', 'contoso.onmicrosoft.example'),
            [string]$Clipboard = '',
            [int]$StubPageSize = 2,
            [double]$CapAboveDays = 0
        )
        $resultFile = Join-Path $TestDrive "$([guid]::NewGuid()).json"
        $dataFile = Join-Path $TestDrive "$([guid]::NewGuid()).json"
        $harness = Join-Path $TestDrive "$([guid]::NewGuid()).ps1"
        $outRoot = Join-Path $TestDrive ([guid]::NewGuid().ToString())
        ConvertTo-Json -InputObject @($Data) -Depth 6 | Set-Content -LiteralPath $dataFile -Encoding utf8
        $answersLiteral = ($Answers | ForEach-Object { "'" + ($_ -replace "'", "''") + "'" }) -join ', '
        $domainsLiteral = ($AcceptedDomains | ForEach-Object { "'$_'" }) -join ', '

        @"
`$env:M365TRIAGE_OUTROOT = '$outRoot'
`$global:Answers = [System.Collections.Generic.List[string]]::new([string[]]@($answersLiteral))
`$global:Prompts = [System.Collections.Generic.List[string]]::new()
`$global:Calls   = [System.Collections.Generic.List[object]]::new()
`$global:Conn    = [System.Collections.Generic.List[object]]::new()
`$global:Data    = @(Get-Content -LiteralPath '$dataFile' -Raw | ConvertFrom-Json)
`$global:Offsets = @{}

function global:Log([string]`$Name, [hashtable]`$Params) { `$global:Calls.Add([pscustomobject]@{ Name = `$Name; Params = `$Params }) }
function global:Read-Host { param([Parameter(Position = 0)]`$Prompt)
    `$global:Prompts.Add("`$Prompt")
    if (`$global:Answers.Count -eq 0) { throw "Unexpected prompt: `$Prompt" }
    `$a = `$global:Answers[0]; `$global:Answers.RemoveAt(0); `$a }
function global:Get-Clipboard { '$Clipboard' -split ';' }
function global:Get-ConnectionInformation { [CmdletBinding()] param() `$global:Conn.ToArray() }
function global:Connect-ExchangeOnline { param(`$ShowBanner, `$UserPrincipalName, [switch]`$DisableWAM)
    Log 'Connect-ExchangeOnline' `$PSBoundParameters
    `$global:Conn.Add([pscustomobject]@{ ConnectionId = 'c1'; State = 'Connected'; IsEopSession = `$false; TenantID = '$($script:Tenant)'; UserPrincipalName = `$UserPrincipalName }) }
function global:Disconnect-ExchangeOnline { [CmdletBinding(SupportsShouldProcess)] param(`$ConnectionId)
    Log 'Disconnect-ExchangeOnline' @{ ConnectionId = `$ConnectionId }
    `$keep = @(`$global:Conn | Where-Object ConnectionId -ne `$ConnectionId); `$global:Conn.Clear(); `$keep | ForEach-Object { `$global:Conn.Add(`$_) } }
function global:Get-AcceptedDomain { Log 'Get-AcceptedDomain' @{}; @($domainsLiteral) | ForEach-Object { [pscustomobject]@{ DomainName = `$_ } } }
function global:Get-OrganizationConfig { Log 'Get-OrganizationConfig' @{}; [pscustomobject]@{ DisplayName = 'Contoso (fake)' } }
function global:Search-UnifiedAuditLog { [CmdletBinding()] param(`$StartDate, `$EndDate, [string[]]`$IPAddresses, `$SessionId, `$SessionCommand, `$ResultSize)
    Log 'Search-UnifiedAuditLog' @{ StartDate = ([datetime]`$StartDate).ToString('o'); EndDate = ([datetime]`$EndDate).ToString('o'); IPAddresses = `$IPAddresses; SessionId = `$SessionId }
    `$s = [datetime]`$StartDate; `$e = [datetime]`$EndDate
    if ($CapAboveDays -gt 0 -and (`$e - `$s).TotalDays -gt $CapAboveDays) {
        return [pscustomobject]@{ ResultCount = 50000; AuditData = '{}'; Identity = 'capped' }
    }
    `$hits = @(`$global:Data | Where-Object { `$IPAddresses -contains `$_.MatchIp -and [datetime]`$_.TimeUtc -ge `$s -and [datetime]`$_.TimeUtc -lt `$e })
    if (-not `$global:Offsets.ContainsKey(`$SessionId)) { `$global:Offsets[`$SessionId] = 0 }
    `$off = `$global:Offsets[`$SessionId]
    `$page = @(`$hits | Select-Object -Skip `$off -First $StubPageSize)
    `$global:Offsets[`$SessionId] = `$off + `$page.Count
    if (`$page.Count -and `$off -gt 0) { `$page = @(`$hits[`$off - 1]) + `$page }    # ReturnLargeSet repeats records
    `$page | ForEach-Object { `$_ | Add-Member -NotePropertyName ResultCount -NotePropertyValue `$hits.Count -Force -PassThru } }
function global:Start-Sleep { param(`$Seconds) }
function global:Invoke-Item { param(`$Path) }

`$err = `$null
try { Invoke-Expression (Get-Content -LiteralPath '$($script:ScriptPath)' -Raw) *>&1 | Out-String | Set-Variable -Name Console -Scope Global }
catch { `$err = `$_.Exception.Message }

`$outDir = Get-ChildItem -LiteralPath '$outRoot' -Directory -ErrorAction SilentlyContinue | Select-Object -First 1
[pscustomobject]@{
    Error      = `$err
    Console    = `$global:Console
    Calls      = @(`$global:Calls)
    Prompts    = @(`$global:Prompts)
    Unanswered = `$global:Answers.Count
    OutDir     = if (`$outDir) { `$outDir.FullName } else { `$null }
    EapAfter   = "`$ErrorActionPreference"
    Leaked     = @('ips', 'events', 'records', 'adminUpn', 'domain' | Where-Object { Get-Variable -Name `$_ -Scope Global -ErrorAction SilentlyContinue })
    ConnLeft   = `$global:Conn.Count
} | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath '$resultFile'
"@ | Set-Content -LiteralPath $harness -Encoding utf8

        & $script:Pwsh -NoProfile -NonInteractive -Command ". '$harness'" | Out-Null
        $r = Get-Content -LiteralPath $resultFile -Raw | ConvertFrom-Json
        $r | Add-Member -NotePropertyName CallNames -NotePropertyValue @($r.Calls | ForEach-Object Name)
        $r | Add-Member -NotePropertyName Searches -NotePropertyValue @($r.Calls | Where-Object Name -eq 'Search-UnifiedAuditLog')
        $r
    }

    function Import-Out([object]$Result, [string]$Name) {
        $p = Join-Path $Result.OutDir $Name
        if (Test-Path -LiteralPath $p) { @(Import-Csv -LiteralPath $p) } else { @() }
    }

    # IPs (two lines, then blank), first seen, domain, admin, known victim, confirm
    $script:Std = @($script:Bad1, "$($script:Bad2), not-an-ip", '', $script:FirstSeen.ToString('yyyy-MM-dd'),
                    'contoso.example', 'admin@contoso.example', 'alex@contoso.example', 'y')
}

Describe 'Sweep: happy path (pasted into a console)' {
    BeforeAll { $script:R = Invoke-Sweep -Answers $script:Std }

    It 'Completes, answers every prompt, leaves nothing behind and disconnects' {
        $R.Error | Should -BeNullOrEmpty
        $R.Unanswered | Should -Be 0
        $R.EapAfter | Should -Be 'Continue'
        @($R.Leaked) | Should -BeNullOrEmpty
        $R.ConnLeft | Should -Be 0
    }

    It 'Is read-only: only connection, domain/org lookups and audit searches' {
        $allowed = 'Connect-ExchangeOnline', 'Disconnect-ExchangeOnline', 'Get-AcceptedDomain', 'Get-OrganizationConfig', 'Search-UnifiedAuditLog'
        @($R.CallNames | Where-Object { $allowed -notcontains $_ }) | Should -BeNullOrEmpty
    }

    It 'Ignores input that isn''t an IP and searches the valid ones' {
        $R.Console | Should -Match 'Ignored \(not IP addresses\): not-an-ip'
        @($R.Searches[0].Params.IPAddresses) | Should -Be @($script:Bad1, $script:Bad2)
    }

    It 'Searches from 14 days before the first-seen date' {
        ([datetime]$R.Searches[0].Params.StartDate).ToUniversalTime() | Should -Be $script:FirstSeen.AddDays(-14)
    }

    It 'Pages through results and removes repeated records' {
        @($R.Searches).Count | Should -BeGreaterThan 1
        (Import-Out $R 'ip_hits.csv').Count | Should -Be 5
    }

    It 'Separates new compromised accounts, the known victim and failed attempts' {
        $users = Import-Out $R 'users_summary.csv'
        ($users | Where-Object User -eq 'bob@contoso.example').Assessment | Should -Be 'LIKELY COMPROMISED'
        ($users | Where-Object User -eq 'alex@contoso.example').Assessment | Should -Be 'Known victim'
        ($users | Where-Object User -eq 'carol@contoso.example').Assessment | Should -Be 'Failed sign-ins only'
        $users.User | Should -Not -Contain 'dave@contoso.example'
        $users[0].Assessment | Should -Be 'LIKELY COMPROMISED'      # most urgent first
        $R.Console | Should -Match 'SUCCESSFUL activity from the bad IPs'
    }

    It 'Normalises IPs with ports and flags records whose own IP differs from the match' {
        $hits = Import-Out $R 'ip_hits.csv'
        ($hits | Where-Object { $_.User -eq 'bob@contoso.example' -and $_.Operation -eq 'MailItemsAccessed' }).IP | Should -Be $script:Bad2
        ($hits | Where-Object User -eq 'erin@contoso.example').IPMatch | Should -Be 'False'
        Get-Content (Join-Path $R.OutDir 'sweep_summary.txt') -Raw | Should -Match '1 where the record''s own IP field differs'
    }

    It 'Writes failed sign-ins with the logon error, per-IP totals, and the raw records as evidence' {
        $failed = Import-Out $R 'failed_signins.csv'
        $failed.Count | Should -Be 1
        $failed[0].LogonError | Should -Be 'InvalidUserNameOrPassword'
        $ipSum = Import-Out $R 'ip_summary.csv'
        ($ipSum | Where-Object IP -eq $script:Bad1).Users | Should -Be '2'   # erin's record carries a different IP itself
        (Import-Out $R 'audit_records.csv')[0].PSObject.Properties.Name | Should -Contain 'AuditData'
    }
}

Describe 'Sweep: tenant safety and inputs' {
    It 'Stops before searching when the domain isn''t in the signed-in tenant' {
        $answers = $script:Std.Clone(); $answers[4] = 'fabrikam.example'
        $r = Invoke-Sweep -Answers $answers
        $r.Error | Should -Match 'WRONG TENANT'
        $r.CallNames | Should -Not -Contain 'Search-UnifiedAuditLog'
        $r.ConnLeft | Should -Be 0
    }

    It 'Doesn''t search if the analyst doesn''t confirm the organisation' {
        $answers = $script:Std.Clone(); $answers[-1] = ''
        $r = Invoke-Sweep -Answers $answers
        $r.Error | Should -BeNullOrEmpty
        $r.CallNames | Should -Not -Contain 'Search-UnifiedAuditLog'
        $r.Console | Should -Match 'Cancelled'
    }

    It 'Reads the IPs from the clipboard when nothing is pasted' {
        $r = Invoke-Sweep -Clipboard "$($script:Bad1);[$('2001:db8::5')]:443" -Answers (@('') + $script:Std[3..7])
        $r.Error | Should -BeNullOrEmpty
        @($r.Searches[0].Params.IPAddresses) | Should -Be @($script:Bad1, '2001:db8::5')
    }

    It 'Rejects things that only look like IPs' {
        $r = Invoke-Sweep -Answers (@('1.2.3, 12345', '') + $script:Std[3..7])
        $r.Error | Should -Match 'No valid IP addresses'
    }

    It 'Clamps the window to the audit retention period' {
        $answers = $script:Std.Clone(); $answers[3] = (Get-Date).ToUniversalTime().AddDays(-400).ToString('yyyy-MM-dd')
        $r = Invoke-Sweep -Answers $answers
        $r.Console | Should -Match 'retention'
        $start = ([datetime]$r.Searches[0].Params.StartDate).ToUniversalTime()
        $start | Should -BeGreaterThan (Get-Date).ToUniversalTime().AddDays(-181)
    }

    It 'Splits time slices that hit the 50,000-result cap, without duplicating events' {
        $r = Invoke-Sweep -Answers $script:Std -CapAboveDays 3
        $r.Error | Should -BeNullOrEmpty
        $r.Console | Should -Match 'splitting'
        $longest = ($r.Searches | ForEach-Object { ([datetime]$_.Params.EndDate - [datetime]$_.Params.StartDate).TotalDays } | Measure-Object -Maximum).Maximum
        $longest | Should -BeGreaterThan 3     # the first, capped attempt
        (Import-Out $r 'ip_hits.csv').Count | Should -Be 5
    }
}

Describe 'Shared helpers' {
    It 'Uses the same IP normalisation as the triage script' {
        $get = { param($path) $text = Get-Content -LiteralPath $path -Raw; [regex]::Match($text, '(?s)function Get-NormIP.*?\n\}').Value }
        & $get $script:ScriptPath | Should -Be (& $get (Join-Path $PSScriptRoot '..' 'Invoke-MailAccessTriage.ps1'))
    }
}
