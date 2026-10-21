<#
.SYNOPSIS
  M365 BEC mailbox-access triage.
  Purview audit CSV -> IP summary grid -> you pick bad IPs ->
  accessed-items CSV (InternetMessageId / time / IP / Bind-Sync) + folderid conversion
  + eDiscovery searches (Bind message IDs + Sync folders). You export the PST from the portal.

.HOW TO RUN
  Paste this whole file into a PowerShell console on Windows (pwsh 7 or Windows PowerShell 5.1).
  Everything runs inside one script block, so nothing is left behind in your console afterwards.
  You're prompted for: audit CSV path, bad IPs (grid), whether to create searches, case name,
  the client's admin account, and the mailbox if the export covers more than one.

.REQUIREMENTS
  Windows (Out-GridView)
  ExchangeOnlineManagement module 3.7.2+ (Install-Module ExchangeOnlineManagement)
  Rights: Get-MailboxFolderStatistics on the mailbox; eDiscovery Manager for searches

.SAFETY
  Tenant writes: New-ComplianceCase, New-ComplianceSearch, Start-ComplianceSearch. Nothing else.
  Before any tenant call, the signed-in tenant is checked against the OrganizationId in the audit
  export. A mismatch disconnects and stops before anything is created.
#>
& {
#region settings (edit before pasting if needed)
$SearchPrefix     = 'BadIP'
$MaxQueryLength   = 9000    # KQL chars per search. Mailbox limit is 10,000 (after expansion); see README
$WaitMinutes      = 30      # how long to poll searches for completion
$EntraWindowHours = 24      # Entra changes within this many hours of bad-IP first/last seen are flagged InAttackWindow
#endregion

$ErrorActionPreference = 'Stop'
$stamp = Get-Date -Format yyyyMMddHHmm
# fixed location regardless of the shell's current folder (admin shells start in System32).
# M365TRIAGE_OUTROOT overrides it, e.g. to an encrypted drive.
$outRoot = $env:M365TRIAGE_OUTROOT
if (-not $outRoot) {
    $docs = [Environment]::GetFolderPath('MyDocuments')
    if (-not $docs) { $docs = $HOME }
    $outRoot = Join-Path $docs 'M365Triage'
}
$OutDir = Join-Path $outRoot "triage_$(Get-Date -Format yyyyMMdd_HHmmss)"

#region helpers
function Get-NormIP([string]$raw) {
    if ([string]::IsNullOrWhiteSpace($raw)) { return '(none)' }
    $s = $raw.Trim()
    if ($s -match '^\[([^\]]+)\]') { $s = $Matches[1] }                          # [v6]:port
    elseif ($s -match '^(\d{1,3}(\.\d{1,3}){3}):\d+$') { $s = $Matches[1] }      # v4:port
    if ($s -match '^::ffff:(\d{1,3}(\.\d{1,3}){3})$') { $s = $Matches[1] }      # v4-mapped v6
    $s.ToLower()
}

function Get-UtcTime($v) {
    $t = [datetime]$v
    if ($t.Kind -eq 'Local') { return $t.ToUniversalTime() }
    [datetime]::SpecifyKind($t, 'Utc')                                          # UAL CreationTime is UTC
}

# Microsoft's documented conversion: base64 FolderId -> bytes 23..46 -> 48-char hex for folderid:
function ConvertTo-FolderQueryId([string]$b64) {
    if (-not $b64) { return $null }
    try { $bytes = [Convert]::FromBase64String($b64) } catch { return $null }
    if ($bytes.Length -lt 47) { return $null }
    -join ($bytes[23..46] | ForEach-Object { $_.ToString('X2') })
}

function Split-Query([string[]]$terms, [int]$max) {
    $out = [System.Collections.Generic.List[string]]::new()
    $cur = [System.Collections.Generic.List[string]]::new(); $len = 0
    foreach ($t in $terms) {
        if ($cur.Count -and ($len + $t.Length + 4) -gt $max) { $out.Add($cur -join ' OR '); $cur.Clear(); $len = 0 }
        $cur.Add($t); $len += $t.Length + 4
    }
    if ($cur.Count) { $out.Add($cur -join ' OR ') }
    , $out
}

function Read-YesNo([string]$prompt, [bool]$default) {
    $hint = if ($default) { '[Y/n]' } else { '[y/N]' }
    $a = (Read-Host "$prompt $hint").Trim()
    if (-not $a) { return $default }
    $a -match '^[Yy]'
}

# The client's admin account, asked once per run, only when the script first needs the tenant.
# Held in $run (a hashtable inside this script block): when pasted, $script: would be the console's
# global scope, and the next run - possibly for another client - would silently reuse it.
$run = @{ AdminUpn = '' }
function Get-AdminUpn {
    while ($run.AdminUpn -notmatch '^[^@\s]+@[^@\s]+\.[^@\s]+$') {
        Write-Host "Enter the admin account for THIS client's tenant (e.g. admin@client.com)." -ForegroundColor Cyan
        $run.AdminUpn = (Read-Host 'Admin UPN').Trim().Trim('"', "'")
    }
    $run.AdminUpn
}

# EXO module 3.7+ uses WAM broker -> "A window handle must be configured" in many hosts. -DisableWAM (3.7.2+) falls back to browser sign-in.
function Get-ConnParams([string]$cmd) {
    $p = @{ ShowBanner = $false; UserPrincipalName = (Get-AdminUpn) }
    if ((Get-Command $cmd).Parameters.ContainsKey('DisableWAM')) { $p.DisableWAM = $true }
    $p
}

function Disconnect-Sessions([switch]$Ipps) {
    try {
        Get-ConnectionInformation -ErrorAction Stop |
            Where-Object { $_.State -eq 'Connected' -and [bool]$_.IsEopSession -eq [bool]$Ipps } |
            ForEach-Object { Disconnect-ExchangeOnline -ConnectionId $_.ConnectionId -Confirm:$false }
    } catch { Write-Verbose "No existing sessions to disconnect: $_" }
}

# Stops unless the live session is signed in to the tenant the audit export came from.
function Assert-Tenant([switch]$Ipps) {
    $kind = if ($Ipps) { 'Purview (IPPS)' } else { 'Exchange Online' }
    $ci = @(Get-ConnectionInformation -ErrorAction Stop | Where-Object { $_.State -eq 'Connected' -and [bool]$_.IsEopSession -eq [bool]$Ipps })
    if (-not $ci) { throw "No $kind connection after sign-in." }
    if (-not $ExpectedTenant) { return }    # operator chose to continue without a tenant ID in the export
    $wrong = @($ci | Where-Object { "$($_.TenantID)" -ne $ExpectedTenant })
    if ($wrong) {
        Disconnect-Sessions -Ipps:$Ipps
        throw "WRONG TENANT: $kind is signed in to tenant $($wrong[0].TenantID) as $($wrong[0].UserPrincipalName), but the audit export is from tenant $ExpectedTenant. Disconnected; nothing was created. Re-run and sign in with this client's admin account."
    }
    Write-Host "$kind tenant check OK ($ExpectedTenant)." -ForegroundColor Green
}

# Always a fresh, verified connection: an existing session in this window may belong to another client.
function Connect-Exo {
    Disconnect-Sessions
    $p = Get-ConnParams 'Connect-ExchangeOnline'
    Connect-ExchangeOnline @p
    Assert-Tenant
}

# Start-ComplianceSearch now requires an IPPS session opened with -EnableSearchOnlySession (MC1213770).
# Drop any existing IPPS connection (opened without it) and reconnect with the flag. EXO connection is left alone.
function Connect-Ipps {
    $p = Get-ConnParams 'Connect-IPPSSession'
    if ((Get-Command Connect-IPPSSession).Parameters.ContainsKey('EnableSearchOnlySession')) { $p.EnableSearchOnlySession = $true }
    else { Write-Warning "ExchangeOnlineManagement too old for -EnableSearchOnlySession; Start-ComplianceSearch may fail. Update-Module ExchangeOnlineManagement." }
    Disconnect-Sessions -Ipps
    Connect-IPPSSession @p
    Assert-Tenant -Ipps
}
#endregion

#region 1. parse export
# quotes stripped either way; prompt loops until the file exists
$AuditCsv = ''
while (-not $AuditCsv -or -not (Test-Path -LiteralPath $AuditCsv -PathType Leaf)) {
    if ($AuditCsv) { Write-Warning "File not found: $AuditCsv" }
    Write-Host "Enter the full path to the Purview audit export CSV." -ForegroundColor Cyan
    Write-Host "  NO quotation marks, even if the path has spaces. e.g. C:\Users\Josh\Downloads\Audit Export.csv" -ForegroundColor Cyan
    $AuditCsv = (Read-Host 'Audit CSV path').Trim().Trim('"', "'")
}
$rows = Import-Csv -LiteralPath $AuditCsv
if (-not $rows) { throw "Empty CSV." }
if (-not ($rows[0].PSObject.Properties.Name -contains 'AuditData')) { throw "No AuditData column - not a Purview audit export?" }

$seen = [System.Collections.Generic.HashSet[string]]::new()
$events = foreach ($r in $rows) {
    try { $d = $r.AuditData | ConvertFrom-Json } catch { Write-Warning "Unparseable AuditData (RecordId $($r.RecordId))"; continue }
    if ($d.Id -and -not $seen.Add([string]$d.Id)) { continue }                  # exports often contain dupes
    $props = @{}
    foreach ($p in @($d.OperationProperties)) { if ($p.Name) { $props[$p.Name] = $p.Value } }
    $ipRaw = @($d.ClientIPAddress, $d.ClientIP, $d.ActorIpAddress) | Where-Object { $_ } | Select-Object -First 1
    [pscustomobject]@{
        TimeUtc    = Get-UtcTime $d.CreationTime
        Operation  = $d.Operation
        IP         = Get-NormIP $ipRaw
        AccessType = $props['MailAccessType']
        Throttled  = ($props['IsThrottled'] -eq 'True')
        SessionId  = $d.SessionId
        Client     = $d.ClientInfoString
        AppId      = $d.AppId
        Owner      = $d.MailboxOwnerUPN
        UserId     = $d.UserId
        Folders    = $d.Folders
        Workload   = $d.Workload
        Raw        = $d
    }
}
$events = @($events)
Write-Host "Parsed $($events.Count) unique events."

# Which tenant the export came from. Every tenant connection is checked against this.
$tenantIds = @($events | ForEach-Object { "$($_.Raw.OrganizationId)" } | Where-Object { $_ } | Sort-Object -Unique)
if ($tenantIds.Count -gt 1) { throw "Export contains events from $($tenantIds.Count) tenants ($($tenantIds -join ', ')). Export one client at a time." }
$ExpectedTenant = if ($tenantIds) { $tenantIds[0] } else { $null }
if ($ExpectedTenant) { Write-Host "Export is from tenant $ExpectedTenant" }
else {
    Write-Warning "No OrganizationId in this export, so the signed-in tenant can't be checked."
    if (-not (Read-YesNo 'Continue WITHOUT the tenant check?' $false)) { return }
}

$miaTotal = @($events | Where-Object Operation -eq 'MailItemsAccessed').Count
if (-not $miaTotal) {
    Write-Warning ("No MailItemsAccessed events in this export. The tenant may not be logging mail access " +
        "(licence / audit tier), or the search didn't include them. This is NOT evidence that no mail was read.")
}
#endregion

#region 2. IP summary + selection
$summary = $events | Group-Object IP | ForEach-Object {
    $g = $_.Group; $mia = @($g | Where-Object Operation -eq 'MailItemsAccessed'); $times = $g.TimeUtc | Sort-Object
    [pscustomobject]@{
        IP                = $_.Name
        Events            = $_.Count
        MailItemsAccessed = $mia.Count
        Bind              = @($mia | Where-Object AccessType -eq 'Bind').Count
        Sync              = @($mia | Where-Object AccessType -eq 'Sync').Count
        FirstSeenUtc      = $times | Select-Object -First 1
        LastSeenUtc       = $times | Select-Object -Last 1
        Operations        = ($g.Operation | Sort-Object -Unique) -join ', '
        Clients           = ($g.Client | Where-Object { $_ } | Sort-Object -Unique | Select-Object -First 3) -join ' | '
    }
} | Sort-Object Events -Descending

New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
$summary | Export-Csv (Join-Path $OutDir 'ip_summary.csv') -NoTypeInformation

# IP list for manual lookups (bulk IP lookup sites): clipboard + console + ip_list.txt, same order as the grid.
# The grid waits for your selection, so you can paste the list into a browser first, then come back and pick.
$ipList = @($summary | Where-Object IP -ne '(none)' | ForEach-Object IP)
$ipList | Set-Content -LiteralPath (Join-Path $OutDir 'ip_list.txt') -Encoding UTF8
Write-Host "`nIPs in this export ($($ipList.Count), most events first):" -ForegroundColor Cyan
$summary | Where-Object IP -ne '(none)' | ForEach-Object { Write-Host ("  {0,-40} events {1,6}  MailItemsAccessed {2,6}" -f $_.IP, $_.Events, $_.MailItemsAccessed) }
try {
    Set-Clipboard -Value ($ipList -join [Environment]::NewLine)
    Write-Host "Copied $($ipList.Count) IPs to the clipboard (also in ip_list.txt). Paste them into an IP lookup site, then pick the bad ones in the grid." -ForegroundColor Green
} catch {
    Write-Host "Couldn't copy to the clipboard; the list is in $(Join-Path $OutDir 'ip_list.txt')." -ForegroundColor Yellow
}

$bad = $summary | Out-GridView -Title 'Select BAD IPs (Ctrl/Shift-click), then OK' -PassThru
if (-not $bad) { Write-Host "No IPs selected. ip_summary.csv written to $OutDir; exiting."; return }
$badSet = @($bad.IP)

# '(none)' is every event without an IP (most Entra records, some Exchange ones) - not one attacker.
if ($badSet -contains '(none)') {
    Write-Warning "You selected '(none)': events with NO IP address. That usually includes plenty of legitimate activity."
    if (-not (Read-YesNo "Treat events with no IP as attacker activity?" $false)) {
        $badSet = @($badSet | Where-Object { $_ -ne '(none)' })
        Write-Host "'(none)' removed from the bad IPs."
    }
    if (-not $badSet) { Write-Host 'No bad IPs left; exiting.'; return }
}
Write-Host "Bad IPs: $($badSet -join ', ')"

# asked up front so a failed run doesn't leave you guessing; existence checked after IPPS connect
$NoSearch = -not (Read-YesNo 'Create the eDiscovery case and searches in the tenant?' $true)
$CaseName = ''
if (-not $NoSearch) {
    while ([string]::IsNullOrWhiteSpace($CaseName)) {
        Write-Host "Enter the eDiscovery case name (your naming convention, e.g. CLIENT-BEC-$(Get-Date -Format yyyy-MM-dd))." -ForegroundColor Cyan
        $CaseName = (Read-Host 'Case name').Trim().Trim('"', "'")
    }
}
#endregion

#region 3. mailbox + accessed items
$owners = @($events | Where-Object Owner | Group-Object Owner | Sort-Object Count -Descending)
if ($owners.Count -gt 1) {
    Write-Warning "The export covers more than one mailbox:"
    for ($i = 0; $i -lt $owners.Count; $i++) { Write-Host ("  [{0}] {1} ({2} events)" -f ($i + 1), $owners[$i].Name, $owners[$i].Count) }
    $pick = 0
    while ($pick -lt 1 -or $pick -gt $owners.Count) { [int]::TryParse((Read-Host "Mailbox to triage [1-$($owners.Count)]"), [ref]$pick) | Out-Null }
    $Mailbox = $owners[$pick - 1].Name
}
elseif ($owners) { $Mailbox = $owners[0].Name }
else { $Mailbox = (@($events | Group-Object UserId | Sort-Object Count -Descending))[0].Name }
Write-Host "Mailbox: $Mailbox"

$events | Where-Object { $badSet -contains $_.IP } | Sort-Object TimeUtc |
    Select-Object @{n='TimestampUtc';e={$_.TimeUtc.ToString('yyyy-MM-dd HH:mm:ss')}}, IP, Operation, AccessType, SessionId, Client, AppId |
    Export-Csv (Join-Path $OutDir 'badip_all_activity.csv') -NoTypeInformation   # Send, inbox rules, deletes, etc.

$badMia = $events | Where-Object { $_.Operation -eq 'MailItemsAccessed' -and $badSet -contains $_.IP -and ($_.Owner -eq $Mailbox -or -not $_.Owner) }
$items = foreach ($e in $badMia) {
    foreach ($f in @($e.Folders)) {
        $base = [ordered]@{
            InternetMessageId = ''
            TimestampUtc      = $e.TimeUtc.ToString('yyyy-MM-dd HH:mm:ss')
            IP                = $e.IP
            AccessType        = $e.AccessType
            FolderPath        = $f.Path
            SessionId         = $e.SessionId
            ClientInfo        = $e.Client
            AppId             = $e.AppId
            Throttled         = $e.Throttled
            AuditFolderId     = $f.Id
        }
        if ($e.AccessType -ne 'Sync' -and $f.FolderItems) {
            foreach ($i in @($f.FolderItems)) { $o = [pscustomobject]$base; $o.InternetMessageId = $i.InternetMessageId; $o }
        } else { [pscustomobject]$base }
    }
}
$items = @($items | Sort-Object TimestampUtc)
$items | Select-Object * -ExcludeProperty AuditFolderId | Export-Csv (Join-Path $OutDir 'accessed_items.csv') -NoTypeInformation

#region 3b. SharePoint / OneDrive file activity from bad IPs
$files = @($events | Where-Object { $_.Workload -in 'SharePoint', 'OneDrive' -and $badSet -contains $_.IP } | Sort-Object TimeUtc | ForEach-Object {
    $d = $_.Raw
    [pscustomobject]@{
        TimestampUtc = $_.TimeUtc.ToString('yyyy-MM-dd HH:mm:ss')
        IP           = $_.IP
        Workload     = $_.Workload
        Operation    = $_.Operation
        FileName     = $d.SourceFileName
        FolderPath   = $d.SourceRelativeUrl
        SiteUrl      = $d.SiteUrl
        FullUrl      = $d.ObjectId
        Extension    = $d.SourceFileExtension
        TargetUser   = $d.TargetUserOrGroupName      # sharing events
        UserAgent    = $d.UserAgent
    }
})
$files | Export-Csv (Join-Path $OutDir 'files_accessed.csv') -NoTypeInformation
Write-Host "SharePoint/OneDrive events from bad IPs: $($files.Count)"
#endregion

#region 3c. Entra: user-level persistence (not IP-filtered - Entra records often lack client IP)
# Scope: what an attacker can do with the USER's own access - register a device, add an MFA method,
# consent to an app, change the password. Admin-only operations are out of scope (users have no admin rights).
$entraOps = 'device|security info|StrongAuthentication|authentication method|consent|delegated permission|password'
$realBad   = @($badSet | Where-Object { $_ -ne '(none)' })                     # no-IP rows must not stretch the window
$badEvents = @($events | Where-Object { $realBad -contains $_.IP })
if (-not $badEvents) { $badEvents = @($events | Where-Object { $badSet -contains $_.IP }) }
$winStart = ($badEvents.TimeUtc | Sort-Object | Select-Object -First 1).AddHours(-$EntraWindowHours)
$winEnd   = ($badEvents.TimeUtc | Sort-Object | Select-Object -Last 1).AddHours($EntraWindowHours)
$entra = @($events | Where-Object { $_.Workload -eq 'AzureActiveDirectory' -and $_.Operation -match $entraOps } | Sort-Object TimeUtc | ForEach-Object {
    $d = $_.Raw
    $targets = @($d.Target | ForEach-Object { $_.ID } | Where-Object { $_ -and $_ -notmatch '^[0-9a-f-]{36}$|^(User|Device|ServicePrincipal|Application|Role|Group)_' } | Sort-Object -Unique)
    $mods = @($d.ModifiedProperties | Where-Object Name | ForEach-Object {
        $nv = "$($_.NewValue)" -replace '\s+', ' '
        if ($nv.Length -gt 150) { $nv = $nv.Substring(0, 150) + '...' }
        "$($_.Name)=$nv"
    })
    $category = switch -Regex ($_.Operation) {
        'device'                                               { 'Device'; break }
        'security info|StrongAuthentication|authentication method' { 'MFA'; break }
        'consent|delegated permission'                         { 'AppConsent'; break }
        default                                                { 'Password' }
    }
    [pscustomobject]@{
        TimestampUtc   = $_.TimeUtc.ToString('yyyy-MM-dd HH:mm:ss')
        Category       = $category
        InAttackWindow = ($_.TimeUtc -ge $winStart -and $_.TimeUtc -le $winEnd)
        FromBadIP      = ($realBad -contains $_.IP)
        IP             = $_.IP
        Operation      = $_.Operation
        Result         = $d.ResultStatus
        Actor          = $_.UserId
        Targets        = ($targets -join '; ')
        ModifiedProps  = ($mods -join ' | ')
    }
})
$entra | Export-Csv (Join-Path $OutDir 'entra_changes.csv') -NoTypeInformation
$entraFlag   = @($entra | Where-Object InAttackWindow).Count
$deviceFlag  = @($entra | Where-Object { $_.InAttackWindow -and $_.Category -eq 'Device' })
Write-Host "Entra user-level changes: $($entra.Count) ($entraFlag in attack window +/-$EntraWindowHours h)"
if ($deviceFlag) {
    Write-Warning "DEVICE activity in the attack window ($($deviceFlag.Count) events) - check entra_changes.csv for a device the attacker registered:"
    $deviceFlag | ForEach-Object { Write-Host "  $($_.TimestampUtc)  $($_.Operation)  $($_.Targets)" -ForegroundColor Yellow }
}
#endregion

$bindIds     = @($items | Where-Object { $_.AccessType -ne 'Sync' -and $_.InternetMessageId } | Select-Object -ExpandProperty InternetMessageId | Sort-Object -Unique)
$syncFolders = @($items | Where-Object AccessType -eq 'Sync' | Group-Object FolderPath)
$throttled   = [bool]($events | Where-Object { $_.Operation -eq 'MailItemsAccessed' -and $_.Throttled })
if ($throttled) { Write-Warning "THROTTLED MailItemsAccessed records present - Bind logging incomplete. Treat whole mailbox as accessed for that window." }
Write-Host "Bind message IDs: $($bindIds.Count) | Sync folders: $($syncFolders.Count)"
#endregion

#region 4. folderid conversion
$folderMap = @()
if ($syncFolders) {
    Connect-Exo
    $stats = Get-MailboxFolderStatistics -Identity $Mailbox
    $byPath = @{}
    foreach ($s in $stats) { $byPath[($s.FolderPath -replace '\\', '/').ToLower()] = $s }
    $folderMap = foreach ($sf in $syncFolders) {
        $hit = $byPath[($sf.Name -replace '\\', '/').ToLower()]
        $qid = if ($hit) { ConvertTo-FolderQueryId $hit.FolderId }
        $src = 'EXO path match'
        if (-not $qid) { $qid = ConvertTo-FolderQueryId ($sf.Group[0].AuditFolderId); $src = 'audit Folder.Id (unverified)' }
        [pscustomobject]@{
            FolderPath     = $sf.Name
            FolderQueryId  = $qid
            Source         = if ($qid) { $src } else { 'NOT RESOLVED' }
            SyncEvents     = $sf.Count
            ItemsInFolder  = $hit.ItemsInFolder
        }
    }
    $folderMap | Export-Csv (Join-Path $OutDir 'sync_folders.csv') -NoTypeInformation
    $unres = @($folderMap | Where-Object Source -eq 'NOT RESOLVED')
    if ($unres) { Write-Warning "Unresolved folders (check archive/renamed): $($unres.FolderPath -join '; ')" }
}
#endregion

#region 5. KQL
$qDir = Join-Path $OutDir 'queries'; New-Item -ItemType Directory -Path $qDir -Force | Out-Null
$queries = [System.Collections.Generic.List[object]]::new()
$n = 0
foreach ($q in (Split-Query ($bindIds | ForEach-Object { 'InternetMessageId:"{0}"' -f $_ }) $MaxQueryLength)) {
    $n++; $queries.Add([pscustomobject]@{ Name = ('{0}_{1}_Bind_{2:00}' -f $SearchPrefix, $stamp, $n); Kind = 'Bind'; Query = $q })
}
$n = 0
$fTerms = @($folderMap | Where-Object FolderQueryId | ForEach-Object { 'folderid:{0}' -f $_.FolderQueryId })
foreach ($q in (Split-Query $fTerms $MaxQueryLength)) {
    $n++; $queries.Add([pscustomobject]@{ Name = ('{0}_{1}_Sync_{2:00}' -f $SearchPrefix, $stamp, $n); Kind = 'Sync'; Query = $q })
}
foreach ($q in $queries) { Set-Content -LiteralPath (Join-Path $qDir "$($q.Name).txt") -Value $q.Query -Encoding UTF8 }
Write-Host "Queries: $($queries.Count) -> $qDir"
#endregion

#region 6. eDiscovery searches
$results = @()
if (-not $NoSearch -and $queries.Count) {
    Connect-Ipps
    # existing case -> use it (e.g. rerun after failure) or pick a new name
    while ($true) {
        $existing = $null
        try { $existing = Get-ComplianceCase -Identity $CaseName -ErrorAction Stop } catch { Write-Verbose "Case not found, will create: $_" }
        if (-not $existing) { New-ComplianceCase -Name $CaseName | Out-Null; Write-Host "Created case $CaseName"; break }
        $old = @(Get-ComplianceSearch -Case $CaseName -ErrorAction SilentlyContinue)
        Write-Warning "Case '$CaseName' already exists ($($old.Count) searches: $(($old.Name | Select-Object -First 5) -join ', '))."
        $ans = Read-Host "[U]se existing case, or [N]ew name"
        if ($ans -match '^[Uu]') { Write-Host "Using existing case $CaseName"; break }
        do { $CaseName = (Read-Host 'New case name').Trim().Trim('"', "'") } while ([string]::IsNullOrWhiteSpace($CaseName))
    }
    foreach ($q in $queries) {
        New-ComplianceSearch -Name $q.Name -Case $CaseName -ExchangeLocation $Mailbox -ContentMatchQuery $q.Query | Out-Null
        Start-ComplianceSearch -Identity $q.Name
        Write-Host "Started $($q.Name)"
    }
    # stop polling as soon as every search has finished, whatever the outcome
    $running = 'NotStarted', 'Starting', 'InProgress', 'Stopping'
    $deadline = (Get-Date).AddMinutes($WaitMinutes)
    do {
        Start-Sleep -Seconds 20
        $st = $queries | ForEach-Object { Get-ComplianceSearch -Identity $_.Name }
        $pending = @($st | Where-Object { $_.Status -in $running })
        Write-Host "Searches pending: $($pending.Count)"
    } while ($pending.Count -and (Get-Date) -lt $deadline)

    $results = foreach ($q in $queries) {
        $s = Get-ComplianceSearch -Identity $q.Name
        [pscustomobject]@{ Name = $q.Name; Kind = $q.Kind; Status = $s.Status; Items = $s.Items; Size = $s.Size; Errors = $s.Errors }
    }
    $results | Export-Csv (Join-Path $OutDir 'searches.csv') -NoTypeInformation
    $notDone = @($results | Where-Object Status -ne 'Completed')
    if ($notDone) { Write-Warning "Searches not completed: $(($notDone | ForEach-Object { "$($_.Name)=$($_.Status)" }) -join ', '). Check them in the portal." }
    $bindHits = ($results | Where-Object Kind -eq 'Bind' | Measure-Object Items -Sum).Sum
    if ($bindIds.Count -and -not $bindHits) {
        Write-Warning "Bind searches returned 0 items. InternetMessageId may not be resolving as a KQL property in this tenant - test one ID manually in the portal."
    }
}
#endregion

#region 7. summary
$sum = @"
Tenant           : $(if ($ExpectedTenant) { $ExpectedTenant } else { 'UNKNOWN (no OrganizationId in export; not checked)' })
Mailbox          : $Mailbox
Bad IPs          : $($badSet -join ', ')
MailItemsAccessed: $miaTotal in export$(if (-not $miaTotal) { '  (NONE - mail access may not be logged; not evidence of no access)' })
Throttled        : $throttled
Bind msg IDs     : $($bindIds.Count)
Sync folders     : $($syncFolders.Count)  (unresolved: $(@($folderMap | Where-Object Source -eq 'NOT RESOLVED').Count))
Searches         : $($queries.Count)$(if ($NoSearch) { '  (not created - you chose not to)' })
Bind hits        : $(($results | Where-Object Kind -eq 'Bind' | Measure-Object Items -Sum).Sum)  (vs $($bindIds.Count) IDs; diff = purged items or dupes across folders)
Sync folder hits : $(($results | Where-Object Kind -eq 'Sync' | Measure-Object Items -Sum).Sum)
SPO/OD events    : $($files.Count)  (files_accessed.csv)
Entra changes    : $($entra.Count)  ($entraFlag in attack window, $($deviceFlag.Count) device; entra_changes.csv)
Case             : $CaseName
Output folder    : $((Resolve-Path $OutDir).Path)
Next             : Purview > eDiscovery > case > each search > Export > PST
"@
$sum | Tee-Object -FilePath (Join-Path $OutDir 'run_summary.txt')
if ($IsWindows -or $env:OS -eq 'Windows_NT') { try { Invoke-Item $OutDir } catch { Write-Verbose "Couldn't open the output folder: $_" } }
#endregion
}
