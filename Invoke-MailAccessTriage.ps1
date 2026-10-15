<#
.SYNOPSIS
  M365 BEC mailbox-access triage.
  Purview audit CSV -> IP summary grid -> you pick bad IPs ->
  accessed-items CSV (InternetMessageId / time / IP / Bind-Sync) + folderid conversion
  + eDiscovery searches (Bind message IDs + Sync folders). You export the PST from the portal.

.REQUIREMENTS
  Windows PowerShell 5.1 or PowerShell 7 on Windows (Out-GridView)
  ExchangeOnlineManagement module v3+ (Install-Module ExchangeOnlineManagement)
  Rights: Get-MailboxFolderStatistics on the mailbox; eDiscovery Manager for searches

.EXAMPLE
  .\Invoke-MailAccessTriage.ps1 -AuditCsv .\audit_export.csv -CaseName "Contoso-BEC-2026-10" -AdminUpn admin@contoso.com

.EXAMPLE
  # files only, no tenant connections for searches
  .\Invoke-MailAccessTriage.ps1 -AuditCsv .\audit_export.csv -NoSearch
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$AuditCsv,
    [string]$OutDir = ".\triage_$(Get-Date -Format yyyyMMdd_HHmmss)",
    [string]$Mailbox,                 # defaults to most common MailboxOwnerUPN in the export
    [string]$CaseName,                # created if missing; omit = standalone content searches
    [string]$AdminUpn,                # pre-fills sign-in for EXO / IPPS
    [string]$SearchPrefix = 'BadIP',
    [int]$MaxQueryLength = 3500,      # KQL chars per search; lower if searches error on length
    [int]$WaitMinutes = 30,           # how long to poll searches for completion
    [switch]$NoSearch                 # build files/queries only
)
$ErrorActionPreference = 'Stop'
$stamp = Get-Date -Format yyyyMMddHHmm

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

function Test-Conn([switch]$Ipps) {
    try {
        $ci = @(Get-ConnectionInformation -ErrorAction Stop | Where-Object State -eq 'Connected')
        if ($Ipps) { [bool]($ci | Where-Object IsEopSession) } else { [bool]($ci | Where-Object { -not $_.IsEopSession }) }
    } catch { $false }
}
# EXO module 3.7+ uses WAM broker -> "A window handle must be configured" in many hosts. -DisableWAM (3.7.2+) falls back to browser sign-in.
function Get-ConnParams([string]$cmd) {
    $p = @{ShowBanner = $false}
    if ($AdminUpn) { $p.UserPrincipalName = $AdminUpn }
    if ((Get-Command $cmd).Parameters.ContainsKey('DisableWAM')) { $p.DisableWAM = $true }
    $p
}
function Connect-Exo  { if (-not (Test-Conn))       { $p = Get-ConnParams 'Connect-ExchangeOnline'; Connect-ExchangeOnline @p } }
# Start-ComplianceSearch now requires an IPPS session opened with -EnableSearchOnlySession (MC1213770).
# Drop any existing IPPS connection (opened without it) and reconnect with the flag. EXO connection is left alone.
function Connect-Ipps {
    $p = Get-ConnParams 'Connect-IPPSSession'
    if ((Get-Command Connect-IPPSSession).Parameters.ContainsKey('EnableSearchOnlySession')) { $p.EnableSearchOnlySession = $true }
    else { Write-Warning "ExchangeOnlineManagement too old for -EnableSearchOnlySession; Start-ComplianceSearch may fail. Update-Module ExchangeOnlineManagement." }
    try {
        Get-ConnectionInformation -ErrorAction Stop | Where-Object { $_.IsEopSession -and $_.State -eq 'Connected' } |
            ForEach-Object { Disconnect-ExchangeOnline -ConnectionId $_.ConnectionId -Confirm:$false }
    } catch { }
    Connect-IPPSSession @p
}
#endregion

#region 1. parse export
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
    }
}
Write-Host "Parsed $(@($events).Count) unique events."
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

$bad = $summary | Out-GridView -Title 'Select BAD IPs (Ctrl/Shift-click), then OK' -PassThru
if (-not $bad) { Write-Host 'No IPs selected. ip_summary.csv written; exiting.'; return }
$badSet = @($bad.IP)
Write-Host "Bad IPs: $($badSet -join ', ')"
#endregion

#region 3. mailbox + accessed items
if (-not $Mailbox) {
    $owners = $events | Where-Object Owner | Group-Object Owner | Sort-Object Count -Descending
    if (@($owners).Count -gt 1) { Write-Warning "Multiple mailbox owners in export: $($owners.Name -join ', '). Using top one; pass -Mailbox to override." }
    $Mailbox = if ($owners) { @($owners)[0].Name } else { (@($events | Group-Object UserId | Sort-Object Count -Descending))[0].Name }
}
Write-Host "Mailbox: $Mailbox"

$events | Where-Object { $badSet -contains $_.IP } | Sort-Object TimeUtc |
    Select-Object @{n='TimestampUtc';e={$_.TimeUtc.ToString('yyyy-MM-dd HH:mm:ss')}}, IP, Operation, AccessType, SessionId, Client, AppId |
    Export-Csv (Join-Path $OutDir 'badip_all_activity.csv') -NoTypeInformation   # Send, inbox rules, deletes, etc.

$badMia = $events | Where-Object { $_.Operation -eq 'MailItemsAccessed' -and $badSet -contains $_.IP }
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
    if ($CaseName) {
        try { Get-ComplianceCase -Identity $CaseName | Out-Null } catch { New-ComplianceCase -Name $CaseName | Out-Null; Write-Host "Created case $CaseName" }
    }
    foreach ($q in $queries) {
        $p = @{ Name = $q.Name; ExchangeLocation = $Mailbox; ContentMatchQuery = $q.Query }
        if ($CaseName) { $p.Case = $CaseName }
        New-ComplianceSearch @p | Out-Null
        Start-ComplianceSearch -Identity $q.Name
        Write-Host "Started $($q.Name)"
    }
    $deadline = (Get-Date).AddMinutes($WaitMinutes)
    do {
        Start-Sleep -Seconds 20
        $st = $queries | ForEach-Object { Get-ComplianceSearch -Identity $_.Name }
        $pending = @($st | Where-Object Status -ne 'Completed')
        Write-Host "Searches pending: $($pending.Count)"
    } while ($pending.Count -and (Get-Date) -lt $deadline)

    $results = foreach ($q in $queries) {
        $s = Get-ComplianceSearch -Identity $q.Name
        [pscustomobject]@{ Name = $q.Name; Kind = $q.Kind; Status = $s.Status; Items = $s.Items; Size = $s.Size; Errors = $s.Errors }
    }
    $results | Export-Csv (Join-Path $OutDir 'searches.csv') -NoTypeInformation
    $bindHits = ($results | Where-Object Kind -eq 'Bind' | Measure-Object Items -Sum).Sum
    if ($bindIds.Count -and -not $bindHits) {
        Write-Warning "Bind searches returned 0 items. InternetMessageId may not be resolving as a KQL property in this tenant - test one ID manually in the portal."
    }
}
#endregion

#region 7. summary
$sum = @"
Mailbox          : $Mailbox
Bad IPs          : $($badSet -join ', ')
Throttled        : $throttled
Bind msg IDs     : $($bindIds.Count)
Sync folders     : $($syncFolders.Count)  (unresolved: $(@($folderMap | Where-Object Source -eq 'NOT RESOLVED').Count))
Searches         : $($queries.Count)
Bind hits        : $(($results | Where-Object Kind -eq 'Bind' | Measure-Object Items -Sum).Sum)  (vs $($bindIds.Count) IDs; diff = purged items or dupes across folders)
Sync folder hits : $(($results | Where-Object Kind -eq 'Sync' | Measure-Object Items -Sum).Sum)
Case             : $CaseName
Next             : Purview > eDiscovery > case > each search > Export > PST
"@
$sum | Tee-Object -FilePath (Join-Path $OutDir 'run_summary.txt')
#endregion
