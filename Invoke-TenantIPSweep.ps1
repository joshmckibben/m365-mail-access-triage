<#
.SYNOPSIS
  M365 BEC tenant-wide IP sweep.
  Bad IPs (pasted) -> unified audit log search across the WHOLE tenant ->
  which accounts had activity from those IPs (new compromised accounts vs failed attempts).

.HOW TO RUN
  Paste this whole file into a PowerShell console on Windows (pwsh 7 or Windows PowerShell 5.1).
  Everything runs inside one script block, so nothing is left behind in your console afterwards.
  You're prompted for: the bad IPs, the date the attacker was first seen, the client's domain,
  the client's admin account, and (optionally) the account already known to be compromised.

.REQUIREMENTS
  ExchangeOnlineManagement module 3.7.2+ (Install-Module ExchangeOnlineManagement)
  Rights: View-Only Audit Logs or Audit Logs role

.SAFETY
  Read-only. Tenant calls: Connect-ExchangeOnline, Get-AcceptedDomain, Get-OrganizationConfig,
  Search-UnifiedAuditLog. Nothing is created or changed.
  Before searching, the client domain you type must be an accepted domain of the signed-in tenant,
  and you confirm the organisation name.
#>
& {
#region settings (edit before pasting if needed)
$LookbackDays   = 14       # search from this many days before the first-seen date, up to now
$RetentionDays  = 180      # Audit (Standard) retention; the window is clamped to this
$IpBatchSize    = 20       # IPs per Search-UnifiedAuditLog call
$PageSize       = 5000     # max per page with ReturnLargeSet
$SessionCap     = 50000    # max results per search session; slices that hit it are split
$MinSliceMinutes = 60      # don't split below this; warn instead
#endregion

$ErrorActionPreference = 'Stop'
$outRoot = $env:M365TRIAGE_OUTROOT
if (-not $outRoot) {
    $docs = [Environment]::GetFolderPath('MyDocuments')
    if (-not $docs) { $docs = $HOME }
    $outRoot = Join-Path $docs 'M365Triage'
}
$OutDir = Join-Path $outRoot "ipsweep_$(Get-Date -Format yyyyMMdd_HHmmss)"

#region helpers
# Same IP normalisation as Invoke-MailAccessTriage.ps1 (a test keeps the two identical).
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

function Read-YesNo([string]$prompt, [bool]$default) {
    $hint = if ($default) { '[Y/n]' } else { '[y/N]' }
    $a = (Read-Host "$prompt $hint").Trim()
    if (-not $a) { return $default }
    $a -match '^[Yy]'
}

# Splits pasted text (lines, commas, spaces, semicolons) into normalised, valid, unique IPs.
function ConvertTo-IpList([string[]]$text) {
    $valid = [System.Collections.Generic.List[string]]::new()
    $bad = [System.Collections.Generic.List[string]]::new()
    foreach ($token in (($text -join "`n") -split '[\s,;]+' | Where-Object { $_ })) {
        $ip = Get-NormIP $token
        $parsed = $null
        # TryParse alone accepts '1.2.3' and '12345' as IPv4, so require dotted-quad IPv4 or an IPv6 form.
        $shapeOk = $ip -match '^\d{1,3}(\.\d{1,3}){3}$' -or $ip -match ':'
        if ($shapeOk -and [System.Net.IPAddress]::TryParse($ip, [ref]$parsed)) { if (-not $valid.Contains($ip)) { $valid.Add($ip) } }
        else { $bad.Add($token) }
    }
    [pscustomobject]@{ Valid = $valid.ToArray(); Invalid = $bad.ToArray() }
}

function Disconnect-Sessions {
    try {
        Get-ConnectionInformation -ErrorAction Stop |
            Where-Object { $_.State -eq 'Connected' -and -not $_.IsEopSession } |
            ForEach-Object { Disconnect-ExchangeOnline -ConnectionId $_.ConnectionId -Confirm:$false }
    } catch { Write-Verbose "No existing sessions to disconnect: $_" }
}

# One Search-UnifiedAuditLog call, retried on transient errors.
function Invoke-UalPage([datetime]$start, [datetime]$end, [string[]]$ips, [string]$sessionId) {
    for ($attempt = 1; ; $attempt++) {
        try {
            return @(Search-UnifiedAuditLog -StartDate $start -EndDate $end -IPAddresses $ips -SessionId $sessionId `
                    -SessionCommand ReturnLargeSet -ResultSize $PageSize -ErrorAction Stop)
        } catch {
            if ($attempt -ge 3) { throw }
            Write-Warning "Search failed (attempt $attempt of 3): $($_.Exception.Message). Retrying..."
            Start-Sleep -Seconds (15 * $attempt)
        }
    }
}

# All records for one time slice and IP batch. If the slice hits the session cap, it's split in half.
function Search-Slice([datetime]$start, [datetime]$end, [string[]]$ips) {
    $sessionId = [guid]::NewGuid().ToString()
    $page = Invoke-UalPage $start $end $ips $sessionId
    if (-not $page) { return }
    $total = [int]$page[0].ResultCount
    if ($total -ge $SessionCap -and ($end - $start).TotalMinutes -gt $MinSliceMinutes) {
        $mid = $start.AddTicks([long](($end - $start).Ticks / 2))
        Write-Host ("  {0:yyyy-MM-dd HH:mm} - {1:yyyy-MM-dd HH:mm}: {2}+ results, splitting" -f $start, $end, $total)
        Search-Slice $start $mid $ips
        Search-Slice $mid $end $ips
        return
    }
    if ($total -ge $SessionCap) {
        Write-Warning ("{0:yyyy-MM-dd HH:mm} - {1:yyyy-MM-dd HH:mm}: still {2}+ results in a {3}-minute slice. Some records may be MISSING." -f $start, $end, $total, $MinSliceMinutes)
    }
    # Count UNIQUE records: ReturnLargeSet repeats records across pages, so counting rows would stop early
    # and silently drop the last records. Stop when every record has arrived or a page adds nothing new.
    $ids = [System.Collections.Generic.HashSet[string]]::new()
    $page | ForEach-Object { [void]$ids.Add([string]$_.Identity) }
    $page
    while ($ids.Count -lt $total) {
        $next = Invoke-UalPage $start $end $ips $sessionId
        $before = $ids.Count
        $next | ForEach-Object { [void]$ids.Add([string]$_.Identity) }
        if ($ids.Count -eq $before) {
            Write-Warning ("{0:yyyy-MM-dd HH:mm} - {1:yyyy-MM-dd HH:mm}: got {2} of {3} records before the search stopped returning new ones." -f $start, $end, $ids.Count, $total)
            break
        }
        $next
    }
}
#endregion

#region 1. inputs
Write-Host "Paste the bad IPs (one per line, or separated by commas/spaces), then press Enter on an empty line." -ForegroundColor Cyan
Write-Host "  Or press Enter straight away to use the IPs currently on the clipboard." -ForegroundColor Cyan
$lines = [System.Collections.Generic.List[string]]::new()
while ($true) {
    $line = Read-Host 'IPs'
    if ([string]::IsNullOrWhiteSpace($line)) { break }
    $lines.Add($line)
}
if ($lines.Count -eq 0) {
    try { $lines.Add(((Get-Clipboard) -join "`n")) } catch { throw "Nothing pasted and the clipboard couldn't be read." }
}
$parsed = ConvertTo-IpList $lines.ToArray()
if ($parsed.Invalid) { Write-Warning "Ignored (not IP addresses): $($parsed.Invalid -join ', ')" }
$ips = @($parsed.Valid)
if (-not $ips) { throw "No valid IP addresses found." }
Write-Host "Bad IPs ($($ips.Count)): $($ips -join ', ')"

$firstSeen = $null
while (-not $firstSeen) {
    $raw = (Read-Host 'Date the attacker was first seen, UTC (yyyy-MM-dd, from the triage ip_summary.csv)').Trim()
    $d = [datetime]::MinValue
    # [string[]] matters: with an untyped array PowerShell 7 binds a different overload and the parse always fails.
    if ([datetime]::TryParseExact($raw, [string[]]@('yyyy-MM-dd', 'yyyy-MM-dd HH:mm', 'yyyy-MM-dd HH:mm:ss', 'yyyy-MM-ddTHH:mm:ss'),
            [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$d)) {
        $firstSeen = [datetime]::SpecifyKind($d, 'Utc')
    } else { Write-Warning "Use the format yyyy-MM-dd, e.g. $((Get-Date).ToString('yyyy-MM-dd'))" }
}
$nowUtc = (Get-Date).ToUniversalTime()
if ($firstSeen -gt $nowUtc) { throw "The first-seen date is in the future." }
$winStart = $firstSeen.Date.AddDays(-$LookbackDays)
$winEnd = $nowUtc
$oldest = $nowUtc.AddDays(-$RetentionDays)
if ($winStart -lt $oldest) {
    Write-Warning "The window starts before the audit log's $RetentionDays-day retention; searching from $($oldest.ToString('yyyy-MM-dd')) instead."
    $winStart = $oldest
}
Write-Host ("Search window (UTC): {0:yyyy-MM-dd HH:mm} -> {1:yyyy-MM-dd HH:mm}" -f $winStart, $winEnd)

$domain = ''
while ($domain -notmatch '^[a-z0-9-]+(\.[a-z0-9-]+)+$') {
    $domain = (Read-Host "Client's email domain (e.g. client.com)").Trim().Trim('"', "'").ToLower()
}
$adminUpn = ''
while ($adminUpn -notmatch '^[^@\s]+@[^@\s]+\.[^@\s]+$') {
    $adminUpn = (Read-Host "Admin account for THIS client's tenant (e.g. admin@$domain)").Trim().Trim('"', "'")
}
$victim = (Read-Host 'Account already known to be compromised (optional, Enter to skip)').Trim().Trim('"', "'").ToLower()
#endregion

#region 2. connect + tenant check
Disconnect-Sessions
$p = @{ ShowBanner = $false; UserPrincipalName = $adminUpn }
if ((Get-Command Connect-ExchangeOnline).Parameters.ContainsKey('DisableWAM')) { $p.DisableWAM = $true }
Connect-ExchangeOnline @p

$accepted = @(Get-AcceptedDomain | ForEach-Object { "$($_.DomainName)".ToLower() })
if ($accepted -notcontains $domain) {
    Disconnect-Sessions
    throw "WRONG TENANT: '$domain' is not an accepted domain of the tenant you signed in to (its domains: $($accepted -join ', ')). Disconnected; nothing was searched."
}
$conn = @(Get-ConnectionInformation | Where-Object { $_.State -eq 'Connected' -and -not $_.IsEopSession }) | Select-Object -First 1
$org = Get-OrganizationConfig
Write-Host "Signed in to: $($org.DisplayName)  (tenant $($conn.TenantID), as $($conn.UserPrincipalName))" -ForegroundColor Green
if (-not (Read-YesNo "Sweep THIS tenant for activity from $($ips.Count) IP(s)?" $false)) {
    Disconnect-Sessions
    Write-Host 'Cancelled; nothing was searched.'
    return
}
#endregion

#region 3. search
$records = [System.Collections.Generic.List[object]]::new()
for ($i = 0; $i -lt $ips.Count; $i += $IpBatchSize) {
    $batch = @($ips[$i..([Math]::Min($i + $IpBatchSize, $ips.Count) - 1)])
    Write-Host "Searching $($batch.Count) IP(s): $($batch -join ', ')"
    foreach ($r in @(Search-Slice $winStart $winEnd $batch)) { $records.Add($r) }
}

$seen = [System.Collections.Generic.HashSet[string]]::new()
$ipSet = [System.Collections.Generic.HashSet[string]]::new([string[]]$ips)
$events = foreach ($r in $records) {
    try { $d = $r.AuditData | ConvertFrom-Json } catch { Write-Warning "Unparseable AuditData ($($r.Identity))"; continue }
    if ($d.Id -and -not $seen.Add([string]$d.Id)) { continue }                  # ReturnLargeSet can repeat records
    $ipRaw = @($d.ClientIPAddress, $d.ClientIP, $d.ActorIpAddress) | Where-Object { $_ } | Select-Object -First 1
    $ip = Get-NormIP $ipRaw
    [pscustomobject]@{
        TimeUtc   = Get-UtcTime $d.CreationTime
        User      = "$($d.UserId)".ToLower()
        Workload  = $d.Workload
        Operation = $d.Operation
        IP        = $ip
        # The server matched these IPs, but if the record's own IP field says otherwise, flag it for review.
        IPMatch   = $ipSet.Contains($ip)
        LogonError = $d.LogonError
        Client    = $d.ClientInfoString
        UserAgent = @($d.ExtendedProperties | Where-Object Name -eq 'UserAgent' | ForEach-Object Value) + @($d.UserAgent) | Where-Object { $_ } | Select-Object -First 1
        Record    = $r
    }
}
$events = @($events | Sort-Object TimeUtc)
Write-Host "Matching events: $($events.Count)"
#endregion

#region 4. outputs
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

# Same column layout as a Purview audit export, as evidence.
$records | Where-Object { $_ } | Select-Object @{n='RecordId';e={$_.Identity}}, @{n='CreationDate';e={$_.CreationDate}}, RecordType,
    @{n='Operation';e={$_.Operations}}, @{n='UserId';e={$_.UserIds}}, AuditData |
    Export-Csv (Join-Path $OutDir 'audit_records.csv') -NoTypeInformation

$events | Select-Object @{n='TimestampUtc';e={$_.TimeUtc.ToString('yyyy-MM-dd HH:mm:ss')}}, User, Workload, Operation, IP, IPMatch, LogonError, Client, UserAgent |
    Export-Csv (Join-Path $OutDir 'ip_hits.csv') -NoTypeInformation

$failedOps = 'UserLoginFailed'
$events | Where-Object Operation -in $failedOps |
    Select-Object @{n='TimestampUtc';e={$_.TimeUtc.ToString('yyyy-MM-dd HH:mm:ss')}}, User, IP, LogonError, UserAgent |
    Export-Csv (Join-Path $OutDir 'failed_signins.csv') -NoTypeInformation

$users = @($events | Group-Object User | ForEach-Object {
    $g = $_.Group
    $ok = @($g | Where-Object { $_.Operation -notin $failedOps })
    $assessment = if ($victim -and $_.Name -eq $victim) { 'Known victim' }
                  elseif ($ok) { 'LIKELY COMPROMISED' }
                  else { 'Failed sign-ins only' }
    [pscustomobject]@{
        User              = $_.Name
        Assessment        = $assessment
        FirstSeenUtc      = ($g.TimeUtc | Sort-Object | Select-Object -First 1).ToString('yyyy-MM-dd HH:mm:ss')
        LastSeenUtc       = ($g.TimeUtc | Sort-Object | Select-Object -Last 1).ToString('yyyy-MM-dd HH:mm:ss')
        Events            = $g.Count
        SuccessfulSignIns = @($g | Where-Object Operation -eq 'UserLoggedIn').Count
        FailedSignIns     = @($g | Where-Object Operation -in $failedOps).Count
        MailItemsAccessed = @($g | Where-Object Operation -eq 'MailItemsAccessed').Count
        MailSent          = @($g | Where-Object Operation -in 'Send', 'SendAs', 'SendOnBehalf').Count
        InboxRuleChanges  = @($g | Where-Object Operation -match 'InboxRule').Count
        FileEvents        = @($g | Where-Object Workload -in 'SharePoint', 'OneDrive').Count
        IPs               = ($g.IP | Sort-Object -Unique) -join ', '
        Workloads         = ($g.Workload | Sort-Object -Unique) -join ', '
    }
} | Sort-Object @{e={ @('LIKELY COMPROMISED', 'Known victim', 'Failed sign-ins only').IndexOf($_.Assessment) }}, User)
$users | Export-Csv (Join-Path $OutDir 'users_summary.csv') -NoTypeInformation

$ipSummary = foreach ($ip in $ips) {
    $g = @($events | Where-Object IP -eq $ip)
    [pscustomobject]@{
        IP           = $ip
        Users        = @($g.User | Sort-Object -Unique).Count
        Events       = $g.Count
        FirstSeenUtc = if ($g) { ($g.TimeUtc | Sort-Object | Select-Object -First 1).ToString('yyyy-MM-dd HH:mm:ss') } else { '' }
        LastSeenUtc  = if ($g) { ($g.TimeUtc | Sort-Object | Select-Object -Last 1).ToString('yyyy-MM-dd HH:mm:ss') } else { '' }
        UserList     = ($g.User | Sort-Object -Unique) -join ', '
    }
}
$ipSummary | Export-Csv (Join-Path $OutDir 'ip_summary.csv') -NoTypeInformation

$compromised = @($users | Where-Object Assessment -eq 'LIKELY COMPROMISED')
$attempts = @($users | Where-Object Assessment -eq 'Failed sign-ins only')
$mismatch = @($events | Where-Object { -not $_.IPMatch }).Count
if ($compromised) {
    Write-Warning "$($compromised.Count) account(s) with SUCCESSFUL activity from the bad IPs (besides any known victim):"
    $compromised | ForEach-Object { Write-Host ("  {0,-45} {1,5} events  first {2}  [{3}]" -f $_.User, $_.Events, $_.FirstSeenUtc, $_.Workloads) -ForegroundColor Yellow }
    Write-Host "  Review each in ip_hits.csv, then run Invoke-MailAccessTriage.ps1 for each confirmed account." -ForegroundColor Yellow
}

$sum = @"
Tenant           : $($org.DisplayName) ($($conn.TenantID))
Domain checked   : $domain
Bad IPs          : $($ips -join ', ')
Window (UTC)     : $($winStart.ToString('yyyy-MM-dd HH:mm')) -> $($winEnd.ToString('yyyy-MM-dd HH:mm'))  (first seen $($firstSeen.ToString('yyyy-MM-dd')) minus $LookbackDays days)
Matching events  : $($events.Count)$(if ($mismatch) { "  ($mismatch where the record's own IP field differs - review)" })
Accounts         : $($users.Count)  (likely compromised: $($compromised.Count); failed sign-ins only: $($attempts.Count)$(if ($victim) { "; known victim: $victim" }))
Output folder    : $((Resolve-Path $OutDir).Path)
Caveats          : IP matches need human review (shared VPN / mobile / cloud IPs). Audit events can take up to
                   24 hours to appear - re-run tomorrow for recent activity. Token refreshes (non-interactive
                   sign-ins) aren't in the audit log.
"@
$sum | Tee-Object -FilePath (Join-Path $OutDir 'sweep_summary.txt')
Disconnect-Sessions
if ($IsWindows -or $env:OS -eq 'Windows_NT') { try { Invoke-Item $OutDir } catch { Write-Verbose "Couldn't open the output folder: $_" } }
#endregion
}
