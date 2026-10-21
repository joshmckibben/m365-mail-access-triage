# Builds a fake Purview audit export CSV for tests. All addresses, IPs and IDs are reserved/fictional:
# example domains, TEST-NET IPs (192.0.2.x, 198.51.100.x, 203.0.113.x) and the 2001:db8:: documentation range.

$script:FakeTenant = '11111111-1111-1111-1111-111111111111'
$script:BadIP      = '203.0.113.10'
$script:GoodIP     = '198.51.100.20'
$script:Victim     = 'alex@contoso.example'

function New-FakeAuditRecord {
    param(
        [Parameter(Mandatory)][string]$Operation,
        [Parameter(Mandatory)][string]$Workload,
        [Parameter(Mandatory)][datetime]$TimeUtc,
        [hashtable]$Extra = @{},
        [string]$Id = [guid]::NewGuid().ToString(),
        [string]$OrganizationId = $script:FakeTenant
    )
    $data = [ordered]@{
        Id             = $Id
        CreationTime   = $TimeUtc.ToString('yyyy-MM-ddTHH:mm:ss')
        Operation      = $Operation
        Workload       = $Workload
        OrganizationId = $OrganizationId
        UserId         = $script:Victim
    }
    foreach ($k in $Extra.Keys) { $data[$k] = $Extra[$k] }
    [pscustomobject]@{
        RecordId     = $Id
        CreationDate = $TimeUtc.ToString('yyyy-MM-ddTHH:mm:ss')
        RecordType   = 'ExchangeItem'
        Operation    = $Operation
        UserId       = $script:Victim
        AuditData    = ($data | ConvertTo-Json -Depth 10 -Compress)
    }
}

function New-FakeMia {
    param([string]$IP, [string]$AccessType, [datetime]$TimeUtc, [object[]]$Folders, [string]$Id = [guid]::NewGuid().ToString(), [switch]$Throttled)
    New-FakeAuditRecord -Operation 'MailItemsAccessed' -Workload 'Exchange' -TimeUtc $TimeUtc -Id $Id -Extra @{
        ClientIPAddress     = $IP
        MailboxOwnerUPN     = $script:Victim
        ClientInfoString    = 'Client=OWA;Action=ViaProxy'
        SessionId           = 'sess-1'
        OperationProperties = @(
            @{ Name = 'MailAccessType'; Value = $AccessType }
            @{ Name = 'IsThrottled'; Value = $(if ($Throttled) { 'True' } else { 'False' }) }
        )
        Folders             = $Folders
    }
}

function New-FakeAuditExport {
    <#
    .SYNOPSIS
        Writes a fake audit export to -Path. Scenario switches change the content.
    .PARAMETER NoMailItemsAccessed
        Leave out every MailItemsAccessed record (tenant that doesn't log mail access).
    .PARAMETER MixedTenants
        Give one record a different OrganizationId.
    .PARAMETER NoSync
        Leave out the Sync record (so the first tenant connection is the Purview one).
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$NoMailItemsAccessed,
        [switch]$MixedTenants,
        [switch]$NoSync
    )

    $t0 = [datetime]::SpecifyKind([datetime]'2026-10-15T09:00:00', 'Utc')
    $records = [System.Collections.Generic.List[object]]::new()

    if (-not $NoMailItemsAccessed) {
        # Bind from the bad IP: 2 messages in Inbox, 1 in Archive
        $bind = New-FakeMia -IP $script:BadIP -AccessType 'Bind' -TimeUtc $t0 -Id 'bind-1' -Folders @(
            @{ Path = '\Inbox'; Id = 'audit-inbox'; FolderItems = @(@{ InternetMessageId = '<msg1@contoso.example>' }, @{ InternetMessageId = '<msg2@contoso.example>' }) }
            @{ Path = '\Archive'; Id = 'audit-archive'; FolderItems = @(@{ InternetMessageId = '<msg3@contoso.example>' }) }
        )
        $records.Add($bind)
        $records.Add($bind)   # exports often contain duplicates

        # Sync from the bad IP (IPv4 with port)
        if (-not $NoSync) {
            $records.Add((New-FakeMia -IP "$($script:BadIP):51234" -AccessType 'Sync' -TimeUtc $t0.AddMinutes(5) -Folders @(@{ Path = '\Inbox'; Id = 'audit-inbox' })))
        }

        # Legitimate Bind from the user's own IP: must NOT appear in the results
        $records.Add((New-FakeMia -IP $script:GoodIP -AccessType 'Bind' -TimeUtc $t0.AddHours(-3) -Folders @(
            @{ Path = '\Inbox'; Id = 'audit-inbox'; FolderItems = @(@{ InternetMessageId = '<legit@contoso.example>' }) }
        )))

        # IPv6 with port, legitimate
        $records.Add((New-FakeMia -IP '[2001:db8::1]:443' -AccessType 'Bind' -TimeUtc $t0.AddHours(-2) -Folders @(
            @{ Path = '\Inbox'; Id = 'audit-inbox'; FolderItems = @(@{ InternetMessageId = '<legit2@contoso.example>' }) }
        )))
    }

    # Inbox rule created from the bad IP
    $records.Add((New-FakeAuditRecord -Operation 'New-InboxRule' -Workload 'Exchange' -TimeUtc $t0.AddMinutes(10) -Extra @{ ClientIP = "$($script:BadIP):60000" }))

    # OneDrive download from the bad IP
    $records.Add((New-FakeAuditRecord -Operation 'FileDownloaded' -Workload 'OneDrive' -TimeUtc $t0.AddMinutes(20) -Extra @{
        ClientIP = $script:BadIP; SourceFileName = 'Q3 invoices.xlsx'; SourceRelativeUrl = 'Documents/Finance'
        SiteUrl = 'https://contoso-my.sharepoint.example/personal/alex'; ObjectId = 'https://contoso-my.sharepoint.example/personal/alex/Documents/Finance/Q3 invoices.xlsx'
        SourceFileExtension = 'xlsx'; UserAgent = 'python-requests/2.31'
    }))

    # Entra: device registered on the user's account during the attack, no IP
    $records.Add((New-FakeAuditRecord -Operation 'Add registered owner to device.' -Workload 'AzureActiveDirectory' -TimeUtc $t0.AddMinutes(30) -Extra @{
        ResultStatus = 'Success'
        Target       = @(@{ ID = 'Device_aaaaaaaa-0000-0000-0000-000000000000' }, @{ ID = 'DESKTOP-ATTACKER' })
    }))
    # Entra: MFA method added during the attack
    $records.Add((New-FakeAuditRecord -Operation 'User registered security info.' -Workload 'AzureActiveDirectory' -TimeUtc $t0.AddMinutes(35) -Extra @{ ResultStatus = 'Success' }))
    # Entra: device activity a week earlier: in scope, but outside the attack window
    $records.Add((New-FakeAuditRecord -Operation 'Add registered owner to device.' -Workload 'AzureActiveDirectory' -TimeUtc $t0.AddDays(-7) -Extra @{
        ResultStatus = 'Success'; Target = @(@{ ID = 'ALEX-LAPTOP' })
    }))
    # Entra: admin-style noise that's now out of scope
    $records.Add((New-FakeAuditRecord -Operation 'Update user.' -Workload 'AzureActiveDirectory' -TimeUtc $t0.AddMinutes(40) -Extra @{ ResultStatus = 'Success' }))

    if ($MixedTenants) {
        $records.Add((New-FakeAuditRecord -Operation 'UserLoggedIn' -Workload 'AzureActiveDirectory' -TimeUtc $t0 -OrganizationId '99999999-9999-9999-9999-999999999999'))
    }

    $records | Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding utf8
}
