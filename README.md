# m365-mail-access-triage

BEC / compromised-mailbox triage for Microsoft 365.

Purview audit export → pick bad IPs → `MailItemsAccessed` breakdown (Bind message IDs + Sync folders) → eDiscovery searches ready for PST export.

## Requirements
- Windows PowerShell 5.1 or PowerShell 7 on Windows (uses `Out-GridView`)
- `ExchangeOnlineManagement` module 3.7.2+ (`Install-Module ExchangeOnlineManagement`)
- Rights: folder statistics on the mailbox; eDiscovery Manager for searches

## Usage
1. Purview → Audit → search the account for the access window → export CSV.
2. Run:
   ```powershell
   .\Invoke-MailAccessTriage.ps1 -AuditCsv "C:\path\export.csv" -CaseName "Client-BEC-2026-10" -AdminUpn you@tenant.com
   ```
3. Select the bad IPs in the grid → OK.
4. Purview → eDiscovery → case → each search → Export → PST.

`-NoSearch` builds the CSVs and queries without creating searches.

## Output (`.\triage_<timestamp>\`)
| File | Contents |
|---|---|
| `ip_summary.csv` | All IPs: event / Bind / Sync counts, first/last seen, operations, clients |
| `accessed_items.csv` | Client deliverable: InternetMessageId, TimestampUtc, IP, Bind/Sync, folder, session |
| `badip_all_activity.csv` | Every operation from bad IPs (Send, inbox rules, deletes…) |
| `sync_folders.csv` | Sync folders → `folderid:` values |
| `queries\*.txt` | Chunked KQL per search |
| `searches.csv` | Search names, status, hit counts |
| `run_summary.txt` | Totals + warnings |

## Notes / caveats
- **Bind** events list individual InternetMessageIds. **Sync** events only list folders; treat the whole folder as accessed.
- If `Throttled = True` appears, Bind logging is incomplete; treat the whole mailbox as accessed for that window.
- `InternetMessageId:` as a KQL property is unverified per tenant. If Bind searches return 0, test one ID by hand.
- Bind hits < ID count usually means the items were purged or are duplicated across folders.
- `-MaxQueryLength` (default 3500) is a guess at the KQL limit; lower it if searches error.
- Sign-in uses `-DisableWAM` when available, to avoid "A window handle must be configured".
