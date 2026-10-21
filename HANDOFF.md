# Handoff: Invoke-MailAccessTriage.ps1

The status of `Invoke-MailAccessTriage.ps1` as of 2026-10-20, for continuing work in Claude Code.

## Purpose
This is incident response for a compromised Microsoft 365 mailbox (BEC). The flow is:

1. Read the Purview audit export.
2. The analyst selects the bad IPs.
3. Build reports of what the attacker accessed: mail, SharePoint/OneDrive files and Entra changes.
4. Build eDiscovery searches so the analyst can export a PST for the client to review.

The analyst runs the script by hand, on Windows, against client tenants.

## Status
- **Production-tested** by Josh on a real client incident (2026-10-15/19). The mail flow, case creation, searches and PST export all worked.
- **Tested only against fake data** (a mock CSV and fake tenant commands): `files_accessed.csv`, `entra_changes.csv` and the field mapping for both. They were added in `247eec9` and haven't yet been checked against a real export.

## Repo
- `joshmckibben/m365-mail-access-triage`, branch `main`.
- `Invoke-MailAccessTriage.ps1`: the script (single file, about 375 lines).
- `README.md`: usage, the outputs table and caveats.
- `.gitignore`: excludes `triage_*/` and `*.csv`. Never commit client data.

## Runtime requirements
- Windows PowerShell 5.1, or PowerShell 7 on Windows. `Out-GridView` is Windows-only.
- ExchangeOnlineManagement module, version 3.7.2 or later.
- Rights: folder statistics on the target mailbox (Exchange admin or equivalent) and eDiscovery Manager.
- Input: a Purview Audit search export CSV, filtered on the user only so every workload is included. It must have an `AuditData` column containing JSON.

## Flow (script regions, in order)
| Region | What it does | Touches the tenant? |
|---|---|---|
| params/top | Default `OutDir` is `Documents\M365Triage\triage_<ts>`, falling back to `$HOME` | no |
| helpers | `Get-NormIP` (strips the port, `[v6]`, `::ffff:`), `Get-UtcTime`, `ConvertTo-FolderQueryId`, `Split-Query`, connection helpers | — |
| 1 parse | Prompts for the CSV path (quotes stripped, loops until the file exists); parses `AuditData`; removes duplicates by `Id`; keeps `Raw` and `Workload` on each event | no |
| 2 IP select | Writes `ip_summary.csv`, then the `Out-GridView` multi-select; prompts for the case name unless `-NoSearch` | no |
| 3 mail | Writes `badip_all_activity.csv` and `accessed_items.csv` (one row per Bind message ID; Sync rows carry the folder only); throttling warning | no |
| 3b files | Writes `files_accessed.csv` (SharePoint/OneDrive workloads, bad IPs only) | no |
| 3c Entra | Writes `entra_changes.csv`: an operation regex, **not IP-filtered**, with `InAttackWindow` = bad-IP first/last seen ± `-EntraWindowHours` (default 24). The `(none)` IP row is excluded from the window calculation | no |
| 4 folderid | `Connect-ExchangeOnline -DisableWAM`, `Get-MailboxFolderStatistics`; writes `sync_folders.csv` | read |
| 5 KQL | Chunks `InternetMessageId:"<id>"` and `folderid:<hex>` queries by `-MaxQueryLength` (default 3500); writes `queries\*.txt` | no |
| 6 eDiscovery | Disconnects any existing Purview connection, reconnects with `-EnableSearchOnlySession -DisableWAM`; if the case exists, asks Use or New name; `New-ComplianceSearch` + `Start-ComplianceSearch` per chunk; polls up to `-WaitMinutes`; writes `searches.csv` | **creates the case and searches** |
| 7 summary | Writes `run_summary.txt`, prints the output path and opens the folder | no |

## Parameters
`-AuditCsv`, `-OutDir`, `-Mailbox`, `-CaseName`, `-AdminUpn`, `-SearchPrefix` (default `BadIP`), `-MaxQueryLength`, `-WaitMinutes`, `-EntraWindowHours`, `-NoSearch`

## Safety constraints (keep these)
- The only tenant writes are `New-ComplianceCase`, `New-ComplianceSearch` and `Start-ComplianceSearch`.
- Never add `New-ComplianceSearchAction` (purge or export), holds, `Remove-*`, `Set-Mailbox*` or anything that sends mail.
- Search names are timestamped (`<prefix>_<yyyyMMddHHmm>_<Bind|Sync>_<nn>`), so reruns never collide.
- Client data stays local in `Documents\M365Triage`. It must stay out of the repo.

## Problems hit and fixed (don't regress)
1. "A window handle must be configured" when connecting to Exchange or Purview: fixed by passing `-DisableWAM` whenever the cmdlet supports it. Sources: [Centrel](https://www.centrel-solutions.com/blog/exchange-online-powershell-window-handle-error), [MS Tech Community](https://techcommunity.microsoft.com/discussions/exchange_general/windows-handle-error-when-using-connect-exchange-onlinew-module-version-3-7-/4372328).
2. Running `Start-ComplianceSearch` requires a Purview connection opened with `-EnableSearchOnlySession`. Fixed by disconnecting the Purview connection and reconnecting with the flag. Source: [MC1213770](https://mc.merill.net/message/MC1213770/v/2026-01-06T05-49-12-473Z). The user has to open a fresh PowerShell window after the error appears.
3. The ParserError from `-f` inside a hashtable literal: wrap the expression in parentheses.
4. Without quote stripping, a CSV path pasted with quotes fails, so quotes are now stripped.
5. Admin shells start in System32: hence the fixed `Documents\M365Triage` output folder.

## Platform facts
- **Bind** `MailItemsAccessed` events list individual InternetMessageIds. **Sync** events list only the folder, so the whole folder must be treated as accessed. Throttling, at more than 1,000 Bind events in 24 hours, makes Bind logging incomplete. Source: [MS Learn: MailItemsAccessed forensics](https://learn.microsoft.com/id-id/microsoft-365/compliance/mailitemsaccessed-forensics-investigations).
- Search query limit: 10,000 characters for mailbox searches; 4,000 or 2,000 for sites. There's no keyword-count limit. Source: [MS Learn: eDiscovery limits](https://learn.microsoft.com/en-us/purview/ediscovery-limits-for-content-search). So `-MaxQueryLength 9500` is safe for mailbox-only searches.
- `New-ComplianceSearchAction -Export` is retired. PST export is done in the portal only. Sources: [powershell.org](https://forums.powershell.org/t/export-parameter-retired-for-new-compliancesearchaction-seeking-alternatives/26133), [retirement notice](https://m365admin.handsontek.net/?p=13168).
- Classic eDiscovery was retired on 2025-08-31; this script targets the new Purview portal.

## Assumptions / unverified
- SharePoint/OneDrive field names (`SourceFileName`, `SourceRelativeUrl`, `SiteUrl`, `ObjectId`, `SourceFileExtension`, `TargetUserOrGroupName`, `UserAgent`) and Entra field names (`Target[].ID`, `ModifiedProperties`, `ResultStatus`) come from general knowledge of the audit log schema, not from a real export. Check them against a redacted sample row.
- The Entra operation regex (`device|security info|StrongAuthentication|consent|...`) may be too broad or too narrow. Tune it on real data.
- The fallback folder-ID conversion from `Folders[].Id` in the audit record is unverified. Results using it are labeled `audit Folder.Id (unverified)`.
- `Export-Csv` writes no file when there are zero rows; the summary still shows a count of 0.

## Testing approach used
- Linux pwsh 7.4.6 with stub functions for `Out-GridView`, `Connect-*`, `Get-ConnectionInformation`, `Get-MailboxFolderStatistics`, `*-ComplianceCase`, `*-ComplianceSearch` and `Read-Host` (scripted answers).
- A mock CSV generator in Python covering Bind, Sync, a duplicate record, IPv6 with a port, an inbox rule, OneDrive `FileDownloaded`, Entra device and security-info changes, and `UserLoggedIn`.
- The harnesses lived in the old session's scratchpad and weren't kept. Suggested next step: rebuild them under `tests/` with Pester.

## Ideas discussed, not built
- Combine the Bind searches into one PST via a review set, through the Graph eDiscovery API (needs eDiscovery Premium and an app registration or Graph sign-in).
- A search covering SharePoint/OneDrive file paths so the files themselves can be exported (site locations; 4,000/2,000-character limits; returns the current version of each file).
- Import an Entra sign-in log export as a second, optional input.
- Enrich `accessed_items.csv` with subject and sender via Graph (declined for now).
- A Pester test suite and CI.
