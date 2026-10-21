# Handoff: Invoke-MailAccessTriage.ps1

The status of `Invoke-MailAccessTriage.ps1` as of 2026-10-20 (baseline hardening pass), for continuing work in Claude Code.

## Purpose
This is incident response for a compromised Microsoft 365 mailbox (BEC). The flow is:

1. Read the Purview audit export.
2. The analyst selects the bad IPs.
3. Build reports of what the attacker accessed: mail, SharePoint/OneDrive files and Entra changes.
4. Build eDiscovery searches so the analyst can export a PST for the client to review.

The analyst runs the script on Windows, against client tenants, by **pasting it into a PowerShell console**. Work devices can't run unsigned `.ps1` files, so it must always work when pasted, and parameters can never be passed: everything that varies per incident is a prompt.

## Status
- **Production-tested** by Josh on a real client incident (2026-10-15/19). The mail flow, case creation, searches and PST export all worked. `InternetMessageId:` resolves as a KQL property: 92 message IDs returned 88 items.
- **Baseline hardening pass (2026-10-20)**, not yet run on a real incident:
  - **Tenant check:** the `OrganizationId` in the export is compared with every sign-in, and a mismatch stops before anything is created. Existing sessions are disconnected first, never reused. Against the old code, a wrong-tenant Purview sign-in created the case and searches in the wrong tenant without any error (reproduced in the tests).
  - **Paste-safe:** the whole script is one `& { }` block. Before this, `$ErrorActionPreference = 'Stop'` stayed set in the console after a run. Parameters were replaced by prompts (admin UPN, create searches Y/N, mailbox pick) plus a settings region.
  - **Analyst guard rails:** selecting `(none)` needs confirmation, and there's a warning when the export has no `MailItemsAccessed` at all.
  - **Search behaviour:** `MaxQueryLength` default raised to 9000, and polling stops on any finished status.
  - **Entra scope narrowed** to the user's own account changes: device, MFA, consent, password. There's a Category column, and device events in the attack window are printed.
  - **Tests rebuilt:** a Pester suite (18 tests) and CI on Linux, Windows pwsh and Windows PowerShell 5.1.
- **Tested only against fake data** (a mock CSV and fake tenant commands): `files_accessed.csv`, `entra_changes.csv` and the field mapping for both. They were added in `247eec9` and haven't yet been checked against a real export.

## Repo
- `joshmckibben/m365-mail-access-triage`, branch `main`.
- `Invoke-MailAccessTriage.ps1`: the script (single file, about 470 lines, one pasted script block).
- `tests/`: `New-FakeAuditExport.ps1` (fake export, reserved domains/IPs only) and `Invoke-MailAccessTriage.Tests.ps1`.
- `tools/Invoke-Checks.ps1`: lint + tests. `.github/workflows/checks.yml`: CI.
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
| settings/top | Settings region (`$SearchPrefix`, `$MaxQueryLength`, `$WaitMinutes`, `$EntraWindowHours`). Output root is `Documents\M365Triage` (or `$env:M365TRIAGE_OUTROOT`), falling back to `$HOME` | no |
| helpers | `Get-NormIP`, `Get-UtcTime`, `ConvertTo-FolderQueryId`, `Split-Query`, `Read-YesNo`, `Get-AdminUpn` (prompted once per run, held in `$run`, never global), `Disconnect-Sessions`, `Assert-Tenant`, `Connect-Exo` / `Connect-Ipps` (always disconnect first, then verify the tenant) | — |
| 1 parse | Prompts for the CSV path (quotes stripped, loops until the file exists); parses `AuditData`; removes duplicates by `Id`; keeps `Raw` and `Workload` on each event. Takes `$ExpectedTenant` from `OrganizationId` (stops if several; asks if none). Warns if there's no `MailItemsAccessed` | no |
| 2 IP select | Writes `ip_summary.csv` and `ip_list.txt`, copies the IP list to the clipboard and prints it, then the `Out-GridView` multi-select; confirms `(none)`; asks whether to create searches, then the case name | no |
| 3 mail | Mailbox pick if several owners; writes `badip_all_activity.csv` and `accessed_items.csv` (one row per Bind message ID; Sync rows carry the folder only); throttling warning | no |
| 3b files | Writes `files_accessed.csv` (SharePoint/OneDrive workloads, bad IPs only) | no |
| 3c Entra | Writes `entra_changes.csv`: the user's own account changes (device, MFA, consent, password), **not IP-filtered**, with `Category` and `InAttackWindow` = bad-IP first/last seen ± `$EntraWindowHours` (default 24). Device events in the window are printed | no |
| 4 folderid | Fresh, tenant-checked `Connect-ExchangeOnline -DisableWAM`; `Get-MailboxFolderStatistics`; writes `sync_folders.csv` | read |
| 5 KQL | Chunks `InternetMessageId:"<id>"` and `folderid:<hex>` queries by `$MaxQueryLength` (default 9000); writes `queries\*.txt` | no |
| 6 eDiscovery | Disconnects any existing Purview connection, reconnects with `-EnableSearchOnlySession -DisableWAM`, **verifies the tenant**; if the case exists, asks Use or New name; `New-ComplianceSearch` + `Start-ComplianceSearch` per chunk; polls until every search has finished (or `$WaitMinutes`); writes `searches.csv` | **creates the case and searches** |
| 7 summary | Writes `run_summary.txt`, prints the output path and opens the folder | no |

## Prompts and settings (no parameters: the script is pasted)
- Prompts: audit CSV path; bad IPs (grid); `(none)` confirmation; create searches Y/N; case name (Use/New if it exists); admin UPN (once per run); mailbox if several.
- Settings region at the top: `$SearchPrefix` (`BadIP`), `$MaxQueryLength` (9000), `$WaitMinutes` (30), `$EntraWindowHours` (24).
- `$env:M365TRIAGE_OUTROOT` overrides the output root.

## Safety constraints (keep these)
- The only tenant writes are `New-ComplianceCase`, `New-ComplianceSearch` and `Start-ComplianceSearch`.
- Every connection is fresh and tenant-checked against the export's `OrganizationId` before use. Never reuse an existing session.
- The script must stay paste-safe: everything inside the `& { }` block, no `$script:`/`$global:` state, no parameters.
- Never add `New-ComplianceSearchAction` (purge or export), holds, `Remove-*`, `Set-Mailbox*` or anything that sends mail.
- Search names are timestamped (`<prefix>_<yyyyMMddHHmm>_<Bind|Sync>_<nn>`), so reruns never collide.
- Client data stays local in `Documents\M365Triage`. It must stay out of the repo.

## Problems hit and fixed (don't regress)
1. "A window handle must be configured" when connecting to Exchange or Purview: fixed by passing `-DisableWAM` whenever the cmdlet supports it. Sources: [Centrel](https://www.centrel-solutions.com/blog/exchange-online-powershell-window-handle-error), [MS Tech Community](https://techcommunity.microsoft.com/discussions/exchange_general/windows-handle-error-when-using-connect-exchange-onlinew-module-version-3-7-/4372328).
2. Running `Start-ComplianceSearch` requires a Purview connection opened with `-EnableSearchOnlySession`. Fixed by disconnecting the Purview connection and reconnecting with the flag. Source: [MC1213770](https://mc.merill.net/message/MC1213770/v/2026-01-06T05-49-12-473Z). The user has to open a fresh PowerShell window after the error appears.
3. The ParserError from `-f` inside a hashtable literal: wrap the expression in parentheses.
4. Without quote stripping, a CSV path pasted with quotes fails, so quotes are now stripped.
5. Admin shells start in System32: hence the fixed `Documents\M365Triage` output folder.
6. A wrong-tenant sign-in (cached browser account, or a leftover session from another client) silently created the case and searches in the wrong tenant: fixed by the tenant check and fresh connections.
7. Pasting left `$ErrorActionPreference = 'Stop'` set in the console: fixed by the `& { }` wrapper. Keep per-run state out of `$script:` (that's global when pasted).

## Platform facts
- **Bind** `MailItemsAccessed` events list individual InternetMessageIds. **Sync** events list only the folder, so the whole folder must be treated as accessed. Throttling, at more than 1,000 Bind events in 24 hours, makes Bind logging incomplete. Source: [MS Learn: MailItemsAccessed forensics](https://learn.microsoft.com/id-id/microsoft-365/compliance/mailitemsaccessed-forensics-investigations).
- Search query limit: 10,000 characters for mailbox searches; 4,000 or 2,000 for sites. There's no keyword-count limit. Source: [MS Learn: eDiscovery limits](https://learn.microsoft.com/en-us/purview/ediscovery-limits-for-content-search). The limit is counted **after expansion** and includes any search permissions filters applied to the searching account. Message-ID and folderid terms don't expand, so the default 9000 leaves 1,000 characters of headroom (about 115 message IDs per search).
- `New-ComplianceSearchAction -Export` is retired. PST export is done in the portal only. Sources: [powershell.org](https://forums.powershell.org/t/export-parameter-retired-for-new-compliancesearchaction-seeking-alternatives/26133), [retirement notice](https://m365admin.handsontek.net/?p=13168).
- Classic eDiscovery was retired on 2025-08-31; this script targets the new Purview portal.

## Assumptions / unverified
- ~~SharePoint/OneDrive field names~~ **Confirmed 2026-10-21** on the real incident export: OneDrive file names and paths in `files_accessed.csv` came out correctly.
- Entra field names (`Target[].ID`, `ModifiedProperties`, `ResultStatus`) come from general knowledge of the audit log schema, not from a real export. Check them against a redacted sample row.
- The Entra operation regex (`device|security info|StrongAuthentication|authentication method|consent|delegated permission|password`) is scoped to user-level persistence. **Unverified:** whether a user-filtered Purview export even contains the device registration events. In Entra's own audit log the actor for "Add device" is the Device Registration Service, not the user. Next step: register a device as the lab victim and check the export (EverythingIsFine lab tenant).
- The fallback folder-ID conversion from `Folders[].Id` in the audit record is unverified. Results using it are labeled `audit Folder.Id (unverified)`.
- `Export-Csv` writes no file when there are zero rows; the summary still shows a count of 0.

## Testing
- `tests/Invoke-MailAccessTriage.Tests.ps1` runs each scenario in a fresh console process, **pasting** the script (`Invoke-Expression` of its text). Stubs record every call to `Out-GridView`, `Read-Host` (scripted answers), `Connect-*`, `Disconnect-ExchangeOnline`, `Get-ConnectionInformation`, `Get-MailboxFolderStatistics`, `*-ComplianceCase` and `*-ComplianceSearch`.
- `tests/New-FakeAuditExport.ps1` covers Bind (with a duplicate record), Sync (IPv4 with a port), legitimate IPs (including IPv6 with a port), an inbox rule, a OneDrive download, device registration in and out of the attack window, security info, `Update user.` (out of scope) and mixed-tenant / no-mail-access variants.
- Tenant-safety tests fail against the pre-hardening script (commit `4278921`).
- `TRIAGE_TEST_SHELL=powershell.exe` runs the script under Windows PowerShell 5.1 (CI does this on Windows).

## Ideas discussed, not built
- Combine the Bind searches into one PST via a review set, through the Graph eDiscovery API (needs eDiscovery Premium and an app registration or Graph sign-in).
- A search covering SharePoint/OneDrive file paths so the files themselves can be exported (site locations; 4,000/2,000-character limits; returns the current version of each file).
- Import an Entra sign-in log export (interactive + non-interactive) as a second, optional input, to add Location to the grid. On hold: Josh prefers manual lookups from the clipboard IP list for now. Needs real column names from a lab download.
- Enrich `accessed_items.csv` with subject and sender via Graph (declined for now).
- ~~A Pester test suite and CI.~~ Done 2026-10-20.
- Add details (rule conditions, Send subjects) to `badip_all_activity.csv`.

## Second script: Invoke-TenantIPSweep.ps1 (added 2026-10-21, branch `ip-sweep`, not yet run on a real tenant)
- **Purpose:** take the bad IPs (pasted, or from the clipboard) and search the whole tenant's unified audit log for activity from them, to find other compromised accounts.
- **Inputs (prompts):**
  - the IPs (validated: dotted-quad IPv4 or IPv6);
  - the first-seen date (UTC). The window is first seen minus `$LookbackDays` (14) up to now, clamped to 180 days;
  - the client domain, the admin UPN and an optional known victim.
- **Tenant check:** the typed domain must be in `Get-AcceptedDomain` of the signed-in tenant, then the analyst confirms the organisation name. The default answer is No.
- **Search:** `Search-UnifiedAuditLog -IPAddresses <batch of 20> -SessionCommand ReturnLargeSet`, pages of 5000.
  - A slice whose `ResultCount` reaches 50,000 is split in half recursively, down to 60 minutes.
  - **Paging counts unique `Identity` values.** ReturnLargeSet repeats records, and counting rows dropped the last records silently (caught by the tests).
  - Transient errors are retried 3 times.
- **Local double-check:** the record's own IP field is normalised with the same `Get-NormIP` (a test keeps both scripts identical). `IPMatch = False` flags records where it differs.
- **Assessment:** `LIKELY COMPROMISED` means any non-`UserLoginFailed` event; `Known victim`; `Failed sign-ins only`.
- **Read-only.** Never add tenant writes to this script.
- **Unverified (check in the lab):**
  1. whether `-IPAddresses` matches `MailItemsAccessed` (IP in `ClientIPAddress`) and IPv6 / port forms;
  2. how `-StartDate`/`-EndDate` treat a UTC `DateTime` (local vs UTC);
  3. whether there's a limit on how many IPs `-IPAddresses` accepts (batches of 20 as a precaution).
- **Later:** a message-trace check by source IP (deferred by Josh).
