# m365-mail-access-triage

[![checks](https://github.com/joshmckibben/m365-mail-access-triage/actions/workflows/checks.yml/badge.svg)](https://github.com/joshmckibben/m365-mail-access-triage/actions/workflows/checks.yml)

BEC / compromised-mailbox triage for Microsoft 365.

Purview audit export → pick bad IPs → `MailItemsAccessed` breakdown (Bind message IDs + Sync folders) → eDiscovery searches ready for PST export.

## Requirements
- Windows, PowerShell 7 or Windows PowerShell 5.1 (uses `Out-GridView`)
- `ExchangeOnlineManagement` module 3.7.2+ (`Install-Module ExchangeOnlineManagement`)
- Rights: folder statistics on the mailbox; eDiscovery Manager for searches

## Usage
1. Purview → Audit → search **the affected user only** (so every workload is included) for the access window → export CSV.
2. Get the script as described in [Run a verified copy](#run-a-verified-copy), then **paste it into a PowerShell console**.
   The whole script runs inside one script block, so nothing is left behind in your console afterwards.
3. Answer the prompts:
   - **Audit CSV path**, without quotation marks (quotes are stripped if you add them anyway).
   - **Bad IPs:** just before the grid opens, every IP is **copied to your clipboard** (most events first), printed in
     the console and saved as `ip_list.txt`. The grid waits for you, so you can paste the list into a bulk IP lookup
     site first, then come back and select the bad ones → OK. Selecting `(none)` (events without an IP) asks for confirmation.
   - **Create the eDiscovery case and searches?** Answer `n` to build the CSVs and query files only.
   - **Case name.** If that case already exists, you're shown its searches and choose to [U]se it or enter a [N]ew name.
   - **Admin UPN** for *this client's* tenant. It's asked once per run and never reused by a later run.
   - **Mailbox**, only if the export covers more than one.
4. Purview → eDiscovery → case → each search → Export → PST.

Settings at the top of the script (query length, polling time, Entra window) can be edited before pasting, but only
after the hash check, and an edited copy is no longer the approved one. Prefer the defaults on a real incident.
To write output somewhere other than `Documents\M365Triage`, set `$env:M365TRIAGE_OUTROOT` before pasting.

## Run a verified copy
Don't run either script from `main`. Run a tagged release, and check it against the hash in your release note before
pasting. The release note is kept **outside GitHub**, somewhere only you can write. A hash stored in this repo proves
nothing, because anything that can change the script here could change the hash too.

1. Open a fresh PowerShell console and your release note.
2. Copy the checker from the note and paste it into the console. It waits for you.
3. Open the script's Raw link from the note → select all → copy → back in the console, press **Enter**.
4. **MATCH** (green): paste the script into the console. It's still on the clipboard. Don't copy anything else first.
5. **NO MATCH** (red): don't paste it. Recopy once, in case the first copy was incomplete. If it still fails, stop, and
   use the previous release in your note until you know why.

The checker only reads the clipboard: it doesn't run, download or save anything. Nothing goes to disk, so the limit on
unsigned `.ps1` files doesn't come into it. It ignores line endings and blank lines at the very end, because browsers
change those when copying. Everything else has to match exactly.

No note to hand means no verified copy. Don't fall back to `main`.

## Releasing
Only a person does this, and only from a device that can reach the release note. Agents may prepare a branch and these
steps, but they never tag, and any hash they report is not the trusted one.

1. Review the changes on GitHub: `compare/<previous tag>...main`. Read every change to the two scripts.
2. Create the release and tag on merged `main`: `vMAJOR.MINOR.PATCH`.
3. Review `compare/<previous tag>...<new tag>`. It should show what you reviewed in step 1, nothing more.
4. Paste your checker and copy each script from its tag's Raw page. It prints `NO MATCH` with the SHA-256, because the
   note doesn't know this release yet. Those are the new hashes.
5. Add them to the checker in your note with the new version, and update the Raw links:
   `https://raw.githubusercontent.com/joshmckibben/m365-mail-access-triage/refs/tags/<tag>/<script>.ps1`
   Keep the previous release in the note as the fallback.

Keep using the checker already in your note. `tools/Confirm-PastedScript.ps1` is its source and is covered by the tests,
but copy it from the repo only when you've read that diff too. To work out a hash without the checker, on a copy with
LF endings: `printf %s "$(cat <script>.ps1)" | sha256sum`.

## Tenant safety
- The export says which tenant it came from (`OrganizationId` in every record). After **every** sign-in, the
  script checks the session is in that tenant. On a mismatch it disconnects and stops **before anything is created**.
- Existing Exchange / Purview sessions in the console are disconnected first, never reused. They might belong to another client.
- The only tenant writes are `New-ComplianceCase`, `New-ComplianceSearch` and `Start-ComplianceSearch`.

## Output (`Documents\M365Triage\triage_<timestamp>\`)
A fixed location, so it doesn't matter which folder the shell is in. The path is printed at the end and the folder opens automatically.

| File | Contents |
|---|---|
| `ip_summary.csv` | All IPs: event / Bind / Sync counts, first/last seen, operations, clients |
| `ip_list.txt` | Just the IPs, one per line (also copied to the clipboard), for bulk lookup sites |
| `accessed_items.csv` | Client deliverable: InternetMessageId, TimestampUtc, IP, Bind/Sync, folder, session |
| `files_accessed.csv` | SharePoint/OneDrive events from bad IPs: operation, file name, folder, site, full URL, share target |
| `entra_changes.csv` | The user's own account changes: **device registration**, MFA / security info, app consent, password. Category column. **Not IP-filtered**, because Entra records often have no client IP. `InAttackWindow` = within 24 h (setting) of the bad-IP first/last seen. Device events in the window are also printed as a warning |
| `badip_all_activity.csv` | Every operation from bad IPs (Send, inbox rules, deletes…) |
| `sync_folders.csv` | Sync folders → `folderid:` values |
| `queries\*.txt` | Chunked KQL per search |
| `searches.csv` | Search names, status, hit counts |
| `run_summary.txt` | Totals + warnings |

## Notes / caveats
- **Bind** events list individual InternetMessageIds. **Sync** events only list folders; treat the whole folder as accessed.
- If `Throttled = True` appears, Bind logging is incomplete; treat the whole mailbox as accessed for that window.
- **No `MailItemsAccessed` events at all** → the script warns. The tenant may not be logging mail access
  (licence / audit tier). That's not evidence that no mail was read.
- `InternetMessageId:` works as a KQL property: on a real incident (2026-10), 92 message IDs returned 88 items.
  Bind hits below the ID count usually mean the items were purged or are duplicated across folders.
  If a tenant returns 0 Bind hits, test one ID by hand in the portal.
- **Query length:** the mailbox search limit is 10,000 characters, counted *after* expansion and including any
  search permissions filters applied to the searching account. Message-ID and folderid terms are exact values
  (no wildcards), so they don't expand. The default of **9,000** leaves 1,000 characters of headroom. That's about
  115 message IDs per search, so fewer searches and fewer PST exports. If a search ever errors on length, lower
  `$MaxQueryLength` in the settings.
- **Entra scope:** user-level changes only (what an attacker can do with the user's own access). Admin-only
  operations aren't in scope, because client users don't have admin rights.
- Sign-in uses `-DisableWAM` when available, to avoid "A window handle must be configured".

## Tenant-wide IP sweep (`Invoke-TenantIPSweep.ps1`)

Once you know the attacker's IPs, sweep the **whole tenant** for activity from them: which other accounts did they get into?

1. Get the script as described in [Run a verified copy](#run-a-verified-copy), then paste it into a PowerShell console.
2. Answer the prompts:
   - **Bad IPs:** paste them one per line (or separated by commas/spaces), then press Enter on an empty line.
     Or press Enter straight away to use the clipboard. Anything that isn't an IP is ignored, with a warning.
   - **First-seen date** (UTC, `yyyy-MM-dd`, from the triage run's `ip_summary.csv`). The search runs from
     **14 days before** that date up to now, clamped to the 180-day audit retention.
   - **Client domain** and **admin UPN**. After sign-in, the domain must be one of the tenant's accepted domains,
     and you confirm the organisation name before anything is searched.
   - **Known victim** (optional), so that account is labelled rather than reported as new.
3. Review the output (`Documents\M365Triage\ipsweep_<timestamp>\`):

| File | Contents |
|---|---|
| `users_summary.csv` | Every account with activity from the bad IPs: **LIKELY COMPROMISED** (any successful activity) first, then the known victim, then **failed sign-ins only**. Counts of sign-ins, mail access, sends, inbox-rule changes, file events |
| `ip_hits.csv` | Every matching event: time, user, workload, operation, IP, logon error, client. `IPMatch = False` means the search matched but the record's own IP field differs - review |
| `failed_signins.csv` | Failed sign-ins with the logon error (password spraying vs. wrong-user attempts) |
| `ip_summary.csv` | Per bad IP: accounts, events, first/last seen |
| `audit_records.csv` | The raw audit records, in the same columns as a Purview export (evidence) |
| `sweep_summary.txt` | Totals, the window and caveats |

**Read-only:** the only tenant calls are sign-in, `Get-AcceptedDomain`, `Get-OrganizationConfig` and
`Search-UnifiedAuditLog`. Needs the **View-Only Audit Logs** (or Audit Logs) role.

**Limitations**
- IP matches need human review: legitimate users can share an IP with an attacker (VPN providers, mobile carriers, cloud hosting).
- Exact IPs only, no ranges.
- Audit events can take up to 24 hours to appear. Re-run the next day for recent activity.
- Token refreshes (non-interactive sign-ins) aren't in the audit log. A stolen token can show up as mail or file activity with no matching sign-in.
- Search sessions are capped at 50,000 results. Busy time slices are split automatically, and a warning is shown if a one-hour slice still hits the cap.
- **To verify in the lab:** that the IP filter matches `MailItemsAccessed` records (which store the IP in a different field).

## Development
```powershell
./tools/Invoke-Checks.ps1                                         # lint + Pester
$env:TRIAGE_TEST_SHELL = 'powershell.exe'; ./tools/Invoke-Checks.ps1  # run the script under Windows PowerShell 5.1
```
The tests paste each script into a fresh console process, with every tenant and UI cmdlet replaced by a
recording stub, and a fake audit export (reserved domains and IPs only). CI runs them on Linux, Windows
(pwsh) and Windows PowerShell 5.1. `tests/Confirm-PastedScript.Tests.ps1` does the same for the hash checker, with a
stubbed clipboard.
