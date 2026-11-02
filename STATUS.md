# Status

Update this at the end of each session: where the work stands, what's next, what's blocked.

Last updated: 2026-11-02

## Where it stands
- `main` is unchanged. Scripts: `Invoke-MailAccessTriage.ps1` and `Invoke-TenantIPSweep.ps1`, no release yet.
- Branch `feature/verified-release` is pushed: run procedure, hash checker with tests, hardened CI workflow, docs.
- Script behaviour is unchanged on the branch.
- `CLAUDE.md` now carries the session rule (Josh approved 2026-11-02).

## What's next
1. Josh tries the checker on a real Windows console and browser (planned for the same day as another check he has scheduled).
2. Josh chooses where the release note lives.
3. Josh reviews and merges the branch, then creates the first release and records its hashes.
4. Until then, the old run procedure is still what's in use on `main`.

## Blocked
- The first tagged release needs Josh: agents don't merge, tag or change repo settings here.
