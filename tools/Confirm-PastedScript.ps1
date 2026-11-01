& {
    # Confirm-PastedScript: paste this first, then copy a script from its Raw page. Reads the clipboard only.
    $approved = @{
        'TRIAGE-HASH' = 'Invoke-MailAccessTriage.ps1 vX.Y.Z'
        'SWEEP-HASH'  = 'Invoke-TenantIPSweep.ps1 vX.Y.Z'
    }
    $sha = [Security.Cryptography.SHA256]::Create()
    while ((Read-Host 'Copy the script from its Raw page, then press Enter here (q quits)') -ne 'q') {
        $text = ([string](Get-Clipboard -Raw)) -replace "`r`n?", "`n"
        if ($text -match 'Confirm-PastedScript') { continue }
        $bytes = [Text.Encoding]::UTF8.GetBytes($text.TrimEnd())
        $hash = ([BitConverter]::ToString($sha.ComputeHash($bytes)) -replace '-').ToLowerInvariant()
        if ($approved.ContainsKey($hash)) {
            Write-Host "MATCH: $($approved[$hash]). Paste it now, unedited." -ForegroundColor Green
            return
        }
        Write-Host "NO MATCH, do not paste this. SHA-256: $hash" -ForegroundColor Red
    }
}
