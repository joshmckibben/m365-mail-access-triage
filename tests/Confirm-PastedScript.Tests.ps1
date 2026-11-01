#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

# Each scenario pastes the checker into a fresh console process, with Read-Host and Get-Clipboard stubbed.
# Every Get-Clipboard call returns the next file's exact text, so line endings reach the checker unchanged.
# The stub honours -Raw like the real cmdlet: without it, the text comes back split into lines.

BeforeAll {
    $script:CheckerPath = Join-Path $PSScriptRoot '..' 'tools' 'Confirm-PastedScript.ps1'
    $script:TriagePath = Join-Path $PSScriptRoot '..' 'Invoke-MailAccessTriage.ps1'
    $script:SweepPath = Join-Path $PSScriptRoot '..' 'Invoke-TenantIPSweep.ps1'
    $script:Pwsh = if ($env:TRIAGE_TEST_SHELL) { $env:TRIAGE_TEST_SHELL } else { (Get-Process -Id $PID).Path }
    $script:Utf8 = [Text.UTF8Encoding]::new($false)

    # The release hash, worked out separately from the checker: LF endings, no trailing newline, UTF-8.
    function Get-ReleaseHash([string]$Text) {
        $file = Join-Path $TestDrive "$([guid]::NewGuid()).bin"
        [IO.File]::WriteAllText($file, ($Text -replace "`r`n", "`n").TrimEnd(), $script:Utf8)
        (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant()
    }

    function Invoke-Checker {
        param([string[]]$Clipboards, [string[]]$Answers, [string]$TriageHash = 'unused-a', [string]$SweepHash = 'unused-b')
        $checker = (Get-Content -LiteralPath $script:CheckerPath -Raw).Replace('TRIAGE-HASH', $TriageHash).Replace('SWEEP-HASH', $SweepHash)
        $checkerFile = Join-Path $TestDrive "$([guid]::NewGuid()).txt"
        [IO.File]::WriteAllText($checkerFile, $checker, $script:Utf8)
        $clipFiles = foreach ($clip in $Clipboards) {
            $f = Join-Path $TestDrive "$([guid]::NewGuid()).txt"
            [IO.File]::WriteAllText($f, $clip, $script:Utf8)
            "'$f'"
        }
        $answerList = ($Answers | ForEach-Object { "'$_'" }) -join ', '
        $resultFile = Join-Path $TestDrive "$([guid]::NewGuid()).json"
        $harness = Join-Path $TestDrive "$([guid]::NewGuid()).ps1"

        @"
`$global:Answers = [System.Collections.Generic.List[string]]::new([string[]]@($answerList))
`$global:ClipFiles = [System.Collections.Generic.List[string]]::new([string[]]@($($clipFiles -join ', ')))
`$global:Prompts = 0
function global:Read-Host { param([Parameter(Position = 0)]`$Prompt)
    `$global:Prompts++
    if (`$global:Answers.Count -eq 0) { throw "Unexpected prompt: `$Prompt" }
    `$a = `$global:Answers[0]; `$global:Answers.RemoveAt(0); `$a }
function global:Get-Clipboard { param([switch]`$Raw)
    `$text = [IO.File]::ReadAllText(`$global:ClipFiles[0]); `$global:ClipFiles.RemoveAt(0)
    if (`$Raw) { `$text } else { `$text -split "``r?``n" } }

`$err = `$null
try { Invoke-Expression ([IO.File]::ReadAllText('$checkerFile')) *>&1 | Out-String | Set-Variable -Name Console -Scope Global }
catch { `$err = `$_.Exception.Message }
[pscustomobject]@{ Error = `$err; Console = `$global:Console; Prompts = `$global:Prompts; Unanswered = `$global:Answers.Count } |
    ConvertTo-Json | Set-Content -LiteralPath '$resultFile'
"@ | Set-Content -LiteralPath $harness -Encoding utf8

        & $script:Pwsh -NoProfile -NonInteractive -Command ". '$harness'" | Out-Null
        Get-Content -LiteralPath $resultFile -Raw | ConvertFrom-Json
    }

    $script:Text = "line one`n  indented line`n`nlast line`n"
    $script:Hash = Get-ReleaseHash $script:Text
}

Describe 'Confirm-PastedScript' {
    It 'matches however the browser hands over the text: <Name>' -TestCases @(
        @{ Name = 'as in the file'; Clip = "line one`n  indented line`n`nlast line`n" }
        @{ Name = 'no final newline'; Clip = "line one`n  indented line`n`nlast line" }
        @{ Name = 'CRLF endings'; Clip = "line one`r`n  indented line`r`n`r`nlast line`r`n" }
        @{ Name = 'CRLF, no final newline'; Clip = "line one`r`n  indented line`r`n`r`nlast line" }
        @{ Name = 'extra blank lines at the end'; Clip = "line one`n  indented line`n`nlast line`n`n`n" }
    ) {
        $r = Invoke-Checker -Clipboards $Clip -Answers '' -TriageHash $script:Hash
        $r.Error | Should -BeNullOrEmpty
        $r.Console | Should -Match 'MATCH: Invoke-MailAccessTriage\.ps1'
        $r.Console | Should -Not -Match 'NO MATCH'
    }

    It 'names which script matched' {
        $r = Invoke-Checker -Clipboards $script:Text -Answers '' -SweepHash $script:Hash
        $r.Console | Should -Match 'MATCH: Invoke-TenantIPSweep\.ps1'
    }

    It 'matches both real scripts as they would arrive from a browser on Windows' {
        foreach ($path in $script:TriagePath, $script:SweepPath) {
            $text = [IO.File]::ReadAllText($path)
            $crlf = ($text -replace "`r`n", "`n" -replace "`n", "`r`n").TrimEnd()
            $r = Invoke-Checker -Clipboards $crlf -Answers '' -TriageHash (Get-ReleaseHash $text)
            $r.Console | Should -Match 'MATCH: '
            $r.Console | Should -Not -Match 'NO MATCH'
        }
    }

    It 'refuses a one-character change and prints the hash it got' {
        $r = Invoke-Checker -Clipboards ($script:Text -replace 'last', 'lost'), 'x' -Answers '', 'q' -TriageHash $script:Hash
        $r.Console | Should -Match 'NO MATCH, do not paste this\. SHA-256: [0-9a-f]{64}'
        $r.Console | Should -Not -Match '(?m)^MATCH: '
    }

    It 'refuses changed indentation inside the script' {
        $r = Invoke-Checker -Clipboards ($script:Text -replace '  indented', ' indented') -Answers '', 'q' -TriageHash $script:Hash
        $r.Console | Should -Match 'NO MATCH'
    }

    It 'refuses an empty clipboard' {
        $r = Invoke-Checker -Clipboards '' -Answers '', 'q' -TriageHash $script:Hash
        $r.Console | Should -Match 'NO MATCH'
    }

    It 'waits rather than failing when the clipboard still holds the checker' {
        # A trailing newline in the pasted checker answers the first prompt before the script has been copied.
        $self = Get-Content -LiteralPath $script:CheckerPath -Raw
        $r = Invoke-Checker -Clipboards $self, $script:Text -Answers '', '' -TriageHash $script:Hash
        $r.Prompts | Should -Be 2
        $r.Console | Should -Not -Match 'NO MATCH'
        $r.Console | Should -Match 'MATCH: Invoke-MailAccessTriage\.ps1'
    }

    It 'lets a recopy succeed after a bad copy' {
        $r = Invoke-Checker -Clipboards 'half a scr', $script:Text -Answers '', '' -TriageHash $script:Hash
        $r.Console | Should -Match 'NO MATCH'
        $r.Console | Should -Match '(?m)^MATCH: '
    }

    It 'quits on q without reading the clipboard' {
        $r = Invoke-Checker -Clipboards @() -Answers 'q'
        $r.Error | Should -BeNullOrEmpty
        $r.Console | Should -Not -Match 'MATCH'
    }

    It 'only reads the clipboard: nothing here can run, fetch or write' {
        $tokens = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path $script:CheckerPath).Path, [ref]$tokens, [ref]$null)
        $commands = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) |
            ForEach-Object { $_.GetCommandName() } | Where-Object { $_ } | Sort-Object -Unique
        $commands | Should -Be @('Get-Clipboard', 'Read-Host', 'Write-Host')
    }
}
