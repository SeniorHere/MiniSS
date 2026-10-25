<#
.SYNOPSIS
    MiniSS - Mini ScreenShare scanner
    Author : Senior
    Discord: https://discord.gg/95MmttMD6

.DESCRIPTION
    Looks for well-known Minecraft cheat / injector / macro strings in:
      - files (.jar .exe .dll .bat .cmd)  - jar files are opened and checked inside
      - running processes
      - Prefetch + Recent traces (programs that ran before, even if deleted)
    Everything stays on this PC. Nothing is uploaded, deleted or changed.
    Suspicious strings are shown in RED. A CSV + HTML report is saved on the Desktop.

.PARAMETER Mode
    Quick = your user profile (Desktop, Downloads, AppData\.minecraft ...)  [default]
    Full  = every fixed / removable drive (slower)
.PARAMETER Path
    Scan only these folders (overrides Mode).
.PARAMETER ShowWeak
    Also list files that only match a single weak keyword.
.PARAMETER NoPause
    Do not wait for Enter at the end.

.EXAMPLE
    .\MiniSS.ps1
    .\MiniSS.ps1 -Mode Full
    .\MiniSS.ps1 -Path "$env:APPDATA\.minecraft"
#>
[CmdletBinding()]
param(
    [ValidateSet('Quick', 'Full')][string]$Mode = 'Quick',
    [string[]]$Path,
    [switch]$ShowWeak,
    [switch]$NoPause,
    [int]$MaxSizeMB = 200,
    [string]$OutDir = [Environment]::GetFolderPath('Desktop')
)

$ErrorActionPreference = 'SilentlyContinue'
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }

$Author = 'Senior'
$Invite = 'https://discord.gg/95MmttMD6'

# ---------------------------------------------------------------------------
# 1) Signature database   weight: 3 = strong, 2 = medium, 1 = weak (ambiguous)
# ---------------------------------------------------------------------------
$db = @{}
function Add-Terms {
    param([int]$Weight, [string[]]$List)
    foreach ($t in $List) { $db[$t] = $Weight }
}

# Strong: combat / PvP cheat modules
Add-Terms 3 @(
    'AutoTotem', 'InventoryTotem', 'InvTotem', 'AutoInventoryTotem', 'TotemHit',
    'AutoCrystal', 'CrystalAura', 'OneHitCrystal', 'CrystalOptimizer', 'FastCrystal', 'AutoHitCrystal',
    'AnchorMacro', 'AnchorAura', 'AutoAnchor',
    'AutoStun', 'StunSlam', 'Stun-Slam', 'ShieldBreaker', 'AutoPot', 'AutoDoubleHand', 'DoubleHand',
    'TriggerBot', 'KillAura', 'AimAssist', 'AimBot', 'AutoClicker',
    'InvMove', 'MaceDMG', 'MaceAura', 'AutoMace', 'NoFall', 'AutoWTap', 'ScaffoldWalk',
    'AutoCrit', 'HitSelect', 'PacketFly', 'ElytraFly', 'AntiKnockback', 'NoKnockback', 'NoSlowdown'
)
# Strong: well-known cheat clients / loaders
Add-Terms 3 @(
    'LiquidBounce', 'meteordevelopment', 'meteor-client', 'wurstclient', 'wurst-client',
    'Aristois', 'RusherHack', 'ThunderHack', 'FutureClient', 'vape.gg', 'VapeV4', 'VapeLite',
    'RavenB', 'DoomsdayClient', 'NovolineClient', 'RiseClient', 'TenacityClient', 'AstolfoClient',
    '3arthh4ck', 'SalHack', 'KamiBlue', 'BleachHack', 'ForgeHax', 'GameSense', 'Pandaware', 'Konas', 'Nodus'
)
# Medium
Add-Terms 2 @(
    'ClickGUI', 'Criticals', 'ReachHack', 'Backtrack', 'TinyTask', 'GSAutoClicker', 'OPAutoClicker',
    'SpeedAutoClicker', 'AutoTrap', 'HoleFiller', 'SelfFill', 'FastBreak'
)
# Weak: common words that also appear in harmless files
Add-Terms 1 @(
    'Flight', 'Macro', 'Velocity', 'XRay', 'FastPlace', 'Hitbox', 'Bhop', 'WallHack', 'Injector',
    'AutoHotkey', 'Surround', 'AutoArmor', 'FreeCam', 'Phobos', 'Slinky', 'Exhibition', 'Entropy'
)

$allTerms = [string[]]@($db.Keys)

# ---------------------------------------------------------------------------
# 2) Byte-level matching engine (compiled once; works on Windows PowerShell 5.1 and 7)
# ---------------------------------------------------------------------------
if (-not ('SigCore' -as [type])) {
    $csharp = @'
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Text;

public static class SigCore
{
    static byte[][] pats = new byte[0][];
    static string[] tags = new string[0];
    static List<int>[] byFirst = new List<int>[256];
    static int longest = 1;
    const int Chunk = 4 * 1024 * 1024;

    public static void Load(string[] terms)
    {
        var p = new List<byte[]>();
        var t = new List<string>();
        byFirst = new List<int>[256];
        longest = 1;
        foreach (string term in terms)
        {
            string low = term.ToLowerInvariant();
            byte[] ascii = Encoding.ASCII.GetBytes(low);
            byte[] wide = Encoding.Unicode.GetBytes(low);
            foreach (byte[] b in new byte[][] { ascii, wide })
            {
                p.Add(b);
                t.Add(term);
                int idx = p.Count - 1;
                if (byFirst[b[0]] == null) byFirst[b[0]] = new List<int>();
                byFirst[b[0]].Add(idx);
                if (b.Length > longest) longest = b.Length;
            }
        }
        pats = p.ToArray();
        tags = t.ToArray();
    }

    static void Scan(byte[] buf, int len, List<string> hits)
    {
        for (int i = 0; i < len; i++)
        {
            byte b = buf[i];
            if (b >= 65 && b <= 90) b += 32;
            List<int> cand = byFirst[b];
            if (cand == null) continue;
            for (int c = 0; c < cand.Count; c++)
            {
                int k = cand[c];
                byte[] p = pats[k];
                if (i + p.Length > len) continue;
                if (hits.Contains(tags[k])) continue;
                int j = 1;
                for (; j < p.Length; j++)
                {
                    byte x = buf[i + j];
                    if (x >= 65 && x <= 90) x += 32;
                    if (x != p[j]) break;
                }
                if (j == p.Length) hits.Add(tags[k]);
            }
        }
    }

    public static string[] ScanText(string s)
    {
        var hits = new List<string>();
        if (string.IsNullOrEmpty(s)) return hits.ToArray();
        byte[] b = Encoding.UTF8.GetBytes(s);
        Scan(b, b.Length, hits);
        return hits.ToArray();
    }

    public static string[] ScanFile(string path)
    {
        var hits = new List<string>();
        using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read,
                                       FileShare.ReadWrite | FileShare.Delete, 1 << 16))
        {
            byte[] buf = new byte[Chunk + longest];
            int carry = 0, n;
            while ((n = fs.Read(buf, carry, Chunk)) > 0)
            {
                int total = carry + n;
                Scan(buf, total, hits);
                carry = Math.Min(longest - 1, total);
                Buffer.BlockCopy(buf, total - carry, buf, 0, carry);
            }
        }
        return hits.ToArray();
    }

    public static string[] ScanJar(string path)
    {
        var hits = new List<string>();
        using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read,
                                       FileShare.ReadWrite | FileShare.Delete))
        using (var zip = new ZipArchive(fs, ZipArchiveMode.Read))
        {
            foreach (ZipArchiveEntry e in zip.Entries)
            {
                byte[] nb = Encoding.UTF8.GetBytes(e.FullName);
                Scan(nb, nb.Length, hits);

                string n = e.FullName.ToLowerInvariant();
                bool readable = n.EndsWith(".class") || n.EndsWith(".json") || n.EndsWith(".txt")
                             || n.EndsWith(".properties") || n.EndsWith(".toml") || n.EndsWith(".mf")
                             || n.EndsWith(".yml");
                if (!readable || e.Length == 0 || e.Length > 4 * 1024 * 1024) continue;

                using (Stream s = e.Open())
                {
                    var ms = new MemoryStream((int)e.Length);
                    s.CopyTo(ms);
                    Scan(ms.GetBuffer(), (int)ms.Length, hits);
                }
            }
        }
        return hits.ToArray();
    }
}
'@
    Add-Type -TypeDefinition $csharp -ReferencedAssemblies 'System.IO.Compression'
}
[SigCore]::Load($allTerms)

# ---------------------------------------------------------------------------
# 3) Look & feel
# ---------------------------------------------------------------------------
function Show-Banner {
    $lit = [string][char]0x25CF     # filled dot
    $dim = [string][char]0x00B7     # faint dot

    $font = @{
        'S' = @('.####', '#....', '.###.', '....#', '####.')
        'e' = @('.###.', '#...#', '#####', '#....', '.####')
        'n' = @('#.##.', '##..#', '#...#', '#...#', '#...#')
        'i' = @('#', '.', '#', '#', '#')
        'o' = @('.###.', '#...#', '#...#', '#...#', '.###.')
        'r' = @('#.##.', '##..#', '#....', '#....', '#....')
    }

    $lines = @('', '', '', '', '')
    foreach ($ch in 'Senior'.ToCharArray()) {
        $g = $font[[string]$ch]
        for ($r = 0; $r -lt 5; $r++) { $lines[$r] += $g[$r] + '.' }
    }

    $grad = @('DarkMagenta', 'Magenta', 'Magenta', 'Cyan', 'Cyan', 'DarkCyan')
    $width = $lines[0].Length

    Write-Host ''
    foreach ($line in $lines) {
        Write-Host '    ' -NoNewline
        for ($c = 0; $c -lt $line.Length; $c++) {
            if ($line[$c] -eq '#') {
                $col = $grad[[math]::Floor($c * $grad.Count / $width)]
                Write-Host ($lit + ' ') -NoNewline -ForegroundColor $col
            } else {
                Write-Host ($dim + ' ') -NoNewline -ForegroundColor DarkGray
            }
        }
        Write-Host ''
    }
    Write-Host ''
    Write-Host '    M i n i S S   ' -NoNewline -ForegroundColor White
    Write-Host '//  Screenshare Scanner' -ForegroundColor DarkCyan
    Write-Host "    by $Author  |  Senior Academy" -ForegroundColor Magenta
    Write-Host "    $Invite" -ForegroundColor DarkCyan
    Write-Host ''
}

function Write-Finding {
    param($Row)
    if ($Row.Severity -eq 'HIGH')       { $badge = 'Red' }
    elseif ($Row.Severity -eq 'MEDIUM') { $badge = 'Yellow' }
    else                                { $badge = 'DarkYellow' }

    Write-Host ''
    Write-Host (' [{0,-6}] ' -f $Row.Severity) -NoNewline -ForegroundColor $badge
    Write-Host ('{0}: {1}' -f $Row.Source, $Row.Name) -ForegroundColor White
    Write-Host '    found : ' -NoNewline -ForegroundColor DarkGray
    Write-Host $Row.Matches -ForegroundColor Red
    Write-Host ('    where : ' + $Row.Location) -ForegroundColor DarkGray
}

# ---------------------------------------------------------------------------
# 4) Helpers
# ---------------------------------------------------------------------------
$rows = New-Object System.Collections.Generic.List[object]

function Add-Row {
    param($Source, $Name, $Location, [string[]]$Terms, $Modified)

    $score = 0; $strongCount = 0
    foreach ($t in $Terms) {
        $score += $db[$t]
        if ($db[$t] -ge 3) { $strongCount++ }
    }
    if (-not ($score -ge 2 -or $ShowWeak)) { return }

    if ($score -ge 6 -or $strongCount -ge 2)      { $label = 'HIGH' }
    elseif ($strongCount -eq 1 -or $score -ge 3)  { $label = 'MEDIUM' }
    else                                          { $label = 'LOW' }

    $row = [pscustomobject]@{
        Severity = $label
        Score    = $score
        Source   = $Source
        Name     = $Name
        Matches  = (($Terms | Sort-Object) -join ', ')
        Modified = $Modified
        Location = $Location
    }
    $rows.Add($row)
    Write-Finding -Row $row
}

function Find-Candidates {
    param([string[]]$Roots, [string[]]$SkipParts, [hashtable]$Exts)
    $stack = New-Object 'System.Collections.Generic.Stack[string]'
    foreach ($r in $Roots) { if (Test-Path -LiteralPath $r) { $stack.Push($r) } }
    while ($stack.Count -gt 0) {
        $dir = $stack.Pop()
        $low = $dir.ToLowerInvariant()
        $skip = $false
        foreach ($s in $SkipParts) { if ($low.Contains($s)) { $skip = $true; break } }
        if ($skip) { continue }
        try {
            foreach ($sub in [IO.Directory]::EnumerateDirectories($dir)) {
                try {
                    if ([IO.File]::GetAttributes($sub) -band [IO.FileAttributes]::ReparsePoint) { continue }
                } catch { continue }
                $stack.Push($sub)
            }
        } catch { }
        try {
            foreach ($f in [IO.Directory]::EnumerateFiles($dir)) {
                $ext = [IO.Path]::GetExtension($f).ToLowerInvariant()
                if ($Exts.ContainsKey($ext)) { $f }
            }
        } catch { }
    }
}

function ConvertTo-HtmlText {
    param($Text)
    [System.Net.WebUtility]::HtmlEncode([string]$Text)
}

# ---------------------------------------------------------------------------
# 5) Start
# ---------------------------------------------------------------------------
Clear-Host
Show-Banner

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if ($Path) {
    $roots = $Path
    $modeName = 'Custom'
    $skipParts = @()
} elseif ($Mode -eq 'Full') {
    $roots = [IO.DriveInfo]::GetDrives() |
             Where-Object { $_.IsReady -and ($_.DriveType -eq 'Fixed' -or $_.DriveType -eq 'Removable') } |
             ForEach-Object { $_.RootDirectory.FullName }
    $modeName = 'Full'
    $skipParts = @('\windows\', '\winsxs\', '\windowsapps\', '\$recycle.bin\', '\system volume information\')
} else {
    $roots = @($env:USERPROFILE, (Join-Path $env:PUBLIC 'Downloads'))
    $modeName = 'Quick'
    $skipParts = @('\windows\', '\winsxs\', '\windowsapps\')
}

$exts = @{ '.jar' = 1; '.exe' = 1; '.dll' = 1; '.bat' = 1; '.cmd' = 1 }
$sizeLimit = [int64]$MaxSizeMB * 1MB
$selfPath = $PSCommandPath

Write-Host "    mode: $modeName   admin: $isAdmin   signatures: $($allTerms.Count)" -ForegroundColor DarkGray
if (-not $isAdmin) {
    Write-Host '    tip: run as Administrator to also read Prefetch (past program runs).' -ForegroundColor DarkYellow
}
Write-Host '    scanning...' -ForegroundColor Cyan

# ---------------------------------------------------------------------------
# 6) Files
# ---------------------------------------------------------------------------
$scanned = 0
$started = Get-Date

Find-Candidates -Roots $roots -SkipParts $skipParts -Exts $exts | ForEach-Object {
    $file = $_
    if ($selfPath -and ($file -ieq $selfPath)) { return }

    $scanned++
    if ($scanned % 150 -eq 0) {
        Write-Progress -Activity 'MiniSS' -Status "$scanned files checked | $($rows.Count) flagged" -CurrentOperation $file
    }

    $info = New-Object IO.FileInfo $file
    if ($info.Length -eq 0 -or $info.Length -gt $sizeLimit) { return }

    $found = New-Object System.Collections.Generic.List[string]
    foreach ($h in [SigCore]::ScanText($info.Name)) { if (-not $found.Contains($h)) { $found.Add($h) } }

    $content = @()
    try {
        if ($info.Extension -ieq '.jar') {
            try { $content = [SigCore]::ScanJar($file) } catch { $content = [SigCore]::ScanFile($file) }
        } else {
            $content = [SigCore]::ScanFile($file)
        }
    } catch { }
    foreach ($h in $content) { if (-not $found.Contains($h)) { $found.Add($h) } }

    if ($found.Count -gt 0) {
        Add-Row -Source 'File' -Name $info.Name -Location $file -Terms $found.ToArray() -Modified $info.LastWriteTime
    }
}
Write-Progress -Activity 'MiniSS' -Completed

# ---------------------------------------------------------------------------
# 7) Running processes
# ---------------------------------------------------------------------------
foreach ($p in Get-Process) {
    $hit = [SigCore]::ScanText("$($p.ProcessName) $($p.MainWindowTitle)")
    if ($hit.Count -gt 0) {
        Add-Row -Source 'Process' -Name $p.ProcessName -Location ("PID $($p.Id) | $($p.MainWindowTitle)") -Terms $hit -Modified $p.StartTime
    }
}

# ---------------------------------------------------------------------------
# 8) Traces of past execution
# ---------------------------------------------------------------------------
$traceSources = @(
    @{ Label = 'Prefetch'; Glob = (Join-Path $env:SystemRoot 'Prefetch\*.pf') },
    @{ Label = 'Recent';   Glob = (Join-Path $env:APPDATA 'Microsoft\Windows\Recent\*.lnk') }
)
foreach ($src in $traceSources) {
    foreach ($item in Get-ChildItem -Path $src.Glob -Force) {
        $hit = [SigCore]::ScanText($item.Name)
        if ($hit.Count -gt 0) {
            Add-Row -Source $src.Label -Name $item.Name -Location $item.FullName -Terms $hit -Modified $item.LastWriteTime
        }
    }
}

# ---------------------------------------------------------------------------
# 9) Summary + reports
# ---------------------------------------------------------------------------
$elapsed = (Get-Date) - $started
Write-Host ''
Write-Host ('    ' + ('- ' * 24)) -ForegroundColor DarkGray
Write-Host ("    checked {0} files in {1:n0}s" -f $scanned, $elapsed.TotalSeconds) -ForegroundColor Cyan

if ($rows.Count -eq 0) {
    Write-Host '    [OK] nothing suspicious found.' -ForegroundColor Green
} else {
    $high = @($rows | Where-Object { $_.Severity -eq 'HIGH' }).Count
    $med  = @($rows | Where-Object { $_.Severity -eq 'MEDIUM' }).Count
    $low  = @($rows | Where-Object { $_.Severity -eq 'LOW' }).Count
    Write-Host '    flagged: ' -NoNewline -ForegroundColor White
    Write-Host "$high HIGH" -NoNewline -ForegroundColor Red
    Write-Host '  ' -NoNewline
    Write-Host "$med MEDIUM" -NoNewline -ForegroundColor Yellow
    Write-Host '  ' -NoNewline
    Write-Host "$low LOW" -ForegroundColor DarkYellow

    $sorted = $rows | Sort-Object @{ Expression = 'Score'; Descending = $true }, Name
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $csv   = Join-Path $OutDir "MiniSS_$stamp.csv"
    $html  = Join-Path $OutDir "MiniSS_$stamp.html"

    try {
        $sorted | Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8

        $css = 'body{background:#0d0b14;color:#e6e1f5;font-family:Segoe UI,Arial,sans-serif;padding:24px}' +
               'h1{color:#c77dff;margin:0}.sub{color:#8d86a8;margin:4px 0 18px}' +
               'table{border-collapse:collapse;width:100%}th{background:#1b1630;color:#9be7ff;text-align:left;padding:8px}' +
               'td{padding:8px;border-bottom:1px solid #2a2342;vertical-align:top;word-break:break-all}' +
               '.m{color:#ff4d4d;font-weight:600}.HIGH td:first-child{color:#ff4d4d;font-weight:700}' +
               '.MEDIUM td:first-child{color:#ffc857}.LOW td:first-child{color:#c9a227}'

        $sb = New-Object System.Text.StringBuilder
        [void]$sb.AppendLine("<html><head><meta charset='utf-8'><title>MiniSS report</title><style>$css</style></head><body>")
        [void]$sb.AppendLine("<h1>MiniSS report</h1><div class='sub'>by $Author | $Invite | $(Get-Date)</div>")
        [void]$sb.AppendLine('<table><tr><th>Severity</th><th>Source</th><th>Name</th><th>Found</th><th>Modified</th><th>Location</th></tr>')
        foreach ($r in $sorted) {
            [void]$sb.AppendLine("<tr class='$($r.Severity)'><td>$($r.Severity)</td><td>$(ConvertTo-HtmlText $r.Source)</td><td>$(ConvertTo-HtmlText $r.Name)</td><td class='m'>$(ConvertTo-HtmlText $r.Matches)</td><td>$(ConvertTo-HtmlText $r.Modified)</td><td>$(ConvertTo-HtmlText $r.Location)</td></tr>")
        }
        [void]$sb.AppendLine('</table></body></html>')
        [System.IO.File]::WriteAllText($html, $sb.ToString(), (New-Object System.Text.UTF8Encoding($true)))

        Write-Host "    saved: $csv" -ForegroundColor Green
        Write-Host "    saved: $html" -ForegroundColor Green
    } catch {
        Write-Host "    could not save reports to $OutDir" -ForegroundColor Red
    }
}

Write-Host ''
Write-Host '    a match is a lead, not proof - check the path and date first.' -ForegroundColor DarkGray
Write-Host "    MiniSS by $Author  |  $Invite" -ForegroundColor Magenta
Write-Host ''

if (-not $NoPause) {
    Write-Host '    press Enter to exit...' -ForegroundColor DarkGray
    [void](Read-Host)
}
