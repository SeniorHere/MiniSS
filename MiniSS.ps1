<#
.SYNOPSIS
    MiniSS - Mini ScreenShare scanner (v3.1 - lightweight)
    Author : Senior
    Discord: https://discord.gg/95MmttMD6

.DESCRIPTION
    Looks for Minecraft cheat clients / modules / injectors / xray packs in:
      - .minecraft (mods, versions, logs, resourcepacks...), Downloads, Desktop, Documents, Temp
      - every jar/zip is opened and ALL its classes are read (like Recaf), nested jars too
      - Prefetch, Recent (.lnk), Recycle Bin (deleted files + original names), hidden / renamed files
      - running processes (+ java command lines / -javaagent)
    Everything stays on this PC. Nothing is uploaded, deleted or changed.
    Results are listed LOW > MEDIUM > HIGH. A CSV + HTML report is saved on the Desktop.

.PARAMETER Mode   Quick (default) = user folders + .minecraft + launchers + traces | Full = all drives
.PARAMETER Deep   Also scans .minecraft\libraries and raises the per-jar read budget (slower).
.PARAMETER Path   Scan only these folders (overrides Mode).
.PARAMETER ShowWeak  Also list files that only match weak (ambiguous) keywords.
.PARAMETER NoPause   Do not wait for Enter at the end.
#>
[CmdletBinding()]
param(
    [ValidateSet('Quick', 'Full')][string]$Mode = 'Quick',
    [string[]]$Path, [switch]$ShowWeak, [switch]$NoPause, [switch]$Deep,
    [int]$MaxSizeMB = 15,
    [string]$OutDir = [Environment]::GetFolderPath('Desktop')
)
$ErrorActionPreference = 'SilentlyContinue'
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }
$Author = 'Senior'
$Invite = 'https://discord.gg/95MmttMD6'

# ---------------------------------------------------------------------------
# 1) Signatures   weight: 3 = strong, 2 = medium, 1 = weak (never reported alone)
# ---------------------------------------------------------------------------
$db = @{}; $clientSet = @{}
function Add-Terms { param([int]$Weight, [string]$List, [switch]$Client) foreach ($t in ($List -split '[,\r\n]+')) { $t = $t.Trim(); if ($t) { $db[$t] = $Weight; if ($Client) { $clientSet[$t] = 1 } } } }
# brand of a client term ("Vape V4", "VapeLite", "vape.gg" -> vape): a scanner / wordlist mentions many brands, a real cheat only its own
function Get-Brand { param($t) ($t.ToLower() -replace '[^a-z0-9]', '' -replace '(client|v\d+|lite|gg|plus|\d+)+$', '') }
function Get-W { param($t) $w = $db[$t]; if ($w) { $w } else { 1 } }

Add-Terms 3 'AutoTotem, Auto Totem, Auto_Totem, Auto-Totem, InventoryTotem, InvTotem, AutoInventoryTotem, TotemHit, TotemSwap, AutoCrystal, CrystalAura, OneHitCrystal, CrystalOptimizer, FastCrystal, AutoHitCrystal,
    AnchorMacro, AnchorAura, AutoAnchor, AutoStun, StunSlam, Stun-Slam, ShieldBreaker, AutoPot, AutoDoubleHand, TriggerBot, KillAura, AimAssist, AimBot, AutoClicker, Auto Clicker, Auto_Clicker, Auto-Clicker,
    InvMove, MaceDMG, MaceAura, AutoMace, NoFall, AutoWTap, ScaffoldWalk, AutoCrit, PacketFly, AntiKnockback, NoKnockback, FakeLag, TargetStrafe, AutoBlock, ChestStealer, InvCleaner, InventoryCleaner,
    AutoSoup, PlayerESP, StorageESP, ChestESP, GhostClicker, Ghost Clicker, JitterClick, Jitter Click, Rapid Clicker, FastClicker'
Add-Terms 3 'LiquidBounce, meteordevelopment, meteor-client, MeteorClient, Meteor Client, wurstclient, wurst-client, Wurst Client, BleachHack, Aristois, RusherHack, ThunderHack, FutureClient, Future Client,
    vape.gg, VapeV4, VapeV3, VapeLite, Vape Client, Vape V4, Vape V3, Vape Lite, RavenB+, Raven B+, RavenBPlus, SigmaClient, Sigma Client, Sigma5, Sigma 5.0, ImpactClient, Impact Client, JigsawClient,
    Jigsaw Client, AresClient, Ares Client, HydraClient, Hydra Client, XuluClient, Xulu Client, FluxClient, Flux Client, PerishClient, Perish Client, JexClient, Jex Client, FrostClient, Frost Client,
    ItamiClient, Itami Client, PolarClient, Polar Client, CurseClient, Curse Client, FDPClient, FDP Client, DopiumClient, Dopium Client, Dopium, RiseClient, Rise Client, NovolineClient, Novoline Client,
    TenacityClient, Tenacity Client, AstolfoClient, Astolfo Client, DoomsdayClient, Doomsday Client, SlinkyClient, Slinky Client, KonasClient, Konas Client, PhobosClient, Phobos Client, 3arthh4ck, SalHack,
    KamiBlue, ForgeHax, Pandaware, ExhibitionClient, Exhibition Client, EntropyClient, Entropy Client, DripClient, Drip Client, ZeroDay Client, ZerodayClient, WolframClient, Wolfram Client, InertiaClient,
    Inertia Client, NodusClient, CosmosClient, Cosmos Client, BozeClient, Boze Client, Nursultan, CelestialClient, Celestial Client, ExpensiveClient, Expensive Client, Wexside, Akrien, RemixClient,
    Remix Client, MoonClient, Moon Client, Huzuni, Lambda Client, lambda-client, gamesense.pub, GameSense Client, SeppukuClient, Seppuku Client, PyroClient, Pyro Client, Weepcraft, GhostClient, Ghost Client' -Client
Add-Terms 3 'Xenos Injector, Extreme Injector, ExtremeInjector, XrayUltimate, Xray Ultimate, Xray_Ultimate, XRay Pack, Xray-Pack, XRayTexture, XRay Texture, XRayResourcePack'
Add-Terms 2 'ClickGUI, ReachHack, TinyTask, HitSelect, DoubleHand, NoSlowdown, ElytraFly, GSAutoClicker, OPAutoClicker, SpeedAutoClicker, AutoTrap, HoleFiller, SelfFill, FastBreak, Baritone, CheatEngine, Cheat Engine,
    XRay, X-Ray, XRayMod, Xray Mod, AdvancedXRay, Advanced XRay, OreESP, Ore ESP, FreeCam, Free Cam, Free-Cam, Free_Cam, FullBright, Full Bright, Full-Bright'
Add-Terms 1 'Flight, Macro, Velocity, FastPlace, Hitbox, Bhop, WallHack, Injector, Criticals, Backtrack, AutoHotkey, Surround, AutoArmor, Nuker, Tracers, AutoSprint, NoClip, Reach, Blink'
$db['xray-pack (transparent blocks)'] = 3

# Generic client names: matched in FILE NAMES only, together with a typical suffix (e.g. "Vape V4.exe")
$genericNames = 'vape|raven|sigma|rise|novoline|tenacity|astolfo|impact|jigsaw|ares|hydra|xulu|flux|perish|jex|frost|itami|polar|curse|fdp|dopium|slinky|doomsday|entropy|drip|exhibition|zeroday|wolfram|inertia|nursultan|celestial|expensive|wexside|akrien|moon|remix|huzuni'
foreach ($g in ($genericNames -split '\|')) { $db["$g (file name)"] = 3 }
$nameRegex = New-Object System.Text.RegularExpressions.Regex(('(?i)(^|[^a-z0-9])(' + $genericNames + ')[ _\-.]*(client|loader|injector|crack(ed)?|hack(ed)?|cheat|ghost|lite|v\d+(\.\d+)*|b\+{1,2}|\d+(\.\d+)+)([^a-z0-9]|$)'))
$trustedNameRegex = '(?i)^(tlauncher|whatsapp)'
$trustedPublishers = @('Microsoft', 'Google', 'WhatsApp', 'Meta Platforms', 'Mozilla', 'Oracle', 'Adoptium', 'Eclipse', 'Discord', 'Valve', 'NVIDIA', 'Intel', 'Advanced Micro Devices', 'Mojang', 'Apple', 'Adobe',
    'Epic Games', 'Spotify', 'Zoom', 'JetBrains', 'Logitech', 'Razer', 'Corsair', 'SteelSeries', 'Realtek', 'Python Software', 'GitHub', 'OBS Project', 'Brave', 'Opera', 'Telegram', 'Riot Games',
    'Blizzard', 'Electronic Arts', 'Ubisoft', 'Amazon', 'Cloudflare', 'Autodesk', 'Dropbox')
$allTerms = [string[]]@($db.Keys)

# ---------------------------------------------------------------------------
# 2) Engine (compiled C#, multi-threaded, word-boundary aware, ASCII + UTF-16)
#    jars/zips: entry names + every .class (library packages skipped) + metadata + nested jars
# ---------------------------------------------------------------------------
if (-not ('SigCore' -as [type])) {
    $csharp = @'
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

public static class SigCore
{
    static byte[][] pats = new byte[0][];
    static string[] tags = new string[0];
    static bool[] wide = new bool[0];
    static List<int>[] byFirst = new List<int>[256];
    static bool[] pairOk = new bool[65536];
    static byte[] lower = MakeLower();
    static int longest = 1;
    public static bool Deep = false;
    public static Regex NameRx = null;
    static readonly string[] Lib = { "com/google/", "org/apache/", "io/netty/", "org/lwjgl/", "kotlin/", "kotlinx/", "it/unimi/", "org/objectweb/", "org/slf4j/", "com/sun/", "javax/", "org/jetbrains/", "org/intellij/", "com/mojang/", "org/joml/", "net/minecraft/", "net/minecraftforge/", "net/fabricmc/", "net/neoforged/", "org/spongepowered/" };
    static readonly string[] MetaExt = { ".json", ".yml", ".yaml", ".toml", ".info", ".mf", ".mcmeta", ".properties", ".cfg" };
    static readonly string[] Block = { "block/stone.png", "block/dirt.png", "block/netherrack.png", "block/deepslate.png", "block/cobblestone.png" };
    static readonly string[] Txt = { ".exe", ".dll", ".bat", ".cmd", ".ahk", ".lnk", ".txt" };

    static byte[] MakeLower() { byte[] t = new byte[256]; for (int i = 0; i < 256; i++) t[i] = (byte)((i >= 65 && i <= 90) ? i + 32 : i); return t; }
    static bool Has(string n, string[] a) { foreach (string x in a) if (n.EndsWith(x, StringComparison.Ordinal)) return true; return false; }
    static bool Pfx(string n, string[] a) { foreach (string x in a) if (n.StartsWith(x, StringComparison.Ordinal)) return true; return false; }

    public static void Load(string[] terms)
    {
        var p = new List<byte[]>(); var t = new List<string>(); var w = new List<bool>();
        byFirst = new List<int>[256]; pairOk = new bool[65536]; longest = 1;
        foreach (string term in terms)
        {
            if (string.IsNullOrEmpty(term) || term.Length < 3) continue;
            string low = term.ToLowerInvariant();
            for (int pass = 0; pass < 2; pass++)
            {
                byte[] b = (pass == 0) ? Encoding.ASCII.GetBytes(low) : Encoding.Unicode.GetBytes(low);
                p.Add(b); t.Add(term); w.Add(pass == 1);
                if (byFirst[b[0]] == null) byFirst[b[0]] = new List<int>();
                byFirst[b[0]].Add(p.Count - 1);
                pairOk[(b[0] << 8) | b[1]] = true;
                if (b.Length > longest) longest = b.Length;
            }
        }
        pats = p.ToArray(); tags = t.ToArray(); wide = w.ToArray();
    }

    static bool Boundary(byte[] buf, int start, int plen, int len, int step)
    {
        bool firstUpper = buf[start] >= 65 && buf[start] <= 90;
        int pi = start - step;
        if (pi >= 0)
        {
            byte pb = buf[pi];
            if (step == 2 && buf[pi + 1] != 0) pb = 0;
            if (((pb >= 65 && pb <= 90) || (pb >= 97 && pb <= 122)) && !firstUpper) return false;
        }
        int ni = start + plen;
        if (ni + step <= len)
        {
            byte nb = buf[ni];
            if (step == 2 && buf[ni + 1] != 0) nb = 0;
            if (nb >= 97 && nb <= 122) return false;
        }
        return true;
    }

    static void Scan(byte[] buf, int len, List<string> hits, bool w)
    {
        for (int i = 0; i + 1 < len; i++)
        {
            byte b0 = lower[buf[i]];
            if (!pairOk[(b0 << 8) | lower[buf[i + 1]]]) continue;
            List<int> cand = byFirst[b0];
            if (cand == null) continue;
            for (int c = 0; c < cand.Count; c++)
            {
                int k = cand[c];
                if (wide[k] && !w) continue;
                byte[] p = pats[k];
                if (i + p.Length > len || hits.Contains(tags[k])) continue;
                int j = 1;
                while (j < p.Length && lower[buf[i + j]] == p[j]) j++;
                if (j == p.Length && Boundary(buf, i, p.Length, len, wide[k] ? 2 : 1)) hits.Add(tags[k]);
            }
        }
    }

    public static string[] ScanText(string s)
    {
        var h = new List<string>();
        if (!string.IsNullOrEmpty(s)) { byte[] b = Encoding.UTF8.GetBytes(s); Scan(b, b.Length, h, true); }
        return h.ToArray();
    }

    static void ScanStream(Stream fs, List<string> hits)
    {
        int chunk = (int)Math.Min(2097152L, fs.Length);
        byte[] buf = new byte[chunk + longest];
        int carry = 0, n;
        while ((n = fs.Read(buf, carry, chunk)) > 0)
        {
            int t = carry + n;
            Scan(buf, t, hits, true);
            carry = Math.Min(longest - 1, t);
            Buffer.BlockCopy(buf, t - carry, buf, 0, carry);
        }
    }

    static readonly string[] Ac = { "anticheat", "anti-cheat", "grimac", "nocheatplus", "/vulcan/", "/intave/", "themis" };

    // ent = hits in entry NAMES (class/package named like a cheat), con = hits in class/metadata CONTENT
    static void ScanZip(Stream st, List<string> ent, List<string> con, int depth, ref long budget)
    {
        using (var zip = new ZipArchive(st, ZipArchiveMode.Read))
        {
            var sb = new StringBuilder(); int tp = 0; bool ac = false;
            foreach (ZipArchiveEntry e in zip.Entries)
            {
                string ln = e.FullName.ToLowerInvariant();
                sb.Append(e.FullName).Append('\n');
                if (e.Length > 0 && e.Length < 110 && Has(ln, Block)) tp++;
                if (!ac) foreach (string a in Ac) if (ln.IndexOf(a, StringComparison.Ordinal) >= 0) { ac = true; break; }
            }
            byte[] nb = Encoding.UTF8.GetBytes(sb.ToString());
            Scan(nb, nb.Length, ent, false);
            if (tp >= 2) ent.Add("xray-pack (transparent blocks)");
            if (ac && !ent.Contains("#anticheat")) ent.Add("#anticheat");   // anti-cheat plugins list cheat names on purpose
            foreach (ZipArchiveEntry e in zip.Entries)
            {
                if (budget <= 0 || con.Count >= 8) break;
                long L = e.Length; if (L == 0) continue;
                string n = e.FullName.ToLowerInvariant();
                bool cls = L <= 2097152 && n.EndsWith(".class", StringComparison.Ordinal) && !Pfx(n, Lib);
                bool meta = !cls && L <= 262144 && Has(n, MetaExt);
                bool nest = !cls && !meta && depth < 1 && L <= 16777216 && n.EndsWith(".jar", StringComparison.Ordinal);
                if (!cls && !meta && !nest) continue;
                budget -= L;
                using (Stream s = e.Open())
                {
                    var ms = new MemoryStream((int)L); s.CopyTo(ms);
                    if (nest) { ms.Position = 0; try { ScanZip(ms, ent, con, depth + 1, ref budget); } catch (Exception) { } }
                    else Scan(ms.GetBuffer(), (int)ms.Length, con, false);
                }
            }
        }
    }

    // decides by magic bytes (so renamed/hidden files are still read): PK = zip/jar, MZ = exe/dll, $I = recycle-bin record
    static void ScanOne(string path, List<string> ent, List<string> con)
    {
        string ext = Path.GetExtension(path).ToLowerInvariant();
        if (ext == ".pf") return;
        using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 4096))
        {
            if (fs.Length < 4) return;
            byte[] m = new byte[4]; fs.Read(m, 0, 4); fs.Position = 0;
            if (ext == ".log")   // game logs: loaded-mod lines count, player chat lines do not
            {
                var sb = new StringBuilder(); string ln;
                using (var sr = new StreamReader(fs)) { while ((ln = sr.ReadLine()) != null) if (ln.IndexOf("CHAT]", StringComparison.Ordinal) < 0) sb.AppendLine(ln); }
                byte[] bb = Encoding.UTF8.GetBytes(sb.ToString());
                Scan(bb, bb.Length, ent, true);
            }
            else if (Path.GetFileName(path).StartsWith("$I")) ScanStream(fs, con);
            else if (m[0] == 0x50 && m[1] == 0x4B && m[2] == 3 && m[3] == 4) { long b = Deep ? 536870912L : 134217728L; ScanZip(fs, ent, con, 0, ref b); }
            else if (ext == ".jar" || ext == ".zip") return;
            else if ((m[0] == 'M' && m[1] == 'Z') || Array.IndexOf(Txt, ext) >= 0) ScanStream(fs, con);
        }
    }

    // roots look like "depth|path". Returns every candidate file (known extension, $I record, or hidden file with unknown extension)
    public static string[] Index(string[] roots, string[] skipNames, string[] exts, long maxB, long maxJar)
    {
        var skip = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
        foreach (string s in skipNames) skip[s] = true;
        var ext = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
        foreach (string x in exts) ext[x] = true;
        var seen = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
        var res = new List<string>(); var rl = new List<KeyValuePair<int, string>>();
        foreach (string r in roots)
        {
            int bar = r.IndexOf('|'); int d;
            if (bar > 0 && int.TryParse(r.Substring(0, bar), out d) && Directory.Exists(r.Substring(bar + 1))) rl.Add(new KeyValuePair<int, string>(d, r.Substring(bar + 1)));
        }
        rl.Sort((a, b) => b.Key.CompareTo(a.Key));   // deeper roots first: a shallow parent never limits a deeper child
        var dirs = new List<string>(); var dep = new List<int>();
        foreach (var kv in rl) { dirs.Add(kv.Value); dep.Add(kv.Key); }
        for (int h = 0; h < dirs.Count; h++)
        {
            string dir = dirs[h]; int left = dep[h]; string key = dir.TrimEnd('\\');
            if (seen.ContainsKey(key)) continue;
            seen[key] = true;
            var di = new DirectoryInfo(dir);
            if (left > 0)
            {
                try { foreach (DirectoryInfo sd in di.EnumerateDirectories()) { if (skip.ContainsKey(sd.Name) || (sd.Attributes & FileAttributes.ReparsePoint) != 0) continue; dirs.Add(sd.FullName); dep.Add(left - 1); } } catch (Exception) { }
            }
            try
            {
                foreach (FileInfo f in di.EnumerateFiles())
                {
                    long len = f.Length; if (len <= 0) continue;
                    string fe = f.Extension;
                    bool known = (fe.Length > 0 && ext.ContainsKey(fe)) || f.Name.StartsWith("$I");
                    bool hid = (f.Attributes & (FileAttributes.Hidden | FileAttributes.System)) != 0;
                    if (!known && !(hid && len >= 4096)) continue;
                    if ((fe == ".txt" || fe == ".log") && f.FullName.IndexOf("minecraft", StringComparison.OrdinalIgnoreCase) < 0) continue;
                    bool arc = fe.Equals(".jar", StringComparison.OrdinalIgnoreCase) || fe.Equals(".zip", StringComparison.OrdinalIgnoreCase);
                    if (len > (arc ? maxJar : maxB)) continue;
                    res.Add(f.FullName);
                }
            }
            catch (Exception) { }
        }
        return res.ToArray();
    }

    // Parallel scan (max 4 threads = low CPU). Returns lines: path <TAB> nameHits <TAB> entryHits <TAB> contentHits
    public static string[] ScanMany(string[] paths)
    {
        var res = new List<string>();
        var o = new ParallelOptions(); o.MaxDegreeOfParallelism = Math.Max(1, Math.Min(4, Environment.ProcessorCount / 2));
        Parallel.ForEach(paths, o, path =>
        {
            try
            {
                var nh = new List<string>(); var en = new List<string>(); var ch = new List<string>();
                string fn = Path.GetFileName(path);
                byte[] nb = Encoding.UTF8.GetBytes(fn);
                Scan(nb, nb.Length, nh, true);
                if (nh.Count == 0 && NameRx != null) { Match mm = NameRx.Match(fn); if (mm.Success) nh.Add(mm.Groups[2].Value + " (file name)"); }
                try { ScanOne(path, en, ch); } catch (Exception) { }
                // a shortcut / recycle-bin record only holds a PATH: its hits are name evidence, not code evidence
                if (fn.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase) || fn.StartsWith("$I")) { foreach (string z in ch) if (!nh.Contains(z)) nh.Add(z); ch.Clear(); }
                if (nh.Count > 0 || en.Count > 0 || ch.Count > 0)
                {
                    string line = path + "\t" + string.Join(",", nh.ToArray()) + "\t" + string.Join(",", en.ToArray()) + "\t" + string.Join(",", ch.ToArray());
                    lock (res) { res.Add(line); }
                }
            }
            catch (Exception) { }
        });
        return res.ToArray();
    }
}
'@
    Add-Type -TypeDefinition $csharp -ReferencedAssemblies 'System.IO.Compression'
}
[SigCore]::Load($allTerms)
[SigCore]::Deep = [bool]$Deep
[SigCore]::NameRx = $nameRegex

# ---------------------------------------------------------------------------
# 3) Look & feel
# ---------------------------------------------------------------------------
function Show-Banner {
    $dot = [string][char]0x25CF; $dim = [string][char]0x00B7
    $font = @{
        'S' = @('.####', '#....', '#....', '.###.', '....#', '....#', '####.')
        'E' = @('#####', '#....', '#....', '####.', '#....', '#....', '#####')
        'N' = @('#...#', '##..#', '##..#', '#.#.#', '#..##', '#..##', '#...#')
        'I' = @('###', '.#.', '.#.', '.#.', '.#.', '.#.', '###')
        'O' = @('.###.', '#...#', '#...#', '#...#', '#...#', '#...#', '.###.')
        'R' = @('####.', '#...#', '#...#', '####.', '#.#..', '#..#.', '#...#')
    }
    $lines = @('', '', '', '', '', '', '')
    foreach ($ch in 'SENIOR'.ToCharArray()) { $g = $font[[string]$ch]; for ($r = 0; $r -lt 7; $r++) { $lines[$r] += $g[$r] + '.' } }
    $grad = @('Magenta', 'Magenta', 'Magenta', 'White', 'Cyan', 'Cyan', 'Cyan')
    $width = $lines[0].Length
    Write-Host ''
    foreach ($line in $lines) {
        $runText = '      '; $runCol = 'Gray'
        for ($c = 0; $c -lt $line.Length; $c++) {
            if ($line[$c] -eq '#') { $col = $grad[[math]::Floor($c * $grad.Count / $width)]; $cell = $dot + ' ' } else { $col = $runCol; $cell = '  ' }
            if ($col -eq $runCol) { $runText += $cell } else { Write-Host $runText -NoNewline -ForegroundColor $runCol; $runText = $cell; $runCol = $col }
        }
        Write-Host $runText -ForegroundColor $runCol
    }
    Write-Host ('      ' + (($dim + ' ') * $width)) -ForegroundColor DarkGray
    Write-Host ''
    $h = [string][char]0x2500; $v = [string][char]0x2502; $pw = 56
    $host1 = 'host {0}   |   {1}' -f $env:COMPUTERNAME, (Get-Date -Format 'yyyy-MM-dd HH:mm')
    $items = @(@('MiniSS  //  Screenshare Scanner        v3.1', 'White'), @('by Senior   |   Senior Academy', 'Magenta'), @($Invite, 'Cyan'),
               @('RED = suspicious    order: LOW > MEDIUM > HIGH', 'Gray'), @($host1, 'DarkGray'))
    Write-Host ('    ' + [char]0x250C + ($h * $pw) + [char]0x2510) -ForegroundColor Magenta
    foreach ($it in $items) {
        $txt = (' ' + $it[0]).PadRight($pw); if ($txt.Length -gt $pw) { $txt = $txt.Substring(0, $pw) }
        Write-Host ('    ' + $v) -NoNewline -ForegroundColor Magenta; Write-Host $txt -NoNewline -ForegroundColor $it[1]; Write-Host $v -ForegroundColor Magenta
    }
    Write-Host ('    ' + [char]0x2514 + ($h * $pw) + [char]0x2518) -ForegroundColor Magenta
    Write-Host ''
}

$script:tick = 0
function Get-Cw { $w = 100; try { $w = $Host.UI.RawUI.WindowSize.Width } catch { }; if (-not $w) { $w = 100 }; $w }
function Show-Hud {
    param([string]$Phase, [string]$Text, [double]$Pct = -1, [string]$Eta = '')
    $script:tick++
    $frame = @('|', '/', '-', '\')[$script:tick % 4]
    $barTxt = ''
    if ($Pct -ge 0) { $cells = [int][math]::Floor($Pct * 16); $barTxt = ' [' + ([string][char]0x2588 * $cells) + ([string][char]0x2591 * (16 - $cells)) + '] ' + ('{0,3}%' -f [int]($Pct * 100)) }
    $text = ' {0} {1,-6}{2}  flagged {3,-3} {4:mm\:ss}{5}  {6}' -f $frame, $Phase, $barTxt, $rows.Count, ((Get-Date) - $started), $Eta, $Text
    $cw = Get-Cw
    if ($text.Length -gt ($cw - 2)) { $text = $text.Substring(0, $cw - 2) }
    Write-Host ("`r" + $text.PadRight($cw - 2)) -NoNewline -ForegroundColor Cyan
}

function Write-SectionHeader {
    param([string]$Label, [int]$Count, [string]$Color)
    Write-Host ''
    Write-Host ('  ' + ([string][char]0x2501 * 3) + ' ' + $Label + ' (' + $Count + ') ' + ([string][char]0x2501 * 44)) -ForegroundColor $Color
}

function Write-Card {
    param($Row)
    $c = @{ HIGH = 'Red'; MEDIUM = 'Yellow'; LOW = 'Green' }[$Row.Severity]
    $mid = [string][char]0x251C; $end = [string][char]0x2514
    Write-Host ''
    Write-Host ('  ' + [char]0x25B8 + ' ') -NoNewline -ForegroundColor $c
    Write-Host ('{0,-6}' -f $Row.Severity) -NoNewline -ForegroundColor $c
    Write-Host (' ' + $Row.Name) -NoNewline -ForegroundColor White
    Write-Host ('   (' + $Row.Source + ')') -ForegroundColor DarkGray
    Write-Host ('    ' + $mid + ' found  ') -NoNewline -ForegroundColor DarkGray
    Write-Host $Row.Matches -NoNewline -ForegroundColor Red
    if ($Row.Hints) { Write-Host ('   + ' + $Row.Hints) -NoNewline -ForegroundColor DarkGray }
    Write-Host ''
    if ($Row.Modified) { Write-Host ('    ' + $mid + ' date   ' + $Row.Modified) -ForegroundColor DarkGray }
    Write-Host ('    ' + $end + ' path   ' + $Row.Location) -ForegroundColor DarkGray
}

# ---------------------------------------------------------------------------
# 4) Helpers
# ---------------------------------------------------------------------------
$rows = New-Object System.Collections.Generic.List[object]

function Add-Row {
    # NameT = hits in file name / path, EntT = hits in jar entry names, ConT = hits in code / metadata strings only
    param($Source, $Name, $Location, [string[]]$NameT = @(), [string[]]$EntT = @(), [string[]]$ConT = @(), $Modified, [bool]$Big = $false, [int]$Bump = 0, [string[]]$Extra = @())
    $a = @($NameT + $EntT | Select-Object -Unique)                              # structural evidence: the file / class is NAMED like a cheat
    $b = @($ConT | Where-Object { $a -notcontains $_ } | Select-Object -Unique) # a string inside code is much weaker evidence
    $As = @($a | Where-Object { (Get-W $_) -ge 3 }); $Am = @($a | Where-Object { (Get-W $_) -eq 2 })
    $Bs = @($b | Where-Object { (Get-W $_) -ge 3 }); $Bm = @($b | Where-Object { (Get-W $_) -eq 2 })
    $weak = @(($a + $b) | Where-Object { (Get-W $_) -le 1 })
    if ($Bs.Count -ge 3) { $As += $Bs; $Bs = @() }                               # 3+ different cheat strings in one code base = real cheat code
    if ($As.Count + $Am.Count + $Bs.Count + $Bm.Count -eq 0 -and -not $ShowWeak) { return }
    $hot = @($As + $Am + $Bs + $Bm); if ($hot.Count -eq 0) { $hot = $weak; $weak = @() }

    if ($As.Count -ge 2 -or ($As.Count -ge 1 -and ($Am.Count + $Bs.Count + $Bm.Count) -ge 1)) { $lvl = 2 }
    elseif ($As.Count -eq 1 -or $Am.Count -ge 1 -or $Bs.Count -ge 2) { $lvl = 1 }
    else { $lvl = 0 }
    if ($Big -and $a.Count -eq 0 -and $lvl -eq 1) { $lvl = 0 }                   # hits only inside a big binary
    if ($As.Count -ge 1) { $lvl = [math]::Min(2, $lvl + $Bump) }                 # hidden / disguised file
    if ($Name -match '\.(log|txt)$') { $lvl = [math]::Min($lvl, 1) }
    if ($a.Count -eq 0) { $Extra += 'code strings only' }

    $stamp = ''; if ($Modified) { try { $stamp = ([datetime]$Modified).ToString('yyyy-MM-dd HH:mm') } catch { } }
    $rows.Add([pscustomobject]@{
        Severity = @('LOW', 'MEDIUM', 'HIGH')[$lvl]; Score = (3 * $As.Count + 2 * ($Am.Count + $Bs.Count) + $Bm.Count); Source = $Source; Name = $Name
        Matches = ($hot -join ', '); Hints = ((@($weak) + $Extra) -join ', '); Modified = $stamp; Location = $Location })
}

# one card per thing: the same file in many folders / Recent / Prefetch / Recycle Bin is merged into a single row
function Merge-Rows {
    $lv = @{ LOW = 0; MEDIUM = 1; HIGH = 2 }
    $key = { if ($_.Source -eq 'Process') { 'p|' + $_.Name } else { $_.Name.ToLower() -replace '\.lnk$', '' -replace '-[0-9a-f]{8}\.pf$', '' -replace '\.pf$', '' } }
    @($rows | Group-Object $key | ForEach-Object {
        $g = @($_.Group | Sort-Object @{ Expression = { $lv[$_.Severity] }; Descending = $true }, @{ Expression = { $_.Score }; Descending = $true }); $t = $g[0]
        [pscustomobject]@{
            Severity = $t.Severity; Score = $t.Score; Source = (@($g.Source | Select-Object -Unique) -join ' + '); Name = $t.Name
            Matches = ((@($g | ForEach-Object { $_.Matches -split ', ' }) | Where-Object { $_ } | Select-Object -Unique) -join ', ')
            Hints = ((@($g | ForEach-Object { $_.Hints -split ', ' }) | Where-Object { $_ } | Select-Object -Unique) -join ', ')
            Modified = $t.Modified; Location = ($t.Location + $(if ($g.Count -gt 1) { "  (+$($g.Count - 1) more)" })) }
    })
}

# original file name of a recycled file ($I record holds the old path)
function Get-Orig {
    param($p, $nm)
    $q = if ($nm -like '$R*') { Join-Path (Split-Path $p) ('$I' + $nm.Substring(2)) } else { $p }
    try { $b = [IO.File]::ReadAllBytes($q); [IO.Path]::GetFileName([Text.Encoding]::Unicode.GetString($b, 28, $b.Length - 28).Trim([char]0)) } catch { $nm }
}

# embedded signer certificate of a well-known publisher (no slow online validation)
function Test-Trusted {
    param([string]$FilePath)
    try {
        $subject = [string][System.Security.Cryptography.X509Certificates.X509Certificate]::CreateFromSignedFile($FilePath).Subject
        foreach ($p in $trustedPublishers) { if ($subject -like "*$p*") { return $true } }
    } catch { }
    return $false
}
function ConvertTo-HtmlText { param($Text) [System.Net.WebUtility]::HtmlEncode([string]$Text) }

# ---------------------------------------------------------------------------
# 5) Start + scan roots
# ---------------------------------------------------------------------------
Clear-Host
Show-Banner
$started = Get-Date
try { [System.Diagnostics.Process]::GetCurrentProcess().PriorityClass = 'BelowNormal' } catch { }   # keep the PC responsive
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

$up = $env:USERPROFILE; $mc = Join-Path $env:APPDATA '.minecraft'
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$fixed = @([IO.DriveInfo]::GetDrives() | Where-Object { $_.IsReady -and ($_.DriveType -eq 'Fixed' -or $_.DriveType -eq 'Removable') })
# traces: Prefetch, Recent, Windows\Temp, Recycle Bin of this user on every drive (deleted cheats + their original names)
$traces = @(('0|' + (Join-Path $env:SystemRoot 'Prefetch')), ('0|' + (Join-Path $env:APPDATA 'Microsoft\Windows\Recent')), ('3|' + (Join-Path $env:SystemRoot 'Temp'))) +
          @($fixed | ForEach-Object { '3|' + $_.Name + '$Recycle.Bin\' + $sid })
if ($Path) { $rootSpecs = @($Path | ForEach-Object { '12|' + $_ }); $modeName = 'Custom' }
elseif ($Mode -eq 'Full') { $rootSpecs = @($fixed | ForEach-Object { '12|' + $_.RootDirectory.FullName }) + $traces + ('8|' + $mc); $modeName = 'Full' }
else {
    $rootSpecs = @(('8|' + $mc), ('6|' + (Join-Path $up 'Downloads')), ('5|' + (Join-Path $up 'Desktop')), ('4|' + (Join-Path $up 'Documents')), ('3|' + (Join-Path $up 'OneDrive')),
        ('5|' + (Join-Path $up 'curseforge')), ('6|' + (Join-Path $env:APPDATA 'PrismLauncher')), ('6|' + (Join-Path $env:APPDATA 'MultiMC')), ('6|' + (Join-Path $env:APPDATA 'ModrinthApp')),
        ('6|' + (Join-Path $env:APPDATA 'com.modrinth.theseus')), ('1|' + $env:APPDATA), ('1|' + $env:LOCALAPPDATA), ('1|' + $up), ('4|' + $env:TEMP), ('3|' + (Join-Path $env:PUBLIC 'Downloads'))) + $traces
    $modeName = 'Quick'
}
# folders that never hold what we look for (resourcepacks / logs / crash-reports are NOT skipped on purpose)
$skipList = @('node_modules', '.git', '__pycache__', 'windows', 'winsxs', 'windowsapps', '$recycle.bin', 'system volume information', 'assets', 'runtime', 'saves', 'natives', 'shaderpacks',
    'screenshots', 'cache', 'code cache', 'gpucache', 'indexeddb', 'local storage', 'service worker', 'discord', 'whatsapp', 'telegram desktop', 'spotify', 'slack', 'zoom', 'teams', 'microsoft',
    'google', 'mozilla', 'opera software', 'brave-browser', 'nvidia', 'nvidia corporation', 'adobe', 'steam', 'steamapps', 'epic games', 'tlauncher', '.tlauncher', 'jetbrains', 'code', 'obs-studio',
    'npm', 'python', 'dotnet', 'nuget')
if (-not ($Deep -or $Mode -eq 'Full' -or $Path)) { $skipList += 'libraries' }

Write-Host "    mode: $modeName   admin: $isAdmin   signatures: $($allTerms.Count)   deep: $([bool]$Deep)" -ForegroundColor DarkGray
if (-not $isAdmin) { Write-Host '    tip: run as Administrator to also read Prefetch, Windows\Temp (past program runs).' -ForegroundColor Yellow }
Write-Host ''

# ---------------------------------------------------------------------------
# 6) Files: index (compiled), then parallel scan in chunks
# ---------------------------------------------------------------------------
$known = @('.jar', '.zip', '.exe', '.dll', '.bat', '.cmd', '.ahk', '.lnk', '.pf', '.log', '.txt')
Show-Hud 'INDEX' 'listing files...'
$list = [SigCore]::Index([string[]]$rootSpecs, [string[]]$skipList, [string[]]$known, ([int64]$MaxSizeMB * 1MB), [int64]200MB)
$total = $list.Count; $scanned = 0; $t0 = Get-Date

for ($i = 0; $i -lt $total; $i += 96) {
    $paths = [string[]]$list[$i..([math]::Min($i + 95, $total - 1))]
    foreach ($line in [SigCore]::ScanMany($paths)) {
        $c = $line -split "`t"; $p = $c[0]
        $nm = [IO.Path]::GetFileName($p); $ext = [IO.Path]::GetExtension($p).ToLowerInvariant()
        if ($p -eq $PSCommandPath -or $nm -match '^MiniSS.*\.(ps1|csv|html|txt)$') { continue }     # never flag this scanner / its reports
        $nh = @(if ($c[1]) { $c[1] -split ',' }); $en = @(if ($c[2]) { $c[2] -split ',' }); $ch = @(if ($c[3]) { $c[3] -split ',' })
        # anti-cheat plugins and signature lists (other scanners, wordlists) contain cheat names on purpose: ignore their content
        $brands = @(@($en + $ch) | Where-Object { $clientSet.ContainsKey($_) } | ForEach-Object { Get-Brand $_ } | Select-Object -Unique)
        $strongN = @(@($en + $ch) | Where-Object { (Get-W $_) -ge 3 } | Select-Object -Unique).Count
        if ($en -contains '#anticheat' -or $brands.Count -ge 4 -or ($ext -ne '.jar' -and $ext -ne '.zip' -and $strongN -ge 15)) { $en = @(); $ch = @() }
        $en = @($en | Where-Object { $_ -ne '#anticheat' })
        if (-not ($nh.Count + $en.Count + $ch.Count)) { continue }
        if (-not $nh.Count) {
            if ($nm -match $trustedNameRegex) { continue }
            if (($ext -eq '.exe' -or $ext -eq '.dll') -and (Test-Trusted -FilePath $p)) { continue }
        }
        $hid = [bool]([int][IO.File]::GetAttributes($p) -band 6); $dis = ($known -notcontains $ext)
        $x = @(); if ($hid) { $x += 'hidden file' }; if ($dis) { $x += 'disguised extension' }
        if ($p -match '\\Prefetch\\') { $src = 'Prefetch' } elseif ($p -match '\\Recent\\') { $src = 'Recent' } elseif ($p -match '\$Recycle\.Bin') { $src = 'Recycle (deleted)' } else { $src = 'File' }
        if ($src -like 'Recycle*') { $nm = Get-Orig $p $nm }
        Add-Row -Source $src -Name $nm -Location $p -NameT $nh -EntT $en -ConT $ch -Modified ([IO.File]::GetLastWriteTime($p)) `
                -Big (([IO.FileInfo]$p).Length -gt 20MB) -Bump ([int]($hid -or $dis)) -Extra $x
    }
    $scanned += $paths.Count
    $secs = ((Get-Date) - $t0).TotalSeconds
    Show-Hud 'SCAN' ("{0}/{1}  {2}" -f $scanned, $total, [IO.Path]::GetFileName($paths[-1])) ($scanned / $total) ('  ETA {0:mm\:ss}' -f [timespan]::FromSeconds($secs * ($total - $scanned) / $scanned))
}

# ---------------------------------------------------------------------------
# 7) Running processes (+ java command lines like -javaagent, + modules loaded into javaw)
# ---------------------------------------------------------------------------
Show-Hud 'PROCS' 'running processes'
foreach ($p in Get-Process) {
    $hit = [SigCore]::ScanText("$($p.ProcessName) $($p.MainWindowTitle)")
    if ($p.ProcessName -match '^javaw?$') { $hit = @($hit) + [SigCore]::ScanText((@($p.Modules | ForEach-Object { $_.FileName }) -join "`n")) | Select-Object -Unique }
    if ($hit.Count -gt 0) { Add-Row -Source 'Process' -Name $p.ProcessName -Location "PID $($p.Id) | $($p.MainWindowTitle)" -NameT $hit -Modified $null }
}
foreach ($cp in Get-CimInstance Win32_Process -Filter "Name like 'java%'") {
    $hit = [SigCore]::ScanText($cp.CommandLine)
    if ($hit.Count -gt 0) { Add-Row -Source 'Process' -Name $cp.Name -Location ("PID $($cp.ProcessId) | " + $cp.CommandLine) -NameT $hit -Modified $null }
}

# ---------------------------------------------------------------------------
# 8) Report  (order: LOW -> MEDIUM -> HIGH, the worst stays at the bottom)
# ---------------------------------------------------------------------------
$elapsed = (Get-Date) - $started
Write-Host ("`r" + (' ' * ((Get-Cw) - 2)) + "`r") -NoNewline
$order = @{ 'LOW' = 0; 'MEDIUM' = 1; 'HIGH' = 2 }
$rows = Merge-Rows
$sorted = @($rows | Sort-Object @{ Expression = { $order[$_.Severity] } }, Score, Name)
$high = @($sorted | Where-Object { $_.Severity -eq 'HIGH' }).Count
$med = @($sorted | Where-Object { $_.Severity -eq 'MEDIUM' }).Count
$low = @($sorted | Where-Object { $_.Severity -eq 'LOW' }).Count

foreach ($sec in @(@('LOW', 'Green'), @('MEDIUM', 'Yellow'), @('HIGH', 'Red'))) {
    $items = @($sorted | Where-Object { $_.Severity -eq $sec[0] })
    if ($items.Count -eq 0) { continue }
    Write-SectionHeader -Label $sec[0] -Count $items.Count -Color $sec[1]
    foreach ($item in $items) { Write-Card -Row $item }
}

$bar = [string][char]0x2501
$points = ($high * 6) + ($med * 3) + $low
$cells = [math]::Min(24, $points)
$meter = ([string][char]0x2588 * $cells) + ([string][char]0x2591 * (24 - $cells))
if ($high -gt 0) { $tColor = 'Red'; $verdict = 'SUSPICIOUS - cheat signatures found' }
elseif ($med -gt 0) { $tColor = 'Yellow'; $verdict = 'REVIEW NEEDED - possible cheat traces' }
elseif ($low -gt 0) { $tColor = 'Green'; $verdict = 'PROBABLY CLEAN - minor hints only' }
else { $tColor = 'Green'; $verdict = 'CLEAN - nothing suspicious found' }

Write-Host ''
Write-Host ('  ' + ($bar * 3) + ' RESULT ' + ($bar * 44)) -ForegroundColor Magenta
Write-Host ''
Write-Host '    threat  ' -NoNewline -ForegroundColor DarkGray
Write-Host $meter -NoNewline -ForegroundColor $tColor
Write-Host ('  ' + $verdict) -ForegroundColor $tColor
Write-Host '    flagged ' -NoNewline -ForegroundColor DarkGray
Write-Host "$high HIGH" -NoNewline -ForegroundColor Red
Write-Host '   ' -NoNewline
Write-Host "$med MEDIUM" -NoNewline -ForegroundColor Yellow
Write-Host '   ' -NoNewline
Write-Host "$low LOW" -ForegroundColor Green

$tally = @{}
foreach ($r in $rows) { foreach ($t in ($r.Matches -split ', ')) { if ($t) { $tally[$t]++ } } }
if ($tally.Count -gt 0) {
    $topList = @($tally.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 5 | ForEach-Object { '{0} x{1}' -f $_.Key, $_.Value })
    Write-Host '    top hits ' -NoNewline -ForegroundColor DarkGray
    Write-Host ($topList -join '  |  ') -ForegroundColor Red
}
Write-Host ('    scanned {0} files in {1:n0}s' -f $scanned, $elapsed.TotalSeconds) -ForegroundColor DarkGray

if ($rows.Count -gt 0) {
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $csv = Join-Path $OutDir "MiniSS_$stamp.csv"; $html = Join-Path $OutDir "MiniSS_$stamp.html"
    try {
        $sorted | Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8
        $css = 'body{background:#0b0a12;color:#e8e4f7;font-family:Segoe UI,Arial,sans-serif;padding:28px;max-width:1200px;margin:auto}' +
               'h1{margin:0;background:linear-gradient(90deg,#ff4df0,#4df3ff);-webkit-background-clip:text;color:transparent}' +
               '.sub{color:#8d86a8;margin:6px 0 18px}' +
               '.chips{display:flex;gap:10px;margin-bottom:18px}.chip{padding:8px 16px;border-radius:999px;font-weight:700;border:1px solid #2a2342}' +
               '.c-HIGH{color:#ff4d4d;background:#2a1217}.c-MEDIUM{color:#ffc857;background:#2a2312}.c-LOW{color:#5dff9a;background:#112a1b}' +
               'table{border-collapse:collapse;width:100%}th{background:#1b1630;color:#9be7ff;text-align:left;padding:8px}' +
               'td{padding:8px;border-bottom:1px solid #2a2342;vertical-align:top;word-break:break-all}' +
               '.m{color:#ff4d4d;font-weight:600}.h{color:#8d86a8}' +
               '.HIGH td:first-child{color:#ff4d4d;font-weight:700}.MEDIUM td:first-child{color:#ffc857;font-weight:700}.LOW td:first-child{color:#5dff9a;font-weight:700}'
        $sb = New-Object System.Text.StringBuilder
        [void]$sb.AppendLine("<html><head><meta charset='utf-8'><title>MiniSS report</title><style>$css</style></head><body>")
        [void]$sb.AppendLine("<h1>MiniSS report</h1><div class='sub'>by $Author | $Invite | host $(ConvertTo-HtmlText $env:COMPUTERNAME) | $(Get-Date -Format 'yyyy-MM-dd HH:mm')</div>")
        [void]$sb.AppendLine("<div class='chips'><span class='chip c-LOW'>$low LOW</span><span class='chip c-MEDIUM'>$med MEDIUM</span><span class='chip c-HIGH'>$high HIGH</span></div>")
        [void]$sb.AppendLine('<table><tr><th>Severity</th><th>Source</th><th>Name</th><th>Found</th><th>Weak hints</th><th>Modified</th><th>Location</th></tr>')
        foreach ($r in $sorted) {
            [void]$sb.AppendLine("<tr class='$($r.Severity)'><td>$($r.Severity)</td><td>$(ConvertTo-HtmlText $r.Source)</td><td>$(ConvertTo-HtmlText $r.Name)</td><td class='m'>$(ConvertTo-HtmlText $r.Matches)</td><td class='h'>$(ConvertTo-HtmlText $r.Hints)</td><td>$(ConvertTo-HtmlText $r.Modified)</td><td>$(ConvertTo-HtmlText $r.Location)</td></tr>")
        }
        [void]$sb.AppendLine('</table></body></html>')
        [System.IO.File]::WriteAllText($html, $sb.ToString(), (New-Object System.Text.UTF8Encoding($true)))
        Write-Host ''
        Write-Host "    saved: $csv" -ForegroundColor Green
        Write-Host "    saved: $html" -ForegroundColor Green
    } catch { Write-Host "    could not save reports to $OutDir" -ForegroundColor Red }
}

Write-Host ''
Write-Host '    a match is a lead, not proof - check the path and date first.' -ForegroundColor DarkGray
Write-Host "    MiniSS by $Author  |  $Invite" -ForegroundColor Magenta
Write-Host ''
if (-not $NoPause) { Write-Host '    press Enter to exit...' -ForegroundColor DarkGray; [void](Read-Host) }
