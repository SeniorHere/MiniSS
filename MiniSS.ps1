<#
.SYNOPSIS
    MiniSS - Mini ScreenShare scanner (v3.9 - bounded scan and signature priority)
    Author : Senior
    Discord: https://discord.gg/95MmttMD6

.DESCRIPTION
    Looks for well-known Minecraft cheat clients / modules / injectors in:
      - files (.jar .exe .dll .bat .cmd)  - jar files are opened and checked inside
      - running processes
      - Prefetch + Recent traces (programs that ran before, even if deleted)
    Everything stays on this PC. Nothing is uploaded, deleted or changed.
    Suspicious strings are shown in RED. Results are listed LOW > MEDIUM > HIGH.
    A CSV + HTML report is saved on the Desktop.

.PARAMETER Mode
    Quick = .minecraft, Downloads, Recent, Prefetch, Temp, Recycle Bin + launcher folders
    Full  = every fixed / removable drive (slower)
.PARAMETER Deep
    Expands class-string scanning to all JARs, including vanilla libraries and versions (slower).
.PARAMETER Path
    Scan only these folders (overrides Mode).
.PARAMETER ShowWeak
    Also list files that only match weak (ambiguous) keywords.
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
    [switch]$Deep,
    [int]$MaxSizeMB = 25,
    [string]$OutDir = [Environment]::GetFolderPath('Desktop')
)

$ErrorActionPreference = 'SilentlyContinue'
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }

$Author = 'Senior'
$Invite = 'https://discord.gg/95MmttMD6'

# ---------------------------------------------------------------------------
# 1) Signature database   weight: 3 = strong, 2 = medium, 1 = weak (ambiguous)
#    Generic names (Vape, Sigma, Flux ...) are only listed with a "Client"-style
#    suffix so normal programs are not flagged.
# ---------------------------------------------------------------------------
$db = @{}
function Add-Terms {
    param([int]$Weight, [string[]]$List)
    foreach ($t in $List) { if (-not $db.ContainsKey($t) -or [int]$db[$t] -lt $Weight) { $db[$t] = $Weight } }
}

# Strong: cheat modules
Add-Terms 3 @(
    'AutoTotem', 'InventoryTotem', 'InvTotem', 'AutoInventoryTotem', 'TotemHit',
    'AutoTotemModule', 'TotemPopCounter', 'TotemSwap', 'AutoTotemSwap',
    'AutoCrystal', 'CrystalAura', 'OneHitCrystal', 'CrystalOptimizer', 'FastCrystal', 'AutoHitCrystal',
    'AnchorMacro', 'AnchorAura', 'AutoAnchor',
    'AutoStun', 'StunSlam', 'Stun-Slam', 'ShieldBreaker', 'AutoPot', 'AutoDoubleHand',
    'TriggerBot', 'KillAura', 'AimAssist', 'AimBot', 'AutoClicker',
    'Freecam', 'FreeCamera', 'Baritone', 'Doomsday', 'AntiAim', 'NoRender', 'NoRotate',
    'TimerHack', 'FastUse', 'FastEat', 'AutoFish', 'AutoMine', 'AutoTool', 'ChestStealer',
    'AutoSteal', 'AutoGG', 'AutoRespawn', 'AutoQueue', 'AutoRequeue', 'Blink', 'Disabler',
    'InvMove', 'MaceDMG', 'MaceAura', 'AutoMace', 'NoFall', 'AutoWTap', 'ScaffoldWalk',
    'AutoCrit', 'PacketFly', 'AntiKnockback', 'NoKnockback', 'Scaffold', 'XRay', 'X-Ray', 'Flight', 'AutoTotem', 'CrystalAura', 'TriggerBot', 'KillAura', 'AimAssist', 'AutoClicker', 'Reach', 'Velocity', 'Jesus', 'SpeedHack', 'Step', 'Phase', 'NoClip', 'ChestESP', 'PlayerESP', 'StorageESP', 'Tracers', 'TargetStrafe', 'SilentAim', 'AntiBot', 'AutoWeapon', 'AutoSword', 'FastPlace', 'FastBreak', 'Timer', 'Blink', 'Disabler', 'NoSlow', 'InventoryMove'
)
# Strong: cheat clients (distinctive names)
Add-Terms 3 @(
    'Wurst', 'WurstClient', 'Wurst Client', 'Wurst-Client', 'WurstMC', 'Prestige', 'Doomsday Client', 'DoomsdayClient',
    'LiquidBounce', 'LiquidBounce Nextgen', 'LiquidBounce-Nextgen', 'meteordevelopment', 'meteor-client', 'MeteorClient', 'Meteor Client',
    'OringoClient', 'Oringo Client', 'Dortware', 'Dortware Client', 'Asteria Client', 'AsteriaClient',
    'Haruka Client', 'HarukaClient', 'Augustus Client', 'AugustusClient', 'Vega Client', 'VegaClient',
    'wurstclient', 'wurst-client', 'Wurst Client', 'BleachHack', 'Aristois', 'RusherHack', 'ThunderHack',
    'FutureClient', 'Future Client', 'vape.gg', 'VapeV4', 'VapeV3', 'VapeLite', 'Vape Client',
    'Vape V4', 'Vape V3', 'Vape Lite', 'RavenB+', 'Raven B+', 'RavenBPlus',
    'SigmaClient', 'Sigma Client', 'Sigma5', 'Sigma 5.0',
    'ImpactClient', 'Impact Client', 'JigsawClient', 'Jigsaw Client', 'AresClient', 'Ares Client',
    'HydraClient', 'Hydra Client', 'XuluClient', 'Xulu Client', 'FluxClient', 'Flux Client',
    'PerishClient', 'Perish Client', 'JexClient', 'Jex Client', 'FrostClient', 'Frost Client',
    'ItamiClient', 'Itami Client', 'PolarClient', 'Polar Client', 'CurseClient', 'Curse Client',
    'FDPClient', 'FDP Client', 'DopiumClient', 'Dopium Client', 'Dopium', 'Manthe', 'Manthe Client', 'Whiteout', 'Whiteout Client', 'Pulsive Client', 'AimWhere Client', 'Dream Client'
)
# Strong: more well-known cheat clients
Add-Terms 3 @(
    'RiseClient', 'Rise Client', 'NovolineClient', 'Novoline Client', 'TenacityClient', 'Tenacity Client',
    'AstolfoClient', 'Astolfo Client', 'DoomsdayClient', 'Doomsday Client', 'SlinkyClient', 'Slinky Client',
    'KonasClient', 'Konas Client', 'PhobosClient', 'Phobos Client', '3arthh4ck', 'SalHack', 'KamiBlue',
    'ForgeHax', 'Pandaware', 'ExhibitionClient', 'Exhibition Client', 'EntropyClient', 'Entropy Client',
    'DripClient', 'Drip Client', 'ZeroDay Client', 'ZerodayClient', 'WolframClient', 'Wolfram Client',
    'InertiaClient', 'Inertia Client', 'NodusClient', 'CosmosClient', 'Cosmos Client',
    'BozeClient', 'Boze Client', 'Nursultan', 'CelestialClient', 'Celestial Client',
    'ExpensiveClient', 'Expensive Client', 'Wexside', 'Akrien', 'RemixClient', 'Remix Client',
    'MoonClient', 'Moon Client', 'Huzuni', 'Lambda Client', 'lambda-client', 'gamesense.pub', 'GameSense Client',
    'Vape', 'VapeClient', 'Vape Client', 'Vape V4', 'Vape V3', 'Vape Lite', 'VapeLite',
    'Wurst Client', 'WurstClient', 'Wurst', 'LiquidBounce', 'Meteor Client', 'MeteorClient'
)
# Medium
Add-Terms 2 @(
    'ClickGUI', 'ReachHack', 'TinyTask', 'HitSelect', 'DoubleHand', 'NoSlowdown', 'ElytraFly',
    'GSAutoClicker', 'OPAutoClicker', 'SpeedAutoClicker', 'AutoTrap', 'HoleFiller', 'SelfFill', 'FastBreak',
    'Xray Ultimate', 'X-Ray Ultimate', 'Xray Texture Pack', 'X-Ray Texture Pack', 'Ores Only',
    'CaveFinder', 'Cave Finder', 'FullBright', 'Full Bright', 'OreESP', 'Ore ESP', 'ESP Module',
    'Freecam Mod', 'Free Camera Mod', 'AutoTotem Mod', 'Totem Swap Mod', 'Baritone Mod'
)
# Weak: common words that also appear in harmless files (never reported alone)
Add-Terms 1 @(
    'Flight', 'Macro', 'Velocity', 'XRay', 'X-Ray', 'FastPlace', 'Hitbox', 'Bhop', 'WallHack', 'Injector',
    'Criticals', 'Backtrack', 'AutoHotkey', 'Surround', 'AutoArmor', 'FreeCam', 'Fullbright', 'OreESP',
    # Java/Minecraft behavior indicators: weak individually; clusters can flag unknown mods for review.
    'C02PacketUseEntity', 'CPacketUseEntity', 'C0BPacketEntityAction', 'CPacketPlayer', 'attackEntity', 'attack', 'autototem', 'crystalaura', 'triggerbot', 'killaura', 'aimassist', 'scaffold', 'xray', 'flight', 'autocrystal', 'silentaim', 'targetstrafe', 'packetfly', 'freecam', 'entityesp', 'playeresp', 'chestesp', 'storageesp', 'wallhack', 'reach', 'velocity', 'fastplace', 'fastbreak',
    'sendPacket', 'attackEntity', 'getMouseOver', 'reachDistance', 'timerSpeed',
    'EntityPlayerSP', 'ClientPlayerEntity', 'PlayerEntity', 'MinecraftClient',
    'org.spongepowered.asm.mixin', 'Mixin', 'EntityRenderer', 'WorldRenderer',
    'KeyBinding', 'InputUtil', 'GLFW_KEY', 'isFlying', 'setVelocity', 'NoSlow',
    'findTarget', 'targetEntity', 'rotationYaw', 'rotationPitch', 'rayTrace'
)

# Generic client names: matched in FILE NAMES only, and only together with a typical suffix
# (e.g. "Vape V4.exe", "Sigma Client.jar", "Raven B+.jar", "Impact_loader.exe").
$genericNames = 'wurst|liquidbounce|meteor|vape|raven|sigma|rise|novoline|tenacity|astolfo|impact|jigsaw|ares|hydra|xulu|flux|perish|jex|frost|itami|polar|curse|fdp|dopium|slinky|doomsday|entropy|drip|exhibition|zeroday|wolfram|inertia|nursultan|celestial|expensive|wexside|akrien|moon|remix|huzuni|whiteout|manthe|aimwhere|pulsive'
$nameRegex = New-Object System.Text.RegularExpressions.Regex(
    ('(?i)(^|[^a-z0-9])(' + $genericNames + ')[ _\-.]*(client|loader|injector|crack(ed)?|hack(ed)?|cheat|ghost|lite|v\d+(\.\d+)*|b\+{1,2}|\d+(\.\d+)+)([^a-z0-9]|$)'))

# Well-known harmless programs: skipped when they match only on content (not on their name)
$trustedNameRegex = '(?i)^(tlauncher|whatsapp)'
$trustedPublishers = @(
    'Microsoft', 'Google', 'WhatsApp', 'Meta Platforms', 'Mozilla', 'Oracle', 'Adoptium', 'Eclipse',
    'Discord', 'Valve', 'NVIDIA', 'Intel', 'Advanced Micro Devices', 'Mojang', 'Apple', 'Adobe',
    'Epic Games', 'Spotify', 'Zoom', 'JetBrains', 'Logitech', 'Razer', 'Corsair', 'SteelSeries',
    'Realtek', 'Python Software', 'GitHub', 'OBS Project', 'Brave', 'Opera', 'Telegram', 'Riot Games',
    'Blizzard', 'Electronic Arts', 'Ubisoft', 'Amazon', 'Cloudflare', 'Autodesk', 'Dropbox'
)

$allTerms = [string[]]@($db.Keys)

# ---------------------------------------------------------------------------
# 2) Matching engine (compiled once; works on Windows PowerShell 5.1 and 7)
#    - case-insensitive, ASCII + UTF-16 strings
#    - word-boundary aware (so "NoFall" does not match "NoFallback")
#    - single-worker, bounded CPU
# ---------------------------------------------------------------------------
if (-not ('SigCore' -as [type])) {
    $csharp = @'
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Text;
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
    const int Chunk = 256 * 1024;
    const long JarBudget = 3L * 1024 * 1024;
    const long ZipBudget = 768L * 1024;
    public static bool Deep = false;
    public static long IndexDeadlineUtcTicks = long.MaxValue;
    public static long ScanDeadlineUtcTicks = long.MaxValue;
    public static bool IndexTimedOut = false;
    public static bool ScanTimedOut = false;
    public static int ProcessedFiles = 0;
    static bool IndexExpired() { if (DateTime.UtcNow.Ticks >= IndexDeadlineUtcTicks) { IndexTimedOut = true; return true; } return false; }
    static bool ScanExpired() { if (DateTime.UtcNow.Ticks >= ScanDeadlineUtcTicks) { ScanTimedOut = true; return true; } return false; }

    static byte[] MakeLower()
    {
        byte[] t = new byte[256];
        for (int i = 0; i < 256; i++) t[i] = (byte)((i >= 65 && i <= 90) ? i + 32 : i);
        return t;
    }

    public static void Load(string[] terms)
    {
        var p = new List<byte[]>();
        var t = new List<string>();
        var w = new List<bool>();
        byFirst = new List<int>[256];
        pairOk = new bool[65536];
        longest = 1;
        foreach (string term in terms)
        {
            if (string.IsNullOrEmpty(term) || term.Length < 3) continue;
            string low = term.ToLowerInvariant();
            byte[] a = Encoding.ASCII.GetBytes(low);
            byte[] u = Encoding.Unicode.GetBytes(low);
            for (int pass = 0; pass < 2; pass++)
            {
                byte[] b = (pass == 0) ? a : u;
                p.Add(b);
                t.Add(term);
                w.Add(pass == 1);
                int idx = p.Count - 1;
                if (byFirst[b[0]] == null) byFirst[b[0]] = new List<int>();
                byFirst[b[0]].Add(idx);
                pairOk[(b[0] << 8) | b[1]] = true;
                if (b.Length > longest) longest = b.Length;
            }
        }
        pats = p.ToArray();
        tags = t.ToArray();
        wide = w.ToArray();
    }

    static bool IsLetter(byte b) { return (b >= 65 && b <= 90) || (b >= 97 && b <= 122); }
    static bool IsLowerCase(byte b) { return b >= 97 && b <= 122; }

    static bool Boundary(byte[] buf, int start, int plen, int len, int step)
    {
        bool firstUpper = buf[start] >= 65 && buf[start] <= 90;
        int pi = start - step;
        if (pi >= 0)
        {
            byte pb = buf[pi];
            if (step == 2 && buf[pi + 1] != 0) pb = 0;
            if (IsLetter(pb) && !firstUpper) return false;
        }
        int ni = start + plen;
        if (ni + step <= len)
        {
            byte nb = buf[ni];
            if (step == 2 && buf[ni + 1] != 0) nb = 0;
            if (IsLowerCase(nb)) return false;
        }
        return true;
    }

    static void Scan(byte[] buf, int len, List<string> hits)
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
                byte[] p = pats[k];
                if (i + p.Length > len) continue;
                string tag = tags[k];
                if (hits.Contains(tag)) continue;
                int j = 1;
                for (; j < p.Length; j++)
                {
                    if (lower[buf[i + j]] != p[j]) break;
                }
                if (j == p.Length && Boundary(buf, i, p.Length, len, wide[k] ? 2 : 1))
                    hits.Add(tag);
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

    static void ScanFileInto(string path, List<string> hits)
    {
        using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read,
                                       FileShare.ReadWrite | FileShare.Delete, 4096))
        {
            long flen = fs.Length;
            if (flen <= 0) return;
            int chunk = (int)Math.Min((long)Chunk, flen);
            byte[] buf = new byte[chunk + longest];
            int carry = 0, n;
            while ((n = fs.Read(buf, carry, chunk)) > 0)
            {
                if (ScanExpired()) break;
                int total = carry + n;
                Scan(buf, total, hits);
                carry = Math.Min(longest - 1, total);
                Buffer.BlockCopy(buf, total - carry, buf, 0, carry);
            }
        }
    }

    // Jar/zip: entry names, descriptors, and prioritized bounded class-string scan
    static void ScanJarInto(string path, List<string> hits)
    {
        string archiveExt = Path.GetExtension(path);
        bool isZip = archiveExt.Equals(".zip", StringComparison.OrdinalIgnoreCase) || archiveExt.Equals(".mrpack", StringComparison.OrdinalIgnoreCase);
        long budget = isZip ? ZipBudget : JarBudget;
        bool deep = Deep;
        string lowerPath = path.ToLowerInvariant();
        bool inMinecraft = lowerPath.Contains("\\.minecraft\\") || lowerPath.Contains("\\minecraft\\");
        bool inTargetFolder = lowerPath.Contains("\\mods\\") || lowerPath.Contains("\\modpacks\\") || lowerPath.Contains("\\downloads\\") || lowerPath.Contains("\\temp\\") || lowerPath.Contains("\\resourcepacks\\") || lowerPath.Contains("\\shaderpacks\\");
        // Class constant-pool strings are scanned in targeted archives and Minecraft archives;
        // the large shared libraries tree is excluded in Quick mode.
        bool inVanillaBulk = lowerPath.Contains("\\libraries\\");
        bool inspectClasses = !isZip && (deep || inTargetFolder || (inMinecraft && !inVanillaBulk));
        using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read,
                                       FileShare.ReadWrite | FileShare.Delete, 4096))
        using (var zip = new ZipArchive(fs, ZipArchiveMode.Read))
        {
            var sb = new StringBuilder();
            foreach (ZipArchiveEntry e in zip.Entries)
            {
                sb.Append(e.FullName);
                sb.Append('\n');
            }
            byte[] nb = Encoding.UTF8.GetBytes(sb.ToString());
            Scan(nb, nb.Length, hits);

            var scanEntries = new List<ZipArchiveEntry>(zip.Entries);
            scanEntries.Sort((a, b) => EntryPriority(a.FullName, isZip).CompareTo(EntryPriority(b.FullName, isZip)));
            foreach (ZipArchiveEntry e in scanEntries)
            {
                if (ScanExpired()) break;
                if (budget <= 0) break;
                if (e.Length == 0) continue;
                string n = e.FullName.ToLowerInvariant();
                // Some modpack/resource archives contain nested JARs. Inspect a bounded
                // amount of their class constant-pool strings without extracting to disk.
                if (isZip && n.EndsWith(".jar", StringComparison.Ordinal) && e.Length <= 4L * 1024 * 1024)
                {
                    try
                    {
                        using (Stream nestedStream = e.Open())
                        using (var nestedMemory = new MemoryStream())
                        {
                            nestedStream.CopyTo(nestedMemory);
                            nestedMemory.Position = 0;
                            using (var nestedZip = new ZipArchive(nestedMemory, ZipArchiveMode.Read))
                            {
                                foreach (ZipArchiveEntry ce in nestedZip.Entries)
                                {
                                    if (ScanExpired() || budget <= 0) break;
                                    string cn = ce.FullName.ToLowerInvariant();
                                    if (!cn.EndsWith(".class", StringComparison.Ordinal) || ce.Length <= 0 || ce.Length > 256 * 1024) continue;
                                    if (ce.Length > budget) continue;
                                    budget -= ce.Length;
                                    using (Stream cs = ce.Open())
                                    using (var cm = new MemoryStream((int)ce.Length))
                                    {
                                        cs.CopyTo(cm);
                                        Scan(cm.GetBuffer(), (int)cm.Length, hits);
                                    }
                                }
                            }
                        }
                    }
                    catch (Exception) { }
                    continue;
                }
                bool meta = e.Length <= 262144 &&
                            (n.EndsWith("mod.json", StringComparison.Ordinal)
                             || n.EndsWith("mcmod.info", StringComparison.Ordinal)
                             || n.EndsWith("plugin.yml", StringComparison.Ordinal)
                             || n.EndsWith("mods.toml", StringComparison.Ordinal)
                             || n.EndsWith("manifest.mf", StringComparison.Ordinal)
                             || n.EndsWith(".mixins.json", StringComparison.Ordinal));
                // Scan class constant-pool strings by default in likely cheat locations.
                // Strict per-entry and per-archive budgets keep CPU/RAM use bounded.
                bool cls = inspectClasses && e.Length <= 256 * 1024 && n.EndsWith(".class", StringComparison.Ordinal);
                // Resource/shader packs often hide their useful content in GLSL source,
                // properties, JSON and mcmeta files, not just pack.mcmeta.
                bool packContent = isZip && e.Length <= 256 * 1024 &&
                            (n.EndsWith("pack.mcmeta", StringComparison.Ordinal) ||
                             n.EndsWith(".txt", StringComparison.Ordinal) ||
                             n.EndsWith(".json", StringComparison.Ordinal) ||
                             n.EndsWith(".mcmeta", StringComparison.Ordinal) ||
                             n.EndsWith(".properties", StringComparison.Ordinal) ||
                             n.EndsWith(".fsh", StringComparison.Ordinal) ||
                             n.EndsWith(".vsh", StringComparison.Ordinal) ||
                             n.EndsWith(".glsl", StringComparison.Ordinal) ||
                             n.EndsWith(".frag", StringComparison.Ordinal) ||
                             n.EndsWith(".vert", StringComparison.Ordinal) ||
                             n.EndsWith(".toml", StringComparison.Ordinal) ||
                             n.EndsWith(".class", StringComparison.Ordinal));
                if (isZip ? (!packContent) : (!meta && !cls)) continue;
                if (cls && budget <= 0) break;

                budget -= e.Length;
                using (Stream s = e.Open())
                {
                    var ms = new MemoryStream((int)e.Length);
                    s.CopyTo(ms);
                    Scan(ms.GetBuffer(), (int)ms.Length, hits);
                }
            }
        }
    }

    static int EntryPriority(string name, bool isZip)
    {
        string n = name.ToLowerInvariant();
        if (!isZip && n.EndsWith(".class", StringComparison.Ordinal)) return 0;
        if (n.EndsWith("mods.toml", StringComparison.Ordinal) || n.EndsWith("mcmod.info", StringComparison.Ordinal) || n.EndsWith("mod.json", StringComparison.Ordinal) || n.EndsWith("manifest.mf", StringComparison.Ordinal) || n.EndsWith(".mixins.json", StringComparison.Ordinal)) return 1;
        if (isZip && (n.EndsWith(".json", StringComparison.Ordinal) || n.EndsWith(".txt", StringComparison.Ordinal) || n.EndsWith(".glsl", StringComparison.Ordinal) || n.EndsWith(".fsh", StringComparison.Ordinal) || n.EndsWith(".vsh", StringComparison.Ordinal))) return 0;
        return 2;
    }

    // Fast bounded index. Roots are prioritized; returns path, size and timestamp.
    public static string[] Index(string[] roots, string[] skipNames, string[] exts, long maxBytes, long maxArchiveBytes, int maxFiles, int maxDirs)
    {
        var skip = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
        foreach (string s in skipNames) skip[s] = true;
        var ext = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
        foreach (string x in exts) ext[x] = true;
        var visited = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
        var results = new List<string>();
        var rootList = new List<KeyValuePair<int, string>>();
        foreach (string r in roots)
        {
            if (string.IsNullOrEmpty(r)) continue;
            int bar = r.IndexOf('|');
            int d = 4;
            string p = r;
            if (bar > 0)
            {
                int.TryParse(r.Substring(0, bar), out d);
                p = r.Substring(bar + 1);
            }
            if (Directory.Exists(p)) rootList.Add(new KeyValuePair<int, string>(d, p));
        }
        // Hidden files/directories are included by EnumerateFiles/EnumerateDirectories; deeper roots first, so a shallow parent root never limits .minecraft.
        rootList.Sort((k1, k2) => k2.Key.CompareTo(k1.Key));

        var dirs = new List<string>();
        var depths = new List<int>();
        foreach (KeyValuePair<int, string> kv in rootList)
        {
            dirs.Add(kv.Value);
            depths.Add(kv.Key);
        }

        int head = 0;
        while (head < dirs.Count)
        {
            if (IndexExpired() || results.Count >= maxFiles || head >= maxDirs) { IndexTimedOut = true; break; }
            string dir = dirs[head];
            int left = depths[head];
            head++;

            string key = dir.TrimEnd('\\');
            if (visited.ContainsKey(key)) continue;
            visited[key] = true;

            if (left > 0)
            {
                try
                {
                    foreach (string sub in Directory.EnumerateDirectories(dir))
                    {
                        if (IndexExpired() || dirs.Count >= maxDirs) { IndexTimedOut = true; break; }
                        string leaf = Path.GetFileName(sub);
                        bool isPackAssets = leaf.Equals("assets", StringComparison.OrdinalIgnoreCase) && dir.IndexOf("\\resourcepacks\\", StringComparison.OrdinalIgnoreCase) >= 0;
                        if (skip.ContainsKey(leaf) && !isPackAssets) continue;
                        try
                        {
                            FileAttributes attr = File.GetAttributes(sub);
                            if ((attr & FileAttributes.ReparsePoint) != 0) continue;
                        }
                        catch (Exception) { continue; }
                        dirs.Add(sub);
                        depths.Add(left - 1);
                    }
                }
                catch (Exception) { }
            }

            try
            {
                foreach (string f in Directory.EnumerateFiles(dir))
                {
                    if (IndexExpired() || results.Count >= maxFiles) break;
                    string fe = Path.GetExtension(f);
                    bool recycleData = f.IndexOf("\\$Recycle.Bin\\", StringComparison.OrdinalIgnoreCase) >= 0;
                    // Recycle Bin stores original filenames in extensionless $I/$R files.
                    if (fe.Length == 0 ? !recycleData : !ext.ContainsKey(fe)) continue;
                    var fi = new FileInfo(f);
                    long len = fi.Length;
                    bool archive = fe.Equals(".jar", StringComparison.OrdinalIgnoreCase) || fe.Equals(".zip", StringComparison.OrdinalIgnoreCase) || fe.Equals(".mrpack", StringComparison.OrdinalIgnoreCase) || fe.Equals(".litemod", StringComparison.OrdinalIgnoreCase);
                    long limit = archive ? maxArchiveBytes : maxBytes;
                    if (len <= 0 || len > limit) continue;
                    results.Add(f + "\t" + len.ToString() + "\t" + fi.LastWriteTime.Ticks.ToString());
                }
            }
            catch (Exception) { }
        }
        return results.ToArray();
    }

    // Scans many files in parallel. Returns lines:  path <TAB> nameHits <TAB> contentHits
    public static string[] ScanMany(string[] paths)
    {
        var results = new List<string>();
        var opts = new ParallelOptions();
        opts.MaxDegreeOfParallelism = 1;
        Parallel.ForEach(paths, opts, path =>
        {
            if (ScanExpired()) return;
            try
            {
                var nameHits = new List<string>();
                var contentHits = new List<string>();
                byte[] nb = Encoding.UTF8.GetBytes(Path.GetFileName(path));
                Scan(nb, nb.Length, nameHits);
                string ext = Path.GetExtension(path).ToLowerInvariant();
                try
                {
                    if (ext == ".jar" || ext == ".zip" || ext == ".mrpack" || ext == ".litemod")
                    {
                        string lp = path.ToLowerInvariant();
                        bool inMcTarget = lp.Contains("\\.minecraft\\mods\\") || lp.Contains("\\.minecraft\\resourcepacks\\") || lp.Contains("\\.minecraft\\shaderpacks\\") || lp.Contains("\\.minecraft\\modpacks\\") || lp.Contains("\\.minecraft\\versions\\") || lp.Contains("\\downloads\\");
                        bool inMinecraftTree = lp.Contains("\\.minecraft\\") || lp.Contains("\\minecraft\\");
                        // Inspect Minecraft archives except shared libraries; class scanning is budgeted per archive.
                        bool likely = (inMinecraftTree && !lp.Contains("\\libraries\\")) || inMcTarget || lp.Contains("\\temp\\") || lp.Contains("\\$recycle.bin\\") || lp.Contains("\\recent\\");
                        // Shared libraries are skipped in Quick mode to avoid decompressing hundreds of dependencies.
                        if (likely || Deep || ext == ".mrpack") ScanJarInto(path, contentHits);
                    }
                    else ScanFileInto(path, contentHits);
                }
                catch (Exception) { }
                System.Threading.Interlocked.Increment(ref ProcessedFiles);
                if (nameHits.Count > 0 || contentHits.Count > 0)
                {
                    string line = path + "\t" + string.Join(",", nameHits.ToArray()) + "\t" + string.Join(",", contentHits.ToArray());
                    lock (results) { results.Add(line); }
                }
            }
            catch (Exception) { }
        });
        return results.ToArray();
    }
}
'@
    Add-Type -TypeDefinition $csharp -ReferencedAssemblies 'System.IO.Compression'
}
[SigCore]::Load($allTerms)
[SigCore]::Deep = [bool]$Deep

# ---------------------------------------------------------------------------
# 3) Look & feel
# ---------------------------------------------------------------------------
function Show-Banner {
    $dot = [string][char]0x25CF
    $dim = [string][char]0x00B7

    # big block letters, 7 rows tall: S E N I O R
    $font = @{
        'S' = @('.####', '#....', '#....', '.###.', '....#', '....#', '####.')
        'E' = @('#####', '#....', '#....', '####.', '#....', '#....', '#####')
        'N' = @('#...#', '##..#', '##..#', '#.#.#', '#..##', '#..##', '#...#')
        'I' = @('###', '.#.', '.#.', '.#.', '.#.', '.#.', '###')
        'O' = @('.###.', '#...#', '#...#', '#...#', '#...#', '#...#', '.###.')
        'R' = @('####.', '#...#', '#...#', '####.', '#.#..', '#..#.', '#...#')
    }

    $lines = @('', '', '', '', '', '', '')
    foreach ($ch in 'SENIOR'.ToCharArray()) {
        $g = $font[[string]$ch]
        for ($r = 0; $r -lt 7; $r++) { $lines[$r] += $g[$r] + '.' }
    }

    # colors that stay visible on the default blue PowerShell background
    $grad = @('Magenta', 'Magenta', 'Magenta', 'White', 'Cyan', 'Cyan', 'Cyan')
    $width = $lines[0].Length

    Write-Host ''
    foreach ($line in $lines) {
        $runText = '      '
        $runCol  = 'Gray'
        for ($c = 0; $c -lt $line.Length; $c++) {
            if ($line[$c] -eq '#') {
                $col  = $grad[[math]::Floor($c * $grad.Count / $width)]
                $cell = $dot + ' '
            } else {
                $col  = $runCol
                $cell = '  '
            }
            if ($col -eq $runCol) { $runText += $cell }
            else {
                Write-Host $runText -NoNewline -ForegroundColor $runCol
                $runText = $cell
                $runCol  = $col
            }
        }
        Write-Host $runText -ForegroundColor $runCol
    }
    Write-Host ('      ' + (($dim + ' ') * $width)) -ForegroundColor DarkGray
    Write-Host ''

    # info panel
    $h  = [string][char]0x2500
    $v  = [string][char]0x2502
    $tl = [string][char]0x250C
    $tr = [string][char]0x2510
    $bl = [string][char]0x2514
    $br = [string][char]0x2518
    $pw = 56
    $host1 = 'host {0}   |   {1}' -f $env:COMPUTERNAME, (Get-Date -Format 'yyyy-MM-dd HH:mm')
    $items = @(
        @('MiniSS  //  Screenshare Scanner        v3.9', 'White'),
        @('by Senior   |   Senior Academy', 'Magenta'),
        @($Invite, 'Cyan'),
        @('RED = suspicious    order: LOW > MEDIUM > HIGH', 'Gray'),
        @($host1, 'DarkGray')
    )
    Write-Host ('    ' + $tl + ($h * $pw) + $tr) -ForegroundColor Magenta
    foreach ($it in $items) {
        $txt = (' ' + $it[0]).PadRight($pw)
        if ($txt.Length -gt $pw) { $txt = $txt.Substring(0, $pw) }
        Write-Host ('    ' + $v) -NoNewline -ForegroundColor Magenta
        Write-Host $txt -NoNewline -ForegroundColor $it[1]
        Write-Host $v -ForegroundColor Magenta
    }
    Write-Host ('    ' + $bl + ($h * $pw) + $br) -ForegroundColor Magenta
    Write-Host ''
}

# live one-line status shown while working
$script:tick = 0
function Show-Hud {
    param([string]$Phase, [string]$Text, [double]$Pct = -1, [string]$Eta = '')
    $script:tick++
    $frames = @('|', '/', '-', '\')
    $frame  = $frames[$script:tick % 4]
    $el     = (Get-Date) - $started
    $barTxt = ''
    if ($Pct -ge 0) {
        $cells  = [int][math]::Floor($Pct * 16)
        $filled = ([string][char]0x2588) * $cells
        $rest   = ([string][char]0x2591) * (16 - $cells)
        $barTxt = ' [' + $filled + $rest + '] ' + ('{0,3}%' -f [int]($Pct * 100))
    }
    $text = ' {0} {1,-6}{2}  flagged {3,-3} {4:mm\:ss}{5}  {6}' -f $frame, $Phase, $barTxt, $rows.Count, $el, $Eta, $Text
    $cw = 100
    try { $cw = $Host.UI.RawUI.WindowSize.Width } catch { }
    if (-not $cw) { $cw = 100 }
    if ($text.Length -gt ($cw - 2)) { $text = $text.Substring(0, $cw - 2) }
    Write-Host ("`r" + $text.PadRight($cw - 2)) -NoNewline -ForegroundColor Cyan
}

function Write-SectionHeader {
    param([string]$Label, [int]$Count, [string]$Color)
    $bar = [string][char]0x2501
    Write-Host ''
    Write-Host ('  ' + ($bar * 3) + ' ' + $Label + ' (' + $Count + ') ' + ($bar * 44)) -ForegroundColor $Color
}

function Write-Card {
    param($Row)
    if ($Row.Severity -eq 'HIGH')       { $c = 'Red' }
    elseif ($Row.Severity -eq 'MEDIUM') { $c = 'Yellow' }
    else                                { $c = 'Green' }
    $arrow = [string][char]0x25B8
    $mid   = [string][char]0x251C
    $end   = [string][char]0x2514

    Write-Host ''
    Write-Host ('  ' + $arrow + ' ') -NoNewline -ForegroundColor $c
    Write-Host ('{0,-6}' -f $Row.Severity) -NoNewline -ForegroundColor $c
    Write-Host (' ' + $Row.Name) -NoNewline -ForegroundColor White
    Write-Host ('   (' + $Row.Source + ')') -ForegroundColor DarkGray

    Write-Host ('    ' + $mid + ' found  ') -NoNewline -ForegroundColor DarkGray
    Write-Host $Row.Matches -NoNewline -ForegroundColor Red
    if ($Row.Hints) { Write-Host ('   + ' + $Row.Hints) -NoNewline -ForegroundColor DarkGray }
    Write-Host ''
    if ($Row.Modified) {
        Write-Host ('    ' + $mid + ' date   ' + $Row.Modified) -ForegroundColor DarkGray
    }
    Write-Host ('    ' + $end + ' path   ' + $Row.Location) -ForegroundColor DarkGray
}

# ---------------------------------------------------------------------------
# 4) Helpers
# ---------------------------------------------------------------------------
$rows = New-Object System.Collections.Generic.List[object]

try { if (-not (Test-Path -LiteralPath $OutDir)) { [void](New-Item -ItemType Directory -Path $OutDir -Force) } } catch { $OutDir = [IO.Path]::GetTempPath() }

function Add-Row {
    param($Source, $Name, $Location, [string[]]$Terms, $Modified, [bool]$NameHit = $false, [bool]$Big = $false)

    $score = 0; $strongCount = 0; $medCount = 0
    $hot = @(); $hints = @()
    foreach ($t in ($Terms | Sort-Object)) {
        $wt = $db[$t]
        if (-not $wt) { $wt = 1 }
        $score += $wt
        if ($wt -ge 3)     { $strongCount++; $hot += $t }
        elseif ($wt -eq 2) { $medCount++;    $hot += $t }
        else               { $hints += $t }
    }

    # Weak behavior/API strings are noisy alone. A cluster is a review lead, not proof.
    $weakCount = @($Terms | Where-Object { $db[$_] -eq 1 } | Sort-Object -Unique).Count
    $clusterLead = ($strongCount -eq 0 -and $medCount -eq 0 -and $weakCount -ge 4)
    if ($strongCount -eq 0 -and $medCount -eq 0 -and -not $ShowWeak -and -not $clusterLead) { return }
    if ($hot.Count -eq 0) { $hot = $hints; $hints = @() }

    # Severity policy: complete client signatures are HIGH; a single limited
    # module is LOW; stronger individual modules are MEDIUM; multiple independent
    # strong signals can raise a result. Names are only leads, not proof.
    $evidenceText = ([string]$Name + ' ' + ($Terms -join ' '))
    $fullClientRegex = '(?i)(^|[^a-z0-9])(wurst(client)?|liquidbounce( nextgen)?|meteor(client)?|doomsday(client)?|prestige(client)?|vape( v?[34]| lite|client)?|raven( b\+{1,2}|client)?|sigma( client|\s*5(\.0)?)?|rise(client)?|novoline(client)?|tenacity(client)?|astolfo(client)?|impact(client)?|jigsaw(client)?|bleachhack|aristois|rusherhack|future(client)?|inertia(client)?|wexside|huzuni|fdp(client)?|thunderhack|whiteout(client)?|manthe(client)?|aimwhere(client)?|pulsive(client)?|entropy(client)?|drip(client)?|exhibition(client)?)([^a-z0-9]|$)'
    $isFullClient = ($evidenceText -match $fullClientRegex)
    $singleLightModule = ($strongCount -eq 1 -and (($Terms -join ' ') -match '(?i)\b(Freecam|FreeCamera|FullBright|Fullbright)\b'))

    if ($isFullClient)                         { $label = 'HIGH' }
    elseif ($strongCount -ge 2 -or $score -ge 8) { $label = 'HIGH' }
    elseif ($singleLightModule)                 { $label = 'LOW' }
    elseif ($strongCount -eq 1 -or $medCount -ge 1) { $label = 'MEDIUM' }
    elseif ($clusterLead)                       { $label = 'MEDIUM' }
    else                                        { $label = 'LOW' }

    # A lone string found inside a large binary is weaker than a filename/signature hit.
    if ($Big -and -not $NameHit -and -not $isFullClient -and $strongCount -le 1 -and $label -eq 'MEDIUM') { $label = 'LOW' }

    $stamp = ''
    if ($Modified) { try { $stamp = ([datetime]$Modified).ToString('yyyy-MM-dd HH:mm') } catch { } }

    $rows.Add([pscustomobject]@{
        Severity = $label
        Score    = $score
        Source   = $Source
        Name     = $Name
        Matches  = ($hot -join ', ')
        Hints    = ($hints -join ', ')
        Modified = $stamp
        Location = $Location
    })
}

# Fast check: does the file carry an embedded signer certificate of a well-known publisher?
# (reads the certificate only - no slow online validation)
function Test-Trusted {
    param([string]$FilePath)
    try {
        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate]::CreateFromSignedFile($FilePath)
        $subject = [string]$cert.Subject
        foreach ($p in $trustedPublishers) { if ($subject -like "*$p*") { return $true } }
    } catch { }
    return $false
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
$started = Get-Date

# stay polite: run below normal priority so the PC does not lag while scanning
try { [System.Diagnostics.Process]::GetCurrentProcess().PriorityClass = 'BelowNormal' } catch { }

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

$up = $env:USERPROFILE
# every root is "depth|folder"  (depth = how many folder levels to go down)
if ($Path) {
    $rootSpecs = @($Path | ForEach-Object { '12|' + $_ })
    $modeName = 'Custom'
} elseif ($Mode -eq 'Full') {
    $rootSpecs = @([IO.DriveInfo]::GetDrives() |
                   Where-Object { $_.IsReady -and ($_.DriveType -eq 'Fixed' -or $_.DriveType -eq 'Removable') } |
                   ForEach-Object { '12|' + $_.RootDirectory.FullName })
    $modeName = 'Full'
} else {
    $rootSpecs = @(
        ('5|' + (Join-Path $up 'Downloads')),
        ('12|' + (Join-Path $env:APPDATA 'Microsoft\Windows\Recent')),
        ('12|' + (Join-Path $env:SystemRoot 'Prefetch')),
        ('5|' + (Join-Path $env:LOCALAPPDATA 'Temp')),
        ('4|' + (Join-Path $env:APPDATA 'Badlion Client')),
        ('4|' + (Join-Path $env:APPDATA 'LunarClient')),
        ('5|' + (Join-Path $up 'Desktop')),
        ('4|' + (Join-Path $up 'Documents')),
        ('4|' + (Join-Path $up 'curseforge')),
        ('8|' + (Join-Path $env:APPDATA '.minecraft')),
        ('8|' + (Join-Path $up '.minecraft')),
        ('2|' + (Join-Path $env:LOCALAPPDATA 'Packages')), 
        ('5|' + (Join-Path $env:APPDATA 'PrismLauncher')),
        ('5|' + (Join-Path $env:APPDATA 'MultiMC')),
        ('5|' + (Join-Path $env:APPDATA 'ModrinthApp')),
        ('5|' + (Join-Path $env:APPDATA 'com.modrinth.theseus')),
        ('4|' + $env:TEMP),
        ('8|' + (Join-Path $env:LOCALAPPDATA 'Temp')),
        ('4|' + (Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup')),
        ('4|' + (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Startup')),
        ('3|' + (Join-Path $env:PUBLIC 'Downloads')),
        ('3|' + (Join-Path $env:SystemDrive '$Recycle.Bin'))
    )
    $modeName = 'Quick'
}

# folders that never contain what we are looking for (matched by folder name)
$skipList = @(
    'node_modules', '.git', '__pycache__', 'windows', 'winsxs', 'windowsapps',
    'system volume information', 'assets', 'runtime', 'logs', 'crash-reports', 'saves', 'natives',
    'screenshots', 'cache', 'code cache', 'gpucache', 'indexeddb',
    'local storage', 'service worker', 'discord', 'whatsapp', 'telegram desktop', 'spotify', 'slack',
    'zoom', 'teams', 'microsoft', 'google', 'mozilla', 'opera software', 'brave-browser', 'nvidia',
    'nvidia corporation', 'adobe', 'steam', 'steamapps', 'epic games', 'tlauncher', '.tlauncher',
    'jetbrains', 'code', 'obs-studio', 'npm', 'python', 'dotnet', 'nuget'
)
# Targeted archives use bounded class-first scanning; library archives remain excluded from class-content scans in Quick mode.

$maxBytes = [int64]$MaxSizeMB * 1MB

Write-Host "    mode: $modeName   admin: $isAdmin   signatures: $($allTerms.Count)   deep: $([bool]$Deep)" -ForegroundColor DarkGray
if (-not $isAdmin) {
    Write-Host '    tip: run as Administrator to also read Prefetch (past program runs).' -ForegroundColor Yellow
}
Write-Host ''

# ---------------------------------------------------------------------------
# 6) Files: fast index (compiled code), then parallel scan
# ---------------------------------------------------------------------------
$scanned = 0
# Hard budget: indexing is limited to ~7 seconds, total file scan to ~26 seconds.
[SigCore]::IndexTimedOut = $false
[SigCore]::ScanTimedOut = $false
[SigCore]::ProcessedFiles = 0
[SigCore]::IndexDeadlineUtcTicks = [DateTime]::UtcNow.AddSeconds(7).Ticks
[SigCore]::ScanDeadlineUtcTicks = [DateTime]::UtcNow.AddSeconds(26).Ticks
Show-Hud 'INDEX' 'listing files (7s budget)...'
$indexLines = [SigCore]::Index([string[]]$rootSpecs, [string[]]$skipList,
                               [string[]]@('.jar', '.zip', '.mrpack', '.litemod', '.class', '.java', '.kt', '.kts', '.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.py', '.json', '.toml', '.cfg', '.conf', '.properties', '.txt', '.fsh', '.vsh', '.glsl', '.frag', '.vert', '.mcmeta', '.mixins.json'), $maxBytes, [int64]200MB, 5000, 10000)

$pathList = New-Object 'System.Collections.Generic.List[string]'
$sizeOf = @{}
$tickOf = @{}
foreach ($ln in $indexLines) {
    $c = $ln.Split("`t")
    $pathList.Add($c[0])
    $sizeOf[$c[0]] = [int64]$c[1]
    $tickOf[$c[0]] = [int64]$c[2]
}

$total = $pathList.Count
$scanStart = Get-Date
$chunkSize = 64

for ($i = 0; $i -lt $total -and -not [SigCore]::ScanTimedOut; $i += $chunkSize) {
    $n     = [math]::Min($chunkSize, $total - $i)
    $paths = $pathList.GetRange($i, $n).ToArray()

    $found = @{}
    foreach ($line in [SigCore]::ScanMany($paths)) {
        $cols = $line -split "`t"
        $nh = @(); if ($cols.Count -gt 1 -and $cols[1]) { $nh = @($cols[1] -split ',') }
        $ch = @(); if ($cols.Count -gt 2 -and $cols[2]) { $ch = @($cols[2] -split ',') }
        $found[$cols[0]] = @{ Name = $nh; Content = $ch }
    }

    # generic client names in file names (Vape V4.exe, Sigma Client.jar ...)
    foreach ($pth in $paths) {
        $baseName = [IO.Path]::GetFileName($pth)
        $mm = $nameRegex.Match($baseName)
        $knownClient = [regex]::Match($baseName, '(?i)(wurst|liquidbounce|meteor|doomsday|prestige|vape|raven|sigma|rise|novoline|tenacity|astolfo|impact|jigsaw|bleachhack|aristois|rusherhack|future|inertia|wexside|huzuni|fdp|thunderhack|whiteout|manthe|aimwhere|pulsive|entropy|drip|exhibition|x.?ray|free.?cam|crystal.?aura|auto.?totem|trigger.?bot|kill.?aura|aim.?assist|scaffold|flight)')
        if ($mm.Success -or $knownClient.Success) {
            $matchedName = if ($mm.Success) { $mm.Groups[2].Value } else { $knownClient.Groups[1].Value }
            $term = '{0} (file name)' -f $matchedName
            $db[$term] = 3
            if (-not $found.ContainsKey($pth)) { $found[$pth] = @{ Name = @(); Content = @() } }
            # filename hits are useful even when the file has no readable strings
            if ($found[$pth].Name.Count -eq 0) { $found[$pth].Name += $term }
        }
    }

    foreach ($path in @($found.Keys)) {
        $name = [IO.Path]::GetFileName($path)
        $e = $found[$path]
        $hasName = ($e.Name.Count -gt 0)

        if (-not $hasName) {
            if ($name -match $trustedNameRegex) { continue }
            $x = [IO.Path]::GetExtension($path).ToLowerInvariant()
            if (($x -eq '.exe' -or $x -eq '.dll') -and (Test-Trusted -FilePath $path)) { continue }
        }

        $all = New-Object System.Collections.Generic.List[string]
        foreach ($h in @($e.Name) + @($e.Content)) { if ($h -and -not $all.Contains($h)) { $all.Add($h) } }
        $when = New-Object System.DateTime ([int64]$tickOf[$path])
        Add-Row -Source 'File' -Name $name -Location $path -Terms $all.ToArray() -Modified $when -NameHit $hasName -Big ($sizeOf[$path] -gt 20MB)
    }

    $scanned = [SigCore]::ProcessedFiles
    $pct  = [math]::Min(1, $scanned / [math]::Max(1, $total))
    $secs = ((Get-Date) - $scanStart).TotalSeconds
    $etaS = 0
    if ($scanned -gt 0) { $etaS = $secs * ($total - $scanned) / $scanned }
    $eta  = '  ETA {0:mm\:ss}' -f [timespan]::FromSeconds($etaS)
    Show-Hud 'SCAN' ("{0}/{1}  {2}" -f $scanned, $total, [IO.Path]::GetFileName($paths[$n - 1])) $pct $eta
}

# ---------------------------------------------------------------------------
# 7) Running processes
# ---------------------------------------------------------------------------
Show-Hud 'PROCS' 'running processes'
foreach ($p in Get-Process) {
    if ([DateTime]::UtcNow.Ticks -ge [SigCore]::ScanDeadlineUtcTicks) { [SigCore]::ScanTimedOut = $true; break }
    $hit = [SigCore]::ScanText("$($p.ProcessName) $($p.MainWindowTitle)")
    if ($hit.Count -gt 0) {
        Add-Row -Source 'Process' -Name $p.ProcessName -Location ("PID $($p.Id) | $($p.MainWindowTitle)") -Terms $hit -Modified $null -NameHit $true
    }
}

# ---------------------------------------------------------------------------
# 8) Traces of past execution
# ---------------------------------------------------------------------------
Show-Hud 'TRACES' 'prefetch + recent'
$traceSources = @(
    @{ Label = 'Prefetch'; Dir = (Join-Path $env:SystemRoot 'Prefetch');                    Pattern = '*.pf' },
    @{ Label = 'Recent';   Dir = (Join-Path $env:APPDATA 'Microsoft\Windows\Recent');       Pattern = '*.lnk' }
)
foreach ($src in $traceSources) {
    if ([DateTime]::UtcNow.Ticks -ge [SigCore]::ScanDeadlineUtcTicks) { [SigCore]::ScanTimedOut = $true; break }
    if (-not (Test-Path -LiteralPath $src.Dir)) { continue }
    try {
        foreach ($full in [IO.Directory]::EnumerateFiles($src.Dir, $src.Pattern)) {
            if ([DateTime]::UtcNow.Ticks -ge [SigCore]::ScanDeadlineUtcTicks) { [SigCore]::ScanTimedOut = $true; break }
            $nm  = [IO.Path]::GetFileName($full)
            $hit = @([SigCore]::ScanText($nm))
            if ($hit.Count -eq 0) {
                $mm = $nameRegex.Match($nm)
                if ($mm.Success) {
                    $term = '{0} (file name)' -f $mm.Groups[2].Value
                    $db[$term] = 3
                    $hit = @($term)
                }
            }
            if ($hit.Count -gt 0) {
                Add-Row -Source $src.Label -Name $nm -Location $full -Terms $hit -Modified ([IO.File]::GetLastWriteTime($full)) -NameHit $true
            }
        }
    } catch { }

    # For Recent shortcuts, inspect the resolved target as well as the .lnk filename.
    # Shortcut names alone are often generic; target path gives better context.
    if ($src.Label -eq 'Recent') {
        try {
            $shell = New-Object -ComObject WScript.Shell
            foreach ($full in [IO.Directory]::EnumerateFiles($src.Dir, '*.lnk')) {
                if ([DateTime]::UtcNow.Ticks -ge [SigCore]::ScanDeadlineUtcTicks) { [SigCore]::ScanTimedOut = $true; break }
                try {
                    $shortcut = $shell.CreateShortcut($full)
                    $targetText = [string]$shortcut.TargetPath + ' ' + [string]$shortcut.Arguments
                    if ([string]::IsNullOrWhiteSpace($targetText)) { continue }
                    $targetHits = @([SigCore]::ScanText($targetText))
                    if ($targetHits.Count -gt 0) {
                        Add-Row -Source 'Recent Target' -Name ([IO.Path]::GetFileName($full)) `
                            -Location ($full + ' -> ' + $targetText) -Terms $targetHits `
                            -Modified ([IO.File]::GetLastWriteTime($full)) -NameHit $false
                    }
                } catch { }
            }
            [void][Runtime.InteropServices.Marshal]::ReleaseComObject($shell)
        } catch { }
    }

    # Prefetch files can retain the executable name/path after the original file is gone.
    # Read only small .pf traces and inspect ASCII/UTF-16 strings; this is evidence of
    # execution history, never proof that a cheat was used in-game.
    if ($src.Label -eq 'Prefetch') {
        try {
            foreach ($full in [IO.Directory]::EnumerateFiles($src.Dir, '*.pf')) {
                if ([DateTime]::UtcNow.Ticks -ge [SigCore]::ScanDeadlineUtcTicks) { [SigCore]::ScanTimedOut = $true; break }
                try {
                    $fi = New-Object IO.FileInfo($full)
                    if ($fi.Length -le 0 -or $fi.Length -gt 8MB) { continue }
                    $bytes = [IO.File]::ReadAllBytes($full)
                    $ascii = [Text.Encoding]::ASCII.GetString($bytes)
                    $unicode = [Text.Encoding]::Unicode.GetString($bytes)
                    $traceText = [IO.Path]::GetFileNameWithoutExtension($full) + ' ' + $ascii + ' ' + $unicode
                    $traceHits = @([SigCore]::ScanText($traceText))
                    if ($traceHits.Count -gt 0) {
                        Add-Row -Source 'Prefetch Content' -Name ([IO.Path]::GetFileName($full)) `
                            -Location $full -Terms $traceHits -Modified $fi.LastWriteTime -NameHit $true
                    }
                } catch { }
            }
        } catch { }
    }
}

# ---------------------------------------------------------------------------
# 9) Report  (order: LOW -> MEDIUM -> HIGH, the worst stays at the bottom)
# ---------------------------------------------------------------------------
$elapsed = (Get-Date) - $started
$cw = 100
try { $cw = $Host.UI.RawUI.WindowSize.Width } catch { }
if (-not $cw) { $cw = 100 }
Write-Host ("`r" + (' ' * ($cw - 2)) + "`r") -NoNewline

$order  = @{ 'LOW' = 0; 'MEDIUM' = 1; 'HIGH' = 2 }
$sorted = @($rows | Sort-Object @{ Expression = { $order[$_.Severity] } }, Score, Name)
$high = @($sorted | Where-Object { $_.Severity -eq 'HIGH' }).Count
$med  = @($sorted | Where-Object { $_.Severity -eq 'MEDIUM' }).Count
$low  = @($sorted | Where-Object { $_.Severity -eq 'LOW' }).Count

$sections = @(
    @{ Label = 'LOW';    Color = 'Green' },
    @{ Label = 'MEDIUM'; Color = 'Yellow' },
    @{ Label = 'HIGH';   Color = 'Red' }
)
foreach ($sec in $sections) {
    $items = @($sorted | Where-Object { $_.Severity -eq $sec.Label })
    if ($items.Count -eq 0) { continue }
    Write-SectionHeader -Label $sec.Label -Count $items.Count -Color $sec.Color
    foreach ($item in $items) { Write-Card -Row $item }
}

# ---- result panel ----
$full   = [string][char]0x2588
$empty  = [string][char]0x2591
$bar    = [string][char]0x2501
$points = ($high * 6) + ($med * 3) + $low
$cells  = [math]::Min(24, $points)
$meter  = ($full * $cells) + ($empty * (24 - $cells))

if ($high -gt 0)    { $tColor = 'Red';    $verdict = 'SUSPICIOUS - cheat signatures found' }
elseif ($med -gt 0) { $tColor = 'Yellow'; $verdict = 'REVIEW NEEDED - possible cheat traces' }
elseif ($low -gt 0) { $tColor = 'Green';  $verdict = 'PROBABLY CLEAN - minor hints only' }
elseif ([SigCore]::IndexTimedOut -or [SigCore]::ScanTimedOut) { $tColor = 'Yellow'; $verdict = 'INCOMPLETE - time budget reached; not a clean verdict' }
else                { $tColor = 'Green';  $verdict = 'CLEAN - nothing suspicious found' }

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
foreach ($r in $rows) {
    foreach ($t in ($r.Matches -split ', ')) { if ($t) { $tally[$t]++ } }
}
if ($tally.Count -gt 0) {
    $topList = @($tally.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 5 |
                 ForEach-Object { '{0} x{1}' -f $_.Key, $_.Value })
    Write-Host '    top hits ' -NoNewline -ForegroundColor DarkGray
    Write-Host ($topList -join '  |  ') -ForegroundColor Red
}
Write-Host ('    scanned {0} files in {1:n0}s' -f $scanned, $elapsed.TotalSeconds) -ForegroundColor DarkGray
if ([SigCore]::IndexTimedOut -or [SigCore]::ScanTimedOut) { Write-Host '    time budget reached: scan is partial; do NOT treat no hits as proof of clean.' -ForegroundColor Yellow }

# ---- reports (CSV + HTML) ----
if ($rows.Count -gt 0) {
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $csv   = Join-Path $OutDir "MiniSS_$stamp.csv"
    $html  = Join-Path $OutDir "MiniSS_$stamp.html"

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
    } catch {
        Write-Host "    could not save reports to $OutDir" -ForegroundColor Red
    }
}

Write-Host ''
Write-Host '    a match is a lead, not proof - check the path and date first.' -ForegroundColor DarkGray
Write-Host '    Hidden files are included when accessible; .minecraft libraries, Downloads, Recent, Prefetch and Recycle Bin are checked.' -ForegroundColor DarkGray
Write-Host '    JAR class-string scan: .minecraft (except bulk libraries), mods/resourcepacks/shaderpacks/modpacks, Downloads and Temp. Prefetch/Recent are traces, not proof.' -ForegroundColor DarkGray
Write-Host "    MiniSS by $Author  |  $Invite" -ForegroundColor Magenta
Write-Host ''

if (-not $NoPause) {
    Write-Host '    press Enter to exit...' -ForegroundColor DarkGray
    [void](Read-Host)
}
