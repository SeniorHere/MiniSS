<# MiniSS - Mini ScreenShare Scanner | Senior design preserved #>
[CmdletBinding()]
param([ValidateSet('Quick','Full')][string]$Mode='Quick',[string[]]$Path,[switch]$NoPause,[ValidateRange(5,600)][int]$TimeLimitSeconds=30,[ValidateRange(1,100)][int]$MaxSizeMB=25)
$ErrorActionPreference='SilentlyContinue'; $Author='Senior'; $Invite='https://discord.gg/95MmttMD6'
$started=Get-Date; $deadline=$started.AddSeconds($TimeLimitSeconds); $maxBytes=[long]$MaxSizeMB*1MB
$script:rows=[Collections.Generic.List[object]]::new(); $seen=@{}; $script:scanned=0; $script:timedOut=$false
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
        @('MiniSS  //  Screenshare Scanner        v3.9.2', 'White'),
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

# Signature tiers: HIGH = distinctive client/module; MEDIUM = suspicious feature; LOW = ambiguous indicator.
$high=@'
Wurst WurstClient Wurst-Client MeteorClient Meteor-Client meteordevelopment LiquidBounce LiquidBounceNextgen LiquidBouncePlus FDPClient BleachHack Aristois ThunderHack RusherHack FutureClient ImpactClient InertiaClient AresClient JigsawClient DoomsdayClient Prestige PrestigeClient RavenB+ VapeV4 VapeV3 VapeLite SigmaClient RiseClient TenacityClient NovolineClient AstolfoClient SlinkyClient PhobosClient KonasClient SalHack KamiBlue ExhibitionClient EntropyClient DripClient WolframClient NodusClient Huzuni LambdaClient OringoClient Dortware DopiumClient Wexside CelestialClient BlackOutClient Earthhack Seppuku ExodusClient Baritone AutoTotem InventoryTotem InvTotem AutoCrystal CrystalAura OneHitCrystal CrystalOptimizer AnchorMacro AnchorAura AutoAnchor AutoStun StunSlam Stun-Slam ShieldBreaker AutoPot TriggerBot KillAura AimAssist AimBot AutoClicker Freecam FreeCamera TimerHack FastUse FastEat AutoFish AutoMine AutoTool ChestStealer AutoSteal AutoRespawn Blink Disabler InvMove MaceDMG MaceAura AutoMace NoFall AutoWTap ScaffoldWalk Scaffold AutoCrit PacketFly AntiKnockback NoKnockback XRay X-Ray Flight Reach Velocity Jesus SpeedHack Phase NoClip ChestESP PlayerESP StorageESP Tracers TargetStrafe SilentAim FastPlace FastBreak NoSlow AutoWeapon AutoSword AutoTrap HoleFiller Backtrack HitSelect ElytraFly AutoDoubleHand
'@ -split '\s+' | ? {$_}
$medium=@'
FullBright Full-Bright XrayUltimate OresOnly CaveFinder OreESP GSAutoClicker OPAutoClicker SpeedAutoClicker TinyTask ReachHack NoSlowdown Macro Injector Criticals WallHack Bhop AutoHotkey ClickGUI FreecamMod XrayTexturePack CaveFinder OreESP
'@ -split '\s+' | ? {$_}
$low=@'
C02PacketUseEntity CPacketUseEntity CPacketPlayer attackEntity sendPacket getMouseOver reachDistance timerSpeed EntityPlayerSP ClientPlayerEntity MinecraftClient org.spongepowered.asm.mixin EntityRenderer WorldRenderer KeyBinding InputUtil GLFW_KEY setVelocity findTarget targetEntity rotationYaw rotationPitch rayTrace Mixin
'@ -split '\s+' | ? {$_}
$db=@{}; foreach($x in $low){$db[$x.ToLowerInvariant()]='LOW'}; foreach($x in $medium){$db[$x.ToLowerInvariant()]='MEDIUM'}; foreach($x in $high){$db[$x.ToLowerInvariant()]='HIGH'}
function Add-Hit([string]$file,[string]$term,[string]$tier,[string]$source){$k="$file|$term";if(!$seen.ContainsKey($k)){$seen[$k]=$true;$script:rows.Add([pscustomobject]@{Severity=$tier;Name=[IO.Path]::GetFileName($file);Matches=$term;Source=$source;Location=$file;Modified=''})}}
function Test-Bytes([byte[]]$bytes,[string]$file,[string]$source){if(!$bytes -or !$bytes.Length){return};$a=[Text.Encoding]::ASCII.GetString($bytes).ToLowerInvariant();$u=[Text.Encoding]::Unicode.GetString($bytes).ToLowerInvariant();foreach($term in $db.Keys){if($a.Contains($term)-or $u.Contains($term)){Add-Hit $file $term $db[$term] $source}}}
function Scan-File($f){if((Get-Date)-ge $deadline){$script:timedOut=$true;return};if($f.Length -le 0 -or $f.Length -gt $maxBytes){return};$script:scanned++;if($f.Extension -in '.jar','.zip'){try{$z=[IO.Compression.ZipFile]::OpenRead($f.FullName);try{$budget=3MB;foreach($e in $z.Entries){if((Get-Date)-ge $deadline){$script:timedOut=$true;break};if($budget -le 0){break};if($e.Length -le 0 -or $e.Length -gt 1MB -or $e.FullName -notmatch '\.(class|json|txt|cfg|toml|properties|xml|mf)$'){continue};$st=$e.Open();$ms=[IO.MemoryStream]::new();try{$buf=New-Object byte[] 8192;$left=[Math]::Min([long]$e.Length,[long]$budget);while($left -gt 0 -and (Get-Date)-lt $deadline){$n=$st.Read($buf,0,[int][Math]::Min($buf.Length,$left));if($n -le 0){break};$ms.Write($buf,0,$n);$left-=$n;$budget-=$n};Test-Bytes $ms.ToArray() $f.FullName ("JAR: "+$e.FullName)}finally{$st.Dispose();$ms.Dispose()}}}finally{$z.Dispose()}}catch{}}else{try{Test-Bytes ([IO.File]::ReadAllBytes($f.FullName)) $f.FullName 'File content'}catch{}}}
try{Add-Type -AssemblyName System.IO.Compression.FileSystem}catch{}
Show-Banner
Write-Host ("    mode: {0}   signatures: {1}   time limit: {2}s" -f $Mode,$db.Count,$TimeLimitSeconds) -ForegroundColor DarkGray
if($Path){$roots=$Path}else{$h=$env:USERPROFILE;$roots=@((Join-Path $env:APPDATA '.minecraft'),(Join-Path $h 'Downloads'),(Join-Path $h 'Desktop'),(Join-Path $h 'Documents'),(Join-Path $env:APPDATA 'PrismLauncher'),(Join-Path $env:APPDATA 'MultiMC'),(Join-Path $env:APPDATA 'ModrinthApp'),(Join-Path $h 'curseforge'),$env:TEMP,(Join-Path $env:LOCALAPPDATA 'Temp'),(Join-Path $env:APPDATA 'Microsoft\Windows\Recent'),(Join-Path $env:SystemDrive '$Recycle.Bin'),(Join-Path $env:SystemRoot 'Prefetch'));if($Mode -eq 'Full'){$roots+=Get-PSDrive -PSProvider FileSystem|%{$_.Root}}}
$exts=@('.jar','.zip','.exe','.dll','.bat','.cmd','.ps1','.json','.txt','.cfg','.toml','.properties','.class','.vbs','.js')
foreach($root in ($roots|?{$_ -and (Test-Path -LiteralPath $_)}|Select-Object -Unique)){if((Get-Date)-ge $deadline){$script:timedOut=$true;break};Write-Host ("    Scanning: {0}" -f $root) -ForegroundColor Gray;try{Get-ChildItem -LiteralPath $root -File -Recurse -Force -ErrorAction SilentlyContinue|%{if((Get-Date)-ge $deadline){$script:timedOut=$true;return};if($_.Extension.ToLowerInvariant() -in $exts){Scan-File $_}}}catch{};if($script:timedOut){break}}
$order=@{LOW=0;MEDIUM=1;HIGH=2};$sorted=@($script:rows|Sort-Object @{Expression={$order[$_.Severity]}},Name)
foreach($tier in @('LOW','MEDIUM','HIGH')){$items=@($sorted|?{$_.Severity -eq $tier});if(!$items.Count){continue};$color=if($tier -eq 'HIGH'){'Red'}elseif($tier -eq 'MEDIUM'){'Yellow'}else{'Green'};Write-Host ("`n    ━━━ {0} ({1}) ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -f $tier,$items.Count) -ForegroundColor $color;foreach($r in $items){Write-Host ("    ▸ {0,-6} {1}" -f $r.Severity,$r.Name) -ForegroundColor $color;Write-Host ("      found  {0}" -f $r.Matches) -ForegroundColor Red;Write-Host ("      path   {0}" -f $r.Location) -ForegroundColor DarkGray}}
$elapsed=[int]((Get-Date)-$started).TotalSeconds;$status=if($script:timedOut){'INCOMPLETE - time limit reached'}else{'SCAN FINISHED'};Write-Host ("`n    {0} | files checked: {1} | findings: {2} | elapsed: {3}s" -f $status,$script:scanned,$script:rows.Count,$elapsed) -ForegroundColor Cyan
if(!$script:rows.Count){Write-Host '    No signatures matched in scanned files.' -ForegroundColor Yellow}
try{$out=Join-Path ([Environment]::GetFolderPath('Desktop')) 'MiniSS_Report.csv';$script:rows|Export-Csv -LiteralPath $out -NoTypeInformation -Encoding UTF8;Write-Host ("    saved: {0}" -f $out) -ForegroundColor Green}catch{}
if(!$NoPause){Read-Host 'Press Enter to close'|Out-Null}
