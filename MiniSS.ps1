<#
MiniSS - Mini ScreenShare Scanner
Compact build: prioritized paths, expanded signatures, bounded scan.
#>
[CmdletBinding()]
param(
    [ValidateSet('Quick','Full')][string]$Mode='Quick',
    [string[]]$Path,
    [ValidateRange(5,600)][int]$TimeLimitSeconds=30,
    [ValidateRange(1,100)][int]$MaxFileMB=25,
    [switch]$NoPause
)
$ErrorActionPreference='SilentlyContinue'
try {[Console]::OutputEncoding=[Text.Encoding]::UTF8} catch {}
$script:Started=Get-Date
$script:Deadline=$script:Started.AddSeconds($TimeLimitSeconds)
$script:MaxBytes=[long]$MaxFileMB*1MB
$script:Scanned=0; $script:TimedOut=$false
$script:Findings=[Collections.Generic.List[object]]::new()
$script:Seen=@{}

Write-Host ''; Write-Host '  MiniSS - Mini ScreenShare Scanner' -ForegroundColor Cyan
Write-Host '  Minecraft client / module signature scan' -ForegroundColor DarkGray
Write-Host ("  Mode: {0} | Time limit: {1}s" -f $Mode,$TimeLimitSeconds) -ForegroundColor DarkGray
Write-Host ''

# HIGH: recognizable client/module names. MEDIUM/LOW require manual review.
$high=@'
Wurst WurstClient MeteorClient Meteor Client meteordevelopment LiquidBounce LiquidBounceNextgen LiquidBounce Nextgen FDPClient FDP Client BleachHack Aristois ThunderHack RusherHack FutureClient Future Client ImpactClient Impact Client InertiaClient Inertia Client AresClient Ares Client JigsawClient Jigsaw Client DoomsdayClient Doomsday Client Prestige RavenB+ Raven B+ VapeV4 Vape V4 VapeLite Vape Lite SigmaClient Sigma Client RiseClient Rise Client TenacityClient Tenacity Client NovolineClient Novoline Client AstolfoClient Astolfo Client SlinkyClient Slinky Client PhobosClient KonasClient SalHack KamiBlue ExhibitionClient EntropyClient DripClient WolframClient NodusClient Huzuni LambdaClient OringoClient Dortware DopiumClient Wexside CelestialClient BlackOutClient BlackOut Earthhack EarthHack Seppuku Kami ExodusClient LiquidBouncePlus LiquidBounce+ LiquidBounce Nextgen Baritone AutoTotem InventoryTotem AutoCrystal CrystalAura OneHitCrystal CrystalOptimizer AnchorMacro AnchorAura AutoAnchor AutoStun StunSlam ShieldBreaker AutoPot TriggerBot KillAura AimAssist AimBot AutoClicker Freecam FreeCamera AntiAim NoRender TimerHack FastUse FastEat AutoFish AutoMine AutoTool ChestStealer AutoSteal AutoRespawn Blink Disabler InvMove MaceDMG MaceAura AutoMace NoFall AutoWTap ScaffoldWalk Scaffold AutoCrit PacketFly AntiKnockback NoKnockback XRay X-Ray Flight Reach Velocity Jesus SpeedHack Phase NoClip ChestESP PlayerESP StorageESP Tracers TargetStrafe SilentAim FastPlace FastBreak NoSlow InventoryMove AutoArmor Surround Backtrack AutoTrap HoleFiller SelfFill ElytraFly ClickGUI HitSelect AutoWeapon AutoSword AutoQueue AutoRequeue AutoGG NoRotate
'@ -split '\s+' | Where-Object {$_}
$medium=@'
FullBright Full-Bright XrayUltimate OresOnly CaveFinder OreESP GSAutoClicker OPAutoClicker SpeedAutoClicker TinyTask ReachHack NoSlowdown Macro Injector Criticals WallHack Bhop AutoHotkey
'@ -split '\s+' | Where-Object {$_}
$low=@'
C02PacketUseEntity CPacketUseEntity CPacketPlayer attackEntity sendPacket getMouseOver reachDistance timerSpeed EntityPlayerSP ClientPlayerEntity MinecraftClient org.spongepowered.asm.mixin EntityRenderer WorldRenderer KeyBinding InputUtil GLFW_KEY setVelocity findTarget targetEntity rotationYaw rotationPitch rayTrace Mixin
'@ -split '\s+' | Where-Object {$_}
$script:Signatures=@{}
foreach($s in $high){$script:Signatures[$s.ToLowerInvariant()]='HIGH'}
foreach($s in $medium){$k=$s.ToLowerInvariant();if(!$script:Signatures.ContainsKey($k)){$script:Signatures[$k]='MEDIUM'}}
foreach($s in $low){$k=$s.ToLowerInvariant();if(!$script:Signatures.ContainsKey($k)){$script:Signatures[$k]='LOW'}}

function Add-Finding([string]$File,[string]$Match,[string]$Severity,[string]$Source){
    $key="$File|$Match"
    if(!$script:Seen.ContainsKey($key)){
        $script:Seen[$key]=$true
        $script:Findings.Add([pscustomobject]@{Severity=$Severity;Match=$Match;Source=$Source;File=$File})
    }
}
function Scan-Bytes([byte[]]$Bytes,[string]$File,[string]$Source){
    if(!$Bytes -or !$Bytes.Length){return}
    $a=[Text.Encoding]::ASCII.GetString($Bytes).ToLowerInvariant()
    $u=[Text.Encoding]::Unicode.GetString($Bytes).ToLowerInvariant()
    foreach($term in $script:Signatures.Keys){
        if($a.Contains($term) -or $u.Contains($term)){
            Add-Finding $File $term $script:Signatures[$term] $Source
        }
    }
}
function Scan-File([IO.FileInfo]$File){
    if((Get-Date) -ge $script:Deadline){$script:TimedOut=$true;return}
    if($File.Length -le 0 -or $File.Length -gt $script:MaxBytes){return}
    $script:Scanned++
    if($File.Extension -in @('.jar','.zip')){
        try{
            $z=[IO.Compression.ZipFile]::OpenRead($File.FullName)
            try{
                $budget=3MB
                foreach($e in $z.Entries){
                    if((Get-Date) -ge $script:Deadline){$script:TimedOut=$true;break}
                    if($budget -le 0){break}
                    if($e.Length -le 0 -or $e.Length -gt 1MB -or $e.FullName -notmatch '\.(class|json|txt|cfg|toml|properties|xml|mf)$'){continue}
                    $st=$null;$ms=$null
                    try{
                        $st=$e.Open();$ms=[IO.MemoryStream]::new();$buf=New-Object byte[] 8192
                        $left=[Math]::Min([long]$e.Length,[long]$budget)
                        while($left -gt 0 -and (Get-Date) -lt $script:Deadline){
                            $n=$st.Read($buf,0,[int][Math]::Min($buf.Length,$left));if($n -le 0){break}
                            $ms.Write($buf,0,$n);$left-=$n;$budget-=$n
                        }
                        Scan-Bytes $ms.ToArray() $File.FullName ("Archive: "+$e.FullName)
                    }catch{}finally{if($st){$st.Dispose()};if($ms){$ms.Dispose()}}
                }
            }finally{$z.Dispose()}
        }catch{}
    }else{
        try{Scan-Bytes ([IO.File]::ReadAllBytes($File.FullName)) $File.FullName 'File content'}catch{}
    }
}
try{Add-Type -AssemblyName System.IO.Compression.FileSystem}catch{}

# Scan likely evidence locations first; Full also adds filesystem roots.
if($Path){$roots=$Path}else{
    $h=$env:USERPROFILE
    $roots=@(
        (Join-Path $env:APPDATA '.minecraft'),(Join-Path $h 'Downloads'),
        (Join-Path $h 'Desktop'),(Join-Path $h 'Documents'),
        (Join-Path $env:APPDATA 'PrismLauncher'),(Join-Path $env:APPDATA 'MultiMC'),
        (Join-Path $env:APPDATA 'ModrinthApp'),(Join-Path $h 'curseforge'),
        $env:TEMP,(Join-Path $env:LOCALAPPDATA 'Temp'),
        (Join-Path $env:APPDATA 'Microsoft\Windows\Recent'),
        (Join-Path $env:SystemDrive '$Recycle.Bin'),(Join-Path $env:SystemRoot 'Prefetch')
    )
    if($Mode -eq 'Full'){$roots+=Get-PSDrive -PSProvider FileSystem|ForEach-Object{$_.Root}}
}
$roots=@($roots|Where-Object{$_ -and (Test-Path -LiteralPath $_)}|Select-Object -Unique)
$extensions=@('.jar','.zip','.exe','.dll','.bat','.cmd','.ps1','.json','.txt','.cfg','.toml','.properties')
foreach($root in $roots){
    if((Get-Date) -ge $script:Deadline){$script:TimedOut=$true;break}
    Write-Host ("  Scanning: {0}" -f $root) -ForegroundColor Gray
    try{
        Get-ChildItem -LiteralPath $root -File -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object{
            if((Get-Date) -ge $script:Deadline){$script:TimedOut=$true;return}
            if($_.Extension.ToLowerInvariant() -in $script:extensions){Scan-File $_}
        }
    }catch{}
    if($script:TimedOut){break}
}
Write-Host ''
if($script:Findings.Count){
    $script:Findings|Sort-Object @{Expression={switch($_.Severity){'HIGH'{0}'MEDIUM'{1}default{2}}}},File|Format-Table Severity,Match,Source,File -AutoSize -Wrap
}else{Write-Host '  No signatures matched in scanned files.' -ForegroundColor Yellow}
$seconds=[int]((Get-Date)-$script:Started).TotalSeconds
$status=if($script:TimedOut){'INCOMPLETE - time limit reached'}else{'SCAN FINISHED'}
Write-Host ("`n  {0} | files checked: {1} | findings: {2} | elapsed: {3}s" -f $status,$script:Scanned,$script:Findings.Count,$seconds) -ForegroundColor $(if($script:TimedOut){'Yellow'}else{'Cyan'})
try{$report=Join-Path ([Environment]::GetFolderPath('Desktop')) 'MiniSS_Report.csv';$script:Findings|Export-Csv -LiteralPath $report -NoTypeInformation -Encoding UTF8;Write-Host ("  Report: {0}" -f $report) -ForegroundColor DarkGray}catch{}
if(!$NoPause){try{Read-Host 'Press Enter to close'|Out-Null}catch{}}
