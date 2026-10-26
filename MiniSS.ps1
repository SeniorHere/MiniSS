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
        @('RED = HIGH    YELLOW = MEDIUM    order: HIGH > MEDIUM', 'Gray'),
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

# Conservative signatures: generic words such as reach/flight/phase/xray are intentionally excluded.
# HIGH = distinctive client identity; MEDIUM = distinctive cheat module/client component.
$high=@'
WurstClient Wurst-Client meteordevelopment meteor-client LiquidBounceNextgen LiquidBouncePlus FDPClient BleachHack Aristois ThunderHack RusherHack FutureClient ImpactClient InertiaClient AresClient JigsawClient DoomsdayClient PrestigeClient RavenB VapeV4 VapeV3 VapeLite SigmaClient RiseClient TenacityClient NovoLineClient AstolfoClient SlinkyClient PhobosClient KonasClient SalHack KamiBlue ExhibitionClient EntropyClient DripClient WolframClient NodusClient Huzuni LambdaClient OringoClient Dortware DopiumClient Wexside CelestialClient BlackOutClient Earthhack Seppuku ExodusClient
'@ -split '\s+' | Where-Object { $_ }
$medium=@'
AutoTotem InventoryTotem InvTotem AutoCrystal CrystalAura OneHitCrystal CrystalOptimizer AnchorMacro AnchorAura AutoAnchor AutoStun StunSlam ShieldBreaker TriggerBot KillAura AimAssist AutoClicker ChestStealer AutoSteal AutoRespawn Blink Disabler InvMove MaceDMG MaceAura AutoMace NoFall NoKnockback ScaffoldWalk PacketFly SilentAim Backtrack HitSelect ElytraFly AutoDoubleHand
'@ -split '\s+' | Where-Object { $_ }
$highRx = '(?i)(wurst[- ]?client|meteordevelopment|meteor[- ]client|liquidbounce(nextgen|plus)?|fdpclient|bleachhack|aristois|thunderhack|rusherhack|futureclient|impactclient|inertiaclient|doomsdayclient|prestigeclient|ravenb|vape(v[34]|lite)|sigmaclient|riseclient|tenacityclient|astolfoclient|slinkyclient|phobosclient|konasclient|salhack|kamiblue|exhibitionclient|entropyclient|dripclient|wolframclient|nodusclient|huzuni|lambda.?client|oringo.?client|dortware|dopiumclient|wexside|celestialclient|blackoutclient|earthhack|seppuku|exodusclient)'
$mediumRx = '(?i)(autototem|inventorytotem|invtotem|autocrystal|crystalaura|onehitcrystal|crystaloptimizer|anchormacro|anchoraura|autoanchor|autostun|stunslam|shieldbreaker|triggerbot|killaura|aimassist|autoclicker|cheststealer|autosteal|autorespawn|invmove|macedmg|maceaura|automace|scaffoldwalk|packetfly|silentaim|backtrack|hitselect|elytrafly|autodoublehand)'
$script:rows=[Collections.Generic.List[object]]::new(); $script:scanned=0; $script:timedOut=$false
$script:seenPaths=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
function Add-Finding([string]$file,[string]$term,[string]$tier,[string]$source){
    if(-not $script:seenPaths.Add($file)){ 
        $old=$script:rows | Where-Object {$_.Location -eq $file} | Select-Object -First 1
        if($old -and $tier -eq 'HIGH' -and $old.Severity -ne 'HIGH'){$old.Severity='HIGH';$old.Matches=$term;$old.Source=$source}
        elseif($old -and $old.Matches -notlike "*$term*"){$old.Matches += ", $term"}
        return
    }
    $script:rows.Add([pscustomobject]@{Severity=$tier;Name=[IO.Path]::GetFileName($file);Matches=$term;Source=$source;Location=$file})
}
function Test-Text([string]$text,[string]$file,[string]$source){
    if(!$text){return}
    if($text -match $highRx){Add-Finding $file $Matches[0] 'HIGH' $source;return}
    if($text -match $mediumRx){Add-Finding $file $Matches[0] 'MEDIUM' $source}
}
function Scan-File($f){
    if((Get-Date) -ge $deadline){$script:timedOut=$true;return}
    if($f.Length -le 0 -or $f.Length -gt $maxBytes){return}
    $script:scanned++
    if($f.Extension.ToLowerInvariant() -in '.jar','.zip'){
        try{
            $z=[IO.Compression.ZipFile]::OpenRead($f.FullName)
            try{
                $budget=4MB
                foreach($e in $z.Entries){
                    if((Get-Date) -ge $deadline){$script:timedOut=$true;break}
                    if($budget -le 0){break}
                    if($e.Length -le 0 -or $e.Length -gt 1MB -or $e.FullName -notmatch '(?i)(fabric\.mod\.json|quilt\.mod\.json|mcmod\.info|mods\.toml|plugin\.yml|\.class$|\.json$|\.toml$|\.properties$|\.mf$)'){continue}
                    $st=$e.Open();$ms=[IO.MemoryStream]::new()
                    try{$buf=New-Object byte[] 8192;$left=[Math]::Min([long]$e.Length,[long]$budget);while($left -gt 0 -and (Get-Date) -lt $deadline){$n=$st.Read($buf,0,[int][Math]::Min($buf.Length,$left));if($n -le 0){break};$ms.Write($buf,0,$n);$left-=$n;$budget-=$n};$text=[Text.Encoding]::UTF8.GetString($ms.ToArray());Test-Text $text $f.FullName ("Archive entry: "+$e.FullName)}
                    finally{$st.Dispose();$ms.Dispose()}
                }
            } finally {$z.Dispose()}
        } catch {}
    } else {
        try{$bytes=[IO.File]::ReadAllBytes($f.FullName);$text=[Text.Encoding]::ASCII.GetString($bytes);Test-Text $text $f.FullName 'File content'}catch{}
    }
}
try{Add-Type -AssemblyName System.IO.Compression.FileSystem}catch{}
Show-Banner
Write-Host ("    mode: {0}   signatures: conservative   time limit: {1}s" -f $Mode,$TimeLimitSeconds) -ForegroundColor DarkGray
if($Path){$roots=$Path}else{$h=$env:USERPROFILE;$roots=@((Join-Path $env:APPDATA '.minecraft\mods'),(Join-Path $env:APPDATA '.minecraft\versions'),(Join-Path $h 'Downloads'),(Join-Path $h 'Desktop'),(Join-Path $h 'Documents'),(Join-Path $env:APPDATA 'PrismLauncher'),(Join-Path $env:APPDATA 'MultiMC'),(Join-Path $env:APPDATA 'ModrinthApp'),(Join-Path $h 'curseforge'),$env:TEMP,(Join-Path $env:LOCALAPPDATA 'Temp'),(Join-Path $env:APPDATA 'Microsoft\Windows\Recent'),(Join-Path $env:SystemDrive '$Recycle.Bin'),(Join-Path $env:SystemRoot 'Prefetch'));if($Mode -eq 'Full'){$roots+=Get-PSDrive -PSProvider FileSystem|ForEach-Object{$_.Root}}}
$exts=@('.jar','.zip','.exe','.dll','.bat','.cmd','.ps1','.json','.txt','.cfg','.toml','.properties','.class','.vbs','.js')
foreach($root in ($roots|Where-Object {$_ -and (Test-Path -LiteralPath $_)}|Select-Object -Unique)){
    if((Get-Date) -ge $deadline){$script:timedOut=$true;break}
    Write-Host ("    Scanning: {0}" -f $root) -ForegroundColor Gray
    try{Get-ChildItem -LiteralPath $root -File -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
        if((Get-Date) -ge $deadline){$script:timedOut=$true;return}
        # Fabric processedMods are generated copies; scan original mods instead to avoid noisy duplicate hits.
        if($_.FullName -match '(?i)\\\.fabric\\processedMods\\'){return}
        if($_.Extension.ToLowerInvariant() -in $exts){Scan-File $_}
    }}catch{}
    if($script:timedOut){break}
}
$order=@{HIGH=0;MEDIUM=1;LOW=2};$sorted=@($script:rows|Sort-Object @{Expression={$order[$_.Severity]}},Name)
foreach($tier in @('HIGH','MEDIUM')){
    $items=@($sorted|Where-Object {$_.Severity -eq $tier});if(!$items.Count){continue}
    $color=if($tier -eq 'HIGH'){'Red'}else{'Yellow'}
    Write-Host ("`n    ━━━ {0} ({1} files) ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -f $tier,$items.Count) -ForegroundColor $color
    foreach($r in $items){Write-Host ("    ▸ {0,-6} {1}" -f $r.Severity,$r.Name) -ForegroundColor $color;Write-Host ("      matched: {0}" -f $r.Matches) -ForegroundColor Gray;Write-Host ("      path:    {0}" -f $r.Location) -ForegroundColor DarkGray}
}
$elapsed=[int]((Get-Date)-$started).TotalSeconds;$status=if($script:timedOut){'INCOMPLETE - time limit reached'}else{'SCAN FINISHED'}
Write-Host ("`n    {0} | files checked: {1} | suspicious files: {2} | elapsed: {3}s" -f $status,$script:scanned,$script:rows.Count,$elapsed) -ForegroundColor Cyan
if(!$script:rows.Count){Write-Host '    No known client/module signatures matched. This does not prove the system is clean.' -ForegroundColor Green}
try{$out=Join-Path ([Environment]::GetFolderPath('Desktop')) 'MiniSS_Report.csv';$script:rows|Export-Csv -LiteralPath $out -NoTypeInformation -Encoding UTF8;Write-Host ("    saved: {0}" -f $out) -ForegroundColor Green}catch{}
if(!$NoPause){Read-Host 'Press Enter to close'|Out-Null}
