#Requires -Version 5.1
param([switch]$Elevated)
# ==========================================================================
#   JHORFGU INTERNAL AND EXTERNAL CHECKER   (NO-ADMIN edition)  -  v2
#   v2 changes:
#     * New dark UI (chooser, live scan window, results dashboard with verdict + sortable table)
#     * Weighted evidence SCORE per detection (not just counting sources) + overall VERDICT
#     * Look-alike / hidden-character name detection (Cyrillic look-alikes, zero-width chars, full-width letters)
#     * Injector / memory-editor tools (Cheat Engine, Xenos, Extreme Injector, kdmapper, ReClass)
#     * New history sources: Jump Lists, Open/Save dialog history, PowerShell history, Start Menu + Startup folders
#     * Running process COMMAND LINES, Roblox client signature check, DLL-hijack (proxy DLL) names in the Roblox folder
#     * Stronger external-cheat check (Roblox internals names + memory APIs inside any program)
# ==========================================================================
# ================== CONFIG ==================
# ---- EASY LIST: to detect something new, just add its name (lowercase, no spaces) to one of these lists ----
# Executors that inject into Roblox ("internals"). MATRIX also covers its "New UI" and "Old UI" launchers.
$internalNames = @('matrix','synapse','scriptware','krnl','fluxus','jjsploit','wearedevs','sirhurt','celery','evon','seliware',
                   'cryptic','potassium','madium','ronix','volcano','velocity','xeno','electron','oxygenu','protosmasher',
                   'skisploit','trigon','vegax','zorara','nihon','comet','argon','swift','wave','delta','codex','hydrogen','sentinel',
                   'nezur','valyse','cosmic','volt','aurora','lunar','atlantis','anaconda',
                   'rc7','elysian','furkultra','arceusx','cubix','krampus','roexec',   # added from memory, not verified
                   'real','macsploit','redengine','fluxteam','kiwix','cocoz','insanity','nexus','ronin','aspect','pandora','incognito','eclipse')   # added in v2.2 from memory, NOT verified: delete any that cause false hits
# Executors that run beside Roblox and read/write its memory ("externals"):
$externalNames = @('matcha','solara','severe','serotonin','awp','isabella','bunni','zenith','photon','neutron',
                   'robloxcheat',                                            # any file/folder called "Roblox External", "Roblox ESP", "RBX Aimbot" ...
                   'santo','ember','nebula','vortex','phantom','specter','venom',
                   'aimbot','triggerbot','camlock','silentaim','wallhack',   # guesses from memory, not verified
                   'ragebot','spinbot','speedhack','flyhack','noclip','hitboxexpander','tapioca','hexware')   # added in v2.2, NOT verified
# Macro / AutoHotkey tools:
$macroNames    = @('visionary','ahksociety','sacredstep')
# Injectors / memory editors / driver mappers that cheats are built with (reported as "Tool"):
$toolNames     = @('cheatengine','extremeinjector','xenos','kdmapper','reclass')
$names = @($internalNames + $externalNames + $macroNames + $toolNames | Select-Object -Unique)

# Names written more than one way (regex). Used everywhere: files, folders, registry, run history.
$nameAlt = @{
  'matrix' = 'matrix|new[-_. ]?ui|old[-_. ]?ui'; 'scriptware' = 'script[-_. ]?ware'; 'jjsploit' = 'jj[-_. ]?sploit'
  'oxygenu' = 'oxygen[-_. ]?u'; 'vegax' = 'vega[-_. ]?x'; 'protosmasher' = 'proto[-_. ]?smasher'
  'ahksociety' = 'ahk[-_. ]?society'; 'sacredstep' = 'sacred[-_. ]?step'
  'visionary' = 'visionary[-_. ]*(?:ahk|macro|society|script|bot|boost|executor)|(?:ahk|macro)[-_. ]*visionary'
  'furkultra' = 'furk[-_. ]?ultra'; 'arceusx' = 'arceus[-_. ]?x'; 'roexec' = 'ro[-_. ]?exec'; 'silentaim' = 'silent[-_. ]?aim'
  'redengine' = 'red[-_. ]?engine'; 'fluxteam' = 'flux[-_. ]?team'; 'cocoz' = 'coco[-_. ]?z'; 'macsploit' = 'mac[-_. ]?sploit'; 'hitboxexpander' = 'hitbox[-_. ]?expander'; 'speedhack' = 'speed[-_. ]?hack'; 'flyhack' = 'fly[-_. ]?hack'; 'ragebot' = 'rage[-_. ]?bot'; 'spinbot' = 'spin[-_. ]?bot'
  'cheatengine' = 'cheat[-_. ]?engine'; 'extremeinjector' = 'extreme[-_. ]?injector'
  'robloxcheat' = '(?:roblox|rbx|blox)[-_. ]?(?:external|aimbot|esp|cheat|hack|hax|exploit)s?|(?:external|aimbot|esp)[-_. ]?(?:for[-_. ]?)?(?:roblox|rbx)' }
# The same spellings written out (Windows run history stores them ROT13-scrambled, so they are listed too)
$aliasWords = @('new ui','new-ui','new_ui','new.ui','old ui','old-ui','old_ui','old.ui','newui','oldui','script-ware','script ware','script_ware',
                'jj-sploit','jj sploit','jj_sploit','oxygen u','oxygen-u','vega x','vega-x','proto smasher','proto-smasher',
                'ahk society','ahk-society','ahk_society','visionary ahk','visionary-ahk','visionary_ahk','visionary macro','furk ultra','furk-ultra','arceus x','arceus-x','ro exec','ro-exec','silent aim','silent-aim','sacred step','sacred-step','sacred_step',
                'red engine','red-engine','flux team','flux-team','coco z','coco-z','mac sploit','mac-sploit','hitbox expander','speed hack','fly hack','rage bot','spin bot','cheat engine','cheat-engine','cheat_engine','extreme injector','extreme-injector','extreme_injector',
                'roblox external','roblox-external','roblox_external','roblox aimbot','roblox esp','roblox cheat','roblox hack','roblox hax','rbx external','rbx aimbot','rbx esp','rbx cheat','rbx hax')
$nameDisplay = @{ 'matrix' = 'MATRIX (incl. New UI / Old UI)'; 'scriptware' = 'SCRIPT-WARE'; 'jjsploit' = 'JJSPLOIT'; 'wearedevs' = 'WEAREDEVS (JJSploit API)'
                  'oxygenu' = 'OXYGEN U'; 'vegax' = 'VEGA X'; 'protosmasher' = 'PROTOSMASHER'; 'ahksociety' = 'AHKSOCIETY (Visionary AHK macro)'; 'sacredstep' = 'SACREDSTEP'; 'visionary' = 'VISIONARY (AHK macro)'; 'furkultra' = 'FURK ULTRA'; 'arceusx' = 'ARCEUS X'; 'roexec' = 'RO-EXEC'; 'silentaim' = 'SILENT AIM'; 'robloxcheat' = 'ROBLOX CHEAT / EXTERNAL (by file name)'
                  'redengine' = 'RED ENGINE'; 'fluxteam' = 'FLUX TEAM'; 'cocoz' = 'COCO Z'; 'macsploit' = 'MACSPLOIT'; 'hitboxexpander' = 'HITBOX EXPANDER'; 'speedhack' = 'SPEED HACK'; 'flyhack' = 'FLY HACK'; 'ragebot' = 'RAGEBOT'; 'spinbot' = 'SPINBOT'
                  'cheatengine' = 'CHEAT ENGINE (memory editor)'; 'extremeinjector' = 'EXTREME INJECTOR (DLL injector)'; 'xenos' = 'XENOS (DLL injector)'; 'kdmapper' = 'KDMAPPER (driver mapper)'; 'reclass' = 'RECLASS (memory tool)' }
# Names that are also ordinary words: only reported when the program really is on the PC / running, or seen in 2+ places
$genericNames = @('potassium','celery','cryptic','synapse','matrix','evon','ronix','volcano','velocity','electron','comet','argon','swift','wave',
                  'delta','codex','hydrogen','sentinel','nihon','severe','serotonin','awp','isabella','zenith','photon','neutron',
                  'nezur','valyse','cosmic','volt','aurora','lunar','atlantis','anaconda','santo','ember','nebula','vortex','phantom','specter','venom','rc7','elysian','cubix','krampus','real','nexus','ronin','aspect','pandora','incognito','eclipse','insanity','noclip','tapioca')
# Very common words (Electron.exe is in every Electron app, Wave/Delta are normal programs...): reported only when seen in 2+ different places
$weakNames = @('electron','wave','delta','swift','argon','comet','zenith','photon','neutron','sentinel','nihon','codex','hydrogen','awp','isabella','severe','serotonin','cosmic','volt','aurora','lunar','atlantis','anaconda','santo','ember','nebula','vortex','phantom','specter','venom','real','nexus','ronin','aspect','pandora','incognito','eclipse','insanity','noclip')
# Exact file fingerprints: SHA256 -> name. Works even if the file is renamed. (add: 'sha256-in-lowercase' = 'name')
$knownHashes = @{
  '721ca1f0a079c7f09c59251885f310e77fe2cb0abeb56e821a6cea0c7315e76e' = 'matrix'       # oldui.exe (Matrix launcher)
  '8445452e08d6bf20d9025185ce58791f0f580c543cb3feb19f7f3a71a9138877' = 'sacredstep'   # SacredStep.exe
}
# Exact program file names that are searched for directly (name -> file names)
$knownExe = @{ 'matcha' = @('matcha.exe'); 'sacredstep' = @('sacredstep.exe'); 'cheatengine' = @('cheatengine-x86_64.exe','cheatengine-x86_64-SSE4-AVX2.exe') }
# Programs that edit Roblox FFlags (not cheats): never reported by the memory-access check
$flagToolRx = '(?i)fflag|fastflag|flagger|flagtool|flag.?inject|flag.?editor|bloxstrap|fishstrap|voidstrap|lunastrap'
# Ignore known legit software that shares a name
$exclude = '(?i)razer|blox?strap|fishstrap|voidstrap|lunastrap|azure.?synapse|synapse.?analytics|matrix-synapse|matcha.?(tea|latte|powder|recipe|whisk)|\\python\d*\\|\\site-packages\\|\\node_modules\\|\\anaconda\d*\\|\\miniconda\d*\\|\\winsxs\\|\\servicing\\|\\driverstore\\|\\windows\\system32\\|\\windows\\syswow64\\|jhorfgu|scan_report_'
# A VALID signature from one of these publishers means the file is legit and is ignored
$trustedPub = 'Microsoft|Razer|Google|Apple|Intel|NVIDIA|AMD|Adobe|Valve|Mozilla|Oracle|Logitech|Corsair|Realtek|Dell|HP Inc|Lenovo|ASUS|Python Software'
# Evidence weights (points). A detection's SCORE = strongest source + 60% of the others + 8 per extra source (max 3) + 10 if it exists now + 15 if the name uses look-alike characters.
#   score >= 65 = HIGH, >= 35 = MEDIUM, below = LOW
$srcWeight = @{
  'Known file (hash match)' = 100; 'Matrix file set' = 90; 'Loaded inside Roblox (injected)' = 90; 'Known text inside file' = 80
  'Memory access to Roblox' = 80; 'Built to control Roblox from outside' = 75; 'Built-in file name (survives renaming)' = 70
  'Executor API strings inside file' = 70; 'Running AutoHotkey macro that targets Roblox' = 60; 'Transparent overlay window' = 55
  'AutoHotkey macro that targets Roblox' = 50; 'Running process' = 45; 'Executor folder layout (autoexec)' = 45; 'Defender detection history' = 45
  'Exploit script (Lua)' = 40; 'File on disk' = 35; 'Install folder' = 30; 'Downloaded from website' = 30; 'Running process (command line)' = 30; 'Startup folder' = 30
  'Defender exclusion' = 25; 'Defender exclusion (history)' = 20; 'Installed program' = 25; 'Startup entry' = 25; 'UserAssist' = 25; 'UserAssist (another user)' = 20; 'Prefetch' = 25
  'Service' = 20; 'Scheduled task' = 20; 'BAM' = 20; 'Start Menu shortcut' = 20
  'Windows execution cache (ShimCache)' = 15; 'Windows run history' = 15; 'Recent shortcut' = 15; 'Recycle Bin' = 15; 'Jump List' = 15
  'File name looks like an executor' = 30; 'Inside archive' = 35; 'Executor folder layout (Monaco editor)' = 40; 'Dialog history (Open/Save)' = 15; 'PowerShell history' = 15; 'Registry key' = 10 }
# Evidence CATEGORIES. A detection is judged by how many independent KINDS of evidence agree, not by how many records exist.
#   Content = what the file itself contains | Presence = it is there / running by name | Behavior = what it does to Roblox
#   History = Windows remembers it ran | Persistence = it keeps itself installed | Network = where it came from
$srcCat = @{
  'Known file (hash match)'='Content'; 'Matrix file set'='Content'; 'Known text inside file'='Content'; 'Built-in file name (survives renaming)'='Content'
  'Executor API strings inside file'='Content'; 'Built to control Roblox from outside'='Content'; 'Exploit script (Lua)'='Content'
  'AutoHotkey macro that targets Roblox'='Content'; 'Executor folder layout (Monaco editor)'='Content'; 'Executor folder layout (autoexec)'='Content'
  'File on disk'='Presence'; 'Install folder'='Presence'; 'Running process'='Presence'; 'Running process (command line)'='Presence'
  'File name looks like an executor'='Presence'; 'Inside archive'='Presence'; 'Start Menu shortcut'='Presence'; 'Installed program'='Presence'
  'Memory access to Roblox'='Behavior'; 'Transparent overlay window'='Behavior'; 'Loaded inside Roblox (injected)'='Behavior'; 'Running AutoHotkey macro that targets Roblox'='Behavior'
  'Startup entry'='Persistence'; 'Startup folder'='Persistence'; 'Service'='Persistence'; 'Scheduled task'='Persistence'; 'Registry key'='Persistence'; 'Defender exclusion'='Persistence'
  'Downloaded from website'='Network' }
$scanSeconds  = 8          # file scan time cap (the scan runs in the background while the other checks run)
$budget       = 17         # hard limit for the whole scan, in seconds (the window closes within 20)
$AdminEdition = $false
# ============================================
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference    = 'SilentlyContinue'
$title = 'JHORFGU INTERNAL AND EXTERNAL CHECKER'

$isAdmin = $false
try { $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) } catch {}

# ---------- Admin edition: relaunch elevated if needed ----------
if ($AdminEdition -and -not $isAdmin) {
  if ($PSCommandPath) {
    try {
      $exe = (Get-Process -Id $PID).Path
      Start-Process -FilePath $exe -Verb RunAs -ErrorAction Stop -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$PSCommandPath`"",'-Elevated')
      exit
    } catch { Write-Host 'Admin was not granted - continuing with the checks that do not need admin.' -ForegroundColor Yellow }
  } else {
    Write-Host 'Open PowerShell as Administrator and run this file to get the admin checks.' -ForegroundColor Yellow
  }
}

# ==========================================================================
#   UI (plain Windows look)
# ==========================================================================
$script:uiOk = $true
try { Add-Type -AssemblyName System.Windows.Forms, System.Drawing; [Windows.Forms.Application]::EnableVisualStyles() } catch { $script:uiOk = $false }
$theme = $null
if ($script:uiOk) {
  $theme = @{
    Bg    = [Drawing.Color]::FromArgb(240,240,240)
    Line  = [Drawing.Color]::FromArgb(205,205,205)
    Text  = [Drawing.Color]::FromArgb(20,20,20)
    Muted = [Drawing.Color]::FromArgb(100,100,100)
    Red   = [Drawing.Color]::FromArgb(170,25,25)
    Amber = [Drawing.Color]::FromArgb(165,95,0)
    Green = [Drawing.Color]::FromArgb(20,110,45)
    Blue  = [Drawing.Color]::FromArgb(0,90,170)
  }
}
$script:prog = 0
function Load-UiLib { }
function Set-Dark($form) { }
function New-Lbl($text, $x, $y, $w, $h) {
  $l = New-Object Windows.Forms.Label
  $l.Text = $text; $l.Location = New-Object Drawing.Point($x,$y)
  if ($w) { $l.Size = New-Object Drawing.Size($w,$h) } else { $l.AutoSize = $true }
  $l.BackColor = [Drawing.Color]::Transparent
  $l
}
# white header strip with a thin line under it (the usual Windows dialog look)
function New-Banner($t1, $t2, $h) {
  $p = New-Object Windows.Forms.Panel
  $p.Dock = 'Top'; $p.Height = $h; $p.BackColor = [Drawing.Color]::White
  $a = New-Lbl $t1 14 9
  $a.Font = New-Object Drawing.Font('Segoe UI',10,[Drawing.FontStyle]::Bold)
  $b = New-Lbl $t2 15 ($h - 25)
  $b.ForeColor = $theme.Muted
  $ln = New-Object Windows.Forms.Panel
  $ln.Dock = 'Bottom'; $ln.Height = 1; $ln.BackColor = $theme.Line
  $p.Controls.AddRange(@($a, $b, $ln))
  $p
}
function New-Btn($text, $w, $h, $primary) {
  $b = New-Object Windows.Forms.Button
  $b.Text = $text; $b.Size = New-Object Drawing.Size($w,$h)
  $b.UseVisualStyleBackColor = $true
  $b
}

# ---------- Start-up window: Internal / External / Both ----------
function Show-Chooser {
  try {
    $script:choice = $null
    $f = New-Object Windows.Forms.Form
    $script:frm = $f
    $f.Text = $title
    $f.ClientSize = New-Object Drawing.Size(440,304)
    $f.StartPosition = 'CenterScreen'; $f.TopMost = $true
    $f.FormBorderStyle = 'FixedDialog'; $f.MaximizeBox = $false; $f.MinimizeBox = $false
    $f.BackColor = $theme.Bg; $f.Font = New-Object Drawing.Font('Segoe UI',9)
    $f.KeyPreview = $true
    $f.Controls.Add((New-Banner 'Scan type' "Choose what to check. $($names.Count) names are known; a scan takes up to about 20 seconds." 56))
    $script:cbtns = @()
    $opts = @(
      @{ Key='Internal'; Text="1.  Internal`r`n      This PC's disks, running programs and Windows history" },
      @{ Key='External'; Text="2.  External`r`n      USB / removable drives, plugged in now and past USB history" },
      @{ Key='Both';     Text="3.  Both  (recommended)`r`n      Everything above; takes a little longer" }
    )
    $y = 68
    foreach ($o in $opts) {
      $b = New-Btn $o.Text 408 52 $false
      $b.Location = New-Object Drawing.Point(16,$y); $b.TextAlign = 'MiddleLeft'; $b.Padding = New-Object Windows.Forms.Padding(8,0,0,0)
      $b.Tag = $o
      $b.Add_Click({ param($s,$e) $script:choice = $s.Tag.Key; $script:frm.Close() })
      $f.Controls.Add($b); $script:cbtns += $b
      $y += 58
    }
    $rbxOn = [bool](Get-Process -Name 'RobloxPlayerBeta' -ErrorAction SilentlyContinue)
    $tip = New-Lbl $(if ($rbxOn) { 'Roblox is running, so the memory, overlay and client checks will run.' } else { 'Roblox is not running. Start it first if you want the memory, overlay and client checks.' }) 16 246
    $tip.ForeColor = $(if ($rbxOn) { $theme.Green } else { $theme.Amber })
    $f.Controls.Add($tip)
    $ed = New-Lbl ($(if ($AdminEdition) { 'Admin edition' } else { 'No-admin edition' }) + $(if ($isAdmin) { ' (running as administrator)' } else { '' })) 16 276
    $ed.ForeColor = $theme.Muted
    $f.Controls.Add($ed)
    $no = New-Btn 'Cancel' 80 26 $false
    $no.Location = New-Object Drawing.Point(344,270)
    $no.Add_Click({ $script:choice = $null; $script:frm.Close() })
    $f.Controls.Add($no); $f.CancelButton = $no
    $f.Add_KeyDown({ param($s,$e)
      switch ($e.KeyCode.ToString()) {
        { $_ -in 'D1','NumPad1' } { $script:cbtns[0].PerformClick() }
        { $_ -in 'D2','NumPad2' } { $script:cbtns[1].PerformClick() }
        { $_ -in 'D3','NumPad3' } { $script:cbtns[2].PerformClick() }
      } })
    [void]$f.ShowDialog()
    if ($script:choice) { return $script:choice } else { return 'CANCEL' }
  } catch { return 'ERR' }
}

# ---------- Scan progress window ----------
$script:splash = $null; $script:splashLbl = $null; $script:splashList = $null; $script:splashCnt = $null; $script:splashTime = $null; $script:splashBar = $null
function Show-Splash {
  try {
    $f = New-Object Windows.Forms.Form
    $f.Text = $title
    $f.FormBorderStyle = 'FixedDialog'; $f.ControlBox = $false
    $f.ClientSize = New-Object Drawing.Size(480,324)
    $f.StartPosition = 'CenterScreen'; $f.TopMost = $true
    $f.BackColor = $theme.Bg; $f.Font = New-Object Drawing.Font('Segoe UI',9)
    $f.Controls.Add((New-Banner 'Scanning' 'This window closes by itself when the scan is finished.' 56))
    $st = New-Lbl 'Starting...' 14 68 452 18
    $lb = New-Object Windows.Forms.ListBox
    $lb.Location = New-Object Drawing.Point(14,92); $lb.Size = New-Object Drawing.Size(452,140)
    $lb.Font = New-Object Drawing.Font('Consolas',9); $lb.SelectionMode = 'None'; $lb.IntegralHeight = $false
    $lb.BackColor = [Drawing.Color]::White; $lb.BorderStyle = 'FixedSingle'
    $c = New-Lbl '' 14 240 310 16
    $c.ForeColor = $theme.Muted
    $t = New-Lbl '' 326 240 140 16
    $t.ForeColor = $theme.Muted; $t.TextAlign = 'TopRight'
    $pb = New-Object Windows.Forms.ProgressBar
    $pb.Style = 'Continuous'; $pb.Minimum = 0; $pb.Maximum = 100; $pb.Value = 0
    $pb.Location = New-Object Drawing.Point(14,262); $pb.Size = New-Object Drawing.Size(452,16)
    $stop = New-Btn 'Stop and show results' 150 26 $false
    $stop.Location = New-Object Drawing.Point(316,288)
    $stop.Add_Click({ $script:cancelled = $true; $this.Text = 'Stopping...'; $this.Enabled = $false })
    $f.Controls.AddRange(@($st,$lb,$c,$t,$pb,$stop))
    $f.Show(); [Windows.Forms.Application]::DoEvents()
    $script:splash = $f; $script:splashLbl = $st; $script:splashList = $lb; $script:splashCnt = $c; $script:splashTime = $t; $script:splashBar = $pb
  } catch {}
}
function Set-Stage($t) {
  try {
    if ($script:splashList) {
      $n = $script:splashList.Items.Count
      if ($n -gt 0) { $script:splashList.Items[$n - 1] = ($script:splashList.Items[$n - 1] -replace '^\[\.\.\]', '[ok]') }
      [void]$script:splashList.Items.Add("[..] $t")
      $script:splashList.TopIndex = [math]::Max(0, $script:splashList.Items.Count - 9)
    }
    if ($script:splashLbl) { $script:splashLbl.Text = $t }
    if ($script:splashTime -and $sw) { $script:splashTime.Text = ('{0:N1} s of 20 s max' -f $sw.Elapsed.TotalSeconds) }
    if ($script:splashCnt) {
      $qs = 'QScanJ4' -as [type]; $ct = ''
      if ($qs -and [QScanJ4]::Dirs -gt 0) { $ct = ('{0:N0} folders, {1:N0} files' -f [QScanJ4]::Dirs, [QScanJ4]::Files) }
      if ($ev) { $ct += $(if ($ct) { '   |   ' } else { '' }) + "leads so far: $($ev.Count)" }
      $script:splashCnt.Text = $ct
    }
    if ($script:splashBar -and $sw) { $script:splashBar.Value = [int][math]::Min(99, ($sw.Elapsed.TotalSeconds / 20) * 100) }
    [Windows.Forms.Application]::DoEvents()
  } catch {}
}
function Close-Splash { try { if ($script:splash) { $script:splash.Close(); $script:splash.Dispose(); $script:splash = $null } } catch {} }
$mode = Show-Chooser
if ($mode -eq 'ERR') {
  Write-Host "`n$title" -ForegroundColor Cyan
  $r = Read-Host 'Type 1 = Internal, 2 = External, 3 = Both'
  $mode = switch ($r) { '1' {'Internal'} '2' {'External'} default {'Both'} }
}
if ($mode -eq 'CANCEL') { Write-Host 'Cancelled.'; exit }
$doInternal = $mode -in 'Internal','Both'
$doExternal = $mode -in 'External','Both'

$sw = [Diagnostics.Stopwatch]::StartNew()
$script:cancelled = $false
function RemainMs($cap) { if ($script:cancelled) { return 0 }; $left = ($budget - $sw.Elapsed.TotalSeconds) * 1000; [int][math]::Max(0, [math]::Min($cap, $left)) }
Show-Splash
Write-Host "`n$title  -  mode: $mode  -  $(if ($isAdmin) {'admin'} else {'no admin'})" -ForegroundColor Cyan
Write-Host 'Scanning...' -ForegroundColor DarkGray

Set-Stage 'Preparing the name patterns'
# ---------- Look-alike / hidden character normalization ----------
# Someone can rename a tool to use Cyrillic look-alike letters, zero-width spaces or full-width letters so a name search misses it.
# Every name is normalized (NFKC + look-alike map + zero-width removal) before it is compared.
$homoFrom = (([char[]](0x430,0x435,0x43E,0x440,0x441,0x445,0x443,0x456,0x455,0x458,0x4CF,0x410,0x412,0x415,0x41A,0x41C,0x41D,0x41E,0x420,0x421,0x422,0x425,0x3BF,0x39F,0x3B1,0x3BD,0x3C1,0x399,0x406,0x405,0x408)) -join '')
$homoTo   = 'aeopcxyisjlABEKMHOPCTXoOavpIISJ'
$homoMap  = @{}
for ($hi = 0; $hi -lt $homoFrom.Length; $hi++) { $homoMap[$homoFrom[$hi]] = [string]$homoTo[$hi] }
foreach ($zc in 0x200B,0x200C,0x200D,0x2060,0xFEFF,0x00AD) { $homoMap[[char]$zc] = '' }
function Norm-Name($s) {
  $s = "$s"
  if ($s -cnotmatch '[^\x00-\x7F]') { return $s }
  try { $s = $s.Normalize([Text.NormalizationForm]::FormKC) } catch {}
  $sb = New-Object Text.StringBuilder
  foreach ($c in $s.ToCharArray()) {
    if ($homoMap.ContainsKey($c)) { [void]$sb.Append($homoMap[$c]) } else { [void]$sb.Append($c) }
  }
  $sb.ToString()
}
# ---------- Matching rules ----------
# Specific names (xeno, solara, krnl...): the name only has to appear as a WORD inside the file name
#   (Xeno.exe, xeno_injector.exe, Xeno-Executor-for-Roblox_36054.exe, "Download Xeno Free.zip" all match).
# Common-word names (matcha, celery, cryptic...): the file name must be the name itself (+ version/suffix).
$execExt = 'exe|dll|bat|cmd|ps1|msi|scr|jar|zip|rar|7z|lnk|sys|ahk|download|crdownload|part'
$presExt = 'exe|dll|bat|cmd|ps1|msi|scr|jar|zip|rar|7z|sys|ahk|download|crdownload|part'   # real program/archive files (not shortcuts)
$suffix  = 'executor|exploit|bootstrapper|bootstrap|loader|injector|setup|installer|launcher|external|internal|roblox|ui|exe'
function Name-Rx($n) { if ($nameAlt.ContainsKey($n)) { '(?:' + $nameAlt[$n] + ')' } else { [regex]::Escape($n) } }
function Name-Disp($n) { if ($nameDisplay.ContainsKey($n)) { $nameDisplay[$n] } else { "$n".ToUpper() } }
$core    = ($names | ForEach-Object { Name-Rx $_ }) -join '|'
$pattern = "(?<![A-Za-z0-9])(?:$core)(?:(?![A-Za-z])|(?=(?:$suffix)(?![A-Za-z])))"
$stemTail = "(?:[-_. ]*(?:$suffix|v?\d[\d.]*|x?64|x?86|win(?:32|64))|[-_. ]+x)*"
$tokTail  = "(?:(?![A-Za-z])|(?=(?:$suffix)(?![A-Za-z])))"
$ngNames = @($names | Where-Object { $genericNames -notcontains $_ })
$gNames  = @($names | Where-Object { $genericNames -contains $_ })
$ngCore  = ($ngNames | ForEach-Object { Name-Rx $_ }) -join '|'
$gCore   = ($gNames  | ForEach-Object { Name-Rx $_ }) -join '|'
$scanParts = New-Object System.Collections.Generic.List[string]
if ($ngCore) { $scanParts.Add("(?<![A-Za-z0-9])(?:$ngCore)$tokTail") }
if ($gCore)  { $scanParts.Add("^(?:$gCore)$stemTail$") }
$stemAll = $scanParts -join '|'
$patNG   = if ($ngCore) { "(?<![A-Za-z0-9])(?:$ngCore)$tokTail" } else { '(?!)' }
$nameRx = @{}
foreach ($n in $names) {
  $e = Name-Rx $n
  if ($genericNames -contains $n) { $nameRx[$n] = "(?i)^$e$stemTail$" } else { $nameRx[$n] = "(?i)(?<![A-Za-z0-9])$e$tokTail" }
}
function Test-Hit($s) { $s = Norm-Name "$s"; ($s -match $pattern) -and ($s -notmatch $exclude) }
function Match-Leaf($leaf, [bool]$allowNoExt) {
  $leaf = (Norm-Name "$leaf").Trim().Trim('"')
  if (-not $leaf) { return $null }
  if ($leaf -match '^(.*?)-[0-9A-F]{8}\.pf$') { $leaf = $Matches[1] }
  $ext = if ($leaf -match '\.([^.\\/]{1,10})$') { $Matches[1] } else { '' }
  if ($ext -and $ext -match "^(?:$execExt)$") { $stem = $leaf.Substring(0, $leaf.Length - $ext.Length - 1) }
  else { if (-not $allowNoExt) { return $null }; $stem = $leaf }
  foreach ($n in $names) { if ($stem -match $nameRx[$n]) { return $n } }
  $null
}
function Leaf-Of($p) { if ($p) { $p.Substring($p.LastIndexOf('\') + 1) } else { $null } }
function Rot13($s) {
  -join ($s.ToCharArray() | ForEach-Object {
    if     ($_ -cmatch '[a-z]') { [char]((([int]$_ - 97 + 13) % 26) + 97) }
    elseif ($_ -cmatch '[A-Z]') { [char]((([int]$_ - 65 + 13) % 26) + 65) }
    else { $_ } })
}
function Read-LockedFile($path) {
  $fs = [IO.File]::Open($path, 'Open', 'Read', 'ReadWrite,Delete')
  try { $ms = New-Object IO.MemoryStream; $fs.CopyTo($ms); $ms.ToArray() } finally { $fs.Dispose() }
}
$knownFolders = @{
  '7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E' = ${env:ProgramFiles(x86)}
  '6D809377-6AF0-444B-8957-A3773F02200E' = $(if ($env:ProgramW6432) { $env:ProgramW6432 } else { $env:ProgramFiles })
  '905E63B6-C1BF-494E-B29C-65B732D3D21A' = $env:ProgramFiles
  '1AC14E77-02E7-4E5D-B744-2EB1AE5198B7' = "$env:windir\System32"
  'F38BF404-1D43-42F2-9305-67DE0B28FC23' = $env:windir
  '374DE290-123F-4565-9164-39C4925E467B' = "$env:USERPROFILE\Downloads"
  'B4BFCC3A-DB2C-424C-B029-7FE99A87C641' = "$env:USERPROFILE\Desktop"
  'FDD39AD0-238F-46AF-ADB4-6C85480369C7' = "$env:USERPROFILE\Documents"
  'F1B32785-6FBA-4FCF-9D55-7B8E7F157091' = $env:LOCALAPPDATA
  '3EB685DB-65F9-4CF6-A03A-E3EF65729F3D' = $env:APPDATA
}
function Expand-KnownFolder($s) {
  if ("$s" -match '^\{([0-9A-Fa-f-]{36})\}(\\.*)?$') {
    $g = $Matches[1].ToUpper(); $rest = $Matches[2]
    if ($knownFolders.ContainsKey($g) -and $knownFolders[$g]) { return "$($knownFolders[$g])$rest" }
  }
  "$s"
}
$extList = 'exe|dll|bat|cmd|ps1|vbs|js|jar|lnk|zip|rar|7z|msi|lua|txt|json|scr|sys|bin|dat|tmp|cfg|ini|pf|py|iso|appx|url'
function Extract-Path($s) {
  $s = "$s" -replace '(?i)\b(?:file|containerfile|folder|process|webfile|regkey):_?(?=[A-Za-z]:\\)',''
  $m = [regex]::Match($s, "(?i)(?:\\Device\\HarddiskVolume\d+|\b[A-Z]:|\\\\[^\\\s]+\\[^\\\s]+)\\[^`"<>|*?\r\n]*?\.(?:$extList)(?![A-Za-z0-9])")
  if (-not $m.Success) { $m = [regex]::Match($s, "(?i)(?:\\Device\\HarddiskVolume\d+|\b[A-Z]:)\\[^`"<>|*?\r\n]*") }
  if ($m.Success) { return $m.Value.Trim().TrimEnd('.',',',';',' ') }
  $null
}

# ---------- Shortcut (.lnk) parser: stores the drive type + volume serial of the original file ----------
function Read-Z($b, $off, $unicode) {
  $sb = New-Object System.Text.StringBuilder
  if ($unicode) { for ($i=$off; $i+1 -lt $b.Length; $i+=2) { $c=[BitConverter]::ToUInt16($b,$i); if ($c -eq 0) {break}; [void]$sb.Append([char]$c) } }
  else          { for ($i=$off; $i -lt $b.Length; $i++)   { if ($b[$i] -eq 0) {break}; [void]$sb.Append([char]$b[$i]) } }
  $sb.ToString()
}
$driveTypeName = @{ 0='Unknown'; 1='NoRoot'; 2='Removable'; 3='Fixed'; 4='Network'; 5='CD-ROM'; 6='RAM disk' }
function Parse-Lnk($file) {
  try {
    $b = Read-LockedFile $file
    if ($b.Length -lt 80 -or [BitConverter]::ToUInt32($b,0) -ne 0x4C) { return $null }
    $flags = [BitConverter]::ToUInt32($b,0x14)
    $pos = 0x4C
    if ($flags -band 1) { $pos += 2 + [BitConverter]::ToUInt16($b,$pos) }
    if (-not ($flags -band 2)) { return $null }
    $li = $pos
    $liSize = [BitConverter]::ToUInt32($b,$li)
    if ($liSize -lt 28 -or $liSize -gt 8192 -or ($li + $liSize) -gt $b.Length) { return $null }
    if (-not ([BitConverter]::ToUInt32($b,$li+8) -band 1)) { return $null }
    $volOff = [BitConverter]::ToUInt32($b,$li+12)
    $lbpOff = [BitConverter]::ToUInt32($b,$li+16)
    $sufOff = [BitConverter]::ToUInt32($b,$li+24)
    if ($volOff -ge $liSize -or $lbpOff -ge $liSize) { return $null }
    $v  = $li + $volOff
    $dt = [BitConverter]::ToUInt32($b,$v+4)
    if ($dt -gt 6) { return $null }
    $sn = [BitConverter]::ToUInt32($b,$v+8)
    $lo = [BitConverter]::ToUInt32($b,$v+12)
    $label = if ($lo -eq 0x14) { Read-Z $b ($v + [BitConverter]::ToUInt32($b,$v+16)) $true } else { Read-Z $b ($v + $lo) $false }
    $target = (Read-Z $b ($li + $lbpOff) $false) + $(if ($sufOff -gt 0 -and $sufOff -lt $liSize) { Read-Z $b ($li + $sufOff) $false } else { '' })
    if ($target -notmatch '^[A-Za-z]:\\' -and $target -notmatch '^\\\\') { return $null }
    [pscustomobject]@{ Target=$target; DriveType=$driveTypeName[[int]$dt]; Serial=('{0:X8}' -f $sn); Label=$label }
  } catch { $null }
}

Set-Stage 'Loading the fast file scanner (first run compiles it)'
# ---------- C#: fast parallel scanner (+ Prefetch decoder). Compiled once, then cached in %TEMP% ----------
# v2: file/folder names are normalized (look-alike letters, zero-width characters) before the name regex runs.
$qDll = Join-Path $env:TEMP 'JHORFGU_QScanJ4_v2.dll'
$qSrc = @'
using System; using System.Collections.Concurrent; using System.Collections.Generic;
using System.IO; using System.Threading; using System.Threading.Tasks; using System.Text.RegularExpressions;
public static class QScanJ4 {
  public static bool TimedOut = false;
  public static long Dirs = 0;
  public static long Files = 0;
  static Task job;
  static List<string> results;
  static readonly HashSet<string> SkipNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase) {
    "Cache","Code Cache","GPUCache","Service Worker","CacheStorage","ScriptCache","IndexedDB","Local Storage",
    "Session Storage","blob_storage","Crashpad","node_modules",".git","__pycache__","DawnCache","GrShaderCache","ShaderCache","D3DSCache" };
  static readonly Dictionary<char,string> Homo = BuildHomo();
  static Dictionary<char,string> BuildHomo() {
    var d = new Dictionary<char,string>();
    string from = "\u0430\u0435\u043E\u0440\u0441\u0445\u0443\u0456\u0455\u0458\u04CF\u0410\u0412\u0415\u041A\u041C\u041D\u041E\u0420\u0421\u0422\u0425\u03BF\u039F\u03B1\u03BD\u03C1\u0399\u0406\u0405\u0408";
    string to   = "aeopcxyisjlABEKMHOPCTXoOavpIISJ";
    for (int i = 0; i < from.Length && i < to.Length; i++) d[from[i]] = to[i].ToString();
    return d;
  }
  static string Norm(string s) {
    if (s == null) return s;
    bool na = false;
    for (int i = 0; i < s.Length; i++) { if (s[i] > 127) { na = true; break; } }
    if (!na) return s;
    try { s = s.Normalize(System.Text.NormalizationForm.FormKC); } catch { }
    var sb = new System.Text.StringBuilder(s.Length);
    foreach (char c in s) {
      if (c == '\u200B' || c == '\u200C' || c == '\u200D' || c == '\u2060' || c == '\uFEFF' || c == '\u00AD') continue;
      string r;
      if (Homo.TryGetValue(c, out r)) sb.Append(r); else sb.Append(c);
    }
    return sb.ToString();
  }
  [System.Runtime.InteropServices.DllImport("kernel32.dll", CharSet = System.Runtime.InteropServices.CharSet.Auto)]
  public static extern uint QueryDosDevice(string lpDeviceName, System.Text.StringBuilder lpTargetPath, int ucchMax);
  [System.Runtime.InteropServices.DllImport("ntdll.dll")]
  static extern uint RtlGetCompressionWorkSpaceSize(ushort fmt, out uint wsCompress, out uint wsFragment);
  [System.Runtime.InteropServices.DllImport("ntdll.dll")]
  static extern uint RtlDecompressBufferEx(ushort fmt, byte[] uncompressed, uint uncompressedSize, byte[] compressed, uint compressedSize, out uint finalSize, byte[] workspace);
  public static byte[] DecompressMam(byte[] data) {
    try {
      if (data == null || data.Length < 8) return null;
      if (data[0] != 0x4D || data[1] != 0x41 || data[2] != 0x4D) return data;
      uint size = BitConverter.ToUInt32(data, 4);
      if (size == 0 || size > 64 * 1024 * 1024) return null;
      uint wsC, wsF;
      if (RtlGetCompressionWorkSpaceSize(4, out wsC, out wsF) != 0) return null;
      byte[] ws = new byte[wsF];
      byte[] outb = new byte[size];
      byte[] comp = new byte[data.Length - 8];
      Array.Copy(data, 8, comp, 0, comp.Length);
      uint fin;
      if (RtlDecompressBufferEx(4, outb, size, comp, (uint)comp.Length, out fin, ws) != 0) return null;
      return outb;
    } catch { return null; }
  }
  static void ScanFiles(string dir, Regex rx, HashSet<string> exts, ConcurrentBag<string> res) {
    long cnt = 0;
    try {
      foreach (var f in Directory.EnumerateFiles(dir)) {
        cnt++;
        var name = Path.GetFileName(f);
        int dot = name.LastIndexOf('.');
        if (dot < 1 || dot == name.Length - 1) continue;
        if (!exts.Contains(name.Substring(dot + 1))) continue;
        if (rx.IsMatch(Norm(name.Substring(0, dot)))) res.Add("F|" + f);
      }
    } catch {}
    Interlocked.Add(ref Files, cnt);
  }
  static bool Skip(string d, string[] skips) {
    foreach (var s in skips) if (d.IndexOf(s, StringComparison.OrdinalIgnoreCase) >= 0) return true;
    return false;
  }
  static bool IsReparse(string d) {
    try { return (File.GetAttributes(d) & FileAttributes.ReparsePoint) != 0; } catch { return true; }
  }
  static List<string> Run(string[] roots, int[] depths, string stemPattern, string[] exts, string[] skips, int seconds) {
    TimedOut = false; Dirs = 0; Files = 0;
    var deadline = DateTime.UtcNow.AddSeconds(seconds);
    var rx = new Regex(stemPattern, RegexOptions.IgnoreCase | RegexOptions.Compiled);
    var extSet = new HashSet<string>(exts, StringComparer.OrdinalIgnoreCase);
    var bag = new ConcurrentBag<string>();
    var queue = new ConcurrentQueue<KeyValuePair<string,int>>();
    int pending = 0;
    for (int i = 0; i < roots.Length; i++) {
      Interlocked.Increment(ref pending);
      queue.Enqueue(new KeyValuePair<string,int>(roots[i], depths[i]));
    }
    int workers = Math.Max(8, Environment.ProcessorCount * 2);
    var tasks = new Task[workers];
    for (int w = 0; w < workers; w++) {
      tasks[w] = Task.Factory.StartNew(() => {
        while (true) {
          if (DateTime.UtcNow > deadline) { TimedOut = true; return; }
          KeyValuePair<string,int> cur;
          if (queue.TryDequeue(out cur)) {
            Interlocked.Increment(ref Dirs);
            try {
              ScanFiles(cur.Key, rx, extSet, bag);
              if (cur.Value >= 1) {
                foreach (var d in Directory.EnumerateDirectories(cur.Key)) {
                  var dn = Path.GetFileName(d);
                  if (SkipNames.Contains(dn) || Skip(d, skips) || IsReparse(d)) continue;
                  if (dn.Equals("autoexec", StringComparison.OrdinalIgnoreCase)) bag.Add("A|" + d);
                  if (rx.IsMatch(Norm(dn))) bag.Add("D|" + d);
                  Interlocked.Increment(ref pending);
                  queue.Enqueue(new KeyValuePair<string,int>(d, cur.Value - 1));
                }
              }
            } catch {}
            Interlocked.Decrement(ref pending);
          } else {
            if (Thread.VolatileRead(ref pending) == 0) return;
            Thread.Sleep(1);
          }
        }
      }, TaskCreationOptions.LongRunning);
    }
    Task.WaitAll(tasks);
    return new List<string>(bag);
  }
  public static void Begin(string[] roots, int[] depths, string stemPattern, string[] exts, string[] skips, int seconds) {
    results = null;
    job = Task.Factory.StartNew(() => { results = Run(roots, depths, stemPattern, exts, skips, seconds); });
  }
  public static List<string> Finish() {
    try { if (job != null) job.Wait(); } catch {}
    return results != null ? results : new List<string>();
  }
}
'@
$scannerOk = $false
try {
  if (-not ('QScanJ4' -as [type])) {
    $loaded = $false
    if (Test-Path -LiteralPath $qDll) { try { Add-Type -Path $qDll -ErrorAction Stop; $loaded = $true } catch {} }
    if (-not $loaded) {
      try { Add-Type -TypeDefinition $qSrc -OutputAssembly $qDll -ErrorAction Stop } catch {}
      if (-not ('QScanJ4' -as [type]) -and (Test-Path -LiteralPath $qDll)) { try { Add-Type -Path $qDll -ErrorAction Stop } catch {} }
      if (-not ('QScanJ4' -as [type])) { Add-Type -TypeDefinition $qSrc -ErrorAction Stop }
    }
  }
  $scannerOk = [bool]('QScanJ4' -as [type])
} catch {}

Set-Stage 'Starting the services and scheduled tasks check'
# ---------- Start the slow Windows queries (services + scheduled tasks) in the background ----------
$asyncPs = $null; $asyncH = $null
try {
  $asyncPs = [powershell]::Create()
  [void]$asyncPs.AddScript({
    param($pat, $excl)
    $out = New-Object System.Collections.Generic.List[object]
    try { Get-CimInstance Win32_Service | ForEach-Object {
        $pp = "$($_.PathName)"
        if ((("$($_.Name) $pp") -match $pat) -and ($pp -notmatch $excl)) { $out.Add([pscustomobject]@{ Kind='Service'; Name="$($_.Name)"; Path=$pp }) } } } catch {}
    try { Get-ScheduledTask | ForEach-Object {
        $ex = ($_.Actions.Execute -join ' ')
        if ((("$($_.TaskName) $ex") -match $pat) -and ($ex -notmatch $excl)) { $out.Add([pscustomobject]@{ Kind='Scheduled task'; Name="$($_.TaskName)"; Path=$ex }) } } } catch {}
    $out.ToArray()
  }).AddArgument($pattern).AddArgument($exclude)
  $asyncH = $asyncPs.BeginInvoke()
} catch {}

# ---------- Current drives: letter, type, serial (bus type is filled in later, in parallel with the scan) ----------
$sysLetter = ($env:SystemDrive).TrimEnd(':').ToUpper()
$volMap = @{}
try {
  foreach ($ld in @(Get-CimInstance Win32_LogicalDisk)) {
    $letter = ($ld.DeviceID).TrimEnd(':').ToUpper()
    $volMap[$letter] = [pscustomobject]@{
      Letter=$letter; DriveType=[int]$ld.DriveType; Serial=("$($ld.VolumeSerialNumber)").ToUpper()
      Label="$($ld.VolumeName)"; Bus=''; Model='' }
  }
} catch {}

$ntMap = @{}
if ($isAdmin -and $scannerOk) {
  try {
    foreach ($c in [char[]](65..90)) {
      $sb = New-Object System.Text.StringBuilder 520
      if ([QScanJ4]::QueryDosDevice("$($c):", $sb, 520) -gt 0) {
        $t = $sb.ToString()
        if ($t -match '^\\Device\\HarddiskVolume\d+$') { $ntMap[$t.ToLower()] = "$c" }
      }
    }
  } catch {}
}

# ---------- Location helpers: main disk / internal / USB now / USB not connected ----------
$usbLetterMap = @{}
function New-Loc($short, $detail) { [pscustomobject]@{ Short=$short; Detail=$detail } }
function Describe-Vol($v) {
  $L = $v.Letter; $bus = $v.Bus
  if     ($v.DriveType -eq 4) { New-Loc 'NETWORK DRIVE' "network drive ${L}:" }
  elseif ($v.DriveType -eq 5) { New-Loc 'OPTICAL DISC' "optical drive ${L}:" }
  elseif ($bus -eq 'USB')     { New-Loc 'USB DRIVE (plugged in now)' "USB drive ${L}: is plugged in now ($($v.Model))" }
  elseif ($L -eq $sysLetter)  { New-Loc 'MAIN DISK' "main system disk ${L}:" }
  elseif ($v.DriveType -eq 2 -or $bus -in 'SD','MMC') { New-Loc 'REMOVABLE MEDIA (plugged in now)' "removable media ${L}: is connected now" }
  else { New-Loc 'OTHER INTERNAL DISK' "secondary disk ${L}: ($bus $($v.Model))" }
}
function Locate($path, $unmapped, $serial, $dtype) {
  if (-not $path) { return (New-Loc 'NAME ONLY' 'only a name was recorded (no drive or path)') }
  if ($unmapped) { return (New-Loc 'VOLUME NOT MOUNTED NOW' 'that volume is not mounted now - removed USB/external disk (approximate)') }
  if ($path -match '^\\\\') { return (New-Loc 'NETWORK SHARE' 'on a network share') }
  if ($path -notmatch '^[A-Za-z]:') { return (New-Loc 'UNKNOWN' 'location could not be determined') }
  $L = $path.Substring(0,1).ToUpper()
  $cur = $volMap[$L]
  $hint = if ($usbLetterMap.ContainsKey($L)) { " Drive letter ${L}: was last assigned to USB device $($usbLetterMap[$L])." } else { '' }
  if ($serial) {
    $sn = "$serial".ToUpper()
    $match = $volMap.Values | Where-Object { $_.Serial -eq $sn } | Select-Object -First 1
    if ($match) {
      $r = Describe-Vol $match
      if ($match.Letter -ne $L) { $r.Detail += " (was ${L}:, now mounted as $($match.Letter):)" }
      return $r
    }
    switch ($dtype) {
      'Removable' { return (New-Loc 'USB/REMOVABLE - NOT PLUGGED IN NOW' "was on a removable drive (${L}:, volume serial $sn) that is not plugged in now.$hint") }
      'Fixed'     { return (New-Loc 'EXTERNAL/OTHER DISK - NOT CONNECTED NOW' "was on a disk (${L}:, serial $sn) that is not connected now - external HDD/SSD or removed disk.$hint") }
      'Network'   { return (New-Loc 'NETWORK DRIVE' 'was on a network drive') }
      default     { return (New-Loc 'DRIVE NOT CONNECTED NOW' "volume serial $sn is not connected now.$hint") }
    }
  }
  if ($cur) { return (Describe-Vol $cur) }
  New-Loc 'DRIVE NOT PRESENT NOW' "drive ${L}: does not exist now - it was a USB/external/network drive that is unplugged.$hint"
}
function Test-Exists($p) {
  if (-not $p -or $p -notmatch '^[A-Za-z]:\\') { return $null }
  $v = $volMap[$p.Substring(0,1).ToUpper()]
  if ($v -and $v.DriveType -eq 4) { return $null }
  try { [bool](Test-Path -LiteralPath $p -ErrorAction Stop) } catch { $null }
}
function Resolve-Nt($p) {
  if ($p -match '^\\Device\\HarddiskVolume(\d+)(\\.*)?$') {
    $k = "\device\harddiskvolume$($Matches[1])"; $rest = $Matches[2]
    if ($ntMap.ContainsKey($k)) { return @{ Path="$($ntMap[$k]):$rest"; Unm=$false } }
    return @{ Path=$p; Unm=$true }
  }
  @{ Path=$p; Unm=$false }
}

# ---------- Prefetch reader (admin): exact run counter + last 8 run times ----------
function Get-PrefetchInfo($file) {
  try {
    if (-not $scannerOk) { return $null }
    $b = Read-LockedFile $file
    $d = [QScanJ4]::DecompressMam($b)
    if (-not $d -or $d.Length -lt 0xD4) { return $null }
    if ([Text.Encoding]::ASCII.GetString($d,4,4) -ne 'SCCA') { return $null }
    $ver = [BitConverter]::ToUInt32($d,0)
    if ($ver -notin 26,30,31) { return $null }
    $runs = [int][BitConverter]::ToUInt32($d,0xD0)
    $times = New-Object System.Collections.Generic.List[datetime]
    for ($i = 0; $i -lt 8; $i++) {
      $ft = [BitConverter]::ToInt64($d, 0x80 + 8*$i)
      if ($ft -gt 0) { try { $times.Add([datetime]::FromFileTime($ft)) } catch {} }
    }
    [pscustomobject]@{ Runs=$runs; Times=@($times | Sort-Object -Descending) }
  } catch { $null }
}

# ---------- Evidence store ----------
$ev = New-Object System.Collections.Generic.List[object]
$evSeen = New-Object 'System.Collections.Generic.HashSet[string]'
function Add-Ev($h) {
  if ($h.Path -and "$($h.Path)" -match $exclude) { return }
  # a name that only matches after look-alike / hidden characters are removed is an evasion attempt
  if ($h.Path -and "$($h.Path)" -match '[^\x00-\x7F]') {
    $lfE = Leaf-Of "$($h.Path)"
    if ($lfE -and ((Norm-Name $lfE) -cne $lfE) -and (Match-Leaf $lfE $true)) { $h.Evasion = $true }
  }
  $pl = "$($h.Path)".ToLower()
  $k = "$($h.Name)|$($h.Src)|$pl|$($h.Run)|$($h.Note)"
  if (-not $evSeen.Add($k)) { return }
  $ev.Add([pscustomobject]$h)
}
# ---------- Matrix fingerprint (from real Matrix files: version.dat + _license.dat + oldui.exe + 1-byte 8-hex .dat markers) ----------
# The names are generic, so a folder is only reported when the CONTENT matches (score 3 or more).
$mxMagic = '7264ad3c383a393833363534cccd3130972e2d2c2b2a29286726252423222120'   # first 32 bytes of Matrix's version.dat (same in every build)
$mxDone = New-Object 'System.Collections.Generic.HashSet[string]'
function Test-MatrixDir($dir) {
  # Looks at file CONTENT, not names, so renamed files are still recognised.
  $score = 0; $parts = New-Object System.Collections.Generic.List[string]; $main = $null
  $big = 0; $hs = 0
  try {
    foreach ($f in @(Get-ChildItem -LiteralPath $dir -File -Force -ErrorAction SilentlyContinue | Select-Object -First 200)) {
      $nm = $f.Name.ToLower(); $ln = $f.Length
      if ($ln -ge 5MB -and $ln -le 200MB) {
        if ($big -ge 25) { continue }; $big++
        try {
          $fs = [IO.File]::Open($f.FullName, 'Open', 'Read', 'ReadWrite')
          try { $b = New-Object byte[] 32; [void]$fs.Read($b, 0, 32) } finally { $fs.Close() }
          if ((([BitConverter]::ToString($b) -replace '-', '').ToLower()) -eq $mxMagic) {
            $score += 3; $parts.Add("$($f.Name) (Matrix data file, $([math]::Round($ln / 1MB, 1)) MB)"); if (-not $main) { $main = $f }
          }
        } catch {}
      }
      elseif ($ln -eq 48 -and $nm -notmatch '\.(exe|dll)$') {
        try {
          $t = ([IO.File]::ReadAllText($f.FullName)).Trim()
          if ($t -match '^[a-z0-9]{6}(-[a-z0-9]{6}){6}$') { $score += 2; $parts.Add("$($f.Name) (license key)"); if (-not $main) { $main = $f } }
        } catch {}
      }
      elseif (($nm -match '\.(exe|dll)$' -or $nm -eq 'oldui.exe') -and $ln -le 2MB -and $ln -ge 1024) {
        if ($hs -ge 25 -and $nm -ne 'oldui.exe') { continue }; $hs++
        $hh = $null; try { $hh = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash.ToLower() } catch {}
        if ($hh -and $knownHashes.ContainsKey($hh)) { $score += 3; $parts.Add("$($f.Name) (known launcher: hash match)"); $main = $f }
        elseif ($nm -eq 'oldui.exe') { $score += 2; $parts.Add("$($f.Name) (launcher)"); $main = $f }
      }
      elseif ($nm -match '^[0-9a-f]{8}\.dat$' -and $ln -eq 1) { $score += 1; $parts.Add("$($f.Name) (1-byte marker)") }
    }
  } catch {}
  [pscustomobject]@{ Score = $score; Parts = $parts; Main = $main }
}
function Check-MxDir($dir) {
  if (-not $dir -or -not $mxDone.Add("$dir".ToLower())) { return }
  $r = Test-MatrixDir $dir
  if ($r.Score -ge 3) {
    $mp = if ($r.Main) { $r.Main.FullName } else { $dir }
    $mm = if ($r.Main) { $r.Main.LastWriteTime } else { $null }
    $mc = if ($r.Main) { $r.Main.CreationTime } else { $null }
    Add-Ev @{ Name='matrix'; Src='Matrix file set'; Path=$mp; PresentNow=$true; Mod=$mm; Created=$mc; Note=('Matrix file fingerprint in this folder: ' + ($r.Parts -join '; ')) }
  }
}
$unkName = '(unrecognized executor-like folder)'
$unkMod  = '(unrecognized module loaded inside Roblox)'
$unkApi  = '(unrecognized file containing Roblox-exploit API names)'
$unkLua  = '(unrecognized exploit script: loadstring / getgenv)'
$unkMem  = '(unrecognized program with memory access to Roblox)'
$unkOvl  = '(unrecognized transparent overlay window on top of the screen)'
$unkExt  = '(unrecognized program built to read/write Roblox memory)'
$unkCli  = '(modified or unsigned Roblox client)'
$unkKw   = '(unrecognized file with an executor-style name)'
$ahkPseudo = @{
  aimbot    = '(AutoHotkey) Aimbot / aim-assist macro'
  trigger   = '(AutoHotkey) Triggerbot / auto-click-on-color macro'
  autoclick = '(AutoHotkey) Auto-clicker macro'
  skill     = '(AutoHotkey) Auto skill / combo macro'
  boost     = '(AutoHotkey) Boost / dash / movement macro'
  farm      = '(AutoHotkey) Auto-farm / fishing / anti-AFK macro'
  esp       = '(AutoHotkey) ESP / color-radar macro'
  lag       = '(AutoHotkey) Lag switch / desync macro'
  generic   = '(AutoHotkey) Roblox keyboard/mouse macro'
}
$ahkLabel = @{ aimbot='aimbot / aim assist'; trigger='triggerbot / auto-click on color'; autoclick='auto-clicker'; skill='auto skill / combo'; boost='boost / dash / movement'; farm='auto-farm / fishing / anti-AFK'; esp='ESP / color radar'; lag='lag switch / desync'; generic='keyboard/mouse macro' }
$pseudoAll = @($unkName, $unkMod, $unkApi, $unkLua, $unkMem, $unkOvl, $unkExt, $unkCli, $unkKw) + @($ahkPseudo.Values)
function Find-NameToken($text) {
  $text = Norm-Name "$text"
  foreach ($n in $names) { if ($text -match ("(?i)(?<![A-Za-z0-9])(?:" + (Name-Rx $n) + ")(?![A-Za-z])")) { return $n } }
  $null
}
function Folder-HasExec($p) {
  try {
    [bool](Get-ChildItem -LiteralPath $p -Recurse -Depth 2 -File -Force -ErrorAction SilentlyContinue |
      Where-Object { $_.Extension.TrimStart('.') -match "^(?:$presExt)$" } | Select-Object -First 1)
  } catch { $false }
}
function Inspect-Folder($p) {
  $o = [pscustomobject]@{ Count=0; Subdirs=@(); Files=@(); HasExec=$false; HasLayout=$false; Note='' }
  try {
    $items = @(Get-ChildItem -LiteralPath $p -Force -ErrorAction Stop | Select-Object -First 80)
    $o.Count   = $items.Count
    $o.Subdirs = @($items | Where-Object { $_.PSIsContainer } | ForEach-Object { $_.Name })
    $o.Files   = @($items | Where-Object { -not $_.PSIsContainer } | ForEach-Object { $_.Name })
    $o.HasLayout = ($o.Subdirs -contains 'autoexec') -or ($o.Subdirs -contains 'workspace')
    $o.HasExec = (@($o.Files | Where-Object { $_ -match "\.(?:$presExt)$" }).Count -gt 0) -or (Folder-HasExec $p)
    $first = @(@($o.Subdirs) + @($o.Files) | Select-Object -First 8)
    if ($first.Count -gt 0) { $o.Note = 'contains: ' + ($first -join ', ') }
  } catch {}
  $o
}
function Folder-Qualifies($n, $i) {
  if ($i.Count -eq 0) { return $false }
  if ($genericNames -contains $n) { return $i.HasLayout }
  $true
}
# Name-independent: Roblox executors keep an 'autoexec' folder (often next to 'workspace'), whatever the program is called
function Add-AutoexecEv($autoPath) {
  $parent = Split-Path -Parent $autoPath
  if (-not $parent -or $parent -match $exclude) { return }
  $i = Inspect-Folder $parent
  $inside = @(Get-ChildItem -LiteralPath $autoPath -Force -ErrorAction SilentlyContinue | Select-Object -First 20)
  $hasLua = @($inside | Where-Object { $_.Name -match '\.(lua|luau|txt)$' }).Count -gt 0
  $hasW   = $i.Subdirs -contains 'workspace'
  if (-not ($hasW -or $hasLua -or $i.HasExec)) { return }
  $n = Find-NameToken ("$parent " + ($i.Files -join ' '))
  if (-not $n) { $n = $unkName }
  $fi = Get-Item -LiteralPath $parent -Force -ErrorAction SilentlyContinue
  Add-Ev @{ Name=$n; Src='Executor folder layout (autoexec)'; Path=$parent; HasExec=$i.HasExec; Mod=$fi.LastWriteTime; Created=$fi.CreationTime
            Note=("has an 'autoexec' folder" + $(if ($hasW) { ' and a workspace folder' } else { '' }) + $(if ($hasLua) { ', with scripts inside' } else { '' })) }
}
$script:psDirs = 0
function Scan-PS($seedList, $seconds) {
  $deadline = (Get-Date).AddSeconds($seconds)
  $res = New-Object System.Collections.Generic.List[string]
  $q = New-Object System.Collections.Generic.Queue[object]
  foreach ($sd in $seedList) { $q.Enqueue(@($sd.Path, [int]$sd.Depth)) }
  $skipNm = '^(Cache|Code Cache|GPUCache|Service Worker|CacheStorage|ScriptCache|IndexedDB|Local Storage|Session Storage|blob_storage|Crashpad|node_modules|\.git|__pycache__|DawnCache|GrShaderCache|ShaderCache|D3DSCache)$'
  while ($q.Count -gt 0) {
    if ((Get-Date) -gt $deadline) { $script:timedOut = $true; break }
    $c = $q.Dequeue(); $dir = $c[0]; $depth = $c[1]
    $script:psDirs++
    try {
      foreach ($f in [IO.Directory]::EnumerateFiles($dir)) {
        $nm = [IO.Path]::GetFileName($f)
        if ($nm -match "\.(?:$execExt)$" -and (Match-Leaf $nm $false)) { $res.Add("F|$f") }
      }
    } catch {}
    if ($depth -ge 1) {
      try {
        foreach ($d in [IO.Directory]::EnumerateDirectories($dir)) {
          $dn = [IO.Path]::GetFileName($d)
          if ($dn -match $skipNm) { continue }
          try { if (([IO.File]::GetAttributes($d) -band [IO.FileAttributes]::ReparsePoint) -ne 0) { continue } } catch { continue }
          $skipped = $false
          foreach ($sk in $skips) { if ($d.IndexOf($sk, [StringComparison]::OrdinalIgnoreCase) -ge 0) { $skipped = $true; break } }
          if ($skipped) { continue }
          if ($dn -ieq 'autoexec') { $res.Add("A|$d") }
          if (Match-Leaf $dn $true) { $res.Add("D|$d") }
          $q.Enqueue(@($d, ($depth - 1)))
        }
      } catch {}
    }
  }
  $res.ToArray()
}

Set-Stage 'Scanning disks and folders (runs in the background)'
# ---------- 1. File scan: START it in the background now (it runs while everything below runs) ----------
$timedOut = $false
Set-Stage 'Looking at the other user accounts on this PC'
# ---------- Other user accounts on this PC (someone can hide a tool in a different Windows user) ----------
# Windows only lets a standard user open another user's folders if that user's permissions allow it; whatever CAN be opened is scanned,
# and the accounts that cannot be opened are listed in the report so nothing is silently skipped.
$otherProfiles = New-Object System.Collections.Generic.List[object]
try {
  $profRoots = New-Object System.Collections.Generic.List[string]
  foreach ($pk in @(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -ErrorAction SilentlyContinue)) {
    $pip = "$((Get-ItemProperty -LiteralPath $pk.PSPath -ErrorAction SilentlyContinue).ProfileImagePath)"
    if ($pip -and -not $profRoots.Contains($pip)) { $profRoots.Add($pip) }
  }
  foreach ($ud0 in @(Get-ChildItem "$env:SystemDrive\Users" -Directory -Force -ErrorAction SilentlyContinue)) { if (-not $profRoots.Contains($ud0.FullName)) { $profRoots.Add($ud0.FullName) } }
  foreach ($pr in $profRoots) {
    $pleaf = Split-Path -Leaf $pr
    if ($pr -ieq $env:USERPROFILE -or $pleaf -match '^(Public|Default|Default User|All Users|defaultuser0|WsiAccount)$') { continue }
    if ($pr.StartsWith($env:windir, [StringComparison]::OrdinalIgnoreCase)) { continue }
    if (-not (Test-Path -LiteralPath $pr)) { continue }
    $okR = $false; try { $null = [IO.Directory]::GetFileSystemEntries($pr); $okR = $true } catch {}
    $otherProfiles.Add([pscustomobject]@{ Path=$pr; Name=$pleaf; Readable=$okR })
  }
} catch {}
$readableProfiles = @($otherProfiles | Where-Object { $_.Readable })
$lockedProfiles   = @($otherProfiles | Where-Object { -not $_.Readable })

$scanStarted = $false
$seedPaths = @()
if ($true) {
  $seeds = New-Object System.Collections.Generic.List[object]
  function Add-Seed($p, $d) { if ($p -and (Test-Path -LiteralPath $p)) { $seeds.Add(@{ Path=$p; Depth=$d }) } }
  $skipTop = '^(Windows|Users|Program Files|Program Files \(x86\)|ProgramData|\$Recycle\.Bin|System Volume Information|Recovery|PerfLogs|\$WinREAgent|Config\.Msi|MSOCache|Documents and Settings)$'
  # most likely places first (the scanner works through them in this order)
  if ($doInternal) {
    $up = $env:USERPROFILE
    Add-Seed "$up\Downloads" 6; Add-Seed "$up\Desktop" 5; Add-Seed "$up\Documents" 5; Add-Seed "$up\OneDrive" 4
    Add-Seed $env:LOCALAPPDATA 4; Add-Seed $env:APPDATA 4; Add-Seed $env:TEMP 3
    Add-Seed $env:ProgramData 3; Add-Seed $env:ProgramFiles 3; Add-Seed ${env:ProgramFiles(x86)} 3; Add-Seed $up 0
    foreach ($op in $readableProfiles) {
      $o = $op.Path
      Add-Seed "$o\Downloads" 6; Add-Seed "$o\Desktop" 5; Add-Seed "$o\Documents" 5; Add-Seed "$o\OneDrive" 4
      Add-Seed "$o\AppData\Local" 4; Add-Seed "$o\AppData\Roaming" 4; Add-Seed $o 0
    }
    foreach ($ps in 'Downloads','Desktop','Documents') { Add-Seed "$env:PUBLIC\$ps" 4 }
    Add-Seed $env:PUBLIC 0
  }
  # Bus type is not known yet, so scan by drive type; the Internal/External filter is applied at the end.
  $scanVols = New-Object System.Collections.Generic.List[object]
  $seenL = @{}
  if ($doInternal) { foreach ($v in $volMap.Values) { if ($v.DriveType -eq 3 -and -not $seenL.ContainsKey($v.Letter)) { $seenL[$v.Letter] = 1; $scanVols.Add($v) } } }
  if ($doExternal) {
    foreach ($v in $volMap.Values) { if ($v.DriveType -eq 2 -and -not $seenL.ContainsKey($v.Letter)) { $seenL[$v.Letter] = 1; $scanVols.Add($v) } }
    foreach ($v in $volMap.Values) { if ($v.DriveType -eq 3 -and $v.Letter -ne $sysLetter -and -not $seenL.ContainsKey($v.Letter)) { $seenL[$v.Letter] = 1; $scanVols.Add($v) } }
  }
  foreach ($v in $scanVols) {
    $root = "$($v.Letter):\"
    Add-Seed $root 0
    foreach ($d in @(Get-ChildItem -LiteralPath $root -Directory -Force -ErrorAction SilentlyContinue)) {
      $skipIt = if ($v.Letter -eq $sysLetter) { $d.Name -match $skipTop } else { $d.Name -match '^(\$Recycle\.Bin|System Volume Information)$' }
      if (-not $skipIt) { Add-Seed $d.FullName 4 }
    }
  }
  $skips = [string[]]@('\Windows\WinSxS','\Windows\Installer','\Windows\servicing','\Windows\assembly','\Windows\Microsoft.NET','\Windows\SoftwareDistribution',
    '\Microsoft\Edge\User Data','\Google\Chrome\User Data','\BraveSoftware','\Mozilla\Firefox\Profiles',
    '\Microsoft\Windows\INetCache','\Microsoft\Windows\WebCache','\Packages\','\CrashDumps','\pip\Cache','\npm-cache','\AppData\Local\Temp')
  $seedPaths = @($seeds | ForEach-Object { "$($_.Path)   (depth $($_.Depth))" })
  if ($seeds.Count -gt 0 -and $scannerOk) {
    [QScanJ4]::Begin([string[]]@($seeds | ForEach-Object { $_.Path }), [int[]]@($seeds | ForEach-Object { $_.Depth }), $stemAll, [string[]]($execExt -split '\|'), $skips, $scanSeconds)
    $scanStarted = $true
  }
}

# Disk bus type (USB / internal) - slow query, so it runs while the scan is already working
$busByLetter = @{}
try {
  $disks = @{}
  Get-Disk -ErrorAction Stop | ForEach-Object { $disks[[int]$_.Number] = $_ }
  Get-Partition -ErrorAction Stop | Where-Object { $_.DriveLetter } | ForEach-Object {
    $d = $disks[[int]$_.DiskNumber]
    if ($d) { $busByLetter["$($_.DriveLetter)".ToUpper()] = @{ Bus="$($d.BusType)"; Model="$($d.FriendlyName)" } }
  }
} catch {}
foreach ($k in @($volMap.Keys)) { $bi = $busByLetter[$k]; if ($bi) { $volMap[$k].Bus = $bi.Bus; $volMap[$k].Model = $bi.Model } }

Set-Stage 'Checking the usual install folders'
# ---------- 1b. Direct check of the usual install spots (instant; does NOT depend on the scanner) ----------
$bases = New-Object System.Collections.Generic.List[string]
foreach ($b in @($env:LOCALAPPDATA, "$env:LOCALAPPDATA\Programs", $env:APPDATA, $env:ProgramData, $env:ProgramFiles, ${env:ProgramFiles(x86)},
                 $env:USERPROFILE, "$env:USERPROFILE\Downloads", "$env:USERPROFILE\Desktop", "$env:USERPROFILE\Documents", $env:TEMP, "$env:SystemDrive\")) {
  if ($b -and (Test-Path -LiteralPath $b) -and -not $bases.Contains($b)) { $bases.Add($b) }
}
foreach ($v in $volMap.Values) { if (($v.DriveType -eq 2 -or $v.DriveType -eq 3) -and $v.Letter -ne $sysLetter) { $bases.Add("$($v.Letter):\") } }
foreach ($op in $readableProfiles) {
  foreach ($sub in '', 'Downloads', 'Desktop', 'Documents', 'AppData\Local', 'AppData\Local\Programs', 'AppData\Roaming') {
    $ob = if ($sub) { Join-Path $op.Path $sub } else { $op.Path }
    if ((Test-Path -LiteralPath $ob) -and -not $bases.Contains($ob)) { $bases.Add($ob) }
  }
}
foreach ($sub in 'Downloads', 'Desktop', 'Documents') { $pb = Join-Path $env:PUBLIC $sub; if ((Test-Path -LiteralPath $pb) -and -not $bases.Contains($pb)) { $bases.Add($pb) } }
foreach ($b in $bases) {
  foreach ($it in @(Get-ChildItem -LiteralPath $b -Force -ErrorAction SilentlyContinue)) {
    if (-not (Test-Hit $it.Name)) { continue }
    if ($it.FullName -match $exclude) { continue }
    if ($it.PSIsContainer) {
      $n = Match-Leaf $it.Name $true
      if ($n) {
        $i = Inspect-Folder $it.FullName
        if (Folder-Qualifies $n $i) { Add-Ev @{ Name=$n; Src='Install folder'; Path=$it.FullName; HasExec=$i.HasExec; Mod=$it.LastWriteTime; Created=$it.CreationTime; Note=$i.Note } }
      }
    } else {
      $n = Match-Leaf $it.Name $false
      if ($n) { Add-Ev @{ Name=$n; Src='File on disk'; Path=$it.FullName; PresentNow=$true; Mod=$it.LastWriteTime; Created=$it.CreationTime } }
    }
  }
}

Set-Stage 'Looking for known program files (matcha.exe, sacredstep.exe, Cheat Engine)'
# ---------- 1c. Exact known file names (Matcha is an external: its program is Matcha.exe) ----------
$kRoots = New-Object System.Collections.Generic.List[string]
foreach ($b in @("$env:USERPROFILE\Downloads","$env:USERPROFILE\Desktop","$env:USERPROFILE\Documents","$env:USERPROFILE\OneDrive",$env:LOCALAPPDATA,$env:APPDATA,$env:ProgramData,$env:TEMP)) {
  if ($b -and (Test-Path -LiteralPath $b) -and -not $kRoots.Contains($b)) { $kRoots.Add($b) }
}
foreach ($v in $volMap.Values) { if (($v.DriveType -eq 2 -or $v.DriveType -eq 3) -and $v.Letter -ne $sysLetter) { $kRoots.Add("$($v.Letter):\") } }
foreach ($op in $readableProfiles) {
  foreach ($sub in 'Downloads', 'Desktop', 'Documents', 'AppData\Local', 'AppData\Roaming') {
    $kp = Join-Path $op.Path $sub; if ((Test-Path -LiteralPath $kp) -and -not $kRoots.Contains($kp)) { $kRoots.Add($kp) }
  }
}
$kDeadline = (Get-Date).AddSeconds(2)
foreach ($kn in $knownExe.Keys) {
  foreach ($kf in $knownExe[$kn]) {
    foreach ($kr in $kRoots) {
      if ((Get-Date) -gt $kDeadline) { break }
      foreach ($hit in @(Get-ChildItem -LiteralPath $kr -Filter $kf -Recurse -Depth 5 -File -Force -ErrorAction SilentlyContinue | Select-Object -First 5)) {
        if ($hit.FullName -match $exclude) { continue }
        Add-Ev @{ Name=$kn; Src='File on disk'; Path=$hit.FullName; PresentNow=$true; Mod=$hit.LastWriteTime; Created=$hit.CreationTime }
      }
    }
  }
}
# A running Matcha.exe (any location)
foreach ($kn in $knownExe.Keys) {
  foreach ($kf in $knownExe[$kn]) {
    Get-Process -Name ([IO.Path]::GetFileNameWithoutExtension($kf)) -ErrorAction SilentlyContinue | ForEach-Object {
      $pp = "$($_.Path)"
      Add-Ev @{ Name=$kn; Src='Running process'; Path=$(if ($pp) { $pp } else { $null }); PresentNow=$true; Run=(Get-Date); RunKind='running right now' }
    }
  }
}

Set-Stage 'Looking for Matrix files'
# Quick pass over the usual folders for Matrix's launcher and license file (content is verified, not just the name)
$mxDeadline = (Get-Date).AddSeconds(2)
foreach ($kr in $kRoots) {
  foreach ($flt in 'oldui.exe', '_license*.dat') {
    if ((Get-Date) -gt $mxDeadline) { break }
    foreach ($hit in @(Get-ChildItem -LiteralPath $kr -Filter $flt -Recurse -Depth 5 -File -Force -ErrorAction SilentlyContinue | Select-Object -First 20)) {
      Check-MxDir (Split-Path -Parent $hit.FullName)
    }
  }
}

Set-Stage 'Starting download-mark and browser history checks'
# ---------- Background job 2: "downloaded from website" marks (works even on renamed files) + browser history ----------
$zoneDirs = @("$env:USERPROFILE\Downloads","$env:USERPROFILE\Desktop","$env:USERPROFILE\Documents") | Where-Object { Test-Path -LiteralPath $_ }
$zoneDirs = @($zoneDirs)
foreach ($op in $readableProfiles) { foreach ($sub in 'Downloads','Desktop','Documents') { $zd = Join-Path $op.Path $sub; if (Test-Path -LiteralPath $zd) { $zoneDirs += $zd } } }
$histFiles = New-Object System.Collections.Generic.List[string]
foreach ($ud in @("$env:LOCALAPPDATA\Google\Chrome\User Data","$env:LOCALAPPDATA\Microsoft\Edge\User Data","$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data","$env:APPDATA\Opera Software\Opera Stable")) {
  if (Test-Path -LiteralPath $ud) {
    $h0 = Join-Path $ud 'History'; if (Test-Path -LiteralPath $h0) { $histFiles.Add($h0) }
    foreach ($pd in @(Get-ChildItem -LiteralPath $ud -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^(Default|Profile \d+)$' })) {
      $h = Join-Path $pd.FullName 'History'; if (Test-Path -LiteralPath $h) { $histFiles.Add($h) }
    }
  }
}
foreach ($fp in @(Get-ChildItem "$env:APPDATA\Mozilla\Firefox\Profiles" -Directory -ErrorAction SilentlyContinue)) {
  $pl = Join-Path $fp.FullName 'places.sqlite'; if (Test-Path -LiteralPath $pl) { $histFiles.Add($pl) }
}
foreach ($op in $readableProfiles) {
  foreach ($ud in @("$($op.Path)\AppData\Local\Google\Chrome\User Data","$($op.Path)\AppData\Local\Microsoft\Edge\User Data","$($op.Path)\AppData\Local\BraveSoftware\Brave-Browser\User Data","$($op.Path)\AppData\Roaming\Opera Software\Opera Stable")) {
    if (Test-Path -LiteralPath $ud) {
      $h0 = Join-Path $ud 'History'; if (Test-Path -LiteralPath $h0) { $histFiles.Add($h0) }
      foreach ($pd in @(Get-ChildItem -LiteralPath $ud -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^(Default|Profile \d+)$' })) {
        $h = Join-Path $pd.FullName 'History'; if (Test-Path -LiteralPath $h) { $histFiles.Add($h) }
      }
    }
  }
  foreach ($fp in @(Get-ChildItem "$($op.Path)\AppData\Roaming\Mozilla\Firefox\Profiles" -Directory -ErrorAction SilentlyContinue)) {
    $pl = Join-Path $fp.FullName 'places.sqlite'; if (Test-Path -LiteralPath $pl) { $histFiles.Add($pl) }
  }
}
$asyncPs2 = $null; $asyncH2 = $null
try {
  $asyncPs2 = [powershell]::Create()
  [void]$asyncPs2.AddScript({
    param($patNG, $excl, $dirs, $histList)
    $out = New-Object System.Collections.Generic.List[object]
    $exts = 'zip','rar','7z','exe','msi','dll','scr','bat','cmd','ps1','jar','iso'
    $files = foreach ($d in $dirs) {
      Get-ChildItem -LiteralPath $d -Recurse -Depth 2 -File -Force -ErrorAction SilentlyContinue |
        Where-Object { $exts -contains $_.Extension.TrimStart('.').ToLower() }
    }
    $files = @($files | Sort-Object LastWriteTime -Descending | Select-Object -First 400)
    foreach ($f in $files) {
      try {
        $z = Get-Content -LiteralPath $f.FullName -Stream Zone.Identifier -ErrorAction Stop
        $u = (($z | Where-Object { $_ -match '^(HostUrl|ReferrerUrl)=' }) -join ' ')
        if ($u -match $patNG -and $u -notmatch $excl) { $out.Add([pscustomobject]@{ Kind='Zone'; Path=$f.FullName; Url=$u; Time=$f.LastWriteTime; Created=$f.CreationTime }) }
      } catch {}
    }
    foreach ($hf in $histList) {
      try {
        if ((Get-Item -LiteralPath $hf).Length -gt 300MB) { continue }
        $fs = [IO.File]::Open($hf, 'Open', 'Read', 'ReadWrite,Delete'); $ms = New-Object IO.MemoryStream; $fs.CopyTo($ms); $fs.Dispose()
        $text = [Text.Encoding]::GetEncoding(28591).GetString($ms.ToArray()); $ms.Dispose()
        $rx = New-Object Text.RegularExpressions.Regex(("(?i)https?://[\x21-\x7E]{0,160}?" + $patNG + "[\x21-\x7E]{0,160}"), [Text.RegularExpressions.RegexOptions]::None, [TimeSpan]::FromSeconds(4))
        $seen = New-Object 'System.Collections.Generic.HashSet[string]'
        foreach ($m in $rx.Matches($text)) {
          if ($seen.Count -ge 25) { break }
          if ($m.Value -notmatch $excl -and $seen.Add($m.Value)) { $out.Add([pscustomobject]@{ Kind='Web'; Path=$hf; Url=$m.Value }) }
        }
        # browser DOWNLOAD records keep the local file path: a downloaded tool shows here even after it was deleted
        $rxD = New-Object Text.RegularExpressions.Regex(("(?i)[A-Z]:\\[\x20-\x7E]{0,200}?" + $patNG + "[\x20-\x7E]{0,100}?\.(?:exe|zip|rar|7z|msi|dll|bat|scr)"), [Text.RegularExpressions.RegexOptions]::None, [TimeSpan]::FromSeconds(4))
        $seenD = New-Object 'System.Collections.Generic.HashSet[string]'
        foreach ($m in $rxD.Matches($text)) {
          if ($seenD.Count -ge 15) { break }
          if ($m.Value -notmatch $excl -and $seenD.Add($m.Value.ToLower())) { $out.Add([pscustomobject]@{ Kind='Dl'; Path=$m.Value; Url=$hf }) }
        }
      } catch {}
    }
    $out.ToArray()
  }).AddArgument($patNG).AddArgument($exclude).AddArgument(@($zoneDirs)).AddArgument(@($histFiles))
  $asyncH2 = $asyncPs2.BeginInvoke()
} catch {}

# ---------- Background job 3: look INSIDE unknown programs for Roblox-exploit API strings (works on renamed files) ----------
# Internal executors and bootstrappers contain Lua-exploit function names such as getgenv / hookfunction / identifyexecutor.
$apiStrings = @('getgenv','getrenv','getrawmetatable','setreadonly','hookfunction','hookmetamethod','newcclosure','checkcaller','identifyexecutor',
                'getnamecallmethod','fireclickdetector','firetouchinterest','getconnections','getscriptbytecode','queue_on_teleport','getthreadidentity','setthreadidentity')
$cRoots = New-Object System.Collections.Generic.List[object]
function Add-CRoot($p, $d) { if ($p -and (Test-Path -LiteralPath $p)) { $cRoots.Add(@{ Path=$p; Depth=$d }) } }
if ($doInternal) {
  $up2 = $env:USERPROFILE
  Add-CRoot "$up2\Downloads" 5; Add-CRoot "$up2\Desktop" 4; Add-CRoot "$up2\Documents" 4; Add-CRoot "$up2\OneDrive" 3
  Add-CRoot $env:LOCALAPPDATA 3; Add-CRoot $env:APPDATA 3; Add-CRoot $env:ProgramData 2; Add-CRoot $env:TEMP 2
  foreach ($op in $readableProfiles) {
    Add-CRoot "$($op.Path)\Downloads" 5; Add-CRoot "$($op.Path)\Desktop" 4; Add-CRoot "$($op.Path)\Documents" 4
    Add-CRoot "$($op.Path)\AppData\Local" 3; Add-CRoot "$($op.Path)\AppData\Roaming" 3
  }
}
foreach ($v in $volMap.Values) {
  if ($v.Letter -eq $sysLetter) { continue }
  if (($v.DriveType -eq 2 -and $doExternal) -or ($v.DriveType -eq 3 -and ($doInternal -or $doExternal))) { Add-CRoot "$($v.Letter):\" 3 }
}
$bagC = New-Object 'System.Collections.Concurrent.ConcurrentBag[object]'
$asyncPs3 = $null; $asyncH3 = $null
try {
  $asyncPs3 = [powershell]::Create()
  [void]$asyncPs3.AddScript({
    param($roots, $api, $bag, $secs, $hashes, $mxMagic, $stemAll, $trustedPub, $exclude)
    $deadline = (Get-Date).AddSeconds($secs)
    $skipDir = '(?i)\\(node_modules|\.git|Cache|Code Cache|GPUCache|WindowsApps|Packages|Google|Mozilla|BraveSoftware|Steam|Epic Games|Discord|Spotify|JetBrains|Visual Studio|Adobe|NVIDIA|AMD|Intel|INetCache|WebCache|Roblox|\$Recycle\.Bin|System Volume Information)(\\|$)'
    $luaRx = New-Object Text.RegularExpressions.Regex('loadstring\s*\(\s*game\s*:\s*HttpGet|getgenv\s*\(|hookfunction\s*\(|hookmetamethod\s*\(|identifyexecutor\s*\(', 'IgnoreCase', [TimeSpan]::FromSeconds(2))
    $enc = [Text.Encoding]::GetEncoding(28591)
    $sha = [Security.Cryptography.SHA256]::Create()
    $noiseExt = '^\.(png|jpe?g|gif|bmp|ico|webp|svg|json|js|css|html?|xml|md|pdf|mp3|mp4|wav|ogg|ttf|otf|woff2?|pak|lnk|log|ini|cfg|csv)$'
    # AutoHotkey macros: judged by WHAT THEY DO. A script is only flagged if it (1) mentions Roblox and (2) automates input
    # (loops/timers/screen search/mouse control). Scripts with nothing to do with Roblox, or plain hotkey remaps, are ignored.
    $uniSacred = (('SacredStep'.ToCharArray() | ForEach-Object { "$_`0" }) -join '')
    $uniRbx = (('RobloxPlayerBeta'.ToCharArray() | ForEach-Object { "$_`0" }) -join '')
    $uniAhk = (('AutoHotkey'.ToCharArray() | ForEach-Object { "$_`0" }) -join '')
    $uniRoblox = (('Roblox'.ToCharArray() | ForEach-Object { "$_`0" }) -join '')
    function Test-Ahk($text, $leaf) {
      if ($text -notmatch '(?i)roblox|WINDOWSCLIENT') { return $null }
      $repeat = $text -match '(?i)\bLoop\b|\bWhile\b|SetTimer'
      $pix    = $text -match '(?i)PixelSearch|PixelGetColor|ImageSearch'
      $mouse  = $text -match '(?i)MouseMove|MouseClickDrag|DllCall[^\r\n]{0,60}(?:mouse_event|SetCursorPos|SendInput)'
      $click  = $text -match '(?i)\bClick\b|MouseClick|ControlClick'
      $keys   = $text -match '(?i)\bSend(?:Input|Event|Play|Raw)?\b|ControlSend|SendMessage|PostMessage'
      if (-not ($repeat -or $pix -or $mouse)) { return $null }
      if (-not ($pix -or $mouse -or $click -or $keys)) { return $null }
      $hay = "$leaf`n$text"
      $sc = @{ aimbot = 0; trigger = 0; autoclick = 0; skill = 0; boost = 0; farm = 0; esp = 0; lag = 0 }
      $why = New-Object System.Collections.Generic.List[string]
      if ($hay -match '(?i)aim\s*-?bot|aim\s*assist|aim\s*lock|cam\s*lock|silent\s*aim|target\s*lock|lock\s*-?on|\baim\b|snap\s*to|head\s*shot|\btrack(?:er|ing)?\b') { $sc.aimbot += 4; $why.Add('aim / lock-on wording') }
      if ($pix -and $mouse) { $sc.aimbot += 3; $why.Add('finds a color/image on screen and moves the mouse to it') }
      if ($hay -match '(?i)trigger\s*-?bot|auto\s*-?shoot|auto\s*-?fire|rapid\s*-?fire') { $sc.trigger += 4; $why.Add('triggerbot wording') }
      if ($pix -and $click -and -not $mouse) { $sc.trigger += 3; $why.Add('clicks when a color/image appears on screen') }
      if ($hay -match '(?i)auto\s*-?click|clicker|\bcps\b') { $sc.autoclick += 4; $why.Add('auto-click wording') }
      if ($click -and $repeat -and -not $pix) { $sc.autoclick += 2; $why.Add('repeats clicks in a loop') }
      if ($hay -match '(?i)skill|abilit(?:y|ies)|combo|\bspam|\bcast\b|\bult(?:imate)?\b|move\s*\d|\bm1\b|auto\s*-?(?:use|skill|move|combat|attack)|rotation') { $sc.skill += 3; $why.Add('skill / combo wording') }
      if ($keys -and $repeat) { $sc.skill += 2; $why.Add('sends keys repeatedly') }
      if ($hay -match '(?i)boost|dash|speed|b-?hop|glitch|\bfly\b|no\s*-?clip|teleport|\btp\b|slide|sprint') { $sc.boost += 3; $why.Add('boost / dash / movement wording') }
      if ($hay -match '(?i)farm|fishing|\bfish\b|grind|auto\s*-?(?:quest|collect|loot)|anti\s*-?afk|\bafk\b|\bidle\b') { $sc.farm += 4; $why.Add('farm / fishing / AFK wording') }
      if ($hay -match '(?i)\besp\b|wall\s*-?hack|radar|chams') { $sc.esp += 3; $why.Add('ESP / radar wording') }
      if ($hay -match '(?i)lag\s*-?switch|desync|fake\s*lag') { $sc.lag += 4; $why.Add('lag switch / desync wording') }
      $best = $sc.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 1
      $key = if ($best.Value -ge 3) { $best.Key } else { 'generic' }
      $fn = New-Object System.Collections.Generic.List[string]
      if ($pix) { $fn.Add('screen search') }; if ($mouse) { $fn.Add('mouse control') }; if ($click) { $fn.Add('clicking') }; if ($keys) { $fn.Add('key sending') }; if ($repeat) { $fn.Add('loop/timer') }
      [pscustomobject]@{ Key = $key; Why = ((@($why | Select-Object -Unique) + @('uses: ' + ($fn -join ', '))) -join '; ') }
    }
    $q = New-Object System.Collections.Generic.Queue[object]
    foreach ($r in $roots) { $q.Enqueue(@($r.Path, [int]$r.Depth)) }
    $nf = 0; $nl = 0; $bytes = 0L; $cut = $false
    $mx = New-Object 'System.Collections.Generic.HashSet[string]'
    while ($q.Count -gt 0) {
      if ((Get-Date) -gt $deadline) { $cut = $true; break }
      $c = $q.Dequeue(); $dir = $c[0]; $dep = $c[1]
      try {
        foreach ($f in [IO.Directory]::EnumerateFiles($dir)) {
          $ext = [IO.Path]::GetExtension($f).ToLower()
          if ($ext -eq '.dat' -or $f -match '(?i)\\oldui\.exe$') {
            $lf = [IO.Path]::GetFileName($f).ToLower()
            if ($mx.Count -lt 60 -and ($lf -eq 'oldui.exe' -or $lf -match '^_license([ _(]\d+\)?)?\.dat$')) { [void]$mx.Add($dir) }
            elseif ($mx.Count -lt 60 -and $lf -match '^version([ _(]\d+\)?)?\.dat$') { try { if ((New-Object IO.FileInfo $f).Length -ge 5MB) { [void]$mx.Add($dir) } } catch {} }
          }
          # A program can be renamed to anything (.txt, .dat, no extension): treat any file that STARTS like a Windows program as one
          $isPE = ($ext -eq '.exe' -or $ext -eq '.dll')
          if (-not $isPE -and $ext -notmatch $noiseExt) {
            try { $fi0 = New-Object IO.FileInfo $f; $l0 = $fi0.Length } catch { $l0 = 0 }
            if ($l0 -eq 48) { try { if (([IO.File]::ReadAllText($f)).Trim() -match '^[a-z0-9]{6}(-[a-z0-9]{6}){6}$') { [void]$mx.Add($dir) } } catch {} }
            elseif ($l0 -ge 20480 -and $l0 -le 60MB -and $ext -ne '.ahk' -and $ext -ne '.lua' -and $ext -ne '.luau') {
              try {
                $fsx = [IO.File]::Open($f, 'Open', 'Read', 'ReadWrite')
                try { $hb = New-Object byte[] 32; [void]$fsx.Read($hb, 0, 32) } finally { $fsx.Close() }
                if ($hb[0] -eq 0x4D -and $hb[1] -eq 0x5A) { $isPE = $true }
                elseif ($l0 -ge 5MB -and $mx.Count -lt 60 -and (([BitConverter]::ToString($hb) -replace '-', '').ToLower()) -eq $mxMagic) { [void]$mx.Add($dir) }
              } catch {}
            }
          }
          if ($isPE) {
            try { $fi = New-Object IO.FileInfo $f; $len = $fi.Length } catch { continue }
            if ($len -lt 1024 -or $len -gt 60MB -or $bytes -gt 900MB) { continue }
            $bytes += $len; $nf++
            try { $raw = [IO.File]::ReadAllBytes($f) } catch { continue }
            $hx = ([BitConverter]::ToString($sha.ComputeHash($raw)) -replace '-', '').ToLower()
            if ($hashes.ContainsKey($hx)) { $bag.Add([pscustomobject]@{ Kind='Hash'; Path=$f; Name=$hashes[$hx]; Mod=$fi.LastWriteTime; Created=$fi.CreationTime }) }
            # The name stored INSIDE a program (original file name / product name) survives renaming
            try {
              $vi = [Diagnostics.FileVersionInfo]::GetVersionInfo($f)
              if ("$($vi.CompanyName)" -notmatch $trustedPub) {
                foreach ($fv in @($vi.OriginalFilename, $vi.InternalName, $vi.ProductName, $vi.FileDescription)) {
                  if ($fv -and "$fv" -notmatch $exclude -and (("$fv".Trim()) -replace '\.(exe|dll)$', '') -match $stemAll) {
                    $bag.Add([pscustomobject]@{ Kind='Meta'; Path=$f; Value="$fv"; Mod=$fi.LastWriteTime; Created=$fi.CreationTime }); break
                  }
                }
              }
            } catch {}
            if ($len -lt 40960) { continue }
            $t = $enc.GetString($raw)
            if ($t.IndexOf($uniSacred, [StringComparison]::Ordinal) -ge 0) { $bag.Add([pscustomobject]@{ Kind='Str'; Path=$f; Name='sacredstep'; Mod=$fi.LastWriteTime; Created=$fi.CreationTime }) }
            # Compiled AutoHotkey program (.exe made from an .ahk): the script text is stored inside it, so read it from there
            if ($t.IndexOf('AutoHotkey', [StringComparison]::OrdinalIgnoreCase) -ge 0 -or $t.IndexOf($uniAhk, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
              $chunk = $null
              $ri = $t.IndexOf('Roblox', [StringComparison]::OrdinalIgnoreCase)
              if ($ri -ge 0) { $cs = [math]::Max(0, $ri - 6000); $chunk = $t.Substring($cs, [math]::Min(14000, $t.Length - $cs)) }
              else {
                $ru = $t.IndexOf($uniRoblox, [StringComparison]::OrdinalIgnoreCase)
                if ($ru -ge 0) { $us = [math]::Max(0, $ru - 12000); if (($us % 2) -ne ($ru % 2)) { $us++ }; $ul = [math]::Min(28000, $raw.Length - $us); $chunk = [Text.Encoding]::Unicode.GetString($raw, $us, ($ul - ($ul % 2))) }
              }
              if ($chunk) {
                $ar = Test-Ahk $chunk ([IO.Path]::GetFileNameWithoutExtension($f))
                if ($ar) { $bag.Add([pscustomobject]@{ Kind='Ahk'; Path=$f; Cat=$ar.Key; Hits=($ar.Why + '; this is a compiled AutoHotkey program'); Mod=$fi.LastWriteTime; Created=$fi.CreationTime }) }
              }
            }
            # An EXTERNAL cheat must find the Roblox process and read/write its memory: that is visible inside the program whatever it is called.
            # v2: also catches programs that never write the process name but contain several Roblox-internals names (DataModel, VisualEngine...) + memory APIs.
            $hasRbx = ($t.IndexOf('RobloxPlayerBeta', [StringComparison]::Ordinal) -ge 0) -or ($t.IndexOf($uniRbx, [StringComparison]::Ordinal) -ge 0)
            $rbxInt = 0
            foreach ($rs in 'VisualEngine','DataModel','TaskScheduler','ScriptContext','RenderView','FakeDataModel','LocalPlayer','Humanoid') { if ($t.IndexOf($rs, [StringComparison]::Ordinal) -ge 0) { $rbxInt++ } }
            if ($hasRbx -or $rbxInt -ge 4) {
              $xw = New-Object System.Collections.Generic.List[string]
              if ($t.IndexOf('ReadProcessMemory', [StringComparison]::Ordinal) -ge 0 -or $t.IndexOf('NtReadVirtualMemory', [StringComparison]::Ordinal) -ge 0) { $xw.Add('reads other programs memory') }
              if ($t.IndexOf('WriteProcessMemory', [StringComparison]::Ordinal) -ge 0 -or $t.IndexOf('NtWriteVirtualMemory', [StringComparison]::Ordinal) -ge 0) { $xw.Add('writes other programs memory') }
              if ($t.IndexOf('keyauth', [StringComparison]::OrdinalIgnoreCase) -ge 0) { $xw.Add('uses the KeyAuth license system (common in cheat loaders)') }
              if ($rbxInt -ge 4) { $xw.Add("contains $rbxInt Roblox-internals names (DataModel / VisualEngine / TaskScheduler ...)") }
              $needMem = @($xw | Where-Object { $_ -match 'memory|KeyAuth' }).Count -ge 1
              if ($needMem -and ($hasRbx -or $xw.Count -ge 2)) { $bag.Add([pscustomobject]@{ Kind='Ext'; Path=$f; Hits=($xw -join ', '); Mod=$fi.LastWriteTime; Created=$fi.CreationTime; Named=$hasRbx }) }
            }
            $hit = New-Object System.Collections.Generic.List[string]
            foreach ($a in $api) { if ($t.IndexOf($a, [StringComparison]::Ordinal) -ge 0) { $hit.Add($a) } }
            if ($hit.Count -ge 4) { $bag.Add([pscustomobject]@{ Kind='Bin'; Path=$f; Hits=($hit -join ', '); Mod=$fi.LastWriteTime; Created=$fi.CreationTime }) }
          }
          elseif ($ext -eq '.ahk') {
            try {
              if ($f -match '(?i)\\Program Files|\\AutoHotkey\\(?:v[12]\\)?(?:Lib|Compiler|UX)\\') { continue }
              $fi = New-Object IO.FileInfo $f
              if ($fi.Length -gt 2MB -or $fi.Length -lt 50) { continue }
              $nl++
              $ar = Test-Ahk ([IO.File]::ReadAllText($f)) ([IO.Path]::GetFileNameWithoutExtension($f))
              if (-not $ar -and [IO.Path]::GetFileNameWithoutExtension($f) -match '(?i)visionary|ahk[-_. ]?society|sacred[-_. ]?step') { $ar = [pscustomobject]@{ Key='generic'; Why='the file name matches a known macro tool' } }
              if ($ar) { $bag.Add([pscustomobject]@{ Kind='Ahk'; Path=$f; Cat=$ar.Key; Hits=$ar.Why; Mod=$fi.LastWriteTime; Created=$fi.CreationTime }) }
            } catch {}
          }
          elseif ($ext -eq '.txt') {
            try {
              $fi = New-Object IO.FileInfo $f
              if ($fi.Length -gt 262144 -or $fi.Length -lt 50) { continue }
              $nl++
              $tx = [IO.File]::ReadAllText($f)
              if ($luaRx.IsMatch($tx)) { $bag.Add([pscustomobject]@{ Kind='Lua'; Path=$f; Hits=''; Mod=$fi.LastWriteTime; Created=$fi.CreationTime }) }
              $ar = Test-Ahk $tx ([IO.Path]::GetFileNameWithoutExtension($f))
              if ($ar) { $bag.Add([pscustomobject]@{ Kind='Ahk'; Path=$f; Cat=$ar.Key; Hits=$ar.Why; Mod=$fi.LastWriteTime; Created=$fi.CreationTime }) }
            } catch {}
          }
          elseif ($ext -eq '.lua' -or $ext -eq '.luau') {
            try { $fi = New-Object IO.FileInfo $f; if ($fi.Length -gt 3MB) { continue }; $nl++
                  $lt = [IO.File]::ReadAllText($f)
                  if ($luaRx.IsMatch($lt)) { $bag.Add([pscustomobject]@{ Kind='Lua'; Path=$f; Hits=''; Mod=$fi.LastWriteTime; Created=$fi.CreationTime }) } } catch {}
          }
        }
      } catch {}
      if ($dep -ge 1) {
        try {
          foreach ($d in [IO.Directory]::EnumerateDirectories($dir)) {
            if ($d -match $skipDir) { continue }
            try { if (([IO.File]::GetAttributes($d) -band [IO.FileAttributes]::ReparsePoint) -ne 0) { continue } } catch { continue }
            $q.Enqueue(@($d, ($dep - 1)))
          }
        } catch {}
      }
    }
    foreach ($md in $mx) { $bag.Add([pscustomobject]@{ Kind='MxDir'; Path=$md }) }
    $bag.Add([pscustomobject]@{ Kind='Stat'; Files=$nf; Lua=$nl; Cut=$cut })
  }).AddArgument($cRoots.ToArray()).AddArgument($apiStrings).AddArgument($bagC).AddArgument(9).AddArgument($knownHashes).AddArgument($mxMagic).AddArgument($stemAll).AddArgument($trustedPub).AddArgument($exclude)
  $asyncH3 = $asyncPs3.BeginInvoke()
} catch {}

Set-Stage 'Reading Windows history'
# ---------- 2. Windows history (internal evidence: fast registry/file lookups) ----------
Set-Stage 'Looking for executor-style file names'
# v2.1: name-INDEPENDENT check. New or renamed tools are often called "Roblox Executor", "Byfron Bypass", "RBX Injector", "Level 8 Executor" ...
$kwRx = '(?i)(?:roblox|rbx|blox)[-_. ]*(?:executor|exploit|injector|bypass|cheat|hack|hax|script[-_. ]*hub|external|aimbot)s?|(?:executor|exploit|injector|bypass)[-_. ]*(?:for[-_. ]*)?(?:roblox|rbx)|byfron|hyperion[-_. ]*bypass|(?:level|lvl)[-_. ]*[78][-_. ]*(?:executor|exploit)|free[-_. ]*(?:roblox[-_. ]*)?executor'
$kwRoots = New-Object System.Collections.Generic.List[string]
foreach ($b in @("$env:USERPROFILE\Downloads","$env:USERPROFILE\Desktop","$env:USERPROFILE\Documents",$env:TEMP)) { if ($b -and (Test-Path -LiteralPath $b)) { $kwRoots.Add($b) } }
foreach ($op in $readableProfiles) { foreach ($sub in 'Downloads','Desktop') { $kp = Join-Path $op.Path $sub; if (Test-Path -LiteralPath $kp) { $kwRoots.Add($kp) } } }
foreach ($v in $volMap.Values) { if (($v.DriveType -eq 2 -or $v.DriveType -eq 3) -and $v.Letter -ne $sysLetter) { $kwRoots.Add("$($v.Letter):\") } }
$kwDeadline = (Get-Date).AddSeconds(3); $kwCount = 0
foreach ($kr in $kwRoots) {
  if ((Get-Date) -gt $kwDeadline -or $kwCount -ge 15) { break }
  foreach ($kf in @(Get-ChildItem -LiteralPath $kr -Recurse -Depth 3 -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.Extension -match '(?i)^\.(exe|dll|zip|rar|7z|msi|bat|lnk|scr|jar)$' } | Select-Object -First 3000)) {
    if ($kwCount -ge 15 -or (Get-Date) -gt $kwDeadline) { break }
    $kn = Norm-Name $kf.Name
    if ($kn -notmatch $kwRx -or $kn -match $exclude -or (Match-Leaf $kf.Name $false)) { continue }
    $kwCount++
    Add-Ev @{ Name=$unkKw; Src='File name looks like an executor'; Path=$kf.FullName; PresentNow=$true; Mod=$kf.LastWriteTime; Created=$kf.CreationTime; Note="the file name matches an executor / bypass / injector pattern: $($kf.Name)" }
  }
}
Set-Stage 'Looking inside downloaded .zip files'
# v2.3: a downloaded executor is often still a .zip. The file LIST inside the zip is read (nothing is extracted or run).
$zipOk = $false
try { Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop; $zipOk = $true } catch {}
if ($zipOk) {
  $zDeadline = (Get-Date).AddSeconds(3); $zHits = 0
  foreach ($zr in $kwRoots) {
    if ((Get-Date) -gt $zDeadline -or $zHits -ge 10) { break }
    foreach ($zf in @(Get-ChildItem -LiteralPath $zr -Recurse -Depth 3 -File -Force -Filter *.zip -ErrorAction SilentlyContinue | Where-Object { $_.Length -lt 300MB } | Select-Object -First 60)) {
      if ((Get-Date) -gt $zDeadline -or $zHits -ge 10) { break }
      try {
        $za = [IO.Compression.ZipFile]::OpenRead($zf.FullName)
        try {
          foreach ($en in @($za.Entries | Select-Object -First 400)) {
            $efull = "$($en.FullName)"
            $ename = Norm-Name $efull
            if ($ename -match $exclude) { continue }
            $nm = Match-Leaf (Leaf-Of ($efull -replace '/','\')) $false
            $isKw = ($ename -match $kwRx)
            $isAuto = ($ename -match '(?i)(^|/)autoexec/')
            if (-not ($nm -or $isKw -or $isAuto)) { continue }
            if (-not $nm) { $nm = Find-NameToken $zf.Name }
            if (-not $nm) { $nm = if ($isKw) { $unkKw } else { $unkName } }
            $zHits++
            Add-Ev @{ Name=$nm; Src='Inside archive'; Path=$zf.FullName; PresentNow=$true; Mod=$zf.LastWriteTime; Created=$zf.CreationTime; Note="the zip file contains '$efull'" }
            break
          }
        } finally { $za.Dispose() }
      } catch {}
    }
  }
}
Set-Stage 'Looking for executor editor folders (Monaco)'
# v2.3: many executors ship a "monaco" folder (the script editor) next to their program. Judged by layout, not by name.
$mnDeadline = (Get-Date).AddSeconds(2); $mnHits = 0
foreach ($mr in @($kRoots)) {
  if ((Get-Date) -gt $mnDeadline -or $mnHits -ge 8) { break }
  foreach ($md in @(Get-ChildItem -LiteralPath $mr -Directory -Recurse -Depth 4 -Filter monaco -Force -ErrorAction SilentlyContinue | Select-Object -First 20)) {
    if ($mnHits -ge 8) { break }
    $mpar = Split-Path -Parent $md.FullName
    if (-not $mpar -or $mpar -match $exclude -or $mpar -match '(?i)\\(Microsoft VS Code|Code|Visual Studio|JetBrains|Cursor|resources|app)(\\|$)') { continue }
    $mi = Inspect-Folder $mpar
    if (-not $mi.HasExec) { continue }
    if (-not (($mi.Subdirs -contains 'workspace') -or ($mi.Subdirs -contains 'autoexec') -or ($mi.Subdirs -contains 'scripts') -or ($mi.Subdirs -contains 'bin'))) { continue }
    $mn = Find-NameToken ("$mpar " + ($mi.Files -join ' '))
    if (-not $mn) { $mn = $unkName }
    $mnHits++
    $mfi = Get-Item -LiteralPath $mpar -Force -ErrorAction SilentlyContinue
    Add-Ev @{ Name=$mn; Src='Executor folder layout (Monaco editor)'; Path=$mpar; HasExec=$true; Mod=$mfi.LastWriteTime; Created=$mfi.CreationTime; Note="has a 'monaco' editor folder next to a program and script folders (typical executor layout)" }
  }
}
# Running processes
Set-Stage 'Checking running processes'
Get-Process | Where-Object { Test-Hit $_.Name } | ForEach-Object {
  $pp = "$($_.Path)"
  $n = Match-Leaf (Leaf-Of $pp) $true
  if (-not $n) { $n = Match-Leaf $_.Name $true }
  if ($n) { Add-Ev @{ Name=$n; Src='Running process'; Path=$(if ($pp) { $pp } else { $null }); PresentNow=$true; Run=(Get-Date); RunKind='running right now' } }
}
# A process running from a folder that has an executor's name (the .exe itself may be renamed)
try {
  Get-CimInstance Win32_Process -ErrorAction Stop | ForEach-Object {
    $ep = "$($_.ExecutablePath)"
    if (-not $ep -or $ep -match $exclude) { return }
    if (Match-Leaf (Leaf-Of $ep) $false) { return }
    $parts = @($ep -split '\\')
    for ($pi = 1; $pi -lt $parts.Count - 1; $pi++) {
      $n = Match-Leaf $parts[$pi] $true
      if ($n) { Add-Ev @{ Name=$n; Src='Running process'; Path=$ep; PresentNow=$true; Run=(Get-Date); RunKind='running right now'; Note="running from a folder named '$($parts[$pi])'" }; break }
    }
  }
} catch {}
# v2: the COMMAND LINE of every running process (catches "powershell -c irm https://xeno... | iex", "cmd /c start loader.exe xeno", renamed hosts)
try {
  $cmdSkip = '(?i)^(chrome|msedge|firefox|brave|opera|iexplore|discord|spotify|code|notepad|notepad\+\+|explorer|slack|teams|conhost|searchhost|svchost|runtimebroker|taskmgr|dllhost)(\.exe)?$'
  foreach ($cp in @(Get-CimInstance Win32_Process -ErrorAction Stop)) {
    if ($cp.ProcessId -eq $PID) { continue }
    $cl = "$($cp.CommandLine)"
    if ($cl.Length -lt 6 -or "$($cp.Name)" -match $cmdSkip) { continue }
    $cl2 = Norm-Name $cl
    if ($cl2 -match $exclude -or $cl2 -notmatch $patNG) { continue }
    $nt = Find-NameToken $cl2
    if ($nt -and ($genericNames -notcontains $nt)) {
      $cp0 = "$($cp.ExecutablePath)"
      Add-Ev @{ Name=$nt; Src='Running process (command line)'; Path=$(if ($cp0) { $cp0 } else { $null }); PresentNow=$true; Run=(Get-Date); RunKind='running right now'
                Note=("command line of '$($cp.Name)' mentions it: " + $(if ($cl.Length -gt 140) { $cl.Substring(0,140) + '...' } else { $cl })) }
    }
  }
} catch {}
# A renamed program that is running right now: check what the file says it really is, and its SHA256
try {
  $rpSeen = @{}
  foreach ($rp in @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path } | Select-Object -First 250)) {
    $pp = "$($rp.Path)"
    if ($rpSeen.ContainsKey($pp.ToLower()) -or $pp.StartsWith($env:windir, [StringComparison]::OrdinalIgnoreCase) -or $pp -match $exclude) { continue }
    $rpSeen[$pp.ToLower()] = 1
    $why = $null; $nn = $null
    try {
      $vi = $rp.MainModule.FileVersionInfo
      if ("$($vi.CompanyName)" -notmatch $trustedPub) {
        foreach ($fv in @($vi.OriginalFilename, $vi.InternalName, $vi.ProductName, $vi.FileDescription)) {
          if ($fv -and "$fv" -notmatch $exclude) {
            $nn = Match-Leaf ((("$fv").Trim() -replace '\.(exe|dll)$', '') + '.exe') $false
            if ($nn) { $why = "the program's built-in name says '$fv'"; break }
          }
        }
      }
    } catch {}
    if (-not $nn) {
      try {
        if ((New-Object IO.FileInfo $pp).Length -le 60MB) {
          $hh = (Get-FileHash -LiteralPath $pp -Algorithm SHA256).Hash.ToLower()
          if ($knownHashes.ContainsKey($hh)) { $nn = $knownHashes[$hh]; $why = 'its SHA256 matches a known sample' }
        }
      } catch {}
    }
    if ($nn) { Add-Ev @{ Name=$nn; Src='Running process'; Path=$pp; PresentNow=$true; Run=(Get-Date); RunKind='running right now'; Note="running as '$(Leaf-Of $pp)' but $why" } }
  }
} catch {}
function Test-Ahk($text, $leaf) {
  if ($text -notmatch '(?i)roblox|WINDOWSCLIENT') { return $null }
  $repeat = $text -match '(?i)\bLoop\b|\bWhile\b|SetTimer'
  $pix    = $text -match '(?i)PixelSearch|PixelGetColor|ImageSearch'
  $mouse  = $text -match '(?i)MouseMove|MouseClickDrag|DllCall[^\r\n]{0,60}(?:mouse_event|SetCursorPos|SendInput)'
  $click  = $text -match '(?i)\bClick\b|MouseClick|ControlClick'
  $keys   = $text -match '(?i)\bSend(?:Input|Event|Play|Raw)?\b|ControlSend|SendMessage|PostMessage'
  if (-not ($repeat -or $pix -or $mouse)) { return $null }
  if (-not ($pix -or $mouse -or $click -or $keys)) { return $null }
  $hay = "$leaf`n$text"
  $sc = @{ aimbot = 0; trigger = 0; autoclick = 0; skill = 0; boost = 0; farm = 0; esp = 0; lag = 0 }
  $why = New-Object System.Collections.Generic.List[string]
  if ($hay -match '(?i)aim\s*-?bot|aim\s*assist|aim\s*lock|cam\s*lock|silent\s*aim|target\s*lock|lock\s*-?on|\baim\b|snap\s*to|head\s*shot|\btrack(?:er|ing)?\b') { $sc.aimbot += 4; $why.Add('aim / lock-on wording') }
  if ($pix -and $mouse) { $sc.aimbot += 3; $why.Add('finds a color/image on screen and moves the mouse to it') }
  if ($hay -match '(?i)trigger\s*-?bot|auto\s*-?shoot|auto\s*-?fire|rapid\s*-?fire') { $sc.trigger += 4; $why.Add('triggerbot wording') }
  if ($pix -and $click -and -not $mouse) { $sc.trigger += 3; $why.Add('clicks when a color/image appears on screen') }
  if ($hay -match '(?i)auto\s*-?click|clicker|\bcps\b') { $sc.autoclick += 4; $why.Add('auto-click wording') }
  if ($click -and $repeat -and -not $pix) { $sc.autoclick += 2; $why.Add('repeats clicks in a loop') }
  if ($hay -match '(?i)skill|abilit(?:y|ies)|combo|\bspam|\bcast\b|\bult(?:imate)?\b|move\s*\d|\bm1\b|auto\s*-?(?:use|skill|move|combat|attack)|rotation') { $sc.skill += 3; $why.Add('skill / combo wording') }
  if ($keys -and $repeat) { $sc.skill += 2; $why.Add('sends keys repeatedly') }
  if ($hay -match '(?i)boost|dash|speed|b-?hop|glitch|\bfly\b|no\s*-?clip|teleport|\btp\b|slide|sprint') { $sc.boost += 3; $why.Add('boost / dash / movement wording') }
  if ($hay -match '(?i)farm|fishing|\bfish\b|grind|auto\s*-?(?:quest|collect|loot)|anti\s*-?afk|\bafk\b|\bidle\b') { $sc.farm += 4; $why.Add('farm / fishing / AFK wording') }
  if ($hay -match '(?i)\besp\b|wall\s*-?hack|radar|chams') { $sc.esp += 3; $why.Add('ESP / radar wording') }
  if ($hay -match '(?i)lag\s*-?switch|desync|fake\s*lag') { $sc.lag += 4; $why.Add('lag switch / desync wording') }
  $best = $sc.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 1
  $key = if ($best.Value -ge 3) { $best.Key } else { 'generic' }
  $fn = New-Object System.Collections.Generic.List[string]
  if ($pix) { $fn.Add('screen search') }; if ($mouse) { $fn.Add('mouse control') }; if ($click) { $fn.Add('clicking') }; if ($keys) { $fn.Add('key sending') }; if ($repeat) { $fn.Add('loop/timer') }
  [pscustomobject]@{ Key = $key; Why = ((@($why | Select-Object -Unique) + @('uses: ' + ($fn -join ', '))) -join '; ') }
}
# AutoHotkey scripts that are running right now: read the script the interpreter was started with (any file name / extension)
try {
  foreach ($ap in @(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object { $_.Name -match '(?i)^autohotkey' })) {
    $cl = "$($ap.CommandLine)"
    foreach ($tm in [regex]::Matches($cl, '"([^"]+)"|(\S+)')) {
      $tp = if ($tm.Groups[1].Success) { $tm.Groups[1].Value } else { $tm.Groups[2].Value }
      if ($tp -like '/*' -or $tp -eq "$($ap.ExecutablePath)" -or -not (Test-Path -LiteralPath $tp -PathType Leaf -ErrorAction SilentlyContinue)) { continue }
      $fi2 = New-Object IO.FileInfo $tp
      if ($fi2.Length -gt 2MB -or $fi2.Length -lt 50) { continue }
      $ar2 = Test-Ahk ([IO.File]::ReadAllText($tp)) ([IO.Path]::GetFileNameWithoutExtension($tp))
      if ($ar2) {
        $an2 = Find-NameToken $tp; if (-not $an2 -and $tp -match '(?i)visionary') { $an2 = 'visionary' }
        if (-not $an2) { $an2 = $ahkPseudo[$ar2.Key] }
        Add-Ev @{ Name=$an2; Src='Running AutoHotkey macro that targets Roblox'; Path=$tp; PresentNow=$true; Run=(Get-Date); RunKind='running right now'; Mod=$fi2.LastWriteTime; Created=$fi2.CreationTime; Note=("AutoHotkey script running right now: " + $ahkLabel[$ar2.Key] + " - " + $ar2.Why) }
      }
    }
  }
} catch {}
Set-Stage 'Checking which programs have memory access to Roblox'
# External cheats read/write Roblox through memory. A program that holds a memory-capable handle to Roblox is reported,
# EXCEPT FFlag injectors (they write Roblox fast flags through memory offsets and are not cheats).
$memNote = ''
$flagSeen = New-Object System.Collections.Generic.List[string]
function Test-FlagTool($path, $leaf) {
  if ($leaf -match $flagToolRx) { return $true }
  try {
    if ((New-Object IO.FileInfo $path).Length -gt 40MB) { return $false }
    $raw = [IO.File]::ReadAllBytes($path)
    $a = [Text.Encoding]::GetEncoding(28591).GetString($raw)
    $u = [Text.Encoding]::Unicode.GetString($raw)
    $cnt = 0
    foreach ($tk in 'DFFlag','FFlag','DFInt','FInt','DFString','FString','DFLog','FLog') {
      foreach ($txt in $a, $u) { $i = 0; while ($cnt -lt 50) { $i = $txt.IndexOf($tk, $i, [StringComparison]::Ordinal); if ($i -lt 0) { break }; $cnt++; $i += $tk.Length } }
    }
    if ($cnt -lt 5) { return $false }
    $exec = 0; foreach ($s in $apiStrings) { if ($a.IndexOf($s, [StringComparison]::Ordinal) -ge 0) { $exec++ } }
    $aim = $false; foreach ($s in 'aimbot','triggerbot','camlock','silentaim','wallhack','esp_') { if ($a.IndexOf($s, [StringComparison]::OrdinalIgnoreCase) -ge 0) { $aim = $true } }
    return ($exec -lt 2 -and -not $aim)
  } catch { return $false }
}
$rbxProcs = @()
try {
  $rbxProcs = @(Get-Process -Name 'RobloxPlayerBeta' -ErrorAction SilentlyContinue)
  if ($rbxProcs.Count -eq 0) { $memNote = 'Memory-access check skipped: Roblox was not running during the scan (open Roblox and scan again to use it).' }
  elseif ([IntPtr]::Size -ne 8) { $memNote = 'Memory-access check skipped: needs 64-bit PowerShell.' }
  else {
    $hDll = Join-Path $env:TEMP 'JHORFGU_QHnd_v2.dll'
    $hSrc = @'
using System; using System.Collections.Generic; using System.Runtime.InteropServices;
public static class QHnd {
  [DllImport("ntdll.dll")] static extern int NtQuerySystemInformation(int c, IntPtr b, int l, out int r);
  [DllImport("kernel32.dll")] static extern IntPtr OpenProcess(uint a, bool i, int p);
  [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
  [DllImport("kernel32.dll")] static extern bool DuplicateHandle(IntPtr sp, IntPtr sh, IntPtr tp, out IntPtr th, uint a, bool i, uint o);
  [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
  [DllImport("kernel32.dll")] static extern int GetProcessId(IntPtr h);
  delegate bool EnumProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] static extern bool EnumWindows(EnumProc p, IntPtr l);
  [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll", EntryPoint = "GetWindowLongW")] static extern int GetWindowLong(IntPtr h, int i);
  struct RECT { public int L, T, R, B; }
  [DllImport("user32.dll")] static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetWindowText(IntPtr h, System.Text.StringBuilder s, int n);
  // Visible, always-on-top, layered (see-through capable) windows of at least 200x200: how ESP overlays of external cheats are drawn.
  // Returns "pid|exStyle|left|top|right|bottom|title".
  public static string[] Overlays() {
    var list = new List<string>();
    EnumWindows(delegate (IntPtr h, IntPtr l) {
      try {
        if (!IsWindowVisible(h)) return true;
        int ex = GetWindowLong(h, -20);
        if ((ex & 0x80000) == 0 || (ex & 0x8) == 0) return true;
        RECT r; if (!GetWindowRect(h, out r)) return true;
        if (r.R - r.L < 200 || r.B - r.T < 200) return true;
        uint pid; GetWindowThreadProcessId(h, out pid);
        var sb = new System.Text.StringBuilder(256); GetWindowText(h, sb, 256);
        list.Add(pid + "|" + ex + "|" + r.L + "|" + r.T + "|" + r.R + "|" + r.B + "|" + sb.ToString().Replace("|", " "));
      } catch { }
      return true;
    }, IntPtr.Zero);
    return list.ToArray();
  }
  // Returns "ownerPid|accessMask" for every program that holds a memory-capable handle (VM read/write/operation) to one of the target processes.
  public static string[] Find(int[] targets, int budgetMs) {
    var res = new Dictionary<int, uint>();
    var opened = new List<IntPtr>(); IntPtr buf = IntPtr.Zero;
    try {
      if (IntPtr.Size != 8) return new string[0];
      DateTime end = DateTime.UtcNow.AddMilliseconds(budgetMs);
      var tset = new HashSet<int>(targets);
      int me = System.Diagnostics.Process.GetCurrentProcess().Id;
      IntPtr myH = OpenProcess(0x1000, false, me); opened.Add(myH);
      var tH = new List<long>();
      foreach (int t in targets) { IntPtr h = OpenProcess(0x1000, false, t); if (h != IntPtr.Zero) { opened.Add(h); tH.Add(h.ToInt64()); } }
      int len = 1 << 23; int ret = 0; int st;
      buf = Marshal.AllocHGlobal(len);
      while ((st = NtQuerySystemInformation(64, buf, len, out ret)) == unchecked((int)0xC0000004)) {
        Marshal.FreeHGlobal(buf); buf = IntPtr.Zero;
        len = Math.Max(len * 2, ret + (1 << 20)); if (len > (1 << 29)) return new string[0];
        buf = Marshal.AllocHGlobal(len);
      }
      if (st != 0) return new string[0];
      long n = Marshal.ReadInt64(buf); const int ESZ = 40; const int OFF = 16;
      ushort procType = 0; bool gotType = false; var tAddr = new HashSet<long>();
      for (long i = 0; i < n; i++) {
        int o = (int)(OFF + i * ESZ);
        long pid = Marshal.ReadInt64(buf, o + 8);
        if (pid != me) continue;
        long hv = Marshal.ReadInt64(buf, o + 16); long obj = Marshal.ReadInt64(buf, o);
        if (hv == myH.ToInt64()) { procType = (ushort)Marshal.ReadInt16(buf, o + 30); gotType = true; }
        if (obj != 0 && tH.Contains(hv)) tAddr.Add(obj);
      }
      if (!gotType) return new string[0];
      var owners = new Dictionary<int, IntPtr>(); int tries = 0;
      for (long i = 0; i < n; i++) {
        int o = (int)(OFF + i * ESZ);
        if ((ushort)Marshal.ReadInt16(buf, o + 30) != procType) continue;
        uint acc = (uint)Marshal.ReadInt32(buf, o + 24);
        if ((acc & 0x38) == 0) continue;
        int opid = (int)Marshal.ReadInt64(buf, o + 8);
        if (opid == me || opid <= 4 || tset.Contains(opid)) continue;
        long obj = Marshal.ReadInt64(buf, o); long hv = Marshal.ReadInt64(buf, o + 16);
        bool hit = false;
        if (tAddr.Count > 0 && obj != 0) hit = tAddr.Contains(obj);
        else {
          if (tries > 6000 || DateTime.UtcNow > end) continue;
          IntPtr oh; if (!owners.TryGetValue(opid, out oh)) { oh = OpenProcess(0x40, false, opid); owners[opid] = oh; }
          if (oh == IntPtr.Zero) continue;
          tries++; IntPtr d;
          if (DuplicateHandle(oh, new IntPtr(hv), GetCurrentProcess(), out d, 0, false, 2)) { int tp = GetProcessId(d); CloseHandle(d); hit = tset.Contains(tp); }
        }
        if (hit) { uint old; res.TryGetValue(opid, out old); res[opid] = old | acc; }
      }
      foreach (var kv in owners) if (kv.Value != IntPtr.Zero) CloseHandle(kv.Value);
    } catch { }
    finally { if (buf != IntPtr.Zero) Marshal.FreeHGlobal(buf); foreach (var h in opened) if (h != IntPtr.Zero) CloseHandle(h); }
    var list = new List<string>(); foreach (var kv in res) list.Add(kv.Key + "|" + kv.Value);
    return list.ToArray();
  }
}
'@
    if (-not ('QHnd' -as [type])) {
      $okH = $false
      if (Test-Path -LiteralPath $hDll) { try { Add-Type -Path $hDll -ErrorAction Stop; $okH = $true } catch {} }
      if (-not $okH) {
        try { Add-Type -TypeDefinition $hSrc -OutputAssembly $hDll -ErrorAction Stop } catch {}
        if (-not ('QHnd' -as [type]) -and (Test-Path -LiteralPath $hDll)) { try { Add-Type -Path $hDll -ErrorAction Stop } catch {} }
        if (-not ('QHnd' -as [type])) { try { Add-Type -TypeDefinition $hSrc -ErrorAction Stop } catch {} }
      }
    }
    if ('QHnd' -as [type]) {
      $memRows = @([QHnd]::Find([int[]]@($rbxProcs | ForEach-Object { $_.Id }), 2500))
      foreach ($row in $memRows) {
        $pr = "$row" -split '\|'; $opid = [int]$pr[0]; $acc = [uint32]$pr[1]
        $opath = ''
        try { $opath = "$((Get-Process -Id $opid -ErrorAction Stop).Path)" } catch {}
        if (-not $opath) { try { $opath = "$((Get-CimInstance Win32_Process -Filter "ProcessId=$opid" -ErrorAction Stop).ExecutablePath)" } catch {} }
        if (-not $opath) { continue }
        if ($opath.StartsWith($env:windir, [StringComparison]::OrdinalIgnoreCase) -or $opath -match '(?i)\\Roblox\\' -or $opath -match $exclude) { continue }
        $sgm = Get-AuthenticodeSignature -LiteralPath $opath -ErrorAction SilentlyContinue
        $sgn = ''; if ($sgm.SignerCertificate) { $sgn = ($sgm.SignerCertificate.Subject -replace '.*CN=([^,]+).*', '$1') }
        if ("$($sgm.Status)" -eq 'Valid' -and $sgn -match $trustedPub) { continue }
        $oleaf = Leaf-Of $opath
        if (Test-FlagTool $opath $oleaf) { if (-not $flagSeen.Contains($oleaf)) { $flagSeen.Add($oleaf) }; continue }
        $nn = Match-Leaf $oleaf $false
        if (-not $nn) {
          try { $vi = (Get-Item -LiteralPath $opath).VersionInfo
                foreach ($fv in @($vi.OriginalFilename, $vi.InternalName, $vi.ProductName)) { if ($fv -and -not $nn) { $nn = Match-Leaf ((("$fv").Trim() -replace '\.(exe|dll)$', '') + '.exe') $false } } } catch {}
        }
        if (-not $nn) { $nn = $unkMem }
        $can = @(); if ($acc -band 0x10) { $can += 'read' }; if ($acc -band 0x20) { $can += 'write' }; if ($acc -band 0x8) { $can += 'modify' }
        Add-Ev @{ Name=$nn; Src='Memory access to Roblox'; Path=$opath; PresentNow=$true; Run=(Get-Date); RunKind='running right now'; Note=("holds a handle to Roblox that can " + ($can -join '/') + " its memory (access 0x" + ('{0:X}' -f $acc) + ")") }
      }
      if ($memRows.Count -eq 0) { $memNote = 'Memory-access check: no program outside Windows/trusted publishers has a memory handle to Roblox right now.' }
      # Transparent always-on-top windows covering the screen: how an external cheat draws its ESP / overlay
      try {
        $scr = [Windows.Forms.Screen]::PrimaryScreen.Bounds
        $ovlOk = '(?i)discord|steam|nvidia|geforce|xbox|gamebar|\bobs|rtss|afterburner|overwolf|medal|streamlabs|spotify|teams|zoom|slack|webview|snip|sharex|powertoys|lightshot|taskmgr|dwm|searchhost|textinput|shellexperience|widgets|clip|recorder|capture'
        $ovlSeen = @{}
        foreach ($orow in @([QHnd]::Overlays())) {
          $op = "$orow" -split '\|'
          $wpid = [int]$op[0]; $ww = [int]$op[4] - [int]$op[2]; $wh = [int]$op[5] - [int]$op[3]; $wt = "$($op[6])"
          if ($ww -lt ($scr.Width * 0.6) -or $wh -lt ($scr.Height * 0.6)) { continue }
          if ($ovlSeen.ContainsKey($wpid)) { continue }; $ovlSeen[$wpid] = 1
          $wproc = Get-Process -Id $wpid -ErrorAction SilentlyContinue
          $wpath = ''; try { $wpath = "$($wproc.Path)" } catch {}
          if (-not $wpath -or $wpath.StartsWith($env:windir, [StringComparison]::OrdinalIgnoreCase) -or $wpath -match '(?i)\\Roblox\\' -or $wpath -match $exclude) { continue }
          if ("$($wproc.ProcessName) $wpath" -match $ovlOk) { continue }
          $sgo = Get-AuthenticodeSignature -LiteralPath $wpath -ErrorAction SilentlyContinue
          $sgon = ''; if ($sgo.SignerCertificate) { $sgon = ($sgo.SignerCertificate.Subject -replace '.*CN=([^,]+).*', '$1') }
          if ("$($sgo.Status)" -eq 'Valid' -and $sgon -match $trustedPub) { continue }
          $nn = Match-Leaf (Leaf-Of $wpath) $false
          if (-not $nn) { $nn = $unkOvl }
          $isAhk = ($wproc.ProcessName -match '(?i)autohotkey')
          Add-Ev @{ Name=$nn; Src='Transparent overlay window'; Path=$wpath; PresentNow=$true; Run=(Get-Date); RunKind='running right now'; Note=("draws a see-through always-on-top window over the screen (${ww}x${wh}, title '$wt')" + $(if ($isAhk) { ' - this is an AutoHotkey script' } else { '' })) }
        }
      } catch {}
    } else { $memNote = 'Memory-access check skipped: could not load the handle reader.' }
  }
} catch { $memNote = 'Memory-access check could not run on this PC.' }
# v2: is the running Roblox client itself the real, signed Roblox program? A patched client is how many internals get around Roblox's protection.
$rbxLeads = New-Object System.Collections.Generic.List[string]
try {
  foreach ($rp0 in @($rbxProcs | Where-Object { $_.Path })) {
    $rpath = "$($rp0.Path)"
    $sgr = Get-AuthenticodeSignature -LiteralPath $rpath -ErrorAction SilentlyContinue
    $sst = "$($sgr.Status)"
    $ssub = ''; if ($sgr.SignerCertificate) { $ssub = "$($sgr.SignerCertificate.Subject)" }
    if ($sst -in 'NotSigned','HashMismatch') {
      Add-Ev @{ Name=$unkCli; Src='Loaded inside Roblox (injected)'; Path=$rpath; PresentNow=$true; Run=(Get-Date); RunKind='running right now'; Note="the running Roblox program has no valid signature ($sst): it was modified or is not the real Roblox client" }
    } elseif ($sst -eq 'Valid' -and $ssub -and $ssub -notmatch 'Roblox') {
      Add-Ev @{ Name=$unkCli; Src='Loaded inside Roblox (injected)'; Path=$rpath; PresentNow=$true; Run=(Get-Date); RunKind='running right now'; Note="the running Roblox program is signed by someone other than Roblox: $($ssub -replace '.*CN=([^,]+).*','$1')" }
    }
    try {
      $pi0 = Get-CimInstance Win32_Process -Filter "ProcessId=$($rp0.Id)" -ErrorAction Stop
      $par = Get-Process -Id $pi0.ParentProcessId -ErrorAction SilentlyContinue
      if ($par -and $par.ProcessName -notmatch '(?i)^(RobloxPlayerLauncher|RobloxPlayerInstaller|RobloxPlayerBeta|Roblox|explorer|chrome|msedge|firefox|brave|opera|bloxstrap|fishstrap|voidstrap|svchost|services|WindowsTerminal|taskhostw|ApplicationFrameHost|sihost|SearchHost|StartMenuExperienceHost|cmd|powershell|pwsh)$') { $rbxLeads.Add("Roblox was started by an unusual program: $($par.ProcessName)  $($par.Path)") }
    } catch {}
    if ($rpath -notmatch '(?i)\\Roblox\\Versions\\|\\Bloxstrap\\|\\Fishstrap\\|\\Voidstrap\\|\\Program Files|WindowsApps') { $rbxLeads.Add("Roblox is running from an unusual folder: $rpath") }
  }
} catch {}
# Informational lead: unsigned programs running from user folders while Roblox is open
$unsignedRun = New-Object System.Collections.Generic.List[string]
try {
  if ($rbxProcs -and $rbxProcs.Count -gt 0) {
    $cnt = 0
    foreach ($up in @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path -and $_.Path -match '(?i)\\(Downloads|Desktop|Documents|AppData|Temp)\\' -and $_.Path -notmatch '(?i)\\Roblox\\' } | Sort-Object Path -Unique | Select-Object -First 40)) {
      if ((RemainMs 1) -le 0 -or $cnt -ge 25) { break }
      $cnt++
      $sgu = Get-AuthenticodeSignature -LiteralPath $up.Path -ErrorAction SilentlyContinue
      if ("$($sgu.Status)" -eq 'NotSigned' -and $up.Path -notmatch $exclude) { $unsignedRun.Add("$($up.ProcessName)  -  $($up.Path)") }
    }
  }
} catch {}
Set-Stage 'Checking open windows (for external tools)'
# External tools (e.g. Matcha) do not inject a DLL: find them by the title of their open window, even if the .exe was renamed
$browserRx = '(?i)^(chrome|msedge|firefox|brave|opera|iexplore|discord|spotify|code|notepad|explorer|slack|teams)'
Get-Process | Where-Object { $_.MainWindowTitle -and $_.Name -notmatch $browserRx } | ForEach-Object {
  $wt = "$($_.MainWindowTitle)"
  if ($wt -match $exclude) { return }
  $n = Find-NameToken $wt
  if ($n) { $pp = "$($_.Path)"; Add-Ev @{ Name=$n; Src='Running process'; Path=$(if ($pp) { $pp } else { $null }); PresentNow=$true; Run=(Get-Date); RunKind='running right now'; Note="open window titled '$wt'" } }
}
Set-Stage 'Reading UserAssist (what was launched and how often)'
# UserAssist (last run + run count)
$rotWords = @($names) + @($aliasWords)
$rotPat = '(?i)(?:' + (($rotWords | ForEach-Object { [regex]::Escape((Rot13 $_)) }) -join '|') + ')'
Get-ChildItem "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\*\Count" | ForEach-Object {
  $k = Get-Item $_.PSPath
  foreach ($p in $k.Property) {
    if ($p -notmatch $rotPat) { continue }
    $prog = Rot13 $p
    if (-not (Test-Hit $prog)) { continue }
    $b = $k.GetValue($p)
    if (-not ($b -is [byte[]] -and $b.Length -ge 68)) { continue }
    $ft = [BitConverter]::ToInt64($b, 60)
    $last = $null; if ($ft -gt 0) { try { $last = [datetime]::FromFileTime($ft) } catch {} }
    $path = Extract-Path (Expand-KnownFolder $prog)
    $leaf = if ($path) { Leaf-Of $path } else { Leaf-Of $prog }
    $n = Match-Leaf $leaf $false
    if ($n) { Add-Ev @{ Name=$n; Src='UserAssist'; Path=$path; PIE=$true; Run=$last; RunKind='last run (Windows UserAssist)'; Runs=[BitConverter]::ToInt32($b,4) } }
  }
}
# Other users whose registry is loaded (logged in / switched away): their run history, if Windows lets this account read it
$hkuRead = 0; $hkuLocked = 0
try {
  $mySid2 = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  foreach ($hk in @(Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue)) {
    $sidn = $hk.PSChildName
    if ($sidn -notmatch '^S-1-5-21-' -or $sidn -match '_Classes$' -or $sidn -eq $mySid2) { continue }
    try {
      $uaKeys = @(Get-ChildItem "Registry::HKEY_USERS\$sidn\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist" -ErrorAction Stop)
      $hkuRead++
      foreach ($g in $uaKeys) {
        $ck = Get-Item -LiteralPath "$($g.PSPath)\Count" -ErrorAction SilentlyContinue
        if (-not $ck) { continue }
        foreach ($vn in $ck.GetValueNames()) {
          $dec = Rot13 $vn
          $nn = Match-Leaf (Leaf-Of $dec) $false
          if ($nn) { Add-Ev @{ Name=$nn; Src='UserAssist (another user)'; Path=$dec; Note="run history of another user account ($sidn)" } }
        }
      }
    } catch { $hkuLocked++ }
  }
} catch {}
Set-Stage 'Checking for drivers that cheats use to reach Roblox memory'
# Cheats that get past Roblox's protection usually load a vulnerable signed driver (BYOVD) through a "mapper". Leads only: some of these
# drivers also belong to normal hardware tools (MSI Afterburner, CPU-Z, ASUS/Gigabyte utilities).
$byovd = 'iqvw64e|gdrv|dbutil_2_3|rtcore64|rtcore32|capcom|winring0x?64|winring0|asio3|asrdrv\d*|atszio64|cpuz\d+_x64|kprocesshacker|mhyprot\d*|physmem|bs_def64|ntiolib_x64|inpoutx64|nvoclock|dbk64|dbk32'
$driverLeads = New-Object System.Collections.Generic.List[string]
try {
  foreach ($dr in @(Get-CimInstance Win32_SystemDriver -ErrorAction Stop | Where-Object { "$($_.PathName)" -match "(?i)\\($byovd)\.sys" })) {
    $driverLeads.Add("loaded/installed driver: $($dr.Name)  -  $($dr.PathName)  [$($dr.State)]" + $(if ("$($dr.PathName)" -match '(?i)dbk(32|64)') { '   <- Cheat Engine kernel driver' } else { '' }))
  }
} catch {}
foreach ($tp in @($env:TEMP, "$env:USERPROFILE\Downloads", "$env:USERPROFILE\Desktop")) {
  if ((RemainMs 1) -le 0) { break }
  if (-not (Test-Path -LiteralPath $tp)) { continue }
  foreach ($df in @(Get-ChildItem -LiteralPath $tp -Filter *.sys -File -Recurse -Depth 3 -Force -ErrorAction SilentlyContinue | Select-Object -First 12)) {
    if ($df.FullName -match $exclude) { continue }
    $driverLeads.Add("driver file in a user folder: $($df.FullName)" + $(if ($df.Name -match "(?i)^($byovd)\.sys$") { '   <- a driver known to be abused by cheat mappers' } else { '' }))
  }
}
# v2.3 (admin): drivers installed as services, from the System event log (survives after the driver file is deleted)
if ($isAdmin) {
  try {
    foreach ($evn in @(Get-WinEvent -FilterHashtable @{ LogName='System'; Id=7045 } -MaxEvents 400 -ErrorAction Stop)) {
      $m7 = "$($evn.Message)"
      if ($m7 -match "(?i)($byovd)\.sys|dbk(32|64)") { $driverLeads.Add("service installed $($evn.TimeCreated.ToString('yyyy-MM-dd HH:mm')): $((($m7 -split "`n") | Select-Object -First 3) -join ' ')") }
    }
  } catch {}
}
Set-Stage 'Reading MUICache and the Run history'
# MUICache / Compatibility store / RunMRU (proves it was run; no time stored)
@("HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
  "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store",
  "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers",
  "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU") | ForEach-Object {
  $k = Get-Item $_ -ErrorAction SilentlyContinue
  if ($k) { foreach ($p in $k.Property) {
    if (-not (Test-Hit $p)) { continue }
    $path = Extract-Path $p
    $n = Match-Leaf $(if ($path) { Leaf-Of $path } else { $p }) $false
    if ($n) { Add-Ev @{ Name=$n; Src='Windows run history'; Path=$path; PIE=$true } }
  } }
}
Set-Stage 'Checking startup entries'
# Startup entries
'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\Microsoft\Windows\CurrentVersion\Run','HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce','HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run' | ForEach-Object {
  $k = Get-Item $_ -ErrorAction SilentlyContinue
  if ($k) { foreach ($p in $k.Property) {
    $v = "$($k.GetValue($p))"
    if (-not (Test-Hit "$p $v")) { continue }
    $path = Extract-Path $v
    $n = Match-Leaf $(if ($path) { Leaf-Of $path } else { $p }) $true
    if ($n) { Add-Ev @{ Name=$n; Src='Startup entry'; Path=$path; PresentNow=$true } }
  } }
}
Set-Stage 'Checking installed programs'
# Installed programs
'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*','HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' |
  ForEach-Object { Get-ItemProperty $_ -ErrorAction SilentlyContinue } |
  Where-Object { Test-Hit $_.DisplayName } | ForEach-Object {
    $n = Match-Leaf $_.DisplayName $true
    if ($n -and ("$($_.Publisher) $($_.InstallLocation)" -notmatch $exclude)) {
      $loc = "$($_.InstallLocation)".TrimEnd('\')
      $hx = $false
      if ($loc -match '^[A-Za-z]:\\' -and (Test-Path -LiteralPath $loc)) { $hx = Folder-HasExec $loc }
      Add-Ev @{ Name=$n; Src='Installed program'; Path=$(if ($loc -match '^[A-Za-z]:\\') { $loc } else { $null }); HasExec=$hx; Note="uninstall-list entry '$($_.DisplayName)'" }
    }
  }
Set-Stage 'Reading recent shortcuts'
# Recent shortcuts (last opened + which drive it was on, even if unplugged now)
$recentDirs = @("$env:APPDATA\Microsoft\Windows\Recent") + @($readableProfiles | ForEach-Object { "$($_.Path)\AppData\Roaming\Microsoft\Windows\Recent" })
foreach ($recentDir in $recentDirs) {
Get-ChildItem $recentDir -Filter *.lnk -Force | Where-Object { Test-Hit $_.Name } | ForEach-Object {
  $lnk = $_; $p = Parse-Lnk $lnk.FullName
  if ($p) {
    $n = Match-Leaf (Leaf-Of $p.Target) $false
    if (-not $n) { $n = Match-Leaf $lnk.BaseName $true }
    if ($n) { Add-Ev @{ Name=$n; Src='Recent shortcut'; Path=$p.Target; PIE=$true; Run=$lnk.LastWriteTime; RunKind='last opened (Recent shortcut)'; Serial=$p.Serial; DType=$p.DriveType; Label=$p.Label } }
  }
}
}
Set-Stage 'Checking Start Menu and Startup folders'
# v2: programs that put a shortcut in the Start Menu or the Startup folder (the shortcut survives even when the program is moved)
foreach ($sm in @("$env:APPDATA\Microsoft\Windows\Start Menu\Programs", "$env:ProgramData\Microsoft\Windows\Start Menu\Programs")) {
  if (-not (Test-Path -LiteralPath $sm)) { continue }
  foreach ($sf in @(Get-ChildItem -LiteralPath $sm -Recurse -Depth 3 -Force -ErrorAction SilentlyContinue | Where-Object { -not $_.PSIsContainer -and $_.Extension -match '(?i)^\.(lnk|exe|bat|cmd|url)$' } | Select-Object -First 3000)) {
    if (-not (Test-Hit $sf.Name)) { continue }
    $srcN = if ($sf.FullName -match '(?i)\\Startup\\') { 'Startup folder' } else { 'Start Menu shortcut' }
    $tgt = $null
    if ($sf.Extension -ieq '.lnk') { $pl2 = Parse-Lnk $sf.FullName; if ($pl2) { $tgt = $pl2.Target } }
    $n = $null
    if ($tgt) { $n = Match-Leaf (Leaf-Of $tgt) $false }
    if (-not $n) { $n = Match-Leaf $sf.BaseName $true }
    if (-not $n) { $n = Match-Leaf $sf.Name $false }
    if (-not $n) { continue }
    $pth = if ($tgt -and (Test-Path -LiteralPath $tgt)) { $tgt } else { $sf.FullName }
    Add-Ev @{ Name=$n; Src=$srcN; Path=$pth; PresentNow=$true; Mod=$sf.LastWriteTime; Created=$sf.CreationTime; Note="shortcut: $($sf.FullName)" }
  }
}
Set-Stage 'Reading Jump Lists (files recently opened per program)'
# v2: Jump Lists remember file paths opened from each program (Explorer, browsers...) even after the file or the USB drive is gone
$jlRx = '(?i)[A-Z]:\\[^\x00-\x1f"<>|*?]{2,260}?\.(?:exe|dll|bat|cmd|ps1|scr|msi|zip|rar|7z|lnk|ahk|lua|jar)'
$jlRoots = @("$env:APPDATA\Microsoft\Windows\Recent") + @($readableProfiles | ForEach-Object { "$($_.Path)\AppData\Roaming\Microsoft\Windows\Recent" })
$jlSeen = New-Object 'System.Collections.Generic.HashSet[string]'
foreach ($jr in $jlRoots) {
  foreach ($jsub in 'AutomaticDestinations','CustomDestinations') {
    $jd = Join-Path $jr $jsub
    foreach ($jf in @(Get-ChildItem -LiteralPath $jd -File -Force -ErrorAction SilentlyContinue | Select-Object -First 300)) {
      if ((RemainMs 1) -le 0) { break }
      try {
        $jb = Read-LockedFile $jf.FullName
        if ($jb.Length -lt 64) { continue }
        $jtexts = @([Text.Encoding]::Unicode.GetString($jb, 0, ($jb.Length -band -2)), [Text.Encoding]::GetEncoding(28591).GetString($jb), [Text.Encoding]::Unicode.GetString($jb, 1, (($jb.Length - 1) -band -2)))
        foreach ($jt in $jtexts) {
          if ($jt -notmatch $pattern) { continue }
          foreach ($m in [regex]::Matches($jt, $jlRx)) {
            $jp = $m.Value
            if (-not $jlSeen.Add($jp.ToLower())) { continue }
            if (-not (Test-Hit $jp)) { continue }
            $n = Match-Leaf (Leaf-Of $jp) $false
            if ($n) { Add-Ev @{ Name=$n; Src='Jump List'; Path=$jp; PIE=$true } }
          }
        }
      } catch {}
    }
  }
}
Set-Stage 'Reading Open/Save dialog history'
# v2: file names that were picked in a Windows Open/Save dialog or opened from Explorer (Recent list)
$mruKeys = @('HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU',
             'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU',
             'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs')
$mruSeen = New-Object 'System.Collections.Generic.HashSet[string]'
foreach ($mk in $mruKeys) {
  $kk = @(Get-Item -LiteralPath $mk -ErrorAction SilentlyContinue) + @(Get-ChildItem -LiteralPath $mk -Recurse -ErrorAction SilentlyContinue)
  foreach ($k in $kk) {
    if (-not $k) { continue }
    foreach ($vn in @($k.GetValueNames())) {
      $bv = $k.GetValue($vn)
      if (-not ($bv -is [byte[]]) -or $bv.Length -lt 8) { continue }
      foreach ($a in 0,1) {
        $s = [Text.Encoding]::Unicode.GetString($bv, $a, (($bv.Length - $a) -band -2))
        foreach ($m in [regex]::Matches($s, '[^\x00-\x1f\\/:*?"<>|]{3,120}?\.(?:exe|dll|zip|rar|7z|bat|msi|ahk|lua|lnk|ps1)(?![A-Za-z0-9])')) {
          $nm = $m.Value.Trim()
          if (-not $mruSeen.Add($nm.ToLower())) { continue }
          if (-not (Test-Hit $nm)) { continue }
          $n = Match-Leaf $nm $false
          if ($n) { Add-Ev @{ Name=$n; Src='Dialog history (Open/Save)'; Path=$null; PIE=$true; Note="file name seen in a Windows Open/Save dialog or Recent list: $nm" } }
        }
      }
    }
  }
}
Set-Stage 'Reading PowerShell command history'
# v2.5: typing a name in PowerShell does NOT prove the tool was ever on this PC (people paste scripts, name lists and notes into the console).
# So history lines are kept as LEADS / extra trace lines only, and pasted code, variable lists and lines with 3+ tool names are ignored.
$psHist = @{}
foreach ($ph in (@("$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt") + @($readableProfiles | ForEach-Object { "$($_.Path)\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" }))) {
  if (-not (Test-Path -LiteralPath $ph)) { continue }
  try {
    $phLines = @(Get-Content -LiteralPath $ph -Tail 4000 -ErrorAction Stop)
    $phSeen = 0
    foreach ($phl in $phLines) {
      if ($phSeen -ge 12) { break }
      $phl2 = Norm-Name "$phl"
      if ($phl2 -notmatch $patNG -or $phl2 -match $exclude) { continue }
      if ($phl2 -match '^\s*[\$#@\[\]{}()]|\$\w+\s*=|@\(|Add-Ev|-match|-notmatch|\bforeach\b|\bfunction\b|\bparam\b|Set-Stage|\$names|Names\b') { continue }
      $cntN = 0
      foreach ($nn2 in $names) { if ($phl2 -match ("(?i)(?<![A-Za-z0-9])(?:" + (Name-Rx $nn2) + ")(?![A-Za-z])")) { $cntN++ } }
      if ($cntN -ge 3) { continue }
      $nt = Find-NameToken $phl2
      if ($nt) {
        $phSeen++
        if (-not $psHist.ContainsKey($nt)) { $psHist[$nt] = New-Object System.Collections.Generic.List[string] }
        $psHist[$nt].Add($(if ("$phl".Length -gt 120) { "$phl".Substring(0,120) + '...' } else { "$phl" }))
      }
    }
  } catch {}
}
Set-Stage 'Looking in the Recycle Bin'
# Recycle Bin (your own bin on each connected drive)
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
foreach ($v in $volMap.Values) {
  if ($v.DriveType -notin 2,3) { continue }
  Get-ChildItem (Join-Path "$($v.Letter):\" "`$Recycle.Bin\$sid") -Force -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -like '$I*' } | ForEach-Object {
      try {
        $b = [IO.File]::ReadAllBytes($_.FullName)
        if ($b.Length -gt 30) {
          $off = if ($b[0] -eq 2) { 28 } else { 24 }
          $orig = [Text.Encoding]::Unicode.GetString($b, $off, $b.Length - $off).TrimEnd([char]0)
          if (Test-Hit $orig) {
            $n = Match-Leaf (Leaf-Of $orig) $false
            if ($n) { Add-Ev @{ Name=$n; Src='Recycle Bin'; Path=$orig; Deleted=$_.LastWriteTime } }
          }
        }
      } catch {}
    }
}

Set-Stage 'Checking registry keys'
# ---------- 2b. More checks (registry keys, ShimCache, Roblox injection, antivirus exclusions) ----------
foreach ($rk in 'HKCU:\Software','HKLM:\SOFTWARE','HKLM:\SOFTWARE\WOW6432Node') {
  foreach ($k in @(Get-ChildItem $rk -ErrorAction SilentlyContinue)) {
    $n = Match-Leaf $k.PSChildName $true
    if ($n) { Add-Ev @{ Name=$n; Src='Registry key'; Path=$null; PresentNow=$false; Note="registry key $($k.Name)" } }
  }
}
Set-Stage 'Reading ShimCache (programs Windows remembers running)'
# ShimCache: Windows remembers the path of programs that were run, even after they are deleted or the USB is gone
try {
  $sc = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache' -ErrorAction Stop).AppCompatCache
  if ($sc -is [byte[]] -and $sc.Length -gt 64) {
    $seenP = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($a in 0,1) {
      $str = [Text.Encoding]::Unicode.GetString($sc, $a, (($sc.Length - $a) -band -2))
      foreach ($m in [regex]::Matches($str, '(?i)[A-Z]:\\[^\x00-\x1f"<>|*?]{2,260}?\.(?:exe|dll|bat|cmd|ps1|scr|msi)')) {
        $path = $m.Value
        if (-not $seenP.Add($path.ToLower())) { continue }
        if (-not (Test-Hit $path)) { continue }
        $n = Match-Leaf (Leaf-Of $path) $false
        if ($n) { Add-Ev @{ Name=$n; Src='Windows execution cache (ShimCache)'; Path=$path; PIE=$true } }
      }
    }
  }
} catch {}
Set-Stage 'Checking modules loaded inside Roblox'
# Roblox: DLLs injected into a running Roblox show up as loaded modules
$unusualMods = New-Object System.Collections.Generic.List[string]
$badMods = 0
$sysModRx = '(?i)^(?:' + [regex]::Escape($env:windir) + '\\|[A-Z]:\\Program Files|[A-Z]:\\ProgramData\\|.*\\Roblox\\|.*\\WindowsApps\\)'
foreach ($rp in @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'Roblox*' })) {
  $mods = @(); try { $mods = @($rp.Modules) } catch {}
  foreach ($m in $mods) {
    $mp = "$($m.FileName)"
    if (-not $mp) { continue }
    $n = Match-Leaf (Leaf-Of $mp) $false
    if ($n) { Add-Ev @{ Name=$n; Src='Loaded inside Roblox (injected)'; Path=$mp; PresentNow=$true; Run=(Get-Date); RunKind='loaded inside a running Roblox right now' } }
    else {
      $inRbx = ($mp -match '(?i)\\Roblox\\')
      if ($mp -notmatch $sysModRx) { $lf = Leaf-Of $mp; if ($lf -and -not $unusualMods.Contains($lf)) { $unusualMods.Add($lf) } }
      # An internal executor is a DLL injected into Roblox. Real Roblox/Windows modules are signed; an unsigned one is a strong sign.
      if (($mp -notmatch $sysModRx) -or $inRbx) {
        if ($badMods -lt 20) {
          $sg = Get-AuthenticodeSignature -LiteralPath $mp -ErrorAction SilentlyContinue
          $st = "$($sg.Status)"
          $bad = if ($inRbx) { $st -in 'NotSigned','HashMismatch' } else { $st -ne 'Valid' }
          if (-not $bad -and $mp -match '(?i)\\(Downloads|Desktop|Documents|Temp)\\') { $bad = $true; $st = "$st, but loaded from a user folder" }
          if ($bad) { $badMods++; Add-Ev @{ Name=$unkMod; Src='Loaded inside Roblox (injected)'; Path=$mp; PresentNow=$true; Run=(Get-Date); RunKind='loaded inside a running Roblox right now'; Note="module with no valid signature ($st)" } }
        }
      }
    }
  }
}
Set-Stage 'Checking the Roblox folder for dropped DLLs'
# Internal executors often drop a DLL into the Roblox install folder: list unsigned ones.
# v2: a DLL with a WINDOWS system-DLL name (version.dll, winmm.dll, dxgi.dll ...) that is not signed is the classic "DLL hijack" way to get loaded into a game.
$rbxDlls = New-Object System.Collections.Generic.List[string]
$proxyRx = '(?i)^(version|winmm|dxgi|d3d8|d3d9|d3d10|d3d11|dinput8|dinput|xinput1_\d|wininet|dbghelp|dwmapi|msimg32|winhttp|iphlpapi|wtsapi32|opengl32|hid|bcrypt|crypt32|ws2_32|user32|kernel32|ntdll)\.dll$'
function Check-RbxDll($df, $who) {
  $nn = Match-Leaf $df.Name $false
  if ($nn) { Add-Ev @{ Name=$nn; Src='File on disk'; Path=$df.FullName; PresentNow=$true; Mod=$df.LastWriteTime; Created=$df.CreationTime; Note=("dropped inside the Roblox folder" + $who) } }
  $sg = Get-AuthenticodeSignature -LiteralPath $df.FullName -ErrorAction SilentlyContinue
  $st = "$($sg.Status)"
  if ($st -in 'NotSigned','HashMismatch') {
    $tag = if ($df.Name -match $proxyRx) { '   <- has a Windows system-DLL name but is NOT signed: typical of DLL hijacking by an injector' } else { '' }
    $rbxDlls.Add("$($df.FullName)   [$st]$tag")
  } elseif ($df.Name -match $proxyRx -and $st -eq 'Valid' -and $sg.SignerCertificate -and "$($sg.SignerCertificate.Subject)" -notmatch 'Microsoft|Roblox') {
    $rbxDlls.Add("$($df.FullName)   [signed by another publisher: $($sg.SignerCertificate.Subject -replace '.*CN=([^,]+).*','$1')]   <- system-DLL name inside the Roblox folder")
  }
}
$vroot = "$env:LOCALAPPDATA\Roblox\Versions"
if (Test-Path -LiteralPath $vroot) {
  foreach ($vd in @(Get-ChildItem -LiteralPath $vroot -Directory -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 2)) {
    foreach ($df in @(Get-ChildItem -LiteralPath $vd.FullName -Filter *.dll -File -Force -ErrorAction SilentlyContinue | Select-Object -First 60)) { Check-RbxDll $df '' }
  }
}
# the same Roblox folder check for the other user accounts that can be opened
foreach ($op in $readableProfiles) {
  $vr = "$($op.Path)\AppData\Local\Roblox\Versions"
  if (-not (Test-Path -LiteralPath $vr)) { continue }
  foreach ($vd in @(Get-ChildItem -LiteralPath $vr -Directory -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 2)) {
    foreach ($df in @(Get-ChildItem -LiteralPath $vd.FullName -Filter *.dll -File -Force -ErrorAction SilentlyContinue | Select-Object -First 60)) { Check-RbxDll $df " of user '$($op.Name)'" }
  }
}
Set-Stage 'Checking Roblox FFlag override files'
# v2.3: FFlag override files are legal (graphics tweaks) but a few flags are used for desync / lag tricks. Reported as a lead only.
$flagFiles = New-Object System.Collections.Generic.List[string]
foreach ($sb0 in 'Bloxstrap','Fishstrap','Voidstrap') { $flagFiles.Add("$env:LOCALAPPDATA\$sb0\Modifications\ClientSettings\ClientAppSettings.json") }
if (Test-Path -LiteralPath $vroot) { foreach ($vd2 in @(Get-ChildItem -LiteralPath $vroot -Directory -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 2)) { $flagFiles.Add("$($vd2.FullName)\ClientSettings\ClientAppSettings.json") } }
$flagWatch = '(?i)^(DFIntS2PhysicsSenderRate|DFIntMaxMissedWorldStepsRemembered)$'
foreach ($ff in $flagFiles) {
  if (-not (Test-Path -LiteralPath $ff)) { continue }
  try {
    $fj = Get-Content -LiteralPath $ff -Raw -ErrorAction Stop | ConvertFrom-Json
    $fnames = @($fj.PSObject.Properties.Name)
    if ($fnames.Count -eq 0) { continue }
    $fw = @($fnames | Where-Object { $_ -match $flagWatch })
    $rbxLeads.Add("Roblox FFlag override file with $($fnames.Count) flag(s): $ff" + $(if ($fw.Count -gt 0) { "   <- includes flags commonly used for desync / lag tricks: $($fw -join ', ')" } else { '' }))
  } catch {}
}
Set-Stage 'Checking Defender exclusions'
# Antivirus exclusions: executors usually need a Defender exclusion for their folder (admin can read these)
$exclPaths = @()
if ($isAdmin) {
  try { $exclPaths = @((Get-MpPreference -ErrorAction Stop).ExclusionPath | Where-Object { $_ -and $_ -notmatch '^N/A' }) } catch {}
  foreach ($xp in $exclPaths) {
    $n = Find-NameToken $xp
    if ($n) { Add-Ev @{ Name=$n; Src='Defender exclusion'; Path=$xp; PresentNow=[bool](Test-Path -LiteralPath $xp); Note='this folder is excluded from antivirus scanning' } }
  }
  try {
    Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Windows Defender/Operational'; Id=5007 } -MaxEvents 300 -ErrorAction Stop | ForEach-Object {
      if ("$($_.Message)" -match 'Exclusions\\Paths\\([^=\r\n]+?)\s*=') {
        $xp = $Matches[1].Trim()
        $n = Find-NameToken $xp
        if ($n) { Add-Ev @{ Name=$n; Src='Defender exclusion (history)'; Path=$xp; PIE=$true; Created=$_.TimeCreated; Note="an antivirus exclusion was added for this path on $($_.TimeCreated.ToString('yyyy-MM-dd HH:mm'))" } }
      }
    }
  } catch {}
}

# Defender detection history: Defender usually flags executors; this remembers them even after they were deleted/quarantined
if ($isAdmin) {
  try {
    Set-Stage 'Reading Defender detection history'
    foreach ($td in @(Get-MpThreatDetection -ErrorAction Stop)) {
      foreach ($res in @($td.Resources)) {
        $dp = Extract-Path "$res"
        if (-not $dp) { continue }
        $n = Match-Leaf (Leaf-Of $dp) $false
        if ($n) { Add-Ev @{ Name=$n; Src='Defender detection history'; Path=$dp; Created=$td.InitialDetectionTime; Note="Windows Defender detected this file on $(([datetime]$td.InitialDetectionTime).ToString('yyyy-MM-dd HH:mm'))" } }
      }
    }
  } catch {}
}
if ($isAdmin) { Set-Stage 'Reading Prefetch and BAM (admin only: exact last-used times)' }
# ---------- 3. Admin-only history: Prefetch + BAM (more accurate "last used" dates) ----------
if ($isAdmin) {
  Get-ChildItem 'C:\Windows\Prefetch\*.pf' -ErrorAction SilentlyContinue | Where-Object { Test-Hit $_.Name } | ForEach-Object {
    $n = Match-Leaf $_.Name $false
    if ($n) {
      $pi = Get-PrefetchInfo $_.FullName
      $lastRun = $_.LastWriteTime
      if ($pi -and $pi.Times.Count -gt 0) { $lastRun = $pi.Times[0] }
      Add-Ev @{ Name=$n; Src='Prefetch'; Path=$null; Run=$lastRun; RunKind='last run (Prefetch)'; Created=$_.CreationTime
                PfRuns=$(if ($pi) { $pi.Runs } else { $null }); RunList=$(if ($pi) { $pi.Times } else { $null }) }
    }
  }
  Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings' -ErrorAction SilentlyContinue | ForEach-Object {
    $k = Get-Item $_.PSPath
    foreach ($p in $k.Property) {
      if (-not (Test-Hit $p)) { continue }
      $b = $k.GetValue($p)
      if (-not ($b -is [byte[]] -and $b.Length -ge 8)) { continue }
      $t = $null; try { $t = [datetime]::FromFileTime([BitConverter]::ToInt64($b,0)) } catch {}
      $r = Resolve-Nt $p
      $n = Match-Leaf (Leaf-Of $r.Path) $false
      if ($n) { Add-Ev @{ Name=$n; Src='BAM'; Path=$r.Path; Unm=$r.Unm; PIE=$true; Run=$t; RunKind='last run (BAM)' } }
    }
  }
}

if ($doExternal) { Set-Stage 'Checking USB device history' }
# ---------- 4. USB device history (External / Both) ----------
$usb = @{}
if ($doExternal) {
  Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR' -ErrorAction SilentlyContinue | ForEach-Object {
    $cls = $_
    Get-ChildItem $cls.PSPath -ErrorAction SilentlyContinue | ForEach-Object {
      $fp = (Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue).FriendlyName
      $o = [pscustomobject]@{ Device=$(if ($fp) { $fp } else { $cls.PSChildName }); Serial=$_.PSChildName; First=$null; Arrival=$null; Removal=$null }
      $pk = "$($_.PSPath)\Properties\{83da6326-97a6-4088-9453-a1923f573b29}"
      foreach ($pair in @(@('0065','First'),@('0066','Arrival'),@('0067','Removal'))) {
        foreach ($suf in @('\00000000','')) {
          try {
            $key = Get-Item -LiteralPath ("$pk\$($pair[0])$suf") -ErrorAction Stop
            $bv = $key.GetValue('')
            if ($bv -is [byte[]] -and $bv.Length -ge 8) { $o.($pair[1]) = [datetime]::FromFileTime([BitConverter]::ToInt64($bv,0)); break }
          } catch {}
        }
      }
      $usb[$_.PSChildName] = $o
    }
  }
  if ($isAdmin) {
    $md = Get-Item 'HKLM:\SYSTEM\MountedDevices' -ErrorAction SilentlyContinue
    if ($md) { foreach ($p in $md.Property) {
      if ($p -match '^\\DosDevices\\([A-Z]):$') {
        $letter = $Matches[1]
        $bv = $md.GetValue($p)
        if ($bv -is [byte[]] -and $bv.Length -gt 24) {
          $s = [Text.Encoding]::Unicode.GetString($bv)
          if ($s -match 'USBSTOR#([^#]+)#([^#]+)#') { $usbLetterMap[$letter] = "$($Matches[1]) (serial $($Matches[2]))" }
        }
      }
    } }
  }
}

Set-Stage 'Waiting for services, tasks and browser history'
# ---------- 5. Collect background results (services/tasks + website marks) ----------
$svcItems = @()
try {
  if ($asyncH -and $asyncH.AsyncWaitHandle.WaitOne((RemainMs 6000))) { $svcItems = @($asyncPs.EndInvoke($asyncH)) } elseif ($asyncPs) { $asyncPs.Stop() }
} catch {}
try { if ($asyncPs) { $asyncPs.Dispose() } } catch {}
foreach ($s in $svcItems) {
  $path = Extract-Path $s.Path
  $n = Match-Leaf $(if ($path) { Leaf-Of $path } else { $s.Name }) $true
  if (-not $n) { $n = Match-Leaf $s.Name $true }
  if ($n) { Add-Ev @{ Name=$n; Src=$s.Kind; Path=$path; PresentNow=$true; Note="$($s.Kind): $($s.Name)" } }
}
$webHits = @{}
$zoneItems = @()
try {
  if ($asyncH2 -and $asyncH2.AsyncWaitHandle.WaitOne((RemainMs 4000))) { $zoneItems = @($asyncPs2.EndInvoke($asyncH2)) } elseif ($asyncPs2) { $asyncPs2.Stop() }
} catch {}
try { if ($asyncPs2) { $asyncPs2.Dispose() } } catch {}
foreach ($z in $zoneItems) {
  if ($z.Kind -eq 'Dl') {
    $dn = Match-Leaf (Leaf-Of $z.Path) $false
    if (-not $dn) { $dn = Find-NameToken $z.Path }
    if ($dn) { Add-Ev @{ Name=$dn; Src='Downloaded from website'; Path=$z.Path; PIE=$true; Note="a browser download record points to this file (history: $(Leaf-Of $z.Url))" } }
    continue
  }
  $n = Find-NameToken $z.Url
  if (-not $n) { continue }
  if ($z.Kind -eq 'Zone') {
    Add-Ev @{ Name=$n; Src='Downloaded from website'; Path=$z.Path; PIE=$true; Mod=$z.Time; Created=$z.Created; Note="downloaded from: $($z.Url)" }
  } elseif ($z.Kind -eq 'Web') {
    if (-not $webHits.ContainsKey($n)) { $webHits[$n] = New-Object System.Collections.Generic.List[string] }
    if (-not $webHits[$n].Contains($z.Url)) { $webHits[$n].Add($z.Url) }
  }
}

Set-Stage 'Checking file fingerprints and looking inside programs for exploit API names'
try { if ($asyncH3) { [void]$asyncH3.AsyncWaitHandle.WaitOne((RemainMs 8000)) } } catch {}
try { if ($asyncPs3 -and $asyncH3 -and -not $asyncH3.IsCompleted) { $asyncPs3.Stop() } } catch {}
try { if ($asyncPs3) { $asyncPs3.Dispose() } } catch {}
$cStat = $null
$apiShown = 0
$extShown = 0
foreach ($ci in @($bagC.ToArray())) {
  if ($ci.Kind -eq 'Stat') { $cStat = $ci; continue }
  if ($ci.Kind -eq 'MxDir') { Check-MxDir $ci.Path; continue }
  if ($ci.Kind -eq 'Hash') {
    Add-Ev @{ Name=$ci.Name; Src='Known file (hash match)'; Path=$ci.Path; PresentNow=$true; Mod=$ci.Mod; Created=$ci.Created; Note='SHA256 matches a file known to belong to this tool (found even if renamed)' }
    continue
  }
  if ($ci.Path -match $exclude) { continue }
  if ($ci.Kind -eq 'Meta') {
    $mn = Match-Leaf ((("$($ci.Value)").Trim() -replace '\.(exe|dll)$', '') + '.exe') $false
    if ($mn) { Add-Ev @{ Name=$mn; Src='Built-in file name (survives renaming)'; Path=$ci.Path; PresentNow=$true; Mod=$ci.Mod; Created=$ci.Created; Note="the file says it is '$($ci.Value)' inside, whatever it is called" } }
    continue
  }
  if ($ci.Kind -eq 'Ext') {
    if ($extShown -ge 10) { continue }
    $sge = Get-AuthenticodeSignature -LiteralPath $ci.Path -ErrorAction SilentlyContinue
    $sne = ''; if ($sge.SignerCertificate) { $sne = ($sge.SignerCertificate.Subject -replace '.*CN=([^,]+).*', '$1') }
    if ("$($sge.Status)" -eq 'Valid' -and $sne -match $trustedPub) { continue }
    $eleaf = Leaf-Of $ci.Path
    if (Test-FlagTool $ci.Path $eleaf) { if (-not $flagSeen.Contains($eleaf)) { $flagSeen.Add($eleaf) }; continue }
    $extShown++
    $en = Find-NameToken "$($ci.Path)"
    if (-not $en) { $en = $unkExt }
    Add-Ev @{ Name=$en; Src='Built to control Roblox from outside'; Path=$ci.Path; PresentNow=$true; Mod=$ci.Mod; Created=$ci.Created; Note=($(if ($ci.Named) { 'the program looks for the Roblox process and ' } else { 'the program contains Roblox-internals names and ' }) + $ci.Hits) }
    continue
  }
  if ($ci.Kind -eq 'Str') {
    Add-Ev @{ Name=$ci.Name; Src='Known text inside file'; Path=$ci.Path; PresentNow=$true; Mod=$ci.Mod; Created=$ci.Created; Note='the program contains this tool''s own name text (renamed copy or another build)' }
    continue
  }
  if ($ci.Kind -eq 'Ahk') {
    $an = Find-NameToken "$($ci.Path)"
    $cat = if ($ahkPseudo.ContainsKey($ci.Cat)) { $ci.Cat } else { 'generic' }
    if (-not $an -and $ci.Path -match '(?i)visionary') { $an = 'visionary' }
    if (-not $an) { $an = $ahkPseudo[$cat] }
    Add-Ev @{ Name=$an; Src='AutoHotkey macro that targets Roblox'; Path=$ci.Path; PresentNow=$true; Mod=$ci.Mod; Created=$ci.Created; Note=("AutoHotkey script: " + $ahkLabel[$cat] + " - " + $ci.Hits) }
    continue
  }
  $nm = Find-NameToken "$($ci.Path)"
  if ($ci.Kind -eq 'Bin') {
    if ($apiShown -ge 12) { continue }
    $sg = Get-AuthenticodeSignature -LiteralPath $ci.Path -ErrorAction SilentlyContinue
    $sn = ''; if ($sg.SignerCertificate) { $sn = ($sg.SignerCertificate.Subject -replace '.*CN=([^,]+).*','$1') }
    if ("$($sg.Status)" -eq 'Valid' -and $sn -match $trustedPub) { continue }
    $apiShown++
    if (-not $nm) { $nm = $unkApi }
    Add-Ev @{ Name=$nm; Src='Executor API strings inside file'; Path=$ci.Path; PresentNow=$true; Mod=$ci.Mod; Created=$ci.Created; Note="the file contains exploit API names: $($ci.Hits)" }
  } elseif ($ci.Kind -eq 'Lua') {
    if (-not $nm) { $nm = $unkLua }
    Add-Ev @{ Name=$nm; Src='Exploit script (Lua)'; Path=$ci.Path; PresentNow=$true; Mod=$ci.Mod; Created=$ci.Created; Note='Lua script using loadstring(game:HttpGet) / getgenv / hookfunction' }
  }
}
# DNS cache: websites of these tools that this PC looked up recently (does not prove the software was run)
try {
  Set-Stage 'Checking the DNS cache'
  foreach ($dc in @(Get-DnsClientCache -ErrorAction Stop)) {
    $dn = "$($dc.Entry)"
    if ($dn -notmatch $patNG -or $dn -match $exclude) { continue }
    $n = Find-NameToken $dn
    if ($n) {
      if (-not $webHits.ContainsKey($n)) { $webHits[$n] = New-Object System.Collections.Generic.List[string] }
      $tag = "DNS lookup: $dn"
      if (-not $webHits[$n].Contains($tag)) { $webHits[$n].Add($tag) }
    }
  }
} catch {}
Set-Stage 'Collecting the file scan results'
# ---------- 5b. Collect the file-scan results ----------
$scanMethod = 'fast scanner'
$hits = @()
if ($scanStarted) {
  $hits = @([QScanJ4]::Finish() | Select-Object -Unique)
  $timedOut = [QScanJ4]::TimedOut
} elseif ($seeds -and $seeds.Count -gt 0) {
  $scanMethod = 'slower fallback scanner (the fast scanner could not load)'
  $hits = @(Scan-PS $seeds 4 | Select-Object -Unique)
}
foreach ($h in $hits) {
  $kind = $h.Substring(0,1); $p = $h.Substring(2)
  if ($p -match $exclude) { continue }
  if ($kind -eq 'A') { Add-AutoexecEv $p; continue }
  $n = Match-Leaf (Leaf-Of $p) ($kind -eq 'D')
  if (-not $n) { continue }
  $fi = Get-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue
  if ($kind -eq 'D') {
    $i = Inspect-Folder $p
    if (-not (Folder-Qualifies $n $i)) { continue }
    Add-Ev @{ Name=$n; Src='Install folder'; Path=$p; HasExec=$i.HasExec; Mod=$fi.LastWriteTime; Created=$fi.CreationTime; Note=$i.Note }
  } else {
    Add-Ev @{ Name=$n; Src='File on disk'; Path=$p; PresentNow=$true; Mod=$fi.LastWriteTime; Created=$fi.CreationTime }
  }
}

Set-Stage 'Checking signatures and hashes of the files found'
# ---------- 6. Look inside files that exist now (signature, hash, download source) - all in parallel ----------
$legit = New-Object 'System.Collections.Generic.HashSet[string]'
$inspect = @{}
$cands = New-Object System.Collections.Generic.List[string]
foreach ($e in $ev) {
  if ($cands.Count -ge 12) { break }
  if ($e.Path -and ($e.Src -in 'File on disk','Running process') -and $e.Path -match '\.(exe|dll|scr|sys)$' -and -not $cands.Contains($e.Path) -and (Test-Path -LiteralPath $e.Path)) { $cands.Add($e.Path) }
}
$jobs = @()
foreach ($cp in $cands) {
  try {
    $ps = [powershell]::Create()
    [void]$ps.AddScript({
      param($path)
      $fi = Get-Item -LiteralPath $path -Force
      $sig = Get-AuthenticodeSignature -LiteralPath $path
      $signer = ''; if ($sig.SignerCertificate) { $signer = ($sig.SignerCertificate.Subject -replace '.*CN=([^,]+).*','$1') }
      $hash = $null; if ($fi.Length -le 50MB) { $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash }
      $zone = ''
      try { $z = Get-Content -LiteralPath $path -Stream Zone.Identifier -ErrorAction Stop; $zone = (($z | Where-Object { $_ -match '^(HostUrl|ReferrerUrl)=' }) -join '  ') } catch {}
      [pscustomobject]@{ Size=$fi.Length; Signature="$($sig.Status)"; Signer=$signer; Sha256=$hash; Download=$zone }
    }).AddArgument($cp)
    $jobs += [pscustomobject]@{ PS=$ps; H=$ps.BeginInvoke(); Path=$cp }
  } catch {}
}
foreach ($j in $jobs) {
  try {
    if ($j.H.AsyncWaitHandle.WaitOne((RemainMs 3000))) {
      $r = @($j.PS.EndInvoke($j.H))
      if ($r.Count -gt 0 -and $r[0]) {
        $inspect[$j.Path.ToLower()] = $r[0]
        if ("$($r[0].Signature)" -eq 'Valid' -and $r[0].Signer -match $trustedPub) { [void]$legit.Add($j.Path.ToLower()) }
      }
    } else { $j.PS.Stop() }
  } catch {}
  try { $j.PS.Dispose() } catch {}
}
$evL = @($ev | Where-Object { -not ($_.Path -and $legit.Contains($_.Path.ToLower())) })

Set-Stage 'Working out which drive each item was on'
# ---------- 7. Work out location + presence for each piece of evidence, then apply Internal/External mode ----------
function Get-Class($short) {
  if     ($short -match 'USB|REMOVABLE|NOT PRESENT|NOT CONNECTED|NOT MOUNTED|EXTERNAL|NETWORK|OPTICAL') { 'External' }
  elseif ($short -eq 'NAME ONLY') { 'Name' }
  else { 'Internal' }
}
# Program  = a real program/archive/process that exists RIGHT NOW (verified)
# Leftover = traces remain (folder with only config/scripts, uninstall entry, startup/service/task entry whose file is gone, registry key, shortcut)
# History  = only old records; the thing itself no longer exists
function Get-EvKind($e, $ex) {
  if ($e.Src -in 'Running process','Running process (command line)','Loaded inside Roblox (injected)') { return 'Program' }
  if ($e.Path -and "$($e.Path)" -match '\.lnk$') { if ($ex -eq $true) { return 'Leftover' } else { return 'History' } }
  if ($e.Src -in 'Install folder','Executor folder layout (autoexec)','Executor folder layout (Monaco editor)') {
    if ($ex -eq $true -and $e.HasExec) { return 'Program' }
    if ($ex -eq $true) { return 'Leftover' }
    return 'History'
  }
  if ($e.Src -eq 'Installed program') { if ($ex -eq $true -and $e.HasExec) { return 'Program' } else { return 'Leftover' } }
  if ($e.Src -in 'Startup entry','Service','Scheduled task') { if ($ex -eq $true) { return 'Program' } else { return 'Leftover' } }
  if ($e.Src -in 'Registry key','Defender exclusion') { return 'Leftover' }
  if ($e.Src -eq 'Defender exclusion (history)') { if ($ex -eq $true) { return 'Leftover' } else { return 'History' } }
  if ($ex -eq $true) { return 'Program' }
  return 'History'
}
foreach ($e in $evL) {
  $ex = Test-Exists $e.Path
  $loc = Locate $e.Path $e.Unm $e.Serial $e.DType
  $kindE = Get-EvKind $e $ex
  $present = ($kindE -eq 'Program')
  $e | Add-Member -NotePropertyName Exists -NotePropertyValue $ex -Force
  $e | Add-Member -NotePropertyName Loc -NotePropertyValue $loc -Force
  $e | Add-Member -NotePropertyName Kind -NotePropertyValue $kindE -Force
  $e | Add-Member -NotePropertyName Present -NotePropertyValue $present -Force
  $cls = Get-Class $loc.Short
  if ($cls -eq 'Name' -and $e.Src -in 'Registry key','Installed program','Startup entry','Service','Scheduled task','Running process','Running process (command line)','Defender exclusion','Defender exclusion (history)','Loaded inside Roblox (injected)') { $cls = 'Internal' }
  $e | Add-Member -NotePropertyName Class -NotePropertyValue $cls -Force
}
if ($mode -eq 'Both') { $evF = @($evL) }
else {
  $evF = @($evL | Where-Object { $_.Class -eq $mode })
  # name-only evidence (e.g. Prefetch) is kept only when the same name has located evidence in this mode
  $located = @{}
  foreach ($x in $evF) { $located[$x.Name] = $true }
  $evF += @($evL | Where-Object { $_.Class -eq 'Name' -and $located.ContainsKey($_.Name) })
}

Set-Stage 'Linking evidence that belongs together'
# ---------- 7b. Entity linking: evidence with no name of its own joins the tool it belongs to (same file path, or inside that tool's folder) ----------
$genericDir = '(?i)^(Downloads|Desktop|Documents|Temp|AppData|Local|Roaming|LocalLow|Users|Program Files|Program Files \(x86\)|ProgramData|Public|Windows|System32|OneDrive|Programs)$'
$pathName = @{}; $dirName = @{}
foreach ($x in $evF) {
  if (-not $x.Path -or ($pseudoAll -contains $x.Name)) { continue }
  $k = "$($x.Path)".ToLower().TrimEnd('\')
  if (-not $pathName.ContainsKey($k)) { $pathName[$k] = $x.Name }
  if (($x.Src -in 'Install folder','Executor folder layout (autoexec)','Executor folder layout (Monaco editor)') -and ($genericNames -notcontains $x.Name)) { $dirName[$k] = $x.Name }
}
foreach ($x in $evF) {
  if (-not $x.Path -or ($pseudoAll -notcontains $x.Name)) { continue }
  $p = "$($x.Path)".TrimEnd('\'); $nn = $null
  if ($pathName.ContainsKey($p.ToLower())) { $nn = $pathName[$p.ToLower()] }
  else {
    $q = $p
    for ($lvl = 0; $lvl -lt 4 -and -not $nn; $lvl++) {
      $q = Split-Path -Parent $q
      if (-not $q -or $q -match '^[A-Za-z]:\\?$') { break }
      if ($dirName.ContainsKey($q.ToLower())) { $nn = $dirName[$q.ToLower()]; break }
      $lf = Leaf-Of $q
      if ($lf -and $lf -notmatch $genericDir) { $mm = Match-Leaf $lf $true; if ($mm -and ($genericNames -notcontains $mm)) { $nn = $mm } }
    }
  }
  if ($nn -and ($nn -ne $x.Name)) { $x.Name = $nn; $x | Add-Member -NotePropertyName Linked -NotePropertyValue $true -Force }
}

Set-Stage 'Building the results'
# ---------- 8. Build the results ----------
function Fmt($d) { if ($d) { ([datetime]$d).ToString('yyyy-MM-dd HH:mm') } else { 'unknown' } }
# Evidence SCORE (v2.4): strongest source + 15 for every extra CATEGORY that agrees (max 3) + 10 for every extra source in an already-counted category (max 3)
#   + 10 if it exists now + 15 for look-alike name tricks.   HIGH >= 65, MEDIUM >= 35.
function Get-Score($e, $pres) {
  $bySrc = @{}
  foreach ($x in $e) { $bySrc[$x.Src] = 1 }
  $items = @($bySrc.Keys | ForEach-Object { [pscustomobject]@{ Src=$_; W=$(if ($srcWeight.ContainsKey($_)) { [int]$srcWeight[$_] } else { 10 }); Cat=$(if ($srcCat.ContainsKey($_)) { $srcCat[$_] } else { 'History' }) } } | Sort-Object W -Descending)
  $score = [double]$items[0].W
  $cats = @($items | ForEach-Object { $_.Cat } | Select-Object -Unique)
  $score += 15 * [math]::Min(3, ($cats.Count - 1))
  $score += 10 * [math]::Min(3, ($items.Count - $cats.Count))
  if ($pres.Count -gt 0) { $score += 10 }
  if (@($e | Where-Object { $_.Evasion }).Count -gt 0) { $score += 15 }
  [pscustomobject]@{ Score=[int][math]::Min(100, [math]::Round($score)); Cats=$cats }
}
function Get-TypeText($n) {
  if ($toolNames -contains $n) { 'Tool' }
  elseif ($externalNames -contains $n -or $n -eq $unkMem -or $n -eq $unkOvl -or $n -eq $unkExt) { 'External' }
  elseif ($macroNames -contains $n -or $ahkPseudo.Values -contains $n) { 'Macro' }
  elseif ($internalNames -contains $n -or $n -eq $unkMod -or $n -eq $unkCli) { 'Internal' }
  elseif ($n -eq $unkKw) { 'Unknown' }
  else { 'Unknown' }
}
$out = New-Object System.Collections.Generic.List[string]
$notFound = New-Object System.Collections.Generic.List[string]
$hiddenGeneric = 0
$found = 0
$sumRows = New-Object System.Collections.Generic.List[string]
$resRows = New-Object System.Collections.Generic.List[object]
$body = New-Object System.Collections.Generic.List[string]
foreach ($n in (@($names) + $unkName + $unkMod + $unkApi + $unkLua + @($ahkPseudo.Values) + $unkMem + $unkOvl + $unkExt + $unkCli + $unkKw)) {
  $e = @($evF | Where-Object { $_.Name -eq $n })
  if ($e.Count -eq 0) { if ($n -notin $pseudoAll) { $notFound.Add($n) }; continue }
  $srcs = @($e | ForEach-Object { $_.Src } | Sort-Object -Unique)
  $pres = @($e | Where-Object { $_.Kind -eq 'Program' })
  $left = @($e | Where-Object { $_.Kind -eq 'Leftover' })
  if (($genericNames -contains $n) -and $pres.Count -eq 0 -and $srcs.Count -lt 2) { $hiddenGeneric++; continue }
  if (($weakNames -contains $n) -and $srcs.Count -lt 2) { $hiddenGeneric++; continue }
  $found++
  $dStart = $body.Count
  $gs = Get-Score $e $pres; $score = $gs.Score; $cats = @($gs.Cats)
  # an unrecognized program can only reach HIGH when it exists now AND at least two kinds of evidence agree, one of them about Roblox behavior
  if ($pseudoAll -contains $n) { $conf = if ($pres.Count -gt 0 -and $cats.Count -ge 2 -and ($cats -contains 'Behavior') -and $score -ge 65) { 'HIGH' } elseif ($pres.Count -gt 0) { 'MEDIUM' } else { 'LOW' } }
  elseif ($score -ge 65) { $conf = 'HIGH' } elseif ($score -ge 35) { $conf = 'MEDIUM' } else { $conf = 'LOW' }
  $status = if ($pres.Count -gt 0) { 'ON YOUR PC NOW' } elseif ($left.Count -gt 0) { 'UNINSTALLED  -  program files are gone, only leftovers remain' } else { 'NOT ON YOUR PC NOW  -  but it WAS on your PC before' }
  $body.Add("[$found] $(Name-Disp $n)    $status    (confidence: $conf)")
  $body.Add("      Was on this PC     : YES")
  $body.Add("      Evidence score     : $score / 100   [$conf]")
  $body.Add("      Evidence categories: $($cats -join ', ')  ($($cats.Count) of 6 kinds agree)")
  $lkn = @($e | Where-Object { $_.Linked }).Count
  if ($lkn -gt 0) { $body.Add("      Linked by path     : $lkn item(s) had no name of their own and were joined to this tool by file path or folder") }
  $body.Add("      Evidence weights   : $((@($srcs | ForEach-Object { '{0} ({1})' -f $_, $(if ($srcWeight.ContainsKey($_)) { $srcWeight[$_] } else { 10 }) })) -join ', ')")
  if (@($e | Where-Object { $_.Evasion }).Count -gt 0) { $body.Add("      Name trick         : the file name uses look-alike or hidden characters to dodge name-based checks") }

  # file name(s)
  $leaves = @($e | Where-Object { $_.Path } | ForEach-Object { Leaf-Of $_.Path } | Where-Object { $_ } | Sort-Object -Unique | Select-Object -First 3)
  if ($leaves.Count -eq 0) { $leaves = @(($e | Where-Object { $_.Note } | Select-Object -First 1).Note) }
  if ($leaves.Count -gt 0 -and $leaves[0]) { $body.Add("      File name          : $($leaves -join ', ')") }

  if ($pres.Count -gt 0) {
    $shownP = @($pres | Where-Object { $_.Path } | Group-Object { $_.Path.ToLower() } | ForEach-Object { $_.Group[0] } | Select-Object -First 3)
    foreach ($p in $shownP) { $body.Add("      On your PC now at  : $($p.Path)   [$($p.Loc.Short)]") }
    if ($shownP.Count -eq 0) { $body.Add("      On your PC now as  : $((($pres | ForEach-Object { $_.Src } | Sort-Object -Unique) -join ', '))") }
  }

  # leftovers that are still there (folders, uninstall/startup/service/task entries, registry keys, shortcuts)
  if ($left.Count -gt 0) {
    $lt = @($left | ForEach-Object { if ($_.Path) { "$($_.Path)   [$($_.Src)]" } else { "$($_.Src): $($_.Note)" } } | Sort-Object -Unique | Select-Object -First 4)
    foreach ($x in $lt) { $body.Add("      Leftover still there: $x") }
    $ln = @($left | Where-Object { $_.Note -match '^contains:' } | Select-Object -First 1)
    if ($ln.Count -gt 0) { $body.Add("      Leftover contents  : $($ln[0].Note -replace '^contains: ','')") }
  }
  # old paths that history remembers but no longer exist (deleted / uninstalled)
  $gone = @($e | Where-Object { $_.Path -and $_.Kind -eq 'History' -and $_.Exists -eq $false } | Group-Object { $_.Path.ToLower() } | ForEach-Object { $_.Group[0] } | Select-Object -First 3)
  foreach ($g in $gone) { $body.Add("      No longer exists   : $($g.Path)   (deleted or uninstalled)") }

  # last used
  $lastUsedTxt = 'no record'
  $runs = @($e | Where-Object { $_.Run } | Sort-Object Run -Descending)
  if ($runs.Count -gt 0) {
    $r = $runs[0]
    $lastUsedTxt = Fmt $r.Run
    $body.Add("      Last used          : $(Fmt $r.Run)   [$($r.RunKind)]")
  } elseif (@($e | Where-Object { $_.Src -in 'Windows run history' }).Count -gt 0) {
    $lastUsedTxt = 'ran (no time stored)'
    $body.Add("      Last used          : it was run, but Windows did not store the time" + $(if (-not $isAdmin) { ' (admin edition can find more)' } else { '' }))
  } else {
    $body.Add("      Last used          : no record of it being run")
  }

  # how many times it was opened
  $uaSum = [int](($e | Where-Object { $_.Runs } | Measure-Object -Property Runs -Sum).Sum)
  $pfSum = [int](($e | Where-Object { $_.PfRuns } | Measure-Object -Property PfRuns -Sum).Sum)
  $opened = [math]::Max($uaSum, $pfSum)
  if ($opened -gt 0) {
    $parts = @()
    if ($uaSum -gt 0) { $parts += "Windows UserAssist: $uaSum" }
    if ($pfSum -gt 0) { $parts += "Prefetch: $pfSum" }
    $body.Add("      Times opened       : $opened   [$($parts -join ' | ')]")
    $rl = @($e | Where-Object { $_.RunList } | ForEach-Object { $_.RunList } | Sort-Object -Descending | Select-Object -First 8)
    if ($rl.Count -gt 1) { $body.Add("      Recent open times  : $((($rl | ForEach-Object { Fmt $_ }) -join ', '))") }
    $openedTxt = "$opened"
  } else {
    $body.Add("      Times opened       : unknown - Windows kept no run counter for it" + $(if (-not $isAdmin) { ' (admin edition reads Prefetch counters)' } else { '' }))
    $openedTxt = 'unknown'
  }

  # last seen / first seen
  $dates = New-Object System.Collections.Generic.List[datetime]
  foreach ($x in $e) { foreach ($d in @($x.Run, $x.Mod, $x.Created, $x.Deleted)) { if ($d -is [datetime]) { $dates.Add($d) } } }
  $dsorted = @($dates | Sort-Object)
  if ($pres.Count -gt 0) {
    $body.Add("      Last seen on PC    : right now (still there)")
  } elseif ($left.Count -gt 0 -and $dsorted.Count -gt 0) {
    $body.Add("      Last seen on PC    : $(Fmt $dsorted[-1])   (the program itself is gone; only leftovers are still there)")
  } elseif ($dsorted.Count -gt 0) {
    $delE = @($e | Where-Object { $_.Deleted } | Sort-Object Deleted -Descending | Select-Object -First 1)
    $body.Add("      Last seen on PC    : $(Fmt $dsorted[-1])" + $(if ($delE.Count -gt 0) { "   (deleted $(Fmt $delE[0].Deleted))" } else { '' }))
  } else {
    $body.Add("      Last seen on PC    : unknown date (history shows it existed, but no time was stored)")
  }
  if ($dsorted.Count -gt 0) { $body.Add("      First seen on PC   : $(Fmt $dsorted[0])") }

  if ($pres.Count -eq 0) {
    $lastPlace = @($e | Where-Object { $_.Path } | Sort-Object @{E={ if ($_.Run) { $_.Run } elseif ($_.Deleted) { $_.Deleted } else { [datetime]::MinValue } }} -Descending | Select-Object -First 1)
    if ($lastPlace.Count -gt 0) {
      $body.Add("      Last known spot    : $($lastPlace[0].Path)   [$($lastPlace[0].Loc.Short)]")
      if ($lastPlace[0].Class -eq 'External') { $body.Add("      Drive note         : $($lastPlace[0].Loc.Detail)") }
    }
  }
  # external drive info for present items
  foreach ($p in @($pres | Where-Object { $_.Class -eq 'External' } | Select-Object -First 1)) { $body.Add("      Drive note         : $($p.Loc.Detail)") }

  # file details
  foreach ($p in @($pres | Where-Object { $_.Path -and $inspect.ContainsKey($_.Path.ToLower()) } | Select-Object -First 1)) {
    $i = $inspect[$p.Path.ToLower()]
    $body.Add("      File details       : $('{0:N0}' -f $i.Size) bytes | signature: $($i.Signature) $($i.Signer)")
    if ($i.Sha256)    { $body.Add("      SHA256             : $($i.Sha256)") }
    if ($i.Download)  { $body.Add("      Downloaded from    : $($i.Download)") }
  }
  $body.Add("      Seen in            : $($srcs -join ', ')")
  $dl = @($e | Where-Object { $_.Src -eq 'Downloaded from website' -and $_.Note } | Select-Object -First 1)
  if ($dl.Count -gt 0) { $body.Add("      Download source    : $($dl[0].Note -replace '^downloaded from: ','')") }
  $nt = @($e | Where-Object { $_.Note -and $_.Src -in 'Running process (command line)','Dialog history (Open/Save)' } | Select-Object -First 2)
  foreach ($x in $nt) { $body.Add("      Trace              : $($x.Note)") }
  if ($psHist.ContainsKey($n)) { foreach ($px in @($psHist[$n] | Select-Object -First 2)) { $body.Add("      Trace              : typed in PowerShell: $px") } }
  if ($webHits.ContainsKey($n)) { $body.Add("      Website activity   : $($webHits[$n].Count) related page(s) in browser history, e.g. $($webHits[$n][0])") }
  $sumRows.Add(("{0,-12} {1,-11} {2,-13} {3}" -f (Name-Disp $n), $(if ($pres.Count -gt 0) { 'YES' } elseif ($left.Count -gt 0) { 'LEFTOVERS' } else { 'no' }), $openedTxt, $lastUsedTxt))
  $stState = if ($pres.Count -gt 0) { 'now' } elseif ($left.Count -gt 0) { 'left' } else { 'hist' }
  $stText  = if ($pres.Count -gt 0) { 'On this PC now' } elseif ($left.Count -gt 0) { 'Uninstalled, leftovers remain' } else { 'History only (gone)' }
  $openPath = (@($pres | Where-Object { $_.Path }) | Select-Object -First 1).Path
  if (-not $openPath) { $openPath = (@($left | Where-Object { $_.Path }) | Select-Object -First 1).Path }
  $resRows.Add([pscustomobject]@{ Name=(Name-Disp $n); Type=(Get-TypeText $n); Path=$openPath; Status=$stText; State=$stState; Conf=$conf; Score=$score; Opened=$openedTxt; Last=$lastUsedTxt
                                  Detail=(@($body.GetRange($dStart, $body.Count - $dStart)) -join "`r`n") })
  $body.Add('')
}

# ---------- Leads that are not detections ----------
$lead = New-Object System.Collections.Generic.List[string]; $leadN = 0
if ($memNote) { $lead.Add('MEMORY / OVERLAY CHECK'); $lead.Add("   $memNote"); $lead.Add('') }
if ($rbxLeads -and $rbxLeads.Count -gt 0) { $leadN += $rbxLeads.Count; $lead.Add('ROBLOX CLIENT CHECK'); foreach ($x in $rbxLeads) { $lead.Add("   - $x") }; $lead.Add('') }
if ($rbxDlls -and $rbxDlls.Count -gt 0) { $leadN += $rbxDlls.Count; $lead.Add('UNSIGNED / SYSTEM-NAMED DLLS INSIDE THE ROBLOX FOLDER (a dropped DLL is typical of an internal executor)'); foreach ($x in ($rbxDlls | Select-Object -First 10)) { $lead.Add("   - $x") }; $lead.Add('') }
if ($unusualMods -and $unusualMods.Count -gt 0) { $leadN += $unusualMods.Count; $lead.Add('UNRECOGNIZED DLLS CURRENTLY LOADED INSIDE ROBLOX'); foreach ($x in ($unusualMods | Select-Object -First 10)) { $lead.Add("   - $x") }; $lead.Add('') }
if ($driverLeads -and $driverLeads.Count -gt 0) { $leadN += $driverLeads.Count; $lead.Add('DRIVERS THAT CHEATS USE TO REACH ROBLOX MEMORY (a lead, not proof)'); foreach ($x in ($driverLeads | Select-Object -First 8)) { $lead.Add("   - $x") }; $lead.Add('') }
if ($unsignedRun -and $unsignedRun.Count -gt 0) { $leadN += $unsignedRun.Count; $lead.Add('UNSIGNED PROGRAMS RUNNING FROM USER FOLDERS WHILE ROBLOX IS OPEN (a lead, not proof)'); foreach ($x in ($unsignedRun | Select-Object -First 8)) { $lead.Add("   - $x") }; $lead.Add('') }
if ($isAdmin -and $exclPaths.Count -gt 0) { $lead.Add("ANTIVIRUS (DEFENDER) EXCLUSIONS: $($exclPaths.Count)"); foreach ($x in ($exclPaths | Select-Object -First 8)) { $lead.Add("   - $x$(if (-not (Test-Path -LiteralPath $x)) { '   (folder no longer exists)' } else { '' })") }; $lead.Add('') }
if ($flagSeen -and $flagSeen.Count -gt 0) { $lead.Add('IGNORED AS FFLAG INJECTORS (they edit Roblox flags through memory offsets)'); foreach ($x in $flagSeen) { $lead.Add("   - $x") }; $lead.Add('') }
if ($lockedProfiles -and $lockedProfiles.Count -gt 0) { $leadN += $lockedProfiles.Count; $lead.Add('USER ACCOUNTS THAT COULD NOT BE OPENED (run the admin edition as administrator)'); foreach ($x in $lockedProfiles) { $lead.Add("   - $($x.Name)") }; $lead.Add('') }
if ($cStat) { $lead.Add('COVERAGE'); $lead.Add("   Looked inside $($cStat.Files) program files and $($cStat.Lua) Lua/AutoHotkey scripts" + $(if ($cStat.Cut) { ' (stopped at the time limit).' } else { '.' })) }
if ($lead.Count -eq 0) { $lead.Add('No extra leads or notes.') }

$shownNames = @($resRows | ForEach-Object { $_.Name })
$psLeadLines = New-Object System.Collections.Generic.List[string]
foreach ($pk in $psHist.Keys) { if ($shownNames -notcontains (Name-Disp $pk)) { $psLeadLines.Add("   - $(Name-Disp $pk): $($psHist[$pk][0])") } }
if ($psLeadLines.Count -gt 0) {
  $leadN += $psLeadLines.Count
  $lead.Insert(0, '')
  $lead.InsertRange(0, [string[]](@('POWERSHELL HISTORY MENTIONS A TOOL NAME (not proof it was ever on this PC)') + @($psLeadLines | Select-Object -First 8)))
  if ($lead.Contains('No extra leads or notes.')) { [void]$lead.Remove('No extra leads or notes.') }
}
# ---------- VERDICT ----------
$nowHigh = @($resRows | Where-Object { $_.State -eq 'now' -and $_.Conf -eq 'HIGH' }).Count
$nowAny  = @($resRows | Where-Object { $_.State -eq 'now' }).Count
$pastMed = @($resRows | Where-Object { $_.State -ne 'now' -and $_.Conf -ne 'LOW' }).Count
if     ($nowHigh -gt 0) { $verdict = 'Cheat software found on this PC';        $verdictKey = 'red';   $verdictSub = "$nowHigh high-confidence detection(s) on this PC right now." }
elseif ($nowAny  -gt 0) { $verdict = 'Possible cheat software found on this PC';   $verdictKey = 'amber'; $verdictSub = 'Something matching a known name is here now, but the evidence is not conclusive.' }
elseif ($pastMed -gt 0) { $verdict = 'Traces of past use found';               $verdictKey = 'amber'; $verdictSub = 'Nothing is here now, but Windows history shows it was here or was run.' }
elseif ($found   -gt 0) { $verdict = 'Only weak traces found';                 $verdictKey = 'muted'; $verdictSub = 'Low-confidence traces only (history, names, website visits). A lead, not proof.' }
elseif ($leadN   -gt 0) { $verdict = 'No known tool found, but there are leads';  $verdictKey = 'amber'; $verdictSub = "No known name matched, but $leadN lead(s) are worth a look (see Leads and notes)." }
else                    { $verdict = 'Nothing found';                          $verdictKey = 'green'; $verdictSub = 'No known tool, trace or lead was found. A scan cannot prove a PC is clean; it only checks what it knows.' }

$secs = [math]::Round($sw.Elapsed.TotalSeconds, 1)
$out.Add("$title  -  RESULTS")
$out.Add("VERDICT: $verdict")
$out.Add("Mode: $($mode.ToUpper())   |   $(if ($isAdmin) {'Admin edition (full history)'} else {'No-admin edition'})   |   finished in ${secs}s")
$out.Add('')
if ($found -gt 0) {
  $out.Add("FOUND $found of $($names.Count) names:")
  $out.Add('  ON YOUR PC NOW = a real program/file/process exists right now (verified)')
  $out.Add('  UNINSTALLED    = the program files are gone, but leftovers (folders, uninstall/startup entries, registry) remain')
  $out.Add('  NOT ON YOUR PC = only old history; nothing of it exists any more')
  $out.Add('  Evidence score : HIGH >= 65, MEDIUM >= 35, LOW below (see the weights printed for each detection)')
  $out.Add(''); $out.AddRange($body)
}
else { $out.Add("NOTHING FOUND for any of the $($names.Count) names in $($mode.ToUpper()) mode."); $out.Add('') }
if ($notFound.Count -gt 0) { $out.Add("Not found: $($notFound -join ', ')"); $out.Add('') }

$webOnlyLines = New-Object System.Collections.Generic.List[string]
foreach ($wn in $webHits.Keys) {
  $has = @($evF | Where-Object { $_.Name -eq $wn }).Count -gt 0
  if (-not $has) { foreach ($u in @($webHits[$wn] | Select-Object -First 2)) { $webOnlyLines.Add("   - $(Name-Disp $wn): $u") } }
}
if ($webOnlyLines.Count -gt 0) {
  $out.Add('Related website activity in your browser history (this alone does NOT prove the software was on this PC):')
  $out.AddRange($webOnlyLines); $out.Add('')
}
if ($isAdmin -and $exclPaths.Count -gt 0) {
  $out.Add("Antivirus (Defender) exclusions on this PC: $($exclPaths.Count)   (executors usually need one for their folder)")
  foreach ($xp in ($exclPaths | Select-Object -First 8)) { $out.Add("   - $xp$(if (-not (Test-Path -LiteralPath $xp)) { '   (folder no longer exists)' } else { '' })") }
  $out.Add('')
}
if ($rbxDlls.Count -gt 0) {
  $out.Add('Unsigned / system-named DLLs inside the Roblox folder (a dropped DLL is typical of an internal executor, but a few legit libraries are unsigned too):')
  foreach ($rd in ($rbxDlls | Select-Object -First 8)) { $out.Add("   - $rd") }
  $out.Add('')
}
if ($rbxLeads.Count -gt 0) { $out.Add('Roblox client check:'); foreach ($x in $rbxLeads) { $out.Add("   - $x") }; $out.Add('') }
if ($unusualMods.Count -gt 0) {
  $out.Add('Unrecognized DLLs currently loaded inside Roblox (could be overlays/drivers, or an injected tool):')
  foreach ($um in ($unusualMods | Select-Object -First 8)) { $out.Add("   - $um") }
  $out.Add('')
}
if ($doExternal) {
  $out.Add('USB storage devices that have been plugged into this PC (history):')
  $ul = @($usb.Values | Sort-Object @{E={ if ($_.Arrival) { $_.Arrival } elseif ($_.First) { $_.First } else { [datetime]::MinValue } }} -Descending)
  if ($ul.Count -eq 0) { $out.Add('   (none found / not readable)') }
  foreach ($u in ($ul | Select-Object -First 6)) {
    $out.Add("   - $($u.Device)   serial $($u.Serial)   first: $(Fmt $u.First)   last plugged in: $(Fmt $u.Arrival)   last removed: $(Fmt $u.Removal)")
  }
  if ($ul.Count -gt 6) { $out.Add("   ... $($ul.Count - 6) more") }
  $out.Add('   (Windows only keeps limited times for USB devices; older sessions are not stored.)')
  $out.Add('')
}
if ($timedOut) { $out.Add("Note: the file scan stopped at the $scanSeconds s time limit, so very large folders may not be fully covered.") }
$cov = if ($scanStarted) { "Coverage: looked in $([QScanJ4]::Dirs) folders / $([QScanJ4]::Files) files with the $scanMethod." } else { "Coverage: looked in $($script:psDirs) folders with the $scanMethod." }
$out.Add($cov)
if ($cStat) { $out.Add("Content scan: looked inside $($cStat.Files) program files and $($cStat.Lua) Lua/AutoHotkey scripts" + $(if ($cStat.Cut) { ' (stopped at the 9 s limit).' } else { '.' })) }
if ($found -eq 0) { $out.Add('If you know something is installed, tell me its file name and folder: the saved report lists every folder that was scanned.') }
if ($hiddenGeneric -gt 0) { $out.Add("Note: $hiddenGeneric ambiguous common-word match(es) were hidden (only one weak sign, not present on disk).") }
if ($memNote) { $out.Add($memNote) }
if ($driverLeads.Count -gt 0) {
  $out.Add('Drivers that cheats use to read Roblox memory (a lead, not proof: some belong to normal hardware tools):')
  foreach ($dl in ($driverLeads | Select-Object -First 8)) { $out.Add("   - $dl") }
  $out.Add('')
}
if ($unsignedRun.Count -gt 0) {
  $out.Add('Unsigned programs running from user folders while Roblox is open (a lead to look at, not proof):')
  foreach ($ur in ($unsignedRun | Select-Object -First 8)) { $out.Add("   - $ur") }
  $out.Add('')
}
if ($flagSeen.Count -gt 0) { $out.Add("Ignored as FFlag injectors (they edit Roblox flags through memory offsets, not cheats): $($flagSeen -join ', ')") }
if ($otherProfiles.Count -gt 0) {
  $out.Add("Other user accounts on this PC: $($otherProfiles.Count) found, $($readableProfiles.Count) could be checked.")
  if ($lockedProfiles.Count -gt 0) {
    $out.Add("   Could NOT be opened (Windows blocks it for this account): $((($lockedProfiles | ForEach-Object { $_.Name }) -join ', '))")
    $out.Add('   Run the ADMIN edition as administrator to check those accounts too (a tool hidden in another user is only visible to an administrator).')
  }
} elseif ($hkuRead -gt 0 -or $hkuLocked -gt 0) { $out.Add('Other user accounts: none found besides this one.') }
if (-not $isAdmin) { $out.Add('Note: no-admin edition. The ADMIN edition also reads Prefetch + BAM for more exact last-used dates.') }
if ($AdminEdition -and -not $isAdmin) { $out.Add('Note: admin rights were not granted, so admin-only checks were skipped.') }

if ($sumRows.Count -gt 0) {
  $out.Add('')
  $out.Add('================ SUMMARY (end of results) ================')
  $out.Add(("{0,-12} {1,-11} {2,-13} {3}" -f 'NAME','ON PC NOW','TIMES OPENED','LAST USED'))
  $out.AddRange($sumRows)
  $out.Add('Times opened = how many launches Windows counted (it keeps counters only for programs that were actually run).')
}

Set-Stage 'Done'
Close-Splash
# ---------- Console output ----------
Write-Host ''
foreach ($l in $out) {
  $c = 'Gray'
  if ($l -match '^\[\d+\]') { $c = if ($l -match '\s{4}ON YOUR PC NOW\s{4}\(') { 'Red' } elseif ($l -match 'UNINSTALLED') { 'DarkYellow' } else { 'Yellow' } }
  elseif ($l -match '^VERDICT') { $c = switch ($verdictKey) { 'red' { 'Red' } 'amber' { 'Yellow' } 'green' { 'Green' } default { 'Gray' } } }
  elseif ($l -match '^(NOTHING FOUND|Not found)') { $c = 'Green' }
  elseif ($l -match '^(=+ SUMMARY|NAME  )') { $c = 'Cyan' }
  Write-Host $l -ForegroundColor $c
}

# ---------- Save report (with raw evidence for troubleshooting) ----------
$desktop = [Environment]::GetFolderPath('Desktop')
if (-not $desktop -or -not (Test-Path $desktop)) { $desktop = $env:TEMP }
$reportPath = Join-Path $desktop ("JHORFGU_report_{0:yyyyMMdd_HHmmss}.txt" -f (Get-Date))
try {
  $rep = New-Object System.Collections.Generic.List[string]
  $rep.AddRange($out)
  $rep.Add(''); $rep.Add('---------------- FOLDERS SCANNED (root and depth) ----------------')
  foreach ($sp in $seedPaths) { $rep.Add($sp) }
  $rep.Add(''); $rep.Add('---------------- RAW EVIDENCE (for troubleshooting) ----------------')
  foreach ($e in $evF) { $rep.Add(("{0} | {1} | {2} | present={3} | run={4} | mod={5} | {6}" -f $e.Name, $e.Src, $e.Path, $e.Present, $e.Run, $e.Mod, $e.Loc.Short)) }
  $rep | Out-File $reportPath -Encoding UTF8 -ErrorAction Stop
  Write-Host "`nReport saved: $reportPath" -ForegroundColor Green
} catch { $reportPath = $null }

# ==========================================================================
#   PASSWORD-LOCKED UNINSTALL
#   The two passwords are NOT stored in this file. Only salted PBKDF2 hashes (SHA1, 10000 rounds, 32 bytes) are.
#   To change a password, make a new salt + hash with: [Convert]::ToBase64String((New-Object Security.Cryptography.Rfc2898DeriveBytes('NewPass',[byte[]](1..16),10000)).GetBytes(32))
#   (use your own random 16-byte salt) and replace the Salt / Hash pair below.
# ==========================================================================
$uninstallLocks = @(
  @{ Salt = 'SNu5t6gLk0Mi5A7l65iW6Q=='; Hash = 'NhU+uTpxizy+N/dgD7rLkKXPY+8T/sqGXvH2qVkXK0Y=' },
  @{ Salt = 'hcIEeKzjqzxD7x1NcPeJLg=='; Hash = 'J/Ql318ifFG39HkR8qqxRftUbNsXiYgRH3kBVfW5NTM=' }
)
function Test-UninstallPassword($pw) {
  $ok = $false
  try {
    foreach ($lk in $uninstallLocks) {
      $d = New-Object Security.Cryptography.Rfc2898DeriveBytes("$pw", [Convert]::FromBase64String($lk.Salt), 10000)
      $calc = $d.GetBytes(32); $want = [Convert]::FromBase64String($lk.Hash)
      $diff = 0; for ($i = 0; $i -lt 32; $i++) { $diff = $diff -bor ($calc[$i] -bxor $want[$i]) }   # constant-time compare
      if ($diff -eq 0) { $ok = $true }
    }
  } catch {}
  $ok
}

# ---------- Password prompt ----------
function Show-PasswordPrompt($owner) {
  $script:pwOk = $false
  try {
    $script:pwTries = 0
    $f = New-Object Windows.Forms.Form
    $script:pwForm = $f
    $f.Text = 'Uninstall'
    $f.ClientSize = New-Object Drawing.Size(360,170)
    $f.StartPosition = 'CenterParent'; $f.FormBorderStyle = 'FixedDialog'; $f.MaximizeBox = $false; $f.MinimizeBox = $false; $f.ShowInTaskbar = $false
    $f.BackColor = $theme.Bg; $f.Font = New-Object Drawing.Font('Segoe UI',9)
    $f.Controls.Add((New-Banner 'Password required' 'Enter the password to remove the checker and its saved files.' 52))
    $tb = New-Object Windows.Forms.TextBox
    $tb.Location = New-Object Drawing.Point(16,68); $tb.Size = New-Object Drawing.Size(328,23)
    $tb.UseSystemPasswordChar = $true
    $script:pwBox = $tb
    $msg = New-Lbl '' 16 96 328 16
    $msg.ForeColor = $theme.Red
    $script:pwMsg = $msg
    $ok = New-Btn 'OK' 80 26 $false
    $ok.Location = New-Object Drawing.Point(176,132)
    $ca = New-Btn 'Cancel' 80 26 $false
    $ca.Location = New-Object Drawing.Point(264,132)
    $ca.Add_Click({ $script:pwForm.Close() })
    $ok.Add_Click({
      $script:pwTries++
      if (Test-UninstallPassword $script:pwBox.Text) { $script:pwOk = $true; $script:pwForm.Close() }
      else {
        $script:pwBox.Text = ''
        if ($script:pwTries -ge 3) { $script:pwMsg.Text = 'Too many wrong attempts.'; [Windows.Forms.Application]::DoEvents(); Start-Sleep -Milliseconds 800; $script:pwForm.Close() }
        else { $script:pwMsg.Text = "Wrong password ($($script:pwTries) of 3)."; [Windows.Forms.Application]::DoEvents(); Start-Sleep -Milliseconds 700 }
      } })
    $f.Controls.AddRange(@($tb,$msg,$ok,$ca))
    $f.AcceptButton = $ok; $f.CancelButton = $ca
    [void]$f.ShowDialog($owner)
  } catch {}
  $script:pwOk
}
# ---------- What the uninstall removes: only this tool's own files ----------
function Get-UninstallTargets {
  $t = New-Object System.Collections.Generic.List[string]
  foreach ($d in @($env:TEMP, [Environment]::GetFolderPath('Desktop'))) {
    if (-not $d -or -not (Test-Path -LiteralPath $d)) { continue }
    foreach ($pat in 'JHORFGU_*.dll','JHORFGU_report_*.txt') {
      foreach ($x in @(Get-ChildItem -LiteralPath $d -Filter $pat -File -Force -ErrorAction SilentlyContinue)) { if (-not $t.Contains($x.FullName)) { $t.Add($x.FullName) } }
    }
  }
  if ($PSCommandPath -and (Test-Path -LiteralPath $PSCommandPath)) { $t.Add($PSCommandPath) }
  $t.ToArray()
}
function Invoke-Uninstall {
  $targets = @(Get-UninstallTargets)
  $list = if ($targets.Count -gt 0) { ($targets | Select-Object -First 12) -join "`n" } else { '(nothing to remove)' }
  $ans = [Windows.Forms.MessageBox]::Show("This will delete the checker and everything it saved:`n`n$list`n`nContinue?", 'Uninstall', 'YesNo', 'Warning')
  if ($ans -ne 'Yes') { return $false }
  $left = New-Object System.Collections.Generic.List[string]
  foreach ($x in $targets) {
    try { Remove-Item -LiteralPath $x -Force -ErrorAction Stop } catch { $left.Add($x) }
  }
  if ($left.Count -gt 0) {
    # files that are still open (the loaded scanner DLLs, this script) are deleted a few seconds after the window closes
    $q = ($left | ForEach-Object { '"' + $_ + '"' }) -join ' '
    try { Start-Process -FilePath 'cmd.exe' -WindowStyle Hidden -ArgumentList ('/c ping 127.0.0.1 -n 4 > nul & del /f /q ' + $q) } catch {}
  }
  [void][Windows.Forms.MessageBox]::Show("Uninstalled. $($targets.Count) item(s) removed" + $(if ($left.Count -gt 0) { " ($($left.Count) will finish deleting in a few seconds)." } else { '.' }), 'Uninstall')
  $true
}

# ---------- Results window ----------
function Show-Results($text) {
  try {
    $f = New-Object Windows.Forms.Form
    $script:rf = $f
    $f.Text = "$title  -  Results"
    $f.ClientSize = New-Object Drawing.Size(1000,700); $f.MinimumSize = New-Object Drawing.Size(820,520)
    $f.StartPosition = 'CenterScreen'; $f.TopMost = $true; $f.KeyPreview = $true
    $f.BackColor = $theme.Bg; $f.Font = New-Object Drawing.Font('Segoe UI',9)
    $script:fMono  = New-Object Drawing.Font('Consolas',9.5)
    $script:fMonoB = New-Object Drawing.Font('Consolas',9.5,[Drawing.FontStyle]::Bold)
    $script:stFilter = 'all'

    $cNow  = @($resRows | Where-Object { $_.State -eq 'now' }).Count
    $cLeft = @($resRows | Where-Object { $_.State -eq 'left' }).Count
    $cHist = @($resRows | Where-Object { $_.State -eq 'hist' }).Count
    $vCol = switch ($verdictKey) { 'red' { $theme.Red } 'amber' { $theme.Amber } 'green' { $theme.Green } default { $theme.Muted } }

    # header
    $hd = New-Object Windows.Forms.Panel
    $hd.Dock = 'Top'; $hd.Height = 78; $hd.BackColor = [Drawing.Color]::White
    $h1 = New-Lbl $verdict 14 8
    $h1.Font = New-Object Drawing.Font('Segoe UI',12,[Drawing.FontStyle]::Bold); $h1.ForeColor = $vCol
    $h2 = New-Lbl $verdictSub 15 34
    $h3 = New-Lbl "On this PC: $cNow     Leftovers: $cLeft     History only: $cHist     Leads: $leadN     |     $mode scan, $secs s" 15 55
    $h3.ForeColor = $theme.Muted
    $ln = New-Object Windows.Forms.Panel; $ln.Dock = 'Bottom'; $ln.Height = 1; $ln.BackColor = $theme.Line
    $hd.Controls.AddRange(@($h1,$h2,$h3,$ln))

    # filter row
    $tbp = New-Object Windows.Forms.Panel
    $tbp.Dock = 'Top'; $tbp.Height = 36
    $l1 = New-Lbl 'Show:' 12 10
    $cmb = New-Object Windows.Forms.ComboBox
    $cmb.DropDownStyle = 'DropDownList'; $cmb.Location = New-Object Drawing.Point(54,6); $cmb.Width = 140
    [void]$cmb.Items.AddRange(@("All ($($resRows.Count))","On this PC ($cNow)","Leftovers ($cLeft)","History only ($cHist)"))
    $cmb.SelectedIndex = 0
    $script:cmb = $cmb
    $l2 = New-Lbl 'Filter:' 214 10
    $tb = New-Object Windows.Forms.TextBox
    $tb.Location = New-Object Drawing.Point(256,6); $tb.Width = 220
    $script:tb = $tb
    $tbp.Controls.AddRange(@($l1,$cmb,$l2,$tb))

    # table
    $dg = New-Object Windows.Forms.DataGridView
    $script:dg = $dg
    $dg.Dock = 'Fill'; $dg.ReadOnly = $true; $dg.AllowUserToAddRows = $false; $dg.AllowUserToDeleteRows = $false; $dg.AllowUserToResizeRows = $false
    $dg.RowHeadersVisible = $false; $dg.SelectionMode = 'FullRowSelect'; $dg.MultiSelect = $false
    $dg.BackgroundColor = [Drawing.Color]::White; $dg.BorderStyle = 'None'; $dg.RowTemplate.Height = 22; $dg.AutoSizeRowsMode = 'None'
    foreach ($cd in @(@('Name','Name',0), @('Type','Type',70), @('Status','Status',190), @('Conf','Confidence',80), @('Score','Score',55), @('Opened','Times opened',90), @('Last','Last used',130))) {
      $cIdx = $dg.Columns.Add($cd[0], $cd[1])
      $col = $dg.Columns[$cIdx]
      if ($cd[2] -eq 0) { $col.AutoSizeMode = 'Fill'; $col.MinimumWidth = 160 } else { $col.AutoSizeMode = 'None'; $col.Width = $cd[2] }
    }
    $script:fillGrid = {
      param($rows)
      $d = $script:dg
      $ordered = @($rows | Sort-Object @{E={ switch ($_.State) { 'now' {0} 'left' {1} default {2} } }}, @{E={ [int]$_.Score }; Descending=$true})
      $d.SuspendLayout(); $d.Rows.Clear()
      foreach ($r in $ordered) {
        $ri = $d.Rows.Add($r.Name, $r.Type, $r.Status, $r.Conf, [int]$r.Score, "$($r.Opened)", "$($r.Last)")
        $row = $d.Rows[$ri]; $row.Tag = $r
        $stc = switch ($r.State) { 'now' { $theme.Red } 'left' { $theme.Amber } default { $theme.Muted } }
        $cfc = switch ($r.Conf) { 'HIGH' { $theme.Red } 'MEDIUM' { $theme.Amber } default { $theme.Muted } }
        $row.Cells[2].Style.ForeColor = $stc; $row.Cells[3].Style.ForeColor = $cfc
      }
      $d.ResumeLayout()
    }
    $dg.Add_SelectionChanged({
      $d = $script:dg
      if ($d.SelectedRows.Count -gt 0) {
        $r = $d.SelectedRows[0].Tag
        if ($r) {
          & $script:showText $r.Detail
          $script:bShow.Enabled = [bool]$r.Path
          $script:sl.Text = switch ($r.Conf) {
            'HIGH'   { "HIGH (score $($r.Score)): strong evidence, such as a file fingerprint, a running program, code inside the file, or several independent traces." }
            'MEDIUM' { "MEDIUM (score $($r.Score)): the file or program is on this PC or has several traces, but only its name or behaviour matched." }
            default  { "LOW (score $($r.Score)): only traces such as history or leftovers. A lead, not proof." } }
        } } })
    $showPath = { if ($script:dg.SelectedRows.Count -gt 0) { $r = $script:dg.SelectedRows[0].Tag; if ($r -and $r.Path) { try { Start-Process explorer.exe -ArgumentList "/select,`"$($r.Path)`"" } catch {} } } }
    $dg.Add_CellDoubleClick($showPath)

    # lower pane: tabs
    $sp = New-Object Windows.Forms.SplitContainer
    $sp.Dock = 'Fill'; $sp.Orientation = 'Horizontal'
    $sp.Panel1.Controls.Add($dg)
    $tabs = New-Object Windows.Forms.TabControl; $tabs.Dock = 'Fill'
    $script:tabs = $tabs
    $tp1 = New-Object Windows.Forms.TabPage; $tp1.Text = 'Details'
    $tp2 = New-Object Windows.Forms.TabPage; $tp2.Text = $(if ($leadN -gt 0) { "Leads and notes ($leadN)" } else { 'Leads and notes' })
    $rt = New-Object Windows.Forms.RichTextBox
    $rt.Dock = 'Fill'; $rt.ReadOnly = $true; $rt.WordWrap = $false; $rt.DetectUrls = $false; $rt.BackColor = [Drawing.Color]::White; $rt.Font = $script:fMono; $rt.BorderStyle = 'None'
    $script:rt = $rt
    $rl = New-Object Windows.Forms.RichTextBox
    $rl.Dock = 'Fill'; $rl.ReadOnly = $true; $rl.WordWrap = $false; $rl.DetectUrls = $false; $rl.BackColor = [Drawing.Color]::White; $rl.Font = $script:fMono; $rl.BorderStyle = 'None'
    $rl.Text = ($lead -join "`n")
    $lpos = 0
    foreach ($ll in ($lead -join "`n") -split "`n") {
      if ($ll -match '^[A-Z]') { $rl.Select($lpos, $ll.Length); $rl.SelectionFont = $script:fMonoB }
      $lpos += $ll.Length + 1
    }
    $rl.Select(0,0)
    $tp1.Controls.Add($rt); $tp2.Controls.Add($rl)
    $tabs.TabPages.AddRange(@($tp1,$tp2))
    $sp.Panel2.Controls.Add($tabs)

    $script:showText = { param($t)
      $r2 = $script:rt
      $t = "$t" -replace "`r", ''
      $r2.Text = $t
      $r2.SelectAll(); $r2.SelectionColor = $theme.Text; $r2.SelectionFont = $script:fMono
      $nl = $t.IndexOf("`n"); if ($nl -lt 0) { $nl = $t.Length }
      $r2.Select(0, $nl); $r2.SelectionFont = $script:fMonoB
      $pos = 0
      foreach ($ln2 in ($t -split "`n")) {
        if ($ln2 -match '^(\s+)([A-Za-z][A-Za-z ]+?)\s*:') { $r2.Select($pos + $Matches[1].Length, $Matches[2].Length); $r2.SelectionColor = $theme.Muted }
        $pos += $ln2.Length + 1
      }
      $r2.Select(0,0)
      $script:tabs.SelectedIndex = 0 }

    $script:applyFilter = {
      $q = $script:tb.Text.Trim()
      $rows = @($resRows | Where-Object {
        ($script:stFilter -eq 'all' -or $_.State -eq $script:stFilter) -and
        ($q -eq '' -or $_.Name.IndexOf($q, [StringComparison]::OrdinalIgnoreCase) -ge 0 -or $_.Type.IndexOf($q, [StringComparison]::OrdinalIgnoreCase) -ge 0 -or
         $_.Status.IndexOf($q, [StringComparison]::OrdinalIgnoreCase) -ge 0 -or $_.Detail.IndexOf($q, [StringComparison]::OrdinalIgnoreCase) -ge 0) })
      & $script:fillGrid $rows
      if ($script:dg.Rows.Count -gt 0) { $script:dg.Rows[0].Selected = $true }
      else { & $script:showText $(if ($resRows.Count -eq 0) { "Nothing was detected.`n`nOpen 'Full text' for the complete report." } else { 'No detections match the filter.' }) }
    }
    $tb.Add_TextChanged({ & $script:applyFilter })
    $cmb.Add_SelectedIndexChanged({ $script:stFilter = @('all','now','left','hist')[$script:cmb.SelectedIndex]; & $script:applyFilter })

    # buttons
    $bp = New-Object Windows.Forms.Panel
    $bp.Dock = 'Bottom'; $bp.Height = 42
    $script:bx = 10
    $mkb = { param($t, $w) $b = New-Btn $t $w 26 $false; $b.Location = New-Object Drawing.Point($script:bx, 8); $script:bx += $w + 6; $bp.Controls.Add($b); $b }
    $script:bShow = & $mkb 'Show in folder' 100; $script:bShow.Enabled = $false; $script:bShow.Add_Click($showPath)
    $bFull = & $mkb 'Full text' 72;     $bFull.Add_Click({ & $script:showText ($text -join "`n") })
    $bSave = & $mkb 'Save report...' 100
    $bSave.Add_Click({ try { $dlg = New-Object Windows.Forms.SaveFileDialog; $dlg.Filter = 'Text file (*.txt)|*.txt'; $dlg.FileName = 'JHORFGU_report.txt'
                             if ($dlg.ShowDialog($script:rf) -eq 'OK') { [IO.File]::WriteAllText($dlg.FileName, ($text -join "`r`n")) } } catch {} })
    $bCopy = & $mkb 'Copy' 60;          $bCopy.Add_Click({ try { [Windows.Forms.Clipboard]::SetText(($text -join "`r`n")); $this.Text = 'Copied' } catch {} })
    $bAgain = $null
    if ($PSCommandPath) {
      $bAgain = & $mkb 'Scan again' 84
      $bAgain.Add_Click({ try { Start-Process powershell.exe -ArgumentList ('-NoProfile -ExecutionPolicy Bypass -File "' + $PSCommandPath + '"'); $script:rf.Close() } catch {} })
    }
    $bUn = & $mkb 'Uninstall...' 90
    $bUn.ForeColor = $theme.Red
    $bUn.Add_Click({ if (Show-PasswordPrompt $script:rf) { if (Invoke-Uninstall) { $script:rf.Close() } } })
    $ok = New-Btn 'Close' 80 26 $false
    $ok.Anchor = 'Top,Right'; $ok.Location = New-Object Drawing.Point(($f.ClientSize.Width - 90), 8)
    $ok.Add_Click({ $script:rf.Close() })
    $bp.Controls.Add($ok)
    $f.CancelButton = $ok
    $script:bAgain = $bAgain
    $f.Add_KeyDown({ param($s,$e)
      if ($e.Control -and $e.KeyCode -eq 'F') { $script:tb.Focus() }
      if ($e.KeyCode -eq 'F5' -and $script:bAgain) { $script:bAgain.PerformClick() } })

    $rbxNow = if (Get-Process -Name 'RobloxPlayerBeta' -ErrorAction SilentlyContinue) { 'yes' } else { 'no' }
    $sl = New-Object Windows.Forms.Label
    $sl.Dock = 'Bottom'; $sl.Height = 22; $sl.TextAlign = 'MiddleLeft'; $sl.Padding = New-Object Windows.Forms.Padding(8,0,0,0); $sl.ForeColor = $theme.Muted
    $sl.Text = "Other user accounts checked: $($readableProfiles.Count) of $($otherProfiles.Count)   |   Roblox running during the scan: $rbxNow   |   Double-click a row to open its folder"
    $script:sl = $sl

    # dock order: Fill first, then bottom bars, then top bars (last added is outermost)
    $f.Controls.Add($sp); $f.Controls.Add($bp); $f.Controls.Add($sl); $f.Controls.Add($tbp); $f.Controls.Add($hd)
    $f.Add_Shown({
      try { $sp.SplitterDistance = [math]::Max(120, [int]($sp.Height * 0.55)) } catch {}
      & $script:applyFilter
      $script:rf.Activate()
      try { $script:rf.TopMost = $false } catch {} })
    [void]$f.ShowDialog()
  } catch {
    try { [void][System.Windows.Forms.MessageBox]::Show(($text -join "`r`n"), $title) } catch {}
  }
}
Show-Results $out

if ($Elevated) { Read-Host 'Press Enter to close' }
