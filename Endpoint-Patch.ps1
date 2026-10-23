<#
  Endpoint-Patch.ps1  -  October 2026 vulnerability scan + update for Windows 7 / 8.1 / 10 / 11 / Server
  Covers the software listed in Endpoint-Patch-Checklist.html.
  Repository: https://github.com/Sriganth-C/Endpoint-Patch  (branch: windows)

  What it does
    1. Detects installed software and shows Installed vs Required version. Not installed = "-".
    2. Asks "Update now?" and installs the stable patch versions, including PHP, Tomcat and OVHcloud CLI.
       Packages come from the GitHub release "patches-2026-10" (checksum verified), falling back to the
       official download site. Anything replaced in place is backed up first and restored on failure.
    3. Scans again and shows the final result. Saves a CSV report and a log.

  One-line run (Administrator PowerShell):
    Start-BitsTransfer https://raw.githubusercontent.com/Sriganth-C/Endpoint-Patch/windows/Endpoint-Patch.ps1 $env:TEMP\Endpoint-Patch.ps1; powershell -ExecutionPolicy Bypass -File $env:TEMP\Endpoint-Patch.ps1

  Options:  -ScanOnly   report only, change nothing
            -Yes        update without asking (for Intune / GPO / SCCM)
            -ScanProjects "C:\path\to\code"   also check and update Next.js in project folders

  Compatible with PowerShell 2.0 (Windows 7) through 5.1, and with Constrained Language Mode.
#>
param([switch]$ScanOnly, [switch]$Yes, [string]$ScanProjects = "")

$ErrorActionPreference = 'SilentlyContinue'
# Company-managed PCs often lock PowerShell to Constrained Language Mode; this script only uses
# what that mode allows, and skips the few full-mode extras when it is active.
$FullLang = ("$($ExecutionContext.SessionState.LanguageMode)" -eq 'FullLanguage')
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $here) { $here = $env:TEMP }
$stamp = Get-Date -Format 'yyyyMMdd-HHmm'
$logFile = Join-Path $here ("Endpoint-Patch-{0}-{1}.log" -f $env:COMPUTERNAME, $stamp)
$csvFile = Join-Path $here ("Endpoint-Patch-{0}-{1}.csv" -f $env:COMPUTERNAME, $stamp)
$dl = Join-Path $env:TEMP 'EndpointPatch'
if (-not (Test-Path $dl)) { New-Item -ItemType Directory -Path $dl | Out-Null }
function Log($m) { Add-Content -Path $logFile -Value ("{0}  {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $m) }

# ---------------- Where the patch packages are stored ----------------
$REPO = 'Sriganth-C/Endpoint-Patch'
$TAG = 'patches-2026-10'
$REL = "https://github.com/$REPO/releases/download/$TAG"

# ---------------- Stable patch versions (October 2026) ----------------
$MIN_CHROME = '156.0.8078.47'
$MIN_EDGE = '156.0.4314.42'; $MIN_EDGE_EXT = '152.0.4191.137'
$MIN_FF = '158.0.1'; $MIN_FF_ESR153 = '153.5.1'; $MIN_FF_ESR115 = '115.43.1'
$MIN_PILLOW = '13.0.0'; $BAD_LITELLM = '1.107.0'; $GOOD_LITELLM = '1.106.2'
$MIN_OVH = '0.16.0'
$NodeMin = @{ '22' = '22.23.4'; '24' = '24.22.1'; '26' = '26.12.1' }
$PhpMin = @{ '8.5' = '8.5.12'; '8.4' = '8.4.27'; '8.3' = '8.3.36'; '8.2' = '8.2.35' }
$PhpVs = @{ '8.5' = 'vs17'; '8.4' = 'vs17'; '8.3' = 'vs16'; '8.2' = 'vs16' }
$JavaMin = @{ '27' = '27.0.1'; '25' = '25.0.5'; '21' = '21.0.13'; '17' = '17.0.21'; '11' = '11.0.33' }
$TomcatMin = @{ '11.0' = '11.0.27'; '10.1' = '10.1.61'; '9.0' = '9.0.123' }

# ---------------- Helpers ----------------
function Norm($v) { if ("$v" -match '(\d+(\.\d+){1,3})') { return $Matches[1] } return $null }
function Test-Min($v, $min) { $n = Norm $v; if (-not $n) { return $null }; try { return ([version]$n -ge [version]$min) } catch { return $null } }
function FileVer($p) { if ($p -and (Test-Path $p)) { return "$((Get-Item $p).VersionInfo.ProductVersion)".Trim() } return $null }
function WhereAll($exe) {
  $out = cmd /c "where $exe 2>nul"
  $r = @(); foreach ($l in $out) { if ($l -and ($l -notmatch 'WindowsApps')) { $r += $l.Trim() } }
  return , $r
}
function Has($exe) { $r = WhereAll $exe; return ($r.Count -gt 0) }
function Get-Wmi($class) { if (Get-Command Get-CimInstance) { return Get-CimInstance $class } return Get-WmiObject $class }

# OS
$os = Get-Wmi Win32_OperatingSystem
$osVer = [version]"$($os.Version)"
$osName = "$($os.Caption)".Trim()
$legacy = ($osVer.Major -eq 6)                    # Windows 7 / 8 / 8.1 / Server 2008 R2 / 2012
$is64 = ($env:PROCESSOR_ARCHITECTURE -eq 'AMD64' -or $env:PROCESSOR_ARCHITEW6432 -eq 'AMD64')
$arch = 'x86'; if ($is64) { $arch = 'x64' }; if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { $arch = 'arm64' }
cmd /c "net session >nul 2>&1"; $isAdmin = ($LASTEXITCODE -eq 0)
$hasWinget = [bool](Get-Command winget.exe)          # winget lives in WindowsApps, which WhereAll skips

# Installed programs from the registry (works on every Windows version)
$apps = @()
foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall', 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall') {
  if (Test-Path $k) {
    foreach ($sub in (Get-ChildItem $k)) {
      $p = Get-ItemProperty $sub.PSPath
      if ($p.DisplayName) { $apps += , @{ Name = "$($p.DisplayName)"; Version = "$($p.DisplayVersion)"; Location = "$($p.InstallLocation)" } }
    }
  }
}
function Find-App($pattern) { $r = @(); foreach ($a in $apps) { if ($a.Name -match $pattern) { $r += , $a } }; return , $r }

# ---------------- Download + verify ----------------
function Download($url, $file) {
  $out = Join-Path $dl $file
  if (Test-Path $out) { Remove-Item $out -Force }
  Log "Download $url"
  # TLS 1.2 for Invoke-WebRequest. Setting .NET properties is blocked in Constrained Language Mode
  # (company-locked PowerShell), so only try it in full mode; BITS and certutil below use TLS 1.2 anyway.
  if ($FullLang) { try { [Net.ServicePointManager]::SecurityProtocol = 3072 } catch { } }
  if (Get-Command Invoke-WebRequest) { Invoke-WebRequest -Uri $url -OutFile $out -UseBasicParsing }
  if (-not (Test-Path $out)) { Import-Module BitsTransfer; Start-BitsTransfer -Source $url -Destination $out }
  if (-not (Test-Path $out)) { cmd /c "certutil -urlcache -split -f `"$url`" `"$out`" >nul 2>&1" }
  if ((Test-Path $out) -and (Get-Item $out).Length -gt 0) { return $out }
  Log "Download failed: $url"
  return $null
}
function Get-Sha256($file) {
  $out = cmd /c "certutil -hashfile `"$file`" SHA256 2>nul"
  foreach ($l in $out) { $h = ("$l" -replace '\s', ''); if ($h -match '^[0-9a-fA-F]{64}$') { return $h.ToLower() } }
  return ''
}
$script:sums = $null
function Load-Sums {
  if ($script:sums) { return }
  $script:sums = @{}
  foreach ($n in 'SHA256SUMS.txt', 'php-sha256sum.txt') {
    $f = Download "$REL/$n" $n
    if ($f) { foreach ($l in (Get-Content $f)) { if ($l -match '^([0-9a-fA-F]{64})\s+\*?(\S+)\s*$') { $script:sums[$Matches[2]] = $Matches[1].ToLower() } } }
  }
  Log ("Loaded {0} checksums" -f $script:sums.Count)
}
# Gets a package from the GitHub release (or the official site) and only returns it if the SHA-256 matches
function Get-Patch($name, $official) {
  Load-Sums
  $exp = $null; if ($script:sums.ContainsKey($name)) { $exp = $script:sums[$name] }
  if (-not $exp) { Log "No checksum for $name - refusing to install an unverified file"; return $null }
  foreach ($u in @("$REL/$name", $official)) {
    if (-not $u) { continue }
    $f = Download $u $name
    if (-not $f) { continue }
    $h = Get-Sha256 $f
    if ($h -eq $exp) { Log "Checksum OK $name"; return $f }
    Log "Checksum MISMATCH $name ($h)"; Remove-Item $f -Force
  }
  return $null
}
function Expand-Zip($zip, $dest) {
  if (Test-Path $dest) { Remove-Item $dest -Recurse -Force }
  New-Item -ItemType Directory -Path $dest | Out-Null
  $tar = Join-Path $env:SystemRoot 'System32\tar.exe'
  if (Test-Path $tar) { & $tar -xf $zip -C $dest; if ($LASTEXITCODE -eq 0) { return $true } }
  if ($FullLang -and (Get-Command Expand-Archive)) { Expand-Archive -Path $zip -DestinationPath $dest -Force; if (@(Get-ChildItem $dest).Count) { return $true } }
  return $false
}
function Robo($src, $dst) {
  # robocopy is on every Windows version; retries locked files; exit code < 8 = success
  cmd /c "robocopy `"$src`" `"$dst`" /E /R:5 /W:2 /NFL /NDL /NJH /NJS /NP >> `"$logFile`" 2>&1"
  return ($LASTEXITCODE -lt 8)
}

# ---------------- Stop / start whatever uses a folder ----------------
function Stop-Users($dir, $includeWeb) {
  $stopped = @()
  $svcs = Get-Wmi Win32_Service | Where-Object { $_.State -eq 'Running' -and (("$($_.PathName)" -like "*$dir*") -or ($includeWeb -and (("$($_.PathName)" -match 'httpd\.exe|nginx\.exe|php-cgi|lsws') -or $_.Name -eq 'W3SVC' -or $_.Name -eq 'WAS'))) }
  foreach ($s in $svcs) { Log "Stop service $($s.Name)"; Stop-Service -Name $s.Name -Force; $stopped += , @{ Kind = 'svc'; Name = $s.Name } }
  if ($svcs | Where-Object { $_.Name -eq 'WAS' }) { if (-not ($stopped | Where-Object { $_.Name -eq 'W3SVC' })) { $stopped += , @{ Kind = 'svc'; Name = 'W3SVC' } } }
  Start-Sleep -Seconds 2
  $procs = Get-Wmi Win32_Process | Where-Object { ("$($_.ExecutablePath)" -like "$dir\*") -or ($includeWeb -and ($_.Name -match '^(httpd|nginx|php-cgi)\.exe$')) }
  $restart = @{}
  foreach ($p in $procs) {
    $path = "$($p.ExecutablePath)"; $cmdline = "$($p.CommandLine)"
    if ($path -and $p.Name -match '^(httpd|nginx)\.exe$' -and -not $restart.ContainsKey($path)) {
      $pargs = ''; if ($cmdline -match '^\s*("[^"]+"|\S+)\s*(.*)$') { $pargs = $Matches[2] }
      $restart[$path] = $pargs
    }
    Log "Stop process $($p.Name) ($($p.ProcessId))"; Stop-Process -Id $p.ProcessId -Force
  }
  foreach ($k in $restart.Keys) { $stopped += , @{ Kind = 'proc'; Path = $k; Args = $restart[$k] } }
  Start-Sleep -Seconds 3
  return , $stopped
}
function Start-Users($stopped) {
  foreach ($s in $stopped) {
    if ($s.Kind -eq 'svc') { Log "Start service $($s.Name)"; Start-Service -Name $s.Name }
    else {
      Log "Start process $($s.Path) $($s.Args)"
      if ($s.Args) { Start-Process -FilePath $s.Path -ArgumentList $s.Args -WorkingDirectory (Split-Path $s.Path) -WindowStyle Hidden }
      else { Start-Process -FilePath $s.Path -WorkingDirectory (Split-Path $s.Path) -WindowStyle Hidden }
    }
  }
}

# ---------------- Java vendor lookups ----------------
$script:javaLatestCache = @{}
function Get-JavaLatest($wid, $vendor, $major) {
  $key = "$vendor-$major-$wid"
  if ($script:javaLatestCache.ContainsKey($key)) { return $script:javaLatestCache[$key] }
  $latest = $null
  if ($hasWinget -and $wid) {
    $out = cmd /c "winget show --id $wid -e --accept-source-agreements 2>nul"
    foreach ($l in $out) { if (-not $latest -and $l -match '^\s*Version:\s*(\S+)') { $latest = $Matches[1] } }
  }
  if ($vendor -eq 'temurin') {
    # Eclipse's own site often has a build before the winget catalog does: use whichever is newer
    $f = Download "https://api.adoptium.net/v3/assets/latest/$major/hotspot?image_type=jdk&os=windows&architecture=x64" "adoptium-$major.json"
    if ($f) {
      $txt = (Get-Content $f) -join ' '
      if ($txt -match '"openjdk_version"\s*:\s*"([^"]+)"') { $api = $Matches[1]; if (-not $latest -or (Test-Min $api (Norm $latest)) -eq $true) { $latest = $api } }
    }
  }
  Log "Java latest for $key = $latest"
  $script:javaLatestCache[$key] = $latest
  return $latest
}
function Get-JavaMsiUrl($vendor, $major, $kind) {
  $a = 'x64'; if ($arch -eq 'x86') { $a = 'x86' }; if ($arch -eq 'arm64') { $a = 'aarch64' }
  switch ($vendor) {
    'temurin' { return "https://api.adoptium.net/v3/installer/latest/$major/ga/windows/$a/$($kind.ToLower())/hotspot/normal/eclipse" }
    'microsoft' { return "https://aka.ms/download-jdk/microsoft-jdk-$major-windows-$a.msi" }
    'corretto' { if ($a -eq 'x64') { return "https://corretto.aws/downloads/latest/amazon-corretto-$major-x64-windows-jdk.msi" } }
    'oracle' { if (@('21', '25', '27') -contains "$major" -and $a -eq 'x64') { return "https://download.oracle.com/java/$major/latest/jdk-${major}_windows-x64_bin.msi" } }
  }
  return ''
}

# ---------------- Scan ----------------
$script:rows = @()
function Add-Row($Type, $Soft, $Inst, $Req, $Status, $Action, $Fix = '', $Arg = '') {
  $script:rows += , @{ Type = "$Type"; Soft = "$Soft"; Inst = "$Inst"; Req = "$Req"; Status = "$Status"; Action = "$Action"; Fix = "$Fix"; Arg = "$Arg" }
}
function St($ok) { if ($ok -eq $true) { 'OK' } elseif ($ok -eq $false) { 'UPDATE' } else { 'CHECK' } }

function Invoke-Scan {
  $script:rows = @()

  # Chrome
  $v = $null
  foreach ($p in "$env:ProgramFiles\Google\Chrome\Application\chrome.exe", "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe", "$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe") { if (-not $v) { $v = FileVer $p } }
  if (-not $v) { $c = Find-App '^Google Chrome$'; if ($c.Count) { $v = $c[0].Version } }
  if (-not $v) { Add-Row 'Browser' 'Google Chrome' '-' $MIN_CHROME '-' '-' }
  elseif ($legacy) { Add-Row 'Browser' 'Google Chrome' $v $MIN_CHROME 'NO PATCH' 'Chrome 110+ needs Windows 10/11. Remove Chrome or upgrade the OS.' }
  else { $s = St (Test-Min $v $MIN_CHROME); $a = '-'; if ($s -eq 'UPDATE') { $a = 'Update Chrome' }; Add-Row 'Browser' 'Google Chrome' $v $MIN_CHROME $s $a 'chrome' }

  # Edge
  $v = $null
  foreach ($p in "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe", "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe") { if (-not $v) { $v = FileVer $p } }
  if (-not $v) { Add-Row 'Browser' 'Microsoft Edge' '-' $MIN_EDGE '-' '-' }
  elseif ($legacy) { Add-Row 'Browser' 'Microsoft Edge' $v $MIN_EDGE 'NO PATCH' 'Edge 110+ needs Windows 10/11.' }
  else {
    $req = $MIN_EDGE; if ((Norm $v) -like '152.*') { $req = $MIN_EDGE_EXT }
    $s = St (Test-Min $v $req); $a = '-'; if ($s -eq 'UPDATE') { $a = 'Update Edge' }; Add-Row 'Browser' 'Microsoft Edge' $v $req $s $a 'edge'
  }

  # Firefox (release / ESR)
  $v = $null; $esr = $false
  foreach ($p in "$env:ProgramFiles\Mozilla Firefox\firefox.exe", "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe") { if (-not $v) { $v = FileVer $p } }
  $f = Find-App '^Mozilla Firefox'; if ($f.Count) { if (-not $v) { $v = $f[0].Version }; if ($f[0].Name -match 'ESR') { $esr = $true } }
  if (-not $v) { Add-Row 'Browser' 'Mozilla Firefox' '-' $MIN_FF '-' '-' }
  else {
    $major = ((Norm $v) -split '\.')[0]
    if ($legacy) { $req = $MIN_FF_ESR115; $chan = 'esr115' }
    elseif ($major -eq '115') { $req = $MIN_FF_ESR115; $chan = 'esr' }
    elseif ($major -eq '153' -or $esr) { $req = $MIN_FF_ESR153; $chan = 'esr' }
    else { $req = $MIN_FF; $chan = 'release' }
    $s = St (Test-Min $v $req); $a = '-'; if ($s -eq 'UPDATE') { $a = "Install latest Firefox ($chan)" }
    Add-Row 'Browser' 'Mozilla Firefox' $v $req $s $a 'firefox' $chan
  }

  # Java (every installed JDK / JRE)
  $javas = Find-App '(Java\(TM\)|^Java \d|Java SE Development Kit|Temurin|OpenJDK|Corretto|Zulu)'
  if (-not $javas.Count) {
    $jx = WhereAll 'java.exe'
    if ($jx.Count) { $out = cmd /c "`"$($jx[0])`" -version 2>&1" | Select-Object -First 1; if ("$out" -match '"([^"]+)"') { $javas = @(, @{ Name = "Java ($($jx[0]))"; Version = $Matches[1]; Location = '' }) } }
  }
  if (-not $javas.Count) { Add-Row 'Runtime' 'Java (JDK / JRE)' '-' '21.0.13 / 17.0.21 / 11.0.33 / 8u511' '-' '-' }
  foreach ($j in $javas) {
    $name = $j.Name; $ver = $j.Version
    if ($name -match 'Update (\d+)' -or $ver -match '^1\.8\.0_(\d+)') {
      $u = [int]$Matches[1]; $ok = ($u -ge 511)
      $wid = ''; $vendor = 'other'; if ($name -match 'Java\(TM\)|^Java \d') { $wid = 'Oracle.JavaRuntimeEnvironment'; $vendor = 'oracle8' }
      if ($ok) { Add-Row 'Runtime' $name "8u$u" '8u511' 'OK' '-'; continue }
      $latest = Get-JavaLatest $wid $vendor '8'
      $lu = $null; if ("$latest" -match '^8\.0\.(\d{3})') { $lu = [int]$Matches[1] }
      if ($lu -and $lu -lt 511 -and $lu -le $u) { Add-Row 'Runtime' $name "8u$u" '8u511' 'NO FIX YET' "Already on the vendor's newest build (8u$lu); 8u511 not released yet. Re-run later." }
      elseif ($wid) { Add-Row 'Runtime' $name "8u$u" '8u511' 'UPDATE' 'Update to the newest Java 8' 'java' "$wid|$vendor|8|JRE" }
      else { Add-Row 'Runtime' $name "8u$u" '8u511' 'MANUAL' 'Unknown Java 8 vendor. Install Java 8u511 from the vendor.' 'manual' }
      continue
    }
    $n = Norm $ver; $major = ($n -split '\.')[0]
    if ($JavaMin.ContainsKey($major)) {
      $req = $JavaMin[$major]; $ok = Test-Min $n $req; $s = St $ok
      $wid = ''; $vendor = 'other'; $kind = 'JDK'; if ($name -match 'JRE') { $kind = 'JRE' }
      if ($name -match 'Temurin') { $wid = "EclipseAdoptium.Temurin.$major.$kind"; $vendor = 'temurin' }
      elseif ($name -match 'Microsoft') { $wid = "Microsoft.OpenJDK.$major"; $vendor = 'microsoft' }
      elseif ($name -match 'Corretto') { $wid = "Amazon.Corretto.$major.JDK"; $vendor = 'corretto' }
      elseif ($name -match 'Zulu') { $wid = "Azul.Zulu.$major.JDK"; $vendor = 'zulu' }
      elseif ($name -match 'Java\(TM\)|Java SE') { $wid = "Oracle.JDK.$major"; $vendor = 'oracle' }
      if ($ok -ne $false) { Add-Row 'Runtime' $name $n $req $s '-'; continue }
      $latest = Get-JavaLatest $wid $vendor $major
      if ($latest -and (Test-Min $latest $req) -eq $false -and (Test-Min $n (Norm $latest)) -eq $false) {
        Add-Row 'Runtime' $name $n $req 'UPDATE' ("Update to {0} now (newest from {1}); {2} not released yet" -f (Norm $latest), $vendor, $req) 'java' "$wid|$vendor|$major|$kind"
      } elseif ($latest -and (Test-Min $latest $req) -eq $false) {
        Add-Row 'Runtime' $name $n $req 'NO FIX YET' ("Already on {0}'s newest build ({1}); {2} not released yet. Re-run later." -f $vendor, (Norm $latest), $req)
      } elseif ($wid -or (Get-JavaMsiUrl $vendor $major $kind)) {
        Add-Row 'Runtime' $name $n $req 'UPDATE' "Update to $req" 'java' "$wid|$vendor|$major|$kind"
      } else {
        Add-Row 'Runtime' $name $n $req 'MANUAL' "Unknown Java vendor. Install Java $req from the vendor." 'manual'
      }
    } else { Add-Row 'Runtime' $name $n 'Supported LTS (25/21/17/11)' 'MANUAL' 'Non-LTS or end-of-life Java. Move to a supported LTS (major version change).' 'manual' }
  }

  # Node.js
  $v = $null; $nodePath = ''
  $nx = WhereAll 'node.exe'; if ($nx.Count) { $nodePath = $nx[0]; $v = (cmd /c "`"$nodePath`" -v 2>nul") -replace '^v', '' }
  if (-not $v) { $na = Find-App '^Node\.js'; if ($na.Count) { $v = $na[0].Version } }
  if (-not $v) { Add-Row 'Runtime' 'Node.js' '-' '22.23.4 / 24.22.1 / 26.12.1' '-' '-' }
  else {
    $major = ((Norm $v) -split '\.')[0]
    if ($NodeMin.ContainsKey($major)) { $req = $NodeMin[$major] } else { $req = $NodeMin['24'] }
    $ok = $false; if ($NodeMin.ContainsKey($major)) { $ok = Test-Min $v $req }
    $s = St $ok; $a = '-'
    if ($legacy) { Add-Row 'Runtime' 'Node.js' $v $req 'NO PATCH' 'Node.js 22+ needs Windows 10/11.' }
    elseif ($nodePath -match '\\nvm') { if (-not $ok) { $a = "nvm install $req" }; Add-Row 'Runtime' 'Node.js (nvm)' $v $req $s $a 'nvm' $req }
    else { if (-not $ok) { $a = "Install Node.js $req" }; Add-Row 'Runtime' 'Node.js' $v $req $s $a 'node' $req }
  }

  # PHP (every php.exe found)
  $phps = WhereAll 'php.exe'
  foreach ($pat in 'C:\xampp\php\php.exe', 'C:\wamp\bin\php\*\php.exe', 'C:\wamp64\bin\php\*\php.exe', 'C:\laragon\bin\php\*\php.exe', 'C:\php\php.exe', 'C:\php*\php.exe', 'C:\tools\php*\php.exe', "$env:ProgramFiles\PHP\*\php.exe", "${env:ProgramFiles(x86)}\PHP\*\php.exe") {
    if (Test-Path $pat) { foreach ($i in (Get-Item $pat)) { $phps += $i.FullName } }
  }
  $phps = $phps | Where-Object { $_ -notmatch '\.bak-\d{8}' } | Sort-Object -Unique      # skip this script's own backups
  if (-not $phps) { Add-Row 'Language' 'PHP' '-' '8.5.12 / 8.4.27 / 8.3.36 / 8.2.35' '-' '-' }
  foreach ($p in $phps) {
    $v = cmd /c "`"$p`" -r `"echo PHP_VERSION;`" 2>nul"; if (-not (Norm $v)) { $v = FileVer $p }
    $br = ((Norm $v) -split '\.')[0..1] -join '.'
    if ($PhpMin.ContainsKey($br)) {
      $req = $PhpMin[$br]; $ok = Test-Min $v $req; $s = St $ok; $a = '-'
      if ($ok -eq $false) { $a = "Update PHP to $req (same TS/NTS, php.ini kept, backup made)" }
      Add-Row 'Language' "PHP [$p]" (Norm $v) $req $s $a 'php' "$p|$req"
    } else { Add-Row 'Language' "PHP [$p]" (Norm $v) '8.2.35 or newer branch' 'MANUAL' 'End-of-life PHP: no fix on this branch. Moving to 8.2+ is a major upgrade; plan it with the app owner.' 'manual' }
  }

  # Apache Tomcat
  $tom = @()
  foreach ($t in (Find-App 'Apache Tomcat')) { if ($t.Location -and (Test-Path (Join-Path $t.Location 'RELEASE-NOTES'))) { $tom += , @{ Dir = $t.Location.TrimEnd('\'); Version = $t.Version } } }
  foreach ($pat in "$env:ProgramFiles\Apache Software Foundation\Tomcat*\RELEASE-NOTES", "${env:ProgramFiles(x86)}\Apache Software Foundation\Tomcat*\RELEASE-NOTES", 'C:\tomcat*\RELEASE-NOTES', 'C:\apache-tomcat*\RELEASE-NOTES', 'C:\xampp\tomcat\RELEASE-NOTES') {
    if (Test-Path $pat) { foreach ($rn in (Get-Item $pat)) { $tom += , @{ Dir = $rn.DirectoryName; Version = '' } } }
  }
  if (-not $tom.Count) { Add-Row 'Server' 'Apache Tomcat' '-' '11.0.27 / 10.1.61 / 9.0.123' '-' '-' }
  $seen = @()
  foreach ($t in $tom) {
    if ($seen -contains $t.Dir -or $t.Dir -match '\.bak-\d{8}') { continue }; $seen += $t.Dir
    $m = Select-String -Path (Join-Path $t.Dir 'RELEASE-NOTES') -Pattern 'Apache Tomcat Version\s+([\d\.]+)' | Select-Object -First 1
    $n = $null; if ($m) { $n = $m.Matches[0].Groups[1].Value } else { $n = Norm $t.Version }
    $br = ($n -split '\.')[0..1] -join '.'
    if ($TomcatMin.ContainsKey($br)) {
      $req = $TomcatMin[$br]; $ok = Test-Min $n $req; $s = St $ok; $a = '-'
      if ($ok -eq $false) { $a = "Update Tomcat to $req (conf\ and webapps\ kept, backup made)" }
      Add-Row 'Server' "Apache Tomcat [$($t.Dir)]" $n $req $s $a 'tomcat' "$($t.Dir)|$req"
    } else { Add-Row 'Server' "Apache Tomcat [$($t.Dir)]" $n '9.0.123+' 'MANUAL' 'End-of-life Tomcat: no fix on this branch. Moving to 9.0+ is a major upgrade.' 'manual' }
  }

  # Python: LiteLLM and Pillow
  $pys = WhereAll 'python.exe'
  foreach ($pa in (Find-App '^Python 3')) { if ($pa.Location) { $c = Join-Path $pa.Location 'python.exe'; if (Test-Path $c) { $pys += $c } } }
  $pys = $pys | Sort-Object -Unique
  if (-not $pys) {
    Add-Row 'Supply chain' 'Python: litellm' '-' "not $BAD_LITELLM" '-' '-'
    Add-Row 'Library' 'Python: Pillow' '-' $MIN_PILLOW '-' '-'
  }
  foreach ($py in $pys) {
    $list = cmd /c "`"$py`" -m pip list --format=freeze 2>nul"
    $lite = $null; $pil = $null
    foreach ($l in $list) { if ($l -match '^litellm==(.+)$') { $lite = $Matches[1].Trim() }; if ($l -match '^(?i)pillow==(.+)$') { $pil = $Matches[1].Trim() } }
    $bad = ($lite -eq $BAD_LITELLM)
    if ($bad) { Add-Row 'Supply chain' "Python: litellm [$py]" $lite "not $BAD_LITELLM ($GOOD_LITELLM)" 'COMPROMISED' 'Security incident: disconnect from network, report to security, rebuild the machine, rotate all secrets. Not auto-fixed: running Python here re-runs the malware.' }
    elseif ($lite) { Add-Row 'Supply chain' "Python: litellm [$py]" $lite "not $BAD_LITELLM" 'OK' '-' }
    else { Add-Row 'Supply chain' "Python: litellm [$py]" '-' "not $BAD_LITELLM" '-' '-' }
    if (-not $pil) { Add-Row 'Library' "Python: Pillow [$py]" '-' $MIN_PILLOW '-' '-' }
    elseif ($bad) { Add-Row 'Library' "Python: Pillow [$py]" $pil $MIN_PILLOW 'COMPROMISED' 'Skipped: this Python is compromised by litellm 1.107.0' }
    else { $ok = Test-Min $pil $MIN_PILLOW; $s = St $ok; $a = '-'; if ($ok -eq $false) { $a = "pip install pillow>=$MIN_PILLOW" }; Add-Row 'Library' "Python: Pillow [$py]" $pil $MIN_PILLOW $s $a 'pillow' $py }
  }

  # GitLab (Linux only)
  Add-Row 'Server' 'GitLab (self-managed)' '-' '19.5.1 / 19.4.3 / ... / 18.11.13' '-' 'Linux only'

  # OVHcloud CLI
  $ov = WhereAll 'ovhcloud.exe'
  if ($ov.Count) {
    $ovv = Norm (cmd /c "`"$($ov[0])`" version 2>nul")
    $ok = $false; if ($ovv) { $ok = Test-Min $ovv $MIN_OVH }
    $s = St $ok; $a = '-'; if (-not $ok) { $a = "Replace with verified $MIN_OVH" }
    $shown = $ovv; if (-not $shown) { $shown = 'unknown' }
    Add-Row 'Supply chain' "OVHcloud CLI [$($ov[0])]" $shown $MIN_OVH $s $a 'ovh' $ov[0]
  } else { Add-Row 'Supply chain' 'OVHcloud CLI' '-' $MIN_OVH '-' '-' }

  # eMudhra certificates
  $bad = Get-ChildItem Cert:\LocalMachine\CA, Cert:\LocalMachine\Root, Cert:\CurrentUser\CA, Cert:\CurrentUser\Root | Where-Object { $_.Subject -match 'EM (DV|OV|EV) TLS CA - G3|EM OV CS CA - G3' }
  if ($bad) { Add-Row 'Certificate' 'eMudhra compromised intermediates' ("{0} found" -f @($bad).Count) 'none' 'UPDATE' 'Delete the compromised certificates' 'emudhra' }
  else { Add-Row 'Certificate' 'eMudhra compromised intermediates' 'none' 'none' 'OK' '-' }

  # Docker images
  if (Has 'docker.exe') {
    $imgs = cmd /c "docker images --format `"{{.Repository}}:{{.Tag}}`" 2>nul"
    if ($LASTEXITCODE -ne 0) { Add-Row 'Container' 'Docker images' 'Docker not running' 'pulled after 21 Oct 2026' 'CHECK' 'Start Docker and run again' }
    else {
      $any = $false
      foreach ($i in $imgs) {
        if ($i -match 'litellm:(v?1\.107\.0|latest|main-latest|main-stable)$') { Add-Row 'Supply chain' "Docker: $i" $i "litellm v$GOOD_LITELLM" 'COMPROMISED' "Remove image, pull v$GOOD_LITELLM, rotate secrets of containers that ran it" 'litellmimg' $i; $any = $true }
        elseif ($i -match '(^|/)(php|node|tomcat|python|openjdk|eclipse-temurin):' -and $i -notmatch '<none>') {
          $created = "$(cmd /c "docker image inspect -f `"{{.Created}}`" $i 2>nul")".Trim()
          $any = $true
          if ($created -ge '2026-10-21') { Add-Row 'Container' "Docker: $i" $created.Substring(0, 10) 'pulled after 21 Oct 2026' 'OK' '-' }
          else { $cd = '-'; if ($created.Length -ge 10) { $cd = $created.Substring(0, 10) }; Add-Row 'Container' "Docker: $i" $cd 'pulled after 21 Oct 2026' 'UPDATE' 'docker pull (then rebuild app images built FROM it)' 'dockerpull' $i }
        }
      }
      if (-not $any) { Add-Row 'Container' 'Docker images' 'no affected images' '-' 'OK' '-' }
    }
  } else { Add-Row 'Container' 'Docker images' '-' 'pulled after 21 Oct 2026' '-' '-' }

  # Next.js (only when -ScanProjects is given)
  if ($ScanProjects -and (Test-Path $ScanProjects)) {
    $found = $false
    foreach ($pj in (Get-ChildItem $ScanProjects -Recurse -Filter package.json | Where-Object { $_.FullName -match '\\node_modules\\next\\package\.json$' })) {
      $m = Select-String -Path $pj.FullName -Pattern '"version"\s*:\s*"([^"]+)"' | Select-Object -First 1
      if ($m) {
        $found = $true; $v = $m.Matches[0].Groups[1].Value; $req = '16.4.1'; if ($v -like '15.*') { $req = '15.5.28' }
        $proj = Split-Path (Split-Path (Split-Path $pj.FullName -Parent) -Parent) -Parent
        $ok = Test-Min $v $req; $s = St $ok; $a = '-'; if ($ok -eq $false) { $a = "npm install next@$req" }
        Add-Row 'Library' "Next.js [$proj]" $v $req $s $a 'nextjs' "$proj|$req"
      }
    }
    if (-not $found) { Add-Row 'Library' 'Next.js' '-' '16.4.1 / 15.5.28' '-' '-' }
  } else { Add-Row 'Library' 'Next.js' '-' '16.4.1 / 15.5.28' '-' 'Use -ScanProjects to check' }
}

function Show-Table($title) {
  Write-Host ''
  Write-Host $title -ForegroundColor Cyan
  Write-Host ("{0,-3} {1,-17} {2,-46} {3,-18} {4,-34} {5,-11} {6}" -f '#', 'TYPE', 'SOFTWARE', 'INSTALLED', 'REQUIRED', 'STATUS', 'ACTION')
  Write-Host ("{0,-3} {1,-17} {2,-46} {3,-18} {4,-34} {5,-11} {6}" -f '--', '----', '--------', '---------', '--------', '------', '------')
  $i = 0
  foreach ($r in $script:rows) {
    $i++
    $c = 'Gray'
    switch ($r.Status) { 'OK' { $c = 'Green' } 'UPDATE' { $c = 'Red' } 'COMPROMISED' { $c = 'Magenta' } 'MANUAL' { $c = 'Yellow' } 'NO PATCH' { $c = 'DarkYellow' } 'NO FIX YET' { $c = 'DarkYellow' } 'CHECK' { $c = 'Yellow' } }
    $soft = $r.Soft; if ($soft.Length -gt 46) { $soft = $soft.Substring(0, 43) + '...' }
    Write-Host ("{0,-3} {1,-17} {2,-46} {3,-18} {4,-34} {5,-11} {6}" -f $i, $r.Type, $soft, $r.Inst, $r.Req, $r.Status, $r.Action) -ForegroundColor $c
  }
}

function Save-Csv($phase) {
  if (-not (Test-Path $csvFile)) { Set-Content -Path $csvFile -Value '"Computer","Phase","Type","Software","Installed","Required","Status","Action"' -Encoding UTF8 }
  foreach ($r in $script:rows) {
    $vals = @($env:COMPUTERNAME, $phase, $r.Type, $r.Soft, $r.Inst, $r.Req, $r.Status, $r.Action) | ForEach-Object { '"' + ("$_" -replace '"', '""') + '"' }
    Add-Content -Path $csvFile -Value ($vals -join ',') -Encoding UTF8
  }
}

# ---------------- Installers ----------------
function Run($exe, $argList) {
  Log "Run $exe $argList"
  $p = Start-Process -FilePath $exe -ArgumentList $argList -Wait -PassThru
  $code = 0; if ($p) { $code = $p.ExitCode }
  Log "Exit $code"
  return $code
}
function Winget($id) {
  if (-not $hasWinget -or -not $id) { return $false }
  Log "winget upgrade $id"
  cmd /c "winget upgrade --id $id -e --silent --accept-package-agreements --accept-source-agreements >> `"$logFile`" 2>&1"
  return ($LASTEXITCODE -eq 0)
}
function Msi($file) { $c = Run 'msiexec.exe' "/i `"$file`" /qn /norestart"; return ($c -eq 0 -or $c -eq 3010) }

function Update-Php($exe, $target) {
  $dir = Split-Path $exe
  $info = cmd /c "`"$exe`" -i 2>nul"
  $nts = $false; $parch = $arch
  foreach ($l in $info) {
    if ($l -match '^Thread Safety\s*=>\s*disabled') { $nts = $true }
    if ($l -match '^Architecture\s*=>\s*(x64|x86)') { $parch = $Matches[1] }
  }
  $br = ($target -split '\.')[0..1] -join '.'
  $name = 'php-' + $target + '-'; if ($nts) { $name += 'nts-' }; $name += "Win32-$($PhpVs[$br])-$parch.zip"
  Log "PHP $exe -> $name"
  $zip = Get-Patch $name "https://windows.php.net/downloads/releases/$name"
  if (-not $zip) { return "FAILED: could not download a verified $name" }
  $new = Join-Path $dl "php-$target-new"
  if (-not (Expand-Zip $zip $new)) { return 'FAILED: could not unzip (needs Windows 10+ or PowerShell 5). Nothing changed.' }
  if (-not (Test-Path (Join-Path $new 'php.exe'))) { return 'FAILED: package is missing php.exe. Nothing changed.' }
  $bak = "$dir.bak-$stamp"
  if (-not (Robo $dir $bak) -or -not (Test-Path (Join-Path $bak 'php.exe'))) { return 'FAILED: could not back up the PHP folder. Nothing changed.' }
  $stopped = Stop-Users $dir $true
  $copied = Robo $new $dir
  $nv = Norm (cmd /c "`"$exe`" -r `"echo PHP_VERSION;`" 2>nul")
  if (-not $copied -or $nv -ne $target) {
    Log "PHP copy failed or wrong version ($nv); restoring"
    Robo $bak $dir | Out-Null
    Start-Users $stopped
    return "FAILED: PHP files still locked; old version restored. Backup: $bak"
  }
  Start-Users $stopped
  return "PHP $target installed (php.ini kept). Web server restarted. Backup: $bak"
}

function Update-Tomcat($dir, $target) {
  $major = ($target -split '\.')[0]
  $name = "apache-tomcat-$target-windows-x64.zip"
  if ($arch -ne 'x64') { return 'FAILED: only 64-bit Tomcat packages are provided. Update manually.' }
  $zip = Get-Patch $name "https://archive.apache.org/dist/tomcat/tomcat-$major/v$target/bin/$name"
  if (-not $zip) { return "FAILED: could not download a verified $name" }
  $tmp = Join-Path $dl "tomcat-$target-new"
  if (-not (Expand-Zip $zip $tmp)) { return 'FAILED: could not unzip. Nothing changed.' }
  $new = Join-Path $tmp "apache-tomcat-$target"
  if (-not (Test-Path (Join-Path $new 'lib\catalina.jar'))) { return 'FAILED: package layout not recognised. Nothing changed.' }
  $bak = "$dir.bak-$stamp"
  if (-not (Robo (Join-Path $dir 'bin') (Join-Path $bak 'bin')) -or -not (Robo (Join-Path $dir 'lib') (Join-Path $bak 'lib'))) { return 'FAILED: could not back up Tomcat. Nothing changed.' }
  foreach ($f in 'RELEASE-NOTES', 'RUNNING.txt', 'LICENSE', 'NOTICE') { Copy-Item (Join-Path $dir $f) $bak -Force }
  # Tomcat run from startup.bat (not a service) is restarted with startup.bat
  $wasRunning = @(Get-Wmi Win32_Process | Where-Object { $_.Name -match '^javaw?\.exe$' -and "$($_.CommandLine)" -like "*$dir*" }).Count -gt 0
  $stopped = Stop-Users $dir $false
  foreach ($p in (Get-Wmi Win32_Process | Where-Object { $_.Name -match '^javaw?\.exe$' -and "$($_.CommandLine)" -like "*$dir*" })) { Stop-Process -Id $p.ProcessId -Force }
  Start-Sleep -Seconds 2
  # Old ecj-*.jar must go when the new version ships a different one
  foreach ($e in (Get-ChildItem (Join-Path $dir 'lib') -Filter 'ecj-*.jar')) { if (-not (Test-Path (Join-Path $new "lib\$($e.Name)"))) { Remove-Item $e.FullName -Force } }
  $ok = (Robo (Join-Path $new 'bin') (Join-Path $dir 'bin')) -and (Robo (Join-Path $new 'lib') (Join-Path $dir 'lib'))
  foreach ($f in 'RELEASE-NOTES', 'RUNNING.txt', 'LICENSE', 'NOTICE') { Copy-Item (Join-Path $new $f) $dir -Force }
  $m = Select-String -Path (Join-Path $dir 'RELEASE-NOTES') -Pattern 'Apache Tomcat Version\s+([\d\.]+)' | Select-Object -First 1
  $nv = ''; if ($m) { $nv = $m.Matches[0].Groups[1].Value }
  if (-not $ok -or $nv -ne $target) {
    Robo (Join-Path $bak 'bin') (Join-Path $dir 'bin') | Out-Null; Robo (Join-Path $bak 'lib') (Join-Path $dir 'lib') | Out-Null
    foreach ($f in 'RELEASE-NOTES', 'RUNNING.txt', 'LICENSE', 'NOTICE') { Copy-Item (Join-Path $bak $f) $dir -Force }
    Start-Users $stopped
    return "FAILED: files locked; old Tomcat restored. Backup: $bak"
  }
  Start-Users $stopped
  if ($wasRunning -and -not ($stopped | Where-Object { $_.Kind -eq 'svc' })) { Start-Process -FilePath (Join-Path $dir 'bin\startup.bat') -WorkingDirectory (Join-Path $dir 'bin') -WindowStyle Hidden }
  return "Tomcat $target installed (conf and webapps kept). Backup: $bak"
}

function Update-Ovh($exe) {
  $name = 'ovhcloud-cli_Windows_x86_64.zip'; if ($arch -eq 'x86') { $name = 'ovhcloud-cli_Windows_i386.zip' }; if ($arch -eq 'arm64') { $name = 'ovhcloud-cli_Windows_arm64.zip' }
  $zip = Get-Patch $name "https://github.com/ovh/ovhcloud-cli/releases/download/v$MIN_OVH/$name"
  if (-not $zip) { return "FAILED: could not download a verified $name" }
  $tmp = Join-Path $dl 'ovh-new'
  if (-not (Expand-Zip $zip $tmp)) { return 'FAILED: could not unzip. Nothing changed.' }
  $newExe = Get-ChildItem $tmp -Recurse -Filter 'ovhcloud.exe' | Select-Object -First 1
  if (-not $newExe) { return 'FAILED: ovhcloud.exe not found in the package.' }
  Copy-Item $exe "$exe.bak-$stamp" -Force
  Get-Wmi Win32_Process | Where-Object { "$($_.ExecutablePath)" -eq $exe } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
  Copy-Item $newExe.FullName $exe -Force
  if ((Get-Sha256 $exe) -eq (Get-Sha256 $newExe.FullName)) { return "OVHcloud CLI $MIN_OVH installed. Backup: $exe.bak-$stamp" }
  Copy-Item "$exe.bak-$stamp" $exe -Force
  return 'FAILED: file in use; old version restored.'
}

function Remove-Emudhra {
  $n = 0
  foreach ($store in 'CA', 'Root') {
    foreach ($scope in 'LocalMachine', 'CurrentUser') {
      foreach ($c in (Get-ChildItem "Cert:\$scope\$store" | Where-Object { $_.Subject -match 'EM (DV|OV|EV) TLS CA - G3|EM OV CS CA - G3' })) {
        $u = ''; if ($scope -eq 'CurrentUser') { $u = '-user' }
        Log "Delete certificate $scope\$store $($c.Thumbprint) $($c.Subject)"
        cmd /c "certutil $u -delstore $store $($c.Thumbprint) >> `"$logFile`" 2>&1"
        if ($LASTEXITCODE -eq 0) { $n++ }
      }
    }
  }
  return "Deleted $n compromised eMudhra certificate(s)."
}

function Fix-Row($r) {
  switch ($r.Fix) {
    'chrome' {
      if (Winget 'Google.Chrome') { return 'Updated with winget. Relaunch Chrome.' }
      foreach ($gu in "${env:ProgramFiles(x86)}\Google\Update\GoogleUpdate.exe", "$env:ProgramFiles\Google\Update\GoogleUpdate.exe", "$env:LOCALAPPDATA\Google\Update\GoogleUpdate.exe") {
        if (Test-Path $gu) { Run $gu '/ua /installsource scheduler' | Out-Null; return 'Google Update triggered. Relaunch Chrome.' }
      }
      $name = 'googlechromestandaloneenterprise.msi'; if ($is64) { $name = 'googlechromestandaloneenterprise64.msi' }
      $f = Download "https://dl.google.com/dl/chrome/install/$name" $name
      if ($f -and (Msi $f)) { return 'Installed latest Chrome MSI. Relaunch Chrome.' }
      return 'FAILED: update Chrome from chrome://settings/help'
    }
    'edge' {
      foreach ($eu in "${env:ProgramFiles(x86)}\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe", "$env:ProgramFiles\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe") {
        if (Test-Path $eu) { Run $eu '/ua /installsource scheduler' | Out-Null; return 'Edge Update triggered. Relaunch Edge.' }
      }
      if (Winget 'Microsoft.Edge') { return 'Updated with winget. Relaunch Edge.' }
      return 'FAILED: update Edge from edge://settings/help'
    }
    'firefox' {
      $id = 'Mozilla.Firefox'; if ($r.Arg -ne 'release') { $id = 'Mozilla.Firefox.ESR' }
      if ($r.Arg -ne 'esr115' -and (Winget $id)) { return 'Updated with winget. Relaunch Firefox.' }
      $prod = 'firefox-latest-ssl'; if ($r.Arg -eq 'esr') { $prod = 'firefox-esr-latest-ssl' }; if ($r.Arg -eq 'esr115') { $prod = 'firefox-esr115-latest-ssl' }
      $osTag = 'win'; if ($is64) { $osTag = 'win64' }
      $f = Download "https://download.mozilla.org/?product=$prod&os=$osTag&lang=en-US" 'firefox-setup.exe'
      if ($f) { Run $f '/S' | Out-Null; return 'Installed latest Firefox. Relaunch Firefox.' }
      return 'FAILED: update Firefox from Help > About Firefox'
    }
    'node' {
      $ver = $r.Arg
      $f = Download "https://nodejs.org/dist/v$ver/node-v$ver-$arch.msi" "node-v$ver-$arch.msi"
      if ($f -and (Msi $f)) { return "Installed Node.js $ver. Restart Node services and terminals." }
      if (Winget 'OpenJS.NodeJS.LTS') { return 'Updated Node.js LTS with winget.' }
      return "FAILED: install Node.js $ver from nodejs.org"
    }
    'nvm' {
      cmd /c "nvm install $($r.Arg) >> `"$logFile`" 2>&1 && nvm use $($r.Arg) >> `"$logFile`" 2>&1"
      if ($LASTEXITCODE -eq 0) { return "Installed Node.js $($r.Arg) with nvm and made it active." } return 'FAILED: nvm could not install it. See log.'
    }
    'java' {
      $parts = $r.Arg -split '\|'; $wid = $parts[0]; $vendor = $parts[1]; $major = $parts[2]; $kind = $parts[3]
      if ($vendor -ne 'temurin' -and (Winget $wid)) { return 'Updated with winget.' }
      $url = Get-JavaMsiUrl $vendor $major $kind
      if ($url) {
        $f = Download $url "java-$vendor-$major-$kind.msi"
        if ($f -and (Msi $f)) { return "Installed the latest $vendor Java $major $kind." }
      }
      if ($vendor -eq 'temurin' -and (Winget $wid)) { return 'Updated with winget.' }
      return 'FAILED: install the fixed Java build from the vendor website. See log.'
    }
    'pillow' {
      Log "pip upgrade pillow on $($r.Arg)"
      cmd /c "`"$($r.Arg)`" -m pip install --upgrade `"pillow>=$MIN_PILLOW`" >> `"$logFile`" 2>&1"
      if ($LASTEXITCODE -eq 0) { return "Pillow upgraded to $MIN_PILLOW+." } return 'FAILED: Pillow 13 may need a newer Python. See log.'
    }
    'php' { $p = $r.Arg -split '\|'; return (Update-Php $p[0] $p[1]) }
    'tomcat' { $p = $r.Arg -split '\|'; return (Update-Tomcat $p[0] $p[1]) }
    'ovh' { return (Update-Ovh $r.Arg) }
    'emudhra' { return (Remove-Emudhra) }
    'dockerpull' {
      cmd /c "docker pull $($r.Arg) >> `"$logFile`" 2>&1"
      if ($LASTEXITCODE -eq 0) { return 'Pulled the patched image. Rebuild app images that use it.' } return 'FAILED: docker pull failed. See log.'
    }
    'litellmimg' {
      $repo = ($r.Arg -split ':')[0]
      cmd /c "docker rmi -f $($r.Arg) >> `"$logFile`" 2>&1"
      cmd /c "docker pull ${repo}:v$GOOD_LITELLM >> `"$logFile`" 2>&1"
      return "Removed $($r.Arg) and pulled ${repo}:v$GOOD_LITELLM. Rotate secrets used by containers that ran it."
    }
    'nextjs' {
      $p = $r.Arg -split '\|'
      cmd /c "cd /d `"$($p[0])`" && npm install next@$($p[1]) >> `"$logFile`" 2>&1"
      if ($LASTEXITCODE -eq 0) { return "Next.js $($p[1]) installed in $($p[0]). Rebuild and redeploy the app." } return 'FAILED: npm install failed. See log.'
    }
    default { return $r.Action }
  }
}

# ---------------- Main ----------------
Write-Host "Endpoint-Patch  |  $env:COMPUTERNAME  |  $osName ($arch)  |  PowerShell $($PSVersionTable.PSVersion)  |  Admin: $isAdmin  |  winget: $hasWinget"
Log "Start on $env:COMPUTERNAME $osName admin=$isAdmin"
Invoke-Scan
Show-Table 'CURRENT STATUS'
Save-Csv 'before'

$todo = @($script:rows | Where-Object { ($_.Status -eq 'UPDATE' -or $_.Status -eq 'COMPROMISED') -and $_.Fix -and $_.Fix -ne 'manual' })
$manual = @($script:rows | Where-Object { ($_.Status -eq 'MANUAL' -or $_.Status -eq 'NO PATCH' -or $_.Status -eq 'COMPROMISED') -and (-not $_.Fix -or $_.Fix -eq 'manual') })
$waiting = @($script:rows | Where-Object { $_.Status -eq 'NO FIX YET' })
Write-Host ''
Write-Host ("Can update automatically: {0}   Need manual action: {1}   Fix not released by vendor yet: {2}" -f $todo.Count, $manual.Count, $waiting.Count)
if ($waiting.Count) { Write-Host 'NO FIX YET = you already have the newest build this vendor offers. Run the script again in a few days.' -ForegroundColor DarkYellow }

if ($ScanOnly -or $todo.Count -eq 0) { Write-Host "Report: $csvFile"; Log 'End (no updates run)'; return }
if (-not $isAdmin) { Write-Host 'Run PowerShell as Administrator to install updates.' -ForegroundColor Yellow; Write-Host "Report: $csvFile"; return }
if (-not $Yes) {
  $ans = Read-Host ("Update these {0} items now? Web servers and browsers may restart. (Y/N)" -f $todo.Count)
  if ($ans -notmatch '^(y|yes)$') { Write-Host 'No changes made.'; Write-Host "Report: $csvFile"; return }
}

Write-Host ''
Write-Host 'UPDATING' -ForegroundColor Cyan
foreach ($r in $todo) {
  Write-Host ("- {0} ... " -f $r.Soft) -NoNewline
  $res = Fix-Row $r
  Log ("{0}: {1}" -f $r.Soft, $res)
  $c = 'Green'; if ($res -match '^FAILED') { $c = 'Yellow' }
  Write-Host $res -ForegroundColor $c
}

Invoke-Scan
Show-Table 'STATUS AFTER UPDATE'
Save-Csv 'after'
Write-Host ''
Write-Host 'Browsers show the new version after they are closed and reopened.'
Write-Host "Report: $csvFile"
Write-Host "Log:    $logFile"
Log 'End'
