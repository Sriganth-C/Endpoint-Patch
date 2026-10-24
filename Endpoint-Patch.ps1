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

  One-line run (Administrator PowerShell, Windows 10 / 11 / Server 2019+):
    curl.exe -fsSL -o $env:TEMP\Endpoint-Patch.ps1 https://raw.githubusercontent.com/Sriganth-C/Endpoint-Patch/windows/Endpoint-Patch.ps1; powershell -ExecutionPolicy Bypass -File $env:TEMP\Endpoint-Patch.ps1
  Windows 7 / 8.1 (no curl.exe):
    certutil -urlcache -split -f https://raw.githubusercontent.com/Sriganth-C/Endpoint-Patch/windows/Endpoint-Patch.ps1 %TEMP%\Endpoint-Patch.ps1 & powershell -ExecutionPolicy Bypass -File %TEMP%\Endpoint-Patch.ps1   (Command Prompt as Administrator)

  Options:  -ScanOnly   report only, change nothing
            -Yes        update without asking (for Intune / GPO / SCCM)
            -ScanProjects "C:\path\to\code"   also check and update Next.js in project folders

  Compatible with PowerShell 2.0 (Windows 7) through 5.1, and with Constrained Language Mode.
#>
param([switch]$ScanOnly, [switch]$Yes, [string]$ScanProjects = "")

# 32-bit PowerShell on 64-bit Windows sees "Program Files (x86)" as Program Files and a redirected registry,
# so 64-bit programs would look "not installed": restart in 64-bit PowerShell
$ps64 = "$env:SystemRoot\Sysnative\WindowsPowerShell\v1.0\powershell.exe"
if ($env:PROCESSOR_ARCHITEW6432 -eq 'AMD64' -and $MyInvocation.MyCommand.Path -and (Test-Path $ps64)) {
  $a = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $MyInvocation.MyCommand.Path)
  if ($ScanOnly) { $a += '-ScanOnly' }; if ($Yes) { $a += '-Yes' }; if ($ScanProjects) { $a += '-ScanProjects'; $a += $ScanProjects }
  & $ps64 @a
  exit $LASTEXITCODE
}

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
# SHA-256 of ovhcloud.exe inside the official 0.16.0 Windows packages (x86_64, i386, arm64)
$OVH_EXE_SHA = @('0aaae123c71d0d965941b5846a9ccf0b4148f60ceb2f95ad765870ef9de22189', 'f3cc22492b9cb71d2b63c385f360245cd620fbaf57ae200cc6d6825243fe6151', 'e9f77e802f5a1f0f0e1ee4f68f2050a061270142fe224b1250cc5e61f6957adc')
$NodeMin = @{ '22' = '22.23.4'; '24' = '24.22.1'; '26' = '26.12.1' }
$PhpMin = @{ '8.5' = '8.5.12'; '8.4' = '8.4.27'; '8.3' = '8.3.36'; '8.2' = '8.2.35' }
$PhpVs = @{ '8.5' = 'vs17'; '8.4' = 'vs17'; '8.3' = 'vs16'; '8.2' = 'vs16' }
$JavaMin = @{ '27' = '27.0.1'; '25' = '25.0.5'; '21' = '21.0.13'; '17' = '17.0.21'; '11' = '11.0.33' }
$TomcatMin = @{ '11.0' = '11.0.27'; '10.1' = '10.1.61'; '9.0' = '9.0.123' }
# Python: 21 Oct releases (eMudhra fix in bundled pip/certifi) for 3.13-3.15; 1 Oct CVE releases for 3.11/3.12
$PyMin = @{ '3.15' = '3.15.1'; '3.14' = '3.14.9'; '3.13' = '3.13.17'; '3.12' = '3.12.15'; '3.11' = '3.11.17' }
$PyHasInstaller = @('3.13', '3.14', '3.15')        # python.org ships no Windows installers for security-only 3.11 / 3.12
$MIN_CERTIFI = '2026.10.19'                         # first certifi without the compromised eMudhra / emSign CA

# ---------------- Helpers ----------------
function Norm($v) { if ("$v" -match '(\d+(\.\d+){1,3})') { return $Matches[1] } return $null }
function Test-Min($v, $min) { $n = Norm $v; if (-not $n) { return $null }; try { return ([version]$n -ge [version]$min) } catch { return $null } }
function FileVer($p) { if ($p -and (Test-Path $p)) { return "$((Get-Item $p).VersionInfo.ProductVersion)".Trim() } return $null }
function WhereAll($exe) {
  $out = cmd /c "where $exe 2>nul"
  $r = @(); foreach ($l in $out) { if ($l -and ($l -notmatch 'WindowsApps')) { $r += $l.Trim() } }
  # plus the PATH of every logged-on user (this window cannot see it when it runs as another account)
  foreach ($d in $script:userPath) { $f = Join-Path $d $exe; if ($d -notmatch 'WindowsApps' -and $r -notcontains $f -and (Test-Path $f)) { $r += $f } }
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

# Every user profile. "Run as administrator" often runs as a different (admin) account than the person
# logged on, so this window's %LOCALAPPDATA%, HKCU and PATH are not where that person's per-user installs
# are (Chrome, Firefox, Python, Node.js in AppData). Each profile and each logged-on user's registry is checked.
$profiles = @()
foreach ($k in (Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList')) {
  $sid = $k.PSChildName
  if ($sid -notmatch '^S-1-(5-21|12-1)-') { continue }        # local, domain and Entra ID (Azure AD) accounts
  $ph = "$((Get-ItemProperty $k.PSPath).ProfileImagePath)".TrimEnd('\')
  if (-not $ph -or -not (Test-Path $ph)) { continue }
  $hive = $null; if (Test-Path "Registry::HKEY_USERS\$sid") { $hive = "Registry::HKEY_USERS\$sid" }
  $profiles += , @{ Sid = $sid; Home = $ph; Name = (Split-Path $ph -Leaf); Local = (Join-Path $ph 'AppData\Local'); Roaming = (Join-Path $ph 'AppData\Roaming'); Hive = $hive }
}
# Registry roots with per-user settings: this window's HKCU plus every logged-on user
$userRoots = @('HKCU:'); foreach ($p in $profiles) { if ($p.Hive) { $userRoots += $p.Hive } }
# PATH of every logged-on user, with %USERPROFILE% etc. expanded for that user (not for this admin window)
$script:userPath = @()
foreach ($p in $profiles) {
  if (-not $p.Hive) { continue }
  $vars = @{ USERPROFILE = $p.Home; LOCALAPPDATA = $p.Local; APPDATA = $p.Roaming; HOMEPATH = $p.Home.Substring(2); HOMEDRIVE = $p.Home.Substring(0, 2); USERNAME = $p.Name }
  $raw = ''
  foreach ($l in (cmd /c "reg query `"HKU\$($p.Sid)\Environment`" 2>nul")) {
    if ($l -match '^\s+(\S+)\s+REG_(EXPAND_)?SZ\s+(.*)$') { if ($Matches[1] -eq 'Path') { $raw = $Matches[3] } else { $vars[$Matches[1].ToUpper()] = $Matches[3] } }
  }
  foreach ($d in ($raw -split ';')) {
    $d = $d.Trim(); $n = 0
    while ($d -match '%([^%]+)%' -and $n -lt 10) {
      $n++; $name = $Matches[1]; $val = ''
      if ($vars.ContainsKey($name.ToUpper())) { $val = $vars[$name.ToUpper()] } else { $val = "$((Get-Item "env:$name").Value)" }
      $d = $d.Replace("%$name%", $val)
    }
    if ($d -and $d -notmatch '%' -and $script:userPath -notcontains $d) { $script:userPath += $d }
  }
}
# Certificates in another logged-on user's store are only reachable through the registry: the certificate
# blob is matched against the compromised CA names (as hex); Cert:\CurrentUser covers this window's account
$mySid = ''; foreach ($l in (cmd /c "whoami /user /fo csv /nh 2>nul")) { if ("$l" -match '"(S-1-[^"]+)"') { $mySid = $Matches[1] } }
$EM_HEX = @()
foreach ($s in 'EM DV TLS CA - G3', 'EM OV TLS CA - G3', 'EM EV TLS CA - G3', 'EM OV CS CA - G3') { $h = ''; foreach ($ch in $s.ToCharArray()) { $h += '{0:X2}' -f [int]$ch }; $EM_HEX += $h }
function Find-UserEmudhra {
  $hits = @()
  foreach ($p in $profiles) {
    if (-not $p.Hive -or $p.Sid -eq $mySid) { continue }
    foreach ($store in 'CA', 'Root') {
      $key = ''
      foreach ($l in (cmd /c "reg query `"HKU\$($p.Sid)\Software\Microsoft\SystemCertificates\$store\Certificates`" /s 2>nul")) {
        # only a certificate key: exactly <store>\Certificates\<40-hex thumbprint> (key names come from the user's hive)
        if ("$l" -match '^HKEY_') { $key = ''; $k = "$l".Trim(); if ($k -match ('^HKEY_USERS\\' + $p.Sid + '\\Software\\Microsoft\\SystemCertificates\\' + $store + '\\Certificates\\[0-9A-Fa-f]{40}$')) { $key = $k } }
        elseif ($key -and "$l" -match '^\s+Blob\s+REG_BINARY\s+([0-9A-Fa-f]+)') {
          $hex = $Matches[1].ToUpper(); foreach ($e in $EM_HEX) { if ($hex.Contains($e)) { $hits += , @{ Key = $key; User = $p.Name }; break } }
        }
      }
    }
  }
  return , $hits
}
function Get-Profile($path) { foreach ($p in $profiles) { if ("$path".ToLower().StartsWith($p.Home.ToLower() + '\')) { return $p } }; return $null }
# When elevated, keep downloads out of the user-writable %TEMP%: a new ProgramData folder created by this
# run is owned by Administrators, so a normal user cannot swap an installer after its checksum is checked
if ($isAdmin) {
  do { $dl = Join-Path $env:ProgramData ("EndpointPatch-{0}-{1}" -f $stamp, (Get-Random -Maximum 999999)) } while (Test-Path $dl)
  New-Item -ItemType Directory -Path $dl | Out-Null
}

# True when only SYSTEM / Administrators / TrustedInstaller can change the folder. The elevated script only
# RUNS programs from such folders; anything a normal user could modify is read from file metadata instead.
function Test-AdminOnly($dir) {
  if (-not $dir -or -not (Test-Path $dir)) { return $false }
  foreach ($ace in (Get-Acl $dir).Access) {
    if ("$($ace.AccessControlType)" -ne 'Allow') { continue }
    $who = "$($ace.IdentityReference)"; $name = $who.Split('\')[-1]
    if (@('SYSTEM', 'Administrators', 'TrustedInstaller', 'CREATOR OWNER') -contains $name -or $who -like 'APPLICATION PACKAGE AUTHORITY*') { continue }
    if ("$($ace.FileSystemRights)" -match 'FullControl|Modify|Write|CreateFiles|AppendData|268435456|1073741824') { return $false }
  }
  return $true
}
function Test-SafeToRun($exe) { return (Test-AdminOnly (Split-Path $exe)) }
# CPU type of a program from its PE header, read as bytes (nothing is executed)
function Get-PeArch($exe) {
  $b = Get-Content $exe -Encoding Byte -TotalCount 4096
  if (-not $b -or $b.Count -lt 64) { return $arch }
  $pe = [int]$b[60] + 256 * [int]$b[61] + 65536 * [int]$b[62]
  if ($pe + 6 -gt $b.Count) { return $arch }
  $m = [int]$b[$pe + 4] + 256 * [int]$b[$pe + 5]
  if ($m -eq 34404) { return 'x64' }; if ($m -eq 332) { return 'x86' }; if ($m -eq 43620) { return 'arm64' }
  return $arch
}
function Get-PyRegKeys { $r = @('HKLM:\SOFTWARE\Python\PythonCore', 'HKLM:\SOFTWARE\WOW6432Node\Python\PythonCore'); foreach ($u in $userRoots) { $r += "$u\SOFTWARE\Python\PythonCore" }; return , $r }
# Python version and packages read from disk (patchlevel.h, registry, .dist-info folders) - Python is never run
function Get-PyInfo($exe) {
  $dir = Split-Path $exe
  $info = @{ Version = $null; Litellm = $null; Pillow = $null; Certifi = $null; PipCertifi = $null }
  $pl = Join-Path $dir 'include\patchlevel.h'
  if (Test-Path $pl) { $m = Select-String -Path $pl -Pattern '#define PY_VERSION\s+"(\d+\.\d+\.\d+)' | Select-Object -First 1; if ($m) { $info.Version = $m.Matches[0].Groups[1].Value } }
  if (-not $info.Version) {
    foreach ($k in (Get-PyRegKeys)) {
      if (-not (Test-Path $k)) { continue }
      foreach ($tag in (Get-ChildItem $k)) {
        $ipk = Join-Path $tag.PSPath 'InstallPath'
        if ((Test-Path $ipk) -and "$((Get-ItemProperty $ipk).'(default)')".TrimEnd('\') -eq $dir) { $rv = Norm "$((Get-ItemProperty $tag.PSPath).Version)"; if ($rv) { $info.Version = $rv } }
      }
    }
  }
  if (-not $info.Version) { $fv = Norm (FileVer $exe); if ($fv -match '^(\d+\.\d+)\.(\d+)$' -and [int]$Matches[2] -lt 1000) { $info.Version = $fv } }
  $sp = @(Join-Path $dir 'Lib\site-packages')
  $short = ''; if ($info.Version -match '^(\d+)\.(\d+)') { $short = "$($Matches[1])$($Matches[2])" }
  # pip install --user packages live in the Roaming folder of the Python's owner (or of this account)
  $rp = Get-Profile $exe; $roam = $env:APPDATA; if ($rp) { $roam = $rp.Roaming }
  if ($short -and $roam) { $sp += Join-Path $roam "Python\Python$short\site-packages" }
  foreach ($s in $sp) {
    if (-not (Test-Path $s)) { continue }
    foreach ($d in (Get-ChildItem $s | Where-Object { $_.PSIsContainer -and $_.Name -match '^(?i)(litellm|pillow|certifi)-([0-9][^-]*)\.dist-info$' })) {
      $null = $d.Name -match '^(?i)(litellm|pillow|certifi)-([0-9][^-]*)\.dist-info$'
      switch ($Matches[1].ToLower()) { 'litellm' { $info.Litellm = $Matches[2] } 'pillow' { $info.Pillow = $Matches[2] } 'certifi' { $info.Certifi = $Matches[2] } }
    }
  }
  $pc = Join-Path $dir 'Lib\site-packages\pip\_vendor\certifi\__init__.py'
  if (Test-Path $pc) { $m = Select-String -Path $pc -Pattern '__version__\s*=\s*"([^"]+)"' | Select-Object -First 1; if ($m) { $info.PipCertifi = $m.Matches[0].Groups[1].Value } }
  return $info
}

# Installed programs from the registry (works on every Windows version)
$apps = @(); $appSeen = @{}
$uk = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')
foreach ($u in $userRoots) { $uk += "$u\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" }
foreach ($k in $uk) {
  if (Test-Path $k) {
    foreach ($sub in (Get-ChildItem $k)) {
      $p = Get-ItemProperty $sub.PSPath
      if (-not $p.DisplayName) { continue }
      $key = ("{0}|{1}|{2}" -f $p.DisplayName, $p.DisplayVersion, $p.InstallLocation).ToLower()
      if ($appSeen.ContainsKey($key)) { continue }; $appSeen[$key] = 1
      $apps += , @{ Name = "$($p.DisplayName)"; Version = "$($p.DisplayVersion)"; Location = "$($p.InstallLocation)" }
    }
  }
}
function Find-App($pattern) { $r = @(); foreach ($a in $apps) { if ($a.Name -match $pattern) { $r += , $a } }; return , $r }

# Runtimes that another application ships for itself (MySQL Workbench, LibreOffice, VS Code, Electron apps...).
# Only that application's own update can change them, so they are reported, never patched.
function Test-InApp($path) {
  $l = "$path".ToLower()
  if ($l -match '\\resources\\|\\dependencies\\|\\node_modules\\|\\lib\\python3|\\program\\python-core|\\app-\d|\\[0-9a-f]{16}\\|\\runtimes?\\') { return $true }
  if ($l -match '\\appdata\\local\\programs\\([^\\]+)\\' -and $Matches[1] -notmatch '^(python|nodejs)') { return $true }
  if ($l -match '\\program files( \(x86\))?\\([^\\]+)\\' -and $Matches[2] -notmatch '^(python|nodejs)') { return $true }
  return $false
}
# Chrome / Edge download a new version into Application\<version>\ and switch to it on the next browser start
function Get-StagedVer($dir, $dll) {
  $best = $null
  if ($dir -and (Test-Path $dir)) {
    foreach ($d in (Get-ChildItem $dir | Where-Object { $_.PSIsContainer -and $_.Name -match '^\d+(\.\d+){3}$' })) {
      if ((Test-Path (Join-Path $d.FullName $dll)) -and (-not $best -or (Test-Min $d.Name $best) -eq $true)) { $best = $d.Name }
    }
  }
  return $best
}
# Real Python installs: registered with Windows (PEP 514) or on PATH; skips app-bundled copies and virtual envs
function Find-Pythons {
  $list = @(); $seen = @()
  foreach ($k in (Get-PyRegKeys)) {
    if (-not (Test-Path $k)) { continue }
    $scope = 'system'; if ($k -notlike 'HKLM:*') { $scope = 'user' }
    foreach ($tag in (Get-ChildItem $k)) {
      $ipk = Join-Path $tag.PSPath 'InstallPath'
      if (-not (Test-Path $ipk)) { continue }
      $ip = "$((Get-ItemProperty $ipk).'(default)')".TrimEnd('\')
      $exe = Join-Path $ip 'python.exe'
      if ($ip -and (Test-Path $exe) -and $seen -notcontains $exe.ToLower()) { $seen += $exe.ToLower(); $list += , @{ Exe = $exe; Scope = $scope } }
    }
  }
  # per-user python.org installs of users who are not logged on (their registry is not loaded)
  $more = @()
  foreach ($p in $profiles) { $g = Join-Path $p.Local 'Programs\Python\Python3*\python.exe'; if (Test-Path $g) { foreach ($e in (Get-Item $g)) { $more += $e.FullName } } }
  foreach ($exe in ((WhereAll 'python.exe') + $more)) {
    if ($seen -contains $exe.ToLower() -or (Test-InApp $exe)) { continue }
    $d = Split-Path $exe
    if ((Test-Path (Join-Path $d 'pyvenv.cfg')) -or (Test-Path (Join-Path (Split-Path $d) 'pyvenv.cfg'))) { continue }
    $seen += $exe.ToLower()
    $scope = 'system'; if ($exe -match '\\Users\\') { $scope = 'user' }
    $list += , @{ Exe = $exe; Scope = $scope }
  }
  return , $list
}
function Get-PathOwner($p) { if ("$p" -match '^[A-Za-z]:\\Users\\([^\\]+)\\') { return $Matches[1] } return '' }

# ---------------- Download + verify ----------------
function Download($url, $file) {
  $out = Join-Path $dl $file
  if (Test-Path $out) { Remove-Item $out -Force }
  Log "Download $url"
  # 1. curl.exe (built into Windows 10/11, System32): works in any session, including "Run as" admin windows
  $curl = Join-Path $env:SystemRoot 'System32\curl.exe'
  if (Test-Path $curl) { cmd /c "`"$curl`" -fsSL --retry 3 --max-time 900 -o `"$out`" `"$url`" >nul 2>&1"; if ($LASTEXITCODE -ne 0 -and (Test-Path $out)) { Remove-Item $out -Force } }
  # 2. Invoke-WebRequest. TLS 1.2 can only be forced in full language mode (blocked on company-locked PowerShell)
  if (-not (Test-Path $out)) {
    if ($FullLang) { try { [Net.ServicePointManager]::SecurityProtocol = 3072 } catch { } }
    if (Get-Command Invoke-WebRequest) { Invoke-WebRequest -Uri $url -OutFile $out -UseBasicParsing }
  }
  # 3. BITS (fails with 0x800704DD when the window runs as a different user than the one logged on)
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
    elseif (-not (Test-SafeToRun $s.Path)) {
      # started by a normal user before; restarting it from this elevated script would run it as admin
      Log "Not restarting $($s.Path) as admin (user-writable folder)"
      Write-Host ("    Start again yourself (e.g. XAMPP Control Panel): {0}" -f $s.Path) -ForegroundColor Yellow
    }
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

  # Chrome: the machine-wide install and every per-user install (AppData\Local of each profile)
  $cdirs = @()
  $cands = @("$env:ProgramFiles\Google\Chrome\Application", "${env:ProgramFiles(x86)}\Google\Chrome\Application")
  foreach ($p in $profiles) { $cands += Join-Path $p.Local 'Google\Chrome\Application' }
  foreach ($d in $cands) { if ($d -match '^[A-Za-z]:\\' -and $cdirs -notcontains $d -and (Test-Path (Join-Path $d 'chrome.exe'))) { $cdirs += $d } }
  if (-not $cdirs.Count) {
    $c = Find-App '^Google Chrome$'
    if ($c.Count) { Add-Row 'Browser' 'Google Chrome' (Norm $c[0].Version) $MIN_CHROME (St (Test-Min $c[0].Version $MIN_CHROME)) 'Installed but chrome.exe not found: open chrome://settings/help to update' }
    else { Add-Row 'Browser' 'Google Chrome' '-' $MIN_CHROME '-' '-' }
  }
  foreach ($cdir in $cdirs) {
    $v = Norm (FileVer (Join-Path $cdir 'chrome.exe'))
    if (-not $v) { $v = Get-StagedVer $cdir 'chrome.dll' }
    $who = Get-PathOwner $cdir; $label = 'Google Chrome'; if ($who) { $label = "Google Chrome (user $who)" }
    if ($legacy) { Add-Row 'Browser' $label $v $MIN_CHROME 'NO PATCH' 'Chrome 110+ needs Windows 10/11. Remove Chrome or upgrade the OS.' }
    elseif ((Test-Min $v $MIN_CHROME) -eq $true) { Add-Row 'Browser' $label $v $MIN_CHROME 'OK' '-' }
    elseif ((Test-Min (Get-StagedVer $cdir 'chrome.dll') $MIN_CHROME) -eq $true) { Add-Row 'Browser' $label "$v (new ready)" $MIN_CHROME 'RESTART' 'Fix downloaded: close and reopen Chrome to finish' }
    elseif ($who) { Add-Row 'Browser' $label $v $MIN_CHROME 'MANUAL' "Per-user Chrome (not run as admin). Logged on as $who, open chrome://settings/help - or install the machine-wide Chrome, which takes over" 'manual' }
    else { Add-Row 'Browser' $label $v $MIN_CHROME (St (Test-Min $v $MIN_CHROME)) 'Update Chrome' 'chrome' $cdir }
  }

  # Edge
  $v = $null; $edir = $null
  foreach ($p in "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe", "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe") { if (-not $v) { $v = FileVer $p; if ($v) { $edir = Split-Path $p } } }
  if (-not $v) { Add-Row 'Browser' 'Microsoft Edge' '-' $MIN_EDGE '-' '-' }
  elseif ($legacy) { Add-Row 'Browser' 'Microsoft Edge' $v $MIN_EDGE 'NO PATCH' 'Edge 110+ needs Windows 10/11.' }
  else {
    $req = $MIN_EDGE; if ((Norm $v) -like '152.*') { $req = $MIN_EDGE_EXT }
    if ((Test-Min $v $req) -ne $true -and (Test-Min (Get-StagedVer $edir 'msedge.dll') $req) -eq $true) { Add-Row 'Browser' 'Microsoft Edge' "$(Norm $v) (new ready)" $req 'RESTART' 'Fix downloaded: close and reopen Edge to finish' }
    else { $s = St (Test-Min $v $req); $a = '-'; if ($s -eq 'UPDATE') { $a = 'Update Edge' }; Add-Row 'Browser' 'Microsoft Edge' $v $req $s $a 'edge' }
  }

  # Firefox (release / ESR): machine-wide and per-user installs
  $fexes = @()
  $cands = @("$env:ProgramFiles\Mozilla Firefox\firefox.exe", "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe")
  foreach ($p in $profiles) { $cands += Join-Path $p.Local 'Mozilla Firefox\firefox.exe' }
  foreach ($e in $cands) { if ($e -match '^[A-Za-z]:\\' -and $fexes -notcontains $e -and (Test-Path $e)) { $fexes += $e } }
  $f = Find-App '^Mozilla Firefox'
  if (-not $fexes.Count) {
    if ($f.Count) { Add-Row 'Browser' 'Mozilla Firefox' (Norm $f[0].Version) $MIN_FF (St (Test-Min $f[0].Version $MIN_FF)) 'Installed but firefox.exe not found: update from Help > About Firefox' }
    else { Add-Row 'Browser' 'Mozilla Firefox' '-' $MIN_FF '-' '-' }
  }
  foreach ($fx in $fexes) {
    $v = Norm (FileVer $fx)
    # ESR builds say so in their own files (the uninstall entry name can belong to another install)
    $esr = $false; $cp = Join-Path (Split-Path $fx) 'defaults\pref\channel-prefs.js'
    if ((Test-Path $cp) -and (Select-String -Path $cp -Pattern 'app\.update\.channel"\s*,\s*"esr' -Quiet)) { $esr = $true }
    if (-not $esr) { foreach ($a in $f) { if ($a.Name -match 'ESR' -and $a.Location -and $fx -like "$($a.Location.TrimEnd('\'))\*") { $esr = $true } } }
    $major = ((Norm $v) -split '\.')[0]
    if ($legacy) { $req = $MIN_FF_ESR115; $chan = 'esr115' }
    elseif ($major -eq '115') { $req = $MIN_FF_ESR115; $chan = 'esr' }
    elseif ($major -eq '153' -or $esr) { $req = $MIN_FF_ESR153; $chan = 'esr' }
    else { $req = $MIN_FF; $chan = 'release' }
    $who = Get-PathOwner $fx; $label = 'Mozilla Firefox'; if ($esr) { $label = 'Mozilla Firefox ESR' }; if ($who) { $label += " (user $who)" }
    $s = St (Test-Min $v $req)
    if ($s -eq 'UPDATE' -and $who) { Add-Row 'Browser' $label $v $req 'MANUAL' "Per-user Firefox (not run as admin). Logged on as ${who}: Help > About Firefox" 'manual' }
    else { $a = '-'; if ($s -eq 'UPDATE') { $a = "Install latest Firefox ($chan)" }; Add-Row 'Browser' $label $v $req $s $a 'firefox' "$chan|$fx" }
  }

  # Java (every installed JDK / JRE)
  $javas = Find-App '(Java\(TM\)|^Java \d|Java SE Development Kit|Temurin|OpenJDK|Corretto|Zulu)'
  if (-not $javas.Count) {
    $jx = WhereAll 'java.exe'
    if ($jx.Count) { $jfv = Norm (FileVer $jx[0]); if ($jfv) { $javas = @(, @{ Name = "Java ($($jx[0]))"; Version = $jfv; Location = '' }) } }
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
  $v = $null; $nodePath = ''; $inApp = @()
  foreach ($n in (WhereAll 'node.exe')) {
    if (Test-InApp $n) { $inApp += $n; continue }          # Node.js shipped inside another app: not ours to patch
    if (-not $nodePath) { $nodePath = $n }
  }
  if ($nodePath) { $v = Norm (FileVer $nodePath) }
  if (-not $v) { $na = Find-App '^Node\.js$'; if ($na.Count) { $v = $na[0].Version } }
  foreach ($n in $inApp) { Add-Row 'Runtime' "Node.js (inside an app) [$n]" (Norm (FileVer $n)) '-' 'IN APP' 'Bundled inside another application: update that application' }
  if (-not $v) { Add-Row 'Runtime' 'Node.js' '-' '22.23.4 / 24.22.1 / 26.12.1' '-' '-' }
  else {
    $major = ((Norm $v) -split '\.')[0]
    if ($NodeMin.ContainsKey($major)) { $req = $NodeMin[$major] } else { $req = $NodeMin['24'] }
    $ok = $false; if ($NodeMin.ContainsKey($major)) { $ok = Test-Min $v $req }
    $s = St $ok; $a = '-'
    if ($legacy) { Add-Row 'Runtime' 'Node.js' $v $req 'NO PATCH' 'Node.js 22+ needs Windows 10/11.' }
    elseif ($nodePath -match '\\nvm') { if ($ok) { Add-Row 'Runtime' 'Node.js (nvm)' $v $req 'OK' '-' } else { Add-Row 'Runtime' 'Node.js (nvm)' $v $req 'MANUAL' "nvm is user-writable, so it is not run as admin. In a normal PowerShell run:  nvm install $req; nvm use $req" 'manual' } }
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
    $v = FileVer $p                                         # read from the file, php.exe is not run
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

  # Python runtime, its certifi (eMudhra), LiteLLM and Pillow - real installs only (see Find-Pythons)
  $pyList = Find-Pythons
  if (-not $pyList.Count) {
    Add-Row 'Language' 'Python' '-' '3.14.9 / 3.13.17 / 3.15.1' '-' '-'
    Add-Row 'Supply chain' 'Python: litellm' '-' "not $BAD_LITELLM" '-' '-'
    Add-Row 'Library' 'Python: Pillow' '-' $MIN_PILLOW '-' '-'
  }
  foreach ($pi in $pyList) {
    $py = $pi.Exe
    # Microsoft Store Python: Windows does not let scripts run it from WindowsApps, and Store build numbers
    # are not python.org versions, so it is reported for an update through the Store
    if ($py -match '\\WindowsApps\\') {
      $sb = '?'; if ($py -match 'Python\.(\d+\.\d+)_') { $sb = $Matches[1] }
      $req = '-'; if ($PyMin.ContainsKey($sb)) { $req = $PyMin[$sb] }
      Add-Row 'Language' "Python $sb (Microsoft Store)" "$sb (Store)" $req 'CHECK' "Microsoft Store > Library > Get updates (must reach $req)"
      continue
    }
    # Everything below is read from disk: this elevated script never runs a Python that users can modify
    $pinfo = Get-PyInfo $py
    $lite = $pinfo.Litellm; $pil = $pinfo.Pillow; $cert = $pinfo.Certifi
    $bad = ($lite -eq $BAD_LITELLM)
    $owner = Get-PathOwner $py
    $mine = (-not $owner -or $owner -eq $env:USERNAME)
    $safe = Test-SafeToRun $py              # folder writable only by admins: safe to run pip / the installer elevated
    $lp = $py.ToLower()
    $userCmd = "In a normal (non-admin) PowerShell"; if (-not $mine) { $userCmd = "Logged on as $owner, in a normal PowerShell" }

    # Python itself
    $pv = $pinfo.Version
    $pbr = ($pv -split '\.')[0..1] -join '.'
    if (-not $pv) { Add-Row 'Language' "Python [$py]" 'unknown' '3.14.9 / 3.13.17' 'CHECK' "Version not readable from disk. $userCmd run:  `"$py`" --version" }
    elseif ($bad) { Add-Row 'Language' "Python [$py]" $pv '-' 'COMPROMISED' 'Skipped: this Python is compromised by litellm 1.107.0' }
    elseif (-not $PyMin.ContainsKey($pbr)) {
      if ((Test-Min $pv '3.16') -eq $true) { Add-Row 'Language' "Python [$py]" $pv '-' 'OK' '-' }
      else { Add-Row 'Language' "Python [$py]" $pv '3.13.17+ (supported branch)' 'MANUAL' "Python $pbr is end-of-life: no more fixes. Move to 3.13 or 3.14 (major upgrade, test the apps)." 'manual' }
    }
    elseif ((Test-Min $pv $PyMin[$pbr]) -eq $true) { Add-Row 'Language' "Python [$py]" $pv $PyMin[$pbr] 'OK' '-' }
    elseif ($lp -match '\\uv\\python\\') { Add-Row 'Language' "Python (uv) [$py]" $pv $PyMin[$pbr] 'MANUAL' "Managed by uv: run  uv python install $($PyMin[$pbr])" 'manual' }
    elseif ($lp -match 'conda|miniforge|mambaforge') { Add-Row 'Language' "Python (conda) [$py]" $pv $PyMin[$pbr] 'MANUAL' "Managed by conda: run  conda install python=$($PyMin[$pbr])" 'manual' }
    elseif ($lp -match '\\pyenv-win\\') { Add-Row 'Language' "Python (pyenv) [$py]" $pv $PyMin[$pbr] 'MANUAL' "Managed by pyenv: run  pyenv install $($PyMin[$pbr])" 'manual' }
    elseif ($lp -match '\\pythoncore-') { Add-Row 'Language' "Python (install manager) [$py]" $pv $PyMin[$pbr] 'MANUAL' "Managed by the Python install manager: update $pbr with it (see: py help install)" 'manual' }
    elseif ($PyHasInstaller -notcontains $pbr) { Add-Row 'Language' "Python [$py]" $pv $PyMin[$pbr] 'NO PATCH' "Python $pbr is security-only: python.org publishes $($PyMin[$pbr]) as source code only, no Windows installer exists (the last Windows build of 3.12 was 3.12.10, of 3.11 was 3.11.9). To get the fixes, install Python 3.13.17 or 3.14.9 and move the apps to it (test them first)." }
    elseif (-not $safe) {
      $pyUrl = "$REL/python-$($PyMin[$pbr])-amd64.exe"
      Add-Row 'Language' "Python [$py]" $pv $PyMin[$pbr] 'MANUAL' "Folder is user-writable, so it is not updated as admin. $userCmd run the python.org installer $($PyMin[$pbr]) ($pyUrl) and choose Upgrade" 'manual'
    }
    else { Add-Row 'Language' "Python [$py]" $pv $PyMin[$pbr] 'UPDATE' "Install Python $($PyMin[$pbr]) over it (python.org installer)" 'pyinst' "$py|$($PyMin[$pbr])|$($pi.Scope)" }

    # certifi used by pip / requests (the eMudhra fix for every Python branch)
    $low = $pinfo.PipCertifi; if ($cert -and (-not $low -or (Test-Min $cert $low) -ne $true)) { $low = $cert }
    if (-not $bad -and $pv -and $low -and (Test-Min $low $MIN_CERTIFI) -ne $true) {
      if ($safe) { Add-Row 'Certificate' "Python certifi [$py]" $low $MIN_CERTIFI 'UPDATE' 'pip install -U pip certifi (drops the eMudhra CA)' 'certifi' $py }
      else { Add-Row 'Certificate' "Python certifi [$py]" $low $MIN_CERTIFI 'MANUAL' "$userCmd run:  `"$py`" -m pip install -U pip certifi" 'manual' }
    }
    if ($bad) { Add-Row 'Supply chain' "Python: litellm [$py]" $lite "not $BAD_LITELLM ($GOOD_LITELLM)" 'COMPROMISED' 'Security incident: disconnect from network, report to security, rebuild the machine, rotate all secrets. Not auto-fixed: running Python here re-runs the malware.' }
    elseif ($lite) { Add-Row 'Supply chain' "Python: litellm [$py]" $lite "not $BAD_LITELLM" 'OK' '-' }
    else { Add-Row 'Supply chain' "Python: litellm [$py]" '-' "not $BAD_LITELLM" '-' '-' }
    if (-not $pil) { Add-Row 'Library' "Python: Pillow [$py]" '-' $MIN_PILLOW '-' '-' }
    elseif ($bad) { Add-Row 'Library' "Python: Pillow [$py]" $pil $MIN_PILLOW 'COMPROMISED' 'Skipped: this Python is compromised by litellm 1.107.0' }
    elseif ((Test-Min $pil $MIN_PILLOW) -eq $true) { Add-Row 'Library' "Python: Pillow [$py]" $pil $MIN_PILLOW 'OK' '-' }
    elseif ($safe) { Add-Row 'Library' "Python: Pillow [$py]" $pil $MIN_PILLOW 'UPDATE' "pip install pillow>=$MIN_PILLOW" 'pillow' $py }
    else { Add-Row 'Library' "Python: Pillow [$py]" $pil $MIN_PILLOW 'MANUAL' "$userCmd run:  `"$py`" -m pip install -U `"pillow>=$MIN_PILLOW`"" 'manual' }
  }

  # GitLab (Linux only)
  Add-Row 'Server' 'GitLab (self-managed)' '-' '19.5.1 / 19.4.3 / ... / 18.11.13' '-' 'Linux only'

  # OVHcloud CLI
  $ov = WhereAll 'ovhcloud.exe'
  if ($ov.Count) {
    # Identified by fingerprint against the official 0.16.0 binaries - the binary is not run
    $isFixed = $OVH_EXE_SHA -contains (Get-Sha256 $ov[0])
    if ($isFixed) { Add-Row 'Supply chain' "OVHcloud CLI [$($ov[0])]" $MIN_OVH $MIN_OVH 'OK' '-' }
    else { Add-Row 'Supply chain' "OVHcloud CLI [$($ov[0])]" "not $MIN_OVH" $MIN_OVH 'UPDATE' "Replace with the verified $MIN_OVH binary" 'ovh' $ov[0] }
  } else { Add-Row 'Supply chain' 'OVHcloud CLI' '-' $MIN_OVH '-' '-' }

  # eMudhra certificates
  $bad = @(Get-ChildItem Cert:\LocalMachine\CA, Cert:\LocalMachine\Root, Cert:\CurrentUser\CA, Cert:\CurrentUser\Root | Where-Object { $_.Subject -match 'EM (DV|OV|EV) TLS CA - G3|EM OV CS CA - G3' })
  $ubad = Find-UserEmudhra
  $cnt = $bad.Count + $ubad.Count
  if ($cnt) { Add-Row 'Certificate' 'eMudhra compromised intermediates' ("{0} found" -f $cnt) 'none' 'UPDATE' 'Delete the compromised certificates' 'emudhra' }
  else { Add-Row 'Certificate' 'eMudhra compromised intermediates' 'none' 'none' 'OK' '-' }

  # Docker images
  $dk = WhereAll 'docker.exe'
  if ($dk.Count -and -not (Test-SafeToRun $dk[0])) { Add-Row 'Container' "Docker images [$($dk[0])]" 'not checked' 'pulled after 21 Oct 2026' 'CHECK' 'docker.exe is in a user-writable folder, so it is not run as admin. Check images from a normal prompt.' }
  elseif ($dk.Count) {
    $imgs = cmd /c "`"$($dk[0])`" images --format `"{{.Repository}}:{{.Tag}}`" 2>nul"
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
        # npm runs the project's own install scripts, so it is never run as admin
        if ((Test-Min $v $req) -eq $true) { Add-Row 'Library' "Next.js [$proj]" $v $req 'OK' '-' }
        else { Add-Row 'Library' "Next.js [$proj]" $v $req 'MANUAL' "In a normal (non-admin) prompt:  cd `"$proj`"; npm install next@$req" 'manual' }
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
    switch ($r.Status) { 'OK' { $c = 'Green' } 'UPDATE' { $c = 'Red' } 'COMPROMISED' { $c = 'Magenta' } 'MANUAL' { $c = 'Yellow' } 'NO PATCH' { $c = 'DarkYellow' } 'NO FIX YET' { $c = 'DarkYellow' } 'CHECK' { $c = 'Yellow' } 'IN APP' { $c = 'DarkGray' } 'RESTART' { $c = 'Yellow' } }
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
  # Thread-safe builds ship php8ts.dll, non-thread-safe builds php8.dll; CPU type from the exe header
  $nts = -not (Test-Path (Join-Path $dir 'php8ts.dll'))
  $parch = Get-PeArch $exe; if ($parch -ne 'x86') { $parch = 'x64' }
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
  $nv = Norm (FileVer $exe)
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
  if ($wasRunning -and -not ($stopped | Where-Object { $_.Kind -eq 'svc' })) {
    if (Test-AdminOnly (Join-Path $dir 'bin')) { Start-Process -FilePath (Join-Path $dir 'bin\startup.bat') -WorkingDirectory (Join-Path $dir 'bin') -WindowStyle Hidden }
    else { return "Tomcat $target installed (conf and webapps kept). Start it again with $dir\bin\startup.bat (not run as admin: user-writable folder). Backup: $bak" }
  }
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

# Mozilla's own installer first (always the newest release; winget's catalog can lag behind),
# signature checked, installed into the same folder, then the version is checked again.
function Update-Firefox($chan, $exe, $req) {
  $prod = 'firefox-latest-ssl'; if ($chan -eq 'esr') { $prod = 'firefox-esr-latest-ssl' }; if ($chan -eq 'esr115') { $prod = 'firefox-esr115-latest-ssl' }
  $osTag = 'win'; if ($is64) { $osTag = 'win64' }
  $f = Download "https://download.mozilla.org/?product=$prod&os=$osTag&lang=en-US" 'firefox-setup.exe'
  if ($f) {
    $sig = Get-AuthenticodeSignature $f
    if ("$($sig.Status)" -ne 'Valid' -or "$($sig.SignerCertificate.Subject)" -notmatch 'Mozilla Corporation') {
      Log "Firefox installer signature not valid ($($sig.Status) $($sig.SignerCertificate.Subject))"; Remove-Item $f -Force; $f = $null
    }
  }
  if ($f) {
    # Firefox restores open tabs on next start; its files must not be in use while installing
    Get-Process firefox | Stop-Process -Force; Start-Sleep -Seconds 2
    $a = '/S'; if ($exe) { $a = "/S /InstallDirectoryPath=`"$(Split-Path $exe)`"" }
    Run $f $a | Out-Null
  }
  $v = FileVer $exe
  if ((Test-Min $v $req) -eq $true) { return "Firefox $(Norm $v) installed (signed by Mozilla). Reopen Firefox; tabs are restored." }
  $id = 'Mozilla.Firefox'; if ($chan -ne 'release') { $id = 'Mozilla.Firefox.ESR' }
  if ($chan -ne 'esr115') { Winget $id | Out-Null }
  $v = FileVer $exe
  if ((Test-Min $v $req) -eq $true) { return "Firefox $(Norm $v) installed with winget. Reopen Firefox." }
  return "FAILED: Firefox is still $(Norm $v) (needs $req). Update from Help > About Firefox."
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
  # the same certificates in the stores of other logged-on users
  foreach ($h in (Find-UserEmudhra)) {
    Log "Delete certificate of $($h.User): $($h.Key)"
    # PowerShell provider with a literal path: no command line is built from registry data
    Remove-Item -LiteralPath ('Registry::' + $h.Key) -Recurse -Force
    if (-not (Test-Path -LiteralPath ('Registry::' + $h.Key))) { $n++ }
  }
  return "Deleted $n compromised eMudhra certificate(s)."
}

# Chrome / Edge: each method is tried in turn and the result is checked; a downloaded update that only
# needs a browser restart counts as installed (the old exe keeps running until the browser is reopened)
function Get-BrowserVer($dir, $exeName, $dll) {
  $v = Norm (FileVer (Join-Path $dir $exeName)); $s = Get-StagedVer $dir $dll
  if ($s -and (-not $v -or (Test-Min $s $v) -eq $true)) { return $s }
  return $v
}
function Wait-BrowserVer($dir, $exeName, $dll, $req, $seconds) {
  for ($i = 0; $i -lt ($seconds / 5); $i++) { if ((Test-Min (Get-BrowserVer $dir $exeName $dll) $req) -eq $true) { return $true }; Start-Sleep -Seconds 5 }
  return ((Test-Min (Get-BrowserVer $dir $exeName $dll) $req) -eq $true)
}
function Update-Chrome($dir, $req) {
  if (Get-PathOwner $dir) { return 'MANUAL: this is a per-user Chrome; update it from chrome://settings/help (not run as admin).' }
  foreach ($gu in "${env:ProgramFiles(x86)}\Google\Update\GoogleUpdate.exe", "$env:ProgramFiles\Google\Update\GoogleUpdate.exe") {
    if ((Test-Path $gu) -and (Test-SafeToRun $gu)) { Run $gu '/ua /installsource scheduler' | Out-Null; break }
  }
  if (Wait-BrowserVer $dir 'chrome.exe' 'chrome.dll' $req 120) { return "Chrome $(Get-BrowserVer $dir 'chrome.exe' 'chrome.dll') ready. Close and reopen Chrome to finish." }
  Winget 'Google.Chrome' | Out-Null
  if (Wait-BrowserVer $dir 'chrome.exe' 'chrome.dll' $req 30) { return "Chrome $(Get-BrowserVer $dir 'chrome.exe' 'chrome.dll') installed with winget. Reopen Chrome." }
  $name = 'googlechromestandaloneenterprise.msi'; if ($is64) { $name = 'googlechromestandaloneenterprise64.msi' }
  $f = Download "https://dl.google.com/dl/chrome/install/$name" $name
  if ($f) {
    $sig = Get-AuthenticodeSignature $f
    if ("$($sig.Status)" -eq 'Valid' -and "$($sig.SignerCertificate.Subject)" -match 'Google LLC') { Msi $f | Out-Null } else { Log "Chrome MSI signature not valid: $($sig.Status)" }
  }
  if (Wait-BrowserVer $dir 'chrome.exe' 'chrome.dll' $req 30) { return "Chrome $(Get-BrowserVer $dir 'chrome.exe' 'chrome.dll') installed (Google-signed MSI). Reopen Chrome." }
  return "FAILED: Chrome is still $(Get-BrowserVer $dir 'chrome.exe' 'chrome.dll') (needs $req). Update from chrome://settings/help."
}
function Update-Edge($req) {
  $dir = $null; foreach ($p in "${env:ProgramFiles(x86)}\Microsoft\Edge\Application", "$env:ProgramFiles\Microsoft\Edge\Application") { if (-not $dir -and (Test-Path "$p\msedge.exe")) { $dir = $p } }
  foreach ($eu in "${env:ProgramFiles(x86)}\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe", "$env:ProgramFiles\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe") {
    if (Test-Path $eu) { Run $eu '/ua /installsource scheduler' | Out-Null; break }
  }
  if (Wait-BrowserVer $dir 'msedge.exe' 'msedge.dll' $req 120) { return "Edge $(Get-BrowserVer $dir 'msedge.exe' 'msedge.dll') ready. Close and reopen Edge to finish." }
  Winget 'Microsoft.Edge' | Out-Null
  if (Wait-BrowserVer $dir 'msedge.exe' 'msedge.dll' $req 30) { return "Edge $(Get-BrowserVer $dir 'msedge.exe' 'msedge.dll') installed with winget. Reopen Edge." }
  # Microsoft's enterprise MSI, listed with its SHA-256 by Microsoft's own release API
  if (Get-Command Invoke-RestMethod) {
    $ea = 'x64'; if ($arch -eq 'x86') { $ea = 'x86' }; if ($arch -eq 'arm64') { $ea = 'arm64' }
    $api = Invoke-RestMethod 'https://edgeupdates.microsoft.com/api/products'
    $rel = $api | Where-Object { $_.Product -eq 'Stable' } | ForEach-Object { $_.Releases } | Where-Object { $_.Platform -eq 'Windows' -and $_.Architecture -eq $ea } | Sort-Object { [datetime]$_.PublishedTime } -Descending | Select-Object -First 1
    $art = $rel.Artifacts | Where-Object { $_.ArtifactName -eq 'msi' } | Select-Object -First 1
    if ($art -and $art.Location) {
      $f = Download $art.Location "MicrosoftEdgeEnterprise-$($rel.ProductVersion)-$ea.msi"
      if ($f -and (Get-Sha256 $f) -eq "$($art.Hash)".ToLower()) { Msi $f | Out-Null } else { Log 'Edge MSI checksum mismatch or download failed' }
    }
  }
  if (Wait-BrowserVer $dir 'msedge.exe' 'msedge.dll' $req 30) { return "Edge $(Get-BrowserVer $dir 'msedge.exe' 'msedge.dll') installed (Microsoft MSI, checksum checked). Reopen Edge." }
  return "FAILED: Edge is still $(Get-BrowserVer $dir 'msedge.exe' 'msedge.dll') (needs $req). Update from edge://settings/help."
}

# Python: official python.org installer for the same branch, run over the existing install (same folder, same scope)
function Update-Python($exe, $target, $scope) {
  $dir = Split-Path $exe
  # Only a real Python folder that only admins can change; never a drive root or a whole Program Files
  if (-not (Test-Path (Join-Path $dir 'Lib\os.py')) -or $dir -match '^[A-Za-z]:\\?$' -or $dir -eq $env:ProgramFiles -or $dir -eq ${env:ProgramFiles(x86)}) { return "FAILED: $dir does not look like a Python install folder. Nothing changed." }
  if (-not (Test-SafeToRun $exe)) { return "FAILED: $dir is user-writable; update it from a normal (non-admin) prompt. Nothing changed." }
  $pa = Get-PeArch $exe
  $suffix = '-amd64'; if ($pa -eq 'x86') { $suffix = '' }; if ($pa -eq 'arm64') { $suffix = '-arm64' }
  $name = "python-$target$suffix.exe"
  $f = Get-Patch $name "https://www.python.org/ftp/python/$target/$name"
  if (-not $f) { return "FAILED: could not download a verified $name" }
  $all = 0; if ($scope -eq 'system') { $all = 1 }
  # stop only this Python (python.exe / pythonw.exe from exactly this folder)
  Get-Wmi Win32_Process | Where-Object { @("$dir\python.exe", "$dir\pythonw.exe") -contains "$($_.ExecutablePath)" } | ForEach-Object { Log "Stop $($_.Name) $($_.ProcessId)"; Stop-Process -Id $_.ProcessId -Force }
  $code = Run $f "/quiet InstallAllUsers=$all TargetDir=`"$dir`" /log `"$dl\python-$target-install.log`""
  $nv = (Get-PyInfo $exe).Version
  if ($nv -eq $target) { return "Python $target installed in $dir (includes pip with certifi $MIN_CERTIFI)." }
  return "FAILED: installer exit $code, Python is still $nv. Log: $dl\python-$target-install.log"
}

function Fix-Row($r) {
  switch ($r.Fix) {
    'chrome' { return (Update-Chrome $r.Arg $r.Req) }
    'edge' { return (Update-Edge $r.Req) }
    'pyinst' { $p = $r.Arg -split '\|'; return (Update-Python $p[0] $p[1] $p[2]) }
    'certifi' {
      Log "pip upgrade pip certifi on $($r.Arg)"
      if (-not (Test-SafeToRun $r.Arg)) { return 'FAILED: this Python folder is user-writable; run pip from a normal prompt. Nothing changed.' }
      cmd /c "`"$($r.Arg)`" -m pip install -U pip certifi --disable-pip-version-check >> `"$logFile`" 2>&1"
      $pi2 = Get-PyInfo $r.Arg; $c = $pi2.Certifi; if (-not $c) { $c = $pi2.PipCertifi }
      if ((Test-Min $c $MIN_CERTIFI) -eq $true) { return "pip and certifi $c installed (eMudhra CA removed)." }
      return 'FAILED: pip could not update certifi (no write access or no pip). See log.'
    }
    'firefox' { $p = $r.Arg -split '\|'; return (Update-Firefox $p[0] $p[1] $r.Req) }
    'node' {
      $ver = $r.Arg
      $f = Download "https://nodejs.org/dist/v$ver/node-v$ver-$arch.msi" "node-v$ver-$arch.msi"
      if ($f -and (Msi $f)) { return "Installed Node.js $ver. Restart Node services and terminals." }
      if (Winget 'OpenJS.NodeJS.LTS') { return 'Updated Node.js LTS with winget.' }
      return "FAILED: install Node.js $ver from nodejs.org"
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
      if (-not (Test-SafeToRun $r.Arg)) { return 'FAILED: this Python folder is user-writable; run pip from a normal prompt. Nothing changed.' }
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
if (@($script:rows | Where-Object { $_.Status -eq 'IN APP' }).Count) { Write-Host 'IN APP = a runtime bundled inside another application (e.g. MySQL Workbench, LibreOffice). Only updating that application changes it.' -ForegroundColor DarkGray }
if (@($script:rows | Where-Object { $_.Status -eq 'RESTART' }).Count) { Write-Host 'RESTART = the fixed browser version is already downloaded. Close and reopen that browser to finish.' -ForegroundColor Yellow }

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
