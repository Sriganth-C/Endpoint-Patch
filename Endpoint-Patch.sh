#!/usr/bin/env bash
# Endpoint-Patch.sh - October 2026 vulnerability scan + update for Linux servers and desktops
# Supports: Ubuntu, Debian, RHEL / Rocky / Alma / CentOS, Fedora, Amazon Linux, SUSE / openSUSE, Alpine
# Repository: https://github.com/Sriganth-C/Endpoint-Patch  (branch: linux)
#
#   1. Detects installed software and shows Installed vs Required. Not installed = "-".
#   2. Asks "Update now?" and installs the stable patch versions: package manager for packaged software,
#      verified packages from the GitHub release "patches-2026-10" (or the official site) for tarball
#      installs of Tomcat, Temurin Java, Node.js and OVHcloud CLI. Replaced files are backed up first.
#   3. Scans again and shows the final result. Saves a CSV report and a log.
#
# One-line run:
#   sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/Sriganth-C/Endpoint-Patch/linux/Endpoint-Patch.sh)"
#
# Options (add after the command above as:  ... )" endpoint-patch --scan-only ):
#   --scan-only     report only, change nothing
#   --yes           update without asking
#   --projects DIR  also check and update Next.js in project folders

SCAN_ONLY=0; YES=0; PROJECTS=""
while [ $# -gt 0 ]; do
  case "$1" in
    --scan-only) SCAN_ONLY=1;;
    --yes|-y) YES=1;;
    --projects) PROJECTS="$2"; shift;;
    *) echo "Unknown option: $1"; exit 1;;
  esac
  shift
done

HOST="$(hostname)"
STAMP="$(date +%Y%m%d-%H%M)"
OUTDIR="$(cd "$(dirname "$0")" 2>/dev/null && pwd)"; { [ -n "$OUTDIR" ] && [ -w "$OUTDIR" ]; } || OUTDIR="$(pwd)"; [ -w "$OUTDIR" ] || OUTDIR="/tmp"
CSV="$OUTDIR/Endpoint-Patch-$HOST-$STAMP.csv"
LOG="$OUTDIR/Endpoint-Patch-$HOST-$STAMP.log"
DL="/tmp/endpoint-patch-$STAMP"; mkdir -p "$DL"
log() { echo "$(date '+%F %T')  $*" >> "$LOG"; }
IS_ROOT=0; [ "$(id -u)" -eq 0 ] && IS_ROOT=1

# ---------------- Where the patch packages are stored ----------------
REPO="Sriganth-C/Endpoint-Patch"
TAG="patches-2026-10"
REL="https://github.com/$REPO/releases/download/$TAG"

# ---------------- Stable patch versions (October 2026) ----------------
MIN_CHROME=156.0.8078.47; MIN_EDGE=156.0.4314.42; MIN_EDGE_EXT=152.0.4191.137
MIN_FF=158.0.1; MIN_FF_ESR153=153.5.1; MIN_FF_ESR115=115.43.1
MIN_PILLOW=13.0.0; BAD_LITELLM=1.107.0; GOOD_LITELLM=1.106.2; MIN_OVH=0.16.0
node_min()   { case "$1" in 22) echo 22.23.4;; 24) echo 24.22.1;; 26) echo 26.12.1;; esac; }
php_min()    { case "$1" in 8.5) echo 8.5.12;; 8.4) echo 8.4.27;; 8.3) echo 8.3.36;; 8.2) echo 8.2.35;; esac; }
java_min()   { case "$1" in 27) echo 27.0.1;; 25) echo 25.0.5;; 21) echo 21.0.13;; 17) echo 17.0.21;; 11) echo 11.0.33;; esac; }
tomcat_min() { case "$1" in 11.0) echo 11.0.27;; 10.1) echo 10.1.61;; 9.0) echo 9.0.123;; esac; }
gitlab_min() { case "$1" in 19.5) echo 19.5.1;; 19.4) echo 19.4.3;; 19.3) echo 19.3.6;; 19.2) echo 19.2.9;; 19.1) echo 19.1.9;; 19.0) echo 19.0.10;; 18.11) echo 18.11.13;; esac; }

# ---------------- Helpers ----------------
ver_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)" = "$2" ]; }
norm()   { echo "$1" | grep -oE '[0-9]+(\.[0-9]+)+' | head -n1; }
branch() { echo "$1" | cut -d. -f1-2; }
owner()  { stat -c %U "$1" 2>/dev/null || echo root; }
ARCH="$(uname -m)"

PM=""
if command -v apt-get >/dev/null 2>&1; then PM=apt
elif command -v dnf >/dev/null 2>&1; then PM=dnf
elif command -v yum >/dev/null 2>&1; then PM=yum
elif command -v zypper >/dev/null 2>&1; then PM=zypper
elif command -v apk >/dev/null 2>&1; then PM=apk; fi
OSNAME="$(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-Linux}")"

# ---------------- Download + verify ----------------
fetch() { # url outfile
  log "download $1"
  if command -v curl >/dev/null 2>&1; then curl -fsSL --retry 3 --max-time 900 -o "$2" "$1" 2>>"$LOG"
  elif command -v wget >/dev/null 2>&1; then wget -q --tries=3 --timeout=60 -O "$2" "$1" 2>>"$LOG"
  else return 1; fi
  [ -s "$2" ]
}
SUMS=""
load_sums() { [ -n "$SUMS" ] && return; SUMS="$DL/SHA256SUMS.txt"; fetch "$REL/SHA256SUMS.txt" "$SUMS" || : > "$SUMS"; }
# get_patch NAME OFFICIAL_URL [SHA256]: from the GitHub release, else the official URL; only returns verified files
get_patch() {
  load_sums
  local name="$1" official="$2" exp="${3:-}" out="$DL/$1" u
  [ -z "$exp" ] && exp=$(awk -v n="$name" '$2==n || $2=="*"n {print $1}' "$SUMS" | head -n1)
  if [ -z "$exp" ]; then log "no checksum for $name - refusing unverified file"; return 1; fi
  for u in "$REL/$name" "$official"; do
    [ -z "$u" ] && continue
    rm -f "$out"
    fetch "$u" "$out" || continue
    if [ "$(sha256sum "$out" | cut -d' ' -f1)" = "$exp" ]; then log "checksum OK $name"; echo "$out"; return 0; fi
    log "checksum MISMATCH $name"; rm -f "$out"
  done
  return 1
}

# ---------------- Package manager ----------------
pkg_of() {
  local f; f="$(readlink -f "$1" 2>/dev/null)"; [ -z "$f" ] && return
  case "$PM" in
    apt) dpkg -S "$f" 2>/dev/null | head -n1 | cut -d: -f1;;
    dnf|yum|zypper) rpm -qf --qf '%{NAME}\n' "$f" 2>/dev/null | grep -v 'not owned' | head -n1;;
    apk) apk info --who-owns "$f" 2>/dev/null | awk '{print $NF}' | sed 's/-[0-9].*//';;
  esac
}
pkg_installed() {
  case "$PM" in
    apt) dpkg -s "$1" 2>/dev/null | grep -q '^Status: install ok installed';;
    dnf|yum|zypper) rpm -q "$1" >/dev/null 2>&1;;
    apk) apk info -e "$1" >/dev/null 2>&1;;
    *) return 1;;
  esac
}
pkg_has_update() {
  case "$PM" in
    apt) apt list --upgradable 2>/dev/null | grep -q "^$1/";;
    dnf|yum) $PM -q check-update "$1" >/dev/null 2>&1; [ $? -eq 100 ];;
    zypper) zypper -q lu 2>/dev/null | awk -F'|' '{gsub(/ /,"",$3); print $3}' | grep -qx "$1";;
    apk) apk version -l '<' 2>/dev/null | grep -q "^$1-";;
    *) return 1;;
  esac
}
pkg_upgrade() {
  log "upgrade packages: $*"
  case "$PM" in
    apt) DEBIAN_FRONTEND=noninteractive apt-get install -y --only-upgrade "$@" >> "$LOG" 2>&1;;
    dnf|yum) $PM -y upgrade "$@" >> "$LOG" 2>&1;;
    zypper) zypper -n update "$@" >> "$LOG" 2>&1;;
    apk) apk upgrade "$@" >> "$LOG" 2>&1;;
  esac
}
refresh_repos() {
  [ "$IS_ROOT" -eq 1 ] || return
  log "refresh package lists"
  case "$PM" in
    apt) apt-get update -qq >> "$LOG" 2>&1;;
    dnf|yum) $PM -q makecache >> "$LOG" 2>&1;;
    zypper) zypper -q refresh >> "$LOG" 2>&1;;
    apk) apk update -q >> "$LOG" 2>&1;;
  esac
}

# rows: TYPE|SOFTWARE|INSTALLED|REQUIRED|STATUS|ACTION|FIX|ARG
ROWS=()
row() { ROWS+=("$1|$2|$3|$4|$5|$6|${7:-}|${8:-}"); }
# Package-managed item below the fix: repo has newer build -> UPDATE, else NO FIX YET (not in repo yet / backported)
pkg_row() { # type software installed required pkg action fix arg
  if [ -n "$5" ] && pkg_has_update "$5"; then row "$1" "$2" "$3" "$4" UPDATE "$6" "$7" "$8"
  else row "$1" "$2" "$3" "$4" "NO FIX YET" "Newest $5 package already installed. Fix not in the repo yet, or backported by the distro (check its security tracker). Re-run later."; fi
}

# ---------------- Temurin (Eclipse Adoptium) ----------------
adopt_arch() { case "$ARCH" in x86_64) echo x64;; aarch64|arm64) echo aarch64;; *) echo x64;; esac; }
# prints: version name link sha256   of the newest Temurin JDK tarball for a major version
temurin_info() {
  local j; j=$(curl -fsSL --max-time 30 "https://api.adoptium.net/v3/assets/latest/$1/hotspot?image_type=jdk&os=linux&architecture=$(adopt_arch)" 2>/dev/null \
    || wget -qO- --timeout=30 "https://api.adoptium.net/v3/assets/latest/$1/hotspot?image_type=jdk&os=linux&architecture=$(adopt_arch)" 2>/dev/null)
  local v n l s
  v=$(echo "$j" | grep -oE '"openjdk_version"[[:space:]]*:[[:space:]]*"[^"]+"' | head -n1 | sed -E 's/.*"([^"]+)"$/\1/')
  n=$(echo "$j" | grep -oE '"name"[[:space:]]*:[[:space:]]*"OpenJDK[^"]+\.tar\.gz"' | head -n1 | sed -E 's/.*"([^"]+)"$/\1/')
  l=$(echo "$j" | grep -oE '"link"[[:space:]]*:[[:space:]]*"[^"]+\.tar\.gz"' | head -n1 | sed -E 's/.*"([^"]+)"$/\1/')
  s=$(echo "$j" | grep -oE '"checksum"[[:space:]]*:[[:space:]]*"[0-9a-f]{64}"' | head -n1 | sed -E 's/.*"([^"]+)"$/\1/')
  [ -n "$v" ] && echo "$v $n $l $s"
}
java_tar_row() { # javabin installed required major
  local home; home=$(dirname "$(dirname "$1")")
  local vendor; vendor=$("$1" -XshowSettings:properties -version 2>&1 | grep -m1 'java.vendor =' | sed 's/.*= //')
  if echo "$vendor" | grep -qi adoptium; then
    local info lt; info=$(temurin_info "$4"); lt=$(norm "$(echo "$info" | awk '{print $1}')")
    if [ -z "$lt" ]; then row Runtime "Java [$home]" "$2" "$3" CHECK "Could not reach adoptium.net. Re-run later."
    elif ! ver_ge "$lt" "$3" && ver_ge "$2" "$lt"; then row Runtime "Java [$home]" "$2" "$3" "NO FIX YET" "Already on Temurin's newest build ($lt); $3 not released yet. Re-run later."
    elif ver_ge "$lt" "$3"; then row Runtime "Java [$home]" "$2" "$3" UPDATE "Replace with Temurin $lt (same path, backup made)" temurin "$home|$4"
    else row Runtime "Java [$home]" "$2" "$3" UPDATE "Replace with Temurin $lt now; $3 not released yet" temurin "$home|$4"; fi
  else row Runtime "Java [$home]" "$2" "$3" MANUAL "Tarball JDK from ${vendor:-an unknown vendor}. Install Java $3 from that vendor."; fi
}

scan() {
  ROWS=()

  # Browsers
  local v
  if command -v google-chrome >/dev/null 2>&1 || command -v google-chrome-stable >/dev/null 2>&1; then
    v=$(norm "$(google-chrome --version 2>/dev/null || google-chrome-stable --version 2>/dev/null)")
    if ver_ge "$v" $MIN_CHROME; then row Browser "Google Chrome" "$v" $MIN_CHROME OK "-"
    else pkg_row Browser "Google Chrome" "$v" $MIN_CHROME google-chrome-stable "Upgrade google-chrome-stable" pkg google-chrome-stable; fi
  else row Browser "Google Chrome" "-" $MIN_CHROME "-" "-"; fi

  if command -v microsoft-edge >/dev/null 2>&1 || command -v microsoft-edge-stable >/dev/null 2>&1; then
    v=$(norm "$(microsoft-edge --version 2>/dev/null || microsoft-edge-stable --version 2>/dev/null)")
    local req=$MIN_EDGE; case "$v" in 152.*) req=$MIN_EDGE_EXT;; esac
    if ver_ge "$v" "$req"; then row Browser "Microsoft Edge" "$v" "$req" OK "-"
    else pkg_row Browser "Microsoft Edge" "$v" "$req" microsoft-edge-stable "Upgrade microsoft-edge-stable" pkg microsoft-edge-stable; fi
  else row Browser "Microsoft Edge" "-" $MIN_EDGE "-" "-"; fi

  if command -v firefox >/dev/null 2>&1 || command -v firefox-esr >/dev/null 2>&1; then
    v=$(norm "$(firefox --version 2>/dev/null || firefox-esr --version 2>/dev/null)")
    local fpkg=firefox; pkg_installed firefox-esr && fpkg=firefox-esr
    local req=$MIN_FF; case "$v" in 153.*) req=$MIN_FF_ESR153;; 115.*) req=$MIN_FF_ESR115;; esac
    local fix=pkg; command -v snap >/dev/null 2>&1 && snap list firefox >/dev/null 2>&1 && fix=snap
    if ver_ge "$v" "$req"; then row Browser "Mozilla Firefox" "$v" "$req" OK "-"
    elif [ "$fix" = snap ]; then row Browser "Mozilla Firefox (snap)" "$v" "$req" UPDATE "snap refresh firefox" snap firefox
    else pkg_row Browser "Mozilla Firefox" "$v" "$req" $fpkg "Upgrade $fpkg" pkg "$fpkg"; fi
  else row Browser "Mozilla Firefox" "-" $MIN_FF "-" "-"; fi

  # Java (every JVM)
  local javas=() j
  for j in $(command -v -a java 2>/dev/null) /usr/lib/jvm/*/bin/java /usr/java/*/bin/java /opt/*/bin/java /opt/java/*/bin/java; do
    [ -x "$j" ] && javas+=("$(readlink -f "$j")")
  done
  if [ ${#javas[@]} -eq 0 ]; then row Runtime "Java (JDK / JRE)" "-" "21.0.13 / 17.0.21 / 11.0.33 / 8u511" "-" "-"; fi
  for j in $(printf '%s\n' "${javas[@]}" | sort -u); do
    case "$j" in */jre/bin/java) [ -x "${j%/jre/bin/java}/bin/java" ] && continue;; esac
    local raw; raw=$("$j" -version 2>&1 | head -n1 | sed -E 's/.*"([^"]+)".*/\1/')
    local jp; jp=$(pkg_of "$j")
    case "$raw" in
      1.8.0_*)
        local u=${raw#1.8.0_}; u=${u%%[^0-9]*}
        if [ "${u:-0}" -ge 511 ]; then row Runtime "Java [$j]" "8u$u" 8u511 OK "-"
        elif [ -n "$jp" ]; then pkg_row Runtime "Java [$j]" "8u$u" 8u511 "$jp" "Upgrade $jp" pkg "$jp"
        else row Runtime "Java [$j]" "8u$u" 8u511 MANUAL "Tarball Java 8. Install Java 8u511 from the vendor."; fi;;
      *)
        local jv; jv=$(norm "$raw"); local maj=${jv%%.*}; local req; req=$(java_min "$maj")
        if [ -z "$req" ]; then row Runtime "Java [$j]" "$jv" "Supported LTS" MANUAL "Non-LTS or end-of-life Java: move to a supported LTS (major version change)"
        elif ver_ge "$jv" "$req"; then row Runtime "Java [$j]" "$jv" "$req" OK "-"
        elif [ -n "$jp" ]; then pkg_row Runtime "Java [$j]" "$jv" "$req" "$jp" "Upgrade $jp" pkg "$jp"
        else java_tar_row "$j" "$jv" "$req" "$maj"; fi;;
    esac
  done

  # Node.js
  if command -v node >/dev/null 2>&1; then
    local nb; nb=$(readlink -f "$(command -v node)"); v=$(norm "$(node -v)"); local maj=${v%%.*}; local req; req=$(node_min "$maj")
    local np; np=$(pkg_of "$nb")
    if [ -n "$req" ] && ver_ge "$v" "$req"; then row Runtime "Node.js [$nb]" "$v" "$req" OK "-"
    elif [ -z "$req" ]; then row Runtime "Node.js [$nb]" "$v" "22.23.4 / 24.22.1 / 26.12.1" MANUAL "End-of-life Node.js: move to 22, 24 or 26 (major version change)."
    elif echo "$nb" | grep -q '/\.nvm/'; then row Runtime "Node.js (nvm) [$nb]" "$v" "$req" UPDATE "nvm install $req (as $(owner "$nb"))" nvm "$(owner "$nb")|$req"
    elif [ -n "$np" ]; then pkg_row Runtime "Node.js [$nb]" "$v" "$req" "$np" "Upgrade $np" pkg "$np"
    elif [ "$nb" = /usr/local/bin/node ]; then row Runtime "Node.js [$nb]" "$v" "$req" UPDATE "Install official Node.js $req tarball into /usr/local" nodetar "$req"
    else row Runtime "Node.js [$nb]" "$v" "$req" MANUAL "Custom install location. Install Node.js $req there."; fi
  else row Runtime "Node.js" "-" "22.23.4 / 24.22.1 / 26.12.1" "-" "-"; fi

  # PHP (every php binary)
  local phps=() b
  for b in $(command -v -a php 2>/dev/null) /usr/bin/php[0-9]* /usr/bin/php[0-9].[0-9] /opt/remi/*/root/usr/bin/php /usr/local/bin/php /usr/local/lsws/lsphp*/bin/php; do
    [ -x "$b" ] && phps+=("$(readlink -f "$b")")
  done
  if [ ${#phps[@]} -eq 0 ]; then row Language "PHP" "-" "8.5.12 / 8.4.27 / 8.3.36 / 8.2.35" "-" "-"; fi
  for b in $(printf '%s\n' "${phps[@]}" | sort -u); do
    v=$("$b" -r 'echo PHP_VERSION;' 2>/dev/null); v=$(norm "$v"); [ -z "$v" ] && continue
    local req; req=$(php_min "$(branch "$v")"); local pp; pp=$(pkg_of "$b")
    if [ -z "$req" ]; then row Language "PHP [$b]" "$v" "8.2.35+" MANUAL "End-of-life PHP: no fix on this branch. Moving to 8.2+ is a major upgrade."
    elif ver_ge "$v" "$req"; then row Language "PHP [$b]" "$v" "$req" OK "-"
    elif [ -n "$pp" ]; then pkg_row Language "PHP [$b]" "$v" "$req" "$pp" "Upgrade all PHP packages + restart PHP-FPM / web server" php "$pp"
    else row Language "PHP [$b]" "$v" "$req" MANUAL "Compiled from source. Rebuild PHP $req from php.net with the same configure options."; fi
  done

  # Apache Tomcat
  local found=0 rn
  for rn in /opt/*tomcat*/RELEASE-NOTES /opt/tomcat/*/RELEASE-NOTES /usr/share/tomcat*/RELEASE-NOTES /usr/local/*tomcat*/RELEASE-NOTES /var/lib/tomcat*/RELEASE-NOTES /srv/*tomcat*/RELEASE-NOTES; do
    [ -f "$rn" ] || continue; found=1
    local td; td=$(dirname "$(readlink -f "$rn")")
    v=$(grep -oE 'Apache Tomcat Version [0-9.]+' "$rn" | head -n1 | awk '{print $4}'); local req; req=$(tomcat_min "$(branch "$v")")
    local tp; tp=$(pkg_of "$rn")
    if [ -z "$req" ]; then row Server "Tomcat [$td]" "$v" "9.0.123+" MANUAL "End-of-life Tomcat: no fix on this branch. Moving to 9.0+ is a major upgrade."
    elif ver_ge "$v" "$req"; then row Server "Tomcat [$td]" "$v" "$req" OK "-"
    elif [ -n "$tp" ]; then pkg_row Server "Tomcat [$td]" "$v" "$req" "$tp" "Upgrade $tp" pkg "$tp"
    else row Server "Tomcat [$td]" "$v" "$req" UPDATE "Update Tomcat to $req (conf/ webapps/ kept, backup made)" tomcat "$td|$req"; fi
  done
  [ $found -eq 0 ] && row Server "Apache Tomcat" "-" "11.0.27 / 10.1.61 / 9.0.123" "-" "-"

  # GitLab (self-managed)
  if [ -f /opt/gitlab/version-manifest.txt ]; then
    local gp; gp=$(head -n1 /opt/gitlab/version-manifest.txt | awk '{print $1}')
    v=$(head -n1 /opt/gitlab/version-manifest.txt | awk '{print $2}'); local req; req=$(gitlab_min "$(branch "$v")")
    if [ -z "$req" ]; then row Server "GitLab ($gp)" "$v" "18.11.13+" MANUAL "No fix on this line. Follow GitLab's upgrade path to a supported release."
    elif ver_ge "$v" "$req"; then row Server "GitLab ($gp)" "$v" "$req" OK "-"
    else row Server "GitLab ($gp)" "$v" "$req" UPDATE "Install $gp $req (same minor line)" gitlab "$gp:$req"; fi
  else row Server "GitLab (self-managed)" "-" "19.5.1 / 19.4.3 / ... / 18.11.13" "-" "-"; fi

  # Python: LiteLLM and Pillow
  local pys=() py
  for py in $(command -v -a python3 python 2>/dev/null); do pys+=("$(readlink -f "$py")"); done
  if [ ${#pys[@]} -eq 0 ]; then
    row "Supply chain" "Python: litellm" "-" "not $BAD_LITELLM" "-" "-"; row Library "Python: Pillow" "-" $MIN_PILLOW "-" "-"
  fi
  for py in $(printf '%s\n' "${pys[@]}" | sort -u); do
    local list lv pv
    list=$("$py" -m pip list --format=freeze 2>/dev/null)
    lv=$(echo "$list" | grep -i '^litellm==' | cut -d= -f3)
    pv=$(echo "$list" | grep -i '^pillow==' | cut -d= -f3)
    if [ "$lv" = "$BAD_LITELLM" ]; then row "Supply chain" "Python: litellm [$py]" "$lv" "not $BAD_LITELLM ($GOOD_LITELLM)" COMPROMISED "Security incident: disconnect, report, rebuild the machine, rotate all secrets. Not auto-fixed: running Python here re-runs the malware."
    elif [ -n "$lv" ]; then row "Supply chain" "Python: litellm [$py]" "$lv" "not $BAD_LITELLM" OK "-"
    else row "Supply chain" "Python: litellm [$py]" "-" "not $BAD_LITELLM" "-" "-"; fi
    if [ -z "$pv" ]; then row Library "Python: Pillow [$py]" "-" $MIN_PILLOW "-" "-"
    elif [ "$lv" = "$BAD_LITELLM" ]; then row Library "Python: Pillow [$py]" "$pv" $MIN_PILLOW COMPROMISED "Skipped: this Python is compromised"
    elif ver_ge "$pv" $MIN_PILLOW; then row Library "Python: Pillow [$py]" "$pv" $MIN_PILLOW OK "-"
    else
      local pk=""; for c in python3-pil python3-pillow python3-Pillow; do pkg_installed "$c" && pk="$c"; done
      if [ -n "$pk" ]; then pkg_row Library "Python: Pillow [$py]" "$pv" $MIN_PILLOW "$pk" "Upgrade $pk" pkg "$pk"
      else row Library "Python: Pillow [$py]" "$pv" $MIN_PILLOW UPDATE "pip install --upgrade pillow>=$MIN_PILLOW" pillow "$py"; fi
    fi
  done

  # OVHcloud CLI
  if command -v ovhcloud >/dev/null 2>&1; then
    local ob ov; ob=$(readlink -f "$(command -v ovhcloud)"); ov=$(norm "$(ovhcloud version 2>/dev/null)")
    if [ -n "$ov" ] && ver_ge "$ov" $MIN_OVH; then row "Supply chain" "OVHcloud CLI [$ob]" "$ov" $MIN_OVH OK "-"
    else row "Supply chain" "OVHcloud CLI [$ob]" "${ov:-unknown}" $MIN_OVH UPDATE "Replace with verified $MIN_OVH" ovh "$ob"; fi
  else row "Supply chain" "OVHcloud CLI" "-" $MIN_OVH "-" "-"; fi

  # eMudhra certificates in the system CA store
  local cnt; cnt=$(grep -il 'EM \(DV\|OV\|EV\) TLS CA - G3\|EM OV CS CA - G3' /etc/ssl/certs/* /etc/pki/ca-trust/extracted/pem/* 2>/dev/null | wc -l)
  if [ "$cnt" -gt 0 ]; then row Certificate "eMudhra compromised intermediates" "$cnt found" none UPDATE "Remove them and refresh the CA store" ca ca-certificates
  elif pkg_installed ca-certificates && pkg_has_update ca-certificates; then row Certificate "ca-certificates" "update available" "latest" UPDATE "Upgrade ca-certificates" ca ca-certificates
  else row Certificate "eMudhra compromised intermediates" none none OK "-"; fi

  # Docker images
  if command -v docker >/dev/null 2>&1; then
    if docker info >/dev/null 2>&1; then
      local any=0 img created
      while read -r img; do
        case "$img" in
          *'<none>'*) ;;
          *litellm*:v1.107.0|*litellm*:1.107.0|*litellm*:latest|*litellm*:main-latest|*litellm*:main-stable)
            row "Supply chain" "Docker: $img" "$img" "litellm v$GOOD_LITELLM" COMPROMISED "Remove image, pull v$GOOD_LITELLM, rotate secrets of containers that ran it" litellmimg "$img"; any=1;;
          php:*|*/php:*|node:*|*/node:*|tomcat:*|*/tomcat:*|python:*|*/python:*|eclipse-temurin:*|*/eclipse-temurin:*|openjdk:*)
            any=1; created=$(docker image inspect -f '{{.Created}}' "$img" 2>/dev/null | cut -c1-10)
            if [[ "$created" > "2026-10-20" ]]; then row Container "Docker: $img" "$created" "pulled after 21 Oct 2026" OK "-"
            else row Container "Docker: $img" "${created:--}" "pulled after 21 Oct 2026" UPDATE "docker pull (then rebuild app images built FROM it)" dockerpull "$img"; fi;;
        esac
      done < <(docker images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null)
      [ $any -eq 0 ] && row Container "Docker images" "no affected images" "-" OK "-"
    else row Container "Docker images" "Docker not running / no access" "pulled after 21 Oct 2026" CHECK "Run with sudo or start Docker"; fi
  else row Container "Docker images" "-" "pulled after 21 Oct 2026" "-" "-"; fi

  # Next.js
  if [ -n "$PROJECTS" ] && [ -d "$PROJECTS" ]; then
    local nf=0 f
    while read -r f; do
      nf=1; v=$(grep -m1 '"version"' "$f" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+'); local req=16.4.1; case "$v" in 15.*) req=15.5.28;; esac
      local proj; proj=$(dirname "$(dirname "$(dirname "$f")")")
      if ver_ge "$v" "$req"; then row Library "Next.js [$proj]" "$v" "$req" OK "-"; else row Library "Next.js [$proj]" "$v" "$req" UPDATE "npm install next@$req" nextjs "$proj|$req"; fi
    done < <(find "$PROJECTS" -path '*/node_modules/next/package.json' -not -path '*/node_modules/*/node_modules/*' 2>/dev/null)
    [ $nf -eq 0 ] && row Library "Next.js" "-" "16.4.1 / 15.5.28" "-" "-"
  else row Library "Next.js" "-" "16.4.1 / 15.5.28" "-" "Use --projects to check"; fi
}

show() {
  echo; printf '\033[36m%s\033[0m\n' "$1"
  printf '%-3s %-17s %-46s %-18s %-34s %-11s %s\n' "#" TYPE SOFTWARE INSTALLED REQUIRED STATUS ACTION
  printf '%-3s %-17s %-46s %-18s %-34s %-11s %s\n' "--" ---- -------- --------- -------- ------ ------
  local i=0 r c
  for r in "${ROWS[@]}"; do
    i=$((i+1)); IFS='|' read -r t s inst req st act fix arg <<< "$r"
    case "$st" in OK) c=32;; UPDATE) c=31;; COMPROMISED) c=35;; MANUAL|CHECK) c=33;; "NO FIX YET") c=36;; *) c=37;; esac
    [ ${#s} -gt 46 ] && s="${s:0:43}..."
    printf "\033[${c}m%-3s %-17s %-46s %-18s %-34s %-11s %s\033[0m\n" "$i" "$t" "$s" "$inst" "$req" "$st" "$act"
  done
}

save_csv() {
  [ -f "$CSV" ] || echo '"Computer","Phase","Type","Software","Installed","Required","Status","Action"' > "$CSV"
  local r
  for r in "${ROWS[@]}"; do
    IFS='|' read -r t s inst req st act fix arg <<< "$r"
    printf '"%s","%s","%s","%s","%s","%s","%s","%s"\n' "$HOST" "$1" "$t" "$s" "$inst" "$req" "$st" "$act" >> "$CSV"
  done
}

restart_web() {
  local svc
  for svc in $(systemctl list-units --type=service --state=running --no-legend 2>/dev/null | awk '{print $1}' | grep -E '^php.*fpm|^lsws|^lshttpd'); do
    log "restart $svc"; systemctl restart "$svc" >> "$LOG" 2>&1
  done
  for svc in apache2 httpd nginx; do
    systemctl is-active --quiet "$svc" 2>/dev/null && { log "reload $svc"; systemctl reload "$svc" >> "$LOG" 2>&1 || systemctl restart "$svc" >> "$LOG" 2>&1; }
  done
}

# ---------------- Updaters for non-package installs ----------------
update_tomcat() { # dir target
  local dir="$1" target="$2" major="${2%%.*}" name="apache-tomcat-$2.tar.gz" tgz bak new unit="" own
  tgz=$(get_patch "$name" "https://archive.apache.org/dist/tomcat/tomcat-$major/v$target/bin/$name") || { echo "FAILED: could not download a verified $name"; return; }
  new="$DL/tomcat-$target"; mkdir -p "$new"; tar -xzf "$tgz" -C "$new" || { echo "FAILED: could not extract. Nothing changed."; return; }
  new="$new/apache-tomcat-$target"; [ -f "$new/lib/catalina.jar" ] || { echo "FAILED: package layout not recognised. Nothing changed."; return; }
  bak="$dir.bak-$STAMP"; mkdir -p "$bak"
  cp -a "$dir/bin" "$dir/lib" "$bak/" && cp -a "$dir"/RELEASE-NOTES "$dir"/RUNNING.txt "$dir"/LICENSE "$dir"/NOTICE "$bak/" 2>/dev/null || { echo "FAILED: could not back up. Nothing changed."; return; }
  own=$(stat -c '%U:%G' "$dir/lib")
  # stop: systemd unit that points at this Tomcat, else its own shutdown script
  unit=$(grep -lsE "$dir|CATALINA_(HOME|BASE)=$dir" /etc/systemd/system/*.service /lib/systemd/system/*.service /usr/lib/systemd/system/*.service 2>/dev/null | head -n1 | xargs -r basename)
  local running=0; pgrep -f "catalina.home=$dir" >/dev/null && running=1
  if [ -n "$unit" ]; then log "stop $unit"; systemctl stop "$unit" >> "$LOG" 2>&1
  elif [ $running -eq 1 ]; then log "shutdown.sh $dir"; sudo -u "$(stat -c %U "$dir")" "$dir/bin/shutdown.sh" >> "$LOG" 2>&1; sleep 5; pkill -f "catalina.home=$dir"; fi
  sleep 2
  for e in "$dir"/lib/ecj-*.jar; do [ -f "$e" ] && [ ! -f "$new/lib/$(basename "$e")" ] && rm -f "$e"; done
  if cp -a "$new/bin/." "$dir/bin/" && cp -a "$new/lib/." "$dir/lib/" && cp -a "$new"/RELEASE-NOTES "$new"/RUNNING.txt "$new"/LICENSE "$new"/NOTICE "$dir/"; then
    chown -R "$own" "$dir/bin" "$dir/lib" 2>/dev/null
  fi
  local nv; nv=$(grep -oE 'Apache Tomcat Version [0-9.]+' "$dir/RELEASE-NOTES" | head -n1 | awk '{print $4}')
  if [ "$nv" != "$target" ]; then
    rm -rf "$dir/bin" "$dir/lib"; cp -a "$bak/bin" "$bak/lib" "$dir/"; cp -a "$bak"/RELEASE-NOTES "$dir/" 2>/dev/null
    [ -n "$unit" ] && systemctl start "$unit" >> "$LOG" 2>&1
    echo "FAILED: old Tomcat restored. Backup: $bak"; return
  fi
  if [ -n "$unit" ]; then systemctl start "$unit" >> "$LOG" 2>&1
  elif [ $running -eq 1 ]; then sudo -u "$(stat -c %U "$dir")" "$dir/bin/startup.sh" >> "$LOG" 2>&1; fi
  echo "Tomcat $target installed (conf and webapps kept). Backup: $bak"
}

update_temurin() { # home major
  local home="$1" info ver name link sum tgz tmp
  info=$(temurin_info "$2"); read -r ver name link sum <<< "$info"
  [ -n "$name" ] || { echo "FAILED: could not reach adoptium.net"; return; }
  tgz=$(get_patch "$name" "$link" "$sum") || { echo "FAILED: could not download a verified $name"; return; }
  tmp="$DL/jdk-$2"; mkdir -p "$tmp"; tar -xzf "$tgz" -C "$tmp" || { echo "FAILED: could not extract. Nothing changed."; return; }
  local newhome; newhome=$(find "$tmp" -mindepth 1 -maxdepth 1 -type d | head -n1)
  [ -x "$newhome/bin/java" ] || { echo "FAILED: package layout not recognised. Nothing changed."; return; }
  chown -R "$(stat -c '%U:%G' "$home")" "$newhome" 2>/dev/null
  mv "$home" "$home.bak-$STAMP" && mv "$newhome" "$home" || { [ -d "$home.bak-$STAMP" ] && [ ! -d "$home" ] && mv "$home.bak-$STAMP" "$home"; echo "FAILED: could not swap folders; old JDK kept."; return; }
  echo "Temurin $ver installed at $home (same path). Restart Java apps. Backup: $home.bak-$STAMP"
}

update_nodetar() { # version
  local v="$1" a name sums tgz exp
  case "$ARCH" in x86_64) a=x64;; aarch64|arm64) a=arm64;; *) echo "FAILED: no Node.js build for $ARCH"; return;; esac
  name="node-v$v-linux-$a.tar.xz"; sums="$DL/node-SHASUMS256.txt"
  fetch "https://nodejs.org/dist/v$v/SHASUMS256.txt" "$sums" || { echo "FAILED: could not reach nodejs.org"; return; }
  exp=$(awk -v n="$name" '$2==n {print $1}' "$sums")
  tgz=$(get_patch "$name" "https://nodejs.org/dist/v$v/$name" "$exp") || { echo "FAILED: could not download a verified $name"; return; }
  tar -xJf "$tgz" -C /usr/local --strip-components=1 --exclude='*/CHANGELOG.md' --exclude='*/LICENSE' --exclude='*/README.md' >> "$LOG" 2>&1 \
    && echo "Node.js $v installed in /usr/local. Restart Node services." || echo "FAILED: could not extract into /usr/local"
}

update_ovh() { # binary path
  local bin="$1" a name tgz tmp nb
  case "$ARCH" in x86_64) a=x86_64;; aarch64|arm64) a=arm64;; *) echo "FAILED: no OVHcloud CLI build for $ARCH"; return;; esac
  name="ovhcloud-cli_Linux_$a.tar.gz"
  tgz=$(get_patch "$name" "https://github.com/ovh/ovhcloud-cli/releases/download/v$MIN_OVH/$name") || { echo "FAILED: could not download a verified $name"; return; }
  tmp="$DL/ovh"; mkdir -p "$tmp"; tar -xzf "$tgz" -C "$tmp"
  nb=$(find "$tmp" -type f -name ovhcloud | head -n1); [ -n "$nb" ] || { echo "FAILED: ovhcloud binary not in package"; return; }
  cp -a "$bin" "$bin.bak-$STAMP" && install -m 755 "$nb" "$bin" && echo "OVHcloud CLI $MIN_OVH installed. Backup: $bin.bak-$STAMP" || echo "FAILED: could not replace $bin"
}

fix_row() { # fix arg
  case "$1" in
    pkg) pkg_upgrade "$2" && echo "Upgraded $2." || echo "FAILED: see log";;
    snap) snap refresh "$2" >> "$LOG" 2>&1 && echo "Refreshed snap $2. Relaunch it." || echo "FAILED: see log";;
    php)
      local all=""
      case "$PM" in
        apt) all=$(dpkg-query -W -f='${Package} ${Status}\n' 'php*' 'libapache2-mod-php*' 2>/dev/null | awk '/install ok installed/{print $1}' | tr '\n' ' ');;
        dnf|yum|zypper) all=$(rpm -qa --qf '%{NAME}\n' 'php*' | tr '\n' ' ');;
        apk) all=$(apk info 2>/dev/null | grep '^php' | tr '\n' ' ');;
      esac
      pkg_upgrade $all && { restart_web; echo "PHP packages upgraded; PHP-FPM restarted and web server reloaded."; } || echo "FAILED: see log";;
    gitlab)
      local gp=${2%%:*} gv=${2##*:}
      log "gitlab $gp $gv"
      case "$PM" in
        apt) local full; full=$(apt-cache madison "$gp" 2>/dev/null | awk '{print $3}' | grep "^$gv-" | head -n1)
             [ -n "$full" ] && DEBIAN_FRONTEND=noninteractive apt-get install -y "$gp=$full" >> "$LOG" 2>&1 && { echo "GitLab $gv installed."; return; };;
        dnf|yum) $PM -y install "$gp-$gv" >> "$LOG" 2>&1 && { echo "GitLab $gv installed."; return; };;
      esac
      echo "FAILED: GitLab $gv not found in the repo. See docs.gitlab.com/update.";;
    pillow)
      if "$2" -m pip install --upgrade "pillow>=$MIN_PILLOW" >> "$LOG" 2>&1; then echo "Pillow upgraded."
      elif grep -q externally-managed "$LOG" && "$2" -m pip install --upgrade --break-system-packages "pillow>=$MIN_PILLOW" >> "$LOG" 2>&1; then echo "Pillow upgraded (pip-managed copy, same way it was installed)."
      else echo "FAILED: pip could not upgrade Pillow (old Python?). See log."; fi;;
    ca)
      pkg_upgrade "$2"
      local f moved=0 keep="/root/emudhra-removed-$STAMP"
      for f in /usr/local/share/ca-certificates/* /usr/local/share/ca-certificates/*/* /etc/pki/ca-trust/source/anchors/* /etc/ca-certificates/trust-source/anchors/*; do
        [ -f "$f" ] && grep -qi 'EM \(DV\|OV\|EV\) TLS CA - G3\|EM OV CS CA - G3' "$f" 2>/dev/null && { mkdir -p "$keep"; mv "$f" "$keep/"; moved=$((moved+1)); }
        [ -f "$f" ] && command -v openssl >/dev/null 2>&1 && openssl x509 -in "$f" -noout -subject 2>/dev/null | grep -qE 'EM (DV|OV|EV) TLS CA - G3|EM OV CS CA - G3' && { mkdir -p "$keep"; mv "$f" "$keep/"; moved=$((moved+1)); }
      done
      command -v update-ca-certificates >/dev/null 2>&1 && update-ca-certificates --fresh >> "$LOG" 2>&1
      command -v update-ca-trust >/dev/null 2>&1 && update-ca-trust extract >> "$LOG" 2>&1
      echo "CA store refreshed; $moved locally added eMudhra file(s) moved to $keep.";;
    tomcat) update_tomcat "${2%%|*}" "${2##*|}";;
    temurin) update_temurin "${2%%|*}" "${2##*|}";;
    nodetar) update_nodetar "$2";;
    nvm)
      local u=${2%%|*} ver=${2##*|}
      sudo -u "$u" -H bash -c "export NVM_DIR=\"\$HOME/.nvm\"; . \"\$NVM_DIR/nvm.sh\" && nvm install $ver && nvm alias default $ver" >> "$LOG" 2>&1 \
        && echo "Node.js $ver installed with nvm for $u and set as default." || echo "FAILED: nvm install failed. See log.";;
    ovh) update_ovh "$2";;
    dockerpull) docker pull "$2" >> "$LOG" 2>&1 && echo "Pulled the patched image. Rebuild app images that use it." || echo "FAILED: docker pull failed. See log.";;
    litellmimg)
      local repo=${2%:*}
      docker rmi -f "$2" >> "$LOG" 2>&1; docker pull "$repo:v$GOOD_LITELLM" >> "$LOG" 2>&1
      echo "Removed $2 and pulled $repo:v$GOOD_LITELLM. Rotate secrets used by containers that ran it.";;
    nextjs)
      local proj=${2%%|*} ver=${2##*|}
      ( cd "$proj" && sudo -u "$(owner "$proj")" -H npm install "next@$ver" >> "$LOG" 2>&1 ) \
        && echo "Next.js $ver installed in $proj. Rebuild and redeploy the app." || echo "FAILED: npm install failed. See log.";;
  esac
}

# ---------------- Main ----------------
echo "Endpoint-Patch | $HOST | $OSNAME | package manager: ${PM:-none} | root: $IS_ROOT"
log "start on $HOST $OSNAME"
refresh_repos
scan
show "CURRENT STATUS"
save_csv before

TODO=(); MAN=0; WAIT=0
for idx in "${!ROWS[@]}"; do
  IFS='|' read -r t s inst req st act fix arg <<< "${ROWS[$idx]}"
  if { [ "$st" = UPDATE ] || [ "$st" = COMPROMISED ]; } && [ -n "$fix" ]; then TODO+=("$idx")
  else case "$st" in MANUAL|COMPROMISED|CHECK) MAN=$((MAN+1));; "NO FIX YET") WAIT=$((WAIT+1));; esac; fi
done
echo; echo "Can update automatically: ${#TODO[@]}   Need manual action: $MAN   Fix not released yet: $WAIT"
[ $WAIT -gt 0 ] && echo "NO FIX YET = the newest available build is already installed. Re-run in a few days, or confirm a distro backport in its security tracker."

if [ $SCAN_ONLY -eq 1 ] || [ ${#TODO[@]} -eq 0 ]; then echo "Report: $CSV"; log "end (no updates)"; rm -rf "$DL"; exit 0; fi
if [ $IS_ROOT -ne 1 ]; then echo "Run with sudo to install updates."; echo "Report: $CSV"; rm -rf "$DL"; exit 0; fi
if [ $YES -ne 1 ]; then
  read -r -p "Update these ${#TODO[@]} items now? Services such as PHP-FPM and Tomcat will restart. [y/N] " ans < /dev/tty
  case "$ans" in y|Y|yes|YES) ;; *) echo "No changes made."; echo "Report: $CSV"; rm -rf "$DL"; exit 0;; esac
fi

echo; printf '\033[36mUPDATING\033[0m\n'
for idx in "${TODO[@]}"; do
  IFS='|' read -r t s inst req st act fix arg <<< "${ROWS[$idx]}"
  printf -- '- %s ... ' "$s"
  res=$(fix_row "$fix" "$arg"); log "$s: $res"
  case "$res" in FAILED*) printf '\033[33m%s\033[0m\n' "$res";; *) printf '\033[32m%s\033[0m\n' "$res";; esac
done

scan
show "STATUS AFTER UPDATE"
save_csv after
rm -rf "$DL"
echo; echo "Browsers show the new version after they are reopened."
echo "Report: $CSV"; echo "Log:    $LOG"
log "end"
