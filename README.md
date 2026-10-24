# Endpoint-Patch — October 2026

Scans Windows and Linux endpoints for the software affected by the October 2026 vulnerabilities, shows installed vs. required versions, and installs the stable patch versions.

| Branch | Contents |
|---|---|
| [`windows`](../../tree/windows) | `Endpoint-Patch.ps1` for Windows 7 / 8.1 / 10 / 11 / Server |
| [`linux`](../../tree/linux) | `Endpoint-Patch.sh` for Ubuntu, Debian, RHEL, Rocky, Alma, CentOS, Fedora, Amazon Linux, SUSE, Alpine |
| `main` | This README and the report pages: `Endpoint-Patch-Checklist.html` (what to update, per version), `October-2026-Threat-Report.html` (full briefing), `Patch-Priority-Board.html` (P0–P3 priorities). Download and open them in a browser. |

Patch packages that the scripts install directly (PHP, Tomcat, OVHcloud CLI, Temurin Java for Linux) are in the release **[patches-2026-10](../../releases/tag/patches-2026-10)**, with `SHA256SUMS.txt`. Every file was verified against the publisher's own checksum before upload, and the scripts verify it again before installing.

## Run it — one command

**Windows 10 / 11 / Server 2019+** (open PowerShell as Administrator):

```powershell
curl.exe -fsSL -o $env:TEMP\Endpoint-Patch.ps1 https://raw.githubusercontent.com/Sriganth-C/Endpoint-Patch/windows/Endpoint-Patch.ps1; powershell -ExecutionPolicy Bypass -File $env:TEMP\Endpoint-Patch.ps1
```

**Windows 7 / 8.1** (no curl.exe; open Command Prompt as Administrator):

```bat
certutil -urlcache -split -f https://raw.githubusercontent.com/Sriganth-C/Endpoint-Patch/windows/Endpoint-Patch.ps1 %TEMP%\Endpoint-Patch.ps1 & powershell -ExecutionPolicy Bypass -File %TEMP%\Endpoint-Patch.ps1
```

`curl.exe` is used instead of `Start-BitsTransfer` because BITS refuses to download (error 0x800704DD) when the admin window runs as a different account than the one logged on.

**Linux:**

```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/Sriganth-C/Endpoint-Patch/linux/Endpoint-Patch.sh)"
```

The script shows the current status, asks **Update now? (Y/N)**, updates, then shows the status again. A CSV report and a log are saved in the folder you ran it from (Windows: `%TEMP%`).

### Options

| What | Windows | Linux |
|---|---|---|
| Report only, change nothing | add `-ScanOnly` | add `endpoint-patch --scan-only` after the closing `)"` |
| Update without asking (Intune / GPO / Ansible) | add `-Yes` | add `endpoint-patch --yes` |
| Skip the deep scan (faster, standard locations only) | add `-Quick` | add `endpoint-patch --quick` |

### Deep scan (default)

Every local drive / filesystem is searched once (about 3–5 minutes) for the checklist software, so the script also finds zip and tarball installs, portable copies, Python virtual environments, and copies **bundled inside other applications** (for example Burp Suite's browser, Playwright's Chromium, the Java inside IDEs and SonarQube, MySQL Shell's Python). Versions are read from the files themselves. Bundled copies are reported as `IN APP`: replacing files inside an application breaks it, so only updating that application fixes them.
| Also check Next.js in code folders | add `-ScanProjects "C:\code"` | add `endpoint-patch --projects /srv/code` |

## What it checks and how it updates

| Item | Windows update method | Linux update method |
|---|---|---|
| Chrome, Edge, Firefox | winget / the browser's updater / official installer | package manager or snap |
| Java (Temurin, Microsoft, Corretto, Zulu, Oracle) | winget or vendor MSI | package manager, or verified Temurin tarball swapped in place |
| Node.js | official MSI; nvm | package manager; nvm (as its owner); official tarball for `/usr/local` |
| PHP | verified zip from the release, same branch and TS/NTS, `php.ini` kept, web server stopped and restarted, backup + automatic rollback | all installed PHP packages, PHP-FPM restarted |
| Apache Tomcat | verified zip; `bin` and `lib` replaced, `conf` and `webapps` kept, service restarted, backup + rollback | package manager, or verified tarball the same way |
| GitLab | — (Linux only) | fixed release on the same minor line |
| Pillow | pip | package manager or pip |
| OVHcloud CLI | verified 0.16.0 binary, backup kept | same |
| eMudhra compromised certificates | deleted from the certificate stores | removed from local CA sources, CA store rebuilt |
| Docker base images | `docker pull` of images older than 21 Oct 2026 | same |
| LiteLLM 1.107.0 Docker images | image removed, `v1.106.2` pulled | same |
| Next.js (with the projects option) | `npm install next@<fixed>` | same, as the project owner |

## Statuses

| Status | Meaning |
|---|---|
| OK | Already on a safe version |
| UPDATE | Outdated; the script installs the fix |
| NO FIX YET | Already on the newest build the vendor has published; the fix is not out yet (or the distro backported it). Run again later. |
| COMPROMISED | Malicious LiteLLM 1.107.0. Docker images are cleaned automatically; a Python install is a security incident: disconnect the machine, rebuild it, rotate secrets |
| MANUAL | Needs a major-version change (end-of-life PHP, Tomcat, Java, Node.js) or a vendor the script does not know |
| NO PATCH | No installable fix exists for this platform (Windows 7/8 browsers and Node.js; Python 3.11/3.12 security releases have no Windows installer) |
| IN APP | Outdated copy bundled inside another application: update (or remove) that application |
| - | Not installed |

## Safety

- Same version branch only: PHP 8.2 stays on 8.2, Java 17 on 17, Tomcat 9.0 on 9.0. Major upgrades are never done automatically.
- Every replaced folder is backed up next to the original as `<folder>.bak-<date>` and restored automatically if the update fails.
- Downloads are refused unless their SHA-256 matches `SHA256SUMS.txt` (or the vendor's published checksum).
- Run `-ScanOnly` / `--scan-only` on one machine of each type before rolling out widely.
