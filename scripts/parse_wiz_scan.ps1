<#
.SYNOPSIS
  Unified Wiz scan enricher — Container + Per-Layer + SCA + IaC.
  Produces: colorized tabular CI logs, enriched SARIF files, GitHub Job Summary markdown.
#>
param(
  [string]$ImageSarifPath       = "image.sarif",
  [string]$ImageLayersPath      = "image-layers.json",
  [string]$DirSarifPath         = "dir.sarif",
  [string]$DockerfileSarifPath  = "dockerfile.sarif",
  [string]$SummaryMarkdownPath  = "wiz-summary.md",
  [string]$GitHubRunUrl         = "",
  [string]$AppSecContact        = "appsec@devsecopswithanshu.com"
)

Set-StrictMode -Off
$ErrorActionPreference = "Continue"
if ([string]::IsNullOrWhiteSpace($AppSecContact)) {
  $AppSecContact = "appsec@devsecopswithanshu.com"
}

$esc       = [char]27
$sevOrder  = @{ CRITICAL=0; HIGH=1; MEDIUM=2; LOW=3; INFORMATIONAL=4; INFO=4; UNKNOWN=5 }
$validSevs = @("CRITICAL","HIGH","MEDIUM","LOW","INFORMATIONAL")

# ── Helpers ──────────────────────────────────────────────────────────────────
function Get-Json([string]$Path) {
  if (-not (Test-Path -LiteralPath $Path)) { return $null }
  try { return (Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -Depth 100) }
  catch { Write-Host "[WARN] Cannot parse JSON: $Path ($($_.Exception.Message))"; return $null }
}

function Safe-Str($v, [string]$d = "") {
  if ($null -eq $v) { return $d }
  $s = [string]$v
  if ([string]::IsNullOrWhiteSpace($s)) { return $d }
  return $s.Trim()
}

function Safe-Int($v) {
  if ($null -eq $v) { return 0 }
  try { return [int]$v } catch { return 0 }
}

function Trunc([string]$s, [int]$max) {
  if (-not $s) { return "" }
  if ($s.Length -gt $max) { return $s.Substring(0, [Math]::Max(0,$max-1)) + [char]0x2026 }
  return $s
}

function Sev-Color([string]$s) {
  switch ($s.ToUpper()) {
    "CRITICAL" { return "1;37;41" }
    "HIGH"     { return "1;31" }
    "MEDIUM"   { return "1;33" }
    "LOW"      { return "1;32" }
    default    { return "0" }
  }
}

function Sev-Level([string]$s) {
  switch ($s.ToUpper()) {
    "CRITICAL" { return "error" }
    "HIGH"     { return "error" }
    "MEDIUM"   { return "warning" }
    default    { return "note" }
  }
}

# CVSS security-severity thresholds per spec
function Sec-Sev([string]$s) {
  switch ($s.ToUpper()) {
    "CRITICAL"      { return "9.5" }
    "HIGH"          { return "8.0" }
    "MEDIUM"        { return "5.5" }
    "LOW"           { return "3.0" }
    "INFORMATIONAL" { return "0.5" }
    default         { return "0.0" }
  }
}

# Parse "Key: value" pairs from Wiz SARIF message.text
function Parse-MsgText([string]$text) {
  $f = [ordered]@{}
  if (-not $text) { return $f }
  foreach ($line in ($text -split "`n")) {
    if ($line -match "^([A-Za-z /]+):\s*(.+)$") {
      $k = $Matches[1].Trim().ToLower()
      $v = $Matches[2].Trim()
      if (-not $f.Contains($k)) { $f[$k] = $v }
    }
  }
  $di = $text.IndexOf("Description:")
  if ($di -ge 0) { $f["description"] = $text.Substring($di + 12).Trim().Split("`n")[0] }
  return $f
}

# Resolve severity from a SARIF result using multi-source fallback
function Get-ResultSeverity([object]$result, [hashtable]$ruleMap) {
  $msgText = ""
  if ($result.message -and $result.message.text) { $msgText = [string]$result.message.text }
  $fields = Parse-MsgText -text $msgText

  # 1. message.text "Severity: X"
  $sev = Safe-Str $fields["severity"] ""
  if ($sev -and $sev.ToUpper() -in $validSevs) { return $sev.ToUpper() }

  # 2. result.properties.severity
  if ($result.properties -and $result.properties.severity) {
    $ps = ([string]$result.properties.severity).ToUpper()
    if ($ps -in $validSevs) { return $ps }
  }

  # 3. rule.properties.severity / security-severity
  $rid = ""; if ($result.ruleId) { $rid = [string]$result.ruleId }
  $rule = $null
  if ($rid -and $ruleMap.ContainsKey($rid)) { $rule = $ruleMap[$rid] }
  if ($rule -and $rule.properties) {
    if ($rule.properties.severity) {
      $rs = ([string]$rule.properties.severity).ToUpper()
      if ($rs -in $validSevs) { return $rs }
    }
    $ss = $rule.properties."security-severity"
    if ($ss) {
      $score = [double]0
      if ([double]::TryParse([string]$ss, [ref]$score)) {
        if     ($score -ge 9.0) { return "CRITICAL" }
        elseif ($score -ge 7.0) { return "HIGH" }
        elseif ($score -ge 4.0) { return "MEDIUM" }
        elseif ($score -gt 0)   { return "LOW" }
        else                    { return "INFORMATIONAL" }
      }
    }
  }

  # 4. SARIF level fallback
  $lvl = ""
  if ($result.level) { $lvl = [string]$result.level }
  elseif ($rule -and $rule.defaultConfiguration -and $rule.defaultConfiguration.level) {
    $lvl = [string]$rule.defaultConfiguration.level
  }
  switch ($lvl.ToLower()) {
    "error"   { return "HIGH" }
    "warning" { return "MEDIUM" }
    "note"    { return "LOW" }
    "none"    { return "INFORMATIONAL" }
  }
  return "UNKNOWN"
}

# Add security-severity to rules, rename to [Wiz Cloud], fix result levels
function Enrich-Sarif([object]$sarif) {
  if (-not $sarif) { return $sarif }

  $ruleMap = @{}
  foreach ($run in $sarif.runs) {
    $rules = $run.tool.driver.rules
    if ($rules) { foreach ($r in $rules) { if ($r.id) { $ruleMap[[string]$r.id] = $r } } }
  }

  # First pass: resolve severity per result, update levels
  $ruleSevMap = @{}
  foreach ($run in $sarif.runs) {
    foreach ($res in $run.results) {
      if (-not $res) { continue }
      $rid = ""; if ($res.ruleId) { $rid = [string]$res.ruleId }
      $sev = Get-ResultSeverity -result $res -ruleMap $ruleMap
      $res.level = Sev-Level -s $sev
      if ($rid -and -not $ruleSevMap.ContainsKey($rid)) { $ruleSevMap[$rid] = $sev }
    }
  }

  # Second pass: enrich rules
  foreach ($run in $sarif.runs) {
    $rules = $run.tool.driver.rules
    if (-not $rules) { continue }
    foreach ($r in $rules) {
      $rid = ""; if ($r.id) { $rid = [string]$r.id }
      if (-not $rid) { continue }
      $sev = if ($ruleSevMap.ContainsKey($rid)) { $ruleSevMap[$rid] } else { "UNKNOWN" }

      if (-not $r.properties) {
        $r | Add-Member -NotePropertyName properties -Value ([ordered]@{}) -Force
      }
      $r.properties."security-severity" = Sec-Sev -s $sev

      $tags = @(); if ($r.properties.tags) { $tags = @($r.properties.tags) }
      if ($tags -notcontains "security") { $tags += "security" }
      if ($tags -notcontains "wiz")      { $tags += "wiz" }
      $r.properties.tags = $tags

      # Rename: [Wiz] -> [Wiz Cloud], or prefix if not already tagged
      $currentName = Safe-Str $r.name $rid
      if ($currentName -match "^\[Wiz\]") {
        $r.name = $currentName -replace "^\[Wiz\]", "[Wiz Cloud]"
      } elseif ($currentName -notmatch "^\[Wiz") {
        $r.name = "[Wiz Cloud] $currentName"
      }
      if ($r.shortDescription -and $r.shortDescription.text) {
        $r.shortDescription.text = ([string]$r.shortDescription.text) -replace "^\[Wiz\]","[Wiz Cloud]"
      }
    }
  }
  return $sarif
}

# Extract display rows from a SARIF object for tabular output
function Get-SarifRows([object]$sarif) {
  $rows = [System.Collections.Generic.List[object]]::new()
  if (-not $sarif) { return $rows }

  $ruleMap = @{}
  foreach ($run in $sarif.runs) {
    $rules = $run.tool.driver.rules
    if ($rules) { foreach ($r in $rules) { if ($r.id) { $ruleMap[[string]$r.id] = $r } } }
  }

  foreach ($run in $sarif.runs) {
    foreach ($res in $run.results) {
      if (-not $res) { continue }
      $rid  = Safe-Str $res.ruleId "N/A"
      $sev  = Get-ResultSeverity -result $res -ruleMap $ruleMap
      $rule = if ($ruleMap.ContainsKey($rid)) { $ruleMap[$rid] } else { $null }

      $msgText = ""
      if ($res.message -and $res.message.text) { $msgText = [string]$res.message.text }
      $fields = Parse-MsgText -text $msgText

      $component = Safe-Str $fields["component"] ""
      if (-not $component -and $rule -and $rule.name) { $component = ([string]$rule.name) -replace "^\[Wiz[^\]]*\]\s*","" }
      if (-not $component) { $component = "N/A" }

      $version = Safe-Str $fields["version"] "N/A"
      $fixed   = Safe-Str $fields["fixed version"] "N/A"
      $cveRule = Safe-Str $fields["cve / rule"] $rid
      $rem     = Safe-Str $fields["remediation"] ""
      $desc    = Safe-Str $fields["description"] ""
      if (-not $desc -and $rule -and $rule.shortDescription -and $rule.shortDescription.text) {
        $desc = ([string]$rule.shortDescription.text) -replace "^\[Wiz[^\]]*\]\s*",""
      }
      if (-not $desc) { $desc = ($msgText -split "`n")[0] }

      # For long UUID-style ruleIds (IaC), prefer the human-readable rule name
      $displayRule = $rid
      if ($rule -and $rule.name -and $rid.Length -gt 32 -and $rid -match "^[0-9a-f-]{30,}$") {
        $displayRule = ([string]$rule.name) -replace "^\[Wiz[^\]]*\]\s*",""
      }

      $filePath = "N/A"
      if ($res.locations -and $res.locations.Count -gt 0) {
        $loc = $res.locations[0]
        if ($loc -and $loc.physicalLocation -and $loc.physicalLocation.artifactLocation) {
          $uri = $loc.physicalLocation.artifactLocation.uri
          if ($uri) { $filePath = [string]$uri }
        }
      }

      $rows.Add([ordered]@{
        ruleId      = $rid
        displayRule = $displayRule
        cveRule     = $cveRule
        severity    = $sev
        component   = $component
        version     = $version
        fixed       = $fixed
        remediation = $rem
        desc        = $desc
        file        = $filePath
      })
    }
  }
  return ($rows | Sort-Object { $sevOrder[[string]$_.severity] })
}

# Print a colored section table to stdout
function Print-Section([string]$title, $rows) {
  $cnt = if ($rows) { @($rows).Count } else { 0 }
  Write-Host ""
  Write-Host "::group::$title ($cnt findings)"
  Write-Host "${esc}[1m╔══════════════════════════════════════════════════════════════╗${esc}[0m"
  Write-Host "${esc}[1m║  $($title.PadRight(60))║${esc}[0m"
  Write-Host "${esc}[1m╚══════════════════════════════════════════════════════════════╝${esc}[0m"
  if ($cnt -eq 0) {
    Write-Host "  ${esc}[1;32mNo findings.${esc}[0m"
    Write-Host "::endgroup::"
    return
  }
  Write-Host ("  " + ("{0,-36} {1,-22} {2,-10} {3,-16} {4,-16} {5,-26} {6}" -f `
    "RULE / CVE","COMPONENT","SEVERITY","VERSION","FIXED","FILE","DESCRIPTION"))
  Write-Host ("  " + ("-" * 160))

  foreach ($r in $rows) {
    $col  = Sev-Color -s $r.severity
    $line = "  ${esc}[${col}m{0,-36}${esc}[0m {1,-22} ${esc}[${col}m{2,-10}${esc}[0m {3,-16} {4,-16} {5,-26} {6}" -f `
      (Trunc $r.displayRule 36), (Trunc $r.component 22), $r.severity, `
      (Trunc $r.version 16), (Trunc $r.fixed 16), (Trunc $r.file 26), (Trunc $r.desc 55)
    Write-Host $line
  }

  $cnts = @{}
  foreach ($r in $rows) { $s = [string]$r.severity; $cnts[$s] = (Safe-Int $cnts[$s]) + 1 }
  $parts = @("CRITICAL","HIGH","MEDIUM","LOW","INFORMATIONAL","UNKNOWN") |
    Where-Object { $cnts[$_] } |
    ForEach-Object { $c = Sev-Color -s $_; "${esc}[${c}m${_}: $($cnts[$_])${esc}[0m" }
  Write-Host ""; Write-Host "  Summary: $($parts -join '  |  ')"
  Write-Host "::endgroup::"
}

# ── SECTION 1: Container Image (image.sarif) ─────────────────────────────────
$imageSarif     = Get-Json -Path $ImageSarifPath
$containerRows  = [System.Collections.Generic.List[object]]::new()

if ($imageSarif) {
  Write-Host "::group::Enriching image.sarif"
  $imageSarif = Enrich-Sarif -sarif $imageSarif
  $imageSarif | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $ImageSarifPath -Encoding utf8
  Write-Host "  image.sarif enriched with security-severity."
  Write-Host "::endgroup::"
  $containerRows = Get-SarifRows -sarif $imageSarif
  Print-Section -title "Container Image Vulnerabilities" -rows $containerRows
} else {
  Write-Host "[INFO] image.sarif not found or empty: $ImageSarifPath"
}

# ── SECTION 2: Per-Layer Report (image-layers.json) ──────────────────────────
$layerJson    = Get-Json -Path $ImageLayersPath
$layerGroups  = [ordered]@{}

if ($layerJson) {
  $lr = if ($layerJson.result) { $layerJson.result } else { $layerJson }
  $allPkgs = [System.Collections.Generic.List[object]]::new()
  foreach ($key in @("osPackages","libraries","applications")) {
    $items = $lr.$key
    if ($items) { foreach ($i in $items) { if ($i) { $allPkgs.Add($i) } } }
  }

  foreach ($pkg in $allPkgs) {
    if (-not $pkg) { continue }
    $vulns = $pkg.vulnerabilities
    if (-not $vulns -or @($vulns).Count -eq 0) { continue }
    $meta = $pkg.layerMetadata
    if (-not $meta -or $meta -isnot [psobject]) { continue }

    $lid = ""
    foreach ($f in @("id","layerId","layerID","digest","layerDigest","sha","hash")) {
      $v = $meta.$f; if ($v) { $lid = [string]$v; break }
    }
    if (-not $lid) { $lid = "unknown" }

    $instr = ""
    foreach ($f in @("details","createdBy","instruction","command","cmd","layerInstruction")) {
      $v = $meta.$f; if ($v) { $instr = [string]$v; break }
    }

    $lidx = 999
    foreach ($f in @("index","layerIndex","order")) {
      $v = $meta.$f
      if ($null -ne $v) { try { $lidx = [int]$v; break } catch {} }
    }
    $isBase = ($meta.isBaseLayer -eq $true)

    if (-not $layerGroups.Contains($lid)) {
      $layerGroups[$lid] = [ordered]@{
        index    = $lidx
        instr    = $instr
        isBase   = $isBase
        findings = [System.Collections.Generic.List[object]]::new()
      }
    }
    foreach ($v in $vulns) {
      if (-not $v) { continue }
      $layerGroups[$lid].findings.Add([ordered]@{
        cve = Safe-Str $v.name "N/A"
        sev = (Safe-Str $v.severity "UNKNOWN").ToUpper()
        pkg = Safe-Str $pkg.name "N/A"
        ver = Safe-Str $pkg.version "N/A"
        fix = Safe-Str $v.fixedVersion "no fix"
      })
    }
  }

  if ($layerGroups.Count -gt 0) {
    Write-Host ""
    Write-Host "::group::Per-Layer Vulnerability Report ($($layerGroups.Count) layers)"
    Write-Host "${esc}[1m╔══════════════════════════════════════════════════════════════╗${esc}[0m"
    Write-Host "${esc}[1m║  PER-LAYER VULNERABILITY REPORT                              ║${esc}[0m"
    Write-Host "${esc}[1m╚══════════════════════════════════════════════════════════════╝${esc}[0m"

    $lIdx = 0
    foreach ($entry in ($layerGroups.GetEnumerator() | Sort-Object { $_.Value.index })) {
      $lIdx++
      $lid   = $entry.Key
      $lpay  = $entry.Value
      $lfinds = @($lpay.findings)
      $lc = @($lfinds | Where-Object { $_.sev -eq "CRITICAL" }).Count
      $lh = @($lfinds | Where-Object { $_.sev -eq "HIGH" }).Count
      $lm = @($lfinds | Where-Object { $_.sev -eq "MEDIUM" }).Count
      $ll = @($lfinds | Where-Object { $_.sev -eq "LOW" }).Count
      $btag = if ($lpay.isBase) { " ${esc}[1;34m[BASE IMAGE]${esc}[0m" } else { "" }

      Write-Host ""
      Write-Host "${esc}[1mLayer #${lIdx}${esc}[0m${btag}  Digest: $(Trunc $lid 55)"
      if ($lpay.instr) { Write-Host "  ${esc}[2mInstruction: $(Trunc $lpay.instr 160)${esc}[0m" }
      Write-Host ("  Findings: $($lfinds.Count)  |  " +
        "${esc}[1;37;41mCRIT: $lc${esc}[0m  " +
        "${esc}[1;31mHIGH: $lh${esc}[0m  " +
        "${esc}[1;33mMED:  $lm${esc}[0m  " +
        "${esc}[1;32mLOW:  $ll${esc}[0m")

      $seen = @{}
      $deduped = [System.Collections.Generic.List[object]]::new()
      foreach ($lf in ($lfinds | Sort-Object { $sevOrder[$_.sev] })) {
        $k = "$($lf.pkg)|$($lf.cve)"
        if (-not $seen.ContainsKey($k)) { $seen[$k] = 1; $deduped.Add($lf) }
      }
      $top = @($deduped | Select-Object -First 5)
      Write-Host "  $("{0,-20} {1,-10} {2,-28} {3,-18} {4}" -f "CVE","SEV","COMPONENT","VERSION","FIXED")"
      Write-Host "  $("-" * 100)"
      foreach ($lf in $top) {
        $col = Sev-Color -s $lf.sev
        Write-Host ("  ${esc}[${col}m$("{0,-20}" -f (Trunc $lf.cve 20))${esc}[0m " +
          "$("{0,-10} {1,-28} {2,-18} {3}" -f $lf.sev, (Trunc $lf.pkg 28), (Trunc $lf.ver 18), (Trunc $lf.fix 18))")
      }
      if ($deduped.Count -gt 5) { Write-Host "  ${esc}[2m... and $($deduped.Count - 5) more vulnerabilities in this layer${esc}[0m" }
    }
    Write-Host "::endgroup::"
  } else {
    Write-Host "[INFO] No layer vulnerability data found in: $ImageLayersPath"
  }
} else {
  Write-Host "[INFO] image-layers.json not found or empty: $ImageLayersPath"
}

# ── SECTION 3: SCA — Source Dependencies (dir.sarif) ─────────────────────────
$scaSarif = Get-Json -Path $DirSarifPath
$scaRows  = [System.Collections.Generic.List[object]]::new()

if ($scaSarif) {
  $scaSarif = Enrich-Sarif -sarif $scaSarif
  $scaSarif | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $DirSarifPath -Encoding utf8
  $scaRows = Get-SarifRows -sarif $scaSarif
  Print-Section -title "Source Dependencies — SCA (dir.sarif)" -rows $scaRows
} else {
  Write-Host "[INFO] SCA SARIF not found or empty: $DirSarifPath"
}

# ── SECTION 4: IaC — Dockerfile Misconfigurations (dockerfile.sarif) ─────────
$iacSarif = Get-Json -Path $DockerfileSarifPath
$iacRows  = [System.Collections.Generic.List[object]]::new()

if ($iacSarif) {
  $iacSarif = Enrich-Sarif -sarif $iacSarif
  $iacSarif | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $DockerfileSarifPath -Encoding utf8
  $iacRows = Get-SarifRows -sarif $iacSarif
  Print-Section -title "Dockerfile Misconfigurations — IaC (dockerfile.sarif)" -rows $iacRows
} else {
  Write-Host "[INFO] IaC SARIF not found or empty: $DockerfileSarifPath"
}

# ── SECTION 5: GitHub Job Summary ─────────────────────────────────────────────
function Count-BySev($rows, [string]$sev) {
  if (-not $rows) { return 0 }
  return @($rows | Where-Object { $_.severity -eq $sev }).Count
}

$md = [System.Collections.Generic.List[string]]::new()
$md.Add("# Wiz Security Scan Report")
$md.Add("")
if ($GitHubRunUrl) { $md.Add("> **CI Run:** $GitHubRunUrl") }
$md.Add("> **AppSec:** $AppSecContact")
$md.Add("")

$cCrit = Count-BySev $containerRows "CRITICAL"; $cHigh = Count-BySev $containerRows "HIGH"
$cMed  = Count-BySev $containerRows "MEDIUM";  $cLow  = Count-BySev $containerRows "LOW"
$sCrit = Count-BySev $scaRows "CRITICAL";      $sHigh = Count-BySev $scaRows "HIGH"
$sMed  = Count-BySev $scaRows "MEDIUM";        $sLow  = Count-BySev $scaRows "LOW"
$iCrit = Count-BySev $iacRows "CRITICAL";      $iHigh = Count-BySev $iacRows "HIGH"
$iMed  = Count-BySev $iacRows "MEDIUM";        $iLow  = Count-BySev $iacRows "LOW"

$md.Add("## Summary")
$md.Add("")
$md.Add("| Scan Type | Findings | Critical | High | Medium | Low |")
$md.Add("|---|---:|---:|---:|---:|---:|")
$md.Add("| Container Image | $(@($containerRows).Count) | $cCrit | $cHigh | $cMed | $cLow |")
$md.Add("| Source Dependencies (SCA) | $(@($scaRows).Count) | $sCrit | $sHigh | $sMed | $sLow |")
$md.Add("| Dockerfile IaC | $(@($iacRows).Count) | $iCrit | $iHigh | $iMed | $iLow |")
$md.Add("| **Layers Analyzed** | **$($layerGroups.Count)** | | | | |")
$md.Add("")

# Container findings table (up to 150 rows)
if (@($containerRows).Count -gt 0) {
  $md.Add("## Container Image Findings")
  $md.Add("")
  $md.Add("| CVE / Rule | Component | Severity | Version | Fixed | Description |")
  $md.Add("|---|---|---|---|---|---|")
  foreach ($r in ($containerRows | Select-Object -First 150)) {
    $d = (Trunc $r.desc 100) -replace '\|','&#124;'
    $md.Add("| ``$($r.displayRule)`` | $($r.component) | **$($r.severity)** | $($r.version) | $($r.fixed) | $d |")
  }
  if (@($containerRows).Count -gt 150) { $md.Add("_... $(@($containerRows).Count - 150) more rows omitted_") }
  $md.Add("")
}

# Per-layer summary
if ($layerGroups.Count -gt 0) {
  $md.Add("## Per-Layer Vulnerability Report")
  $md.Add("")
  $lIdx = 0
  foreach ($entry in ($layerGroups.GetEnumerator() | Sort-Object { $_.Value.index })) {
    $lIdx++; $lid = $entry.Key; $lpay = $entry.Value
    $lfinds = @($lpay.findings)
    $lc = @($lfinds | Where-Object { $_.sev -eq "CRITICAL" }).Count
    $lh = @($lfinds | Where-Object { $_.sev -eq "HIGH" }).Count
    $lm = @($lfinds | Where-Object { $_.sev -eq "MEDIUM" }).Count
    $ll = @($lfinds | Where-Object { $_.sev -eq "LOW" }).Count
    $btag = if ($lpay.isBase) { " · BASE IMAGE" } else { "" }
    $md.Add("### Layer #${lIdx}${btag}")
    $md.Add("**Digest:** ``$(Trunc $lid 64)``  ")
    if ($lpay.instr) { $md.Add("**Instruction:** ``$(Trunc $lpay.instr 200)``  ") }
    $md.Add("**Findings:** $($lfinds.Count) — Critical: $lc | High: $lh | Medium: $lm | Low: $ll")
    $md.Add("")

    $seen = @{}; $deduped = [System.Collections.Generic.List[object]]::new()
    foreach ($lf in ($lfinds | Sort-Object { $sevOrder[$_.sev] })) {
      $k = "$($lf.pkg)|$($lf.cve)"
      if (-not $seen.ContainsKey($k)) { $seen[$k] = 1; $deduped.Add($lf) }
    }
    $md.Add("| CVE | Severity | Component | Version | Fixed |")
    $md.Add("|---|---|---|---|---|")
    foreach ($lf in ($deduped | Select-Object -First 5)) {
      $md.Add("| $($lf.cve) | **$($lf.sev)** | $($lf.pkg) | $($lf.ver) | $($lf.fix) |")
    }
    if ($deduped.Count -gt 5) { $md.Add("_... and $($deduped.Count - 5) more_") }
    $md.Add("")
  }
}

# SCA findings table
if (@($scaRows).Count -gt 0) {
  $md.Add("## Source Dependencies — SCA Findings")
  $md.Add("")
  $md.Add("| Rule / CVE | Component | Severity | Version | Fixed | File | Description |")
  $md.Add("|---|---|---|---|---|---|---|")
  foreach ($r in ($scaRows | Select-Object -First 100)) {
    $d = (Trunc $r.desc 100) -replace '\|','&#124;'
    $md.Add("| ``$($r.displayRule)`` | $($r.component) | **$($r.severity)** | $($r.version) | $($r.fixed) | $($r.file) | $d |")
  }
  if (@($scaRows).Count -gt 100) { $md.Add("_... $(@($scaRows).Count - 100) more rows omitted_") }
  $md.Add("")
}

# IaC findings table
if (@($iacRows).Count -gt 0) {
  $md.Add("## Dockerfile Misconfigurations — IaC Findings")
  $md.Add("")
  $md.Add("| Rule | Severity | File | Description |")
  $md.Add("|---|---|---|---|")
  foreach ($r in ($iacRows | Select-Object -First 100)) {
    $d = (Trunc $r.desc 120) -replace '\|','&#124;'
    $md.Add("| ``$($r.displayRule)`` | **$($r.severity)** | $($r.file) | $d |")
  }
  $md.Add("")
}

$md | Set-Content -LiteralPath $SummaryMarkdownPath -Encoding utf8
Write-Host "Generated: $SummaryMarkdownPath"

# ── Final notices ─────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "::notice::Container findings: $(@($containerRows).Count)  |  Layers analyzed: $($layerGroups.Count)"
Write-Host "::notice::SCA findings: $(@($scaRows).Count)  |  IaC findings: $(@($iacRows).Count)"
if ($GitHubRunUrl) { Write-Host "::notice::CI Run: $GitHubRunUrl" }
Write-Host "::notice::AppSec contact: $AppSecContact"
exit 0
