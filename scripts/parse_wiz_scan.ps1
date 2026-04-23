<#
.SYNOPSIS
  Parses Wiz CLI container-image scan JSON output.
  Produces: rich colorized log table, GitHub SARIF, and Job Summary markdown.

  Wiz JSON schema (from wizcli scan container-image --json-output-file):
    .result.vulnerableSBOMArtifactsByNameVersion[]
      .name                                  (package name)
      .version                               (current installed version)
      .vulnerabilityFindings
        .fixedVersion                        (single fixed version for this package)
        .remediation                         (e.g. "apt upgrade <pkg>")
        .severities.criticalCount / highCount / mediumCount / lowCount
        .findings[]                          (per-CVE details, may be null)
          .name      (CVE ID)
          .description
          .link      (NVD or vendor advisory URL)
          .severity
          .fixedVersions[]
    .extraInfo.buildParams.jobUrl            (GitHub Actions run URL)
    .extraInfo.buildParams.commitUrl
    .id                                      (Wiz scan UUID)
    .status.verdict                          (PASS / WARN_BY_POLICY / FAIL / etc.)

  Wiz portal deep-link:
    https://app.wiz.io/findings/cicd-scans#~(cicd_scan~'<scanId>*)
#>
param(
  [string]$WizJsonPath         = "wiz.json",
  [string]$WizStdoutPath       = "wiz-stdout.json",
  [string]$WizSarifPath        = "wiz.sarif",
  [string]$OutputSarifPath     = "wiz-github.sarif",
  [string]$SummaryMarkdownPath = "wiz-summary.md",
  [string]$GitHubRunUrl        = "",
  [string]$AppSecContact       = "Emergency: contact AppSec Team at appsec@company.com or #appsec-oncall"
)

Set-StrictMode -Off
$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($AppSecContact)) {
  $AppSecContact = "Emergency: contact AppSec Team at appsec@company.com or #appsec-oncall"
}

# ─── helpers ────────────────────────────────────────────────────────────────

function Get-JsonObject ([string]$Path) {
  if (-not (Test-Path -LiteralPath $Path)) { return $null }
  try { return (Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -Depth 100) }
  catch { return $null }
}

function Safe-Int ($v) {
  if ($null -eq $v) { return 0 }
  try { return [int]$v } catch { return 0 }
}

function Safe-Str ($v, [string]$Default = "") {
  if ($null -eq $v) { return $Default }
  $s = [string]$v
  if ([string]::IsNullOrWhiteSpace($s)) { return $Default }
  return $s.Trim()
}

function Normalize-Cve ([string]$t) {
  if ([string]::IsNullOrWhiteSpace($t)) { return $null }
  $m = [regex]::Match($t.ToUpperInvariant(), "CVE-\d{4}-\d+")
  if ($m.Success) { return $m.Value }
  return $null
}

function Sev-Level ([string]$s) {
  switch ($s.ToUpper()) {
    "CRITICAL" { return "error" }
    "HIGH"     { return "error" }
    "MEDIUM"   { return "warning" }
    default    { return "note" }
  }
}

function Max-Sev ([int]$c, [int]$h, [int]$m, [int]$l) {
  if ($c -gt 0) { return "CRITICAL" }
  if ($h -gt 0) { return "HIGH" }
  if ($m -gt 0) { return "MEDIUM" }
  if ($l -gt 0) { return "LOW" }
  return "INFO"
}

function Color-Code ([string]$s) {
  switch ($s.ToUpper()) {
    "CRITICAL" { return "31" }
    "HIGH"     { return "33" }
    "MEDIUM"   { return "34" }
    "LOW"      { return "37" }
    default    { return "32" }
  }
}

function Safe-PkgId ([string]$name, [string]$version) {
  $n = ($name    -replace "[^a-zA-Z0-9._-]", "-").Trim("-")
  $v = ($version -replace "[^a-zA-Z0-9._-]", "-").Trim("-")
  if ($n.Length -gt 40) { $n = $n.Substring(0, 40) }
  if ($v.Length -gt 30) { $v = $v.Substring(0, 30) }
  return "WIZ-PKG-$n-$v"
}

# ─── load JSON ───────────────────────────────────────────────────────────────

$wizJson = Get-JsonObject -Path $WizJsonPath
if (-not $wizJson) { $wizJson = Get-JsonObject -Path $WizStdoutPath }
if (-not $wizJson) {
  throw "No parseable Wiz JSON found at '$WizJsonPath' or '$WizStdoutPath'"
}

# ─── extract top-level metadata ──────────────────────────────────────────────

$scanId  = Safe-Str $wizJson.id
$verdict = "UNKNOWN"
if ($wizJson.status -and $wizJson.status.verdict) {
  $verdict = Safe-Str $wizJson.status.verdict "UNKNOWN"
}

# Wiz portal deep-link from scan ID
$wizPortalUrl = ""
if ($scanId) {
  $wizPortalUrl = "https://app.wiz.io/findings/cicd-scans#~%2528cicd_scan~%2527${scanId}%252A%2529"
}

# GitHub Actions run URL (prefer from JSON, fallback to parameter)
$jobUrl = ""
if ($wizJson.extraInfo -and $wizJson.extraInfo.buildParams) {
  $jobUrl = Safe-Str $wizJson.extraInfo.buildParams.jobUrl
}
if ([string]::IsNullOrWhiteSpace($jobUrl) -and -not [string]::IsNullOrWhiteSpace($GitHubRunUrl)) {
  $jobUrl = $GitHubRunUrl
}

$commitUrl = ""
if ($wizJson.extraInfo -and $wizJson.extraInfo.buildParams) {
  $commitUrl = Safe-Str $wizJson.extraInfo.buildParams.commitUrl
}

$repository = ""
if ($wizJson.extraInfo -and $wizJson.extraInfo.buildParams) {
  $repository = Safe-Str $wizJson.extraInfo.buildParams.repository
}

$imageName = ""
if ($wizJson.scanOriginResource -and $wizJson.scanOriginResource.name) {
  $imageName = Safe-Str $wizJson.scanOriginResource.name
}

$imageDigest = ""
if ($wizJson.scanOriginResource) {
  $imageDigest = Safe-Str $wizJson.scanOriginResource.id
  if (-not $imageDigest) { $imageDigest = Safe-Str $wizJson.scanOriginResource.digest }
}

$wizcliVersion = ""
if ($wizJson.extraInfo) { $wizcliVersion = Safe-Str $wizJson.extraInfo.clientVersion }

# ─── parse packages ──────────────────────────────────────────────────────────
# Direct structured parsing — no recursive traversal.
# All needed data is at .result.vulnerableSBOMArtifactsByNameVersion[]

$packages        = [System.Collections.Generic.List[object]]::new()
$detailedFindings = [System.Collections.Generic.List[object]]::new()
$totalC = 0; $totalH = 0; $totalM = 0; $totalL = 0

$artifacts = $null
if ($wizJson.result) {
  $artifacts = $wizJson.result.vulnerableSBOMArtifactsByNameVersion
}

if ($null -ne $artifacts) {
  foreach ($art in $artifacts) {
    if ($null -eq $art) { continue }

    $pkgName    = Safe-Str $art.name "unknown-package"
    $pkgVersion = Safe-Str $art.version "-"
    $pkgType    = if ($art.type) { Safe-Str $art.type.group "" } else { "" }

    $vf = $art.vulnerabilityFindings
    if ($null -eq $vf) { continue }

    $fixedVersion = Safe-Str $vf.fixedVersion "unknown-fixed-version"
    $remediation  = Safe-Str $vf.remediation  "Upgrade package using your package manager."

    $sev = $vf.severities
    $c = Safe-Int ($null -ne $sev ? $sev.criticalCount : 0)
    $h = Safe-Int ($null -ne $sev ? $sev.highCount     : 0)
    $m = Safe-Int ($null -ne $sev ? $sev.mediumCount   : 0)
    $l = Safe-Int ($null -ne $sev ? $sev.lowCount      : 0)
    $t = $c + $h + $m + $l
    if ($t -le 0) { continue }

    $totalC += $c; $totalH += $h; $totalM += $m; $totalL += $l

    $packages.Add([ordered]@{
      name         = $pkgName
      version      = $pkgVersion
      fixedVersion = $fixedVersion
      remediation  = $remediation
      critical     = $c
      high         = $h
      medium       = $m
      low          = $l
      total        = $t
      pkgType      = $pkgType
    })

    # Per-CVE findings array (may be null — Wiz only returns these with expanded API tier)
    if ($vf.findings -and $vf.findings.Count -gt 0) {
      foreach ($fi in $vf.findings) {
        if ($null -eq $fi) { continue }

        $cveId   = Safe-Str $fi.name ""
        $normCve = Normalize-Cve -t $cveId
        if ($normCve) { $cveId = $normCve }

        $cveDesc   = Safe-Str $fi.description "No description available."
        $cveLink   = Safe-Str $fi.link ""
        $cveSevRaw = (Safe-Str $fi.severity "").ToUpper()

        # Per-CVE fixedVersion may differ from package-level
        $cveFix = $fixedVersion
        if ($fi.fixedVersions -and $fi.fixedVersions.Count -gt 0) {
          $cveFix = Safe-Str $fi.fixedVersions[0] $fixedVersion
        }

        # Build NVD link if vendor link absent
        if ([string]::IsNullOrWhiteSpace($cveLink)) {
          $nvdId = Normalize-Cve -t $cveId
          if ($nvdId) { $cveLink = "https://nvd.nist.gov/vuln/detail/$nvdId" }
        }

        $fc = if ($cveSevRaw -eq "CRITICAL") { 1 } else { 0 }
        $fh = if ($cveSevRaw -eq "HIGH")     { 1 } else { 0 }
        $fm = if ($cveSevRaw -eq "MEDIUM")   { 1 } else { 0 }
        $fl = if ($cveSevRaw -eq "LOW")      { 1 } else { 0 }
        if (($fc + $fh + $fm + $fl) -eq 0) { $fh = 1 }

        $detailedFindings.Add([ordered]@{
          package      = $pkgName
          version      = $pkgVersion
          fixedVersion = $cveFix
          remediation  = $remediation
          cve          = $(if ($cveId) { $cveId } else { Safe-PkgId $pkgName $pkgVersion })
          description  = $cveDesc
          link         = $cveLink
          severity     = $(if ($cveSevRaw) { $cveSevRaw } else { Max-Sev $fc $fh $fm $fl })
          critical     = $fc
          high         = $fh
          medium       = $fm
          low          = $fl
          total        = ($fc + $fh + $fm + $fl)
        })
      }
    } else {
      # No per-CVE breakdown — emit one aggregate finding per package
      $pkgRuleId  = Safe-PkgId $pkgName $pkgVersion
      $nvdSearch  = "https://nvd.nist.gov/vuln/search/results?query=$([System.Uri]::EscapeDataString($pkgName))&queryType=phrase"

      $detailedFindings.Add([ordered]@{
        package      = $pkgName
        version      = $pkgVersion
        fixedVersion = $fixedVersion
        remediation  = $remediation
        cve          = $pkgRuleId
        description  = "Package '$pkgName' v$pkgVersion has $t vulnerabilities (C:$c H:$h M:$m L:$l). Upgrade to $fixedVersion."
        link         = $nvdSearch
        severity     = (Max-Sev $c $h $m $l)
        critical     = $c
        high         = $h
        medium       = $m
        low          = $l
        total        = $t
      })
    }
  }
}

Write-Host ""
Write-Host "PARSER_COUNTS: packages=$($packages.Count) detailed_findings=$($detailedFindings.Count) verdict=$verdict"

# ─── colorized console output ─────────────────────────────────────────────────

$esc          = [char]27
$maxSevLabel  = Max-Sev $totalC $totalH $totalM $totalL
$summaryColor = Color-Code -s $maxSevLabel

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════════╗"
Write-Host "║                   WIZ CONTAINER SCAN RESULTS                    ║"
Write-Host "╚══════════════════════════════════════════════════════════════════╝"
Write-Host ""
Write-Host "${esc}[1mSCAN ID   :${esc}[0m $scanId"
Write-Host "${esc}[1mIMAGE     :${esc}[0m $imageName"
if ($imageDigest)  { Write-Host "${esc}[1mDIGEST    :${esc}[0m $imageDigest" }
Write-Host "${esc}[1mREPO      :${esc}[0m $repository"
if ($commitUrl)    { Write-Host "${esc}[1mCOMMIT    :${esc}[0m $commitUrl" }
if ($jobUrl)       { Write-Host "${esc}[1mRUN URL   :${esc}[0m $jobUrl" }
if ($wizPortalUrl) { Write-Host "${esc}[1mWIZ PORTAL:${esc}[0m ${esc}[36m$wizPortalUrl${esc}[0m" }
Write-Host ""
Write-Host ("${esc}[${summaryColor}mVERDICT: $verdict${esc}[0m  |  " +
  "${esc}[31mCRITICAL: $totalC${esc}[0m  |  " +
  "${esc}[33mHIGH: $totalH${esc}[0m  |  " +
  "${esc}[34mMEDIUM: $totalM${esc}[0m  |  " +
  "${esc}[37mLOW: $totalL${esc}[0m")
Write-Host ""

# ── Package summary table ─────────────────────────────────────────────────────
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
Write-Host "  PACKAGE SUMMARY  (top $([Math]::Min($packages.Count,60)) packages by total vulns)"
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

$sortedPkgs = $packages | Sort-Object -Property total -Descending | Select-Object -First 60

$hdr = "  {0,-40} {1,-32} {2,-32} {3,5} {4,5} {5,5} {6,4} {7,6}" -f `
  "PACKAGE", "CURRENT VERSION", "FIXED VERSION", "CRIT", "HIGH", "MED", "LOW", "TOTAL"
Write-Host $hdr
Write-Host ("  " + ("-" * 136))

foreach ($p in $sortedPkgs) {
  $sev = Max-Sev $p.critical $p.high $p.medium $p.low
  $col = Color-Code -s $sev
  $pkgDisp = [string]$p.name;    if ($pkgDisp.Length -gt 40) { $pkgDisp = $pkgDisp.Substring(0,39) + "…" }
  $curDisp = [string]$p.version; if ($curDisp.Length -gt 32) { $curDisp = $curDisp.Substring(0,31) + "…" }
  $fixDisp = [string]$p.fixedVersion; if ($fixDisp.Length -gt 32) { $fixDisp = $fixDisp.Substring(0,31) + "…" }
  $line = "  ${esc}[${col}m{0,-40}${esc}[0m {1,-32} {2,-32} {3,5} {4,5} {5,5} {6,4} {7,6}" -f `
    $pkgDisp, $curDisp, $fixDisp, $p.critical, $p.high, $p.medium, $p.low, $p.total
  Write-Host $line
}

# ── Detailed findings table ────────────────────────────────────────────────────
Write-Host ""
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
Write-Host "  DETAILED FINDINGS  (sorted by severity, up to 200)"
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

$sevOrder = @{ "CRITICAL" = 0; "HIGH" = 1; "MEDIUM" = 2; "LOW" = 3; "INFO" = 4 }
$sortedFindings = $detailedFindings | Sort-Object -Property @{
  Expression = { $sevOrder[([string]$_.severity).ToUpper()] }
}, total -Descending | Select-Object -First 200

$dhdr = "  {0,-38} {1,-22} {2,-9} {3,-32} {4,-32} {5}" -f `
  "PACKAGE @ VERSION", "CVE / RULE ID", "SEVERITY", "CURRENT VERSION", "FIXED VERSION", "REMEDIATION / REF"
Write-Host $dhdr
Write-Host ("  " + ("-" * 178))

foreach ($f in $sortedFindings) {
  $sev = (Safe-Str $f.severity "INFO").ToUpper()
  $col = Color-Code -s $sev

  $pkgVer = "$($f.package)@$($f.version)"
  if ($pkgVer.Length -gt 38) { $pkgVer = $pkgVer.Substring(0,37) + "…" }

  $cveDisp = Safe-Str $f.cve "n/a"
  if ($cveDisp.Length -gt 22) { $cveDisp = $cveDisp.Substring(0,21) + "…" }

  $curDisp = Safe-Str $f.version "-"
  if ($curDisp.Length -gt 32) { $curDisp = $curDisp.Substring(0,31) + "…" }

  $fixDisp = Safe-Str $f.fixedVersion "unknown-fixed-version"
  if ($fixDisp.Length -gt 32) { $fixDisp = $fixDisp.Substring(0,31) + "…" }

  $remDisp = Safe-Str $f.remediation ""
  $refLink = Safe-Str $f.link ""
  $remRef  = if ($refLink) { "$remDisp | $refLink" } else { $remDisp }
  if ($remRef.Length -gt 80) { $remRef = $remRef.Substring(0,79) + "…" }

  $line = "  ${esc}[${col}m{0,-38}${esc}[0m {1,-22} ${esc}[${col}m{2,-9}${esc}[0m {3,-32} {4,-32} {5}" -f `
    $pkgVer, $cveDisp, $sev, $curDisp, $fixDisp, $remRef
  Write-Host $line
}

Write-Host ""
Write-Host "${esc}[1mTotal packages   : $($packages.Count)${esc}[0m"
Write-Host "${esc}[1mTotal findings   : $($detailedFindings.Count)${esc}[0m"
if ($wizPortalUrl) {
  Write-Host "${esc}[36mView in Wiz Portal: $wizPortalUrl${esc}[0m"
}
if ($verdict -notin @("PASS", "SUCCESS")) {
  Write-Host "${esc}[31m$AppSecContact${esc}[0m"
}

# ─── Build GitHub SARIF ──────────────────────────────────────────────────────

$rules   = [ordered]@{}
$results = [System.Collections.Generic.List[object]]::new()

foreach ($f in $detailedFindings) {
  if ($f.total -le 0) { continue }

  $sev    = (Safe-Str $f.severity "LOW").ToUpper()
  $level  = Sev-Level -s $sev
  $ruleId = Safe-Str $f.cve (Safe-PkgId $f.package $f.version)
  $pkgAt  = "$($f.package)@$($f.version)"
  $fixedV = Safe-Str $f.fixedVersion "unknown-fixed-version"
  $curV   = Safe-Str $f.version "-"
  $ref    = Safe-Str $f.link ""
  $desc   = Safe-Str $f.description "Vulnerability detected by Wiz container image scan."

  # Ensure a reference URL
  if ([string]::IsNullOrWhiteSpace($ref)) {
    $nvdId = Normalize-Cve -t $ruleId
    if ($nvdId) { $ref = "https://nvd.nist.gov/vuln/detail/$nvdId" }
    elseif ($wizPortalUrl) { $ref = $wizPortalUrl }
  }

  $secSeverity = switch ($sev) {
    "CRITICAL" { "9.5" }
    "HIGH"     { "7.5" }
    "MEDIUM"   { "5.0" }
    default    { "2.0" }
  }

  $helpText  = "Package: $pkgAt`n"
  $helpText += "CVE / Rule: $ruleId`n"
  $helpText += "Severity: $sev`n"
  $helpText += "Current version: $curV`n"
  $helpText += "Fixed version: $fixedV`n"
  $helpText += "Remediation: $($f.remediation)`n"
  if ($ref)          { $helpText += "Reference: $ref`n" }
  if ($wizPortalUrl) { $helpText += "Wiz Portal: $wizPortalUrl`n" }
  if ($jobUrl)       { $helpText += "CI Run: $jobUrl`n" }
  $helpText += "`n$AppSecContact"

  if (-not $rules.ContainsKey($ruleId)) {
    $ruleObj = [ordered]@{
      id               = $ruleId
      name             = $ruleId
      shortDescription = @{ text = "[Wiz] $ruleId in $($f.package)" }
      fullDescription  = @{ text = $desc }
      defaultConfiguration = @{ level = $level }
      help             = @{ text = $helpText; markdown = $helpText }
      properties       = @{
        tags                = @("wiz", "container", "vulnerability")
        "security-severity" = $secSeverity
      }
    }
    if ($ref) { $ruleObj["helpUri"] = $ref }
    $rules[$ruleId] = $ruleObj
  }

  $msgLines = @(
    "[Wiz] $ruleId — $pkgAt",
    "Severity: $sev  (C:$($f.critical) H:$($f.high) M:$($f.medium) L:$($f.low))",
    "Current version: $curV",
    "Fixed version: $fixedV",
    "Remediation: $($f.remediation)",
    $desc
  )
  if ($ref)          { $msgLines += "Reference: $ref" }
  if ($wizPortalUrl) { $msgLines += "Wiz Portal: $wizPortalUrl" }
  if ($jobUrl)       { $msgLines += "CI Run: $jobUrl" }
  $msgLines += $AppSecContact

  $results.Add([ordered]@{
    ruleId  = $ruleId
    level   = $level
    message = @{ text = ($msgLines -join "`n") }
    locations = @(
      @{
        physicalLocation = @{
          artifactLocation = @{ uri = "Dockerfile"; uriBaseId = "%SRCROOT%" }
          region           = @{ startLine = 1 }
        }
        logicalLocations = @(
          @{ name = $pkgAt; kind = "package" }
        )
      }
    )
    partialFingerprints = @{
      primary        = "$pkgAt|$ruleId"
      packageName    = Safe-Str $f.package ""
      packageVersion = Safe-Str $f.version ""
    }
    properties = @{
      package      = Safe-Str $f.package ""
      version      = Safe-Str $f.version ""
      fixedVersion = $fixedV
      severity     = $sev
      cve          = $ruleId
      wizPortalUrl = $wizPortalUrl
      jobUrl       = $jobUrl
    }
  })
}

# Fallback: emit policy-level result if nothing parsed
if ($results.Count -eq 0) {
  $rules["WIZ-POLICY-VERDICT"] = [ordered]@{
    id               = "WIZ-POLICY-VERDICT"
    name             = "WIZ-POLICY-VERDICT"
    shortDescription = @{ text = "[Wiz] Policy verdict: $verdict" }
    fullDescription  = @{ text = "Wiz container scan verdict: $verdict. No package-level findings parsed." }
    defaultConfiguration = @{ level = "warning" }
    help             = @{ text = $AppSecContact }
  }
  $results.Add([ordered]@{
    ruleId    = "WIZ-POLICY-VERDICT"
    level     = "warning"
    message   = @{ text = "Wiz policy verdict: $verdict`n$AppSecContact" }
    locations = @(@{ physicalLocation = @{ artifactLocation = @{ uri = "Dockerfile" }; region = @{ startLine = 1 } } })
  })
}

$sarif = [ordered]@{
  version   = "2.1.0"
  '$schema' = "https://json.schemastore.org/sarif-2.1.0.json"
  runs      = @(
    [ordered]@{
      tool = [ordered]@{
        driver = [ordered]@{
          name           = "WizCLI"
          version        = $wizcliVersion
          informationUri = "https://docs.wiz.io/docs/scan-and-tag-container-images-with-wiz-cli"
          rules          = @($rules.Values)
        }
      }
      automationDetails = @{
        id          = "wiz-container-scan/$scanId"
        description = @{ text = "Wiz CLI container image scan" }
      }
      invocations = @(
        @{
          executionSuccessful = $true
          commandLine         = "wizcli scan container-image"
          properties          = @{
            verdict    = $verdict
            scanId     = $scanId
            imageName  = $imageName
            repository = $repository
            jobUrl     = $jobUrl
            wizPortal  = $wizPortalUrl
          }
        }
      )
      results = @($results)
    }
  )
}

$sarif | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $OutputSarifPath -Encoding utf8

# ─── GitHub Job Summary (markdown) ────────────────────────────────────────────

$md = [System.Collections.Generic.List[string]]::new()
$md.Add("# Wiz Container Scan Report")
$md.Add("")
$md.Add("| Field | Value |")
$md.Add("|---|---|")
$md.Add("| **Verdict** | ``$verdict`` |")
$md.Add("| **Image** | ``$imageName`` |")
$md.Add("| **Scan ID** | ``$scanId`` |")
$md.Add("| **Critical** | $totalC |")
$md.Add("| **High** | $totalH |")
$md.Add("| **Medium** | $totalM |")
$md.Add("| **Low** | $totalL |")
if ($wizPortalUrl) { $md.Add("| **Wiz Portal** | [$wizPortalUrl]($wizPortalUrl) |") }
if ($jobUrl)       { $md.Add("| **CI Run** | [$jobUrl]($jobUrl) |") }
if ($commitUrl)    { $md.Add("| **Commit** | [$commitUrl]($commitUrl) |") }
$md.Add("| **AppSec Contact** | $AppSecContact |")
$md.Add("")

$md.Add("## Top Vulnerable Packages")
$md.Add("")
$md.Add("| Package | Type | Current Version | Fixed Version | Critical | High | Medium | Low | Total | Remediation |")
$md.Add("|---|---|---|---|---:|---:|---:|---:|---:|---|")
foreach ($p in ($packages | Sort-Object -Property total -Descending | Select-Object -First 100)) {
  $md.Add("| $($p.name) | $($p.pkgType) | ``$($p.version)`` | ``$($p.fixedVersion)`` | $($p.critical) | $($p.high) | $($p.medium) | $($p.low) | $($p.total) | $($p.remediation) |")
}
$md.Add("")

if ($sortedFindings.Count -gt 0) {
  $md.Add("## Individual Findings")
  $md.Add("")
  $md.Add("| CVE / Rule | Package | Current Version | Fixed Version | Severity | Remediation | Reference |")
  $md.Add("|---|---|---|---|---|---|---|")
  foreach ($f in ($sortedFindings | Select-Object -First 150)) {
    $refLink = if ($f.link) { "[$($f.link)]($($f.link))" } else { "n/a" }
    $descShort = Safe-Str $f.description ""
    if ($descShort.Length -gt 80) { $descShort = $descShort.Substring(0, 77) + "..." }
    $md.Add("| ``$($f.cve)`` | $($f.package) | ``$($f.version)`` | ``$($f.fixedVersion)`` | **$($f.severity)** | $($f.remediation) | $refLink |")
  }
  $md.Add("")
}

$md.Add("## Summary")
$md.Add("- Packages with vulnerabilities: **$($packages.Count)**")
$md.Add("- SARIF results generated: **$($results.Count)**")
$md.Add("- Findings parsed: **$($detailedFindings.Count)**")

$md | Set-Content -LiteralPath $SummaryMarkdownPath -Encoding utf8

# ─── final notices ───────────────────────────────────────────────────────────

Write-Host ""
Write-Host "::notice::Wiz scan complete. Verdict=$verdict  C=$totalC H=$totalH M=$totalM L=$totalL"
Write-Host "::notice::SARIF results: $($results.Count)  packages: $($packages.Count)  findings: $($detailedFindings.Count)"
if ($wizPortalUrl) { Write-Host "::notice::Wiz Portal URL: $wizPortalUrl" }
if ($jobUrl)       { Write-Host "::notice::CI Run URL: $jobUrl" }
Write-Host "::notice::AppSec contact: $AppSecContact"
Write-Host "Generated $OutputSarifPath ($($results.Count) results)"
Write-Host "Generated $SummaryMarkdownPath"
exit 0
