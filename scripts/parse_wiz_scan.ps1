param(
  [string]$WizJsonPath = "wiz.json",
  [string]$WizStdoutPath = "wiz-stdout.json",
  [string]$OutputSarifPath = "wiz-github.sarif",
  [string]$SummaryMarkdownPath = "wiz-summary.md",
  [string]$AppSecContact = "Emergency: contact AppSec Team at appsec@company.com or #appsec-oncall"
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($AppSecContact)) {
  $AppSecContact = "Emergency: contact AppSec Team at appsec@company.com or #appsec-oncall"
}

function Get-JsonObject {
  param([string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) { return $null }
  try {
    return (Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -Depth 100)
  } catch {
    return $null
  }
}

function Get-NormalizedInt {
  param($Value)
  if ($null -eq $Value) { return 0 }
  try { return [int]$Value } catch { return 0 }
}

function Get-MaxSeverityLabel {
  param([int]$Critical, [int]$High, [int]$Medium, [int]$Low)
  if ($Critical -gt 0) { return "CRITICAL" }
  if ($High -gt 0) { return "HIGH" }
  if ($Medium -gt 0) { return "MEDIUM" }
  if ($Low -gt 0) { return "LOW" }
  return "INFO"
}

function Get-SarifLevel {
  param([string]$Severity)
  switch ($Severity) {
    "CRITICAL" { return "error" }
    "HIGH" { return "error" }
    "MEDIUM" { return "warning" }
    "LOW" { return "note" }
    default { return "note" }
  }
}

function Get-ColorCode {
  param([string]$Severity)
  switch ($Severity) {
    "CRITICAL" { return "31" }
    "HIGH" { return "33" }
    "MEDIUM" { return "34" }
    "LOW" { return "37" }
    default { return "32" }
  }
}

function Get-ShortPackage {
  param([string]$Name)
  if ([string]::IsNullOrWhiteSpace($Name)) { return "unknown-pkg" }
  $short = $Name -replace "[^a-zA-Z0-9._-]", "-"
  if ($short.Length -gt 24) { return $short.Substring(0, 24) }
  return $short
}

$script:Verdict = "UNKNOWN"
$script:WizUrl = ""
$script:Packages = @{}
$script:DetailedFindings = [System.Collections.Generic.List[object]]::new()

function Process-Node {
  param($Node)

  if ($null -eq $Node) { return @() }

  if ($Node -is [System.Collections.IEnumerable] -and -not ($Node -is [string]) -and -not ($Node.PSObject -and $Node.PSObject.Properties)) {
    return @($Node)
  }

  if (-not ($Node.PSObject -and $Node.PSObject.Properties)) { return @() }

  if ($script:Verdict -eq "UNKNOWN" -and $Node.status -and $Node.status.verdict) {
    $script:Verdict = [string]$Node.status.verdict
  }

  foreach ($urlField in @("jobUrl", "scanUrl", "commitUrl", "url")) {
    if ($script:WizUrl -eq "" -and $Node.PSObject.Properties[$urlField] -and $Node.$urlField -is [string] -and $Node.$urlField -match "^https?://") {
      $script:WizUrl = [string]$Node.$urlField
    }
  }

  $pkgName = ""
  $pkgVersion = "-"
  if ($Node.type -and $Node.type.name) { $pkgName = [string]$Node.type.name }
  elseif ($Node.name) { $pkgName = [string]$Node.name }
  if ($Node.type -and $Node.type.version) { $pkgVersion = [string]$Node.type.version }
  elseif ($Node.version) { $pkgVersion = [string]$Node.version }

  $critical = Get-NormalizedInt ($Node.criticalCount)
  if ($critical -eq 0) { $critical = Get-NormalizedInt ($Node.vulnerabilityFindings.severities.criticalCount) }
  if ($critical -eq 0) { $critical = Get-NormalizedInt ($Node.severities.criticalCount) }

  $high = Get-NormalizedInt ($Node.highCount)
  if ($high -eq 0) { $high = Get-NormalizedInt ($Node.vulnerabilityFindings.severities.highCount) }
  if ($high -eq 0) { $high = Get-NormalizedInt ($Node.severities.highCount) }

  $medium = Get-NormalizedInt ($Node.mediumCount)
  if ($medium -eq 0) { $medium = Get-NormalizedInt ($Node.vulnerabilityFindings.severities.mediumCount) }
  if ($medium -eq 0) { $medium = Get-NormalizedInt ($Node.severities.mediumCount) }

  $low = Get-NormalizedInt ($Node.lowCount)
  if ($low -eq 0) { $low = Get-NormalizedInt ($Node.vulnerabilityFindings.severities.lowCount) }
  if ($low -eq 0) { $low = Get-NormalizedInt ($Node.severities.lowCount) }

  $total = $critical + $high + $medium + $low
  if ($pkgName -and $total -gt 0) {
    $key = "$pkgName@$pkgVersion"
    if (-not $script:Packages.ContainsKey($key)) {
      $script:Packages[$key] = [ordered]@{
        package = $pkgName
        version = $pkgVersion
        critical = 0
        high = 0
        medium = 0
        low = 0
        total = 0
      }
    }
    $script:Packages[$key].critical += $critical
    $script:Packages[$key].high += $high
    $script:Packages[$key].medium += $medium
    $script:Packages[$key].low += $low
    $script:Packages[$key].total += $total
  }

  if ($Node.vulnerabilityFindings -and $Node.vulnerabilityFindings.findings) {
    foreach ($finding in $Node.vulnerabilityFindings.findings) {
      if ($null -eq $finding) { continue }

      $cve = "UNKNOWN-CVE"
      if ($finding.cves -and $finding.cves.Count -gt 0 -and $finding.cves[0]) {
        $cve = [string]$finding.cves[0]
      } elseif ($finding.id -and [string]$finding.id -match "CVE-\d{4}-\d+") {
        $cve = [string]$finding.id
      }

      $fCritical = Get-NormalizedInt ($finding.severities.criticalCount)
      if ($fCritical -eq 0) { $fCritical = Get-NormalizedInt ($finding.criticalCount) }
      $fHigh = Get-NormalizedInt ($finding.severities.highCount)
      if ($fHigh -eq 0) { $fHigh = Get-NormalizedInt ($finding.highCount) }
      $fMedium = Get-NormalizedInt ($finding.severities.mediumCount)
      if ($fMedium -eq 0) { $fMedium = Get-NormalizedInt ($finding.mediumCount) }
      $fLow = Get-NormalizedInt ($finding.severities.lowCount)
      if ($fLow -eq 0) { $fLow = Get-NormalizedInt ($finding.lowCount) }

      $fTotal = $fCritical + $fHigh + $fMedium + $fLow
      if ($fTotal -eq 0) {
        $fCritical = $critical
        $fHigh = $high
        $fMedium = $medium
        $fLow = $low
        $fTotal = $fCritical + $fHigh + $fMedium + $fLow
      }
      if ($fTotal -eq 0) { continue }

      $remediation = "No remediation details provided by Wiz."
      if ($finding.remediation) { $remediation = [string]$finding.remediation }
      elseif ($Node.remediation) { $remediation = [string]$Node.remediation }

      $script:DetailedFindings.Add([ordered]@{
        package = $(if ($pkgName) { $pkgName } else { "unknown-package" })
        version = $pkgVersion
        cve = $cve
        critical = $fCritical
        high = $fHigh
        medium = $fMedium
        low = $fLow
        total = $fTotal
        remediation = $remediation
      })
    }
  }

  $children = @()
  foreach ($prop in $Node.PSObject.Properties) {
    $val = $prop.Value
    if ($val -is [string] -or $val -is [int] -or $val -is [double] -or $val -is [bool] -or $null -eq $val) { continue }
    $children += $val
  }

  return $children
}

$inputs = @()
$wizJson = Get-JsonObject -Path $WizJsonPath
if ($wizJson) { $inputs += $wizJson }
$wizStdout = Get-JsonObject -Path $WizStdoutPath
if ($wizStdout) { $inputs += $wizStdout }

if ($inputs.Count -eq 0) {
  throw "No parseable Wiz JSON inputs found at $WizJsonPath or $WizStdoutPath"
}

foreach ($obj in $inputs) {
  $stack = [System.Collections.Stack]::new()
  $stack.Push($obj)
  while ($stack.Count -gt 0) {
    $node = $stack.Pop()
    $children = Process-Node -Node $node
    foreach ($child in $children) {
      if ($null -ne $child) { $stack.Push($child) }
    }
  }
}

$rows = $script:Packages.Values | Sort-Object -Property total -Descending
$totals = [ordered]@{ critical = 0; high = 0; medium = 0; low = 0 }
foreach ($r in $rows) {
  $totals.critical += [int]$r.critical
  $totals.high += [int]$r.high
  $totals.medium += [int]$r.medium
  $totals.low += [int]$r.low
}

$esc = [char]27
$maxSev = Get-MaxSeverityLabel -Critical $totals.critical -High $totals.high -Medium $totals.medium -Low $totals.low
$summaryColor = Get-ColorCode -Severity $maxSev

Write-Host "===== WIZ SCAN SUMMARY ====="
Write-Host (("{0}[{1}mVERDICT: {2}  CRITICAL: {3}  HIGH: {4}  MEDIUM: {5}  LOW: {6}{0}[0m" -f $esc, $summaryColor, $script:Verdict, $totals.critical, $totals.high, $totals.medium, $totals.low))

if ($script:WizUrl) {
  Write-Host "WIZ_SCAN_URL: $($script:WizUrl)"
}

if ($script:Verdict -notin @("PASS", "SUCCESS")) {
  Write-Host (("{0}[31m{1}{0}[0m" -f $esc, $AppSecContact))
}

Write-Host "===== TOP PACKAGES BY VULNERABILITY COUNT ====="
$rows | Select-Object -First 50 package, version, critical, high, medium, low, total | Format-Table -AutoSize | Out-String | Write-Host

if ($script:DetailedFindings.Count -eq 0) {
  foreach ($r in $rows) {
    $script:DetailedFindings.Add([ordered]@{
      package = $r.package
      version = $r.version
      cve = "UNKNOWN-CVE"
      critical = $r.critical
      high = $r.high
      medium = $r.medium
      low = $r.low
      total = $r.total
      remediation = "Use your package manager to upgrade this package to a fixed version."
    })
  }
}

$rules = @{}
$results = [System.Collections.Generic.List[object]]::new()

foreach ($f in $script:DetailedFindings) {
  if ($f.total -le 0) { continue }
  $sev = Get-MaxSeverityLabel -Critical $f.critical -High $f.high -Medium $f.medium -Low $f.low
  $level = Get-SarifLevel -Severity $sev
  $pkgShort = Get-ShortPackage -Name $f.package
  $cve = if ($f.cve) { [string]$f.cve } else { "UNKNOWN-CVE" }
  $subject = "[Wiz-Cloud-Scan] $cve $pkgShort"
  $ruleId = if ($cve -match "^CVE-\d{4}-\d+$") { $cve } else { "WIZ-OS-PACKAGE-VULNS" }

  if (-not $rules.ContainsKey($ruleId)) {
    $rules[$ruleId] = [ordered]@{
      id = $ruleId
      shortDescription = @{ text = $subject }
      fullDescription = @{ text = "Container vulnerability detected by Wiz for package $($f.package)@$($f.version)." }
      defaultConfiguration = @{ level = $level }
      help = @{ text = "Fix guidance: $($f.remediation)`n$AppSecContact" }
    }
  }

  $msg = @(
    $subject,
    "Package: $($f.package)@$($f.version)",
    "Severity counts: critical=$($f.critical), high=$($f.high), medium=$($f.medium), low=$($f.low)",
    "Fix guidance: $($f.remediation)",
    "Wiz verdict: $($script:Verdict)",
    $AppSecContact
  )
  if ($script:WizUrl) { $msg += "Wiz URL: $($script:WizUrl)" }

  $results.Add([ordered]@{
    ruleId = $ruleId
    level = $level
    message = @{ text = ($msg -join "`n") }
    locations = @(
      @{
        physicalLocation = @{
          artifactLocation = @{ uri = "Dockerfile" }
          region = @{ startLine = 1 }
        }
      }
    )
    partialFingerprints = @{ primary = "$($f.package)@$($f.version)|$cve" }
    properties = @{
      subject = $subject
      package = $f.package
      packageVersion = $f.version
      cve = $cve
      severity = $sev
    }
  })
}

if ($results.Count -eq 0 -and $script:Verdict -notin @("PASS", "SUCCESS")) {
  $subject = "[Wiz-Cloud-Scan] POLICY $((Get-ShortPackage -Name $script:Verdict))"
  $rules["WIZ-POLICY-VERDICT"] = [ordered]@{
    id = "WIZ-POLICY-VERDICT"
    shortDescription = @{ text = $subject }
    fullDescription = @{ text = "Wiz reported policy verdict without parseable package-level details in JSON payload." }
    defaultConfiguration = @{ level = "warning" }
    help = @{ text = $AppSecContact }
  }
  $results.Add([ordered]@{
    ruleId = "WIZ-POLICY-VERDICT"
    level = "warning"
    message = @{ text = "$subject`nVerdict: $($script:Verdict)`n$AppSecContact" }
    locations = @(@{ physicalLocation = @{ artifactLocation = @{ uri = "Dockerfile" }; region = @{ startLine = 1 } } })
    partialFingerprints = @{ policy = $script:Verdict }
  })
}

$sarif = [ordered]@{
  version = "2.1.0"
  '$schema' = "https://json.schemastore.org/sarif-2.1.0.json"
  runs = @(
    [ordered]@{
      tool = [ordered]@{
        driver = [ordered]@{
          name = "WizCLI"
          informationUri = "https://www.wiz.io/"
          rules = @($rules.Values)
        }
      }
      automationDetails = @{ id = "wiz-container-scan" }
      invocations = @(@{ executionSuccessful = $true })
      results = @($results)
    }
  )
}

$sarif | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $OutputSarifPath -Encoding utf8

$md = @()
$md += "# Wiz Container Scan Summary"
$md += ""
$md += "- Verdict: **$($script:Verdict)**"
$md += "- Critical: **$($totals.critical)**"
$md += "- High: **$($totals.high)**"
$md += "- Medium: **$($totals.medium)**"
$md += "- Low: **$($totals.low)**"
if ($script:WizUrl) { $md += "- Wiz Scan URL: $($script:WizUrl)" }
$md += "- Contact: $AppSecContact"
$md += ""
$md += "## Top Packages"
$md += ""
$md += "| Package | Version | Critical | High | Medium | Low | Total |"
$md += "|---|---:|---:|---:|---:|---:|---:|"
foreach ($r in ($rows | Select-Object -First 100)) {
  $md += "| $($r.package) | $($r.version) | $($r.critical) | $($r.high) | $($r.medium) | $($r.low) | $($r.total) |"
}
$md += ""
$md += "## Parsed Finding Count"
$md += ""
$md += "- SARIF results generated: **$($results.Count)**"

$md -join "`n" | Set-Content -LiteralPath $SummaryMarkdownPath -Encoding utf8

Write-Host "Generated $OutputSarifPath with $($results.Count) result(s)."
Write-Host "Generated $SummaryMarkdownPath"
if ($script:WizUrl) { Write-Host "Latest Wiz scan URL: $($script:WizUrl)" }
Write-Host "::notice::Wiz parsing complete. SARIF results: $($results.Count)."
Write-Host "::notice::AppSec escalation contact: $AppSecContact"

if ($script:Verdict -eq "BLOCK_BY_POLICY") {
  exit 2
}
exit 0

# Note: GitHub Security tab controls severity colors in its own UI.
# This script uses ANSI colors in workflow logs for visual severity emphasis.