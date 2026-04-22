param(
  [string]$WizJsonPath = "wiz.json",
  [string]$WizStdoutPath = "wiz-stdout.json",
  [string]$WizSarifPath = "wiz.sarif",
  [string]$OutputSarifPath = "wiz-github.sarif",
  [string]$SummaryMarkdownPath = "wiz-summary.md",
  [string]$GitHubRunUrl = "",
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

function Get-ColorizedSeverity {
  param([string]$Severity)
  $color = Get-ColorCode -Severity $Severity
  return "$([char]27)[$color`m$Severity$([char]27)[0m"
}

function Get-StableIssueId {
  param(
    [string]$Primary,
    [string]$Fallback,
    [string]$Package,
    [string]$Version
  )

  $normalizedPrimary = Normalize-CveIdentifier -Text $Primary
  if ($normalizedPrimary) { return $normalizedPrimary }

  $normalizedFallback = Normalize-CveIdentifier -Text $Fallback
  if ($normalizedFallback) { return $normalizedFallback }

  $p = Get-NonEmptyString $Primary ""
  if (-not [string]::IsNullOrWhiteSpace($p)) {
    $cleanPrimary = ($p -replace "[^a-zA-Z0-9._:-]", "-").Trim('-')
    if (-not [string]::IsNullOrWhiteSpace($cleanPrimary)) { return $cleanPrimary }
  }

  $f = Get-NonEmptyString $Fallback ""
  if (-not [string]::IsNullOrWhiteSpace($f)) {
    $cleanFallback = ($f -replace "[^a-zA-Z0-9._:-]", "-").Trim('-')
    if (-not [string]::IsNullOrWhiteSpace($cleanFallback)) { return $cleanFallback }
  }

  $pkgShort = Get-ShortPackage -Name (Get-NonEmptyString $Package "unknown-package")
  $verShort = Get-ShortPackage -Name (Get-NonEmptyString $Version "-")
  return "WIZ-PKG-$pkgShort-$verShort"
}

function Get-UpgradeGuidance {
  param(
    [string]$CurrentVersion,
    [string]$FixedVersion,
    [string]$Remediation
  )

  $current = if ([string]::IsNullOrWhiteSpace($CurrentVersion)) { "unknown-current-version" } else { $CurrentVersion }
  $fixed = if ([string]::IsNullOrWhiteSpace($FixedVersion)) { "unknown-fixed-version" } else { $FixedVersion }
  if ($fixed -eq "unknown-fixed-version") {
    return "Current version: $current. Fixed version: unknown. $Remediation"
  }

  return "Upgrade from $current to $fixed. $Remediation"
}

function Normalize-CveIdentifier {
  param([string]$Text)
  if ([string]::IsNullOrWhiteSpace($Text)) { return $null }

  $m = [regex]::Match($Text.ToUpperInvariant(), "CVE-\d{4}-\d+")
  if ($m.Success) { return $m.Value }
  return $null
}

function Get-NonEmptyString {
  param($Value, [string]$Default = "")
  if ($null -eq $Value) { return $Default }
  $s = [string]$Value
  if ([string]::IsNullOrWhiteSpace($s)) { return $Default }
  return $s.Trim()
}

function Extract-FirstUrl {
  param([string]$Text)
  if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
  $m = [regex]::Match($Text, "https?://\S+")
  if ($m.Success) {
    return ([string]$m.Value).TrimEnd(')',']','"','''',',','.')
  }
  return $null
}

function Parse-SeverityCountsFromText {
  param([string]$Text)
  $counts = [ordered]@{ critical = 0; high = 0; medium = 0; low = 0 }
  if ([string]::IsNullOrWhiteSpace($Text)) { return $counts }

  $patterns = @{
    critical = "critical\s*=\s*(\d+)"
    high = "high\s*=\s*(\d+)"
    medium = "medium\s*=\s*(\d+)"
    low = "low\s*=\s*(\d+)"
  }

  foreach ($k in $patterns.Keys) {
    $m = [regex]::Match($Text.ToLowerInvariant(), $patterns[$k])
    if ($m.Success) {
      $counts[$k] = Get-NormalizedInt $m.Groups[1].Value
    }
  }

  return $counts
}

function Get-MapInt {
  param($Obj, [string]$Key)
  if ($null -eq $Obj) { return 0 }
  if ($Obj -is [System.Collections.IDictionary]) {
    if ($Obj.Contains($Key)) { return Get-NormalizedInt $Obj[$Key] }
    return 0
  }
  if ($Obj.PSObject -and $Obj.PSObject.Properties[$Key]) {
    return Get-NormalizedInt $Obj.$Key
  }
  return 0
}

function Get-MapString {
  param($Obj, [string]$Key, [string]$Default = "")
  if ($null -eq $Obj) { return $Default }
  if ($Obj -is [System.Collections.IDictionary]) {
    if ($Obj.Contains($Key)) { return Get-NonEmptyString $Obj[$Key] $Default }
    return $Default
  }
  if ($Obj.PSObject -and $Obj.PSObject.Properties[$Key]) {
    return Get-NonEmptyString $Obj.$Key $Default
  }
  return $Default
}

function Find-PropertyValueRecursive {
  param(
    $Node,
    [string[]]$PropertyNames,
    [System.Collections.Generic.HashSet[string]]$Visited
  )

  if ($null -eq $Node) { return $null }
  if ($Node -is [string] -or $Node -is [int] -or $Node -is [double] -or $Node -is [bool]) { return $null }

  $identity = [System.Runtime.CompilerServices.RuntimeHelpers]::GetHashCode($Node).ToString()
  if (-not $Visited.Add($identity)) { return $null }

  if ($Node.PSObject -and $Node.PSObject.Properties) {
    foreach ($name in $PropertyNames) {
      $prop = $Node.PSObject.Properties[$name]
      if (-not $prop) { continue }

      $value = $prop.Value
      if ($null -eq $value) { continue }
      if ($value -is [string] -and -not [string]::IsNullOrWhiteSpace($value)) { return [string]$value }
      if ($value -is [System.Collections.IEnumerable] -and -not ($value -is [string])) {
        foreach ($item in $value) {
          if ($item -is [string] -and -not [string]::IsNullOrWhiteSpace($item)) { return [string]$item }
          if ($item -is [int] -or $item -is [double] -or $item -is [bool] -or $null -eq $item) { continue }
          $found = Find-PropertyValueRecursive -Node $item -PropertyNames $PropertyNames -Visited $Visited
          if ($found) { return $found }
        }
      }
    }

    foreach ($prop in $Node.PSObject.Properties) {
      $value = $prop.Value
      if ($null -eq $value) { continue }
      if ($value -is [string] -and -not [string]::IsNullOrWhiteSpace($value)) { continue }
      if ($value -is [int] -or $value -is [double] -or $value -is [bool]) { continue }
      $found = Find-PropertyValueRecursive -Node $value -PropertyNames $PropertyNames -Visited $Visited
      if ($found) { return $found }
    }
  }

  if ($Node -is [System.Collections.IEnumerable] -and -not ($Node -is [string])) {
    foreach ($item in $Node) {
      if ($item -is [string] -or $item -is [int] -or $item -is [double] -or $item -is [bool] -or $null -eq $item) { continue }
      $found = Find-PropertyValueRecursive -Node $item -PropertyNames $PropertyNames -Visited $Visited
      if ($found) { return $found }
    }
  }

  return $null
}

$script:Verdict = "UNKNOWN"
$script:WizUrl = ""
$script:WizCloudUrl = ""
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
    if ($Node.PSObject.Properties[$urlField] -and $Node.$urlField -is [string] -and $Node.$urlField -match "^https?://") {
      $candidateUrl = [string]$Node.$urlField
      if ($candidateUrl -match "wiz\.io" -and $script:WizCloudUrl -eq "") {
        $script:WizCloudUrl = $candidateUrl
      }
      if ($script:WizUrl -eq "") {
        $script:WizUrl = $candidateUrl
      }
    }
  }

  $pkgName = ""
  $pkgVersion = "-"
  if ($Node.type -and $Node.type.name) { $pkgName = [string]$Node.type.name }
  elseif ($Node.name) { $pkgName = [string]$Node.name }
  $pkgName = $pkgName.Trim()
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
  if (-not [string]::IsNullOrWhiteSpace($pkgName) -and $total -gt 0) {
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
        $rawCve = [string]$finding.cves[0]
        $normalized = Normalize-CveIdentifier -Text $rawCve
        if ($normalized) { $cve = $normalized }
      } elseif ($finding.id) {
        $normalized = Normalize-CveIdentifier -Text ([string]$finding.id)
        if ($normalized) { $cve = $normalized }
      }

      if ($cve -eq "UNKNOWN-CVE") {
        $foundCve = Find-PropertyValueRecursive -Node $finding -PropertyNames @("cve", "cves", "cveId", "cveID", "vulnerabilityId", "vulnerabilityID", "id") -Visited ([System.Collections.Generic.HashSet[string]]::new())
        $normalized = Normalize-CveIdentifier -Text ([string]$foundCve)
        if ($normalized) { $cve = $normalized }
      }

      $currentVersion = Find-PropertyValueRecursive -Node $finding -PropertyNames @("currentVersion", "installedVersion", "packageVersion", "version", "current", "installed") -Visited ([System.Collections.Generic.HashSet[string]]::new())
      if (-not $currentVersion) { $currentVersion = $pkgVersion }
      $fixedVersion = Find-PropertyValueRecursive -Node $finding -PropertyNames @("fixedVersion", "fixedVersions", "patchedVersion", "upgradeVersion", "safeVersion", "recommendedVersion", "remediationVersion") -Visited ([System.Collections.Generic.HashSet[string]]::new())
      if (-not $fixedVersion) { $fixedVersion = "unknown-fixed-version" }

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
        currentVersion = $currentVersion
        fixedVersion = $fixedVersion
        cve = $cve
        issueId = $cve
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

function Merge-DetailedFindingsFromSarif {
  param($SarifObject)

  if ($null -eq $SarifObject -or -not $SarifObject.runs -or $SarifObject.runs.Count -eq 0) { return }

  $run = $SarifObject.runs[0]
  if (-not $run.results) { return }

  $ruleHelpById = @{}
  if ($run.tool -and $run.tool.driver -and $run.tool.driver.rules) {
    foreach ($rule in $run.tool.driver.rules) {
      if ($rule.id) {
        $helpText = ""
        if ($rule.help -and $rule.help.text) { $helpText = [string]$rule.help.text }
        $helpUri = ""
        if ($rule.helpUri) { $helpUri = [string]$rule.helpUri }
        $ruleHelpById[[string]$rule.id] = [ordered]@{ help = $helpText; helpUri = $helpUri }
      }
    }
  }

  $existing = [System.Collections.Generic.HashSet[string]]::new()
  foreach ($f in $script:DetailedFindings) {
    $k = "$(Get-NonEmptyString $f.package 'unknown-package')|$(Get-NonEmptyString $f.version '-')|$(Get-NonEmptyString $f.cve 'UNKNOWN-CVE')"
    $null = $existing.Add($k)
  }

  foreach ($r in $run.results) {
    $ruleId = Get-NonEmptyString $r.ruleId ""
    $messageText = ""
    if ($r.message -and $r.message.text) { $messageText = [string]$r.message.text }

    $cve = Normalize-CveIdentifier -Text $ruleId
    if (-not $cve) { $cve = Normalize-CveIdentifier -Text $messageText }
    if (-not $cve) {
      if (-not [string]::IsNullOrWhiteSpace($ruleId)) { $cve = $ruleId }
      else { $cve = "UNKNOWN-CVE" }
    }

    $package = "unknown-package"
    $version = "-"
    $currentVersion = "-"
    $fixedVersion = "unknown-fixed-version"

    $pkgMatch = [regex]::Match($messageText, "Package:\s*([^@\r\n]+)@([^\r\n]+)")
    if ($pkgMatch.Success) {
      $package = Get-NonEmptyString $pkgMatch.Groups[1].Value "unknown-package"
      $version = Get-NonEmptyString $pkgMatch.Groups[2].Value "-"
      $currentVersion = $version
    }

    $currentMatch = [regex]::Match($messageText, "Current\s+version:\s*([^\r\n]+)")
    if ($currentMatch.Success) {
      $currentVersion = Get-NonEmptyString $currentMatch.Groups[1].Value $currentVersion
    }

    $fixedMatch = [regex]::Match($messageText, "Fixed\s+version:\s*([^\r\n]+)")
    if ($fixedMatch.Success) {
      $fixedVersion = Get-NonEmptyString $fixedMatch.Groups[1].Value $fixedVersion
    }

    $sevCounts = Parse-SeverityCountsFromText -Text $messageText
    $critical = [int]$sevCounts.critical
    $high = [int]$sevCounts.high
    $medium = [int]$sevCounts.medium
    $low = [int]$sevCounts.low

    if (($critical + $high + $medium + $low) -eq 0) {
      $lvl = Get-NonEmptyString $r.level "note"
      switch ($lvl) {
        "error" { $high = 1 }
        "warning" { $medium = 1 }
        default { $low = 1 }
      }
    }

    $remediation = "Use your package manager to upgrade this package to a fixed version."
    $fixMatch = [regex]::Match($messageText, "Fix guidance:\s*([^\r\n]+)")
    if ($fixMatch.Success) {
      $remediation = Get-NonEmptyString $fixMatch.Groups[1].Value $remediation
    }

    $referenceUrl = ""
    if ($ruleId -and $ruleHelpById.ContainsKey($ruleId)) {
      $ruleHelp = $ruleHelpById[$ruleId]
      if ($ruleHelp.helpUri) { $referenceUrl = [string]$ruleHelp.helpUri }
      if (-not $referenceUrl -and $ruleHelp.help) { $referenceUrl = Extract-FirstUrl -Text ([string]$ruleHelp.help) }
    }
    if (-not $referenceUrl) { $referenceUrl = Extract-FirstUrl -Text $messageText }
    if (-not $referenceUrl) {
      $normalizedCve = Normalize-CveIdentifier -Text $cve
      if ($normalizedCve) { $referenceUrl = "https://nvd.nist.gov/vuln/detail/$normalizedCve" }
    }

    $key = "$package|$version|$cve"
    if ($existing.Contains($key)) { continue }
    $null = $existing.Add($key)

    $script:DetailedFindings.Add([ordered]@{
      package = $package
      version = $version
      currentVersion = $currentVersion
      fixedVersion = $fixedVersion
      cve = $cve
      issueId = (Get-StableIssueId -Primary $ruleId -Fallback $cve -Package $package -Version $version)
      sourceRuleId = $ruleId
      critical = $critical
      high = $high
      medium = $medium
      low = $low
      total = ($critical + $high + $medium + $low)
      remediation = $remediation
      referenceUrl = $referenceUrl
    })
  }
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

$jsonFindingCount = $script:DetailedFindings.Count

$wizSarif = Get-JsonObject -Path $WizSarifPath
if ($wizSarif) {
  Merge-DetailedFindingsFromSarif -SarifObject $wizSarif
}
$sarifEnrichedCount = $script:DetailedFindings.Count - $jsonFindingCount
if ($sarifEnrichedCount -lt 0) { $sarifEnrichedCount = 0 }

if ($script:WizCloudUrl) {
  $script:WizUrl = $script:WizCloudUrl
} elseif ($GitHubRunUrl -and $script:WizUrl -eq "") {
  $script:WizUrl = $GitHubRunUrl
}

$rowFallbackCount = 0

$rows = $script:Packages.Values |
  Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_.package) -and [int]$_.total -gt 0 } |
  Sort-Object -Property total -Descending

if ($rows.Count -eq 0 -and $script:DetailedFindings.Count -gt 0) {
  $agg = @{}
  foreach ($f in $script:DetailedFindings) {
    $pkg = Get-NonEmptyString $f.package "unknown-package"
    $ver = Get-NonEmptyString $f.version "-"
    $k = "$pkg@$ver"
    if (-not $agg.ContainsKey($k)) {
      $agg[$k] = [ordered]@{ package = $pkg; version = $ver; critical = 0; high = 0; medium = 0; low = 0; total = 0 }
    }
    $agg[$k].critical += [int](Get-NormalizedInt $f.critical)
    $agg[$k].high += [int](Get-NormalizedInt $f.high)
    $agg[$k].medium += [int](Get-NormalizedInt $f.medium)
    $agg[$k].low += [int](Get-NormalizedInt $f.low)
    $agg[$k].total += [int](Get-NormalizedInt $f.total)
  }
  $rows = $agg.Values | Sort-Object -Property total -Descending
}

if ($script:DetailedFindings.Count -eq 0) {
  foreach ($r in $rows) {
    $pkg = Get-MapString -Obj $r -Key "package" -Default "unknown-package"
    $ver = Get-MapString -Obj $r -Key "version" -Default "-"
    $criticalVal = Get-MapInt -Obj $r -Key "critical"
    $highVal = Get-MapInt -Obj $r -Key "high"
    $mediumVal = Get-MapInt -Obj $r -Key "medium"
    $lowVal = Get-MapInt -Obj $r -Key "low"
    $totalVal = Get-MapInt -Obj $r -Key "total"
    if ($totalVal -le 0) { continue }
    $rowFallbackCount += 1
    $fallbackIssueId = Get-StableIssueId -Primary "" -Fallback "" -Package $pkg -Version $ver
    $script:DetailedFindings.Add([ordered]@{
      package = $pkg
      version = $ver
      currentVersion = $ver
      fixedVersion = "unknown-fixed-version"
      cve = $fallbackIssueId
      issueId = $fallbackIssueId
      critical = $criticalVal
      high = $highVal
      medium = $mediumVal
      low = $lowVal
      total = $totalVal
      remediation = "Use your package manager to upgrade this package to a fixed version."
      referenceUrl = $(if ($script:WizUrl) { $script:WizUrl } else { "" })
    })
  }
}
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
Write-Host "PARSER_COUNTS: json_findings=$jsonFindingCount sarif_enriched=$sarifEnrichedCount total_findings=$($script:DetailedFindings.Count)"
Write-Host "PARSER_FALLBACK: package_rows=$($rows.Count) row_enriched_findings=$rowFallbackCount"

if ($script:WizUrl) {
  Write-Host "WIZ_SCAN_URL: $($script:WizUrl)"
}

if ($script:Verdict -notin @("PASS", "SUCCESS")) {
  Write-Host (("{0}[31m{1}{0}[0m" -f $esc, $AppSecContact))
}

Write-Host "===== TOP PACKAGES BY VULNERABILITY COUNT ====="
$packageRowsForDisplay = @()
foreach ($r in $rows) {
  $pkg = Get-MapString -Obj $r -Key "package" -Default ""
  $ver = Get-MapString -Obj $r -Key "version" -Default "-"
  $criticalVal = Get-MapInt -Obj $r -Key "critical"
  $highVal = Get-MapInt -Obj $r -Key "high"
  $mediumVal = Get-MapInt -Obj $r -Key "medium"
  $lowVal = Get-MapInt -Obj $r -Key "low"
  $totalVal = Get-MapInt -Obj $r -Key "total"
  if ([string]::IsNullOrWhiteSpace($pkg) -or $totalVal -le 0) { continue }
  $packageRowsForDisplay += [pscustomobject]@{
    package = $pkg
    version = $ver
    critical = $criticalVal
    high = $highVal
    medium = $mediumVal
    low = $lowVal
    total = $totalVal
  }
}

if ($packageRowsForDisplay.Count -eq 0) {
  Write-Host "No package breakdown found in Wiz JSON. Using rule-level fallback from SARIF results."
} else {
  $packageRowsForDisplay | Select-Object -First 50 package, version, critical, high, medium, low, total | Format-Table -AutoSize | Out-String | Write-Host
}

Write-Host "===== DETAILED FINDINGS ====="
$detailRows = $script:DetailedFindings | Sort-Object -Property total -Descending | Select-Object -First 150
if ($detailRows.Count -eq 0) {
  Write-Host "No detailed findings were parsed from the Wiz JSON payload."
} else {
  $header = @("PACKAGE", "ISSUE", "SEVERITY", "CURRENT VERSION", "FIXED VERSION", "CRITICAL", "HIGH", "MEDIUM", "LOW", "REFERENCE", "FIX")
  $header -join " | " | Write-Host
  ("-" * 220) | Write-Host
  foreach ($finding in $detailRows) {
    $sev = Get-MaxSeverityLabel -Critical $finding.critical -High $finding.high -Medium $finding.medium -Low $finding.low
    $sevText = Get-ColorizedSeverity -Severity $sev
    $fix = $finding.remediation
    if ($fix.Length -gt 120) { $fix = $fix.Substring(0, 117) + "..." }
    $current = if ($finding.currentVersion) { $finding.currentVersion } else { $finding.version }
    $fixed = if ($finding.fixedVersion) { $finding.fixedVersion } else { "unknown-fixed-version" }
    $guidance = Get-UpgradeGuidance -CurrentVersion $current -FixedVersion $fixed -Remediation $fix
    $refUrl = Get-NonEmptyString $finding.referenceUrl ""
    $issue = Get-StableIssueId -Primary (Get-NonEmptyString $finding.issueId "") -Fallback (Get-NonEmptyString $finding.cve "") -Package (Get-NonEmptyString $finding.package "unknown-package") -Version (Get-NonEmptyString $finding.version "-")
    if ($refUrl) { $guidance = "$guidance Ref: $refUrl" }
    @(
      $finding.package,
      $issue,
      $sevText,
      $current,
      $fixed,
      $finding.critical,
      $finding.high,
      $finding.medium,
      $finding.low,
      $(if ($refUrl) { $refUrl } else { "n/a" }),
      $guidance
    ) -join " | " | Write-Host
  }
}

$rules = @{}
$results = [System.Collections.Generic.List[object]]::new()

foreach ($f in $script:DetailedFindings) {
  if ($f.total -le 0) { continue }
  $sev = Get-MaxSeverityLabel -Critical $f.critical -High $f.high -Medium $f.medium -Low $f.low
  $level = Get-SarifLevel -Severity $sev
  $pkgShort = Get-ShortPackage -Name $f.package
  $issueId = Get-StableIssueId -Primary (Get-NonEmptyString $f.issueId "") -Fallback (Get-NonEmptyString $f.cve "") -Package (Get-NonEmptyString $f.package "unknown-package") -Version (Get-NonEmptyString $f.version "-")
  $cve = Normalize-CveIdentifier -Text $issueId
  $currentVersion = if ($f.currentVersion) { [string]$f.currentVersion } else { [string]$f.version }
  $fixedVersion = if ($f.fixedVersion) { [string]$f.fixedVersion } else { "unknown-fixed-version" }
  $upgradeGuidance = Get-UpgradeGuidance -CurrentVersion $currentVersion -FixedVersion $fixedVersion -Remediation $f.remediation
  $referenceUrl = Get-NonEmptyString $f.referenceUrl ""
  if (-not $referenceUrl) {
    $normalizedCveForRef = Normalize-CveIdentifier -Text $issueId
    if ($normalizedCveForRef) { $referenceUrl = "https://nvd.nist.gov/vuln/detail/$normalizedCveForRef" }
    elseif ($script:WizUrl) { $referenceUrl = $script:WizUrl }
  }
  $subject = "[Wiz-Cloud-Scan] $issueId $pkgShort"
  $ruleId = $issueId

  $helpText = "Current version: $currentVersion`nFixed version: $fixedVersion`nFix guidance: $upgradeGuidance"
  if ($referenceUrl) { $helpText += "`nReference: $referenceUrl" }
  if ($script:WizUrl) { $helpText += "`nWiz Portal URL: $($script:WizUrl)" }
  $helpText += "`n$AppSecContact"

  if (-not $rules.ContainsKey($ruleId)) {
    $rules[$ruleId] = [ordered]@{
      id = $ruleId
      shortDescription = @{ text = $subject }
      fullDescription = @{ text = "Container vulnerability detected by Wiz for package $($f.package). Current version: $currentVersion. Fixed version: $fixedVersion." }
      defaultConfiguration = @{ level = $level }
      help = @{ text = $helpText }
    }
  }

  $msg = @(
    $subject,
    "Package: $($f.package)@$($f.version)",
    "Issue ID: $issueId",
    "Current version: $currentVersion",
    "Fixed version: $fixedVersion",
    "Severity counts: critical=$($f.critical), high=$($f.high), medium=$($f.medium), low=$($f.low)",
    "Fix guidance: $upgradeGuidance",
    "Wiz verdict: $($script:Verdict)",
    $AppSecContact
  )
  if ($referenceUrl) { $msg += "Reference: $referenceUrl" }
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
      currentVersion = $currentVersion
      fixedVersion = $fixedVersion
      upgradeGuidance = $upgradeGuidance
      referenceUrl = $referenceUrl
      cve = $(if ($cve) { $cve } else { "" })
      issueId = $issueId
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
    message = @{ text = "$subject`nVerdict: $($script:Verdict)`nCurrent version: unknown`nFixed version: unknown-fixed-version`n$AppSecContact" }
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
$md += "| Package | Current Version | Fixed Version | Critical | High | Medium | Low | Total |"
$md += "|---|---:|---:|---:|---:|---:|---:|---:|"

$fixedVersionByPackageKey = @{}
foreach ($f in $script:DetailedFindings) {
  if (-not $f.package -or -not $f.version) { continue }
  if (-not $f.fixedVersion -or $f.fixedVersion -eq "unknown-fixed-version") { continue }
  $fixedVersionByPackageKey["$($f.package)@$($f.version)"] = [string]$f.fixedVersion
}

foreach ($r in ($rows | Select-Object -First 100)) {
  $pkgKey = "$($r.package)@$($r.version)"
  $mdFixedVersion = "unknown-fixed-version"
  if ($fixedVersionByPackageKey.ContainsKey($pkgKey)) {
    $mdFixedVersion = $fixedVersionByPackageKey[$pkgKey]
  }
  $md += "| $($r.package) | $($r.version) | $mdFixedVersion | $($r.critical) | $($r.high) | $($r.medium) | $($r.low) | $($r.total) |"
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
exit 0

# Note: GitHub Security tab controls severity colors in its own UI.
# This script uses ANSI colors in workflow logs for visual severity emphasis.