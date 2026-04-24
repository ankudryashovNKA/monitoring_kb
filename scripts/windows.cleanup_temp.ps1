$ErrorActionPreference = 'Stop'
$argsJson = $env:MONITORING_KB_ARGS_JSON
$dryRunEnv = ($env:MONITORING_KB_DRY_RUN -eq 'true')
$obj = @{}
if ($argsJson) {
  try { $obj = $argsJson | ConvertFrom-Json -AsHashtable } catch { $obj = @{} }
}
$dryRun = $true
if ($obj.ContainsKey('dry_run')) { $dryRun = [bool]$obj['dry_run'] }
if ($dryRunEnv) { $dryRun = $true }

$targets = @($env:TEMP, "$env:windir\Temp") | Where-Object { $_ -and (Test-Path $_) }
foreach ($target in $targets) {
  Write-Output "Target: $target DryRun=$dryRun"
  Get-ChildItem -Path $target -Force -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
    if ($dryRun) {
      Write-Output "[DRY-RUN] Would remove $($_.FullName)"
    } else {
      try {
        Remove-Item -Path $_.FullName -Recurse -Force -ErrorAction Stop
        Write-Output "Removed $($_.FullName)"
      } catch {
        Write-Output "Skipped $($_.FullName): $($_.Exception.Message)"
      }
    }
  }
}
