$ErrorActionPreference = 'Stop'
Write-Output "[diagnose] logical disks"
Get-PSDrive -PSProvider FileSystem | Select-Object Name, Used, Free
Write-Output "[diagnose] temp/log directories"
$targets = @($env:TEMP, "$env:windir\Temp", "C:\Windows\Logs") | Where-Object { $_ -and (Test-Path $_) }
foreach ($t in $targets) {
  Write-Output "Target: $t"
  Get-ChildItem -Path $t -Force -ErrorAction SilentlyContinue | Sort-Object Length -Descending | Select-Object -First 20 FullName, Length
}
