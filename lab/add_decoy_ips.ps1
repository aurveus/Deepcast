# Run ONCE per machine in an ADMINISTRATOR PowerShell:  .\lab\add_decoy_ips.ps1
# Adds the decoy IP pool (DECOY_IP_FIRST..DECOY_IP_LAST from .env) as extra addresses on the
# VMnet1 host adapter, so spawned decoys can appear as new hosts on the lab subnet.
$ErrorActionPreference = "Stop"
$envFile = Join-Path $PSScriptRoot "..\.env"
$cfg = @{}
Get-Content $envFile | Where-Object { $_ -match "^\s*[A-Za-z_]+=" } | ForEach-Object {
    $k, $v = $_ -split "=", 2; $cfg[$k.Trim()] = $v.Trim()
}
$adapter = "VMware Network Adapter VMnet1"
$prefix = ($cfg["DECOY_IP_FIRST"] -split "\.")[0..2] -join "."
$first = [int](($cfg["DECOY_IP_FIRST"] -split "\.")[3])
$last = [int](($cfg["DECOY_IP_LAST"] -split "\.")[3])
foreach ($i in $first..$last) {
    $ip = "$prefix.$i"
    if (Get-NetIPAddress -IPAddress $ip -ErrorAction SilentlyContinue) { Write-Host "$ip already present"; continue }
    New-NetIPAddress -InterfaceAlias $adapter -IPAddress $ip -PrefixLength 24 -SkipAsSource $true | Out-Null
    Write-Host "added $ip"
}
