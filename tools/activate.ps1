<#
.SYNOPSIS
  DishNet Secure Connect — manual activation helper for the pilot (Windows).
  Generates a WireGuard key pair locally, activates the device against the
  management API and writes a tunnel configuration you can import into the
  official WireGuard for Windows client. The private key never leaves this PC.

.USAGE
  Install WireGuard for Windows first: https://www.wireguard.com/install/
  Then in PowerShell (as Administrator):
    powershell -ExecutionPolicy Bypass -File activate.ps1 -Code DN-XXXX-XXXX-XXXX-XXXX -Name "Accounts laptop"
  Gateway (office server) with no LAN:   same command, using the GATEWAY code.
  Gateway advertising an office LAN:     add  -Lan 192.168.10.0/24
#>
param(
  [Parameter(Mandatory=$true)][string]$Code,
  [string]$Name = $env:COMPUTERNAME,
  [string[]]$Lan = @(),
  [string]$Api = "https://vpn.dishnetuganda.com",
  [string]$OutDir = "$env:USERPROFILE\Desktop"
)
$ErrorActionPreference = "Stop"
$wg = "C:\Program Files\WireGuard\wg.exe"
if (-not (Test-Path $wg)) { throw "WireGuard for Windows is not installed ($wg missing). Install it from https://www.wireguard.com/install/" }

$priv = (& $wg genkey).Trim()
$pub  = ($priv | & $wg pubkey).Trim()

$body = @{ code = $Code; public_key = $pub; device_name = $Name; os = (Get-CimInstance Win32_OperatingSystem).Caption; client_version = "manual-0.1" }
if ($Lan.Count -gt 0) { $body.lan_subnets = $Lan }
try {
  $resp = Invoke-RestMethod -Method Post -Uri "$Api/api/v1/activate" -ContentType "application/json" -Body ($body | ConvertTo-Json -Compress)
} catch {
  $msg = $_.ErrorDetails.Message; if (-not $msg) { $msg = $_.Exception.Message }
  throw "Activation failed: $msg"
}
$c = $resp.config
$allowed = ($c.allowed_ips -join ", ")
if (-not $allowed) { $allowed = "" }

$conf = @"
# DishNet Secure Connect — $($c.customer_name) — $($c.device_name) ($($c.role))
# Generated $(Get-Date -Format s). Device token stored separately; do not share this file.
[Interface]
PrivateKey = $priv
Address = $($c.address)

[Peer]
PublicKey = $($c.hub_public_key)
Endpoint = $($c.endpoint)
AllowedIPs = $allowed
PersistentKeepalive = $($c.persistent_keepalive)
"@
$safe = ("dn-" + ($c.device_name -replace '[^A-Za-z0-9]+','-').Trim('-').ToLower()); if ($safe.Length -gt 15) { $safe = $safe.Substring(0,15).TrimEnd('-') }  # tunnel name <= 15 chars
$file = Join-Path $OutDir "$safe.conf"
Set-Content -Path $file -Value $conf -Encoding ASCII
Set-Content -Path (Join-Path $OutDir "$safe.token") -Value $resp.device_token -Encoding ASCII

Write-Host ""
Write-Host "Activated: $($c.device_name) as $($c.role) for $($c.customer_name)" -ForegroundColor Green
Write-Host "VPN address : $($c.address)"
Write-Host "Allowed IPs : $allowed"
if ($c.access) { $c.access | ForEach-Object { Write-Host ("Access      : {0} -> {1} {2} {3}" -f $_.label, $_.target, $_.proto, ($_.ports -join ",")) } }
if (-not $allowed) { Write-Host "NOTE: no targets yet (register the office gateway first, then re-run or wait for the policy)." -ForegroundColor Yellow }
Write-Host ""
Write-Host "Config written: $file"
Write-Host "Import it in WireGuard: Add Tunnel -> Import tunnel(s) from file, then Activate."
