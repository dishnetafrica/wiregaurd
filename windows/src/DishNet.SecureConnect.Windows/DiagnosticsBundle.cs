using System.IO.Compression;
using System.Runtime.Versioning;
using System.Text;
using DishNet.SecureConnect.Core.Diagnostics;
using DishNet.SecureConnect.Core.Secrets;
using DishNet.SecureConnect.Core.Session;

namespace DishNet.SecureConnect.Windows;

/// <summary>
/// Builds the zip a customer sends to DishNet support. Contains only
/// redacted, non-secret information: app log, tunnel status, device/customer
/// names, VPN address, OS, and the tunnel configuration with the private key
/// removed. Never the identity file.
/// </summary>
[SupportedOSPlatform("windows")]
public static class DiagnosticsBundle
{
    public static async Task<string> CreateAsync(string outDir, AppLog log, DeviceIdentity? identity, ConnectionState state, TunnelStatus status, string clientVersion, CancellationToken ct)
    {
        Directory.CreateDirectory(outDir);
        var path = Path.Combine(outDir, $"DishNet-diagnostics-{DateTime.Now:yyyyMMdd-HHmm}.zip");
        using var zip = new ZipArchive(File.Create(path), ZipArchiveMode.Create);

        var summary = new StringBuilder();
        summary.AppendLine("DishNet Secure Connect diagnostics");
        summary.AppendLine($"Generated: {DateTimeOffset.Now:O}");
        summary.AppendLine($"Client version: {clientVersion}");
        summary.AppendLine($"OS: {OsInfo.Description()}");
        summary.AppendLine($"Machine: {Environment.MachineName}");
        summary.AppendLine($"State: {state}");
        summary.AppendLine($"Tunnel running: {status.Running}; last handshake: {status.LastHandshake?.ToString("O") ?? "never"}; rx={status.RxBytes} tx={status.TxBytes}; endpoint={status.Endpoint}");
        if (identity is not null)
        {
            summary.AppendLine($"Device: #{identity.DeviceId} {identity.DeviceName} ({identity.Role}) customer={identity.CustomerName}");
            summary.AppendLine($"Public key: {identity.PublicKey}");
            summary.AppendLine($"API: {identity.ApiOrigin}; config version {identity.ConfigVersion}; activated {identity.ActivatedAt:O}");
        }
        else summary.AppendLine("Device: not activated");
        await AddAsync(zip, "summary.txt", summary.ToString(), ct);
        await AddAsync(zip, "app.log", log.Tail(), ct);
        if (File.Exists(Paths.TunnelConfigFile))
            await AddAsync(zip, "tunnel.conf.redacted", await File.ReadAllTextAsync(Paths.TunnelConfigFile, ct), ct);
        // WireGuard's own ring log: shows every handshake attempt and why it failed. Nothing in it is secret (keys are never logged).
        try { await AddAsync(zip, "wireguard-log.txt", File.Exists(Paths.WireGuardExe) ? await RunAsync(Paths.WireGuardExe, "/dumplog", ct) : "wireguard.exe not found", ct); } catch (Exception ex) { await AddAsync(zip, "wireguard-log.txt", "failed: " + ex.Message, ct); }
        try { await AddAsync(zip, "ipconfig.txt", await RunAsync("ipconfig", "/all", ct), ct); } catch (Exception ex) { await AddAsync(zip, "ipconfig.txt", "failed: " + ex.Message, ct); }
        try { await AddAsync(zip, "route.txt", await RunAsync("route", "print", ct), ct); } catch (Exception ex) { await AddAsync(zip, "route.txt", "failed: " + ex.Message, ct); }
        return path;
    }

    private static async Task AddAsync(ZipArchive zip, string name, string content, CancellationToken ct)
    {
        var entry = zip.CreateEntry(name, CompressionLevel.Optimal);
        using var w = new StreamWriter(entry.Open(), Encoding.UTF8);
        await w.WriteAsync(Redactor.Redact(content).AsMemory(), ct); // belt and braces: everything is redacted again here
    }

    private static async Task<string> RunAsync(string exe, string args, CancellationToken ct)
    {
        var psi = new System.Diagnostics.ProcessStartInfo(exe, args) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true };
        using var p = System.Diagnostics.Process.Start(psi)!;
        var out_ = await p.StandardOutput.ReadToEndAsync(ct);
        await p.WaitForExitAsync(ct);
        return out_;
    }
}
