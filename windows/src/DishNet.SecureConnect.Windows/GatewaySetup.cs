using System.Diagnostics;
using System.Runtime.Versioning;
using System.Text;
using DishNet.SecureConnect.Core.Session;
using Microsoft.Win32;

namespace DishNet.SecureConnect.Windows;

/// <summary>
/// Prepares this PC to be the customer's office server: enables Remote
/// Desktop, enables Windows' built-in "Remote Desktop" firewall group, and
/// adds inbound rules for the ports DishNet policies allow — scoped to the
/// VPN range only, so nothing is opened to the office LAN or the internet
/// that was not open before. Idempotent; safe to run on every Connect.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsGatewaySetup : IGatewaySetup
{
    private const string RulePrefix = "DishNet VPN - port ";
    private readonly AppLog _log;

    public WindowsGatewaySetup(AppLog log) { _log = log; }

    public async Task<string> ApplyAsync(IReadOnlyList<int> tcpPorts, string vpnPool, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(vpnPool) || !System.Net.IPNetwork.TryParse(vpnPool, out _)) throw new ArgumentException("invalid VPN range from server");
        var done = new StringBuilder();

        if (tcpPorts.Contains(3389))
        {
            // Remote Desktop on, Network Level Authentication left as configured (default on).
            using var ts = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Terminal Server", writable: true)
                ?? throw new InvalidOperationException("Terminal Server registry key missing");
            if ((int?)ts.GetValue("fDenyTSConnections") != 0)
            {
                ts.SetValue("fDenyTSConnections", 0, RegistryValueKind.DWord);
                done.Append("Remote Desktop enabled. ");
            }
            await NetshAsync("advfirewall firewall set rule group=\"Remote Desktop\" new enable=Yes", ct, ignoreFailure: true);
        }

        foreach (var port in tcpPorts.Distinct())
        {
            if (port < 1 || port > 65535) continue;
            var name = RulePrefix + port;
            // Replace so a changed VPN range is picked up.
            await NetshAsync($"advfirewall firewall delete rule name=\"{name}\"", ct, ignoreFailure: true);
            await NetshAsync($"advfirewall firewall add rule name=\"{name}\" dir=in action=allow protocol=TCP localport={port} remoteip={vpnPool} profile=any enable=yes description=\"Allows DishNet Secure Connect users to reach this office server\"", ct, ignoreFailure: false);
        }
        done.Append(tcpPorts.Count == 0 ? "No ports allowed yet — DishNet will add them." : $"Firewall allows DishNet users on port{(tcpPorts.Count > 1 ? "s" : "")} {string.Join(", ", tcpPorts)}.");
        _log.Info("gateway setup: " + done);
        return done.ToString().Trim();
    }

    private static async Task NetshAsync(string args, CancellationToken ct, bool ignoreFailure)
    {
        var psi = new ProcessStartInfo("netsh.exe", args) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        using var p = Process.Start(psi) ?? throw new InvalidOperationException("netsh not found");
        var output = await p.StandardOutput.ReadToEndAsync(ct);
        await p.WaitForExitAsync(ct);
        if (p.ExitCode != 0 && !ignoreFailure) throw new InvalidOperationException($"netsh failed ({p.ExitCode}): {output.Trim()}");
    }
}
