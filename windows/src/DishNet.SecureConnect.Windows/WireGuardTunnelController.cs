using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using DishNet.SecureConnect.Core.Session;
using DishNet.SecureConnect.Core.Tunnel;

namespace DishNet.SecureConnect.Windows;

/// <summary>
/// Drives the tunnel through the official WireGuard for Windows tunnel
/// service integration: `wireguard.exe /installtunnelservice &lt;conf&gt;`
/// registers a Windows service named WireGuardTunnel$DishNetOffice that
/// runs as SYSTEM, starts at boot and reconnects by itself. Status comes from
/// the service's named pipe (the same UAPI the WireGuard UI uses).
/// No cryptography or protocol code lives here.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WireGuardTunnelController : ITunnelController
{
    public const string ServiceName = "WireGuardTunnel$" + TunnelConfigRenderer.TunnelName;
    private static readonly string PipeName = @"ProtectedPrefix\Administrators\WireGuard\" + TunnelConfigRenderer.TunnelName;

    private readonly string _wireGuardExe;
    private readonly string _confPath;
    private readonly AppLog _log;

    public WireGuardTunnelController(AppLog log, string? wireGuardExe = null, string? confPath = null)
    {
        _log = log;
        _wireGuardExe = wireGuardExe ?? Paths.WireGuardExe;
        _confPath = confPath ?? Paths.TunnelConfigFile;
    }

    public bool IsWireGuardInstalled => File.Exists(_wireGuardExe);

    public async Task StartAsync(string configText, CancellationToken ct)
    {
        if (!IsWireGuardInstalled) throw new InvalidOperationException("The WireGuard tunnel component is not installed. Please reinstall DishNet Secure Connect.");
        Paths.EnsureDataDir();
        WriteProtectedConfig(configText);
        // (Re)install so a changed configuration is picked up; the service name is derived from the file name.
        if (ServiceExists())
        {
            await RunWireGuardAsync($"/uninstalltunnelservice {TunnelConfigRenderer.TunnelName}", ct);
            await WaitForServiceGoneAsync(ct);
        }
        await RunWireGuardAsync($"/installtunnelservice \"{_confPath}\"", ct);
        _log.Info("tunnel service installed and started");
    }

    public async Task StopAsync(CancellationToken ct)
    {
        if (!ServiceExists()) return;
        await RunWireGuardAsync($"/uninstalltunnelservice {TunnelConfigRenderer.TunnelName}", ct);
        await WaitForServiceGoneAsync(ct);
        _log.Info("tunnel service stopped");
    }

    public async Task RemoveAsync(CancellationToken ct)
    {
        await StopAsync(ct);
        if (File.Exists(_confPath))
        {
            File.WriteAllBytes(_confPath, new byte[new FileInfo(_confPath).Length]);
            File.Delete(_confPath);
        }
    }

    public async Task<TunnelStatus> GetStatusAsync(CancellationToken ct)
    {
        if (!ServiceRunning()) return TunnelStatus.Down;
        try
        {
            var kv = await QueryPipeAsync(ct);
            DateTimeOffset? hs = null;
            if (kv.TryGetValue("last_handshake_time_sec", out var secStr) && long.TryParse(secStr, out var sec) && sec > 0)
                hs = DateTimeOffset.FromUnixTimeSeconds(sec);
            kv.TryGetValue("rx_bytes", out var rx);
            kv.TryGetValue("tx_bytes", out var tx);
            kv.TryGetValue("endpoint", out var ep);
            return new TunnelStatus(true, hs, long.TryParse(rx, out var r) ? r : 0, long.TryParse(tx, out var t) ? t : 0, ep);
        }
        catch (Exception ex) when (ex is IOException or System.TimeoutException or UnauthorizedAccessException)
        {
            _log.Warn("status pipe unavailable: " + ex.Message);
            return new TunnelStatus(true, null, 0, 0, null);
        }
    }

    // ---------- helpers ----------

    /// <summary>Writes the config readable only by SYSTEM and Administrators (same posture as WireGuard's own configuration store).</summary>
    private void WriteProtectedConfig(string text)
    {
        var tmp = _confPath + ".tmp";
        File.WriteAllBytes(tmp, Encoding.ASCII.GetBytes(text));
        try
        {
            // SetAccessControl needs a handle opened with WRITE_DAC; FileInfo does that itself,
            // a plain FileStream opened for writing does not ("Attempted to perform an unauthorized operation").
            var sec = new FileSecurity();
            sec.SetAccessRuleProtection(true, false);
            sec.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), FileSystemRights.FullControl, AccessControlType.Allow));
            sec.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), FileSystemRights.FullControl, AccessControlType.Allow));
            new FileInfo(tmp).SetAccessControl(sec);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            // The data directory itself is already restricted to SYSTEM + Administrators, so this is defence in depth, not a blocker.
            _log.Warn("could not tighten config ACL: " + ex.Message);
        }
        File.Move(tmp, _confPath, overwrite: true);
    }

    private async Task RunWireGuardAsync(string args, CancellationToken ct)
    {
        var psi = new ProcessStartInfo(_wireGuardExe, args) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardError = true, RedirectStandardOutput = true };
        using var p = Process.Start(psi) ?? throw new InvalidOperationException("Could not start wireguard.exe");
        var stderr = await p.StandardError.ReadToEndAsync(ct);
        await p.WaitForExitAsync(ct);
        if (p.ExitCode != 0)
        {
            _log.Error($"wireguard.exe {args.Split(' ')[0]} failed ({p.ExitCode}): {stderr.Trim()}");
            throw new InvalidOperationException(string.IsNullOrWhiteSpace(stderr) ? $"wireguard.exe exited with code {p.ExitCode}" : stderr.Trim());
        }
    }

    private static bool ServiceExists()
    {
        try { using var sc = new ServiceController(ServiceName); _ = sc.Status; return true; }
        catch (InvalidOperationException) { return false; }
    }

    private static bool ServiceRunning()
    {
        try { using var sc = new ServiceController(ServiceName); return sc.Status == ServiceControllerStatus.Running; }
        catch (InvalidOperationException) { return false; }
    }

    private static async Task WaitForServiceGoneAsync(CancellationToken ct)
    {
        for (var i = 0; i < 50 && ServiceExists(); i++) await Task.Delay(100, ct);
    }

    /// <summary>Speaks the WireGuard UAPI "get=1" over the tunnel's named pipe and returns the peer section as key/values.</summary>
    private static async Task<Dictionary<string, string>> QueryPipeAsync(CancellationToken ct)
    {
        using var pipe = new NamedPipeClientStream(".", PipeName, PipeDirection.InOut);
        await pipe.ConnectAsync(2000, ct);
        var req = Encoding.ASCII.GetBytes("get=1\n\n");
        await pipe.WriteAsync(req, ct);
        using var reader = new StreamReader(pipe, Encoding.ASCII);
        var kv = new Dictionary<string, string>(StringComparer.Ordinal);
        string? line;
        while ((line = await reader.ReadLineAsync(ct)) is not null)
        {
            if (line.Length == 0) break;
            var i = line.IndexOf('=');
            if (i > 0) kv[line[..i]] = line[(i + 1)..];
        }
        return kv;
    }
}

/// <summary>Minimal rolling log; every line passes through the redactor.</summary>
public sealed class AppLog
{
    private readonly string _path;
    private readonly object _gate = new();

    public AppLog(string path) { _path = path; }

    public void Info(string msg) => Write("INFO", msg);
    public void Warn(string msg) => Write("WARN", msg);
    public void Error(string msg) => Write("ERROR", msg);

    private void Write(string level, string msg)
    {
        var line = $"{DateTimeOffset.UtcNow:yyyy-MM-ddTHH:mm:ssZ} {level} {Core.Diagnostics.Redactor.Redact(msg)}{Environment.NewLine}";
        lock (_gate)
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
                if (File.Exists(_path) && new FileInfo(_path).Length > 1_000_000) File.Move(_path, _path + ".1", overwrite: true);
                File.AppendAllText(_path, line);
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
    }

    public string Tail(int maxBytes = 200_000)
    {
        try
        {
            if (!File.Exists(_path)) return "";
            var all = File.ReadAllText(_path);
            return all.Length <= maxBytes ? all : all[^maxBytes..];
        }
        catch (IOException) { return ""; }
    }
}
