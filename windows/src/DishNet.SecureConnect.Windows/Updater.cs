using System.Diagnostics;
using System.Net.Http;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using DishNet.SecureConnect.Core.Api;

namespace DishNet.SecureConnect.Windows;

/// <summary>
/// Downloads a newer installer from the hub, verifies its SHA-256 against
/// what the hub advertised, and runs it silently. Inno Setup upgrades in
/// place (same AppId), closes and restarts this app, and keeps the device
/// identity and the running tunnel service.
/// </summary>
[SupportedOSPlatform("windows")]
public static class Updater
{
    public static async Task<string> DownloadAsync(HttpClient http, LatestClient latest, IProgress<double>? progress, CancellationToken ct)
    {
        var dir = Path.Combine(Path.GetTempPath(), "DishNetUpdate");
        Directory.CreateDirectory(dir);
        var path = Path.Combine(dir, $"DishNetSecureConnect-Setup-{latest.Version}.exe");
        using (var res = await http.GetAsync(latest.Url, HttpCompletionOption.ResponseHeadersRead, ct))
        {
            res.EnsureSuccessStatusCode();
            var total = res.Content.Headers.ContentLength ?? latest.Size;
            await using var src = await res.Content.ReadAsStreamAsync(ct);
            await using var dst = File.Create(path);
            var buf = new byte[81920];
            long read = 0;
            int n;
            while ((n = await src.ReadAsync(buf, ct)) > 0)
            {
                await dst.WriteAsync(buf.AsMemory(0, n), ct);
                read += n;
                if (total > 0) progress?.Report((double)read / total);
            }
        }
        await using (var f = File.OpenRead(path))
        {
            var sum = Convert.ToHexString(await SHA256.HashDataAsync(f, ct)).ToLowerInvariant();
            if (!string.Equals(sum, latest.Sha256, StringComparison.OrdinalIgnoreCase))
            {
                File.Delete(path);
                throw new InvalidOperationException("The downloaded update is corrupted (checksum mismatch). Please try again later.");
            }
        }
        return path;
    }

    /// <summary>Starts the installer silently; the installer closes this app and relaunches it when done.</summary>
    public static void RunInstaller(string path)
    {
        Process.Start(new ProcessStartInfo(path, "/SILENT /SP- /NORESTART /CLOSEAPPLICATIONS /RESTARTAPPLICATIONS") { UseShellExecute = true });
    }
}
