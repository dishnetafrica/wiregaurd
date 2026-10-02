using System.Text.RegularExpressions;
using DishNet.SecureConnect.Core.Api;

namespace DishNet.SecureConnect.Core.Session;

/// <summary>
/// The install link embeds the activation code in the installer's file name
/// (DishNetSecureConnect-Setup-DN-XXXX-XXXX-XXXX-XXXX.exe). The installer
/// passes its own path to the app, which pulls the code back out so the
/// customer never types it. Browsers may rename duplicates ("… (1).exe") and
/// users may lower-case things; both are tolerated.
/// </summary>
public static partial class InstallLink
{
    [GeneratedRegex(@"DN-?([A-Z2-9]{4})-?([A-Z2-9]{4})-?([A-Z2-9]{4})-?([A-Z2-9]{4})", RegexOptions.IgnoreCase)]
    private static partial Regex CodePattern();

    /// <summary>Returns the normalised code found in a file name/path, or null.</summary>
    public static string? ExtractCode(string? fileNameOrPath)
    {
        if (string.IsNullOrWhiteSpace(fileNameOrPath)) return null;
        var name = Path.GetFileName(fileNameOrPath);
        var m = CodePattern().Match(name);
        if (!m.Success) return null;
        return $"DN-{m.Groups[1].Value}-{m.Groups[2].Value}-{m.Groups[3].Value}-{m.Groups[4].Value}".ToUpperInvariant();
    }

    /// <summary>Parses command-line arguments: "/setup &lt;installer path&gt;" or "/code=DN-…".</summary>
    public static string? CodeFromArgs(IReadOnlyList<string> args)
    {
        for (var i = 0; i < args.Count; i++)
        {
            var a = args[i];
            if (a.StartsWith("/code=", StringComparison.OrdinalIgnoreCase)) return ExtractCode(a[6..]) ?? a[6..].Trim();
            if (a.Equals("/setup", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Count) return ExtractCode(args[i + 1]);
        }
        return null;
    }
}

/// <summary>Human text for the plan/expiry shown in the status card.</summary>
public static class PlanText
{
    public static string Describe(DeviceConfig? cfg, DateTimeOffset now)
    {
        if (cfg is null) return "";
        DateTimeOffset? exp = DateTimeOffset.TryParse(cfg.SubscriptionExpiresAt, null, System.Globalization.DateTimeStyles.AssumeUniversal | System.Globalization.DateTimeStyles.AdjustToUniversal, out var e) ? e : null;
        var days = exp is { } x ? (int)Math.Ceiling((x - now).TotalDays) : (int?)null;
        return cfg.Plan switch
        {
            "trial" when days is { } d && d > 0 => d == 1 ? "Free trial — ends tomorrow" : $"Free trial — {d} days left",
            "trial" => "Free trial has ended — contact DishNet to continue",
            "paid" when days is { } d && d > 0 => $"Subscription active until {exp:dd MMM yyyy}",
            "paid" => "Subscription expired — contact DishNet",
            _ => "",
        };
    }
}
