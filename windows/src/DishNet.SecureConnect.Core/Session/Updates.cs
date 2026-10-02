using DishNet.SecureConnect.Core.Api;

namespace DishNet.SecureConnect.Core.Session;

/// <summary>Decides whether the hub's build is newer than the running one.</summary>
public static class UpdateCheck
{
    public static bool IsNewer(string running, string offered)
    {
        if (!Version.TryParse(Normalise(running), out var a) || !Version.TryParse(Normalise(offered), out var b)) return false;
        return b > a;
    }

    private static string Normalise(string v)
    {
        v = v.Trim().TrimStart('v', 'V');
        var parts = v.Split('.');
        return parts.Length < 2 ? v + ".0" : v;
    }

    /// <summary>Returns the offered build if it is newer and its checksum/URL look sane, else null.</summary>
    public static LatestClient? Evaluate(string runningVersion, LatestClient? offered, string apiOrigin)
    {
        if (offered is null || !IsNewer(runningVersion, offered.Version)) return null;
        if (offered.Sha256.Length != 64 || !Uri.TryCreate(offered.Url, UriKind.Absolute, out var u) || u.Scheme != "https") return null;
        // Only accept downloads from our own hub.
        if (!Uri.TryCreate(apiOrigin, UriKind.Absolute, out var origin) || !string.Equals(u.Host, origin.Host, StringComparison.OrdinalIgnoreCase)) return null;
        return offered;
    }
}

/// <summary>
/// Office-gateway preparation: when this computer is the customer's office
/// server, Remote Desktop must be enabled and the local firewall must admit
/// the VPN range on the allowed ports. Customers will not do this by hand,
/// so the (elevated) app does it. The Windows implementation uses the
/// registry and netsh; tests use a fake.
/// </summary>
public interface IGatewaySetup
{
    /// <summary>Returns a short human summary of what was done, or throws.</summary>
    Task<string> ApplyAsync(IReadOnlyList<int> tcpPorts, string vpnPool, CancellationToken ct);
}
