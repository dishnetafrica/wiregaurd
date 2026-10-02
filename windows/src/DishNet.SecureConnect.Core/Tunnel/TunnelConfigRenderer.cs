using System.Net;
using System.Text;
using DishNet.SecureConnect.Core.Api;

namespace DishNet.SecureConnect.Core.Tunnel;

/// <summary>
/// Turns the API's DeviceConfig plus the locally held private key into the
/// WireGuard configuration text consumed by the tunnel service. Every field
/// is validated so a malformed server response can never produce a tunnel
/// that routes more than intended (e.g. 0.0.0.0/0).
/// </summary>
public static class TunnelConfigRenderer
{
    /// <summary>Tunnel/interface name; WireGuard limits it to 15 characters.</summary>
    public const string TunnelName = "DishNetOffice";

    public static string Render(DeviceConfig cfg, string privateKeyBase64)
    {
        if (!WireGuardKeys.IsValidKey(privateKeyBase64)) throw new TunnelConfigException("Private key is not a valid WireGuard key.");
        if (!WireGuardKeys.IsValidKey(cfg.HubPublicKey)) throw new TunnelConfigException("Server public key is not a valid WireGuard key.");
        var address = ParseHostPrefix(cfg.Address, "Address");
        var endpoint = ParseEndpoint(cfg.Endpoint);
        if (cfg.AllowedIps.Count == 0) throw new TunnelConfigException("No allowed IPs: there is nothing to connect to yet. Ask DishNet to register your office server.");
        var allowed = new List<string>(cfg.AllowedIps.Count);
        foreach (var a in cfg.AllowedIps)
        {
            var p = ParsePrefix(a, "AllowedIPs");
            if (p.PrefixLength < 8) throw new TunnelConfigException($"Refusing to route {a}: too broad for a DishNet tunnel.");
            if (!IsPrivate(p.Address)) throw new TunnelConfigException($"Refusing to route {a}: only private office ranges are allowed.");
            allowed.Add($"{p.Address}/{p.PrefixLength}");
        }
        var keepalive = Math.Clamp(cfg.PersistentKeepalive, 10, 120);

        var sb = new StringBuilder();
        sb.Append("[Interface]\n");
        sb.Append("PrivateKey = ").Append(privateKeyBase64).Append('\n');
        sb.Append("Address = ").Append(address).Append('\n');
        if (cfg.Dns.Count > 0)
        {
            var dns = cfg.Dns.Select(d => IPAddress.TryParse(d, out var ip) ? ip.ToString() : throw new TunnelConfigException($"Invalid DNS server {d}"));
            sb.Append("DNS = ").Append(string.Join(", ", dns)).Append('\n');
        }
        sb.Append('\n');
        sb.Append("[Peer]\n");
        sb.Append("PublicKey = ").Append(cfg.HubPublicKey).Append('\n');
        sb.Append("Endpoint = ").Append(endpoint).Append('\n');
        sb.Append("AllowedIPs = ").Append(string.Join(", ", allowed)).Append('\n');
        sb.Append("PersistentKeepalive = ").Append(keepalive).Append('\n');
        return sb.ToString();
    }

    private static string ParseHostPrefix(string s, string field)
    {
        var p = ParsePrefix(s, field);
        if (p.PrefixLength != 32) throw new TunnelConfigException($"{field} must be a single /32 address.");
        return $"{p.Address}/32";
    }

    private static (IPAddress Address, int PrefixLength) ParsePrefix(string s, string field)
    {
        var parts = (s ?? "").Trim().Split('/');
        if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out var ip) || ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork
            || !int.TryParse(parts[1], out var len) || len < 0 || len > 32)
            throw new TunnelConfigException($"{field} '{s}' is not a valid IPv4 CIDR.");
        return (ip, len);
    }

    private static string ParseEndpoint(string s)
    {
        var idx = (s ?? "").LastIndexOf(':');
        if (idx <= 0) throw new TunnelConfigException("Endpoint must be host:port.");
        var host = s![..idx];
        if (!int.TryParse(s[(idx + 1)..], out var port) || port < 1 || port > 65535) throw new TunnelConfigException("Endpoint port is invalid.");
        if (!IPAddress.TryParse(host, out _) && Uri.CheckHostName(host) != UriHostNameType.Dns) throw new TunnelConfigException("Endpoint host is invalid.");
        return $"{host}:{port}";
    }

    private static bool IsPrivate(IPAddress ip)
    {
        var b = ip.GetAddressBytes();
        return b[0] == 10 || (b[0] == 172 && b[1] >= 16 && b[1] <= 31) || (b[0] == 192 && b[1] == 168);
    }
}

public sealed class TunnelConfigException(string message) : Exception(message);
