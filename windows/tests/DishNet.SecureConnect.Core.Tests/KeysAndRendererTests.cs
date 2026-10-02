using DishNet.SecureConnect.Core.Api;
using DishNet.SecureConnect.Core.Diagnostics;
using DishNet.SecureConnect.Core.Tunnel;
using Xunit;

namespace DishNet.SecureConnect.Core.Tests;

public class WireGuardKeysTests
{
    [Fact]
    public void Rfc7748_TestVector_PublicKeyDerivation()
    {
        // RFC 7748 §6.1: Alice's private key -> public key.
        var priv = Convert.ToBase64String(Convert.FromHexString("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"));
        var pub = WireGuardKeys.PublicKeyFromPrivate(priv);
        Assert.Equal("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a", Convert.ToHexString(Convert.FromBase64String(pub)).ToLowerInvariant());
    }

    [Fact]
    public void Generate_ProducesValidDistinctKeys()
    {
        var a = WireGuardKeys.Generate();
        var b = WireGuardKeys.Generate();
        Assert.True(WireGuardKeys.IsValidKey(a.PrivateKey));
        Assert.True(WireGuardKeys.IsValidKey(a.PublicKey));
        Assert.NotEqual(a.PrivateKey, b.PrivateKey);
        Assert.Equal(a.PublicKey, WireGuardKeys.PublicKeyFromPrivate(a.PrivateKey));
        // Clamped as WireGuard expects.
        var raw = Convert.FromBase64String(a.PrivateKey);
        Assert.Equal(0, raw[0] & 7);
        Assert.Equal(64, raw[31] & 192);
    }

    [Theory]
    [InlineData("")]
    [InlineData("not-base64")]
    [InlineData("AAAA")]
    [InlineData("UBCUzaw/MppPOGdTq7FRm2ZGn+TsaTYR8MhtAgv6tV")] // 42 chars
    public void IsValidKey_RejectsGarbage(string s) => Assert.False(WireGuardKeys.IsValidKey(s));

    [Fact]
    public void IsValidKey_AcceptsHubKey() => Assert.True(WireGuardKeys.IsValidKey("UBCUzaw/MppPOGdTq7FRm2ZGn+TsaTYR8MhtAgv6tVs="));
}

public class TunnelConfigRendererTests
{
    private static readonly string Priv = WireGuardKeys.Generate().PrivateKey;

    private static DeviceConfig Sample() => new()
    {
        DeviceId = 7, DeviceName = "Accounts laptop", Role = "client", CustomerName = "Kampala Traders",
        Address = "10.20.0.18/32", HubPublicKey = "UBCUzaw/MppPOGdTq7FRm2ZGn+TsaTYR8MhtAgv6tVs=", Endpoint = "165.227.89.92:51820",
        AllowedIps = new[] { "10.20.0.1/32", "10.20.0.17/32" }, PersistentKeepalive = 25, ConfigVersion = 3,
    };

    [Fact]
    public void Renders_ExactWireGuardText()
    {
        var text = TunnelConfigRenderer.Render(Sample(), Priv);
        var expected = $"[Interface]\nPrivateKey = {Priv}\nAddress = 10.20.0.18/32\n\n[Peer]\nPublicKey = UBCUzaw/MppPOGdTq7FRm2ZGn+TsaTYR8MhtAgv6tVs=\nEndpoint = 165.227.89.92:51820\nAllowedIPs = 10.20.0.1/32, 10.20.0.17/32\nPersistentKeepalive = 25\n";
        Assert.Equal(expected, text);
    }

    [Theory]
    [InlineData("0.0.0.0/0")]       // full tunnel
    [InlineData("8.8.8.0/24")]      // public range
    [InlineData("10.0.0.0/7")]      // too broad
    [InlineData("10.20.0.17")]      // missing prefix
    [InlineData("::/0")]            // IPv6
    public void Refuses_DangerousAllowedIps(string bad)
    {
        var cfg = Sample() with { AllowedIps = new[] { bad } };
        Assert.Throws<TunnelConfigException>(() => TunnelConfigRenderer.Render(cfg, Priv));
    }

    [Fact]
    public void Refuses_BadKeysAddressEndpoint()
    {
        Assert.Throws<TunnelConfigException>(() => TunnelConfigRenderer.Render(Sample(), "nope"));
        Assert.Throws<TunnelConfigException>(() => TunnelConfigRenderer.Render(Sample() with { HubPublicKey = "x" }, Priv));
        Assert.Throws<TunnelConfigException>(() => TunnelConfigRenderer.Render(Sample() with { Address = "10.20.0.0/24" }, Priv));
        Assert.Throws<TunnelConfigException>(() => TunnelConfigRenderer.Render(Sample() with { Endpoint = "165.227.89.92" }, Priv));
        Assert.Throws<TunnelConfigException>(() => TunnelConfigRenderer.Render(Sample() with { Endpoint = "evil host:51820" }, Priv));
        Assert.Throws<TunnelConfigException>(() => TunnelConfigRenderer.Render(Sample() with { AllowedIps = Array.Empty<string>() }, Priv));
    }

    [Fact]
    public void Keepalive_IsClamped_AndDnsRendered()
    {
        var text = TunnelConfigRenderer.Render(Sample() with { PersistentKeepalive = 0, Dns = new[] { "10.20.0.1" } }, Priv);
        Assert.Contains("PersistentKeepalive = 10\n", text);
        Assert.Contains("DNS = 10.20.0.1\n", text);
    }

    [Fact]
    public void TunnelName_FitsWireGuardLimit() => Assert.True(TunnelConfigRenderer.TunnelName.Length <= 15);
}

public class RedactorTests
{
    [Fact]
    public void Strips_PrivateKeysTokensAndCodes()
    {
        var priv = WireGuardKeys.Generate().PrivateKey;
        var input = $"[Interface]\nPrivateKey = {priv}\nAddress = 10.20.0.18/32\n" +
                    "token dnd_ERVVH58FuDlEpoQshA4EtPd3ijCcgkfeMbtZiKVVXrM used; code DN-J668-7GMJ-NFW7-XLCP; {\"device_token\":\"dnd_abcdefghijklmnopqrstuvwxyz\",\"password\":\"hunter2hunter2\"}";
        var out_ = Redactor.Redact(input);
        Assert.DoesNotContain(priv, out_);
        Assert.DoesNotContain("ERVVH58F", out_);
        Assert.DoesNotContain("7GMJ-NFW7", out_);
        Assert.DoesNotContain("hunter2", out_);
        Assert.Contains("Address = 10.20.0.18/32", out_);   // non-secrets survive
        Assert.Contains("DN-J668-<redacted>", out_);        // hint kept for support
    }
}
