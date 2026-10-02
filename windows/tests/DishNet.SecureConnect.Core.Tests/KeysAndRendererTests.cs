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

public class InstallLinkTests
{
    [Theory]
    [InlineData(@"C:\Users\bhavin\Downloads\DishNetSecureConnect-Setup-DN-J668-7GMJ-NFW7-XLCP.exe", "DN-J668-7GMJ-NFW7-XLCP")]
    [InlineData(@"C:\Downloads\DishNetSecureConnect-Setup-DN-J668-7GMJ-NFW7-XLCP (1).exe", "DN-J668-7GMJ-NFW7-XLCP")]
    [InlineData("dishnetsecureconnect-setup-dn-j668-7gmj-nfw7-xlcp.exe", "DN-J668-7GMJ-NFW7-XLCP")]
    [InlineData("DishNetSecureConnect-Setup-DNJ6687GMJNFW7XLCP.exe", "DN-J668-7GMJ-NFW7-XLCP")]
    [InlineData(@"C:\Downloads\DishNetSecureConnect-Setup-0.1.0.exe", null)]
    [InlineData("", null)]
    public void ExtractsCodeFromInstallerName(string name, string? want) => Xunit.Assert.Equal(want, DishNet.SecureConnect.Core.Session.InstallLink.ExtractCode(name));

    [Fact]
    public void ParsesCommandLine()
    {
        Xunit.Assert.Equal("DN-J668-7GMJ-NFW7-XLCP", DishNet.SecureConnect.Core.Session.InstallLink.CodeFromArgs(new[] { "/setup", @"C:\x\DishNetSecureConnect-Setup-DN-J668-7GMJ-NFW7-XLCP.exe" }));
        Xunit.Assert.Equal("DN-J668-7GMJ-NFW7-XLCP", DishNet.SecureConnect.Core.Session.InstallLink.CodeFromArgs(new[] { "/code=dn-j668-7gmj-nfw7-xlcp" }));
        Xunit.Assert.Null(DishNet.SecureConnect.Core.Session.InstallLink.CodeFromArgs(new[] { "/minimized" }));
    }

    [Fact]
    public void PlanTextCountsDown()
    {
        var now = new DateTimeOffset(2026, 10, 2, 12, 0, 0, TimeSpan.Zero);
        var trial = new DishNet.SecureConnect.Core.Api.DeviceConfig { Plan = "trial", SubscriptionExpiresAt = "2026-10-25T11:59:59Z" };
        Xunit.Assert.Equal("Free trial — 23 days left", DishNet.SecureConnect.Core.Session.PlanText.Describe(trial, now));
        Xunit.Assert.Equal("Free trial has ended — contact DishNet to continue", DishNet.SecureConnect.Core.Session.PlanText.Describe(trial, now.AddDays(40)));
        var paid = new DishNet.SecureConnect.Core.Api.DeviceConfig { Plan = "paid", SubscriptionExpiresAt = "2027-10-01T00:00:00Z" };
        Xunit.Assert.StartsWith("Subscription active until", DishNet.SecureConnect.Core.Session.PlanText.Describe(paid, now));
        Xunit.Assert.Equal("", DishNet.SecureConnect.Core.Session.PlanText.Describe(new DishNet.SecureConnect.Core.Api.DeviceConfig { Plan = "unlimited" }, now));
    }
}

public class UpdateCheckTests
{
    [Theory]
    [InlineData("0.2.2", "0.2.3", true)]
    [InlineData("0.2.2", "0.2.2", false)]
    [InlineData("0.2.3", "0.2.2", false)]
    [InlineData("0.2.2", "v0.3.0", true)]
    [InlineData("0.2.2", "garbage", false)]
    public void ComparesVersions(string running, string offered, bool want) => Xunit.Assert.Equal(want, DishNet.SecureConnect.Core.Session.UpdateCheck.IsNewer(running, offered));

    [Fact]
    public void OnlyAcceptsOurHubOverHttps()
    {
        var sha = new string('a', 64);
        var ok = new DishNet.SecureConnect.Core.Api.LatestClient { Version = "9.9.9", Url = "https://vpn.dishnetuganda.com/download/DishNetSecureConnect-Setup.exe", Sha256 = sha };
        Xunit.Assert.NotNull(DishNet.SecureConnect.Core.Session.UpdateCheck.Evaluate("0.2.2", ok, "https://vpn.dishnetuganda.com"));
        Xunit.Assert.Null(DishNet.SecureConnect.Core.Session.UpdateCheck.Evaluate("0.2.2", ok with { Url = "https://evil.example/x.exe" }, "https://vpn.dishnetuganda.com"));
        Xunit.Assert.Null(DishNet.SecureConnect.Core.Session.UpdateCheck.Evaluate("0.2.2", ok with { Url = "http://vpn.dishnetuganda.com/x.exe" }, "https://vpn.dishnetuganda.com"));
        Xunit.Assert.Null(DishNet.SecureConnect.Core.Session.UpdateCheck.Evaluate("0.2.2", ok with { Sha256 = "short" }, "https://vpn.dishnetuganda.com"));
        Xunit.Assert.Null(DishNet.SecureConnect.Core.Session.UpdateCheck.Evaluate("9.9.9", ok, "https://vpn.dishnetuganda.com"));
    }
}

public class GatewaySetupHookTests
{
    sealed class FakeGateway : DishNet.SecureConnect.Core.Session.IGatewaySetup
    {
        public IReadOnlyList<int>? Ports; public string? Pool;
        public Task<string> ApplyAsync(IReadOnlyList<int> tcpPorts, string vpnPool, CancellationToken ct) { Ports = tcpPorts; Pool = vpnPool; return Task.FromResult("ok"); }
    }

    [Fact]
    public async Task GatewaySetup_RunsOnlyAfterExplicitConsent()
    {
        var api = new FakeApi
        {
            Handler = (req, _) => req.RequestUri!.AbsolutePath == "/api/v1/activate"
                ? (System.Net.HttpStatusCode.Created, new { device_token = "dnd_t", config = Gw() })
                : (System.Net.HttpStatusCode.OK, Gw()),
        };
        var gw = new FakeGateway();
        var tunnel = new FakeTunnel();
        var store = new DishNet.SecureConnect.Core.Secrets.DeviceIdentityStore(Path.Combine(Path.GetTempPath(), "dn-gw-" + Guid.NewGuid(), "id.bin"), new DishNet.SecureConnect.Core.Secrets.InsecureXorProtector());
        var sm = new DishNet.SecureConnect.Core.Session.SessionManager(new DishNet.SecureConnect.Core.Api.ApiClient(new HttpClient(api) { BaseAddress = new Uri("https://vpn.test") }, "t"), store, tunnel, "https://vpn.test", "win", gateway: gw);
        await sm.ActivateAsync("DN-J668-7GMJ-NFW7-XLCP", "Office", null, default);

        // No consent: the tunnel comes up but Remote Desktop / firewall are NOT touched, and the note says what is pending.
        await sm.ConnectAsync(default);
        Xunit.Assert.True(tunnel.Running);
        Xunit.Assert.Null(gw.Ports);
        Xunit.Assert.Contains("not enabled yet", sm.GatewayNote);

        // Consent given in the app: applied immediately because the tunnel is already up.
        await sm.GrantGatewayConsentAsync(default);
        Xunit.Assert.Equal(new[] { 3389, 9000 }, gw.Ports);
        Xunit.Assert.Equal("10.20.0.0/24", gw.Pool);
        Xunit.Assert.Equal("ok", sm.GatewayNote);
    }

    private static object Gw() => new
    {
        device_id = 2, device_name = "Office", role = "gateway", customer_name = "Kishan Bhai", address = "10.20.0.65/32",
        hub_public_key = "UBCUzaw/MppPOGdTq7FRm2ZGn+TsaTYR8MhtAgv6tVs=", endpoint = "165.227.89.92:51820",
        allowed_ips = new[] { "10.20.0.64/28" }, persistent_keepalive = 25, dns = Array.Empty<string>(), access = Array.Empty<object>(),
        config_version = 1, gateway_ports = new[] { 3389, 9000 }, vpn_pool = "10.20.0.0/24", plan = "trial",
    };
}

public class ChecklistTests
{
    private static readonly DishNet.SecureConnect.Core.Api.DeviceConfig Client = new()
    {
        DeviceName = "Laptop", CustomerName = "Kampala Traders", Role = "client",
        Access = new[] { new DishNet.SecureConnect.Core.Api.AccessTarget { Label = "Office server", Target = "10.20.0.17", Proto = "tcp", Ports = new[] { 3389 } } },
    };
    private static readonly DishNet.SecureConnect.Core.Onboarding.UserSettings Fresh = new();

    [Fact]
    public void NothingIsDoneBeforeActivation()
    {
        var steps = DishNet.SecureConnect.Core.Onboarding.Checklist.Build(false, null, DishNet.SecureConnect.Core.Session.ConnectionState.NotActivated, DishNet.SecureConnect.Core.Onboarding.ProbeResult.NotChecked, Fresh);
        Xunit.Assert.Equal(6, steps.Count);
        Xunit.Assert.All(steps, s => Xunit.Assert.False(s.IsDone));
        Xunit.Assert.StartsWith("Enter your activation code", DishNet.SecureConnect.Core.Onboarding.Checklist.NextAction(steps));
    }

    [Fact]
    public void HandshakeAloneDoesNotMarkOfficeReachable()
    {
        var steps = DishNet.SecureConnect.Core.Onboarding.Checklist.Build(true, Client, DishNet.SecureConnect.Core.Session.ConnectionState.Connected, DishNet.SecureConnect.Core.Onboarding.ProbeResult.NotChecked, Fresh);
        Xunit.Assert.True(steps[2].IsDone);                       // VPN verified by handshake
        Xunit.Assert.False(steps[3].IsDone);                      // office: still being checked
        Xunit.Assert.Equal(DishNet.SecureConnect.Core.Onboarding.StepStatus.Pending, steps[3].Status);
        var reachable = DishNet.SecureConnect.Core.Onboarding.Checklist.Build(true, Client, DishNet.SecureConnect.Core.Session.ConnectionState.Connected, DishNet.SecureConnect.Core.Onboarding.ProbeResult.Reachable, Fresh);
        Xunit.Assert.Equal(DishNet.SecureConnect.Core.Onboarding.StepStatus.Verified, reachable[3].Status);
        var down = DishNet.SecureConnect.Core.Onboarding.Checklist.Build(true, Client, DishNet.SecureConnect.Core.Session.ConnectionState.Connected, DishNet.SecureConnect.Core.Onboarding.ProbeResult.Unreachable, Fresh);
        Xunit.Assert.Equal(DishNet.SecureConnect.Core.Onboarding.StepStatus.Attention, down[3].Status);
        Xunit.Assert.Contains("switched on", down[3].Detail);
    }

    [Fact]
    public void ManualStepsOnlyCompleteWhenCustomerConfirms()
    {
        var steps = DishNet.SecureConnect.Core.Onboarding.Checklist.Build(true, Client, DishNet.SecureConnect.Core.Session.ConnectionState.Connected, DishNet.SecureConnect.Core.Onboarding.ProbeResult.Reachable, Fresh);
        Xunit.Assert.False(steps[4].IsDone); Xunit.Assert.True(steps[4].IsManual);
        Xunit.Assert.False(steps[5].IsDone); Xunit.Assert.True(steps[5].IsManual);
        var confirmed = Fresh with { ConfirmedRdpInstructionsAt = DateTimeOffset.UtcNow, ConfirmedTallyOpenedAt = DateTimeOffset.UtcNow };
        var done = DishNet.SecureConnect.Core.Onboarding.Checklist.Build(true, Client, DishNet.SecureConnect.Core.Session.ConnectionState.Connected, DishNet.SecureConnect.Core.Onboarding.ProbeResult.Reachable, confirmed);
        Xunit.Assert.All(done, s => Xunit.Assert.True(s.IsDone));
        Xunit.Assert.Equal(DishNet.SecureConnect.Core.Onboarding.StepStatus.Confirmed, done[5].Status);
        Xunit.Assert.StartsWith("All set", DishNet.SecureConnect.Core.Onboarding.Checklist.NextAction(done));
    }

    [Fact]
    public void NoOfficeRegistered_IsFlagged()
    {
        var cfg = Client with { Access = Array.Empty<DishNet.SecureConnect.Core.Api.AccessTarget>() };
        var steps = DishNet.SecureConnect.Core.Onboarding.Checklist.Build(true, cfg, DishNet.SecureConnect.Core.Session.ConnectionState.Connected, DishNet.SecureConnect.Core.Onboarding.ProbeResult.NotChecked, Fresh);
        Xunit.Assert.Equal(DishNet.SecureConnect.Core.Onboarding.StepStatus.Attention, steps[3].Status);
        Xunit.Assert.Contains("not registered your office computer", steps[3].Detail);
    }

    [Fact]
    public void SettingsStore_RoundTrips_AndContainsNoSecrets()
    {
        var path = Path.Combine(Path.GetTempPath(), "dn-settings-" + Guid.NewGuid(), "settings.json");
        var store = new DishNet.SecureConnect.Core.Onboarding.UserSettingsStore(path);
        Xunit.Assert.False(store.Current.TourDone);
        store.Update(s => s with { TourCompletedAt = DateTimeOffset.UnixEpoch, GatewayConsentAt = DateTimeOffset.UnixEpoch });
        var again = new DishNet.SecureConnect.Core.Onboarding.UserSettingsStore(path);
        Xunit.Assert.True(again.Current.TourDone);
        Xunit.Assert.True(again.Current.GatewayConsentGiven);
        var raw = File.ReadAllText(path);
        Xunit.Assert.DoesNotContain("key", raw, StringComparison.OrdinalIgnoreCase);
        Xunit.Assert.DoesNotContain("token", raw, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Probe_TargetsOfficeRdpPort_OnlyWhenConnected()
    {
        var api = new FakeApi { Handler = (req, _) => req.RequestUri!.AbsolutePath == "/api/v1/activate" ? (System.Net.HttpStatusCode.Created, new { device_token = "dnd_t", config = FakeApi.Config() }) : (System.Net.HttpStatusCode.OK, FakeApi.Config()) };
        var probe = new DishNet.SecureConnect.Core.Onboarding.FakeReachabilityProbe(DishNet.SecureConnect.Core.Onboarding.ProbeResult.Reachable);
        var tunnel = new FakeTunnel();
        var now = new DateTimeOffset(2026, 10, 2, 12, 0, 0, TimeSpan.Zero);
        var store = new DishNet.SecureConnect.Core.Secrets.DeviceIdentityStore(Path.Combine(Path.GetTempPath(), "dn-probe-" + Guid.NewGuid(), "id.bin"), new DishNet.SecureConnect.Core.Secrets.InsecureXorProtector());
        var sm = new DishNet.SecureConnect.Core.Session.SessionManager(new DishNet.SecureConnect.Core.Api.ApiClient(new HttpClient(api) { BaseAddress = new Uri("https://vpn.test") }, "t"), store, tunnel, "https://vpn.test", "win", () => now, probe: probe);
        await sm.ActivateAsync("DN-J668-7GMJ-NFW7-XLCP", "Laptop", null, default);
        Xunit.Assert.Equal(DishNet.SecureConnect.Core.Onboarding.ProbeResult.NotChecked, await sm.ProbeOfficeAsync(default)); // tunnel down: not probed
        Xunit.Assert.Null(probe.LastTarget);
        await sm.ConnectAsync(default);
        tunnel.Handshake = now;
        Xunit.Assert.Equal(DishNet.SecureConnect.Core.Onboarding.ProbeResult.Reachable, await sm.ProbeOfficeAsync(default));
        Xunit.Assert.Equal(("10.20.0.17", 3389), probe.LastTarget);
        probe.Result = DishNet.SecureConnect.Core.Onboarding.ProbeResult.Unreachable;
        Xunit.Assert.Equal(DishNet.SecureConnect.Core.Onboarding.ProbeResult.Unreachable, await sm.ProbeOfficeAsync(default));
    }
}
