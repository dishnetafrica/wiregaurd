using System.Net;
using System.Text;
using System.Text.Json;
using DishNet.SecureConnect.Core.Api;
using DishNet.SecureConnect.Core.Secrets;
using DishNet.SecureConnect.Core.Session;
using DishNet.SecureConnect.Core.Tunnel;
using Xunit;

namespace DishNet.SecureConnect.Core.Tests;

/// <summary>Scripted fake of the management API: records requests, serves canned responses.</summary>
sealed class FakeApi : HttpMessageHandler
{
    public readonly List<(string Method, string Path, string? Auth, string Body)> Requests = new();
    public Func<HttpRequestMessage, string, (HttpStatusCode, object)> Handler = (_, _) => (HttpStatusCode.NotFound, new { error = "nope", code = "unknown" });
    public bool Offline;

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        if (Offline) throw new HttpRequestException("no route to host");
        var body = request.Content is null ? "" : await request.Content.ReadAsStringAsync(ct);
        Requests.Add((request.Method.Method, request.RequestUri!.AbsolutePath, request.Headers.Authorization?.Parameter, body));
        var (status, payload) = Handler(request, body);
        return new HttpResponseMessage(status) { Content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json") };
    }

    public static object Config(int version = 1, params string[] allowed) => new
    {
        device_id = 12, device_name = "Laptop", role = "client", customer_name = "Kampala Traders", address = "10.20.0.18/32",
        hub_public_key = "UBCUzaw/MppPOGdTq7FRm2ZGn+TsaTYR8MhtAgv6tVs=", endpoint = "165.227.89.92:51820",
        allowed_ips = allowed.Length == 0 ? new[] { "10.20.0.1/32", "10.20.0.17/32" } : allowed,
        persistent_keepalive = 25, dns = Array.Empty<string>(),
        access = new[] { new { label = "Office server", target = "10.20.0.17", proto = "tcp", ports = new[] { 3389 } } },
        config_version = version,
    };
}

sealed class FakeTunnel : ITunnelController
{
    public string? Config;
    public bool Running;
    public bool Removed;
    public DateTimeOffset? Handshake;
    public Task StartAsync(string configText, CancellationToken ct) { Config = configText; Running = true; Removed = false; return Task.CompletedTask; }
    public Task StopAsync(CancellationToken ct) { Running = false; return Task.CompletedTask; }
    public Task RemoveAsync(CancellationToken ct) { Running = false; Removed = true; Config = null; return Task.CompletedTask; }
    public Task<TunnelStatus> GetStatusAsync(CancellationToken ct) => Task.FromResult(new TunnelStatus(Running, Handshake, 100, 200, "165.227.89.92:51820"));
}

public class ApiClientTests
{
    private static ApiClient Client(FakeApi api) => new(new HttpClient(api) { BaseAddress = new Uri("https://vpn.test") }, "test-1.0");

    [Fact]
    public async Task Activate_SendsPublicKeyOnly_AndParsesResponse()
    {
        var api = new FakeApi { Handler = (_, _) => (HttpStatusCode.Created, new { device_token = "dnd_tok", config = FakeApi.Config() }) };
        var res = await Client(api).ActivateAsync("dn-j668-7gmj-nfw7-xlcp", "PUBKEY", "Laptop", "Windows 11", null, default);
        Assert.Equal("dnd_tok", res.DeviceToken);
        Assert.Equal("10.20.0.18/32", res.Config.Address);
        Assert.Equal(2, res.Config.AllowedIps.Count);
        var sent = api.Requests.Single();
        Assert.Equal("/api/v1/activate", sent.Path);
        Assert.Contains("\"public_key\":\"PUBKEY\"", sent.Body);
        Assert.DoesNotContain("private", sent.Body);
        Assert.DoesNotContain("lan_subnets", sent.Body); // omitted when null
    }

    [Theory]
    [InlineData(HttpStatusCode.Unauthorized, "invalid_code", null, ApiFailure.InvalidCode)]
    [InlineData(HttpStatusCode.Conflict, "code_used", null, ApiFailure.CodeUsed)]
    [InlineData(HttpStatusCode.Forbidden, "device_limit", null, ApiFailure.DeviceLimit)]
    [InlineData(HttpStatusCode.TooManyRequests, "rate_limited", null, ApiFailure.RateLimited)]
    [InlineData(HttpStatusCode.Forbidden, "access_denied", "revoked", ApiFailure.AccessDeniedRevoked)]
    [InlineData(HttpStatusCode.Forbidden, "access_denied", "expired", ApiFailure.AccessDeniedExpired)]
    [InlineData(HttpStatusCode.ServiceUnavailable, "provisioning_failed", null, ApiFailure.ProvisioningFailed)]
    public async Task ErrorCodes_MapToTypedFailures(HttpStatusCode status, string code, string? reason, ApiFailure want)
    {
        var api = new FakeApi { Handler = (_, _) => (status, new { error = "msg", code, reason }) };
        var ex = await Assert.ThrowsAsync<ApiException>(() => Client(api).GetConfigAsync("dnd_x", default));
        Assert.Equal(want, ex.Failure);
        Assert.Equal(status, ex.Status);
    }

    [Fact]
    public async Task Offline_IsNetworkFailure_NotTerminal()
    {
        var api = new FakeApi { Offline = true };
        var ex = await Assert.ThrowsAsync<ApiException>(() => Client(api).HeartbeatAsync("dnd_x", true, default));
        Assert.Equal(ApiFailure.Network, ex.Failure);
        Assert.False(ex.IsTerminal);
    }

    [Fact]
    public async Task BearerToken_IsSentOnDeviceCalls()
    {
        var api = new FakeApi { Handler = (_, _) => (HttpStatusCode.OK, new { ok = true, config_version = 4 }) };
        var hb = await Client(api).HeartbeatAsync("dnd_secret", true, default);
        Assert.Equal(4, hb.ConfigVersion);
        Assert.Equal("dnd_secret", api.Requests.Single().Auth);
    }
}

public class DeviceIdentityStoreTests
{
    [Fact]
    public void RoundTrip_ProtectedOnDisk_AndDeleteWipes()
    {
        var path = Path.Combine(Path.GetTempPath(), "dishnet-test-" + Guid.NewGuid() + "/identity.bin");
        var store = new DeviceIdentityStore(path, new InsecureXorProtector());
        Assert.Null(store.Load());
        var keys = WireGuardKeys.Generate();
        var id = new DeviceIdentity { DeviceId = 5, DeviceName = "L", PrivateKey = keys.PrivateKey, PublicKey = keys.PublicKey, DeviceToken = "dnd_abc", ApiOrigin = "https://vpn.test", ConfigVersion = 2, ActivatedAt = DateTimeOffset.UnixEpoch };
        store.Save(id);
        var raw = File.ReadAllText(path);
        Assert.DoesNotContain(keys.PrivateKey, raw);   // not plaintext on disk
        Assert.DoesNotContain("dnd_abc", raw);
        Assert.Equal(id, store.Load());
        store.Delete();
        Assert.False(File.Exists(path));
    }
}

public class ConnectionStateMachineTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 2, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Derives_EveryState()
    {
        var up = new TunnelStatus(true, Now.AddSeconds(-30), 1, 1, null);
        var stale = new TunnelStatus(true, Now.AddMinutes(-10), 1, 1, null);
        var noHs = new TunnelStatus(true, null, 0, 0, null);
        Assert.Equal(ConnectionState.NotActivated, ConnectionStateMachine.Derive(false, false, false, false, TunnelStatus.Down, Now));
        Assert.Equal(ConnectionState.Revoked, ConnectionStateMachine.Derive(true, true, false, true, up, Now));
        Assert.Equal(ConnectionState.Error, ConnectionStateMachine.Derive(true, false, true, false, TunnelStatus.Down, Now));
        Assert.Equal(ConnectionState.Disconnected, ConnectionStateMachine.Derive(true, false, false, false, TunnelStatus.Down, Now));
        Assert.Equal(ConnectionState.Connecting, ConnectionStateMachine.Derive(true, false, false, true, TunnelStatus.Down, Now));
        Assert.Equal(ConnectionState.Connecting, ConnectionStateMachine.Derive(true, false, false, true, noHs, Now));
        Assert.Equal(ConnectionState.Connected, ConnectionStateMachine.Derive(true, false, false, true, up, Now));
        Assert.Equal(ConnectionState.Reconnecting, ConnectionStateMachine.Derive(true, false, false, true, stale, Now));
    }
}

public class SessionManagerTests
{
    private readonly FakeApi _api = new();
    private readonly FakeTunnel _tunnel = new();
    private readonly DeviceIdentityStore _store = new(Path.Combine(Path.GetTempPath(), "dishnet-sm-" + Guid.NewGuid(), "id.bin"), new InsecureXorProtector());
    private DateTimeOffset _now = new(2026, 10, 2, 12, 0, 0, TimeSpan.Zero);

    private SessionManager NewManager() => new(new ApiClient(new HttpClient(_api) { BaseAddress = new Uri("https://vpn.test") }, "test-1.0"), _store, _tunnel, "https://vpn.test", "Windows 11 Pro", () => _now);

    [Fact]
    public async Task Activate_Connect_Heartbeat_Revoke_FullFlow()
    {
        _api.Handler = (req, _) => req.RequestUri!.AbsolutePath switch
        {
            "/api/v1/activate" => (HttpStatusCode.Created, new { device_token = "dnd_tok", config = FakeApi.Config(1) }),
            "/api/v1/device/config" => (HttpStatusCode.OK, FakeApi.Config(1)),
            "/api/v1/device/heartbeat" => (HttpStatusCode.OK, new { ok = true, config_version = 1 }),
            _ => (HttpStatusCode.NotFound, new { error = "x", code = "unknown" }),
        };
        var sm = NewManager();
        Assert.Equal(ConnectionState.NotActivated, await sm.GetStateAsync(default));

        await sm.ActivateAsync("DN-J668-7GMJ-NFW7-XLCP", "Laptop", null, default);
        Assert.True(sm.IsActivated);
        Assert.True(_store.Exists);
        var sentKey = _api.Requests[0].Body;
        Assert.Contains(sm.Identity!.PublicKey, sentKey);
        Assert.DoesNotContain(sm.Identity.PrivateKey, sentKey);
        Assert.Equal(ConnectionState.Disconnected, await sm.GetStateAsync(default));

        await sm.ConnectAsync(default);
        Assert.True(_tunnel.Running);
        Assert.Contains("AllowedIPs = 10.20.0.1/32, 10.20.0.17/32", _tunnel.Config);
        Assert.Contains("PrivateKey = " + sm.Identity.PrivateKey, _tunnel.Config);
        Assert.Equal(ConnectionState.Connecting, await sm.GetStateAsync(default));
        _tunnel.Handshake = _now.AddSeconds(-5);
        Assert.Equal(ConnectionState.Connected, await sm.GetStateAsync(default));

        // Link drops: handshake goes stale -> Reconnecting, no error.
        _now = _now.AddMinutes(10);
        Assert.Equal(ConnectionState.Reconnecting, await sm.GetStateAsync(default));

        // Policy change on the server: heartbeat reports a new version, config is re-applied.
        _api.Handler = (req, _) => req.RequestUri!.AbsolutePath switch
        {
            "/api/v1/device/config" => (HttpStatusCode.OK, FakeApi.Config(2, "10.20.0.1/32", "10.20.0.17/32", "192.168.10.0/24")),
            "/api/v1/device/heartbeat" => (HttpStatusCode.OK, new { ok = true, config_version = 2 }),
            _ => (HttpStatusCode.NotFound, new { error = "x", code = "unknown" }),
        };
        await sm.HeartbeatAsync(default);
        Assert.Contains("192.168.10.0/24", _tunnel.Config);
        Assert.Equal(2, _store.Load()!.ConfigVersion);

        // Admin revokes: next heartbeat tears the tunnel down and the state is Revoked.
        _api.Handler = (_, _) => (HttpStatusCode.Forbidden, new { error = "access denied: revoked", code = "access_denied", reason = "revoked" });
        await sm.HeartbeatAsync(default);
        Assert.True(_tunnel.Removed);
        Assert.Equal(ConnectionState.Revoked, await sm.GetStateAsync(default));
        Assert.Equal("Access revoked", ConnectionStateMachine.Describe(ConnectionState.Revoked).Title);

        await sm.ForgetAsync(default);
        Assert.False(_store.Exists);
        Assert.Equal(ConnectionState.NotActivated, await sm.GetStateAsync(default));
    }

    [Fact]
    public async Task Activate_BadCode_SurfacesTypedError_AndStoresNothing()
    {
        _api.Handler = (_, _) => (HttpStatusCode.Unauthorized, new { error = "activation code is invalid", code = "invalid_code" });
        var sm = NewManager();
        var ex = await Assert.ThrowsAsync<ApiException>(() => sm.ActivateAsync("DN-AAAA-AAAA-AAAA-AAAA", "L", null, default));
        Assert.Equal(ApiFailure.InvalidCode, ex.Failure);
        Assert.False(sm.IsActivated);
        Assert.False(_store.Exists);
    }

    [Fact]
    public async Task Connect_WhileOffline_UsesCachedConfig()
    {
        _api.Handler = (req, _) => req.RequestUri!.AbsolutePath == "/api/v1/activate"
            ? (HttpStatusCode.Created, new { device_token = "dnd_tok", config = FakeApi.Config(1) })
            : (HttpStatusCode.OK, FakeApi.Config(1));
        var sm = NewManager();
        await sm.ActivateAsync("DN-J668-7GMJ-NFW7-XLCP", "Laptop", null, default);
        _api.Offline = true;
        await sm.ConnectAsync(default);
        Assert.True(_tunnel.Running); // cached config from activation is good enough to connect
    }

    [Fact]
    public async Task Restart_ReloadsIdentity_FromProtectedStore()
    {
        _api.Handler = (req, _) => req.RequestUri!.AbsolutePath == "/api/v1/activate"
            ? (HttpStatusCode.Created, new { device_token = "dnd_tok", config = FakeApi.Config(1) })
            : (HttpStatusCode.OK, FakeApi.Config(1));
        await NewManager().ActivateAsync("DN-J668-7GMJ-NFW7-XLCP", "Laptop", null, default);
        var again = NewManager(); // fresh process
        Assert.True(again.IsActivated);
        await again.ConnectAsync(default);
        Assert.True(_tunnel.Running);
        Assert.Equal("dnd_tok", _api.Requests.Last().Auth);
    }
}
