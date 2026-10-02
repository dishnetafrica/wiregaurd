using DishNet.SecureConnect.Core.Api;
using DishNet.SecureConnect.Core.Onboarding;
using DishNet.SecureConnect.Core.Secrets;
using DishNet.SecureConnect.Core.Tunnel;

namespace DishNet.SecureConnect.Core.Session;

/// <summary>
/// Controls the tunnel on the local machine. The Windows implementation
/// installs/starts/stops the WireGuard tunnel service and reads its status;
/// tests use an in-memory fake.
/// </summary>
public interface ITunnelController
{
    /// <summary>Install (or update) the tunnel with this configuration text and start it.</summary>
    Task StartAsync(string configText, CancellationToken ct);
    Task StopAsync(CancellationToken ct);
    /// <summary>Remove the tunnel entirely (uninstall, revocation).</summary>
    Task RemoveAsync(CancellationToken ct);
    Task<TunnelStatus> GetStatusAsync(CancellationToken ct);
}

/// <summary>
/// The application's brain: activation, config refresh, connect/disconnect,
/// heartbeat and revocation handling. UI-agnostic so it is fully unit-tested;
/// the WPF app only binds to it.
/// </summary>
public sealed class SessionManager
{
    private readonly ApiClient _api;
    private readonly DeviceIdentityStore _store;
    private readonly ITunnelController _tunnel;
    private readonly Func<DateTimeOffset> _now;
    private readonly IGatewaySetup? _gateway;
    private readonly string _apiOrigin;
    private readonly string _osDescription;

    private DeviceIdentity? _identity;
    private DeviceConfig? _config;
    private bool _revoked;
    private string? _lastError;
    private bool _wantUp;

    private readonly IReachabilityProbe? _probe;

    public SessionManager(ApiClient api, DeviceIdentityStore store, ITunnelController tunnel, string apiOrigin, string osDescription, Func<DateTimeOffset>? now = null, IGatewaySetup? gateway = null, IReachabilityProbe? probe = null)
    {
        _api = api;
        _gateway = gateway;
        _probe = probe;
        _store = store;
        _tunnel = tunnel;
        _apiOrigin = apiOrigin;
        _osDescription = osDescription;
        _now = now ?? (() => DateTimeOffset.UtcNow);
        _identity = store.Load();
    }

    public bool IsActivated => _identity is not null;
    public DeviceIdentity? Identity => _identity;
    public DeviceConfig? Config => _config;
    public string? LastError => _lastError;
    public string? GatewayNote { get; private set; }
    /// <summary>Set by the app from the operator's explicit, explained consent. Without it the app never touches Remote Desktop or the firewall.</summary>
    public bool GatewayConsentGranted { get; set; }
    public ProbeResult LastProbe { get; private set; } = ProbeResult.NotChecked;
    public event Action? Changed;

    private void Notify() => Changed?.Invoke();

    // ---------- activation ----------

    /// <summary>Generates the key pair locally, registers the public key and stores the identity.</summary>
    public async Task ActivateAsync(string code, string deviceName, IReadOnlyList<string>? lanSubnets, CancellationToken ct)
    {
        if (_identity is not null) throw new InvalidOperationException("This device is already activated.");
        var keys = WireGuardKeys.Generate();
        ActivateResponse res;
        try
        {
            res = await _api.ActivateAsync(code, keys.PublicKey, deviceName, _osDescription, lanSubnets, ct);
        }
        catch (ApiException ex)
        {
            _lastError = ex.Message;
            Notify();
            throw;
        }
        var id = new DeviceIdentity
        {
            DeviceId = res.Config.DeviceId, DeviceName = res.Config.DeviceName, CustomerName = res.Config.CustomerName, Role = res.Config.Role,
            PrivateKey = keys.PrivateKey, PublicKey = keys.PublicKey, DeviceToken = res.DeviceToken, ApiOrigin = _apiOrigin,
            ConfigVersion = res.Config.ConfigVersion, ActivatedAt = _now(),
        };
        _store.Save(id);
        _identity = id;
        _config = res.Config;
        _revoked = false;
        _lastError = null;
        Notify();
    }

    // ---------- configuration ----------

    /// <summary>Fetches the latest configuration; marks the device revoked on a terminal refusal.</summary>
    public async Task<DeviceConfig?> RefreshConfigAsync(CancellationToken ct)
    {
        var id = _identity ?? throw new InvalidOperationException("Not activated.");
        try
        {
            _config = await _api.GetConfigAsync(id.DeviceToken, ct);
            if (_config.ConfigVersion != id.ConfigVersion)
            {
                _identity = id with { ConfigVersion = _config.ConfigVersion };
                _store.Save(_identity);
            }
            _lastError = null;
            Notify();
            return _config;
        }
        catch (ApiException ex) when (ex.IsTerminal)
        {
            await HandleRevokedAsync(ex, ct);
            throw;
        }
        catch (ApiException ex)
        {
            _lastError = ex.Message; // offline: keep using the cached config
            Notify();
            return _config;
        }
    }

    private async Task HandleRevokedAsync(ApiException ex, CancellationToken ct)
    {
        _revoked = true;
        _wantUp = false;
        _lastError = ex.Message;
        try { await _tunnel.RemoveAsync(ct); } catch (Exception) { /* best effort: access is already gone server-side */ }
        Notify();
    }

    // ---------- connect / disconnect ----------

    public async Task ConnectAsync(CancellationToken ct)
    {
        var id = _identity ?? throw new InvalidOperationException("Not activated.");
        _wantUp = true;
        var cfg = _config;
        try
        {
            cfg = await RefreshConfigAsync(ct) ?? cfg;
        }
        catch (ApiException ex) when (ex.IsTerminal)
        {
            return; // state is now Revoked
        }
        if (cfg is null)
        {
            _lastError = "No configuration available. Connect to the internet and try again.";
            _wantUp = false;
            Notify();
            return;
        }
        try
        {
            var text = TunnelConfigRenderer.Render(cfg, id.PrivateKey);
            await _tunnel.StartAsync(text, ct);
            _lastError = null;
            if (cfg.IsGateway) await ApplyGatewaySetupIfAllowedAsync(cfg, ct);
        }
        catch (UnauthorizedAccessException ex)
        {
            _lastError = "Windows refused a file or service operation (" + ex.Message + "). Please run DishNet Secure Connect as administrator.";
            _wantUp = false;
        }
        catch (TunnelConfigException ex)
        {
            _lastError = ex.Message;
            _wantUp = false;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _lastError = "Could not start the secure tunnel: " + ex.Message;
            _wantUp = false;
        }
        Notify();
    }

    /// <summary>Runs the office-gateway preparation only when the operator has consented; otherwise explains what is pending.</summary>
    public async Task ApplyGatewaySetupIfAllowedAsync(DeviceConfig cfg, CancellationToken ct)
    {
        if (!cfg.IsGateway || _gateway is null) return;
        if (!GatewayConsentGranted)
        {
            GatewayNote = "Remote Desktop is not enabled yet. Click \"Allow Remote Desktop for DishNet users\" so staff can reach this computer.";
            Notify();
            return;
        }
        try { GatewayNote = await _gateway.ApplyAsync(cfg.GatewayPorts, cfg.VpnPool, ct); }
        catch (Exception ex) when (ex is not OperationCanceledException) { GatewayNote = "Remote Desktop could not be enabled: " + ex.Message; }
        Notify();
    }

    /// <summary>Called after the operator consents: applies immediately if the tunnel is already up.</summary>
    public async Task GrantGatewayConsentAsync(CancellationToken ct)
    {
        GatewayConsentGranted = true;
        if (_config is { IsGateway: true } cfg && (await _tunnel.GetStatusAsync(ct)).Running) await ApplyGatewaySetupIfAllowedAsync(cfg, ct);
        else Notify();
    }

    /// <summary>
    /// Tests whether the office computer answers on its allowed port through
    /// the tunnel (only meaningful for a client device while Connected).
    /// </summary>
    public async Task<ProbeResult> ProbeOfficeAsync(CancellationToken ct)
    {
        var cfg = _config;
        if (_probe is null || cfg is null || cfg.IsGateway || cfg.Access.Count == 0) { LastProbe = ProbeResult.NotChecked; return LastProbe; }
        var status = await _tunnel.GetStatusAsync(ct);
        if (!status.IsHealthy(_now())) { LastProbe = ProbeResult.NotChecked; return LastProbe; }
        var target = cfg.Access.FirstOrDefault(a => a.Ports.Contains(3389)) ?? cfg.Access[0];
        var port = target.Ports.Contains(3389) ? 3389 : target.Ports.FirstOrDefault();
        var host = target.Target.Split('/')[0];
        if (port == 0 || string.IsNullOrEmpty(host)) { LastProbe = ProbeResult.NotChecked; return LastProbe; }
        LastProbe = await _probe.ProbeAsync(host, port, TimeSpan.FromSeconds(4), ct);
        Notify();
        return LastProbe;
    }

    public async Task DisconnectAsync(CancellationToken ct)
    {
        _wantUp = false;
        await _tunnel.StopAsync(ct);
        Notify();
    }

    // ---------- periodic ----------

    /// <summary>Called by a timer (every 60 s): reports presence, picks up config changes, detects revocation.</summary>
    public async Task HeartbeatAsync(CancellationToken ct)
    {
        var id = _identity;
        if (id is null || _revoked) return;
        var status = await _tunnel.GetStatusAsync(ct);
        try
        {
            var hb = await _api.HeartbeatAsync(id.DeviceToken, status.IsHealthy(_now()), ct);
            if (hb.ConfigVersion != id.ConfigVersion)
            {
                var cfg = await RefreshConfigAsync(ct);
                if (cfg is not null && _wantUp)
                {
                    await _tunnel.StartAsync(TunnelConfigRenderer.Render(cfg, id.PrivateKey), ct); // re-apply changed policy
                }
            }
        }
        catch (ApiException ex) when (ex.IsTerminal)
        {
            await HandleRevokedAsync(ex, ct);
        }
        catch (ApiException)
        {
            // offline: nothing to do, the tunnel keeps retrying by itself
        }
        catch (TunnelConfigException ex)
        {
            _lastError = ex.Message;
            Notify();
        }
    }

    public async Task<ConnectionState> GetStateAsync(CancellationToken ct)
    {
        var status = _identity is null ? TunnelStatus.Down : await _tunnel.GetStatusAsync(ct);
        return ConnectionStateMachine.Derive(_identity is not null, _revoked, _lastError is not null && !_revoked && !_wantUp && !status.Running, _wantUp, status, _now());
    }

    /// <summary>Forget this device locally (after revocation, or "Reset" in the UI).</summary>
    public async Task ForgetAsync(CancellationToken ct)
    {
        try { await _tunnel.RemoveAsync(ct); } catch (Exception) { }
        _store.Delete();
        _identity = null;
        _config = null;
        _revoked = false;
        _wantUp = false;
        _lastError = null;
        Notify();
    }
}
