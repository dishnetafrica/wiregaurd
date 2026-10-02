using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows.Input;
using DishNet.SecureConnect.Core.Api;
using DishNet.SecureConnect.Core.Session;
using DishNet.SecureConnect.Windows;

namespace DishNet.SecureConnect.App;

public sealed class RelayCommand(Func<Task> run, Func<bool>? can = null) : ICommand
{
    private bool _busy;
    public event EventHandler? CanExecuteChanged;
    public bool CanExecute(object? p) => !_busy && (can?.Invoke() ?? true);
    public async void Execute(object? p)
    {
        _busy = true; Raise();
        try { await run(); } finally { _busy = false; Raise(); }
    }
    public void Raise() => CanExecuteChanged?.Invoke(this, EventArgs.Empty);
}

/// <summary>Everything the window binds to. No tunnel/API logic here — that is SessionManager (tested in Core).</summary>
public sealed class MainViewModel : INotifyPropertyChanged
{
    private readonly SessionManager _session;
    private readonly WireGuardTunnelController _tunnel;
    private readonly AppLog _log;
    private readonly CancellationTokenSource _cts = new();

    private readonly ApiClient _api;
    private readonly System.Net.Http.HttpClient _http;
    private readonly string _apiOrigin;
    private LatestClient? _update;

    public MainViewModel(SessionManager session, WireGuardTunnelController tunnel, AppLog log, ApiClient api, System.Net.Http.HttpClient http, string apiOrigin)
    {
        _session = session; _tunnel = tunnel; _log = log; _api = api; _http = http; _apiOrigin = apiOrigin;
        UpdateCommand = new RelayCommand(UpdateAsync, () => _update is not null);
        ActivateCommand = new RelayCommand(ActivateAsync, () => !IsActivated && Code.Trim().Length >= 10);
        ConnectCommand = new RelayCommand(ConnectAsync, () => IsActivated && !IsConnected);
        DisconnectCommand = new RelayCommand(DisconnectAsync, () => IsActivated && IsConnected);
        DiagnosticsCommand = new RelayCommand(DiagnosticsAsync);
        ForgetCommand = new RelayCommand(ForgetAsync, () => IsActivated);
        StartWithWindows = StartupRegistration.IsEnabled();
        _session.Changed += () => _ = RefreshAsync();
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    private void Set<T>(ref T field, T value, [CallerMemberName] string? name = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value)) return;
        field = value;
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }

    // ---------- bindable state ----------
    private string _code = "";
    public string Code { get => _code; set { Set(ref _code, value); ActivateCommand.Raise(); } }

    private string _deviceName = Environment.MachineName;
    public string DeviceName { get => _deviceName; set => Set(ref _deviceName, value); }

    private ConnectionState _state = ConnectionState.NotActivated;
    public ConnectionState State { get => _state; private set { Set(ref _state, value); Notify(nameof(IsActivated), nameof(IsConnected), nameof(IsBusy), nameof(StateTitle), nameof(StateDetail), nameof(StateBrushKey), nameof(ShowActivation), nameof(ShowMain)); RaiseAll(); } }

    public bool IsActivated => State != ConnectionState.NotActivated;
    public bool IsConnected => State is ConnectionState.Connected or ConnectionState.Connecting or ConnectionState.Reconnecting;
    public bool IsBusy => State is ConnectionState.Connecting;
    public bool ShowActivation => !IsActivated;
    public bool ShowMain => IsActivated;
    public string StateTitle => ConnectionStateMachine.Describe(State).Title;
    public string StateDetail => ConnectionStateMachine.Describe(State).Detail;
    public string StateBrushKey => State switch
    {
        ConnectionState.Connected => "OkSoft",
        ConnectionState.Connecting or ConnectionState.Reconnecting => "WarnSoft",
        ConnectionState.Revoked or ConnectionState.Error => "BadSoft",
        _ => "NeutralSoft",
    };

    private string _customerName = "";
    public string CustomerName { get => _customerName; private set => Set(ref _customerName, value); }
    private string _assignedDevice = "";
    public string AssignedDevice { get => _assignedDevice; private set => Set(ref _assignedDevice, value); }
    private string _vpnAddress = "";
    public string VpnAddress { get => _vpnAddress; private set => Set(ref _vpnAddress, value); }
    private string _officeTargets = "";
    public string OfficeTargets { get => _officeTargets; private set => Set(ref _officeTargets, value); }
    private string _handshake = "";
    public string Handshake { get => _handshake; private set => Set(ref _handshake, value); }
    private string _traffic = "";
    public string Traffic { get => _traffic; private set => Set(ref _traffic, value); }
    private string _error = "";
    public string Error { get => _error; private set { Set(ref _error, value); Notify(nameof(HasError)); } }
    public bool HasError => Error.Length > 0;
    private string _info = "";
    public string Info { get => _info; private set { Set(ref _info, value); Notify(nameof(HasInfo)); } }
    public bool HasInfo => Info.Length > 0;
    private bool _isGateway;
    public bool IsGateway { get => _isGateway; private set => Set(ref _isGateway, value); }
    private string _gatewayNote = "";
    public string GatewayNote { get => _gatewayNote; private set { Set(ref _gatewayNote, value); Notify(nameof(HasGatewayNote)); } }
    public bool HasGatewayNote => GatewayNote.Length > 0;
    private string _updateText = "";
    public string UpdateText { get => _updateText; private set { Set(ref _updateText, value); Notify(nameof(HasUpdate)); UpdateCommand.Raise(); } }
    public bool HasUpdate => UpdateText.Length > 0;
    public RelayCommand UpdateCommand { get; }
    private string _planText = "";
    public string PlanText { get => _planText; private set => Set(ref _planText, value); }

    private bool _startWithWindows;
    public bool StartWithWindows
    {
        get => _startWithWindows;
        set { Set(ref _startWithWindows, value); try { StartupRegistration.Set(value, Environment.ProcessPath ?? ""); } catch (Exception ex) { Error = "Could not change startup setting: " + ex.Message; } }
    }

    public string Version => "v" + App.ClientVersion;
    public string TunnelComponentHint => _tunnel.IsWireGuardInstalled ? "" : "The tunnel component is missing — please reinstall DishNet Secure Connect.";

    public RelayCommand ActivateCommand { get; }
    public RelayCommand ConnectCommand { get; }
    public RelayCommand DisconnectCommand { get; }
    public RelayCommand DiagnosticsCommand { get; }
    public RelayCommand ForgetCommand { get; }

    private void Notify(params string[] names) { foreach (var n in names) PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(n)); }
    private void RaiseAll() { ActivateCommand.Raise(); ConnectCommand.Raise(); DisconnectCommand.Raise(); ForgetCommand.Raise(); }

    // ---------- actions ----------

    public async Task RefreshAsync()
    {
        try
        {
            State = await _session.GetStateAsync(_cts.Token);
            var id = _session.Identity;
            var cfg = _session.Config;
            CustomerName = id?.CustomerName ?? "";
            AssignedDevice = id is null ? "" : $"{id.DeviceName} (#{id.DeviceId})";
            IsGateway = id?.Role == "gateway";
            VpnAddress = cfg?.Address ?? "";
            PlanText = Core.Session.PlanText.Describe(cfg, DateTimeOffset.UtcNow);
            OfficeTargets = cfg is null ? "" : IsGateway
                ? "This computer is the office server. Staff devices connect to it through DishNet."
                : cfg.Access.Count == 0 ? "No office server registered yet — ask DishNet." : string.Join("\n", cfg.Access.Select(a => $"{a.Label}: {a.Target} ({a.Proto} {string.Join(",", a.Ports)})"));
            var st = IsActivated ? await _tunnel.GetStatusAsync(_cts.Token) : TunnelStatus.Down;
            Handshake = st.LastHandshake is { } h ? $"Last handshake {(DateTimeOffset.UtcNow - h).TotalSeconds:0} s ago" : (st.Running ? "Waiting for handshake…" : "");
            Traffic = st.Running ? $"↓ {st.RxBytes / 1e6:0.0} MB  ↑ {st.TxBytes / 1e6:0.0} MB" : "";
            Error = _session.LastError ?? "";
            GatewayNote = IsGateway ? (_session.GatewayNote ?? "") : "";
        }
        catch (Exception ex)
        {
            _log.Error("refresh: " + ex);
            Error = ex.Message;
        }
    }

    /// <summary>Install-link flow: activate with the embedded code and connect, no typing.</summary>
    public async Task AutoSetupAsync(string code)
    {
        Code = code;
        Info = "Setting up your DishNet connection…";
        await ActivateAsync();
        if (_session.IsActivated)
        {
            StartWithWindows = true;
            await ConnectAsync();
        }
    }

    private async Task ActivateAsync()
    {
        Error = ""; Info = "Activating…";
        try
        {
            await _session.ActivateAsync(Code, DeviceName.Trim(), null, _cts.Token);
            Code = "";
            Info = "Activated. Click Connect to reach your office.";
            _log.Info("activated");
        }
        catch (ApiException ex)
        {
            Info = "";
            Error = ex.Failure switch
            {
                ApiFailure.InvalidCode => "That activation code is not valid. Check it and try again.",
                ApiFailure.CodeUsed => "This activation code has already been used. Ask DishNet for a new one.",
                ApiFailure.CodeExpired => "This activation code has expired. Ask DishNet for a new one.",
                ApiFailure.CodeRevoked => "This activation code was cancelled by DishNet.",
                ApiFailure.DeviceLimit => "Your business has reached its device limit. Ask DishNet to increase it or remove an old device.",
                ApiFailure.CustomerBlocked => "Your DishNet subscription is suspended or expired. Please contact DishNet.",
                ApiFailure.RateLimited => "Too many attempts. Please wait 10 minutes and try again.",
                ApiFailure.Network => "Cannot reach the DishNet server. Check your internet connection and try again.",
                ApiFailure.ProvisioningFailed => "DishNet could not provision this device right now. Please try again in a few minutes.",
                _ => "Activation failed: " + ex.Message,
            };
        }
        catch (Exception ex) { Info = ""; Error = ex.Message; _log.Error("activate: " + ex); }
        await RefreshAsync();
    }

    private async Task ConnectAsync()
    {
        Error = ""; Info = "";
        if (!_tunnel.IsWireGuardInstalled) { Error = TunnelComponentHint; return; }
        try { await _session.ConnectAsync(_cts.Token); }
        catch (Exception ex) { Error = ex.Message; _log.Error("connect: " + ex); }
        await RefreshAsync();
    }

    private async Task DisconnectAsync()
    {
        Error = ""; Info = "";
        try { await _session.DisconnectAsync(_cts.Token); }
        catch (Exception ex) { Error = ex.Message; _log.Error("disconnect: " + ex); }
        await RefreshAsync();
    }

    public async Task HeartbeatAsync()
    {
        try { await _session.HeartbeatAsync(_cts.Token); }
        catch (Exception ex) { _log.Warn("heartbeat: " + ex.Message); }
    }

    public async Task CheckForUpdateAsync()
    {
        try
        {
            var latest = await _api.GetLatestClientAsync(_cts.Token);
            _update = UpdateCheck.Evaluate(App.ClientVersion, latest, _apiOrigin);
            UpdateText = _update is null ? "" : $"Version {_update.Version} of DishNet Secure Connect is available.";
        }
        catch (Exception ex) { _log.Warn("update check: " + ex.Message); }
    }

    private async Task UpdateAsync()
    {
        var u = _update;
        if (u is null) return;
        try
        {
            Info = $"Downloading version {u.Version}…";
            var path = await Updater.DownloadAsync(_http, u, new Progress<double>(p => Info = $"Downloading version {u.Version}… {p:P0}"), _cts.Token);
            Info = "Installing the update. DishNet Secure Connect will restart in a moment.";
            _log.Info("running updater " + u.Version);
            Updater.RunInstaller(path);
        }
        catch (Exception ex) { Error = "Update failed: " + ex.Message; _log.Error("update: " + ex); }
    }

    private async Task DiagnosticsAsync()
    {
        try
        {
            var st = await _tunnel.GetStatusAsync(_cts.Token);
            var path = await DiagnosticsBundle.CreateAsync(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), _log, _session.Identity, State, st, App.ClientVersion, _cts.Token);
            Info = $"Diagnostics saved to your Desktop: {System.IO.Path.GetFileName(path)}. Send it to DishNet support.";
        }
        catch (Exception ex) { Error = "Could not create diagnostics: " + ex.Message; }
    }

    private async Task ForgetAsync()
    {
        try { await _session.ForgetAsync(_cts.Token); Info = "This device has been reset. Enter a new activation code to use it again."; }
        catch (Exception ex) { Error = ex.Message; }
        await RefreshAsync();
    }
}
