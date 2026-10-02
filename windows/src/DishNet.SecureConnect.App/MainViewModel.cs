using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows.Input;
using System.Collections.ObjectModel;
using DishNet.SecureConnect.Core.Api;
using DishNet.SecureConnect.Core.Onboarding;
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

    private readonly UserSettingsStore _settings;
    private DateTimeOffset _lastProbeAt;

    public MainViewModel(SessionManager session, WireGuardTunnelController tunnel, AppLog log, ApiClient api, System.Net.Http.HttpClient http, string apiOrigin, UserSettingsStore settings)
    {
        _session = session; _tunnel = tunnel; _log = log; _api = api; _http = http; _apiOrigin = apiOrigin; _settings = settings;
        _session.GatewayConsentGranted = settings.Current.GatewayConsentGiven;
        UpdateCommand = new RelayCommand(UpdateAsync, () => _update is not null);
        AllowGatewayCommand = new RelayCommand(AllowGatewayAsync, () => IsGateway && !GatewayConsentGiven && !OfficeIsHome);
        OpenRemoteDesktopCommand = new RelayCommand(OpenRemoteDesktopAsync, () => !IsGateway && OfficeHost.Length > 0);
        ConfirmRdpCommand = new RelayCommand(() => ConfirmStepAsync(Checklist.KeyRdpInstructions), () => IsActivated && !IsGateway);
        ConfirmTallyCommand = new RelayCommand(() => ConfirmStepAsync(Checklist.KeyTally), () => IsActivated && !IsGateway);
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
    public RelayCommand AllowGatewayCommand { get; }
    public RelayCommand OpenRemoteDesktopCommand { get; }
    public RelayCommand ConfirmRdpCommand { get; }
    public RelayCommand ConfirmTallyCommand { get; }

    public ObservableCollection<ChecklistStep> Steps { get; } = new();
    private string _nextAction = "";
    public string NextAction { get => _nextAction; private set => Set(ref _nextAction, value); }
    private string _supportContact = "";
    public string SupportContact { get => _supportContact; private set { Set(ref _supportContact, value); Notify(nameof(SupportLine)); } }
    public string SupportLine => SupportContact.Length > 0 ? "DishNet support: " + SupportContact : "Contact DishNet support";
    public bool GatewayConsentGiven => _settings.Current.GatewayConsentGiven;
    public bool ShowGatewayConsent => IsActivated && IsGateway && !GatewayConsentGiven;
    public bool OfficeIsHome => OperatingSystem.IsWindows() && OsInfo.Edition() == EditionClass.Home;
    public string HomeWarning => OfficeIsHome
        ? "This computer runs Windows Home, which cannot accept Remote Desktop connections, so it cannot be the office computer for DishNet. Recommended: upgrade this PC to Windows Pro (a licence upgrade, no reinstall) or use another office PC that runs Pro. Contact DishNet for advice."
        : "";
    public bool HasHomeWarning => IsGateway && OfficeIsHome;
    public bool ShowClientTools => IsActivated && !IsGateway;
    private string _officeHost = "";
    public string OfficeHost { get => _officeHost; private set => Set(ref _officeHost, value); }
    public string GatewayConsentText => "To let your staff use Remote Desktop on this computer, DishNet Secure Connect needs to:\n" +
        "  •  switch on Windows Remote Desktop on this computer;\n" +
        "  •  allow connections to it only from DishNet-authorised devices on the Remote Desktop port" + (GatewayPortsText.Length > 0 ? " (" + GatewayPortsText + ")" : "") + ".\n" +
        "Nothing is opened to the internet or to the rest of your office network. You can undo this in Windows settings at any time.";
    private string _gatewayPortsText = "";
    public string GatewayPortsText { get => _gatewayPortsText; private set => Set(ref _gatewayPortsText, value); }
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
            SupportContact = cfg?.SupportContact ?? SupportContact;
            GatewayPortsText = cfg is null ? "" : string.Join(", ", cfg.GatewayPorts);
            OfficeHost = cfg is { IsGateway: false } && cfg.Access.Count > 0 ? cfg.Access[0].Target.Split('/')[0] : "";
            // Probe the office computer at most every 30 s while connected; the checklist never claims reachability without it.
            if (State == ConnectionState.Connected && !IsGateway && DateTimeOffset.UtcNow - _lastProbeAt > TimeSpan.FromSeconds(30))
            {
                _lastProbeAt = DateTimeOffset.UtcNow;
                await _session.ProbeOfficeAsync(_cts.Token);
            }
            var steps = Checklist.Build(IsActivated, cfg, State, _session.LastProbe, _settings.Current);
            Steps.Clear();
            foreach (var s in steps) Steps.Add(s);
            NextAction = Checklist.NextAction(steps);
            Notify(nameof(ShowGatewayConsent), nameof(ShowClientTools), nameof(GatewayConsentGiven), nameof(GatewayConsentText), nameof(HasHomeWarning), nameof(HomeWarning));
            AllowGatewayCommand.Raise(); OpenRemoteDesktopCommand.Raise(); ConfirmRdpCommand.Raise(); ConfirmTallyCommand.Raise();
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

    // ---------- onboarding ----------

    private async Task AllowGatewayAsync()
    {
        _settings.Update(s => s with { GatewayConsentAt = DateTimeOffset.UtcNow, GatewayConsentDeclined = false });
        _log.Info("gateway consent given by operator");
        await _session.GrantGatewayConsentAsync(_cts.Token);
        await RefreshAsync();
    }

    public void DeclineGateway()
    {
        _settings.Update(s => s with { GatewayConsentDeclined = true });
        Info = "Remote Desktop was not enabled. Staff cannot reach this computer until you allow it (button on this screen).";
    }

    private Task OpenRemoteDesktopAsync()
    {
        try
        {
            if (OfficeHost.Length == 0) return Task.CompletedTask;
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("mstsc.exe", $"/v:{OfficeHost}") { UseShellExecute = true });
            Info = "Remote Desktop is opening. Sign in with your Windows user name and password for the office computer. DishNet never sees this password.";
        }
        catch (Exception ex) { Error = "Could not open Remote Desktop: " + ex.Message; }
        return Task.CompletedTask;
    }

    private async Task ConfirmStepAsync(string key)
    {
        _settings.Update(s => key == Checklist.KeyRdpInstructions ? s with { ConfirmedRdpInstructionsAt = DateTimeOffset.UtcNow } : s with { ConfirmedTallyOpenedAt = DateTimeOffset.UtcNow });
        await RefreshAsync();
    }

    public void ShowTour(System.Windows.Window owner)
    {
        var tour = new TourWindow { Owner = owner };
        tour.ShowDialog();
        _settings.Update(s => tour.Completed ? s with { TourCompletedAt = DateTimeOffset.UtcNow, TourSkipped = false } : s with { TourSkipped = true });
    }

    public bool TourDone => _settings.Current.TourDone;

    public void ShowHelp(System.Windows.Window owner, string? topic = null) => new HelpWindow(this, topic) { Owner = owner }.Show();

    public void ContactSupport(System.Windows.Window owner)
    {
        var text = SupportContact.Length > 0 ? SupportContact : "your DishNet representative";
        System.Windows.MessageBox.Show(owner,
            $"Contact DishNet support: {text}\n\nPlease tell us your business name and what the app shows (for example \"Office computer not answering\").\nUse \"Save diagnostics…\" and send the file if asked. Never send your Windows or Tally password.",
            "DishNet support", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Information);
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
