using System.Net.Http;
using System.Windows;
using System.Windows.Threading;
using DishNet.SecureConnect.Core.Api;
using DishNet.SecureConnect.Core.Secrets;
using DishNet.SecureConnect.Core.Session;
using DishNet.SecureConnect.Windows;

namespace DishNet.SecureConnect.App;

public partial class App : Application
{
    /// <summary>The management API origin. Override for testing with DISHNET_API_ORIGIN.</summary>
    public const string DefaultApiOrigin = "https://vpn.dishnetuganda.com";
    public static string ClientVersion => typeof(App).Assembly.GetName().Version?.ToString(3) ?? "0.0.0";

    private AppLog? _log;
    private DispatcherTimer? _timer;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        DispatcherUnhandledException += (_, ex) =>
        {
            _log?.Error("unhandled: " + ex.Exception);
            MessageBox.Show("DishNet Secure Connect hit an unexpected problem:\n\n" + ex.Exception.Message, "DishNet Secure Connect", MessageBoxButton.OK, MessageBoxImage.Error);
            ex.Handled = true;
        };

        if (!Elevation.IsAdministrator())
        {
            MessageBox.Show("DishNet Secure Connect needs administrator rights to manage the secure tunnel. Please right-click the app and choose \"Run as administrator\".", "DishNet Secure Connect", MessageBoxButton.OK, MessageBoxImage.Warning);
            Shutdown(1);
            return;
        }

        Paths.EnsureDataDir();
        _log = new AppLog(System.IO.Path.Combine(Paths.LogDir, "app.log"));
        _log.Info($"start v{ClientVersion} on {OsInfo.Description()}");

        var origin = Environment.GetEnvironmentVariable("DISHNET_API_ORIGIN") is { Length: > 0 } o ? o : DefaultApiOrigin;
        var http = new HttpClient { BaseAddress = new Uri(origin) };
        var api = new ApiClient(http, ClientVersion);
        var store = new DeviceIdentityStore(Paths.IdentityFile, new DpapiProtector());
        var tunnel = new WireGuardTunnelController(_log);
        var session = new SessionManager(api, store, tunnel, origin, OsInfo.Description());
        var vm = new MainViewModel(session, tunnel, _log);

        var window = new MainWindow { DataContext = vm };
        MainWindow = window;
        if (e.Args.Contains("/minimized")) window.WindowState = WindowState.Minimized;
        window.Show();
        _ = vm.RefreshAsync();

        // Heartbeat + status refresh. The tunnel service keeps running on its own; this only updates the UI and picks up policy changes/revocation.
        _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(15) };
        var tick = 0;
        _timer.Tick += async (_, _) =>
        {
            tick++;
            if (tick % 4 == 0) await vm.HeartbeatAsync(); // every 60 s
            await vm.RefreshAsync();
        };
        _timer.Start();
    }
}
