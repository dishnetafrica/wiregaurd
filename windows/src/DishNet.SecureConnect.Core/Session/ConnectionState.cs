namespace DishNet.SecureConnect.Core.Session;

public enum ConnectionState
{
    NotActivated,   // no identity on this device
    Disconnected,   // activated, tunnel down
    Connecting,     // tunnel service starting / waiting for first handshake
    Connected,      // handshake within the last 3 minutes
    Reconnecting,   // tunnel up but no handshake for > 3 minutes (link down, Starlink outage)
    Revoked,        // server said revoked / suspended / expired — tunnel torn down
    Error,          // local failure (service missing, no admin rights, bad config)
}

/// <summary>Live figures shown in the UI; all derived from the tunnel service, none secret.</summary>
public sealed record TunnelStatus(bool Running, DateTimeOffset? LastHandshake, long RxBytes, long TxBytes, string? Endpoint)
{
    public static readonly TunnelStatus Down = new(false, null, 0, 0, null);
    public static readonly TimeSpan HandshakeTimeout = TimeSpan.FromMinutes(3);

    public bool IsHealthy(DateTimeOffset now) => Running && LastHandshake is { } h && now - h < HandshakeTimeout;
}

public static class ConnectionStateMachine
{
    /// <summary>Pure derivation of the displayed state from facts; easy to test, no I/O.</summary>
    public static ConnectionState Derive(bool activated, bool revoked, bool localError, bool userWantsUp, TunnelStatus status, DateTimeOffset now)
    {
        if (!activated) return ConnectionState.NotActivated;
        if (revoked) return ConnectionState.Revoked;
        if (localError) return ConnectionState.Error;
        if (!userWantsUp && !status.Running) return ConnectionState.Disconnected;
        if (!status.Running) return ConnectionState.Connecting;
        if (status.IsHealthy(now)) return ConnectionState.Connected;
        return status.LastHandshake is null ? ConnectionState.Connecting : ConnectionState.Reconnecting;
    }

    /// <summary>User-facing text for each state (red/white UI copies these verbatim).</summary>
    public static (string Title, string Detail) Describe(ConnectionState s) => s switch
    {
        ConnectionState.NotActivated => ("Not activated", "Enter the activation code you received from DishNet."),
        ConnectionState.Disconnected => ("Disconnected", "Ready to connect to your office."),
        ConnectionState.Connecting => ("Connecting…", "Establishing the secure tunnel."),
        ConnectionState.Connected => ("Connected", "Your office server is reachable."),
        ConnectionState.Reconnecting => ("Reconnecting…", "Waiting for the internet link to come back. The tunnel resumes automatically."),
        ConnectionState.Revoked => ("Access revoked", "This device no longer has access. Contact DishNet for a new activation code."),
        ConnectionState.Error => ("Problem", "See details below. Try again or send diagnostics to DishNet."),
        _ => ("Unknown", ""),
    };
}
