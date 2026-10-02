using System.Net.Sockets;

namespace DishNet.SecureConnect.Core.Onboarding;

public enum ProbeResult
{
    NotChecked,
    Reachable,     // a TCP connection to the office computer's allowed port succeeded through the tunnel
    Unreachable,   // tunnel is up but the office computer did not answer on that port
}

/// <summary>
/// Checks whether the office computer actually answers on an allowed port
/// (normally 3389, Remote Desktop) through the tunnel. A WireGuard handshake
/// only proves the hub is reachable; this proves the office computer is on,
/// online, and accepting connections on that port. It says nothing about
/// Tally — only the customer can confirm that.
/// </summary>
public interface IReachabilityProbe
{
    Task<ProbeResult> ProbeAsync(string host, int port, TimeSpan timeout, CancellationToken ct);
}

public sealed class TcpReachabilityProbe : IReachabilityProbe
{
    public async Task<ProbeResult> ProbeAsync(string host, int port, TimeSpan timeout, CancellationToken ct)
    {
        try
        {
            using var client = new TcpClient();
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(timeout);
            await client.ConnectAsync(host, port, cts.Token);
            return ProbeResult.Reachable;
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { return ProbeResult.Unreachable; }
        catch (SocketException) { return ProbeResult.Unreachable; }
    }
}

public sealed class FakeReachabilityProbe(ProbeResult result) : IReachabilityProbe
{
    public ProbeResult Result { get; set; } = result;
    public (string Host, int Port)? LastTarget { get; private set; }
    public Task<ProbeResult> ProbeAsync(string host, int port, TimeSpan timeout, CancellationToken ct)
    {
        LastTarget = (host, port);
        return Task.FromResult(Result);
    }
}
