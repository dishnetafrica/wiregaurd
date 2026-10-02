using DishNet.SecureConnect.Core.Api;
using DishNet.SecureConnect.Core.Session;

namespace DishNet.SecureConnect.Core.Onboarding;

public enum StepStatus
{
    Pending,       // not done yet
    Verified,      // proven by the software (activation response, handshake, probe)
    Confirmed,     // the customer ticked it themselves (manual step)
    Attention,     // something is wrong and the detail says what to do
}

public sealed record ChecklistStep(string Key, string Title, string Detail, StepStatus Status, bool IsManual)
{
    public bool IsDone => Status is StepStatus.Verified or StepStatus.Confirmed;
}

/// <summary>
/// The guided checklist shown to a remote (client) device. Every status is
/// derived from facts; a step is never marked done unless the software
/// verified it or the customer explicitly confirmed a manual step.
/// </summary>
public static class Checklist
{
    public const string KeyActivated = "activated";
    public const string KeyRegistered = "registered";
    public const string KeyVpn = "vpn";
    public const string KeyOfficeReachable = "office";
    public const string KeyRdpInstructions = "rdp";
    public const string KeyTally = "tally";

    public static IReadOnlyList<ChecklistStep> Build(bool activated, DeviceConfig? cfg, ConnectionState state, ProbeResult probe, UserSettings settings)
    {
        var steps = new List<ChecklistStep>(6);

        steps.Add(activated
            ? new(KeyActivated, "Activation code accepted", "This computer was activated with its DishNet code.", StepStatus.Verified, false)
            : new(KeyActivated, "Enter your activation code", "You received it from DishNet (or it was built into your install link).", StepStatus.Pending, false));

        steps.Add(activated && cfg is not null
            ? new(KeyRegistered, "Device registered", $"Registered as \"{cfg.DeviceName}\" for {cfg.CustomerName}.", StepStatus.Verified, false)
            : new(KeyRegistered, "Device registered", "Happens automatically after activation.", StepStatus.Pending, false));

        steps.Add(state switch
        {
            ConnectionState.Connected => new(KeyVpn, "Secure connection to DishNet", "Encrypted tunnel is up.", StepStatus.Verified, false),
            ConnectionState.Connecting => new(KeyVpn, "Secure connection to DishNet", "Connecting… this usually takes a few seconds.", StepStatus.Pending, false),
            ConnectionState.Reconnecting => new(KeyVpn, "Secure connection to DishNet", "Waiting for your internet to come back. It reconnects by itself.", StepStatus.Attention, false),
            ConnectionState.Revoked => new(KeyVpn, "Secure connection to DishNet", "This device's access was removed. Contact DishNet.", StepStatus.Attention, false),
            ConnectionState.Error => new(KeyVpn, "Secure connection to DishNet", "Could not start the tunnel. See the message on the main screen.", StepStatus.Attention, false),
            _ => new(KeyVpn, "Connect to DishNet", "Click \"Connect to Office\".", StepStatus.Pending, false),
        });

        var office = cfg?.Access.FirstOrDefault();
        var officeStep = (state, probe, office) switch
        {
            (_, _, null) when activated && cfg is not null => new ChecklistStep(KeyOfficeReachable, "Office computer", "DishNet has not registered your office computer yet. Contact DishNet.", StepStatus.Attention, false),
            (ConnectionState.Connected, ProbeResult.Reachable, _) => new(KeyOfficeReachable, "Office computer reachable", $"\"{office!.Label}\" answers on the Remote Desktop port.", StepStatus.Verified, false),
            (ConnectionState.Connected, ProbeResult.Unreachable, _) => new(KeyOfficeReachable, "Office computer not answering", "Is the office computer switched on and online, with DishNet connected there? Remote Desktop must be allowed on it.", StepStatus.Attention, false),
            (ConnectionState.Connected, _, _) => new(KeyOfficeReachable, "Checking the office computer…", "Testing whether it answers through the tunnel.", StepStatus.Pending, false),
            _ => new(KeyOfficeReachable, "Office computer reachable", "Checked once the secure connection is up.", StepStatus.Pending, false),
        };
        steps.Add(officeStep);

        steps.Add(settings.ConfirmedRdpInstructionsAt is not null
            ? new(KeyRdpInstructions, "Remote Desktop opened", "You confirmed you can open Remote Desktop to the office computer.", StepStatus.Confirmed, true)
            : new(KeyRdpInstructions, "Open Remote Desktop", "Click \"Open Remote Desktop\" and sign in with your Windows user name and password for the office computer. Then tick this step.", StepStatus.Pending, true));

        steps.Add(settings.ConfirmedTallyOpenedAt is not null
            ? new(KeyTally, "Tally opened on the office desktop", "You confirmed Tally works through Remote Desktop.", StepStatus.Confirmed, true)
            : new(KeyTally, "Open Tally on the office desktop", "Inside the Remote Desktop window, open Tally as you do at the office. Tick this step once it works.", StepStatus.Pending, true));

        return steps;
    }

    /// <summary>The next thing the customer should do, in plain words.</summary>
    public static string NextAction(IReadOnlyList<ChecklistStep> steps)
    {
        var next = steps.FirstOrDefault(s => !s.IsDone);
        return next is null ? "All set. Use Tally through Remote Desktop and disconnect when you finish." : next.Title + " — " + next.Detail;
    }
}
