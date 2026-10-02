using DishNet.SecureConnect.Core.Api;
using DishNet.SecureConnect.Core.Session;

namespace DishNet.SecureConnect.Core.Onboarding;

public sealed record JourneyStep(string Key, string Title, string Instruction, StepStatus Status, string Action)
{
    public bool IsDone => Status is StepStatus.Verified or StepStatus.Confirmed;
}

/// <summary>
/// The "Set up Tally remote access" guided journey for a staff computer, in
/// the order a first-time user experiences it. Verified steps come from the
/// software (activation, tunnel state, office probe, disconnect observed);
/// confirmed steps are ticked by the customer and never set automatically.
/// Practice mode walks the same steps once end to end, including a clean
/// disconnect, so the customer has done the whole thing before relying on it.
/// </summary>
public static class TallyJourney
{
    public const string KeyActivate = "activate";
    public const string KeyConnect = "connect";
    public const string KeyOffice = "office";
    public const string KeyOpenRdp = "open_rdp";
    public const string KeySignIn = "sign_in";
    public const string KeyOpenCompany = "open_company";
    public const string KeyTask = "task";
    public const string KeyDisconnect = "disconnect";

    public const string ActionConnect = "connect";
    public const string ActionOpenRdp = "open_rdp";
    public const string ActionConfirm = "confirm";
    public const string ActionDisconnect = "disconnect";
    public const string ActionNone = "";

    public static IReadOnlyList<JourneyStep> Build(bool activated, DeviceConfig? cfg, ConnectionState state, ProbeResult probe, UserSettings s)
    {
        var steps = new List<JourneyStep>(8);
        var company = string.IsNullOrWhiteSpace(cfg?.TallyCompany) ? "your company" : "\"" + cfg!.TallyCompany.Trim() + "\"";
        var office = cfg?.Access.FirstOrDefault()?.Label ?? "the office computer";

        steps.Add(activated
            ? new(KeyActivate, "This laptop is activated", "Activated with its own DishNet device code.", StepStatus.Verified, ActionNone)
            : new(KeyActivate, "Activate this laptop", "Use the install link or activation code DishNet sent for this computer. One code per computer.", StepStatus.Pending, ActionNone));

        steps.Add(state switch
        {
            ConnectionState.Connected => new(KeyConnect, "Connected to DishNet", "The private connection to your office is up.", StepStatus.Verified, ActionNone),
            ConnectionState.Connecting => new(KeyConnect, "Connecting…", "Usually takes a few seconds. Make sure this laptop has internet.", StepStatus.Pending, ActionNone),
            ConnectionState.Reconnecting => new(KeyConnect, "Reconnecting…", "Your internet dropped. The app reconnects by itself.", StepStatus.Attention, ActionNone),
            ConnectionState.Revoked => new(KeyConnect, "Access removed", "DishNet has stopped this device, or the trial ended. Contact DishNet.", StepStatus.Attention, ActionNone),
            ConnectionState.Error => new(KeyConnect, "Connection problem", "See the message on the main screen, then try Connect again.", StepStatus.Attention, ActionConnect),
            _ => new(KeyConnect, "Connect to Office", "Click Connect. This opens the private road to the office; it does not open Tally yet.", StepStatus.Pending, ActionConnect),
        });

        var connected = state == ConnectionState.Connected;
        steps.Add((connected, probe, cfg?.Access.Count ?? 0) switch
        {
            (_, _, 0) when activated && cfg is not null => new(KeyOffice, "Office computer not set up yet", "DishNet has not registered your office computer. Contact DishNet.", StepStatus.Attention, ActionNone),
            (true, ProbeResult.Reachable, _) => new(KeyOffice, "Office computer is reachable", $"{office} answers on the Remote Desktop port. Tally there is one step away.", StepStatus.Verified, ActionNone),
            (true, ProbeResult.Unreachable, _) => new(KeyOffice, "Office computer not answering", "Is it switched on and online, with DishNet connected there and Remote Desktop allowed? Ask someone at the office.", StepStatus.Attention, ActionNone),
            (true, _, _) => new(KeyOffice, "Checking the office computer…", "Testing whether it answers through the connection.", StepStatus.Pending, ActionNone),
            _ => new(KeyOffice, "Office computer reachable", "Checked once you are connected.", StepStatus.Pending, ActionNone),
        });

        steps.Add(s.ConfirmedRdpInstructionsAt is not null
            ? new(KeyOpenRdp, "Remote Desktop opened", "You confirmed Remote Desktop opens to the office computer.", StepStatus.Confirmed, ActionNone)
            : new(KeyOpenRdp, "Open Remote Desktop", "Click Open Remote Desktop. A Windows window opens with the office computer's address filled in. Click Connect in it.", StepStatus.Pending, ActionOpenRdp));

        steps.Add(s.PracticeSignedInAt is not null
            ? new(KeySignIn, "Signed in to the office computer", "You confirmed your Windows sign-in works.", StepStatus.Confirmed, ActionNone)
            : new(KeySignIn, "Sign in with your office Windows account", "Type the user name and password you use on the office computer. DishNet never asks for or stores it. If Windows warns about the computer's identity, choose Yes.", StepStatus.Pending, ActionConfirm));

        steps.Add(s.PracticeCompanyOpenedAt is not null || s.ConfirmedTallyOpenedAt is not null
            ? new(KeyOpenCompany, "Tally company opened", "You confirmed Tally opened the right company on the office computer.", StepStatus.Confirmed, ActionNone)
            : new(KeyOpenCompany, $"Open Tally and select {company}", "On the office desktop (inside the Remote Desktop window) open Tally as you do at the office, then select the company from Tally's list. Tally and the data stay on the office computer.", StepStatus.Pending, ActionConfirm));

        steps.Add(s.PracticeTaskDoneAt is not null
            ? new(KeyTask, "Did a simple task in Tally", "You confirmed a normal task worked (for example viewing a report).", StepStatus.Confirmed, ActionNone)
            : new(KeyTask, "Do one simple task in Tally", "For example open Display → Day Book, or any report you are allowed to view. Work only within what your business authorises you to do.", StepStatus.Pending, ActionConfirm));

        steps.Add(s.PracticeDisconnectedAt is not null
            ? new(KeyDisconnect, "Disconnected properly", "You know the safe way to finish: close the company in Tally, close Remote Desktop, then Disconnect.", StepStatus.Confirmed, ActionNone)
            : new(KeyDisconnect, "Finish properly", "Close the company in Tally, close the Remote Desktop window, then click Disconnect here. To work again later, just Connect and Open Remote Desktop.", StepStatus.Pending, ActionDisconnect));

        return steps;
    }

    public static bool AllDone(IReadOnlyList<JourneyStep> steps) => steps.All(s => s.IsDone);

    public static JourneyStep? Current(IReadOnlyList<JourneyStep> steps) => steps.FirstOrDefault(s => !s.IsDone);

    /// <summary>A confirmation is accepted only for the step that is currently due and only when its prerequisites are verified.</summary>
    public static bool CanConfirm(IReadOnlyList<JourneyStep> steps, string key)
    {
        var cur = Current(steps);
        return cur is not null && cur.Key == key && cur.Action is ActionConfirm or ActionOpenRdp or ActionDisconnect && cur.Status != StepStatus.Attention;
    }

    public static UserSettings Confirm(UserSettings s, string key, DateTimeOffset now) => key switch
    {
        KeyOpenRdp => s with { ConfirmedRdpInstructionsAt = now },
        KeySignIn => s with { PracticeSignedInAt = now },
        KeyOpenCompany => s with { PracticeCompanyOpenedAt = now, ConfirmedTallyOpenedAt = s.ConfirmedTallyOpenedAt ?? now },
        KeyTask => s with { PracticeTaskDoneAt = now },
        KeyDisconnect => s with { PracticeDisconnectedAt = now, PracticeCompletedAt = s.PracticeCompletedAt ?? now },
        _ => s,
    };

    /// <summary>Clears only the customer-ticked practice steps so the journey can be practised again. Verified facts are untouched.</summary>
    public static UserSettings ResetPractice(UserSettings s) => s with
    {
        ConfirmedRdpInstructionsAt = null, PracticeSignedInAt = null, PracticeCompanyOpenedAt = null, PracticeTaskDoneAt = null, PracticeDisconnectedAt = null,
    };
}
