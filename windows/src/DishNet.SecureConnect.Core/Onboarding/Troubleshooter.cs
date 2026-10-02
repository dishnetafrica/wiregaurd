using DishNet.SecureConnect.Core.Api;
using DishNet.SecureConnect.Core.Session;

namespace DishNet.SecureConnect.Core.Onboarding;

/// <summary>Which layer of the remote-Tally journey is failing. Each layer has a different owner and fix.</summary>
public enum FailureLayer { None, Activation, Vpn, OfficePc, RemoteDesktop, WindowsSignIn, Tally }

/// <summary>Answers the customer gives in the troubleshooting assistant. Null = not asked / not answered yet.</summary>
public sealed record TroubleshootAnswers
{
    /// <summary>Did a Remote Desktop window open and show a sign-in screen?</summary>
    public bool? RdpWindowOpened { get; init; }
    /// <summary>Did the sign-in succeed (the office desktop appeared)?</summary>
    public bool? SignInWorked { get; init; }
    /// <summary>Did Tally open and show the right company?</summary>
    public bool? TallyWorked { get; init; }
}

public sealed record Diagnosis(FailureLayer Layer, string Title, string Explanation, string WhatToDo, string WhoFixes, string? NextQuestion)
{
    public bool NeedsAnswer => NextQuestion is not null;
}

/// <summary>
/// Decides where the journey breaks, using what the software can observe
/// first (activation, tunnel, office probe) and asking the customer only for
/// what it cannot observe (Remote Desktop, Windows sign-in, Tally). It never
/// infers that Tally works from a handshake.
/// </summary>
public static class Troubleshooter
{
    public const string QRdp = "Did a Remote Desktop window open and ask you to sign in?";
    public const string QSignIn = "After signing in, did the office computer's desktop appear?";
    public const string QTally = "Did Tally open and show the right company?";

    public static Diagnosis Diagnose(bool activated, DeviceConfig? cfg, ConnectionState state, ProbeResult probe, TroubleshootAnswers a)
    {
        if (!activated)
            return new(FailureLayer.Activation, "This laptop is not activated", "Without activation DishNet does not know this computer and cannot connect it.",
                "Open the install link DishNet sent for this computer, or enter the activation code on the main screen. Each code works once, on one computer.", "You, with DishNet", null);

        switch (state)
        {
            case ConnectionState.Revoked:
                return new(FailureLayer.Activation, "Access to DishNet was removed", "DishNet has revoked this device or the subscription/trial has ended.",
                    "Contact DishNet. A new install link or code is needed if the device was removed; renewal restores access within a minute.", "DishNet", null);
            case ConnectionState.Error:
                return new(FailureLayer.Vpn, "The connection could not start", "A problem on this laptop stopped the secure tunnel (see the message on the main screen).",
                    "Close the app and open it again as administrator. If it repeats, click Save diagnostics… and send the file to DishNet.", "You, then DishNet", null);
            case ConnectionState.Connecting:
            case ConnectionState.Reconnecting:
                return new(FailureLayer.Vpn, "Not connected to DishNet yet", "The tunnel has not come up. Almost always this laptop has no working internet.",
                    "Open any website in a browser. Once the internet works, the app connects by itself. Nothing at the office needs to change.", "You (your internet)", null);
            case ConnectionState.Disconnected:
            case ConnectionState.NotActivated:
                return new(FailureLayer.Vpn, "Not connected", "You have not clicked Connect, or you disconnected.",
                    "Click Connect to Office and wait for Connected.", "You", null);
        }

        if (cfg is null || cfg.Access.Count == 0)
            return new(FailureLayer.OfficePc, "No office computer registered", "DishNet has not set up an office computer for your business yet, so there is nothing to connect to.",
                "Contact DishNet to set up the office computer.", "DishNet", null);

        if (probe == ProbeResult.Unreachable)
            return new(FailureLayer.OfficePc, "The office computer is not answering", "Your laptop is connected, but the office computer does not respond on the Remote Desktop port. It is off, asleep, offline, DishNet is not connected there, or Remote Desktop was not allowed on it.",
                "Ask someone at the office to: switch the computer on; check the DishNet app there shows Connected; check \"Allow Remote Desktop for DishNet users\" was clicked. Then try again.", "The office (IT contact)", null);

        if (probe == ProbeResult.NotChecked)
            return new(FailureLayer.OfficePc, "Checking the office computer…", "The app is testing whether the office computer answers.",
                "Wait a few seconds and run the check again.", "—", null);

        // From here the software has verified the path to the office. The rest it must ask.
        if (a.RdpWindowOpened is null)
            return new(FailureLayer.RemoteDesktop, "Office computer reachable — let's check Remote Desktop", "The connection and the office computer are fine.", "", "—", QRdp);
        if (a.RdpWindowOpened == false)
            return new(FailureLayer.RemoteDesktop, "Remote Desktop did not open", "Windows Remote Desktop on this laptop did not start or could not reach the sign-in screen, although the office computer is reachable.",
                "Click Open Remote Desktop again. If nothing appears, press the Windows key, type \"mstsc\", open Remote Desktop Connection and type the office computer's address shown on the main screen. If it says the remote computer refused the connection, Remote Desktop is not enabled on the office computer — the office must click Allow in their DishNet app.", "You, then the office", null);

        if (a.SignInWorked is null)
            return new(FailureLayer.WindowsSignIn, "Remote Desktop opened — let's check the sign-in", "", "", "—", QSignIn);
        if (a.SignInWorked == false)
            return new(FailureLayer.WindowsSignIn, "Windows sign-in failed", "The office computer refused the user name or password. DishNet does not hold these and cannot reset them.",
                "Use exactly the user name and password that work on the office computer itself. Accounts with no password cannot use Remote Desktop — set one on that computer. If you are unsure, your office IT contact can reset it. Never send passwords to DishNet.", "Your office IT contact", null);

        if (a.TallyWorked is null)
            return new(FailureLayer.Tally, "Signed in — let's check Tally", "", "", "—", QTally);
        if (a.TallyWorked == false)
            return new(FailureLayer.Tally, "Tally problem on the office computer", "The connection, Remote Desktop and sign-in all work; the issue is inside Tally itself, exactly as it would be at the office desk.",
                "Check Tally opens when someone sits at the office computer. Licence, company list and data-path questions are for your Tally provider. DishNet supports the connection and Remote Desktop.", "Your Tally provider", null);

        return new(FailureLayer.None, "Everything checks out", "Connection, office computer, Remote Desktop, sign-in and Tally all work.",
            "If something still looks wrong, click Save diagnostics… and contact DishNet with a description of what you see.", "—", null);
    }
}
