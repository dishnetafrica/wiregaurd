namespace DishNet.SecureConnect.Core.Onboarding;

public enum EditionClass { Unknown, Home, Pro, Server }

/// <summary>
/// Classifies a Windows edition for the office-computer role. Only Pro,
/// Enterprise, Education and Server editions can accept Remote Desktop
/// connections; Home ("Core") editions cannot.
/// </summary>
public static class WindowsEdition
{
    public static EditionClass Classify(string? editionId, string? productName = null)
    {
        var e = (editionId ?? "").Trim();
        var n = (productName ?? "").Trim();
        if (e.StartsWith("Server", StringComparison.OrdinalIgnoreCase) || n.Contains("Server", StringComparison.OrdinalIgnoreCase)) return EditionClass.Server;
        if (e.StartsWith("Core", StringComparison.OrdinalIgnoreCase) || n.Contains(" Home", StringComparison.OrdinalIgnoreCase)) return EditionClass.Home;
        if (e.Length > 0 || n.Length > 0) return EditionClass.Pro; // Professional, Enterprise, Education, ProfessionalWorkstation …
        return EditionClass.Unknown;
    }

    public static string Describe(EditionClass c) => c switch
    {
        EditionClass.Home => "Home",
        EditionClass.Pro => "Pro",
        EditionClass.Server => "Server",
        _ => "unknown edition",
    };
}
