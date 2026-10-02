using System.Text.RegularExpressions;

namespace DishNet.SecureConnect.Core.Diagnostics;

/// <summary>
/// Strips secrets from anything that goes to a log or a diagnostics bundle:
/// WireGuard private keys, device tokens, activation codes and admin
/// passwords. Public keys and addresses are kept — they are needed for
/// support and are not secret.
/// </summary>
public static partial class Redactor
{
    [GeneratedRegex(@"(?im)^(\s*PrivateKey\s*=\s*).+$")] private static partial Regex PrivateKeyLine();
    [GeneratedRegex(@"dnd_[A-Za-z0-9_-]{20,}")] private static partial Regex DeviceToken();
    [GeneratedRegex(@"(?i)\bDN-[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}\b")] private static partial Regex ActivationCode();
    [GeneratedRegex(@"(?i)(""?(private_key|password|device_token|token)""?\s*[:=]\s*""?)([^""\s,}]+)")] private static partial Regex JsonSecret();

    public static string Redact(string? text)
    {
        if (string.IsNullOrEmpty(text)) return "";
        var t = PrivateKeyLine().Replace(text, "$1<redacted>");
        t = DeviceToken().Replace(t, "dnd_<redacted>");
        t = ActivationCode().Replace(t, m => m.Value[..7] + "-<redacted>");
        t = JsonSecret().Replace(t, "$1<redacted>");
        return t;
    }
}
