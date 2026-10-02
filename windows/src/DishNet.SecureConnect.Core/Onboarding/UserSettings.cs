using System.Text.Json;
using System.Text.Json.Serialization;

namespace DishNet.SecureConnect.Core.Onboarding;

/// <summary>
/// Non-secret, per-machine preferences and the customer's own confirmations.
/// Stored as plain JSON next to the identity (never contains keys/tokens).
/// </summary>
public sealed record UserSettings
{
    [JsonPropertyName("tour_completed_at")] public DateTimeOffset? TourCompletedAt { get; init; }
    [JsonPropertyName("tour_skipped")] public bool TourSkipped { get; init; }
    /// <summary>When the operator of this PC explicitly allowed DishNet to enable Remote Desktop and VPN-scoped firewall rules.</summary>
    [JsonPropertyName("gateway_consent_at")] public DateTimeOffset? GatewayConsentAt { get; init; }
    [JsonPropertyName("gateway_consent_declined")] public bool GatewayConsentDeclined { get; init; }
    /// <summary>Manual checklist confirmations the customer ticked themselves (never set automatically).</summary>
    [JsonPropertyName("confirmed_rdp_instructions_at")] public DateTimeOffset? ConfirmedRdpInstructionsAt { get; init; }
    [JsonPropertyName("confirmed_tally_opened_at")] public DateTimeOffset? ConfirmedTallyOpenedAt { get; init; }
    /// <summary>Practice-session confirmations for the "Set up Tally remote access" journey (customer-ticked, never automatic).</summary>
    [JsonPropertyName("practice_signed_in_at")] public DateTimeOffset? PracticeSignedInAt { get; init; }
    [JsonPropertyName("practice_company_opened_at")] public DateTimeOffset? PracticeCompanyOpenedAt { get; init; }
    [JsonPropertyName("practice_task_done_at")] public DateTimeOffset? PracticeTaskDoneAt { get; init; }
    [JsonPropertyName("practice_disconnected_at")] public DateTimeOffset? PracticeDisconnectedAt { get; init; }
    [JsonPropertyName("practice_completed_at")] public DateTimeOffset? PracticeCompletedAt { get; init; }

    public bool TourDone => TourCompletedAt is not null || TourSkipped;
    public bool GatewayConsentGiven => GatewayConsentAt is not null;
}

public sealed class UserSettingsStore
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { WriteIndented = true };
    private readonly string _path;
    private UserSettings _current;

    public UserSettingsStore(string path)
    {
        _path = path;
        _current = Load();
    }

    public UserSettings Current => _current;

    public void Update(Func<UserSettings, UserSettings> change)
    {
        _current = change(_current);
        var dir = Path.GetDirectoryName(_path);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
        var tmp = _path + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(_current, Json));
        File.Move(tmp, _path, overwrite: true);
    }

    private UserSettings Load()
    {
        try
        {
            if (!File.Exists(_path)) return new UserSettings();
            return JsonSerializer.Deserialize<UserSettings>(File.ReadAllText(_path), Json) ?? new UserSettings();
        }
        catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException)
        {
            return new UserSettings();
        }
    }
}
