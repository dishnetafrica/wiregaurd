using System.Text.Json.Serialization;

namespace DishNet.SecureConnect.Core.Api;

/// <summary>Mirror of the management API's device configuration (see docs/phase2-backend.md §3).</summary>
public sealed record DeviceConfig
{
    [JsonPropertyName("device_id")] public long DeviceId { get; init; }
    [JsonPropertyName("device_name")] public string DeviceName { get; init; } = "";
    [JsonPropertyName("role")] public string Role { get; init; } = "client";
    [JsonPropertyName("customer_name")] public string CustomerName { get; init; } = "";
    [JsonPropertyName("address")] public string Address { get; init; } = "";
    [JsonPropertyName("hub_public_key")] public string HubPublicKey { get; init; } = "";
    [JsonPropertyName("endpoint")] public string Endpoint { get; init; } = "";
    [JsonPropertyName("allowed_ips")] public IReadOnlyList<string> AllowedIps { get; init; } = Array.Empty<string>();
    [JsonPropertyName("persistent_keepalive")] public int PersistentKeepalive { get; init; } = 25;
    [JsonPropertyName("dns")] public IReadOnlyList<string> Dns { get; init; } = Array.Empty<string>();
    [JsonPropertyName("access")] public IReadOnlyList<AccessTarget> Access { get; init; } = Array.Empty<AccessTarget>();
    [JsonPropertyName("config_version")] public int ConfigVersion { get; init; }
    [JsonPropertyName("gateway_ports")] public IReadOnlyList<int> GatewayPorts { get; init; } = Array.Empty<int>();
    [JsonPropertyName("vpn_pool")] public string VpnPool { get; init; } = "";
    [JsonPropertyName("plan")] public string Plan { get; init; } = "";
    [JsonPropertyName("subscription_expires_at")] public string? SubscriptionExpiresAt { get; init; }

    public bool IsGateway => string.Equals(Role, "gateway", StringComparison.OrdinalIgnoreCase);
}

public sealed record AccessTarget
{
    [JsonPropertyName("label")] public string Label { get; init; } = "";
    [JsonPropertyName("target")] public string Target { get; init; } = "";
    [JsonPropertyName("proto")] public string Proto { get; init; } = "tcp";
    [JsonPropertyName("ports")] public IReadOnlyList<int> Ports { get; init; } = Array.Empty<int>();
}

public sealed record ActivateRequest
{
    [JsonPropertyName("code")] public string Code { get; init; } = "";
    [JsonPropertyName("public_key")] public string PublicKey { get; init; } = "";
    [JsonPropertyName("device_name")] public string DeviceName { get; init; } = "";
    [JsonPropertyName("os")] public string Os { get; init; } = "";
    [JsonPropertyName("client_version")] public string ClientVersion { get; init; } = "";
    [JsonPropertyName("lan_subnets")] [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyList<string>? LanSubnets { get; init; }
}

public sealed record ActivateResponse
{
    [JsonPropertyName("device_token")] public string DeviceToken { get; init; } = "";
    [JsonPropertyName("config")] public DeviceConfig Config { get; init; } = new();
}

public sealed record HeartbeatRequest
{
    [JsonPropertyName("client_version")] public string ClientVersion { get; init; } = "";
    [JsonPropertyName("connected")] public bool Connected { get; init; }
}

public sealed record HeartbeatResponse
{
    [JsonPropertyName("ok")] public bool Ok { get; init; }
    [JsonPropertyName("config_version")] public int ConfigVersion { get; init; }
}

public sealed record RotateKeyRequest
{
    [JsonPropertyName("new_public_key")] public string NewPublicKey { get; init; } = "";
}

public sealed record LatestClient
{
    [JsonPropertyName("version")] public string Version { get; init; } = "";
    [JsonPropertyName("url")] public string Url { get; init; } = "";
    [JsonPropertyName("sha256")] public string Sha256 { get; init; } = "";
    [JsonPropertyName("size")] public long Size { get; init; }
}

public sealed record ApiErrorBody
{
    [JsonPropertyName("error")] public string Error { get; init; } = "";
    [JsonPropertyName("code")] public string Code { get; init; } = "";
    [JsonPropertyName("reason")] public string? Reason { get; init; }
}
