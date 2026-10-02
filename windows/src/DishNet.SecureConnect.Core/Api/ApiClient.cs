using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;

namespace DishNet.SecureConnect.Core.Api;

/// <summary>
/// Why an API call was refused, mapped from the server's stable error codes so
/// the UI can show the right message without parsing text.
/// </summary>
public enum ApiFailure
{
    Network,            // could not reach the server (offline, DNS, TLS)
    InvalidCode,
    CodeUsed,
    CodeExpired,
    CodeRevoked,
    CustomerBlocked,
    DeviceLimit,
    BadPublicKey,
    DuplicateKey,
    RateLimited,
    Unauthorized,       // device token no longer valid
    AccessDeniedRevoked,
    AccessDeniedSuspended,
    AccessDeniedExpired,
    ProvisioningFailed, // server-side; retry later
    ServerError,
    Unknown,
}

public sealed class ApiException : Exception
{
    public ApiFailure Failure { get; }
    public HttpStatusCode? Status { get; }
    public string? ServerCode { get; }

    public ApiException(ApiFailure failure, string message, HttpStatusCode? status = null, string? serverCode = null, Exception? inner = null)
        : base(message, inner)
    {
        Failure = failure;
        Status = status;
        ServerCode = serverCode;
    }

    /// <summary>True when the device should stop trying: it has been revoked, or its customer suspended/expired.</summary>
    public bool IsTerminal => Failure is ApiFailure.AccessDeniedRevoked or ApiFailure.AccessDeniedSuspended or ApiFailure.AccessDeniedExpired or ApiFailure.Unauthorized;

    public static ApiFailure MapServerCode(string? code, string? reason) => code switch
    {
        "invalid_code" => ApiFailure.InvalidCode,
        "code_used" => ApiFailure.CodeUsed,
        "code_expired" => ApiFailure.CodeExpired,
        "code_revoked" => ApiFailure.CodeRevoked,
        "customer_blocked" => ApiFailure.CustomerBlocked,
        "device_limit" => ApiFailure.DeviceLimit,
        "bad_public_key" => ApiFailure.BadPublicKey,
        "duplicate_key" => ApiFailure.DuplicateKey,
        "rate_limited" => ApiFailure.RateLimited,
        "unauthorized" => ApiFailure.Unauthorized,
        "provisioning_failed" => ApiFailure.ProvisioningFailed,
        "access_denied" => reason switch
        {
            "revoked" => ApiFailure.AccessDeniedRevoked,
            "suspended" => ApiFailure.AccessDeniedSuspended,
            "expired" => ApiFailure.AccessDeniedExpired,
            _ => ApiFailure.Unauthorized,
        },
        "internal" => ApiFailure.ServerError,
        _ => ApiFailure.Unknown,
    };
}

/// <summary>
/// Thin, typed client for the DishNet management API. It never sees the
/// device's private key: callers pass the public key only.
/// </summary>
public sealed class ApiClient
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    private readonly HttpClient _http;
    private readonly string _clientVersion;

    public ApiClient(HttpClient http, string clientVersion)
    {
        _http = http;
        _clientVersion = clientVersion;
        if (_http.BaseAddress is null) throw new ArgumentException("HttpClient.BaseAddress must be set to the API origin", nameof(http));
        _http.Timeout = TimeSpan.FromSeconds(20);
        _http.DefaultRequestHeaders.UserAgent.ParseAdd($"DishNetSecureConnect/{clientVersion}");
        _http.DefaultRequestHeaders.Add("X-Client-Version", clientVersion);
    }

    public async Task<ActivateResponse> ActivateAsync(string code, string publicKey, string deviceName, string os, IReadOnlyList<string>? lanSubnets, CancellationToken ct)
    {
        var req = new ActivateRequest { Code = code.Trim(), PublicKey = publicKey, DeviceName = deviceName, Os = os, ClientVersion = _clientVersion, LanSubnets = lanSubnets };
        using var msg = new HttpRequestMessage(HttpMethod.Post, "/api/v1/activate") { Content = JsonContent.Create(req, options: Json) };
        return await SendAsync<ActivateResponse>(msg, ct);
    }

    public async Task<DeviceConfig> GetConfigAsync(string deviceToken, CancellationToken ct)
    {
        using var msg = new HttpRequestMessage(HttpMethod.Get, "/api/v1/device/config");
        msg.Headers.Authorization = new AuthenticationHeaderValue("Bearer", deviceToken);
        return await SendAsync<DeviceConfig>(msg, ct);
    }

    public async Task<HeartbeatResponse> HeartbeatAsync(string deviceToken, bool connected, CancellationToken ct)
    {
        using var msg = new HttpRequestMessage(HttpMethod.Post, "/api/v1/device/heartbeat")
        {
            Content = JsonContent.Create(new HeartbeatRequest { ClientVersion = _clientVersion, Connected = connected }, options: Json),
        };
        msg.Headers.Authorization = new AuthenticationHeaderValue("Bearer", deviceToken);
        return await SendAsync<HeartbeatResponse>(msg, ct);
    }

    public async Task<DeviceConfig> RotateKeyAsync(string deviceToken, string newPublicKey, CancellationToken ct)
    {
        using var msg = new HttpRequestMessage(HttpMethod.Post, "/api/v1/device/rotate-key")
        {
            Content = JsonContent.Create(new RotateKeyRequest { NewPublicKey = newPublicKey }, options: Json),
        };
        msg.Headers.Authorization = new AuthenticationHeaderValue("Bearer", deviceToken);
        return await SendAsync<DeviceConfig>(msg, ct);
    }

    private async Task<T> SendAsync<T>(HttpRequestMessage msg, CancellationToken ct)
    {
        HttpResponseMessage res;
        try
        {
            res = await _http.SendAsync(msg, HttpCompletionOption.ResponseHeadersRead, ct);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            throw new ApiException(ApiFailure.Network, "The DishNet server did not respond in time.");
        }
        catch (HttpRequestException ex)
        {
            throw new ApiException(ApiFailure.Network, "Could not reach the DishNet server. Check your internet connection.", inner: ex);
        }

        using (res)
        {
            if (res.IsSuccessStatusCode)
            {
                var body = await res.Content.ReadFromJsonAsync<T>(Json, ct);
                return body ?? throw new ApiException(ApiFailure.ServerError, "Empty response from server.", res.StatusCode);
            }

            ApiErrorBody? err = null;
            try { err = await res.Content.ReadFromJsonAsync<ApiErrorBody>(Json, ct); } catch (JsonException) { }
            var failure = err is null
                ? (res.StatusCode >= HttpStatusCode.InternalServerError ? ApiFailure.ServerError : ApiFailure.Unknown)
                : ApiException.MapServerCode(err.Code, err.Reason);
            if (res.StatusCode == HttpStatusCode.TooManyRequests) failure = ApiFailure.RateLimited;
            var message = err?.Error is { Length: > 0 } m ? m : $"Server returned {(int)res.StatusCode}.";
            throw new ApiException(failure, message, res.StatusCode, err?.Code);
        }
    }
}
