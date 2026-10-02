using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace DishNet.SecureConnect.Core.Secrets;

/// <summary>
/// Protects bytes at rest. The Windows implementation wraps DPAPI
/// (LocalMachine scope, so the SYSTEM tunnel service and the user's app share
/// it); tests use an in-memory XOR stand-in. The private key and device token
/// are only ever written through this interface.
/// </summary>
public interface ISecretProtector
{
    byte[] Protect(byte[] plaintext);
    byte[] Unprotect(byte[] ciphertext);
}

/// <summary>What the device remembers between runs. Never logged unredacted.</summary>
public sealed record DeviceIdentity
{
    [JsonPropertyName("device_id")] public long DeviceId { get; init; }
    [JsonPropertyName("device_name")] public string DeviceName { get; init; } = "";
    [JsonPropertyName("customer_name")] public string CustomerName { get; init; } = "";
    [JsonPropertyName("role")] public string Role { get; init; } = "client";
    [JsonPropertyName("private_key")] public string PrivateKey { get; init; } = "";
    [JsonPropertyName("public_key")] public string PublicKey { get; init; } = "";
    [JsonPropertyName("device_token")] public string DeviceToken { get; init; } = "";
    [JsonPropertyName("api_origin")] public string ApiOrigin { get; init; } = "";
    [JsonPropertyName("config_version")] public int ConfigVersion { get; init; }
    [JsonPropertyName("activated_at")] public DateTimeOffset ActivatedAt { get; init; }
}

/// <summary>
/// Stores the identity as a single protected file (default
/// %ProgramData%\DishNet\SecureConnect\identity.bin). Writes are atomic
/// (temp file + rename) so a crash never leaves a half-written identity.
/// </summary>
public sealed class DeviceIdentityStore
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    private readonly string _path;
    private readonly ISecretProtector _protector;

    public DeviceIdentityStore(string path, ISecretProtector protector)
    {
        _path = path;
        _protector = protector;
    }

    public string Path => _path;
    public bool Exists => File.Exists(_path);

    public DeviceIdentity? Load()
    {
        if (!File.Exists(_path)) return null;
        var plain = _protector.Unprotect(File.ReadAllBytes(_path));
        try
        {
            return JsonSerializer.Deserialize<DeviceIdentity>(plain, Json);
        }
        finally
        {
            Array.Clear(plain);
        }
    }

    public void Save(DeviceIdentity identity)
    {
        var dir = System.IO.Path.GetDirectoryName(_path);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
        var plain = JsonSerializer.SerializeToUtf8Bytes(identity, Json);
        var protectedBytes = _protector.Protect(plain);
        Array.Clear(plain);
        var tmp = _path + ".tmp";
        File.WriteAllBytes(tmp, protectedBytes);
        File.Move(tmp, _path, overwrite: true);
    }

    /// <summary>Forgets the device (after revocation or on uninstall).</summary>
    public void Delete()
    {
        if (File.Exists(_path))
        {
            // Overwrite before unlink so the protected blob is not recoverable from free space.
            var len = new FileInfo(_path).Length;
            File.WriteAllBytes(_path, new byte[len]);
            File.Delete(_path);
        }
    }
}

/// <summary>Test/dev protector: reversible, NOT secure. The Windows app registers DpapiProtector instead.</summary>
public sealed class InsecureXorProtector(byte key = 0x5A) : ISecretProtector
{
    public byte[] Protect(byte[] plaintext) => plaintext.Select(b => (byte)(b ^ key)).ToArray();
    public byte[] Unprotect(byte[] ciphertext) => ciphertext.Select(b => (byte)(b ^ key)).ToArray();
}

public static class Utf8
{
    public static byte[] Bytes(string s) => Encoding.UTF8.GetBytes(s);
}
