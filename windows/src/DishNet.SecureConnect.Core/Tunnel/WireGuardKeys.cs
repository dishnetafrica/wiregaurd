using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace DishNet.SecureConnect.Core.Tunnel;

/// <summary>
/// Curve25519 key pairs in WireGuard's base64 format. Uses BouncyCastle's
/// audited X25519 implementation; nothing cryptographic is hand-rolled.
/// On Windows the app may alternatively call WireGuardGenerateKeypair in
/// tunnel.dll — both produce interchangeable keys.
/// </summary>
public static class WireGuardKeys
{
    public const int KeyLength = 32;

    public sealed record KeyPair(string PrivateKey, string PublicKey);

    public static KeyPair Generate()
    {
        var priv = new X25519PrivateKeyParameters(new SecureRandom());
        return new KeyPair(Convert.ToBase64String(priv.GetEncoded()), Convert.ToBase64String(priv.GeneratePublicKey().GetEncoded()));
    }

    /// <summary>Derives the public key from a private key (same operation as `wg pubkey`).</summary>
    public static string PublicKeyFromPrivate(string privateKeyBase64)
    {
        var raw = Decode(privateKeyBase64) ?? throw new ArgumentException("not a valid WireGuard private key");
        return Convert.ToBase64String(new X25519PrivateKeyParameters(raw).GeneratePublicKey().GetEncoded());
    }

    public static bool IsValidKey(string? base64) => Decode(base64) is not null;

    private static byte[]? Decode(string? s)
    {
        if (string.IsNullOrWhiteSpace(s) || s.Length != 44) return null;
        try
        {
            var b = Convert.FromBase64String(s);
            return b.Length == KeyLength ? b : null;
        }
        catch (FormatException) { return null; }
    }
}
