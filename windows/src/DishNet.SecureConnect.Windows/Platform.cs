using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using DishNet.SecureConnect.Core.Secrets;
using Microsoft.Win32;

namespace DishNet.SecureConnect.Windows;

/// <summary>Well-known locations. Everything lives under ProgramData so the SYSTEM tunnel service and the elevated app see the same files.</summary>
[SupportedOSPlatform("windows")]
public static class Paths
{
    public static readonly string DataDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "DishNet", "SecureConnect");
    public static readonly string IdentityFile = Path.Combine(DataDir, "identity.bin");
    public static readonly string LogDir = Path.Combine(DataDir, "logs");
    public static readonly string TunnelConfigFile = Path.Combine(DataDir, Core.Tunnel.TunnelConfigRenderer.TunnelName + ".conf");

    /// <summary>Official WireGuard for Windows install location (installed by the DishNet setup).</summary>
    public static readonly string WireGuardExe = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "WireGuard", "wireguard.exe");

    /// <summary>Creates the data directory readable/writable by SYSTEM and Administrators only.</summary>
    public static void EnsureDataDir()
    {
        var existed = Directory.Exists(DataDir);
        Directory.CreateDirectory(DataDir);
        Directory.CreateDirectory(LogDir);
        if (existed) return;
        try
        {
            var sec = new DirectorySecurity();
            sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            sec.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
            sec.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
            new DirectoryInfo(DataDir).SetAccessControl(sec);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            // Non-fatal: ProgramData subfolders are not world-writable by default either.
            System.Diagnostics.Debug.WriteLine("EnsureDataDir ACL: " + ex.Message);
        }
    }
}

/// <summary>DPAPI, machine scope, with app-specific entropy. The blob can only be read on this machine.</summary>
[SupportedOSPlatform("windows")]
public sealed class DpapiProtector : ISecretProtector
{
    private static readonly byte[] Entropy = System.Text.Encoding.UTF8.GetBytes("DishNet Secure Connect identity v1");
    public byte[] Protect(byte[] plaintext) => ProtectedData.Protect(plaintext, Entropy, DataProtectionScope.LocalMachine);
    public byte[] Unprotect(byte[] ciphertext) => ProtectedData.Unprotect(ciphertext, Entropy, DataProtectionScope.LocalMachine);
}

[SupportedOSPlatform("windows")]
public static class Elevation
{
    public static bool IsAdministrator()
    {
        using var id = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
    }
}

/// <summary>"Start with Windows" via the per-user Run key (the tunnel service itself is auto-start regardless; this only brings the status window back).</summary>
[SupportedOSPlatform("windows")]
public static class StartupRegistration
{
    private const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string ValueName = "DishNetSecureConnect";

    public static bool IsEnabled()
    {
        using var k = Registry.CurrentUser.OpenSubKey(RunKey);
        return k?.GetValue(ValueName) is string;
    }

    public static void Set(bool enabled, string exePath)
    {
        using var k = Registry.CurrentUser.CreateSubKey(RunKey)!;
        if (enabled) k.SetValue(ValueName, $"\"{exePath}\" /minimized");
        else k.DeleteValue(ValueName, throwOnMissingValue: false);
    }
}

public static class OsInfo
{
    /// <summary>e.g. "Windows 11 Pro 10.0.22631 x64" — the edition word is what the dashboard uses to verify office-PC suitability.</summary>
    public static string Description()
    {
        var v = Environment.OSVersion.Version;
        var name = v.Build >= 22000 ? "Windows 11" : "Windows 10";
        var edition = OperatingSystem.IsWindows() ? Edition() : Core.Onboarding.EditionClass.Unknown;
        if (edition == Core.Onboarding.EditionClass.Server) name = "Windows Server";
        var ed = edition == Core.Onboarding.EditionClass.Unknown ? "" : " " + Core.Onboarding.WindowsEdition.Describe(edition);
        return $"{name}{ed} {v.Major}.{v.Minor}.{v.Build} {(Environment.Is64BitOperatingSystem ? "x64" : "x86")}";
    }

    [SupportedOSPlatform("windows")]
    public static Core.Onboarding.EditionClass Edition()
    {
        try
        {
            using var k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
            return Core.Onboarding.WindowsEdition.Classify(k?.GetValue("EditionID") as string, k?.GetValue("ProductName") as string);
        }
        catch { return Core.Onboarding.EditionClass.Unknown; }
    }

    [SupportedOSPlatform("windows")]
    private static bool IsServer()
    {
        try
        {
            using var k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
            return (k?.GetValue("InstallationType") as string)?.Equals("Server", StringComparison.OrdinalIgnoreCase) == true;
        }
        catch { return false; }
    }
}
