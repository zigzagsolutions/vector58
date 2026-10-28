using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace BrowserSecurity.Agent.Service;

public interface ISystemInfo
{
    string Hostname { get; }
    string OsVersion { get; }
    string? LocalIp { get; }
}

public sealed class SystemInfo : ISystemInfo
{
    public string Hostname => Environment.MachineName;
    public string OsVersion => RuntimeInformation.OSDescription.Trim();

    /// <summary>Informational only. The server records the public IP from the connection, never from the agent.</summary>
    public string? LocalIp
    {
        get
        {
            try
            {
                return NetworkInterface.GetAllNetworkInterfaces()
                    .Where(n => n.OperationalStatus == OperationalStatus.Up && n.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                    .SelectMany(n => n.GetIPProperties().UnicastAddresses)
                    .Select(a => a.Address)
                    .FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork)
                    ?.ToString();
            }
            catch (NetworkInformationException)
            {
                return null;
            }
        }
    }
}
