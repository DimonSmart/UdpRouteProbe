using System.Security.Cryptography;
using System.Text;

namespace UdpRouteProbe.Shared.Protocol;

public static class HmacHelper
{
    public static ulong ComputeClientIdHash(string clientId)
    {
        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(clientId));
        return BigEndianBinary.ReadUInt64(hash, 0);
    }

    public static ulong NowMs()
        => (ulong)DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
}
