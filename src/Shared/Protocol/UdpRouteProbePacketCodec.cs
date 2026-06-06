using System.Security.Cryptography;

namespace UdpRouteProbe.Shared.Protocol;

// Packet wire format (big-endian):
//   [0..3]  magic        "URP1"
//   [4]     version      1
//   [5]     messageType
//   [6..7]  flags
//   [8..15] clientIdHash
//   [16..23] sessionId
//   [24..31] sequence
//   [32..39] timestampMs
//   [40..41] payloadLength
//   [42..42+N-1] payload
//   [42+N..42+N+31] hmac-sha256

public static class UdpRouteProbePacketCodec
{
    private static readonly byte[] Magic = [(byte)'U', (byte)'R', (byte)'P', (byte)'1'];
    private const byte   Version     = 1;
    public  const int    HeaderSize  = 42;  // bytes before payload
    public  const int    HmacSize    = 32;
    public  const int    MinSize     = HeaderSize + HmacSize;
    public  const int    MaxPayload  = 65000;

    public static byte[] Encode(UdpRouteProbePacket packet, byte[] secretKey)
    {
        int payloadLen = packet.Payload?.Length ?? 0;
        byte[] buf = new byte[HeaderSize + payloadLen + HmacSize];

        buf[0] = Magic[0]; buf[1] = Magic[1]; buf[2] = Magic[2]; buf[3] = Magic[3];
        buf[4] = Version;
        buf[5] = (byte)packet.MessageType;
        BigEndianBinary.WriteUInt16(buf, 6,  packet.Flags);
        BigEndianBinary.WriteUInt64(buf, 8,  packet.ClientIdHash);
        BigEndianBinary.WriteUInt64(buf, 16, packet.SessionId);
        BigEndianBinary.WriteUInt64(buf, 24, packet.Sequence);
        BigEndianBinary.WriteUInt64(buf, 32, packet.TimestampMs);
        BigEndianBinary.WriteUInt16(buf, 40, (ushort)payloadLen);

        if (payloadLen > 0)
            packet.Payload.AsSpan().CopyTo(buf.AsSpan(HeaderSize, payloadLen));

        using var hmac = new HMACSHA256(secretKey);
        byte[] hash = hmac.ComputeHash(buf, 0, HeaderSize + payloadLen);
        hash.AsSpan().CopyTo(buf.AsSpan(HeaderSize + payloadLen, HmacSize));

        return buf;
    }

    // Peeks clientIdHash without verifying HMAC — used by server to look up the key first.
    public static bool TryPeekClientIdHash(ReadOnlySpan<byte> data, out ulong clientIdHash)
    {
        clientIdHash = 0;
        if (data.Length < MinSize) return false;
        if (data[0] != Magic[0] || data[1] != Magic[1] ||
            data[2] != Magic[2] || data[3] != Magic[3]) return false;
        if (data[4] != Version) return false;
        clientIdHash = BigEndianBinary.ReadUInt64(data, 8);
        return true;
    }

    public static bool TryDecode(
        ReadOnlySpan<byte> data,
        byte[] secretKey,
        out UdpRouteProbePacket? packet)
    {
        packet = null;
        if (data.Length < MinSize) return false;
        if (data[0] != Magic[0] || data[1] != Magic[1] ||
            data[2] != Magic[2] || data[3] != Magic[3]) return false;
        if (data[4] != Version) return false;

        ushort payloadLen = BigEndianBinary.ReadUInt16(data, 40);
        if (data.Length != HeaderSize + payloadLen + HmacSize) return false;

        // Verify HMAC
        byte[] body = data[..(HeaderSize + payloadLen)].ToArray();
        using var hmac  = new HMACSHA256(secretKey);
        byte[] expected = hmac.ComputeHash(body);
        ReadOnlySpan<byte> actual = data.Slice(HeaderSize + payloadLen, HmacSize);
        if (!CryptographicOperations.FixedTimeEquals(expected, actual)) return false;

        packet = new UdpRouteProbePacket
        {
            MessageType  = (UdpRouteProbeMessageType)data[5],
            Flags        = BigEndianBinary.ReadUInt16(data, 6),
            ClientIdHash = BigEndianBinary.ReadUInt64(data, 8),
            SessionId    = BigEndianBinary.ReadUInt64(data, 16),
            Sequence     = BigEndianBinary.ReadUInt64(data, 24),
            TimestampMs  = BigEndianBinary.ReadUInt64(data, 32),
            Payload      = payloadLen > 0
                               ? data.Slice(HeaderSize, payloadLen).ToArray()
                               : Array.Empty<byte>(),
        };
        return true;
    }
}
