namespace UdpRouteProbe.Shared.Protocol;

public sealed class UdpRouteProbePacket
{
    public UdpRouteProbeMessageType MessageType { get; set; }
    public ushort Flags        { get; set; }
    public ulong  ClientIdHash { get; set; }
    public ulong  SessionId    { get; set; }
    public ulong  Sequence     { get; set; }
    public ulong  TimestampMs  { get; set; }
    public byte[] Payload      { get; set; } = Array.Empty<byte>();
}
