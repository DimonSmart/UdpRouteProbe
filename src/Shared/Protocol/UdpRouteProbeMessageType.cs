namespace UdpRouteProbe.Shared.Protocol;

public enum UdpRouteProbeMessageType : byte
{
    ClientHello  = 1,
    ServerHello  = 2,
    Ping         = 3,
    Pong         = 4,
    EchoRequest  = 5,
    EchoResponse = 6,
    PushRequest  = 7,
    Push         = 8,
    Error        = 9,
}
