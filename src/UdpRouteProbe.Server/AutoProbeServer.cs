using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using UdpRouteProbe.Shared.Protocol;

namespace UdpRouteProbe.Server;

sealed class AutoProbeServerConfig
{
    public string Mode { get; set; } = "autoprobe";
    public string ListenHost { get; set; } = "0.0.0.0";
    public int ListenPort { get; set; } = 9000;
    public List<int> ListenPorts { get; set; } = [];
    public List<ClientEntry> Clients { get; set; } = [];
    public int SessionTimeoutSeconds { get; set; } = 300;
    public string AutoProbeLogDirectory { get; set; } = "logs";
    public bool LogRawPackets { get; set; } = true;
    public int MaxDatagramSize { get; set; } = 65507;
}

sealed class AutoProbeServerSession
{
    public required string ClientId { get; init; }
    public required ulong SessionId { get; init; }
    public required IPEndPoint RemoteEndPoint { get; set; }
    public DateTime LastSeenUtc { get; set; } = DateTime.UtcNow;
}

static class AutoProbeServer
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    private static readonly ConcurrentDictionary<ulong, ClientEntry> Clients = new();
    private static readonly ConcurrentDictionary<string, byte[]> Keys = new();
    private static readonly ConcurrentDictionary<ulong, AutoProbeServerSession> Sessions = new();
    private static readonly object LogLock = new();
    private static AutoProbeServerConfig Config = new();
    private static string LogPath = "";
    private static long ServerReceiveIndex;
    private static long RawPacketCount;
    private static long AcceptedPacketCount;
    private static long RejectedPacketCount;
    private static long ResponseSentCount;
    private static readonly object ConsoleLock = new();

    public static async Task<int> Run(string[] args)
    {
        string configFile = Path.Combine(AppContext.BaseDirectory, "server.json");
        string? listenHost = null;
        string? portsArg = null;
        string? logDir = null;

        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--config" when i + 1 < args.Length: configFile = args[++i]; break;
                case "--listen" when i + 1 < args.Length: listenHost = args[++i]; break;
                case "--ports" when i + 1 < args.Length: portsArg = args[++i]; break;
                case "--log-dir" when i + 1 < args.Length: logDir = args[++i]; break;
            }
        }

        if (!File.Exists(configFile))
        {
            Console.Error.WriteLine($"Config file not found: {configFile}");
            return 1;
        }

        Config = JsonSerializer.Deserialize<AutoProbeServerConfig>(await File.ReadAllTextAsync(configFile), JsonOptions) ?? new();
        if (listenHost is not null) Config.ListenHost = listenHost;
        if (portsArg is not null) Config.ListenPorts = ParsePorts(portsArg);
        if (logDir is not null) Config.AutoProbeLogDirectory = logDir;
        if (Config.ListenPorts.Count == 0) Config.ListenPorts.Add(Config.ListenPort);

        foreach (ClientEntry client in Config.Clients)
        {
            Clients[HmacHelper.ComputeClientIdHash(client.ClientId)] = client;
            Keys[client.ClientId] = Encoding.UTF8.GetBytes(client.SecretKey);
        }

        Directory.CreateDirectory(Config.AutoProbeLogDirectory);
        LogPath = Path.Combine(Config.AutoProbeLogDirectory, $"autoprobe-server-{DateTime.UtcNow:yyyyMMdd}.jsonl");

        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

        WriteEvent(new
        {
            eventType = "ServerStarted",
            process = "server",
            listenHost = Config.ListenHost,
            listenPorts = Config.ListenPorts,
        });
        Console.WriteLine($"AutoProbe log: {LogPath}");
        Console.WriteLine($"AutoProbe clients: {string.Join(", ", Config.Clients.Select(c => c.ClientId))}");

        var listeners = Config.ListenPorts
            .Select(port => Task.Run(() => Listen(port, cts.Token)))
            .ToArray();

        _ = Task.Run(() => CleanupSessions(cts.Token));
        await Task.WhenAll(listeners);
        return 0;
    }

    private static async Task Listen(int port, CancellationToken ct)
    {
        var local = new IPEndPoint(IPAddress.Parse(Config.ListenHost), port);
        using var udp = new UdpClient(local);
        ct.Register(() => udp.Dispose());

        Console.WriteLine($"AutoProbe listening on {local}");
        WriteEvent(new { eventType = "ListenerStarted", process = "server", localEndpoint = local.ToString() });

        while (!ct.IsCancellationRequested)
        {
            try
            {
                UdpReceiveResult result = await udp.ReceiveAsync(ct);
                _ = Task.Run(() => ProcessPacket(udp, local, result.Buffer, result.RemoteEndPoint), CancellationToken.None);
            }
            catch (OperationCanceledException) { break; }
            catch (ObjectDisposedException) when (ct.IsCancellationRequested) { break; }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Listener {port} error: {ex.Message}");
            }
        }
    }

    private static void ProcessPacket(UdpClient udp, IPEndPoint local, byte[] datagram, IPEndPoint remote)
    {
        string packetHash = AutoProbeProtocol.PacketHash64(datagram);
        string first16 = AutoProbeProtocol.First16Hex(datagram);

        if (Config.LogRawPackets)
        {
            long rawCount = Interlocked.Increment(ref RawPacketCount);
            WriteEvent(new
            {
                eventType = "RawPacketReceived",
                process = "server",
                localEndpoint = local.ToString(),
                remoteEndpoint = remote.ToString(),
                datagramSize = datagram.Length,
                first16BytesHex = first16,
                packetHash64 = packetHash,
            });
            ConsoleRaw(rawCount, local, remote, datagram.Length, first16, packetHash);
        }

        if (datagram.Length > Config.MaxDatagramSize)
        {
            Reject(remote, local, "PayloadTooLarge", datagram.Length, first16, packetHash, null);
            return;
        }

        if (!AutoProbeProtocol.TryPeekClientIdHash(datagram, out ulong clientIdHash) || !Clients.TryGetValue(clientIdHash, out ClientEntry? client))
        {
            Reject(remote, local, "UnknownClientIdHash", datagram.Length, first16, packetHash, null);
            return;
        }

        byte[] key = Keys[client.ClientId];
        if (!AutoProbeProtocol.TryDecode(datagram, key, out AutoProbeDecodedPacket? decoded, out string reason) || decoded is null)
        {
            Reject(remote, local, reason, datagram.Length, first16, packetHash, null);
            return;
        }

        AutoProbeMetadata meta = decoded.Metadata;
        if (meta.PacketRole == AutoProbePacketRole.SameServerNoise.ToString())
        {
            Reject(remote, local, "NoisePacket", datagram.Length, first16, packetHash, meta);
            return;
        }

        ulong sessionId = decoded.Packet.SessionId;
        if (decoded.Packet.MessageType == UdpRouteProbeMessageType.ClientHello || sessionId == 0)
        {
            if (sessionId == 0)
                sessionId = unchecked((ulong)Random.Shared.NextInt64());
            while (sessionId == 0) sessionId = unchecked((ulong)Random.Shared.NextInt64());
            Sessions[sessionId] = new AutoProbeServerSession
            {
                ClientId = client.ClientId,
                SessionId = sessionId,
                RemoteEndPoint = remote,
            };
        }
        else if (Sessions.TryGetValue(sessionId, out AutoProbeServerSession? session))
        {
            if (!session.RemoteEndPoint.Equals(remote))
            {
                WriteEvent(new
                {
                    eventType = "EndpointChanged",
                    process = "server",
                    meta.RunId,
                    client.ClientId,
                    sessionId,
                    oldEndpoint = session.RemoteEndPoint.ToString(),
                    newEndpoint = remote.ToString(),
                });
                session.RemoteEndPoint = remote;
            }
            session.LastSeenUtc = DateTime.UtcNow;
        }
        else
        {
            Reject(remote, local, "UnknownSession", datagram.Length, first16, packetHash, meta);
            return;
        }

        long receiveIndex = Interlocked.Increment(ref ServerReceiveIndex);
        long acceptedCount = Interlocked.Increment(ref AcceptedPacketCount);
        WriteEvent(new
        {
            eventType = "PacketAccepted",
            process = "server",
            meta.RunId,
            client.ClientId,
            meta.TestId,
            meta.CaseId,
            meta.ProbeId,
            meta.PacketId,
            packetRole = meta.PacketRole,
            messageType = decoded.Packet.MessageType.ToString(),
            wireFormat = decoded.WireFormat,
            payloadProfile = meta.PayloadProfile,
            payloadSize = decoded.Payload.Length,
            packetHash64 = packetHash,
            remoteEndpoint = remote.ToString(),
            localEndpoint = local.ToString(),
            serverReceiveIndex = receiveIndex,
        });
        ConsoleLine($"ACCEPT #{acceptedCount} {meta.TestId}/{meta.CaseId}/{meta.ProbeId} {decoded.Packet.MessageType} {decoded.WireFormat} payload={decoded.Payload.Length} {remote} -> {local}");

        if (meta.ResponseMode == AutoProbeResponseMode.NoResponse.ToString() ||
            meta.DirectionMode == AutoProbeDirectionMode.ClientToServerOnly.ToString())
            return;

        int delayMs = meta.ResponseMode == AutoProbeResponseMode.DelayedEcho100ms.ToString()
            ? 100
            : meta.ResponseMode == AutoProbeResponseMode.DelayedEcho1000ms.ToString() ? 1000 : 0;

        _ = Task.Run(async () =>
        {
            if (delayMs > 0) await Task.Delay(delayMs);
            var responseMeta = new AutoProbeMetadata
            {
                RunId = meta.RunId,
                ClientId = client.ClientId,
                TestId = meta.TestId,
                CaseId = meta.CaseId,
                ProbeId = meta.ProbeId,
                PacketId = meta.PacketId,
                Sequence = decoded.Packet.Sequence,
                PayloadProfile = meta.PayloadProfile,
                WireFormat = meta.WireFormat,
                PacketRole = meta.PacketRole,
                ResponseMode = meta.ResponseMode,
                DirectionMode = meta.DirectionMode,
            };
            byte[] response = AutoProbeProtocol.BuildDatagram(
                responseMeta,
                decoded.Payload,
                decoded.Packet.ClientIdHash,
                sessionId,
                decoded.Packet.MessageType == UdpRouteProbeMessageType.ClientHello
                    ? UdpRouteProbeMessageType.ServerHello
                    : UdpRouteProbeMessageType.EchoResponse,
                key);
            try
            {
                udp.Send(response, response.Length, remote);
                long responseCount = Interlocked.Increment(ref ResponseSentCount);
                WriteEvent(new
                {
                    eventType = "ResponseSent",
                    process = "server",
                    meta.RunId,
                    client.ClientId,
                    meta.TestId,
                    meta.CaseId,
                    meta.ProbeId,
                    meta.PacketId,
                    messageType = decoded.Packet.MessageType == UdpRouteProbeMessageType.ClientHello ? "ServerHello" : "EchoResponse",
                    remoteEndpoint = remote.ToString(),
                    localEndpoint = local.ToString(),
                    datagramSize = response.Length,
                    sendResult = "OK",
                });
                ConsoleLine($"TX #{responseCount} {meta.TestId}/{meta.CaseId}/{meta.ProbeId} {(decoded.Packet.MessageType == UdpRouteProbeMessageType.ClientHello ? "ServerHello" : "EchoResponse")} bytes={response.Length} {local} -> {remote}");
            }
            catch (Exception ex)
            {
                long responseCount = Interlocked.Increment(ref ResponseSentCount);
                WriteEvent(new
                {
                    eventType = "ResponseSent",
                    process = "server",
                    meta.RunId,
                    client.ClientId,
                    meta.TestId,
                    meta.CaseId,
                    meta.ProbeId,
                    meta.PacketId,
                    remoteEndpoint = remote.ToString(),
                    localEndpoint = local.ToString(),
                    datagramSize = response.Length,
                    sendResult = ex.GetType().Name,
                });
                ConsoleLine($"TX #{responseCount} FAILED {meta.TestId}/{meta.CaseId}/{meta.ProbeId} bytes={response.Length} {local} -> {remote}: {ex.GetType().Name}");
            }
        });
    }

    private static void Reject(IPEndPoint remote, IPEndPoint local, string reason, int datagramSize, string first16, string packetHash, AutoProbeMetadata? meta)
    {
        long rejectedCount = Interlocked.Increment(ref RejectedPacketCount);
        WriteEvent(new
        {
            eventType = "PacketRejected",
            process = "server",
            runId = meta?.RunId,
            clientId = meta?.ClientId,
            testId = meta?.TestId,
            caseId = meta?.CaseId,
            probeId = meta?.ProbeId,
            packetId = meta?.PacketId,
            packetRole = meta?.PacketRole,
            remoteEndpoint = remote.ToString(),
            localEndpoint = local.ToString(),
            reason,
            datagramSize,
            first16BytesHex = first16,
            packetHash64 = packetHash,
        });
        string id = meta is null ? packetHash : $"{meta.TestId}/{meta.CaseId}/{meta.ProbeId}";
        ConsoleReject(rejectedCount, reason, id, remote, local, datagramSize, first16);
    }

    private static async Task CleanupSessions(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try { await Task.Delay(TimeSpan.FromSeconds(30), ct); }
            catch (OperationCanceledException) { break; }

            DateTime cutoff = DateTime.UtcNow - TimeSpan.FromSeconds(Config.SessionTimeoutSeconds);
            foreach (var (id, session) in Sessions)
            {
                if (session.LastSeenUtc < cutoff)
                    Sessions.TryRemove(id, out _);
            }
        }
    }

    private static void ConsoleRaw(long count, IPEndPoint local, IPEndPoint remote, int size, string first16, string packetHash)
    {
        if (count <= 20 || count % 100 == 0)
            ConsoleLine($"RX raw #{count} bytes={size} {remote} -> {local} hash={packetHash} first16={first16}");
    }

    private static void ConsoleReject(long count, string reason, string id, IPEndPoint remote, IPEndPoint local, int size, string first16)
    {
        if (count <= 20 || count % 50 == 0)
            ConsoleLine($"REJECT #{count} reason={reason} id={id} bytes={size} {remote} -> {local} first16={first16}");
    }

    private static void ConsoleLine(string message)
    {
        lock (ConsoleLock)
            Console.WriteLine($"{DateTime.UtcNow:HH:mm:ss.fff} {message}");
    }

    private static void WriteEvent(object value)
    {
        var common = new Dictionary<string, object?>
        {
            ["schemaVersion"] = 1,
            ["eventId"] = Guid.NewGuid().ToString(),
            ["utc"] = DateTime.UtcNow.ToString("O"),
            ["monotonicTimestampMs"] = Stopwatch.GetTimestamp() * 1000 / Stopwatch.Frequency,
        };

        foreach (var property in value.GetType().GetProperties())
            common[property.Name[..1].ToLowerInvariant() + property.Name[1..]] = property.GetValue(value);

        string line = JsonSerializer.Serialize(common, JsonOptions);
        lock (LogLock)
            File.AppendAllText(LogPath, line + Environment.NewLine);
    }

    private static List<int> ParsePorts(string value)
        => value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(int.Parse)
            .Distinct()
            .ToList();
}
