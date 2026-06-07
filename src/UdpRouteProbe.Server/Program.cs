using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using UdpRouteProbe.Shared.Protocol;

namespace UdpRouteProbe.Server;

// ─── Config ──────────────────────────────────────────────────────────────────

sealed class ServerConfig
{
    public string            Mode                  { get; set; } = "server";
    public string            ListenHost            { get; set; } = "0.0.0.0";
    public int               ListenPort            { get; set; } = 9000;
    public List<ClientEntry> Clients               { get; set; } = [];
    public int               SessionTimeoutSeconds { get; set; } = 300;
    public string            LogLevel              { get; set; } = "Information";
}

sealed class ClientEntry
{
    public string ClientId  { get; set; } = "";
    public string SecretKey { get; set; } = "";
}

// ─── Session ─────────────────────────────────────────────────────────────────

sealed class Session
{
    public string     ClientId       { get; set; } = "";
    public ulong      SessionId      { get; set; }
    public DateTime   CreatedAt      { get; set; }
    public DateTime   LastSeenAt     { get; set; }
    public IPEndPoint RemoteEndPoint { get; set; } = null!;
    public long       ReceivedPackets;
    public long       SentPackets;
#pragma warning disable CS0649
    public long       InvalidPackets; // counted by caller — reserved for future use
#pragma warning restore CS0649
    public ulong      LastSequence;
}

// ─── Server ───────────────────────────────────────────────────────────────────

static class Program
{
    static ServerConfig _config = new();

    // clientIdHash → ClientEntry
    static readonly ConcurrentDictionary<ulong, ClientEntry> _clients = new();

    // sessionId → Session
    static readonly ConcurrentDictionary<ulong, Session> _sessions = new();

    // clientId → secretKey bytes (cached)
    static readonly ConcurrentDictionary<string, byte[]> _keyCache = new();

    static UdpClient _udp = null!;
    static bool      _verbose;

    static readonly JsonSerializerOptions _jsonOpts = new()
    {
        PropertyNameCaseInsensitive = true,
        WriteIndented = false,
    };

    // ── Entry point ──────────────────────────────────────────────────────────

    static async Task<int> Main(string[] args)
    {
        string  configFile = Path.Combine(AppContext.BaseDirectory, "server.json");
        string? listenArg  = null;
        string? modeArg    = null;

        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--config"  when i + 1 < args.Length: configFile = args[++i]; break;
                case "--listen"  when i + 1 < args.Length: listenArg  = args[++i]; break;
                case "--mode"    when i + 1 < args.Length: modeArg    = args[++i]; break;
                case "--verbose" or "-v":                   _verbose   = true;       break;
            }
        }

        string? configuredMode = modeArg ?? await ReadConfiguredMode(configFile);
        if (string.Equals(configuredMode, "autoprobe", StringComparison.OrdinalIgnoreCase))
            return await AutoProbeServer.Run(args);

        if (File.Exists(configFile))
        {
            string json = await File.ReadAllTextAsync(configFile);
            _config = JsonSerializer.Deserialize<ServerConfig>(json, _jsonOpts) ?? new ServerConfig();
        }
        else
        {
            Log("ERROR", $"Config file not found: {configFile}");
            return 1;
        }

        if (listenArg != null)
        {
            int colon = listenArg.LastIndexOf(':');
            if (colon > 0 && int.TryParse(listenArg[(colon + 1)..], out int port))
            {
                _config.ListenHost = listenArg[..colon];
                _config.ListenPort = port;
            }
        }

        foreach (ClientEntry c in _config.Clients)
        {
            ulong hash = HmacHelper.ComputeClientIdHash(c.ClientId);
            _clients[hash] = c;
            _keyCache[c.ClientId] = Encoding.UTF8.GetBytes(c.SecretKey);
        }

        var listenEp = new IPEndPoint(IPAddress.Parse(_config.ListenHost), _config.ListenPort);
        _udp = new UdpClient(listenEp);

        Log("INFO", $"Listening on {_config.ListenHost}:{_config.ListenPort}");
        Log("INFO", $"Known clients: {_config.Clients.Count}");
        if (_config.Clients.Count > 0)
            Log("INFO", $"  " + string.Join(", ", _config.Clients.Select(c => c.ClientId)));

        using var cts = new CancellationTokenSource();
        using CancellationTokenRegistration closeUdpOnCancel = cts.Token.Register(() => _udp.Dispose());

        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            cts.Cancel();
        };

        _ = Task.Run(() => SessionCleanupLoop(cts.Token));

        await ReceiveLoop(cts.Token);
        return 0;
    }

    static async Task<string?> ReadConfiguredMode(string configFile)
    {
        if (!File.Exists(configFile))
            return null;

        using JsonDocument doc = JsonDocument.Parse(await File.ReadAllTextAsync(configFile));
        foreach (JsonProperty property in doc.RootElement.EnumerateObject())
        {
            if (string.Equals(property.Name, "Mode", StringComparison.OrdinalIgnoreCase))
                return property.Value.GetString();
        }

        return null;
    }

    // ── Receive loop ─────────────────────────────────────────────────────────

    static async Task ReceiveLoop(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                UdpReceiveResult result = await _udp.ReceiveAsync(ct);
                _ = Task.Run(() => ProcessPacket(result.Buffer, result.RemoteEndPoint), CancellationToken.None);
            }
            catch (OperationCanceledException) { break; }
            catch (ObjectDisposedException) when (ct.IsCancellationRequested) { break; }
            catch (Exception ex)
            {
                Log("ERROR", $"Receive error: {ex.Message}");
                await Task.Delay(100, CancellationToken.None);
            }
        }
        Log("INFO", "Server stopped.");
    }

    // ── Per-packet processing ────────────────────────────────────────────────

    static void ProcessPacket(byte[] data, IPEndPoint remote)
    {
        try
        {
            if (!UdpRouteProbePacketCodec.TryPeekClientIdHash(data, out ulong hash))
            {
                if (_verbose) Log("DEBUG", $"Malformed packet from {remote} (bad magic or too short)");
                return;
            }

            if (!_clients.TryGetValue(hash, out ClientEntry? entry))
            {
                Log("WARN", $"Unknown clientIdHash {hash:X16} from {remote}");
                return;
            }

            byte[] key = _keyCache[entry.ClientId];

            if (!UdpRouteProbePacketCodec.TryDecode(data, key, out UdpRouteProbePacket? pkt) || pkt is null)
            {
                Log("WARN", $"Invalid HMAC from {remote}");
                return;
            }

            switch (pkt.MessageType)
            {
                case UdpRouteProbeMessageType.ClientHello:
                    HandleClientHello(pkt, entry, remote, key);
                    break;
                case UdpRouteProbeMessageType.Ping:
                    HandlePing(pkt, remote, key);
                    break;
                case UdpRouteProbeMessageType.EchoRequest:
                    HandleEchoRequest(pkt, remote, key);
                    break;
                case UdpRouteProbeMessageType.PushRequest:
                    HandlePushRequest(pkt, remote, key);
                    break;
                default:
                    if (_verbose) Log("DEBUG", $"Unhandled type {pkt.MessageType} from {remote}");
                    break;
            }
        }
        catch (Exception ex)
        {
            Log("ERROR", $"ProcessPacket error from {remote}: {ex.Message}");
        }
    }

    // ── ClientHello ──────────────────────────────────────────────────────────

    static void HandleClientHello(UdpRouteProbePacket pkt, ClientEntry entry, IPEndPoint remote, byte[] key)
    {
        ulong sessionId = pkt.SessionId;

        if (sessionId == 0 || !_sessions.ContainsKey(sessionId))
        {
            sessionId = unchecked((ulong)Random.Shared.NextInt64());
            while (sessionId == 0) sessionId = unchecked((ulong)Random.Shared.NextInt64());
        }

        var session = new Session
        {
            ClientId       = entry.ClientId,
            SessionId      = sessionId,
            CreatedAt      = DateTime.UtcNow,
            LastSeenAt     = DateTime.UtcNow,
            RemoteEndPoint = remote,
            ReceivedPackets = 1,
        };
        _sessions[sessionId] = session;

        Log("INFO",
            $"ClientHello accepted: clientId={entry.ClientId} endpoint={remote} sessionId={sessionId}");

        var payload = new
        {
            sessionId          = sessionId,
            observedRemoteIp   = remote.Address.ToString(),
            observedRemotePort = remote.Port,
            serverTimeUtc      = DateTime.UtcNow.ToString("O"),
        };
        byte[] payloadBytes = JsonSerializer.SerializeToUtf8Bytes(payload, _jsonOpts);

        Send(new UdpRouteProbePacket
        {
            MessageType  = UdpRouteProbeMessageType.ServerHello,
            ClientIdHash = pkt.ClientIdHash,
            SessionId    = sessionId,
            Sequence     = 1,
            TimestampMs  = HmacHelper.NowMs(),
            Payload      = payloadBytes,
        }, remote, key);

        session.SentPackets++;
    }

    // ── Ping ─────────────────────────────────────────────────────────────────

    static void HandlePing(UdpRouteProbePacket pkt, IPEndPoint remote, byte[] key)
    {
        Session? session = GetSession(pkt, remote);
        if (session is null) return;

        // Include observed endpoint so client can detect NAT mapping changes
        byte[] payload = JsonSerializer.SerializeToUtf8Bytes(new
        {
            observedIp   = remote.Address.ToString(),
            observedPort = remote.Port,
        }, _jsonOpts);

        Send(new UdpRouteProbePacket
        {
            MessageType  = UdpRouteProbeMessageType.Pong,
            ClientIdHash = pkt.ClientIdHash,
            SessionId    = pkt.SessionId,
            Sequence     = pkt.Sequence,
            TimestampMs  = HmacHelper.NowMs(),
            Payload      = payload,
        }, remote, key);

        session.SentPackets++;
    }

    // ── EchoRequest ──────────────────────────────────────────────────────────

    static void HandleEchoRequest(UdpRouteProbePacket pkt, IPEndPoint remote, byte[] key)
    {
        Session? session = GetSession(pkt, remote);
        if (session is null) return;

        Send(new UdpRouteProbePacket
        {
            MessageType  = UdpRouteProbeMessageType.EchoResponse,
            ClientIdHash = pkt.ClientIdHash,
            SessionId    = pkt.SessionId,
            Sequence     = pkt.Sequence,
            TimestampMs  = HmacHelper.NowMs(),
            Payload      = pkt.Payload,
        }, remote, key);

        session.SentPackets++;
    }

    // ── PushRequest ──────────────────────────────────────────────────────────

    static void HandlePushRequest(UdpRouteProbePacket pkt, IPEndPoint remote, byte[] key)
    {
        Session? session = GetSession(pkt, remote);
        if (session is null) return;

        int[] delays;
        try
        {
            using JsonDocument doc = JsonDocument.Parse(pkt.Payload);
            delays = doc.RootElement
                .GetProperty("delaysSeconds")
                .EnumerateArray()
                .Select(e => e.GetInt32())
                .ToArray();
        }
        catch
        {
            Log("WARN", $"Bad PushRequest payload from {remote}");
            return;
        }

        Log("INFO", $"PushRequest from {session.ClientId}: {delays.Length} pushes at [{string.Join(", ", delays)}]s");

        ulong seqBase = pkt.Sequence;

        foreach (int delaySec in delays)
        {
            int   d   = delaySec;
            ulong seq = seqBase + (ulong)(d + 1);

            _ = Task.Run(async () =>
            {
                if (d > 0) await Task.Delay(TimeSpan.FromSeconds(d));

                if (!_sessions.TryGetValue(pkt.SessionId, out Session? s))
                {
                    Log("WARN", $"Session {pkt.SessionId} gone before push at {d}s");
                    return;
                }

                byte[] payload = JsonSerializer.SerializeToUtf8Bytes(
                    new { delaySeconds = d }, _jsonOpts);

                Send(new UdpRouteProbePacket
                {
                    MessageType  = UdpRouteProbeMessageType.Push,
                    ClientIdHash = pkt.ClientIdHash,
                    SessionId    = pkt.SessionId,
                    Sequence     = seq,
                    TimestampMs  = HmacHelper.NowMs(),
                    Payload      = payload,
                }, s.RemoteEndPoint, key);

                Interlocked.Increment(ref s.SentPackets);
                Log("INFO", $"Push → {s.ClientId} after {d}s → {s.RemoteEndPoint}");
            });
        }
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    static Session? GetSession(UdpRouteProbePacket pkt, IPEndPoint remote)
    {
        if (!_sessions.TryGetValue(pkt.SessionId, out Session? session))
        {
            Log("WARN", $"Unknown sessionId {pkt.SessionId} from {remote}");
            return null;
        }

        Interlocked.Increment(ref session.ReceivedPackets);
        session.LastSeenAt   = DateTime.UtcNow;
        session.LastSequence = pkt.Sequence;

        IPEndPoint current = session.RemoteEndPoint;
        if (!current.Equals(remote))
        {
            Log("INFO",
                $"Endpoint changed: clientId={session.ClientId} old={current} new={remote}");
            session.RemoteEndPoint = remote;
        }

        return session;
    }

    static void Send(UdpRouteProbePacket pkt, IPEndPoint ep, byte[] key)
    {
        try
        {
            byte[] data = UdpRouteProbePacketCodec.Encode(pkt, key);
            _udp.Send(data, data.Length, ep);
        }
        catch (Exception ex)
        {
            Log("ERROR", $"Send error to {ep}: {ex.Message}");
        }
    }

    static async Task SessionCleanupLoop(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try { await Task.Delay(TimeSpan.FromSeconds(30), ct); }
            catch (OperationCanceledException) { break; }

            var timeout = TimeSpan.FromSeconds(_config.SessionTimeoutSeconds);
            var now     = DateTime.UtcNow;

            foreach (var (id, s) in _sessions)
            {
                if (now - s.LastSeenAt > timeout && _sessions.TryRemove(id, out Session? removed))
                    Log("INFO",
                        $"Session expired: clientId={removed.ClientId} sessionId={removed.SessionId} " +
                        $"rx={removed.ReceivedPackets} tx={removed.SentPackets}");
            }
        }
    }

    static void Log(string level, string message)
    {
        if (level == "DEBUG" && !_verbose) return;
        Console.WriteLine($"[{DateTime.UtcNow:yyyy-MM-dd HH:mm:ss.fff}] [{level,-5}] {message}");
    }
}
