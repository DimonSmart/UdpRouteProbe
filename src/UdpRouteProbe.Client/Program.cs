using System.Collections.Concurrent;
using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Channels;
using UdpRouteProbe.Shared.Protocol;

namespace UdpRouteProbe.Client;

// ─── Config ──────────────────────────────────────────────────────────────────

sealed class ClientConfig
{
    public string ServerHost               { get; set; } = "";
    public int    ServerPort               { get; set; } = 9000;
    public string ClientId                 { get; set; } = "";
    public string SecretKey                { get; set; } = "";
    public int    LocalBindPort            { get; set; } = 0;
    public string OutputDirectory          { get; set; } = "probe-results";
    public int    EchoPacketCount          { get; set; } = 100;
    public int    EchoPayloadSize          { get; set; } = 256;
    public int    EchoDelayMs             { get; set; } = 20;
    public int    SizeSweepPacketsPerSize  { get; set; } = 50;
    public int    ResponseTimeoutMs        { get; set; } = 3000;
    public bool   SkipNatTest             { get; set; } = false;
    public bool   SkipPushTest            { get; set; } = false;
}

// ─── Result models ───────────────────────────────────────────────────────────

sealed class EchoResult
{
    public int    Sent        { get; set; }
    public int    Received    { get; set; }
    public int    Duplicate   { get; set; }
    public int    OutOfOrder  { get; set; }
    public double MinRttMs    { get; set; }
    public double AvgRttMs    { get; set; }
    public double MaxRttMs    { get; set; }
    public double P95RttMs    { get; set; }
    public int    Lost        => Sent - Received;
    public double LossPercent => Sent > 0 ? 100.0 * Lost / Sent : 0;
}

sealed class SizeSweepResult
{
    public int    PayloadSize  { get; set; }
    public int    Sent         { get; set; }
    public int    Received     { get; set; }
    public double AvgRttMs     { get; set; }
    public double MaxRttMs     { get; set; }
    public double LossPercent  => Sent > 0 ? 100.0 * (Sent - Received) / Sent : 0;
}

sealed class BurstResult
{
    public int    PacketCount  { get; set; }
    public int    Sent         { get; set; }
    public int    Received     { get; set; }
    public int    Duplicate    { get; set; }
    public int    OutOfOrder   { get; set; }
    public double DurationMs   { get; set; }
    public double LossPercent  => Sent > 0 ? 100.0 * (Sent - Received) / Sent : 0;
    public double ReceiveRate  => DurationMs > 0 ? Received / (DurationMs / 1000.0) : 0;
}

sealed class NatTimeoutResult
{
    public int    WaitSeconds    { get; set; }
    public bool   Success        { get; set; }
    public string EndpointBefore { get; set; } = "";
    public string EndpointAfter  { get; set; } = "";
    public bool   EndpointChanged => EndpointBefore != "" && EndpointBefore != EndpointAfter;
}

sealed class PushResult
{
    public int  DelaySeconds { get; set; }
    public bool Received     { get; set; }
}

sealed class ProbeReport
{
    public string              Server             { get; set; } = "";
    public string              ClientId           { get; set; } = "";
    public string              LocalEndpoint      { get; set; } = "";
    public string              ObservedEndpoint   { get; set; } = "";
    public bool                HandshakeOk        { get; set; }
    public ulong               SessionId          { get; set; }
    public EchoResult?         Echo               { get; set; }
    public List<SizeSweepResult> SizeSweep        { get; set; } = [];
    public List<BurstResult>   Burst              { get; set; } = [];
    public List<NatTimeoutResult> NatTimeout      { get; set; } = [];
    public List<PushResult>    Push               { get; set; } = [];
    public int                 RecommendedPayloadSize      { get; set; }
    public int                 RecommendedKeepAliveSeconds { get; set; }
    public DateTime            GeneratedAt        { get; set; }
}

// ─── Received packet ─────────────────────────────────────────────────────────

sealed record ReceivedItem(UdpRouteProbePacket Packet, long TicksReceived);

// ─── Main program ─────────────────────────────────────────────────────────────

static class Program
{
    static ClientConfig _cfg     = new();
    static byte[]       _key     = [];
    static ulong        _idHash;
    static ulong        _sessionId;
    static string       _observedEndpoint = "";

    static UdpClient    _udp    = null!;
    static IPEndPoint   _server = null!;

    // All decoded incoming packets flow through here
    static readonly Channel<ReceivedItem> _inbound =
        Channel.CreateUnbounded<ReceivedItem>(new UnboundedChannelOptions
        {
            SingleReader = false, SingleWriter = true
        });

    static ulong _seqCounter;
    static ulong NextSeq() => Interlocked.Increment(ref _seqCounter);

    static readonly JsonSerializerOptions _jsonOpts = new()
    {
        PropertyNameCaseInsensitive = true,
        WriteIndented               = true,
    };

    // ── Entry point ──────────────────────────────────────────────────────────

    static async Task<int> Main(string[] args)
    {
        if (args.FirstOrDefault() == "autoprobe")
            return await AutoProbeClient.Run(args.Skip(1).ToArray());
        if (args.FirstOrDefault() == "compare")
            return await AutoProbeCompare.Run(args.Skip(1).ToArray());

        string? configFile = null;
        string? serverArg  = null;
        string? clientId   = null;
        string? secretKey  = null;

        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--config"     when i + 1 < args.Length: configFile = args[++i]; break;
                case "--server"     when i + 1 < args.Length: serverArg  = args[++i]; break;
                case "--client-id"  when i + 1 < args.Length: clientId   = args[++i]; break;
                case "--secret-key" when i + 1 < args.Length: secretKey  = args[++i]; break;
                case "--skip-nat":  _cfg.SkipNatTest  = true; break;
                case "--skip-push": _cfg.SkipPushTest = true; break;
            }
        }

        if (configFile != null && File.Exists(configFile))
        {
            string json = await File.ReadAllTextAsync(configFile);
            _cfg = JsonSerializer.Deserialize<ClientConfig>(json, _jsonOpts) ?? new ClientConfig();
        }
        else if (configFile != null)
        {
            Console.Error.WriteLine($"Config file not found: {configFile}");
            return 1;
        }

        if (serverArg != null)
        {
            int colon = serverArg.LastIndexOf(':');
            if (colon > 0 && int.TryParse(serverArg[(colon + 1)..], out int port))
            {
                _cfg.ServerHost = serverArg[..colon];
                _cfg.ServerPort = port;
            }
        }
        if (clientId  != null) _cfg.ClientId  = clientId;
        if (secretKey != null) _cfg.SecretKey = secretKey;

        if (string.IsNullOrWhiteSpace(_cfg.ServerHost))
        {
            Console.Error.WriteLine("Server host is required (--server HOST:PORT or config).");
            return 1;
        }
        if (string.IsNullOrWhiteSpace(_cfg.ClientId) || string.IsNullOrWhiteSpace(_cfg.SecretKey))
        {
            Console.Error.WriteLine("ClientId and SecretKey are required.");
            return 1;
        }

        _key = Encoding.UTF8.GetBytes(_cfg.SecretKey);

        _idHash = HmacHelper.ComputeClientIdHash(_cfg.ClientId);

        // Resolve server address
        IPAddress[]? addrs = await Dns.GetHostAddressesAsync(_cfg.ServerHost);
        if (addrs.Length == 0)
        {
            Console.Error.WriteLine($"Cannot resolve: {_cfg.ServerHost}");
            return 1;
        }
        _server = new IPEndPoint(addrs[0], _cfg.ServerPort);

        // Bind local UDP socket
        _udp = new UdpClient(_cfg.LocalBindPort);
        _udp.Connect(_server);

        IPEndPoint localEp = (IPEndPoint)_udp.Client.LocalEndPoint!;
        Console.WriteLine($"Local UDP endpoint: {localEp}");
        Console.WriteLine($"Connecting to server: {_server}");
        Console.WriteLine();

        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

        // Start background receiver (linked so Ctrl+C stops it too)
        using var recvCts = CancellationTokenSource.CreateLinkedTokenSource(cts.Token);
        var recvTask = Task.Run(() => ReceiveLoop(recvCts.Token));

        var ct = cts.Token;

        try
        {
            var report = new ProbeReport
            {
                Server        = $"{_cfg.ServerHost}:{_cfg.ServerPort}",
                ClientId      = _cfg.ClientId,
                LocalEndpoint = localEp.ToString(),
                GeneratedAt   = DateTime.UtcNow,
            };

            // ── Handshake ────────────────────────────────────────────────────
            Console.WriteLine("=== Handshake ===");
            bool ok = await RunHandshake(report, ct);
            if (!ok)
            {
                Console.WriteLine("Handshake FAILED — aborting.");
                return 2;
            }

            // ── Echo RTT ─────────────────────────────────────────────────────
            Console.WriteLine("\n=== Echo RTT test ===");
            report.Echo = await RunEchoTest(ct);

            // ── Size sweep ───────────────────────────────────────────────────
            Console.WriteLine("\n=== Packet size sweep ===");
            report.SizeSweep = await RunSizeSweep(ct);

            // ── Burst ────────────────────────────────────────────────────────
            Console.WriteLine("\n=== Burst test ===");
            report.Burst = await RunBurstTest(ct);

            // ── NAT timeout ──────────────────────────────────────────────────
            if (!_cfg.SkipNatTest)
            {
                Console.WriteLine("\n=== NAT idle timeout test ===");
                Console.WriteLine("(this can take up to ~18 minutes; use --skip-nat to skip)");
                report.NatTimeout = await RunNatTimeoutTest(ct);
            }
            else
            {
                Console.WriteLine("\n[NAT idle timeout test skipped]");
            }

            // ── Server push ──────────────────────────────────────────────────
            if (!_cfg.SkipPushTest)
            {
                Console.WriteLine("\n=== Server push test ===");
                Console.WriteLine("(this can take up to ~2 minutes)");
                report.Push = await RunServerPushTest(ct);
            }
            else
            {
                Console.WriteLine("\n[Server push test skipped]");
            }

            // ── Recommendations ──────────────────────────────────────────────
            ComputeRecommendations(report);

            // ── Report ───────────────────────────────────────────────────────
            Console.WriteLine();
            PrintReport(report);
            SaveReport(report, localEp.ToString());

            return 0;
        }
        catch (OperationCanceledException)
        {
            Console.WriteLine("\nInterrupted.");
            return 130;
        }
        finally
        {
            recvCts.Cancel();
            await recvTask;
        }
    }

    // ── Background receive loop ───────────────────────────────────────────────

    static async Task ReceiveLoop(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                UdpReceiveResult result = await _udp.ReceiveAsync(ct);
                long ts = Stopwatch.GetTimestamp();

                if (UdpRouteProbePacketCodec.TryDecode(result.Buffer, _key, out var pkt) && pkt is not null)
                    _inbound.Writer.TryWrite(new ReceivedItem(pkt, ts));
            }
            catch (OperationCanceledException) { break; }
            catch { /* discard malformed */ }
        }
        _inbound.Writer.TryComplete();
    }

    // ── Receive helpers ───────────────────────────────────────────────────────

    // Wait for the first packet matching predicate; non-matching packets are buffered.
    static async Task<ReceivedItem?> WaitFor(
        Func<UdpRouteProbePacket, bool> pred,
        int timeoutMs,
        CancellationToken ct = default)
    {
        var deadline = Stopwatch.GetTimestamp() + (long)(timeoutMs * (Stopwatch.Frequency / 1000.0));
        var skipped  = new List<ReceivedItem>();

        while (true)
        {
            long remaining = deadline - Stopwatch.GetTimestamp();
            if (remaining <= 0) break;

            int remainingMs = (int)(remaining * 1000 / Stopwatch.Frequency);
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(remainingMs);

            ReceivedItem item;
            try   { item = await _inbound.Reader.ReadAsync(cts.Token); }
            catch { break; }

            if (pred(item.Packet))
            {
                // Put back anything we skipped
                foreach (var s in skipped) _inbound.Writer.TryWrite(s);
                return item;
            }
            skipped.Add(item);
        }

        foreach (var s in skipped) _inbound.Writer.TryWrite(s);
        return null;
    }

    // Collect all packets of given type arriving within the window.
    static async Task<List<ReceivedItem>> CollectFor(
        int durationMs,
        UdpRouteProbeMessageType type,
        CancellationToken ct = default)
    {
        var results  = new List<ReceivedItem>();
        var deadline = Stopwatch.GetTimestamp() + (long)(durationMs * (Stopwatch.Frequency / 1000.0));

        while (true)
        {
            long remaining = deadline - Stopwatch.GetTimestamp();
            if (remaining <= 0) break;

            int remainingMs = (int)(remaining * 1000 / Stopwatch.Frequency);
            using var timeoutCts = new CancellationTokenSource(Math.Max(remainingMs, 1));
            using var linkedCts  = CancellationTokenSource.CreateLinkedTokenSource(ct, timeoutCts.Token);

            ReceivedItem item;
            try   { item = await _inbound.Reader.ReadAsync(linkedCts.Token); }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch { break; }

            if (item.Packet.MessageType == type)
                results.Add(item);
            // discard non-matching (burst only called during burst)
        }
        return results;
    }

    // ── Send helper ───────────────────────────────────────────────────────────

    static void SendPacket(UdpRouteProbePacket pkt)
    {
        pkt.ClientIdHash = _idHash;
        pkt.SessionId    = _sessionId;
        pkt.TimestampMs  = HmacHelper.NowMs();
        byte[] data = UdpRouteProbePacketCodec.Encode(pkt, _key);
        _udp.Send(data, data.Length);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Tests
    // ─────────────────────────────────────────────────────────────────────────

    static async Task<bool> RunHandshake(ProbeReport report, CancellationToken ct = default)
    {
        for (int attempt = 1; attempt <= 3; attempt++)
        {
            SendPacket(new UdpRouteProbePacket
            {
                MessageType = UdpRouteProbeMessageType.ClientHello,
                Sequence    = NextSeq(),
            });

            ReceivedItem? item = await WaitFor(
                p => p.MessageType == UdpRouteProbeMessageType.ServerHello,
                _cfg.ResponseTimeoutMs,
                ct);

            if (item is null)
            {
                Console.WriteLine($"  Attempt {attempt}: no ServerHello (timeout {_cfg.ResponseTimeoutMs}ms)");
                continue;
            }

            try
            {
                using var doc    = JsonDocument.Parse(item.Packet.Payload);
                var root         = doc.RootElement;
                _sessionId       = root.GetProperty("sessionId").GetUInt64();
                string ip        = root.GetProperty("observedRemoteIp").GetString()!;
                int port         = root.GetProperty("observedRemotePort").GetInt32();
                _observedEndpoint = $"{ip}:{port}";

                report.HandshakeOk      = true;
                report.SessionId        = _sessionId;
                report.ObservedEndpoint = _observedEndpoint;

                Console.WriteLine($"  Handshake: OK");
                Console.WriteLine($"  Server sees client as: {_observedEndpoint}");
                Console.WriteLine($"  SessionId: {_sessionId}");
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  Attempt {attempt}: bad ServerHello payload: {ex.Message}");
            }
        }
        return false;
    }

    // ── Echo RTT ─────────────────────────────────────────────────────────────

    static async Task<EchoResult> RunEchoTest(CancellationToken ct = default)
    {
        int    count   = _cfg.EchoPacketCount;
        int    paySize = _cfg.EchoPayloadSize;
        int    delayMs = _cfg.EchoDelayMs;

        byte[] payload = new byte[paySize];
        Random.Shared.NextBytes(payload);

        var sentTimes   = new Dictionary<ulong, long>();
        var rttsMs      = new List<double>();
        var seqsReceived = new HashSet<ulong>();
        int duplicate   = 0;
        int outOfOrder  = 0;
        ulong maxSeqSeen = 0;

        // Send all packets
        for (int i = 0; i < count; i++)
        {
            ulong seq = NextSeq();
            sentTimes[seq] = Stopwatch.GetTimestamp();
            SendPacket(new UdpRouteProbePacket
            {
                MessageType = UdpRouteProbeMessageType.EchoRequest,
                Sequence    = seq,
                Payload     = payload,
            });
            if (delayMs > 0 && i < count - 1)
                await Task.Delay(delayMs, ct);
        }

        // Collect responses — wait up to timeout after last send
        long collectDeadline = Stopwatch.GetTimestamp() +
            (long)(_cfg.ResponseTimeoutMs * (Stopwatch.Frequency / 1000.0));

        while (Stopwatch.GetTimestamp() < collectDeadline && rttsMs.Count + duplicate < count)
        {
            int ms = (int)((collectDeadline - Stopwatch.GetTimestamp()) * 1000 / Stopwatch.Frequency);
            ReceivedItem? item = await WaitFor(
                p => p.MessageType == UdpRouteProbeMessageType.EchoResponse && sentTimes.ContainsKey(p.Sequence),
                Math.Max(ms, 1),
                ct);

            if (item is null) break;

            ulong seq = item.Packet.Sequence;

            if (seqsReceived.Contains(seq)) { duplicate++; continue; }
            seqsReceived.Add(seq);

            if (seq < maxSeqSeen) outOfOrder++;
            else maxSeqSeen = seq;

            double rttMs = (item.TicksReceived - sentTimes[seq]) * 1000.0 / Stopwatch.Frequency;
            rttsMs.Add(rttMs);
        }

        var result = new EchoResult
        {
            Sent       = count,
            Received   = rttsMs.Count,
            Duplicate  = duplicate,
            OutOfOrder = outOfOrder,
        };

        if (rttsMs.Count > 0)
        {
            rttsMs.Sort();
            result.MinRttMs = Math.Round(rttsMs[0], 1);
            result.AvgRttMs = Math.Round(rttsMs.Average(), 1);
            result.MaxRttMs = Math.Round(rttsMs[^1], 1);
            result.P95RttMs = Math.Round(rttsMs[(int)(rttsMs.Count * 0.95)], 1);
        }

        Console.WriteLine($"  Sent: {result.Sent}  Received: {result.Received}  Lost: {result.Lost}  " +
                          $"Dup: {result.Duplicate}  OOO: {result.OutOfOrder}");
        if (rttsMs.Count > 0)
            Console.WriteLine($"  RTT min/avg/max/p95: " +
                              $"{result.MinRttMs}/{result.AvgRttMs}/{result.MaxRttMs}/{result.P95RttMs} ms");

        return result;
    }

    // ── Packet size sweep ────────────────────────────────────────────────────

    static readonly int[] SweepSizes =
        [64, 128, 256, 512, 1000, 1200, 1300, 1400, 1472, 1500, 2000, 4096, 8192, 16384, 32768, 60000];

    static async Task<List<SizeSweepResult>> RunSizeSweep(CancellationToken ct = default)
    {
        int n = _cfg.SizeSweepPacketsPerSize;
        var results = new List<SizeSweepResult>();

        foreach (int size in SweepSizes)
        {
            // Skip sizes that exceed UDP practical limit
            if (size > UdpRouteProbePacketCodec.MaxPayload)
            {
                Console.WriteLine($"  {size,6} bytes: SKIPPED (exceeds protocol limit)");
                results.Add(new SizeSweepResult { PayloadSize = size, Sent = n, Received = 0 });
                continue;
            }

            byte[] payload = new byte[size];
            Random.Shared.NextBytes(payload);

            var sentTimes    = new Dictionary<ulong, long>();
            var rttsMs       = new List<double>();
            var seqsReceived = new HashSet<ulong>();

            for (int i = 0; i < n; i++)
            {
                ulong seq = NextSeq();
                sentTimes[seq] = Stopwatch.GetTimestamp();
                try
                {
                    SendPacket(new UdpRouteProbePacket
                    {
                        MessageType = UdpRouteProbeMessageType.EchoRequest,
                        Sequence    = seq,
                        Payload     = payload,
                    });
                }
                catch { /* packet too large for OS buffer — count as lost */ }
                if (i < n - 1) await Task.Delay(10, ct);
            }

            long deadline = Stopwatch.GetTimestamp() +
                (long)(_cfg.ResponseTimeoutMs * (Stopwatch.Frequency / 1000.0));

            while (Stopwatch.GetTimestamp() < deadline && rttsMs.Count < n)
            {
                int ms = (int)((deadline - Stopwatch.GetTimestamp()) * 1000 / Stopwatch.Frequency);
                ReceivedItem? item = await WaitFor(
                    p => p.MessageType == UdpRouteProbeMessageType.EchoResponse && sentTimes.ContainsKey(p.Sequence),
                    Math.Max(ms, 1),
                    ct);
                if (item is null) break;
                if (seqsReceived.Add(item.Packet.Sequence))
                {
                    double rtt = (item.TicksReceived - sentTimes[item.Packet.Sequence]) * 1000.0 / Stopwatch.Frequency;
                    rttsMs.Add(rtt);
                }
            }

            var sr = new SizeSweepResult
            {
                PayloadSize = size,
                Sent        = n,
                Received    = rttsMs.Count,
                AvgRttMs    = rttsMs.Count > 0 ? Math.Round(rttsMs.Average(), 1) : 0,
                MaxRttMs    = rttsMs.Count > 0 ? Math.Round(rttsMs.Max(), 1) : 0,
            };
            results.Add(sr);

            Console.WriteLine($"  {size,6} bytes: {sr.Received}/{sr.Sent}  loss {sr.LossPercent:F0}%  " +
                              $"avg {sr.AvgRttMs}ms  max {sr.MaxRttMs}ms");
        }

        return results;
    }

    // ── Burst test ───────────────────────────────────────────────────────────

    static readonly int[] BurstCounts = [100, 1000, 5000];

    static async Task<List<BurstResult>> RunBurstTest(CancellationToken ct = default)
    {
        const int burstPayloadSize = 1200;
        var results = new List<BurstResult>();

        foreach (int count in BurstCounts)
        {
            byte[] payload = new byte[burstPayloadSize];
            Random.Shared.NextBytes(payload);

            ulong firstSeq = _seqCounter + 1;
            var seqSet     = new HashSet<ulong>();
            for (ulong s = firstSeq; s < firstSeq + (ulong)count; s++) seqSet.Add(s);

            var sw = Stopwatch.StartNew();
            int sent = 0;
            for (int i = 0; i < count; i++)
            {
                ulong seq = NextSeq();
                try
                {
                    SendPacket(new UdpRouteProbePacket
                    {
                        MessageType = UdpRouteProbeMessageType.EchoRequest,
                        Sequence    = seq,
                        Payload     = payload,
                    });
                    sent++;
                }
                catch { /* discard */ }
            }
            double sendDurationMs = sw.Elapsed.TotalMilliseconds;

            // Collection window: max(2s, 3× send duration)
            int windowMs = (int)Math.Max(2000, sendDurationMs * 3);
            List<ReceivedItem> received = await CollectFor(windowMs, UdpRouteProbeMessageType.EchoResponse, ct);

            double totalMs = sw.Elapsed.TotalMilliseconds;

            var seqsSeen = new HashSet<ulong>();
            int duplicate  = 0;
            int outOfOrder = 0;
            ulong maxSeen  = 0;

            foreach (var item in received)
            {
                ulong seq = item.Packet.Sequence;
                if (!seqSet.Contains(seq)) continue; // belongs to another test
                if (!seqsSeen.Add(seq)) { duplicate++; continue; }
                if (seq < maxSeen) outOfOrder++;
                else maxSeen = seq;
            }

            var br = new BurstResult
            {
                PacketCount = count,
                Sent        = sent,
                Received    = seqsSeen.Count,
                Duplicate   = duplicate,
                OutOfOrder  = outOfOrder,
                DurationMs  = Math.Round(totalMs, 1),
            };
            results.Add(br);

            Console.WriteLine($"  {count,5} packets: {br.Received}/{br.Sent}  loss {br.LossPercent:F1}%  " +
                              $"dup {br.Duplicate}  ooo {br.OutOfOrder}  " +
                              $"rate {br.ReceiveRate:F0} pkt/s");
        }

        return results;
    }

    // ── NAT idle timeout ─────────────────────────────────────────────────────

    static readonly int[] NatWaits = [10, 30, 60, 120, 300, 600];

    static async Task<List<NatTimeoutResult>> RunNatTimeoutTest(CancellationToken ct = default)
    {
        var results = new List<NatTimeoutResult>();
        string currentEndpoint = _observedEndpoint;

        foreach (int waitSec in NatWaits)
        {
            Console.Write($"  Waiting {waitSec}s ...");
            await Task.Delay(TimeSpan.FromSeconds(waitSec), ct);

            string before = currentEndpoint;
            ulong seq = NextSeq();

            SendPacket(new UdpRouteProbePacket
            {
                MessageType = UdpRouteProbeMessageType.Ping,
                Sequence    = seq,
            });

            ReceivedItem? item = await WaitFor(
                p => p.MessageType == UdpRouteProbeMessageType.Pong && p.Sequence == seq,
                _cfg.ResponseTimeoutMs,
                ct);

            bool success = item is not null;
            string after = before;

            if (success && item!.Packet.Payload.Length > 0)
            {
                try
                {
                    using var doc = JsonDocument.Parse(item.Packet.Payload);
                    string ip  = doc.RootElement.GetProperty("observedIp").GetString()!;
                    int    port = doc.RootElement.GetProperty("observedPort").GetInt32();
                    after = $"{ip}:{port}";
                    currentEndpoint = after;
                }
                catch { /* non-critical */ }
            }

            var r = new NatTimeoutResult
            {
                WaitSeconds    = waitSec,
                Success        = success,
                EndpointBefore = before,
                EndpointAfter  = after,
            };
            results.Add(r);

            string status = success ? "OK" : "FAILED";
            Console.Write($" {status}");

            if (r.EndpointChanged)
            {
                Console.WriteLine();
                Console.WriteLine($"    Endpoint changed after {waitSec}s:");
                Console.WriteLine($"      old: {before}");
                Console.WriteLine($"      new: {after}");
            }
            else
            {
                Console.WriteLine();
            }

            if (!success)
            {
                Console.WriteLine($"  NAT mapping closed after >{waitSec - (results.Count > 1 ? NatWaits[results.Count - 2] : 0)}s idle. Stopping NAT test.");
                break;
            }
        }

        return results;
    }

    // ── Server push ──────────────────────────────────────────────────────────

    static readonly int[] PushDelays = [0, 10, 30, 60, 120];

    static async Task<List<PushResult>> RunServerPushTest(CancellationToken ct = default)
    {
        var results = new List<PushResult>(PushDelays.Length);
        foreach (int d in PushDelays) results.Add(new PushResult { DelaySeconds = d });

        ulong seq = NextSeq();
        byte[] payload = JsonSerializer.SerializeToUtf8Bytes(
            new { delaysSeconds = PushDelays },
            new JsonSerializerOptions { WriteIndented = false });

        SendPacket(new UdpRouteProbePacket
        {
            MessageType = UdpRouteProbeMessageType.PushRequest,
            Sequence    = seq,
            Payload     = payload,
        });

        int maxWaitMs = (PushDelays[^1] + 10) * 1000;
        var deadline  = Stopwatch.GetTimestamp() + (long)(maxWaitMs * (Stopwatch.Frequency / 1000.0));

        int received = 0;
        while (received < PushDelays.Length && Stopwatch.GetTimestamp() < deadline)
        {
            int ms = (int)((deadline - Stopwatch.GetTimestamp()) * 1000 / Stopwatch.Frequency);
            ReceivedItem? item = await WaitFor(
                p => p.MessageType == UdpRouteProbeMessageType.Push,
                Math.Max(ms, 1),
                ct);

            if (item is null) break;

            try
            {
                using var doc = JsonDocument.Parse(item.Packet.Payload);
                int delay = doc.RootElement.GetProperty("delaySeconds").GetInt32();
                var r = results.FirstOrDefault(x => x.DelaySeconds == delay);
                if (r is not null && !r.Received)
                {
                    r.Received = true;
                    received++;
                    Console.WriteLine($"  Push at {delay}s: OK");
                }
            }
            catch { received++; /* count but can't match */ }
        }

        foreach (var r in results.Where(r => !r.Received))
            Console.WriteLine($"  Push at {r.DelaySeconds}s: FAILED (no packet)");

        return results;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Recommendations
    // ─────────────────────────────────────────────────────────────────────────

    static void ComputeRecommendations(ProbeReport report)
    {
        // Safe payload: largest size with <5% loss
        int safeSize = 64;
        foreach (var sr in report.SizeSweep)
        {
            if (sr.LossPercent < 5) safeSize = sr.PayloadSize;
            else break;
        }
        report.RecommendedPayloadSize = safeSize;

        // Keep-alive: last successful NAT wait
        int keepAlive = 30; // conservative default
        if (report.NatTimeout.Count > 0)
        {
            var last = report.NatTimeout.LastOrDefault(r => r.Success);
            if (last is not null)
                keepAlive = (int)Math.Ceiling(last.WaitSeconds * 0.5);
        }
        report.RecommendedKeepAliveSeconds = Math.Max(keepAlive, 10);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Report output
    // ─────────────────────────────────────────────────────────────────────────

    static void PrintReport(ProbeReport r)
    {
        Console.WriteLine(new string('═', 60));
        Console.WriteLine("UDP ROUTE PROBE REPORT");
        Console.WriteLine(new string('─', 60));
        Console.WriteLine($"Server:            {r.Server}");
        Console.WriteLine($"ClientId:          {r.ClientId}");
        Console.WriteLine($"Local endpoint:    {r.LocalEndpoint}");
        Console.WriteLine($"Observed endpoint: {r.ObservedEndpoint}");
        Console.WriteLine($"Generated:         {r.GeneratedAt:yyyy-MM-dd HH:mm:ss} UTC");
        Console.WriteLine();

        Console.WriteLine($"Handshake: {(r.HandshakeOk ? "OK" : "FAILED")}");
        Console.WriteLine();

        if (r.Echo is { } e)
        {
            Console.WriteLine("Echo test:");
            Console.WriteLine($"  Sent: {e.Sent}  Received: {e.Received}  " +
                              $"Loss: {e.LossPercent:F0}%  Dup: {e.Duplicate}  OOO: {e.OutOfOrder}");
            Console.WriteLine($"  RTT min/avg/max/p95: {e.MinRttMs}/{e.AvgRttMs}/{e.MaxRttMs}/{e.P95RttMs} ms");
        }
        Console.WriteLine();

        if (r.SizeSweep.Count > 0)
        {
            Console.WriteLine("Packet size sweep:");
            foreach (var s in r.SizeSweep)
                Console.WriteLine($"  {s.PayloadSize,6} bytes: {s.Received}/{s.Sent}  loss {s.LossPercent:F0}%  avg {s.AvgRttMs}ms");
        }
        Console.WriteLine();

        if (r.Burst.Count > 0)
        {
            Console.WriteLine("Burst test:");
            foreach (var b in r.Burst)
                Console.WriteLine($"  {b.PacketCount,5} packets:  loss {b.LossPercent:F1}%  " +
                                  $"rate {b.ReceiveRate:F0} pkt/s");
        }
        Console.WriteLine();

        if (r.NatTimeout.Count > 0)
        {
            Console.WriteLine("NAT idle timeout:");
            foreach (var n in r.NatTimeout)
            {
                Console.Write($"  {n.WaitSeconds,4}s  {(n.Success ? "OK" : "FAILED")}");
                if (n.EndpointChanged)
                    Console.Write($"  [endpoint changed: {n.EndpointBefore} → {n.EndpointAfter}]");
                Console.WriteLine();
            }
        }
        else if (!_cfg.SkipNatTest)
        {
            Console.WriteLine("NAT idle timeout: not tested");
        }
        Console.WriteLine();

        if (r.Push.Count > 0)
        {
            Console.WriteLine("Server push:");
            foreach (var p in r.Push)
                Console.WriteLine($"  {p.DelaySeconds,4}s  {(p.Received ? "OK" : "FAILED")}");
        }
        else if (!_cfg.SkipPushTest)
        {
            Console.WriteLine("Server push: not tested");
        }
        Console.WriteLine();

        Console.WriteLine("Recommended:");
        Console.WriteLine($"  Safe UDP payload size: {r.RecommendedPayloadSize} bytes");
        Console.WriteLine($"  Keep-alive interval:   {r.RecommendedKeepAliveSeconds}s");
        Console.WriteLine(new string('═', 60));
    }

    static void SaveReport(ProbeReport report, string localEp)
    {
        try
        {
            Directory.CreateDirectory(_cfg.OutputDirectory);
            string ts   = DateTime.Now.ToString("yyyyMMdd-HHmmss");
            string stem = Path.Combine(_cfg.OutputDirectory, $"report-{ts}");

            // JSON
            string json = JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText($"{stem}.json", json);

            // CSV
            var sb = new StringBuilder();
            sb.AppendLine("test,metric,value");
            sb.AppendLine($"info,server,{report.Server}");
            sb.AppendLine($"info,clientId,{report.ClientId}");
            sb.AppendLine($"info,localEndpoint,{localEp}");
            sb.AppendLine($"info,observedEndpoint,{report.ObservedEndpoint}");
            sb.AppendLine($"handshake,ok,{report.HandshakeOk}");

            if (report.Echo is { } e)
            {
                sb.AppendLine($"echo,sent,{e.Sent}");
                sb.AppendLine($"echo,received,{e.Received}");
                sb.AppendLine($"echo,lossPercent,{e.LossPercent:F2}");
                sb.AppendLine($"echo,minRttMs,{e.MinRttMs}");
                sb.AppendLine($"echo,avgRttMs,{e.AvgRttMs}");
                sb.AppendLine($"echo,maxRttMs,{e.MaxRttMs}");
                sb.AppendLine($"echo,p95RttMs,{e.P95RttMs}");
            }

            foreach (var s in report.SizeSweep)
                sb.AppendLine($"sizeSweep_{s.PayloadSize},lossPercent,{s.LossPercent:F2}," +
                              $"avgRttMs,{s.AvgRttMs},maxRttMs,{s.MaxRttMs}," +
                              $"received,{s.Received},sent,{s.Sent}");

            foreach (var b in report.Burst)
                sb.AppendLine($"burst_{b.PacketCount},lossPercent,{b.LossPercent:F2}," +
                              $"receiveRate,{b.ReceiveRate:F1},durationMs,{b.DurationMs}");

            foreach (var n in report.NatTimeout)
                sb.AppendLine($"nat_{n.WaitSeconds}s,success,{n.Success}," +
                              $"endpointChanged,{n.EndpointChanged}");

            foreach (var p in report.Push)
                sb.AppendLine($"push_{p.DelaySeconds}s,received,{p.Received}");

            sb.AppendLine($"recommend,payloadSize,{report.RecommendedPayloadSize}");
            sb.AppendLine($"recommend,keepAliveSeconds,{report.RecommendedKeepAliveSeconds}");

            File.WriteAllText($"{stem}.csv", sb.ToString());

            Console.WriteLine($"\nResults saved:");
            Console.WriteLine($"  {stem}.json");
            Console.WriteLine($"  {stem}.csv");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Failed to save report: {ex.Message}");
        }
    }
}
