using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using UdpRouteProbe.Shared.Protocol;

namespace UdpRouteProbe.Client;

sealed class AutoProbeClientConfig
{
    public string ServerHost { get; set; } = "";
    public List<int> ServerPorts { get; set; } = [];
    public int ServerPort { get; set; } = 9000;
    public string ClientId { get; set; } = "";
    public string SecretKey { get; set; } = "";
    public TimeSpan Duration { get; set; } = TimeSpan.FromHours(1);
    public string OutputDirectory { get; set; } = "probe-results";
    public bool EnableDecoyTargets { get; set; }
    public bool AllowHighDecoyRate { get; set; }
    public List<string> DecoyTargets { get; set; } = [];
    public List<int> DecoyPorts { get; set; } = [];
}

sealed class AutoProbeCaseResult
{
    public required AutoProbeCase Case { get; init; }
    public int ClientSent { get; set; }
    public int ClientReceived { get; set; }
    public int SameServerNoiseSent { get; set; }
    public int DecoySent { get; set; }
    public int RawGarbageSent { get; set; }
    public int Duplicates { get; set; }
    public int OutOfOrder { get; set; }
    public List<double> RttsMs { get; } = [];
    public int FirstLossAtSequence { get; set; }
    public int LastSuccessfulSequence { get; set; }
    public double LossPercent => ClientSent > 0 ? 100.0 * (ClientSent - ClientReceived) / ClientSent : 0;
    public string Classification { get; set; } = "";
}

sealed class AutoProbeSummary
{
    public string RunId { get; set; } = "";
    public DateTime StartedAtUtc { get; set; }
    public DateTime FinishedAtUtc { get; set; }
    public double DurationSeconds { get; set; }
    public string Server { get; set; } = "";
    public List<int> PortsTested { get; set; } = [];
    public List<int> PortsReachable { get; set; } = [];
    public List<string> Classifications { get; set; } = [];
    public List<object> BestCases { get; set; } = [];
    public List<string> Warnings { get; set; } = [];
    public object Recommendations { get; set; } = new();
}

sealed class AutoProbeBestCase
{
    public string CaseId { get; set; } = "";
    public int ServerPort { get; set; }
    public string WireFormat { get; set; } = "";
    public string PayloadProfile { get; set; } = "";
    public int PayloadSize { get; set; }
    public int SendIntervalMs { get; set; }
    public double SuccessPercent { get; set; }
}

static class AutoProbeClient
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        WriteIndented = false,
    };

    private static AutoProbeClientConfig Config = new();
    private static byte[] Key = [];
    private static ulong ClientIdHash;
    private static string RunId = "";
    private static string ClientLogPath = "";
    private static long PacketId;
    private static long Sequence;
    private static DateTime DeadlineUtc;
    private static readonly object LogLock = new();

    public static async Task<int> Run(string[] args)
    {
        string? configFile = null;
        string? portsArg = null;
        string? decoyTargetsArg = null;
        string? decoyPortsArg = null;
        string? durationArg = null;
        bool skipNat = false;
        bool skipPush = false;
        bool skipNoise = false;
        bool quick = false;
        int maxCases = 200;
        int maxPacketSize = 60000;

        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--config" when i + 1 < args.Length: configFile = args[++i]; break;
                case "--server" when i + 1 < args.Length: Config.ServerHost = args[++i]; break;
                case "--ports" when i + 1 < args.Length: portsArg = args[++i]; break;
                case "--decoy-targets" when i + 1 < args.Length: decoyTargetsArg = args[++i]; break;
                case "--decoy-ports" when i + 1 < args.Length: decoyPortsArg = args[++i]; break;
                case "--client-id" when i + 1 < args.Length: Config.ClientId = args[++i]; break;
                case "--secret-key" when i + 1 < args.Length: Config.SecretKey = args[++i]; break;
                case "--duration" when i + 1 < args.Length: durationArg = args[++i]; break;
                case "--output" when i + 1 < args.Length: Config.OutputDirectory = args[++i]; break;
                case "--skip-nat": skipNat = true; break;
                case "--skip-push": skipPush = true; break;
                case "--skip-noise": skipNoise = true; break;
                case "--quick": quick = true; break;
                case "--max-cases" when i + 1 < args.Length: maxCases = int.Parse(args[++i], CultureInfo.InvariantCulture); break;
                case "--max-packet-size" when i + 1 < args.Length: maxPacketSize = int.Parse(args[++i], CultureInfo.InvariantCulture); break;
                case "--enable-decoy-targets": Config.EnableDecoyTargets = true; break;
                case "--allow-high-decoy-rate": Config.AllowHighDecoyRate = true; break;
            }
        }

        if (configFile is not null)
        {
            if (!File.Exists(configFile))
            {
                Console.Error.WriteLine($"Config file not found: {configFile}");
                return 1;
            }
            var fileConfig = JsonSerializer.Deserialize<AutoProbeClientConfig>(await File.ReadAllTextAsync(configFile), JsonOptions) ?? new();
            MergeConfig(fileConfig);
        }

        if (portsArg is not null) Config.ServerPorts = ParsePorts(portsArg);
        if (decoyTargetsArg is not null) Config.DecoyTargets = ParseStringList(decoyTargetsArg);
        if (decoyPortsArg is not null) Config.DecoyPorts = ParsePorts(decoyPortsArg);
        if (Config.DecoyTargets.Count > 0) Config.EnableDecoyTargets = true;
        if (durationArg is not null) Config.Duration = TimeSpan.Parse(durationArg, CultureInfo.InvariantCulture);
        if (Config.ServerPorts.Count == 0) Config.ServerPorts.Add(Config.ServerPort);
        if (quick)
        {
            Config.Duration = TimeSpan.FromSeconds(Math.Min(Config.Duration.TotalSeconds, 90));
            maxCases = Math.Min(maxCases, 24);
        }

        if (string.IsNullOrWhiteSpace(Config.ServerHost) ||
            string.IsNullOrWhiteSpace(Config.ClientId) ||
            string.IsNullOrWhiteSpace(Config.SecretKey))
        {
            Console.Error.WriteLine("Required: --server HOST --ports P1,P2 --client-id ID --secret-key KEY");
            return 1;
        }

        Directory.CreateDirectory(Config.OutputDirectory);
        RunId = Guid.NewGuid().ToString();
        string stamp = DateTime.UtcNow.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture);
        ClientLogPath = Path.Combine(Config.OutputDirectory, $"autoprobe-client-{stamp}.jsonl");
        Key = Encoding.UTF8.GetBytes(Config.SecretKey);
        ClientIdHash = HmacHelper.ComputeClientIdHash(Config.ClientId);

        var started = DateTime.UtcNow;
        DeadlineUtc = started + Config.Duration;
        using var cts = new CancellationTokenSource(Config.Duration);
        Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

        WriteEvent(new
        {
            eventType = "AutoProbeStarted",
            process = "client",
            runId = RunId,
            clientId = Config.ClientId,
            serverHost = Config.ServerHost,
            serverPorts = Config.ServerPorts,
            durationLimitSeconds = (int)Config.Duration.TotalSeconds,
        });

        var results = new List<AutoProbeCaseResult>();
        var warnings = new List<string>();
        await RunOpeningTraffic(cts.Token);
        var reachable = await RunPreflight(cts.Token);
        if (reachable.Count == 0)
        {
            warnings.Add("No client-observed UDP replies during preflight; continuing because server raw logs can still prove client-to-server delivery.");
            Console.WriteLine("No client-observed UDP replies during preflight; continuing with server-observed probes.");
        }

        var portsForCases = Config.ServerPorts;
        var cases = new List<AutoProbeCase>();
        cases.AddRange(GenerateServerObservedCases(portsForCases, maxPacketSize));
        cases.AddRange(GeneratePairwiseCases(portsForCases, maxCases, maxPacketSize));
        cases.AddRange(GenerateThresholdCases(portsForCases, maxPacketSize));
        cases.AddRange(GenerateSizeSweepCases(portsForCases, maxPacketSize));
        cases.AddRange(GenerateRateCases(portsForCases, maxPacketSize));
        cases.AddRange(GenerateDirectionCases(portsForCases, skipPush, maxPacketSize));
        if (!skipNat) cases.AddRange(GenerateRecoveryCases(portsForCases, maxPacketSize));
        if (!skipNoise) cases.AddRange(GenerateNoiseCases(portsForCases, maxPacketSize));
        cases.AddRange(GenerateStableCases(portsForCases, maxPacketSize));

        Console.WriteLine($"Running {cases.Count} AutoProbe cases until {DeadlineUtc:O} UTC.");
        int completedCases = 0;
        foreach (AutoProbeCase testCase in cases)
        {
            if (cts.IsCancellationRequested || Remaining(cts) < TimeSpan.FromSeconds(2))
                break;
            if (testCase.CaseStartDelayMs > 0)
            {
                Console.WriteLine($"Waiting {testCase.CaseStartDelayMs}ms before {testCase.CaseId} ({testCase.TestId})...");
                await Task.Delay(TimeSpan.FromMilliseconds(Math.Min(testCase.CaseStartDelayMs, Remaining(cts).TotalMilliseconds)), cts.Token);
            }
            try
            {
                Console.WriteLine(FormatCaseStart(testCase, completedCases + 1, cases.Count));
                AutoProbeCaseResult result = await RunCase(testCase, cts.Token);
                results.Add(result);
                completedCases++;
                Console.WriteLine(FormatCaseResult(result, completedCases, cases.Count));
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }

        List<string> classifications = Classify(results, reachable);
        var summary = CreateSummary(started, reachable, results, classifications, warnings);
        SaveSummary(summary, stamp, results);
        Console.WriteLine($"AutoProbe complete. Cases completed: {completedCases}/{cases.Count}. Log: {ClientLogPath}");
        return 0;
    }

    private static async Task<List<int>> RunPreflight(CancellationToken ct)
    {
        var reachable = new List<int>();
        foreach (int port in Config.ServerPorts)
        {
            var testCase = new AutoProbeCase
            {
                TestId = "preflight",
                CaseId = $"pre-{port}",
                ServerPort = port,
                WireFormat = nameof(AutoProbeWireFormat.LegacyUrp1),
                PayloadProfile = nameof(AutoProbePayloadProfile.RandomFixedSeed),
                PayloadSize = 64,
                PacketCount = 6,
                SendIntervalMs = 50,
                SocketMode = nameof(AutoProbeSocketMode.FreshSocket),
                ResponseMode = nameof(AutoProbeResponseMode.ImmediateEcho),
                DecoyEnabled = Config.EnableDecoyTargets,
                DecoyRatio = Config.EnableDecoyTargets ? 1 : 0,
                RawGarbageBeforeUsefulCount = 2,
                RawGarbageAfterUsefulCount = 1,
                RawGarbageSize = 96,
                RawGarbageIntervalMs = 25,
                PauseAfterRawGarbageMs = 50,
                InterleavingPattern = "RawGarbageAndDecoyBeforeHandshake",
            };
            AutoProbeCaseResult result = await RunCase(testCase, ct, firstPacketHello: true);
            if (result.ClientReceived > 0)
                reachable.Add(port);
            Console.WriteLine($"Port {port}: {(result.ClientReceived > 0 ? "handshake OK" : "handshake FAILED")} ({result.ClientReceived}/{result.ClientSent})");
        }
        return reachable;
    }

    private static async Task RunOpeningTraffic(CancellationToken ct)
    {
        WriteEvent(new
        {
            eventType = "CaseStarted",
            process = "client",
            runId = RunId,
            clientId = Config.ClientId,
            testId = "opening-camouflage",
            caseId = "opening-0001",
            parameters = new
            {
                serverPorts = Config.ServerPorts,
                decoyTargets = Config.DecoyTargets,
                decoyPorts = Config.DecoyPorts,
                packetRole = AutoProbePacketRole.RawGarbage.ToString(),
            },
        });

        IPAddress serverAddress = (await Dns.GetHostAddressesAsync(Config.ServerHost, ct))[0];
        var mainTargets = Config.ServerPorts
            .Select(port => new IPEndPoint(serverAddress, port))
            .ToList();
        var decoyTargets = await ResolveDecoyTargets(ct);

        using var udp = new UdpClient(0);
        int[] sizes = [48, 96, 256, 1200, 64, 1400, 512, 32];
        for (int i = 0; i < sizes.Length && !ct.IsCancellationRequested; i++)
        {
            bool sendDecoy = decoyTargets.Count > 0 && i % 2 == 0;
            IPEndPoint target = sendDecoy
                ? decoyTargets[i % decoyTargets.Count]
                : mainTargets[i % mainTargets.Count];
            byte[] garbage = AutoProbeProtocol.CreatePayload(
                AutoProbePayloadProfile.RandomCrypto,
                sizes[i],
                $"{RunId}:opening:{i}");

            udp.Send(garbage, garbage.Length, target);
            WriteEvent(new
            {
                eventType = "PacketSent",
                process = "client",
                runId = RunId,
                clientId = Config.ClientId,
                testId = "opening-camouflage",
                caseId = "opening-0001",
                probeId = $"opening-raw-{i + 1:000000}",
                packetRole = sendDecoy ? AutoProbePacketRole.DecoyNoise.ToString() : AutoProbePacketRole.RawGarbage.ToString(),
                targetRole = sendDecoy ? "DecoyTarget" : "MainServer",
                remoteEndpoint = target.ToString(),
                localEndpoint = udp.Client.LocalEndPoint?.ToString(),
                datagramSize = garbage.Length,
                packetHash64 = AutoProbeProtocol.PacketHash64(garbage),
                first16BytesHex = AutoProbeProtocol.First16Hex(garbage),
            });

            await Task.Delay(i % 3 == 0 ? 100 : 25, ct);
        }
    }

    private static async Task<AutoProbeCaseResult> RunCase(AutoProbeCase testCase, CancellationToken ct, bool firstPacketHello = true)
    {
        WriteEvent(new
        {
            eventType = "CaseStarted",
            process = "client",
            runId = RunId,
            clientId = Config.ClientId,
            testCase.TestId,
            testCase.CaseId,
            parameters = AutoProbeProtocol.ToLogParameters(testCase),
        });

        var result = new AutoProbeCaseResult { Case = testCase };
        IPAddress serverAddress = (await Dns.GetHostAddressesAsync(Config.ServerHost, ct))[0];
        var server = new IPEndPoint(serverAddress, testCase.ServerPort);
        using var udp = new UdpClient(0);
        ulong sessionId = unchecked((ulong)Random.Shared.NextInt64());
        var sentTicks = new Dictionary<ulong, long>();
        var received = new HashSet<ulong>();
        ulong maxReceived = 0;
        DateTime nextProgressUtc = DateTime.UtcNow.AddSeconds(5);

        for (int i = 0; i < testCase.PacketCount && !ct.IsCancellationRequested; i++)
        {
            if (testCase.RawGarbageBeforeUsefulCount > 0)
            {
                await SendRawGarbagePackets(udp, server, testCase, i, "BeforeUseful", testCase.RawGarbageBeforeUsefulCount, result, ct);
                if (testCase.PauseAfterRawGarbageMs > 0)
                    await Task.Delay(testCase.PauseAfterRawGarbageMs, ct);
            }

            if (Config.EnableDecoyTargets && testCase.DecoyEnabled && testCase.DecoyRatio > 0)
                await SendDecoyPackets(udp, testCase, i, "BeforeUseful", result, ct);

            ulong seq = (ulong)Interlocked.Increment(ref Sequence);
            long packetId = Interlocked.Increment(ref PacketId);
            string probeId = $"{testCase.CaseId}-{i + 1:000000}";
            var payloadProfile = Enum.Parse<AutoProbePayloadProfile>(testCase.PayloadProfile);
            byte[] payload = AutoProbeProtocol.CreatePayload(payloadProfile, testCase.PayloadSize, $"{RunId}:{testCase.CaseId}:{seq}");
            var meta = new AutoProbeMetadata
            {
                RunId = RunId,
                ClientId = Config.ClientId,
                TestId = testCase.TestId,
                CaseId = testCase.CaseId,
                ProbeId = probeId,
                PacketId = packetId,
                Sequence = seq,
                PayloadProfile = testCase.PayloadProfile,
                WireFormat = testCase.WireFormat,
                PacketRole = AutoProbePacketRole.UsefulProbe.ToString(),
                ResponseMode = testCase.ResponseMode,
                DirectionMode = testCase.DirectionMode,
            };
            byte[] datagram = AutoProbeProtocol.BuildDatagram(
                meta,
                payload,
                ClientIdHash,
                sessionId,
                firstPacketHello && i == 0 ? UdpRouteProbeMessageType.ClientHello : UdpRouteProbeMessageType.EchoRequest,
                Key);

            sentTicks[seq] = Stopwatch.GetTimestamp();
            udp.Send(datagram, datagram.Length, server);
            result.ClientSent++;
            LogSent(testCase, meta, udp, server, datagram, payload.Length, "UsefulProbe", "MainServer");

            if (testCase.NoiseEnabled && testCase.DecoyRatio > 0)
                SendSameServerNoise(udp, server, testCase, i, result);

            if (testCase.RawGarbageAfterUsefulCount > 0)
                await SendRawGarbagePackets(udp, server, testCase, i, "AfterUseful", testCase.RawGarbageAfterUsefulCount, result, ct);

            if (Config.EnableDecoyTargets && testCase.DecoyEnabled && testCase.DecoyRatio > 0)
                await SendDecoyPackets(udp, testCase, i, "AfterUseful", result, ct);

            if (testCase.SendIntervalMs > 0 && i < testCase.PacketCount - 1)
                await Task.Delay(testCase.SendIntervalMs, ct);

            if (DateTime.UtcNow >= nextProgressUtc && i < testCase.PacketCount - 1)
            {
                Console.WriteLine($"    {testCase.CaseId}: sent {i + 1}/{testCase.PacketCount}, useful={result.ClientSent}, raw={result.RawGarbageSent}, decoy={result.DecoySent}");
                nextProgressUtc = DateTime.UtcNow.AddSeconds(5);
            }
        }

        if (testCase.ResponseMode != nameof(AutoProbeResponseMode.NoResponse) &&
            testCase.DirectionMode != nameof(AutoProbeDirectionMode.ClientToServerOnly))
        {
            long deadline = Stopwatch.GetTimestamp() + Stopwatch.Frequency * 2;
            Console.WriteLine($"    {testCase.CaseId}: waiting for responses...");
            while (Stopwatch.GetTimestamp() < deadline && received.Count < result.ClientSent)
            {
                int timeoutMs = Math.Max(1, (int)((deadline - Stopwatch.GetTimestamp()) * 1000 / Stopwatch.Frequency));
                using var timeout = new CancellationTokenSource(timeoutMs);
                using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, timeout.Token);
                try
                {
                    UdpReceiveResult receive = await udp.ReceiveAsync(linked.Token);
                    if (!AutoProbeProtocol.TryDecode(receive.Buffer, Key, out AutoProbeDecodedPacket? decoded, out _) || decoded is null)
                        continue;
                    ulong seq = decoded.Packet.Sequence;
                    if (received.Add(seq))
                    {
                        if (seq < maxReceived) result.OutOfOrder++;
                        maxReceived = Math.Max(maxReceived, seq);
                        result.ClientReceived++;
                        result.LastSuccessfulSequence = (int)seq;
                        if (sentTicks.TryGetValue(seq, out long sent))
                            result.RttsMs.Add((Stopwatch.GetTimestamp() - sent) * 1000.0 / Stopwatch.Frequency);
                    }
                    else
                    {
                        result.Duplicates++;
                    }

                    WriteEvent(new
                    {
                        eventType = "PacketReceived",
                        process = "client",
                        runId = RunId,
                        clientId = Config.ClientId,
                        decoded.Metadata.TestId,
                        decoded.Metadata.CaseId,
                        decoded.Metadata.ProbeId,
                        decoded.Metadata.PacketId,
                        direction = "server-to-client",
                        localEndpoint = udp.Client.LocalEndPoint?.ToString(),
                        remoteEndpoint = receive.RemoteEndPoint.ToString(),
                        decoded.Metadata.Sequence,
                        rttMs = sentTicks.TryGetValue(seq, out long st) ? (double?)Math.Round((Stopwatch.GetTimestamp() - st) * 1000.0 / Stopwatch.Frequency, 1) : null,
                        datagramSize = receive.Buffer.Length,
                        packetHash64 = AutoProbeProtocol.PacketHash64(receive.Buffer),
                    });
                }
                catch (OperationCanceledException) when (!ct.IsCancellationRequested)
                {
                    break;
                }
                catch (SocketException ex) when (IsUdpUnreachable(ex))
                {
                    break;
                }
            }
        }

        if (result.ClientReceived < result.ClientSent)
            result.FirstLossAtSequence = Enumerable.Range(1, result.ClientSent).FirstOrDefault(n => !received.Contains((ulong)n));

        result.Classification = result.ClientReceived == result.ClientSent
            ? "success"
            : result.ClientReceived == 0 ? "server-to-client-or-client-to-server-loss" : "partial-loss";

        WriteEvent(new
        {
            eventType = "CaseCompleted",
            process = "client",
            runId = RunId,
            clientId = Config.ClientId,
            testCase.TestId,
            testCase.CaseId,
            sent = result.ClientSent,
            received = result.ClientReceived,
            lossPercent = Math.Round(result.LossPercent, 1),
            duplicates = result.Duplicates,
            outOfOrder = result.OutOfOrder,
            rttMinMs = result.RttsMs.Count > 0 ? Math.Round(result.RttsMs.Min(), 1) : 0,
            rttAvgMs = result.RttsMs.Count > 0 ? Math.Round(result.RttsMs.Average(), 1) : 0,
            rttMaxMs = result.RttsMs.Count > 0 ? Math.Round(result.RttsMs.Max(), 1) : 0,
            rttP95Ms = Percentile(result.RttsMs, 0.95),
        });
        return result;
    }

    private static void SendSameServerNoise(UdpClient udp, IPEndPoint server, AutoProbeCase testCase, int packetIndex, AutoProbeCaseResult result)
    {
        for (int n = 0; n < testCase.DecoyRatio; n++)
        {
            byte[] noise = AutoProbeProtocol.CreatePayload(AutoProbePayloadProfile.RandomCrypto, Math.Max(16, testCase.NoiseSize), $"{testCase.CaseId}:noise:{packetIndex}:{n}");
            udp.Send(noise, noise.Length, server);
            result.SameServerNoiseSent++;
            WriteEvent(new
            {
                eventType = "PacketSent",
                process = "client",
                runId = RunId,
                clientId = Config.ClientId,
                testCase.TestId,
                testCase.CaseId,
                probeId = $"{testCase.CaseId}-noise-{packetIndex:000000}-{n}",
                packetRole = "SameServerNoise",
                targetRole = "MainServer",
                remoteEndpoint = server.ToString(),
                localEndpoint = udp.Client.LocalEndPoint?.ToString(),
                datagramSize = noise.Length,
                packetHash64 = AutoProbeProtocol.PacketHash64(noise),
                first16BytesHex = AutoProbeProtocol.First16Hex(noise),
            });
        }
    }

    private static async Task SendRawGarbagePackets(
        UdpClient udp,
        IPEndPoint server,
        AutoProbeCase testCase,
        int packetIndex,
        string placement,
        int count,
        AutoProbeCaseResult result,
        CancellationToken ct)
    {
        int size = Math.Max(1, testCase.RawGarbageSize);
        for (int n = 0; n < count; n++)
        {
            byte[] garbage = AutoProbeProtocol.CreatePayload(
                AutoProbePayloadProfile.RandomCrypto,
                size,
                $"{RunId}:{testCase.CaseId}:raw-garbage:{packetIndex}:{placement}:{n}");

            udp.Send(garbage, garbage.Length, server);
            result.RawGarbageSent++;
            WriteEvent(new
            {
                eventType = "PacketSent",
                process = "client",
                runId = RunId,
                clientId = Config.ClientId,
                testCase.TestId,
                testCase.CaseId,
                probeId = $"{testCase.CaseId}-raw-{placement.ToLowerInvariant()}-{packetIndex:000000}-{n}",
                packetRole = AutoProbePacketRole.RawGarbage.ToString(),
                rawGarbagePlacement = placement,
                targetRole = "MainServer",
                remoteEndpoint = server.ToString(),
                localEndpoint = udp.Client.LocalEndPoint?.ToString(),
                datagramSize = garbage.Length,
                packetHash64 = AutoProbeProtocol.PacketHash64(garbage),
                first16BytesHex = AutoProbeProtocol.First16Hex(garbage),
            });

            if (testCase.RawGarbageIntervalMs > 0 && n < count - 1)
                await Task.Delay(testCase.RawGarbageIntervalMs, ct);
        }
    }

    private static async Task SendDecoyPackets(
        UdpClient udp,
        AutoProbeCase testCase,
        int packetIndex,
        string placement,
        AutoProbeCaseResult result,
        CancellationToken ct)
    {
        if (Config.DecoyTargets.Count == 0) return;
        int count = Config.AllowHighDecoyRate ? testCase.DecoyRatio : Math.Min(testCase.DecoyRatio, 1);
        for (int i = 0; i < count; i++)
        {
            string target = Config.DecoyTargets[(packetIndex + i) % Config.DecoyTargets.Count];
            int port = Config.DecoyPorts.Count > 0 ? Config.DecoyPorts[(packetIndex + i) % Config.DecoyPorts.Count] : testCase.ServerPort;
            var endpoint = new IPEndPoint((await Dns.GetHostAddressesAsync(target, ct))[0], port);
            byte[] datagram = AutoProbeProtocol.CreatePayload(AutoProbePayloadProfile.RandomCrypto, Math.Max(32, testCase.PayloadSize), $"{RunId}:decoy:{packetIndex}:{i}");
            udp.Send(datagram, datagram.Length, endpoint);
            result.DecoySent++;
            WriteEvent(new
            {
                eventType = "PacketSent",
                process = "client",
                runId = RunId,
                clientId = Config.ClientId,
                testCase.TestId,
                testCase.CaseId,
                probeId = $"{testCase.CaseId}-decoy-{placement.ToLowerInvariant()}-{packetIndex:000000}-{i}",
                packetRole = "DecoyNoise",
                decoyPlacement = placement,
                targetRole = "DecoyTarget",
                remoteEndpoint = endpoint.ToString(),
                localEndpoint = udp.Client.LocalEndPoint?.ToString(),
                datagramSize = datagram.Length,
                decoyProfile = "RandomCrypto",
                packetHash64 = AutoProbeProtocol.PacketHash64(datagram),
                first16BytesHex = AutoProbeProtocol.First16Hex(datagram),
            });
        }
    }

    private static void LogSent(AutoProbeCase testCase, AutoProbeMetadata meta, UdpClient udp, IPEndPoint remote, byte[] datagram, int payloadSize, string role, string targetRole)
    {
        WriteEvent(new
        {
            eventType = "PacketSent",
            process = "client",
            runId = RunId,
            clientId = Config.ClientId,
            testCase.TestId,
            testCase.CaseId,
            meta.ProbeId,
            meta.PacketId,
            packetRole = role,
            targetRole,
            direction = "client-to-server",
            localEndpoint = udp.Client.LocalEndPoint?.ToString(),
            remoteEndpoint = remote.ToString(),
            datagramSize = datagram.Length,
            payloadSize,
            testCase.WireFormat,
            testCase.PayloadProfile,
            meta.Sequence,
            packetHash64 = AutoProbeProtocol.PacketHash64(datagram),
            first16BytesHex = AutoProbeProtocol.First16Hex(datagram),
        });
    }

    private static async Task<List<IPEndPoint>> ResolveDecoyTargets(CancellationToken ct)
    {
        var endpoints = new List<IPEndPoint>();
        for (int i = 0; i < Config.DecoyTargets.Count; i++)
        {
            string host = Config.DecoyTargets[i];
            int port = Config.DecoyPorts.Count > 0
                ? Config.DecoyPorts[i % Config.DecoyPorts.Count]
                : Config.ServerPorts[i % Config.ServerPorts.Count];
            IPAddress[] addresses = await Dns.GetHostAddressesAsync(host, ct);
            if (addresses.Length > 0)
                endpoints.Add(new IPEndPoint(addresses[0], port));
        }
        return endpoints;
    }

    private static List<AutoProbeCase> GeneratePairwiseCases(List<int> ports, int maxCases, int maxPacketSize)
    {
        var factors = new Dictionary<string, string[]>
        {
            ["wire"] = [nameof(AutoProbeWireFormat.LegacyUrp1), nameof(AutoProbeWireFormat.RandomPrefixUrp1), nameof(AutoProbeWireFormat.NoMagicMinimal), nameof(AutoProbeWireFormat.JsonText)],
            ["profile"] = Enum.GetNames<AutoProbePayloadProfile>(),
            ["size"] = [.. new[] { 64, 256, 512, 1200, 1400 }.Where(s => s <= maxPacketSize).Select(s => s.ToString(CultureInfo.InvariantCulture))],
            ["interval"] = ["0", "10", "50", "100", "500", "1000"],
            ["count"] = ["5", "10", "20", "50"],
            ["response"] = [nameof(AutoProbeResponseMode.ImmediateEcho), nameof(AutoProbeResponseMode.DelayedEcho100ms), nameof(AutoProbeResponseMode.DelayedEcho1000ms), nameof(AutoProbeResponseMode.NoResponse)],
        };

        var cases = new List<AutoProbeCase>();
        int index = 0;
        foreach (int port in ports)
        {
            foreach (string wire in factors["wire"])
            foreach (string profile in factors["profile"])
            {
                string size = factors["size"][index % factors["size"].Length];
                string interval = factors["interval"][(index / 2) % factors["interval"].Length];
                string count = factors["count"][(index / 3) % factors["count"].Length];
                string response = factors["response"][(index / 5) % factors["response"].Length];
                cases.Add(new AutoProbeCase
                {
                    TestId = "pairwise-short",
                    CaseId = $"pw-{index + 1:0000}",
                    ServerPort = port,
                    WireFormat = wire,
                    PayloadProfile = profile,
                    PayloadSize = int.Parse(size, CultureInfo.InvariantCulture),
                    SendIntervalMs = int.Parse(interval, CultureInfo.InvariantCulture),
                    PacketCount = int.Parse(count, CultureInfo.InvariantCulture),
                    SocketMode = index % 2 == 0 ? nameof(AutoProbeSocketMode.FreshSocket) : nameof(AutoProbeSocketMode.ReuseSocketWithinCase),
                    ResponseMode = response,
                });
                index++;
                if (cases.Count >= maxCases) return cases;
            }
        }
        return cases;
    }

    private static IEnumerable<AutoProbeCase> GenerateServerObservedCases(List<int> ports, int maxPacketSize)
    {
        int[] sizes = [32, 64, 128, 256, 512, 1000, 1200, 1400, 1472, 1500, 2000, 4096, 8192, 16384];
        int[] intervals = [0, 25, 100, 500, 1000, 5000];
        int index = 0;

        foreach (int port in ports)
        foreach (int size in sizes.Where(s => s <= maxPacketSize))
        {
            int interval = intervals[index % intervals.Length];
            var observed = Baseline("server-observed-size-port", $"obs-{index + 1:0000}", port, size, 8, interval);
            observed.DirectionMode = nameof(AutoProbeDirectionMode.ClientToServerOnly);
            observed.ResponseMode = nameof(AutoProbeResponseMode.NoResponse);
            observed.WireFormat = index % 3 == 0
                ? nameof(AutoProbeWireFormat.LegacyUrp1)
                : index % 3 == 1 ? nameof(AutoProbeWireFormat.RandomPrefixUrp1) : nameof(AutoProbeWireFormat.NoMagicMinimal);
            observed.PayloadProfile = index % 2 == 0
                ? nameof(AutoProbePayloadProfile.RandomCrypto)
                : nameof(AutoProbePayloadProfile.RepeatedPattern);
            yield return observed;
            index++;
        }

        int garbageIndex = 0;
        foreach (int port in ports)
        foreach (int garbageSize in new[] { 32, 64, 256, 1200, 1400, 1500, 4096 }.Where(s => s <= maxPacketSize))
        foreach (int pauseMs in new[] { 0, 100, 1000, 5000 })
        {
            var garbage = Baseline("raw-garbage-interleaving", $"garbage-{garbageIndex + 1:0000}", port, Math.Min(256, maxPacketSize), 6, Math.Max(100, pauseMs));
            garbage.DirectionMode = nameof(AutoProbeDirectionMode.ClientToServerOnly);
            garbage.ResponseMode = nameof(AutoProbeResponseMode.NoResponse);
            garbage.PayloadProfile = nameof(AutoProbePayloadProfile.RandomCrypto);
            garbage.RawGarbageBeforeUsefulCount = 1;
            garbage.RawGarbageAfterUsefulCount = 1;
            garbage.RawGarbageSize = garbageSize;
            garbage.RawGarbageIntervalMs = pauseMs;
            garbage.PauseAfterRawGarbageMs = pauseMs;
            garbage.InterleavingPattern = $"RawGarbageBeforeAndAfterUseful_Pause{pauseMs}ms";
            yield return garbage;
            garbageIndex++;
        }
    }

    private static IEnumerable<AutoProbeCase> GenerateThresholdCases(List<int> ports, int maxPacketSize)
        => new[] { 10, 20, 50, 100, 200, 500, 1000 }
            .Where(c => maxPacketSize >= 256)
            .Select((count, i) => Baseline("threshold", $"th-{i + 1:0000}", ports[0], 256, count, i % 4 == 0 ? 0 : 50));

    private static IEnumerable<AutoProbeCase> GenerateSizeSweepCases(List<int> ports, int maxPacketSize)
        => new[] { 64, 128, 256, 512, 1000, 1200, 1300, 1400, 1472, 1500, 2000, 4096, 8192, 16384, 32768, 60000 }
            .Where(s => s <= maxPacketSize)
            .Select((size, i) => Baseline("size-sweep-isolated", $"sz-{i + 1:0000}", ports[i % ports.Count], size, 10, 50));

    private static IEnumerable<AutoProbeCase> GenerateRateCases(List<int> ports, int maxPacketSize)
        => new[] { 0, 10, 50, 100, 500, 1000 }
            .Select((rate, i) => Baseline("rate-sweep", $"rate-{i + 1:0000}", ports[0], Math.Min(512, maxPacketSize), 50, rate));

    private static IEnumerable<AutoProbeCase> GenerateDirectionCases(List<int> ports, bool skipPush, int maxPacketSize)
    {
        AutoProbeCase clientToServerOnly = Baseline("directionality", "dir-0001", ports[0], Math.Min(256, maxPacketSize), 20, 50);
        clientToServerOnly.DirectionMode = nameof(AutoProbeDirectionMode.ClientToServerOnly);
        clientToServerOnly.ResponseMode = nameof(AutoProbeResponseMode.NoResponse);
        yield return clientToServerOnly;
        yield return Baseline("directionality", "dir-0002", ports[0], Math.Min(256, maxPacketSize), 20, 50);
        if (!skipPush)
        {
            AutoProbeCase push = Baseline("directionality", "dir-0003", ports[0], Math.Min(256, maxPacketSize), 5, 1000);
            push.DirectionMode = nameof(AutoProbeDirectionMode.ServerPushAfterClientPacket);
            push.ResponseMode = nameof(AutoProbeResponseMode.DelayedEcho1000ms);
            yield return push;
        }
    }

    private static IEnumerable<AutoProbeCase> GenerateRecoveryCases(List<int> ports, int maxPacketSize)
    {
        string[] variants = ["SameSocketSameSession", "SameSocketNewSession", "NewSocketSameServerPort", "NewSocketDifferentServerPort", "NewSocketAfterDelay10s", "NewSocketAfterDelay60s"];
        for (int i = 0; i < variants.Length; i++)
        {
            AutoProbeCase recovery = Baseline("flow-recovery", $"rec-{i + 1:0000}", ports[i == 3 && ports.Count > 1 ? 1 : 0], Math.Min(256, maxPacketSize), 20, 50);
            recovery.SocketMode = variants[i];
            recovery.CaseStartDelayMs = i == 4 ? 10000 : i == 5 ? 60000 : 0;
            yield return recovery;
        }
    }

    private static IEnumerable<AutoProbeCase> GenerateNoiseCases(List<int> ports, int maxPacketSize)
    {
        string[] placements = ["PrefixNoise", "SuffixNoise", "RandomOffsetProtocol"];
        for (int i = 0; i < placements.Length; i++)
        {
            AutoProbeCase noise = Baseline("noise-in-packet", $"noise-{i + 1:0000}", ports[0], Math.Min(256, maxPacketSize), 20, 100);
            noise.NoiseEnabled = true;
            noise.NoisePlacement = placements[i];
            noise.NoiseSize = 32 * (i + 1);
            noise.NoiseProfile = nameof(AutoProbePayloadProfile.RandomCrypto);
            noise.DecoyRatio = 1;
            yield return noise;
        }
        AutoProbeCase decoy = Baseline("interleaving-decoy", "decoy-0001", ports[0], Math.Min(256, maxPacketSize), 20, 100);
        decoy.DecoyEnabled = Config.EnableDecoyTargets;
        decoy.DecoyRatio = Config.AllowHighDecoyRate ? 5 : 1;
        decoy.InterleavingPattern = "AfterEachUseful";
        yield return decoy;
    }

    private static IEnumerable<AutoProbeCase> GenerateStableCases(List<int> ports, int maxPacketSize)
    {
        for (int i = 0; i < Math.Min(3, ports.Count); i++)
            yield return Baseline("long-stable-candidate", $"stable-{i + 1:0000}", ports[i], Math.Min(512, maxPacketSize), 300, 1000);
    }

    private static AutoProbeCase Baseline(string testId, string caseId, int port, int size, int count, int interval)
        => new()
        {
            TestId = testId,
            CaseId = caseId,
            ServerPort = port,
            WireFormat = nameof(AutoProbeWireFormat.LegacyUrp1),
            PayloadProfile = nameof(AutoProbePayloadProfile.RandomFixedSeed),
            PayloadSize = size,
            PacketCount = count,
            SendIntervalMs = interval,
            SocketMode = nameof(AutoProbeSocketMode.FreshSocket),
            ResponseMode = nameof(AutoProbeResponseMode.ImmediateEcho),
        };

    private static string FormatCaseStart(AutoProbeCase testCase, int index, int total)
    {
        string extras = "";
        if (testCase.RawGarbageBeforeUsefulCount > 0 || testCase.RawGarbageAfterUsefulCount > 0)
            extras += $" raw={testCase.RawGarbageBeforeUsefulCount}+{testCase.RawGarbageAfterUsefulCount}x{testCase.RawGarbageSize}";
        if (testCase.DecoyEnabled)
            extras += $" decoyRatio={testCase.DecoyRatio}";
        return $"[{index}/{total}] {testCase.TestId}/{testCase.CaseId}: port={testCase.ServerPort} wire={testCase.WireFormat} payload={testCase.PayloadProfile}/{testCase.PayloadSize} count={testCase.PacketCount} interval={testCase.SendIntervalMs}ms response={testCase.ResponseMode}{extras}";
    }

    private static string FormatCaseResult(AutoProbeCaseResult result, int index, int total)
    {
        string rtt = result.RttsMs.Count == 0
            ? "rtt=n/a"
            : $"rtt(avg/p95)={Math.Round(result.RttsMs.Average(), 1)}/{Percentile(result.RttsMs, 0.95)}ms";
        return $"[{index}/{total}] {result.Case.CaseId} done: useful {result.ClientReceived}/{result.ClientSent}, loss={Math.Round(result.LossPercent, 1)}%, raw={result.RawGarbageSent}, decoy={result.DecoySent}, {rtt}, {result.Classification}";
    }

    private static List<string> Classify(List<AutoProbeCaseResult> results, List<int> reachable)
    {
        var c = new HashSet<string>();
        if (reachable.Count < Config.ServerPorts.Count) c.Add("port-sensitive-behavior");
        if (results.Any(r => r.LossPercent > 0 && r.LossPercent < 100)) c.Add("server-to-client-loss");
        if (results.Any(r => r.Case.TestId == "rate-sweep" && r.LossPercent > 20)) c.Add("rate-sensitive-loss");
        if (results.Any(r => r.Case.TestId == "size-sweep-isolated" && r.LossPercent > 20)) c.Add("size-sensitive-loss");
        if (results.GroupBy(r => r.Case.WireFormat).Where(g => g.Count() > 1).Select(g => g.Average(r => r.LossPercent)).DefaultIfEmpty(0).Max() > 20) c.Add("wire-format-sensitive-behavior");
        if (results.Any(r => r.Case.NoiseEnabled && r.LossPercent != results.Where(x => !x.Case.NoiseEnabled).Select(x => x.LossPercent).DefaultIfEmpty(r.LossPercent).Average())) c.Add("packet-shape-sensitive");
        if (results.Any(r => r.Case.DecoyEnabled)) c.Add("traffic-shape-sensitive");
        if (results.Any(r => r.LossPercent <= 5)) c.Add("stable-profile-found");
        else c.Add("no-stable-udp-profile-found");
        return [.. c];
    }

    private static AutoProbeSummary CreateSummary(DateTime started, List<int> reachable, List<AutoProbeCaseResult> results, List<string> classifications, List<string> warnings)
    {
        List<AutoProbeBestCase> typedBest = results.OrderBy(r => r.LossPercent).ThenBy(r => r.RttsMs.Count > 0 ? r.RttsMs.Average() : double.MaxValue).Take(3)
            .Select(r => new AutoProbeBestCase
            {
                CaseId = r.Case.CaseId,
                ServerPort = r.Case.ServerPort,
                WireFormat = r.Case.WireFormat,
                PayloadProfile = r.Case.PayloadProfile,
                PayloadSize = r.Case.PayloadSize,
                SendIntervalMs = r.Case.SendIntervalMs,
                SuccessPercent = Math.Round(100 - r.LossPercent, 1),
            }).ToList();
        List<object> best = typedBest.Cast<object>().ToList();

        object recommendations = typedBest.Count == 0
            ? new { safePayloadSize = "unknown", suggestedKeepAliveSeconds = "unknown" }
            : new
            {
                safePayloadSize = "unknown",
                reason = "AutoProbe reports observed best cases only; safe size requires corroborated size-sweep evidence.",
                bestObservedPort = typedBest[0].ServerPort,
                bestObservedPayloadProfile = typedBest[0].PayloadProfile,
                bestObservedWireFormat = typedBest[0].WireFormat,
            };

        DateTime finished = DateTime.UtcNow;
        return new AutoProbeSummary
        {
            RunId = RunId,
            StartedAtUtc = started,
            FinishedAtUtc = finished,
            DurationSeconds = Math.Round((finished - started).TotalSeconds, 1),
            Server = Config.ServerHost,
            PortsTested = Config.ServerPorts,
            PortsReachable = reachable,
            Classifications = classifications,
            BestCases = best,
            Warnings = warnings,
            Recommendations = recommendations,
        };
    }

    private static void SaveSummary(AutoProbeSummary summary, string stamp, List<AutoProbeCaseResult> results)
    {
        string jsonPath = Path.Combine(Config.OutputDirectory, $"autoprobe-summary-{stamp}.json");
        string csvPath = Path.Combine(Config.OutputDirectory, $"autoprobe-summary-{stamp}.csv");
        File.WriteAllText(jsonPath, JsonSerializer.Serialize(summary, new JsonSerializerOptions(JsonOptions) { WriteIndented = true }));

        var sb = new StringBuilder();
        sb.AppendLine("runId,testId,caseId,serverPort,wireFormat,payloadProfile,payloadSize,sendIntervalMs,packetCount,socketMode,responseMode,noiseEnabled,noisePlacement,noiseSize,noiseProfile,decoyEnabled,decoyRatio,interleavingPattern,rawGarbageBeforeUsefulCount,rawGarbageAfterUsefulCount,rawGarbageSize,rawGarbageIntervalMs,pauseAfterRawGarbageMs,clientSent,sameServerNoiseSent,rawGarbageSent,decoySent,serverReceived,serverRejected,serverResponded,clientReceived,clientToServerLossPercent,serverToClientLossPercent,rttMinMs,rttAvgMs,rttMaxMs,rttP95Ms,firstLossAtSequence,lastSuccessfulSequence,classification");
        foreach (AutoProbeCaseResult r in results)
        {
            double rttMin = r.RttsMs.Count > 0 ? r.RttsMs.Min() : 0;
            double rttAvg = r.RttsMs.Count > 0 ? r.RttsMs.Average() : 0;
            double rttMax = r.RttsMs.Count > 0 ? r.RttsMs.Max() : 0;
            sb.AppendLine(string.Join(',',
                Csv(RunId), Csv(r.Case.TestId), Csv(r.Case.CaseId), r.Case.ServerPort, Csv(r.Case.WireFormat), Csv(r.Case.PayloadProfile),
                r.Case.PayloadSize, r.Case.SendIntervalMs, r.Case.PacketCount, Csv(r.Case.SocketMode), Csv(r.Case.ResponseMode),
                r.Case.NoiseEnabled, Csv(r.Case.NoisePlacement ?? ""), r.Case.NoiseSize, Csv(r.Case.NoiseProfile ?? ""),
                r.Case.DecoyEnabled, r.Case.DecoyRatio, Csv(r.Case.InterleavingPattern ?? ""),
                r.Case.RawGarbageBeforeUsefulCount, r.Case.RawGarbageAfterUsefulCount, r.Case.RawGarbageSize,
                r.Case.RawGarbageIntervalMs, r.Case.PauseAfterRawGarbageMs, r.ClientSent, r.SameServerNoiseSent,
                r.RawGarbageSent, r.DecoySent, "", "", "", r.ClientReceived, "", "", Math.Round(rttMin, 1), Math.Round(rttAvg, 1), Math.Round(rttMax, 1),
                Percentile(r.RttsMs, 0.95), r.FirstLossAtSequence, r.LastSuccessfulSequence, Csv(r.Classification)));
        }
        File.WriteAllText(csvPath, sb.ToString());
        Console.WriteLine($"Summary: {jsonPath}");
        Console.WriteLine($"CSV: {csvPath}");
    }

    private static void WriteEvent(object value)
    {
        var map = new Dictionary<string, object?>
        {
            ["schemaVersion"] = 1,
            ["eventId"] = Guid.NewGuid().ToString(),
            ["utc"] = DateTime.UtcNow.ToString("O"),
            ["monotonicTimestampMs"] = Stopwatch.GetTimestamp() * 1000 / Stopwatch.Frequency,
        };
        foreach (var property in value.GetType().GetProperties())
            map[property.Name[..1].ToLowerInvariant() + property.Name[1..]] = property.GetValue(value);
        lock (LogLock)
            File.AppendAllText(ClientLogPath, JsonSerializer.Serialize(map, JsonOptions) + Environment.NewLine);
    }

    private static void MergeConfig(AutoProbeClientConfig fileConfig)
    {
        if (string.IsNullOrWhiteSpace(Config.ServerHost)) Config.ServerHost = fileConfig.ServerHost;
        if (Config.ServerPorts.Count == 0) Config.ServerPorts = fileConfig.ServerPorts.Count > 0 ? fileConfig.ServerPorts : [fileConfig.ServerPort];
        if (string.IsNullOrWhiteSpace(Config.ClientId)) Config.ClientId = fileConfig.ClientId;
        if (string.IsNullOrWhiteSpace(Config.SecretKey)) Config.SecretKey = fileConfig.SecretKey;
        if (Config.OutputDirectory == "probe-results") Config.OutputDirectory = fileConfig.OutputDirectory;
        Config.Duration = fileConfig.Duration;
        Config.EnableDecoyTargets |= fileConfig.EnableDecoyTargets;
        Config.AllowHighDecoyRate |= fileConfig.AllowHighDecoyRate;
        Config.DecoyTargets = fileConfig.DecoyTargets;
        Config.DecoyPorts = fileConfig.DecoyPorts;
    }

    private static TimeSpan Remaining(CancellationTokenSource cts) => cts.Token.IsCancellationRequested ? TimeSpan.Zero : DeadlineUtc - DateTime.UtcNow;
    private static bool IsUdpUnreachable(SocketException ex)
        => ex.SocketErrorCode is SocketError.ConnectionReset
            or SocketError.ConnectionRefused
            or SocketError.HostUnreachable
            or SocketError.NetworkUnreachable;
    private static List<int> ParsePorts(string value) => value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Select(int.Parse).Distinct().ToList();
    private static List<string> ParseStringList(string value) => value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    private static double Percentile(List<double> values, double percentile) => values.Count == 0 ? 0 : Math.Round(values.Order().ElementAt(Math.Min(values.Count - 1, (int)(values.Count * percentile))), 1);
    private static string Csv(string value) => "\"" + value.Replace("\"", "\"\"") + "\"";
}
