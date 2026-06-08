using System.Text.Json;
using System.Text.Json.Serialization;

namespace UdpRouteProbe.Client;

sealed class CompareProbeState
{
    public string ProbeId { get; set; } = "";
    public string CaseId { get; set; } = "";
    public string TestId { get; set; } = "";
    public string PacketRole { get; set; } = "UsefulProbe";
    public bool ClientSent { get; set; }
    public bool ServerAccepted { get; set; }
    public bool ServerRawReceived { get; set; }
    public bool ServerRejected { get; set; }
    public bool ServerResponded { get; set; }
    public bool ClientReceived { get; set; }
    public bool ExpectsResponse { get; set; } = true;
    public string PacketHash64 { get; set; } = "";
    public long PacketId { get; set; }
    public ulong Sequence { get; set; }
    public string RejectReason { get; set; } = "";
    public string State { get; set; } = "";
}

static class AutoProbeCompare
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        WriteIndented = true,
    };

    public static async Task<int> Run(string[] args)
    {
        string? clientLog = null;
        string? serverLog = null;
        string? output = null;
        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--client-log" when i + 1 < args.Length: clientLog = args[++i]; break;
                case "--server-log" when i + 1 < args.Length: serverLog = args[++i]; break;
                case "--output" when i + 1 < args.Length: output = args[++i]; break;
            }
        }

        if (clientLog is null || serverLog is null || output is null)
        {
            Console.Error.WriteLine("Required: compare --client-log FILE --server-log FILE --output FILE");
            return 1;
        }
        if (!File.Exists(clientLog))
        {
            Console.Error.WriteLine($"Client log not found: {clientLog}");
            return 1;
        }
        if (!File.Exists(serverLog))
        {
            Console.Error.WriteLine($"Server log not found: {serverLog}");
            return 1;
        }

        var probes = new Dictionary<string, CompareProbeState>(StringComparer.Ordinal);
        var probesByPacketHash = new Dictionary<string, CompareProbeState>(StringComparer.OrdinalIgnoreCase);
        string runId = "";
        var caseParameters = new Dictionary<string, JsonElement>(StringComparer.Ordinal);

        await ReadLog(clientLog, e =>
        {
            string eventType = GetString(e, "eventType");
            runId = runId.Length == 0 ? GetString(e, "runId") : runId;
            if (eventType == "CaseStarted")
            {
                string caseId = GetString(e, "caseId");
                if (caseId.Length > 0 && e.TryGetProperty("parameters", out JsonElement parameters))
                    caseParameters[caseId] = parameters.Clone();
                return;
            }

            string probeId = GetString(e, "probeId");
            if (probeId.Length == 0) return;
            CompareProbeState p = GetProbe(probes, probeId, e);
            if (eventType == "PacketSent") p.ClientSent = true;
            if (eventType == "PacketReceived") p.ClientReceived = true;
            ApplyCaseParameters(p, caseParameters);
            string packetHash = GetString(e, "packetHash64");
            if (packetHash.Length > 0)
            {
                p.PacketHash64 = packetHash;
                probesByPacketHash[packetHash] = p;
            }
        });

        await ReadLog(serverLog, e =>
        {
            string probeId = GetString(e, "probeId");
            CompareProbeState? p;
            if (probeId.Length == 0)
            {
                string packetHash = GetString(e, "packetHash64");
                if (packetHash.Length == 0 || !probesByPacketHash.TryGetValue(packetHash, out p))
                    return;
            }
            else
            {
                p = GetProbe(probes, probeId, e);
            }

            switch (GetString(e, "eventType"))
            {
                case "RawPacketReceived":
                    p.ServerRawReceived = true;
                    break;
                case "PacketAccepted":
                    p.ServerRawReceived = true;
                    p.ServerAccepted = true;
                    break;
                case "PacketRejected":
                    p.ServerRawReceived = true;
                    p.ServerRejected = true;
                    p.RejectReason = GetString(e, "reason");
                    break;
                case "ResponseSent":
                    p.ServerResponded = true;
                    break;
            }
            ApplyCaseParameters(p, caseParameters);
        });

        foreach (CompareProbeState p in probes.Values)
            p.State = Classify(p);

        var useful = probes.Values.Where(p => p.PacketRole == "UsefulProbe").ToList();
        var cases = probes.Values.GroupBy(p => p.CaseId).Select(g =>
        {
            var items = g.ToList();
            int clientSent = items.Count(p => p.ClientSent && p.PacketRole == "UsefulProbe");
            int serverRawReceived = items.Count(p => p.ServerRawReceived && p.PacketRole == "UsefulProbe");
            int serverAccepted = items.Count(p => p.ServerAccepted && p.PacketRole == "UsefulProbe");
            int serverRejected = items.Count(p => p.ServerRejected && p.PacketRole == "UsefulProbe");
            int serverResponded = items.Count(p => p.ServerResponded && p.PacketRole == "UsefulProbe");
            int clientReceived = items.Count(p => p.ClientReceived && p.PacketRole == "UsefulProbe");
            int sameServerNoiseSent = items.Count(p => p.ClientSent && p.PacketRole == "SameServerNoise");
            int sameServerNoiseReceived = items.Count(p => p.ServerRejected && p.PacketRole == "SameServerNoise");
            int decoySent = items.Count(p => p.ClientSent && p.PacketRole == "DecoyNoise");
            bool expectsResponse = items.Any(p => p.PacketRole == "UsefulProbe") && items.Where(p => p.PacketRole == "UsefulProbe").All(p => p.ExpectsResponse);
            caseParameters.TryGetValue(g.Key, out JsonElement parameters);
            return new
            {
                caseId = g.Key,
                testId = items.FirstOrDefault()?.TestId ?? "",
                parameters,
                expectsResponse,
                clientSent,
                serverRawReceived,
                serverAccepted,
                serverRejected,
                serverResponded,
                clientReceived = expectsResponse ? clientReceived : (int?)null,
                sameServerNoiseSent,
                sameServerNoiseReceived,
                decoySent,
                clientToServerRawLossPercent = Percent(clientSent - serverRawReceived, clientSent),
                serverRejectPercent = Percent(serverRejected, serverRawReceived),
                serverAcceptedButNoResponsePercent = Percent(serverAccepted - serverResponded, serverAccepted),
                serverToClientResponseLossPercent = expectsResponse ? Percent(serverResponded - clientReceived, serverResponded) : (double?)null,
                endToEndSuccessPercent = expectsResponse ? Percent(clientReceived, clientSent) : (double?)null,
                firstLossAtSequence = FirstLossAtSequence(items, expectsResponse),
                lastSuccessfulSequence = LastSuccessfulSequence(items),
                classification = CaseClassification(items, clientSent, serverRawReceived, serverAccepted, serverRejected, serverResponded, clientReceived, expectsResponse),
            };
        }).OrderBy(c => c.caseId).ToList();

        var report = new
        {
            runId,
            totalClientSent = useful.Count(p => p.ClientSent),
            serverAccepted = useful.Count(p => p.ServerAccepted),
            serverRawReceived = probes.Values.Count(p => p.ServerRawReceived),
            serverRejected = useful.Count(p => p.ServerRejected),
            serverResponded = useful.Count(p => p.ServerResponded),
            clientReceived = useful.Count(p => p.ClientReceived),
            clientToServerRawLossPercent = Percent(useful.Count(p => p.ClientSent && !p.ServerRawReceived), useful.Count(p => p.ClientSent)),
            serverRejectPercent = Percent(useful.Count(p => p.ServerRejected), useful.Count(p => p.ServerRawReceived)),
            serverToClientLossPercent = Percent(useful.Count(p => p.ServerResponded && !p.ClientReceived), useful.Count(p => p.ServerResponded)),
            states = probes.Values.OrderBy(p => p.CaseId).ThenBy(p => p.ProbeId).ToList(),
            cases,
        };

        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(output)) ?? ".");
        await File.WriteAllTextAsync(output, JsonSerializer.Serialize(report, JsonOptions));
        Console.WriteLine($"Compare written: {output}");
        return 0;
    }

    private static async Task ReadLog(string path, Action<JsonElement> handle)
    {
        foreach (string line in await File.ReadAllLinesAsync(path))
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            using JsonDocument doc = JsonDocument.Parse(line);
            handle(doc.RootElement);
        }
    }

    private static CompareProbeState GetProbe(Dictionary<string, CompareProbeState> probes, string probeId, JsonElement e)
    {
        if (!probes.TryGetValue(probeId, out CompareProbeState? state))
        {
            state = new CompareProbeState { ProbeId = probeId };
            probes[probeId] = state;
        }
        string caseId = GetString(e, "caseId");
        string testId = GetString(e, "testId");
        string packetRole = GetString(e, "packetRole");
        if (caseId.Length > 0) state.CaseId = caseId;
        if (testId.Length > 0) state.TestId = testId;
        if (packetRole.Length > 0) state.PacketRole = packetRole;
        if (e.TryGetProperty("packetId", out JsonElement packetIdElement) && packetIdElement.TryGetInt64(out long packetId)) state.PacketId = packetId;
        if (e.TryGetProperty("sequence", out JsonElement sequenceElement) && sequenceElement.TryGetUInt64(out ulong sequence)) state.Sequence = sequence;
        return state;
    }

    private static string Classify(CompareProbeState p)
    {
        if (p.PacketRole == "DecoyNoise") return "NotApplicable_DecoyTarget";
        if (p.PacketRole == "RawGarbage" && p.ServerRawReceived) return "RawGarbage_ServerReceived";
        if (p.PacketRole == "RawGarbage" && p.ClientSent && !p.ServerRawReceived) return "RawGarbage_ServerDidNotReceive";
        if (p.ServerRejected) return "ServerRawReceived_ServerRejected";
        if (p.ClientSent && !p.ServerRawReceived) return "ClientSent_ServerDidNotReceive";
        if (!p.ExpectsResponse && p.ServerAccepted) return "ServerAccepted_NoResponseExpected";
        if (p.ServerAccepted && !p.ServerResponded) return "ServerAccepted_ServerDidNotRespond";
        if (p.ServerResponded && !p.ClientReceived) return "ServerResponded_ClientDidNotReceive";
        if (p.ClientSent && p.ServerAccepted && (p.ClientReceived || !p.ExpectsResponse)) return p.ExpectsResponse ? "Success" : "ServerAccepted_NoResponseExpected";
        return "ClientSent_ServerDidNotReceive";
    }

    private static string CaseClassification(List<CompareProbeState> items, int clientSent, int serverRawReceived, int serverAccepted, int serverRejected, int serverResponded, int clientReceived, bool expectsResponse)
    {
        if (clientSent == 0) return "no-client-packets";
        if (serverRawReceived > 0 && serverAccepted == 0 && serverRejected > 0) return RejectClassification(items);
        if (serverRawReceived == 0) return "client-to-server-loss";
        if (!expectsResponse && serverAccepted >= clientSent * 0.95) return "client-to-server-ok-noresponse";
        if (serverResponded > 0 && PercentRatio(clientReceived, serverResponded) < 0.5) return "server-to-client-loss";
        if (expectsResponse && clientReceived == clientSent) return "success";
        if (expectsResponse && serverAccepted > 0 && serverResponded > 0 && clientReceived < serverResponded) return "client-to-server-ok-server-to-client-loss";
        return "partial-loss";
    }

    private static string RejectClassification(List<CompareProbeState> items)
    {
        var reasons = items.Where(p => p.ServerRejected).Select(p => p.RejectReason).ToHashSet(StringComparer.Ordinal);
        if (reasons.Any(r => r.Contains("Hmac", StringComparison.OrdinalIgnoreCase) || r.Contains("ClientIdHash", StringComparison.OrdinalIgnoreCase)))
            return "server-auth-reject";
        if (reasons.Any(r => r.Contains("Session", StringComparison.OrdinalIgnoreCase)))
            return "server-session-reject";
        if (reasons.Any(r => r.Contains("Magic", StringComparison.OrdinalIgnoreCase) || r.Contains("Prefix", StringComparison.OrdinalIgnoreCase) || r.Contains("WireFormat", StringComparison.OrdinalIgnoreCase)))
            return "server-wireformat-reject";
        return "server-parser-reject";
    }

    private static void ApplyCaseParameters(CompareProbeState p, Dictionary<string, JsonElement> caseParameters)
    {
        if (p.CaseId.Length == 0 || !caseParameters.TryGetValue(p.CaseId, out JsonElement parameters))
            return;
        string responseMode = GetString(parameters, "responseMode");
        string directionMode = GetString(parameters, "directionMode");
        p.ExpectsResponse = responseMode != "NoResponse" && directionMode != "ClientToServerOnly";
    }

    private static ulong FirstLossAtSequence(List<CompareProbeState> items, bool expectsResponse)
        => !expectsResponse
            ? 0
            : items.Where(p => p.ClientSent && p.PacketRole == "UsefulProbe" && !p.ClientReceived)
                .OrderBy(p => p.Sequence)
                .Select(p => p.Sequence)
                .FirstOrDefault();

    private static ulong LastSuccessfulSequence(List<CompareProbeState> items)
        => items.Where(p => p.ClientReceived && p.PacketRole == "UsefulProbe")
            .OrderByDescending(p => p.Sequence)
            .Select(p => p.Sequence)
            .FirstOrDefault();

    private static double PercentRatio(int numerator, int denominator)
        => denominator > 0 ? (double)numerator / denominator : 0;

    private static double Percent(int numerator, int denominator)
        => denominator > 0 ? Math.Round(100.0 * numerator / denominator, 1) : 0;

    private static string GetString(JsonElement e, string property)
        => e.TryGetProperty(property, out JsonElement value) && value.ValueKind != JsonValueKind.Null ? value.ToString() : "";
}
