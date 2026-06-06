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
    public bool ServerReceived { get; set; }
    public bool ServerRejected { get; set; }
    public bool ServerResponded { get; set; }
    public bool ClientReceived { get; set; }
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
        });

        await ReadLog(serverLog, e =>
        {
            string probeId = GetString(e, "probeId");
            if (probeId.Length == 0) return;
            CompareProbeState p = GetProbe(probes, probeId, e);
            switch (GetString(e, "eventType"))
            {
                case "PacketAccepted":
                    p.ServerReceived = true;
                    break;
                case "PacketRejected":
                    p.ServerRejected = true;
                    break;
                case "ResponseSent":
                    p.ServerResponded = true;
                    break;
            }
        });

        foreach (CompareProbeState p in probes.Values)
            p.State = Classify(p);

        var useful = probes.Values.Where(p => p.PacketRole == "UsefulProbe").ToList();
        var cases = probes.Values.GroupBy(p => p.CaseId).Select(g =>
        {
            var items = g.ToList();
            int clientSent = items.Count(p => p.ClientSent && p.PacketRole == "UsefulProbe");
            int serverReceived = items.Count(p => p.ServerReceived && p.PacketRole == "UsefulProbe");
            int serverResponded = items.Count(p => p.ServerResponded && p.PacketRole == "UsefulProbe");
            int clientReceived = items.Count(p => p.ClientReceived && p.PacketRole == "UsefulProbe");
            int sameServerNoiseSent = items.Count(p => p.ClientSent && p.PacketRole == "SameServerNoise");
            int sameServerNoiseReceived = items.Count(p => p.ServerRejected && p.PacketRole == "SameServerNoise");
            int decoySent = items.Count(p => p.ClientSent && p.PacketRole == "DecoyNoise");
            caseParameters.TryGetValue(g.Key, out JsonElement parameters);
            return new
            {
                caseId = g.Key,
                testId = items.FirstOrDefault()?.TestId ?? "",
                parameters,
                clientSent,
                serverReceived,
                serverResponded,
                clientReceived,
                sameServerNoiseSent,
                sameServerNoiseReceived,
                decoySent,
                clientToServerLossPercent = Percent(clientSent - serverReceived, clientSent),
                serverToClientLossPercent = Percent(serverResponded - clientReceived, serverResponded),
                classification = CaseClassification(clientSent, serverReceived, serverResponded, clientReceived),
            };
        }).OrderBy(c => c.caseId).ToList();

        var report = new
        {
            runId,
            totalClientSent = useful.Count(p => p.ClientSent),
            serverReceived = useful.Count(p => p.ServerReceived),
            serverRejected = useful.Count(p => p.ServerRejected),
            serverResponded = useful.Count(p => p.ServerResponded),
            clientReceived = useful.Count(p => p.ClientReceived),
            clientToServerLossPercent = Percent(useful.Count(p => p.ClientSent && !p.ServerReceived), useful.Count(p => p.ClientSent)),
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
        return state;
    }

    private static string Classify(CompareProbeState p)
    {
        if (p.PacketRole == "DecoyNoise") return "NotApplicable_DecoyTarget";
        if (p.ServerRejected) return "ServerRejected";
        if (p.ClientSent && !p.ServerReceived) return "ClientSent_ServerDidNotReceive";
        if (p.ServerReceived && !p.ServerResponded) return "ServerReceived_ClientDidNotReceiveResponse";
        if (p.ServerResponded && !p.ClientReceived) return "ServerResponded_ClientDidNotReceive";
        if (p.ClientSent && p.ServerReceived && p.ServerResponded && p.ClientReceived) return "Success";
        return "ServerReceived_ClientDidNotReceiveResponse";
    }

    private static string CaseClassification(int clientSent, int serverReceived, int serverResponded, int clientReceived)
    {
        if (clientSent == 0) return "no-client-packets";
        if (serverReceived == 0) return "client-to-server-loss";
        if (serverResponded > 0 && clientReceived == 0) return "mostly-server-to-client-loss";
        if (clientReceived == clientSent) return "success";
        return "partial-loss";
    }

    private static double Percent(int numerator, int denominator)
        => denominator > 0 ? Math.Round(100.0 * numerator / denominator, 1) : 0;

    private static string GetString(JsonElement e, string property)
        => e.TryGetProperty(property, out JsonElement value) && value.ValueKind != JsonValueKind.Null ? value.ToString() : "";
}
