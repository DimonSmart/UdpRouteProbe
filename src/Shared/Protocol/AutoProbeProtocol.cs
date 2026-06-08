using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace UdpRouteProbe.Shared.Protocol;

public enum AutoProbeWireFormat
{
    LegacyUrp1,
    RandomPrefixUrp1,
    NoMagicMinimal,
    JsonText,
}

public enum AutoProbePayloadProfile
{
    Zeroes,
    Ones,
    IncrementingBytes,
    RandomFixedSeed,
    RandomCrypto,
    AsciiText,
    JsonLike,
    RepeatedPattern,
    CurrentBinaryPayload,
}

public enum AutoProbeSocketMode
{
    FreshSocket,
    ReuseSocketWithinCase,
    ReuseSocketAcrossCases,
}

public enum AutoProbeResponseMode
{
    ImmediateEcho,
    DelayedEcho100ms,
    DelayedEcho1000ms,
    SparseEcho,
    NoResponse,
}

public enum AutoProbeResponsePayloadMode
{
    SameAsRequest,
    SmallAck,
    HeaderOnlyAck,
    FixedSize,
}

public enum AutoProbeDirectionMode
{
    ClientToServerOnly,
    ClientToServerWithEcho,
    ServerPushAfterClientPacket,
}

public enum AutoProbePacketRole
{
    Handshake,
    UsefulProbe,
    SameServerNoise,
    DecoyNoise,
    RawGarbage,
}

public sealed class AutoProbeCase
{
    public string TestId { get; set; } = "";
    public string CaseId { get; set; } = "";
    public int ServerPort { get; set; }
    public string WireFormat { get; set; } = AutoProbeWireFormat.LegacyUrp1.ToString();
    public string PayloadProfile { get; set; } = AutoProbePayloadProfile.RandomFixedSeed.ToString();
    public int PayloadSize { get; set; }
    public int PacketCount { get; set; }
    public int SendIntervalMs { get; set; }
    public string SocketMode { get; set; } = AutoProbeSocketMode.FreshSocket.ToString();
    public string ResponseMode { get; set; } = AutoProbeResponseMode.ImmediateEcho.ToString();
    public string DirectionMode { get; set; } = AutoProbeDirectionMode.ClientToServerWithEcho.ToString();
    public int CaseStartDelayMs { get; set; }
    public bool NoiseEnabled { get; set; }
    public string? NoisePlacement { get; set; }
    public int NoiseSize { get; set; }
    public string? NoiseProfile { get; set; }
    public bool DecoyEnabled { get; set; }
    public int DecoyRatio { get; set; }
    public string? InterleavingPattern { get; set; }
    public int RawGarbageBeforeUsefulCount { get; set; }
    public int RawGarbageAfterUsefulCount { get; set; }
    public int RawGarbageSize { get; set; }
    public int RawGarbageIntervalMs { get; set; }
    public int PauseAfterRawGarbageMs { get; set; }
    public bool ExpectsResponse { get; set; } = true;
    public string ResponsePayloadMode { get; set; } = AutoProbeResponsePayloadMode.SameAsRequest.ToString();
    public int ResponsePayloadSize { get; set; }
    public int RespondEveryN { get; set; }
}

public sealed class AutoProbeMetadata
{
    public int SchemaVersion { get; set; } = 1;
    public string RunId { get; set; } = "";
    public string ClientId { get; set; } = "";
    public string TestId { get; set; } = "";
    public string CaseId { get; set; } = "";
    public string ProbeId { get; set; } = "";
    public long PacketId { get; set; }
    public ulong Sequence { get; set; }
    public int PayloadSize { get; set; }
    public string PayloadProfile { get; set; } = "";
    public string WireFormat { get; set; } = "";
    public string PacketRole { get; set; } = AutoProbePacketRole.UsefulProbe.ToString();
    public string ResponseMode { get; set; } = AutoProbeResponseMode.ImmediateEcho.ToString();
    public string DirectionMode { get; set; } = AutoProbeDirectionMode.ClientToServerWithEcho.ToString();
    public long SendUnixMs { get; set; }
    public string ResponsePayloadMode { get; set; } = AutoProbeResponsePayloadMode.SameAsRequest.ToString();
    public int ResponsePayloadSize { get; set; }
    public int RespondEveryN { get; set; }
}

public sealed class AutoProbeDecodedPacket
{
    public required AutoProbeMetadata Metadata { get; init; }
    public required UdpRouteProbePacket Packet { get; init; }
    public required byte[] Datagram { get; init; }
    public required byte[] Payload { get; init; }
    public required string WireFormat { get; init; }
}

public static class AutoProbeProtocol
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    private static readonly byte[] NoMagicMarker = [(byte)'A', (byte)'P', 1];

    public static byte[] BuildDatagram(
        AutoProbeMetadata metadata,
        byte[] payload,
        ulong clientIdHash,
        ulong sessionId,
        UdpRouteProbeMessageType messageType,
        byte[] secretKey)
    {
        metadata.PayloadSize = payload.Length;
        metadata.SendUnixMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        var packet = new UdpRouteProbePacket
        {
            MessageType = messageType,
            ClientIdHash = clientIdHash,
            SessionId = sessionId,
            Sequence = metadata.Sequence,
            TimestampMs = HmacHelper.NowMs(),
            Payload = PackPayload(metadata, payload),
        };

        return metadata.WireFormat switch
        {
            nameof(AutoProbeWireFormat.RandomPrefixUrp1) => BuildRandomPrefix(packet, secretKey, metadata.Sequence),
            nameof(AutoProbeWireFormat.NoMagicMinimal) => BuildNoMagic(metadata, payload, clientIdHash, sessionId, messageType, secretKey),
            nameof(AutoProbeWireFormat.JsonText) => BuildJsonText(metadata, payload, clientIdHash, sessionId, messageType, secretKey),
            _ => UdpRouteProbePacketCodec.Encode(packet, secretKey),
        };
    }

    public static bool TryDecode(
        ReadOnlySpan<byte> datagram,
        byte[] secretKey,
        out AutoProbeDecodedPacket? decoded,
        out string rejectReason)
    {
        decoded = null;
        rejectReason = "";

        if (datagram.Length == 0)
        {
            rejectReason = "TooSmall";
            return false;
        }

        if (UdpRouteProbePacketCodec.TryDecode(datagram, secretKey, out UdpRouteProbePacket? legacy) && legacy is not null)
            return TryUnpackLegacy(legacy, datagram.ToArray(), nameof(AutoProbeWireFormat.LegacyUrp1), out decoded, out rejectReason);

        if (TryDecodeRandomPrefix(datagram, secretKey, out decoded, out rejectReason))
            return true;

        if (TryDecodeNoMagic(datagram, secretKey, out decoded, out rejectReason))
            return true;

        if (TryDecodeJsonText(datagram, secretKey, out decoded, out rejectReason))
            return true;

        if (rejectReason.Length == 0)
            rejectReason = "UnknownWireFormat";
        return false;
    }

    public static bool TryPeekClientIdHash(ReadOnlySpan<byte> datagram, out ulong clientIdHash)
    {
        if (UdpRouteProbePacketCodec.TryPeekClientIdHash(datagram, out clientIdHash))
            return true;

        if (TryPeekRandomPrefixClientIdHash(datagram, out clientIdHash))
            return true;

        if (datagram.Length >= 29 && datagram[0] == NoMagicMarker[0] && datagram[1] == NoMagicMarker[1] && datagram[2] == NoMagicMarker[2])
        {
            clientIdHash = BinaryPrimitives.ReadUInt64BigEndian(datagram[5..13]);
            return true;
        }

        try
        {
            using JsonDocument doc = JsonDocument.Parse(datagram.ToArray());
            if (doc.RootElement.TryGetProperty("clientIdHash", out JsonElement e))
            {
                clientIdHash = Convert.ToUInt64(e.GetString(), 16);
                return true;
            }
        }
        catch
        {
        }

        clientIdHash = 0;
        return false;
    }

    public static byte[] CreatePayload(AutoProbePayloadProfile profile, int size, string seed)
    {
        byte[] payload = new byte[Math.Max(0, size)];
        switch (profile)
        {
            case AutoProbePayloadProfile.Zeroes:
                break;
            case AutoProbePayloadProfile.Ones:
                Array.Fill(payload, (byte)0xFF);
                break;
            case AutoProbePayloadProfile.IncrementingBytes:
                for (int i = 0; i < payload.Length; i++) payload[i] = (byte)i;
                break;
            case AutoProbePayloadProfile.RandomCrypto:
                RandomNumberGenerator.Fill(payload);
                break;
            case AutoProbePayloadProfile.AsciiText:
                FillRepeated(payload, Encoding.ASCII.GetBytes("udp route probe ascii text "));
                break;
            case AutoProbePayloadProfile.JsonLike:
                FillRepeated(payload, Encoding.ASCII.GetBytes("{\"message\":\"udp-probe\",\"value\":42}"));
                break;
            case AutoProbePayloadProfile.RepeatedPattern:
                FillRepeated(payload, Encoding.ASCII.GetBytes("ABCD"));
                break;
            case AutoProbePayloadProfile.CurrentBinaryPayload:
                FillRepeated(payload, [0x55, 0x52, 0x50, 0x31, 0x01, 0x05, 0x00, 0x00]);
                break;
            default:
                var random = new Random(seed.GetHashCode(StringComparison.Ordinal));
                random.NextBytes(payload);
                break;
        }
        return payload;
    }

    public static string PacketHash64(ReadOnlySpan<byte> datagram)
        => Convert.ToHexString(SHA256.HashData(datagram.ToArray()).AsSpan(0, 8)).ToLowerInvariant();

    public static string First16Hex(ReadOnlySpan<byte> datagram)
        => Convert.ToHexString(datagram[..Math.Min(16, datagram.Length)]).ToLowerInvariant();

    public static object ToLogParameters(AutoProbeCase testCase) => new
    {
        testCase.ServerPort,
        testCase.WireFormat,
        testCase.PayloadProfile,
        testCase.PayloadSize,
        testCase.PacketCount,
        testCase.SendIntervalMs,
        testCase.SocketMode,
        testCase.ResponseMode,
        testCase.DirectionMode,
        testCase.CaseStartDelayMs,
        testCase.NoiseEnabled,
        testCase.NoisePlacement,
        testCase.NoiseSize,
        testCase.NoiseProfile,
        testCase.DecoyEnabled,
        testCase.DecoyRatio,
        testCase.InterleavingPattern,
        testCase.RawGarbageBeforeUsefulCount,
        testCase.RawGarbageAfterUsefulCount,
        testCase.RawGarbageSize,
        testCase.RawGarbageIntervalMs,
        testCase.PauseAfterRawGarbageMs,
        testCase.ExpectsResponse,
        testCase.ResponsePayloadMode,
        testCase.ResponsePayloadSize,
        testCase.RespondEveryN,
    };

    private static byte[] PackPayload(AutoProbeMetadata metadata, byte[] payload)
    {
        byte[] meta = JsonSerializer.SerializeToUtf8Bytes(metadata, JsonOptions);
        byte[] packed = new byte[2 + meta.Length + payload.Length];
        BinaryPrimitives.WriteUInt16BigEndian(packed, (ushort)meta.Length);
        meta.CopyTo(packed.AsSpan(2));
        payload.CopyTo(packed.AsSpan(2 + meta.Length));
        return packed;
    }

    private static bool TryUnpackPayload(ReadOnlySpan<byte> packed, out AutoProbeMetadata? metadata, out byte[] payload)
    {
        metadata = null;
        payload = [];
        if (packed.Length < 2) return false;
        int metaLength = BinaryPrimitives.ReadUInt16BigEndian(packed[..2]);
        if (packed.Length < 2 + metaLength) return false;
        metadata = JsonSerializer.Deserialize<AutoProbeMetadata>(packed.Slice(2, metaLength), JsonOptions);
        payload = packed[(2 + metaLength)..].ToArray();
        return metadata is not null;
    }

    private static byte[] BuildRandomPrefix(UdpRouteProbePacket packet, byte[] secretKey, ulong sequence)
    {
        int prefixLength = (int)((sequence % 4UL) switch { 0 => 8UL, 1 => 16UL, 2 => 32UL, _ => 64UL });
        byte[] legacy = UdpRouteProbePacketCodec.Encode(packet, secretKey);
        ReadOnlySpan<byte> legacyWithoutHmac = legacy.AsSpan(0, legacy.Length - UdpRouteProbePacketCodec.HmacSize);
        byte[] datagram = new byte[1 + prefixLength + legacy.Length];
        datagram[0] = (byte)prefixLength;
        RandomNumberGenerator.Fill(datagram.AsSpan(1, prefixLength));
        legacyWithoutHmac.CopyTo(datagram.AsSpan(1 + prefixLength));
        byte[] hmac = new HMACSHA256(secretKey).ComputeHash(datagram.AsSpan(0, datagram.Length - UdpRouteProbePacketCodec.HmacSize).ToArray());
        hmac.CopyTo(datagram.AsSpan(datagram.Length - UdpRouteProbePacketCodec.HmacSize));
        return datagram;
    }

    private static bool TryDecodeRandomPrefix(ReadOnlySpan<byte> datagram, byte[] secretKey, out AutoProbeDecodedPacket? decoded, out string rejectReason)
    {
        decoded = null;
        rejectReason = "";
        if (datagram.Length == 0)
        {
            rejectReason = "InvalidPrefixLength";
            return false;
        }

        int prefixLength = datagram[0];
        if (prefixLength is not (8 or 16 or 32 or 64))
        {
            rejectReason = prefixLength > 64 ? "PrefixTooLarge" : "InvalidPrefixLength";
            return false;
        }
        if (datagram.Length <= 1 + prefixLength)
        {
            rejectReason = "MissingLegacyPayloadAfterPrefix";
            return false;
        }

        ReadOnlySpan<byte> inner = datagram[(1 + prefixLength)..];
        if (!LooksLikeLegacy(inner))
        {
            rejectReason = "InvalidInnerMagic";
            return false;
        }
        if (inner.Length < UdpRouteProbePacketCodec.MinSize)
        {
            rejectReason = "MissingLegacyPayloadAfterPrefix";
            return false;
        }

        int payloadLength = BigEndianBinary.ReadUInt16(inner, 40);
        if (inner.Length != UdpRouteProbePacketCodec.HeaderSize + payloadLength + UdpRouteProbePacketCodec.HmacSize)
        {
            rejectReason = "MissingLegacyPayloadAfterPrefix";
            return false;
        }

        byte[] expected = new HMACSHA256(secretKey).ComputeHash(datagram[..^UdpRouteProbePacketCodec.HmacSize].ToArray());
        if (!CryptographicOperations.FixedTimeEquals(expected, datagram[^UdpRouteProbePacketCodec.HmacSize..]))
        {
            rejectReason = "InvalidHmac";
            return false;
        }

        var packet = new UdpRouteProbePacket
        {
            MessageType = (UdpRouteProbeMessageType)inner[5],
            Flags = BigEndianBinary.ReadUInt16(inner, 6),
            ClientIdHash = BigEndianBinary.ReadUInt64(inner, 8),
            SessionId = BigEndianBinary.ReadUInt64(inner, 16),
            Sequence = BigEndianBinary.ReadUInt64(inner, 24),
            TimestampMs = BigEndianBinary.ReadUInt64(inner, 32),
            Payload = payloadLength > 0
                ? inner.Slice(UdpRouteProbePacketCodec.HeaderSize, payloadLength).ToArray()
                : [],
        };
        return TryUnpackLegacy(packet, datagram.ToArray(), nameof(AutoProbeWireFormat.RandomPrefixUrp1), out decoded, out rejectReason);
    }

    private static bool TryPeekRandomPrefixClientIdHash(ReadOnlySpan<byte> datagram, out ulong clientIdHash)
    {
        clientIdHash = 0;
        if (datagram.Length == 0) return false;
        int prefixLength = datagram[0];
        if (prefixLength is not (8 or 16 or 32 or 64)) return false;
        ReadOnlySpan<byte> inner = datagram[(1 + prefixLength)..];
        if (!LooksLikeLegacy(inner) || inner.Length < UdpRouteProbePacketCodec.MinSize) return false;
        clientIdHash = BigEndianBinary.ReadUInt64(inner, 8);
        return true;
    }

    private static bool LooksLikeLegacy(ReadOnlySpan<byte> data)
        => data.Length >= 5 &&
           data[0] == (byte)'U' &&
           data[1] == (byte)'R' &&
           data[2] == (byte)'P' &&
           data[3] == (byte)'1' &&
           data[4] == 1;

    private static bool TryUnpackLegacy(UdpRouteProbePacket packet, byte[] datagram, string wireFormat, out AutoProbeDecodedPacket? decoded, out string rejectReason)
    {
        decoded = null;
        rejectReason = "";
        if (!TryUnpackPayload(packet.Payload, out AutoProbeMetadata? metadata, out byte[] payload) || metadata is null)
        {
            rejectReason = "MalformedPacket";
            return false;
        }

        metadata.WireFormat = wireFormat;
        decoded = new AutoProbeDecodedPacket
        {
            Metadata = metadata,
            Packet = packet,
            Datagram = datagram,
            Payload = payload,
            WireFormat = wireFormat,
        };
        return true;
    }

    private static byte[] BuildNoMagic(AutoProbeMetadata metadata, byte[] payload, ulong clientIdHash, ulong sessionId, UdpRouteProbeMessageType messageType, byte[] secretKey)
    {
        byte[] packed = PackPayload(metadata, payload);
        byte[] body = new byte[3 + 1 + 1 + 8 + 8 + 8 + 8 + 2 + packed.Length];
        NoMagicMarker.CopyTo(body, 0);
        body[3] = (byte)messageType;
        body[4] = 0;
        BinaryPrimitives.WriteUInt64BigEndian(body.AsSpan(5), clientIdHash);
        BinaryPrimitives.WriteUInt64BigEndian(body.AsSpan(13), sessionId);
        BinaryPrimitives.WriteUInt64BigEndian(body.AsSpan(21), metadata.Sequence);
        BinaryPrimitives.WriteUInt64BigEndian(body.AsSpan(29), HmacHelper.NowMs());
        BinaryPrimitives.WriteUInt16BigEndian(body.AsSpan(37), (ushort)packed.Length);
        packed.CopyTo(body.AsSpan(39));

        byte[] hmac = new HMACSHA256(secretKey).ComputeHash(body);
        return [.. body, .. hmac];
    }

    private static bool TryDecodeNoMagic(ReadOnlySpan<byte> datagram, byte[] secretKey, out AutoProbeDecodedPacket? decoded, out string rejectReason)
    {
        decoded = null;
        rejectReason = "";
        if (datagram.Length < 3 || datagram[0] != NoMagicMarker[0] || datagram[1] != NoMagicMarker[1] || datagram[2] != NoMagicMarker[2])
            return false;
        if (datagram.Length < 39 + UdpRouteProbePacketCodec.HmacSize)
        {
            rejectReason = "TooSmall";
            return false;
        }

        int payloadLength = BinaryPrimitives.ReadUInt16BigEndian(datagram[37..39]);
        if (datagram.Length != 39 + payloadLength + UdpRouteProbePacketCodec.HmacSize)
        {
            rejectReason = "MalformedPacket";
            return false;
        }

        byte[] expected = new HMACSHA256(secretKey).ComputeHash(datagram[..(39 + payloadLength)].ToArray());
        if (!CryptographicOperations.FixedTimeEquals(expected, datagram.Slice(39 + payloadLength, UdpRouteProbePacketCodec.HmacSize)))
        {
            rejectReason = "InvalidHmac";
            return false;
        }

        if (!TryUnpackPayload(datagram.Slice(39, payloadLength), out AutoProbeMetadata? metadata, out byte[] payload) || metadata is null)
        {
            rejectReason = "MalformedPacket";
            return false;
        }

        var packet = new UdpRouteProbePacket
        {
            MessageType = (UdpRouteProbeMessageType)datagram[3],
            ClientIdHash = BinaryPrimitives.ReadUInt64BigEndian(datagram[5..13]),
            SessionId = BinaryPrimitives.ReadUInt64BigEndian(datagram[13..21]),
            Sequence = BinaryPrimitives.ReadUInt64BigEndian(datagram[21..29]),
            TimestampMs = BinaryPrimitives.ReadUInt64BigEndian(datagram[29..37]),
            Payload = datagram.Slice(39, payloadLength).ToArray(),
        };

        metadata.WireFormat = nameof(AutoProbeWireFormat.NoMagicMinimal);
        decoded = new AutoProbeDecodedPacket
        {
            Metadata = metadata,
            Packet = packet,
            Datagram = datagram.ToArray(),
            Payload = payload,
            WireFormat = nameof(AutoProbeWireFormat.NoMagicMinimal),
        };
        return true;
    }

    private static byte[] BuildJsonText(AutoProbeMetadata metadata, byte[] payload, ulong clientIdHash, ulong sessionId, UdpRouteProbeMessageType messageType, byte[] secretKey)
    {
        byte[] canonical = BuildJsonCanonical(metadata, payload, clientIdHash, sessionId, messageType, includeHmac: false, hmacBase64: null);
        string hmac = Convert.ToBase64String(new HMACSHA256(secretKey).ComputeHash(canonical));
        return BuildJsonCanonical(metadata, payload, clientIdHash, sessionId, messageType, includeHmac: true, hmacBase64: hmac);
    }

    private static bool TryDecodeJsonText(ReadOnlySpan<byte> datagram, byte[] secretKey, out AutoProbeDecodedPacket? decoded, out string rejectReason)
    {
        decoded = null;
        rejectReason = "";
        if (datagram[0] != (byte)'{') return false;
        try
        {
            using JsonDocument doc = JsonDocument.Parse(datagram.ToArray());
            JsonElement root = doc.RootElement;
            int version = RequiredInt(root, "v");
            if (version != 1)
            {
                rejectReason = "UnsupportedJsonVersion";
                return false;
            }

            string hmac = RequiredString(root, "hmac");
            ulong clientIdHash = Convert.ToUInt64(RequiredString(root, "clientIdHash"), 16);
            ulong sessionId = RequiredUInt64(root, "sessionId");
            string type = RequiredString(root, "t");
            byte[] payload = Convert.FromBase64String(RequiredString(root, "payloadBase64"));
            var metadata = new AutoProbeMetadata
            {
                SchemaVersion = version,
                RunId = RequiredString(root, "runId"),
                ClientId = root.TryGetProperty("clientId", out JsonElement clientIdElement) ? clientIdElement.GetString() ?? "" : "",
                TestId = RequiredString(root, "testId"),
                CaseId = RequiredString(root, "caseId"),
                ProbeId = RequiredString(root, "probeId"),
                PacketId = RequiredInt64(root, "packetId"),
                Sequence = RequiredUInt64(root, "sequence"),
                PayloadProfile = RequiredString(root, "payloadProfile"),
                PayloadSize = RequiredInt(root, "payloadSize"),
                WireFormat = nameof(AutoProbeWireFormat.JsonText),
                PacketRole = root.TryGetProperty("packetRole", out JsonElement roleElement) ? roleElement.GetString() ?? AutoProbePacketRole.UsefulProbe.ToString() : AutoProbePacketRole.UsefulProbe.ToString(),
                ResponseMode = RequiredString(root, "responseMode"),
                DirectionMode = RequiredString(root, "directionMode"),
                SendUnixMs = root.TryGetProperty("sendUnixMs", out JsonElement sendElement) ? sendElement.GetInt64() : 0,
                ResponsePayloadMode = root.TryGetProperty("responsePayloadMode", out JsonElement responsePayloadModeElement) ? responsePayloadModeElement.GetString() ?? AutoProbeResponsePayloadMode.SameAsRequest.ToString() : AutoProbeResponsePayloadMode.SameAsRequest.ToString(),
                ResponsePayloadSize = root.TryGetProperty("responsePayloadSize", out JsonElement responsePayloadSizeElement) ? responsePayloadSizeElement.GetInt32() : 0,
                RespondEveryN = root.TryGetProperty("respondEveryN", out JsonElement respondEveryNElement) ? respondEveryNElement.GetInt32() : 0,
            };
            byte[] canonical = BuildJsonCanonical(metadata, payload, clientIdHash, sessionId, Enum.Parse<UdpRouteProbeMessageType>(type), includeHmac: false, hmacBase64: null);
            byte[] expected = new HMACSHA256(secretKey).ComputeHash(canonical);
            if (!CryptographicOperations.FixedTimeEquals(expected, Convert.FromBase64String(hmac)))
            {
                rejectReason = "InvalidJsonHmac";
                return false;
            }

            var packet = new UdpRouteProbePacket
            {
                MessageType = Enum.Parse<UdpRouteProbeMessageType>(type),
                ClientIdHash = clientIdHash,
                SessionId = sessionId,
                Sequence = metadata.Sequence,
                TimestampMs = HmacHelper.NowMs(),
                Payload = PackPayload(metadata, payload),
            };

            metadata.WireFormat = nameof(AutoProbeWireFormat.JsonText);
            decoded = new AutoProbeDecodedPacket
            {
                Metadata = metadata,
                Packet = packet,
                Datagram = datagram.ToArray(),
                Payload = payload,
                WireFormat = nameof(AutoProbeWireFormat.JsonText),
            };
            return true;
        }
        catch (JsonException)
        {
            rejectReason = "InvalidJson";
            return false;
        }
        catch (KeyNotFoundException)
        {
            rejectReason = "MissingJsonField";
            return false;
        }
        catch (FormatException)
        {
            rejectReason = "MissingJsonField";
            return false;
        }
        catch
        {
            rejectReason = "InvalidJson";
            return false;
        }
    }

    private static byte[] BuildJsonCanonical(AutoProbeMetadata metadata, byte[] payload, ulong clientIdHash, ulong sessionId, UdpRouteProbeMessageType messageType, bool includeHmac, string? hmacBase64)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = false }))
        {
            writer.WriteStartObject();
            writer.WriteNumber("v", 1);
            writer.WriteString("t", messageType.ToString());
            writer.WriteString("clientIdHash", clientIdHash.ToString("x16"));
            writer.WriteNumber("sessionId", sessionId);
            writer.WriteString("runId", metadata.RunId);
            writer.WriteString("clientId", metadata.ClientId);
            writer.WriteString("testId", metadata.TestId);
            writer.WriteString("caseId", metadata.CaseId);
            writer.WriteString("probeId", metadata.ProbeId);
            writer.WriteNumber("packetId", metadata.PacketId);
            writer.WriteNumber("sequence", metadata.Sequence);
            writer.WriteString("payloadProfile", metadata.PayloadProfile);
            writer.WriteNumber("payloadSize", payload.Length);
            writer.WriteString("payloadBase64", Convert.ToBase64String(payload));
            writer.WriteString("packetRole", metadata.PacketRole);
            writer.WriteString("responseMode", metadata.ResponseMode);
            writer.WriteString("directionMode", metadata.DirectionMode);
            writer.WriteNumber("sendUnixMs", metadata.SendUnixMs);
            writer.WriteString("responsePayloadMode", metadata.ResponsePayloadMode);
            writer.WriteNumber("responsePayloadSize", metadata.ResponsePayloadSize);
            writer.WriteNumber("respondEveryN", metadata.RespondEveryN);
            if (includeHmac) writer.WriteString("hmac", hmacBase64);
            writer.WriteEndObject();
        }
        return stream.ToArray();
    }

    private static string RequiredString(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out JsonElement element) || element.ValueKind == JsonValueKind.Null)
            throw new KeyNotFoundException(name);
        return element.GetString() ?? "";
    }

    private static int RequiredInt(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out JsonElement element))
            throw new KeyNotFoundException(name);
        return element.GetInt32();
    }

    private static long RequiredInt64(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out JsonElement element))
            throw new KeyNotFoundException(name);
        return element.GetInt64();
    }

    private static ulong RequiredUInt64(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out JsonElement element))
            throw new KeyNotFoundException(name);
        return element.GetUInt64();
    }

    private static void FillRepeated(byte[] target, byte[] pattern)
    {
        if (pattern.Length == 0) return;
        for (int i = 0; i < target.Length; i++)
            target[i] = pattern[i % pattern.Length];
    }
}
