# UdpRouteProbe

Diagnostic tool for measuring UDP connectivity between a NATted client and a public server.  
Not a proxy — a lab that tells you whether a future UDP transport will work on a given network.

## What this tool measures

- Whether UDP packets reach the server and whether the server can reply
- The client's external endpoint as seen by the server
- NAT port stability across multiple packets
- Which payload sizes transit without loss (fragmentation boundary)
- Packet loss, duplicates, reordering
- Round-trip time (min / avg / max / p95)
- How long NAT keeps the UDP mapping alive when idle
- What keep-alive interval is required
- Whether the server can push packets back to the client

## Server setup

Requirements: Linux VPS with a public IP, .NET 8+ runtime (or use the self-contained binary).

```bash
# With runtime installed
dotnet run --project src/UdpRouteProbe.Server

# Or with the self-contained binary (see "Publish for Ubuntu" below)
./UdpRouteProbe.Server
```

By default, the server reads `server.json` from the executable directory.

Open the UDP port in your firewall:
```bash
ufw allow 9000/udp
```

## Client setup

```bash
# Using command-line arguments
dotnet run --project src/UdpRouteProbe.Client -- \
  --server 1.2.3.4:9000 \
  --client-id home-pc \
  --secret-key "ABC"

# Using a config file
dotnet run --project src/UdpRouteProbe.Client -- --config client.json

# Skip slow tests
dotnet run --project src/UdpRouteProbe.Client -- \
  --config client.json --skip-nat --skip-push
```

## AutoProbe for hostile UDP paths

`autoprobe` is the research mode for networks that may classify UDP by source
endpoint, destination endpoint, packet size, rate, and content. It starts with
raw random datagrams and can interleave decoy traffic before sending recognizable
probe packets.

Server:
```bash
UdpRouteProbe.Server --mode autoprobe --config server.json --ports 9000,9001,9002 --log-dir logs
```

Client:
```bash
UdpRouteProbe.Client autoprobe \
  --server 207.180.194.130 \
  --ports 9000,9001,9002 \
  --client-id home-pc \
  --secret-key "ABC" \
  --duration 01:00:00 \
  --decoy-targets 203.0.113.10,198.51.100.20 \
  --decoy-ports 443,123 \
  --output probe-results
```

Compare client and server logs after copying the server JSONL locally:
```bash
UdpRouteProbe.Client compare \
  --client-log probe-results/autoprobe-client-YYYYMMDD-HHMMSS.jsonl \
  --server-log logs/autoprobe-server-YYYYMMDD.jsonl \
  --output probe-results/autoprobe-compare.json
```

## Publish server for Ubuntu (single-file exe)

```bash
dotnet publish src/UdpRouteProbe.Server/UdpRouteProbe.Server.csproj \
  -c Release \
  -r linux-x64 \
  --self-contained true \
  /p:PublishSingleFile=true \
  /p:EnableCompressionInSingleFile=true \
  -o artifacts/linux-x64
```

Copy `artifacts/linux-x64/UdpRouteProbe.Server` to your VPS and `chmod +x` it.

## Example server config (`server.json`)

```json
{
  "ListenHost": "0.0.0.0",
  "ListenPort": 9000,
  "Clients": [
    {
      "ClientId": "home-pc",
      "SecretKey": "ABC"
    }
  ],
  "SessionTimeoutSeconds": 300,
  "LogLevel": "Information"
}
```

Generate a random key: `openssl rand -hex 32`

## Example client config (`client.json`)

```json
{
  "ServerHost": "1.2.3.4",
  "ServerPort": 9000,
  "ClientId": "home-pc",
  "SecretKey": "ABC",
  "LocalBindPort": 0,
  "OutputDirectory": "probe-results",
  "EchoPacketCount": 100,
  "EchoPayloadSize": 256,
  "EchoDelayMs": 20,
  "SizeSweepPacketsPerSize": 50,
  "ResponseTimeoutMs": 3000,
  "SkipNatTest": false,
  "SkipPushTest": false
}
```

`LocalBindPort: 0` lets the OS pick the local port.

## How to read the results

### Observed endpoint
The IP:port the server sees as your source address. If this differs from your local IP,
you are behind NAT (expected). Note whether the port is stable across packets.

### Packet size sweep
Find the largest payload size with 0% loss — that is your MTU-safe ceiling.
Typical safe values: 1200–1400 bytes on most networks.
Loss starting at 1472+ bytes usually means IP fragmentation is being dropped.

### Burst test
Shows how your NAT and network handle bursts. High loss at 5000 packets often means
a NAT or intermediate buffer is filling up.

### NAT idle timeout
The first `FAILED` entry tells you how long NAT keeps the mapping.  
Set keep-alive to ≤50% of the last OK wait time.

### Server push
Shows whether the server can initiate delivery after the client has opened the mapping.
This is required for any server-to-client notification pattern.

### Saved files
`probe-results/report-YYYYMMDD-HHMMSS.json` — full structured results  
`probe-results/report-YYYYMMDD-HHMMSS.csv`  — flat key/value rows for spreadsheet import

## Known limitations

- IPv4 only (IPv6 not implemented in this version)
- No retransmit logic — loss figures depend on a single pass
- NAT timeout test requires up to ~18 minutes of wall-clock time
- Server push test requires up to ~2 minutes
- The tool does not test TCP fallback or QUIC
- Payload sizes > 60000 bytes are rejected by the protocol (not a real constraint for UDP transport design)
- Multiple simultaneous clients are supported by the server but the client tool is single-session
