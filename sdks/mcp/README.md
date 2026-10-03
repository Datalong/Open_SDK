# @a2net/mcp — A2Net ↔ MCP Interoperability Gateway (Open Source)

Bridges the **Model Context Protocol (MCP)** and the **A2Net** decentralized agent network.

| Direction | Class | What it does |
| --- | --- | --- |
| **Ingress** | `McpIngressAdapter` | Any MCP server → A2Net agent: derives a `did:key` identity, publishes a signed Agent Card, maps MCP tools to A2Net capability tags, and serves E2EE queries from the whole network |
| **Egress** | `A2NetMcpServer` | The A2Net network → a standard MCP server: Claude Desktop / Cursor / Cline can discover and invoke any A2Net agent |

```
┌──────────────────┐   MCP (stdio/HTTP)   ┌──────────────────┐   A2Net E2EE   ┌──────────────────┐
│  MCP Server      │ ◀──────────────────▶ │ McpIngressAdapter│ ◀────────────▶ │  any A2Net node  │
│ (filesystem/...) │                      │  = A2Net Agent   │  (ciphertext   │                  │
└──────────────────┘                      └──────────────────┘   relay only)   └──────────────────┘
                                                                                      ▲
┌──────────────────┐   MCP (stdio)       ┌──────────────────┐                         │
│ Claude / Cursor  │ ◀──────────────────▶ │ A2NetMcpServer   │ ────────────────────────┘
│  (MCP Client)    │                      │  (a2net_* tools) │
└──────────────────┘                      └──────────────────┘
```

---

## Install

```bash
npm install @a2net/mcp @a2net/client ws
```

## Usage 1 — Mount an MCP server as an A2Net agent (Ingress)

```ts
import WebSocket from 'ws';
import { McpIngressAdapter } from '@a2net/mcp';

const adapter = new McpIngressAdapter({
  mcp: {
    transport: 'stdio',
    command: 'npx',
    args: ['-y', '@modelcontextprotocol/server-filesystem', '/srv/shared'],
  },
  relayUrl: 'wss://relay.example.com',
  directoryUrl: 'https://directory.example.com',
  name: 'Shared Filesystem Agent',
  encryptContent: true,
});

const state = await adapter.start();
console.log(state.address);       // did:key:z...
console.log(state.tools.length);  // mapped MCP tools
```

Any A2Net peer can now reach it with end-to-end encryption:

```ts
await client.query(state.address, JSON.stringify({ tool: 'read_file', arguments: { path: '/srv/shared/a.md' } }));
await client.query(state.address, 'read_file /srv/shared/a.md'); // command style
await client.query(state.address, '__tools__');                  // tool catalogue
```

## Usage 2 — Expose the A2Net network as MCP tools (Egress)

```ts
import { serveA2NetMcpStdio } from '@a2net/mcp';

await serveA2NetMcpStdio({
  relayUrl: 'wss://relay.example.com',
  directoryUrl: 'https://directory.example.com',
  exposeAgents: true, // optional: expose each discovered agent as its own tool
});
```

Built-in tools:

| Tool | Description |
| --- | --- |
| `a2net_identity` | Local DID and relay connection status |
| `a2net_list_agents` | Search the public directory (keyword / capability / verified-only) |
| `a2net_get_agent_card` | Fetch and verify an Agent Card by URL or DID |
| `a2net_invoke_agent` | E2EE query to a target DID |

### Claude Desktop / Cursor config

```json
{
  "mcpServers": {
    "a2net": {
      "command": "node",
      "args": ["/path/to/a2net-mcp-server.mjs"],
      "env": {
        "A2NET_RELAY_URL": "wss://relay.example.com",
        "A2NET_DIRECTORY_URL": "https://directory.example.com"
      }
    }
  }
}
```

---

## API

```ts
// Low-level MCP client (stdio / Streamable HTTP)
class McpClient {
  constructor(config: McpServerConfig, options?: McpClientOptions)
  connect(): Promise<McpInitializeResult>
  listTools(): Promise<McpTool[]>
  getTools(forceRefresh?: boolean): Promise<McpTool[]>
  callTool(name: string, args?: Record<string, unknown>): Promise<McpToolCallResult>
  onNotification(handler: (method, params) => void): void
  close(): Promise<void>
}

class McpIngressAdapter {
  constructor(config: McpIngressConfig)
  start(): Promise<McpIngressState>
  stop(): Promise<void>
  buildCard(): AgentCard
  callTool(name: string, args?): Promise<string>
}

// Transport-agnostic — embed it in any host process
class A2NetMcpServer {
  constructor(config: A2NetMcpServerConfig)
  handleMessage(msg: JsonRpcMessage): Promise<JsonRpcMessage | null>
  listTools(): Promise<McpTool[]>
  callTool(params): Promise<McpToolCallResult>
  close(): Promise<void>
}
```

---

## Design notes

- **Zero MCP changes**: any spec-compliant MCP server can be mounted as-is.
- **Capability mapping**: MCP tool `read_file` → A2Net capability `mcp.read_file`, written into a signed Agent Card and thus directory-searchable.
- **Protocol compatibility**: JSON-RPC 2.0 with `initialize` / `tools/list` / `tools/call`; interoperates across `2024-11-05`, `2025-03-26`, `2025-06-18`.
- **Dual transport**: stdio (newline-delimited JSON) and Streamable HTTP (with SSE event parsing).
- **No downgrade**: the A2Net side always uses X25519 + AES-256-GCM end-to-end encryption; the MCP side keeps its own trust model.
- **Graceful shutdown**: pending requests are flushed before the stdio server exits on stdin EOF.

## Tests

```bash
npm test --workspace=@a2net/mcp
```

Covers bridge mapping/intent parsing, real stdio MCP subprocess interop, and error paths.
