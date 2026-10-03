import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it } from 'vitest';
import { McpClient } from '../src/client.js';

const FIXTURE = fileURLToPath(new URL('./fixtures/echo-mcp-server.mjs', import.meta.url));

function stdioConfig() {
  return {
    transport: 'stdio' as const,
    command: process.execPath, // node
    args: [FIXTURE],
  };
}

const clients: McpClient[] = [];

afterEach(async () => {
  for (const c of clients.splice(0)) await c.close();
});

describe('McpClient over stdio', () => {
  it('completes the initialize handshake and reports server info', async () => {
    const client = new McpClient(stdioConfig());
    clients.push(client);
    const init = await client.connect();
    expect(init.serverInfo.name).toBe('echo-mcp');
    expect(init.serverInfo.version).toBe('0.0.1');
    expect(init.capabilities.tools).toBeDefined();
    expect(client.protocolVersion).toBeTruthy();
  });

  it('discovers tools with their JSON schemas', async () => {
    const client = new McpClient(stdioConfig());
    clients.push(client);
    await client.connect();
    const tools = await client.listTools();
    expect(tools.map((t) => t.name).sort()).toEqual(['add', 'boom', 'echo']);
    const echo = tools.find((t) => t.name === 'echo')!;
    expect(echo.inputSchema.required).toEqual(['text']);
  });

  it('calls tools and returns content', async () => {
    const client = new McpClient(stdioConfig());
    clients.push(client);
    await client.connect();
    const echoed = await client.callTool('echo', { text: 'hi a2net' });
    expect(echoed.content[0]).toEqual({ type: 'text', text: 'echo: hi a2net' });

    const sum = await client.callTool('add', { a: 19, b: 23 });
    expect((sum.content[0] as { text: string }).text).toBe('42');
  });

  it('surfaces tool-level errors without throwing', async () => {
    const client = new McpClient(stdioConfig());
    clients.push(client);
    await client.connect();
    const res = await client.callTool('boom', {});
    expect(res.isError).toBe(true);
  });

  it('throws on JSON-RPC level errors (unknown method)', async () => {
    const client = new McpClient(stdioConfig());
    clients.push(client);
    await client.connect();
    await expect(
      // @ts-expect-error 故意调用内部 request 通道验证错误传播
      client.request('nonexistent/method', {})
    ).rejects.toThrow(/METHOD_NOT_FOUND|-32601/);
  });

  it('caches the tool list via getTools', async () => {
    const client = new McpClient(stdioConfig());
    clients.push(client);
    await client.connect();
    const first = await client.getTools();
    const second = await client.getTools();
    expect(second).toBe(first); // 命中缓存，同一引用
    const refreshed = await client.getTools(true);
    expect(refreshed).not.toBe(first);
  });

  it('fails fast when the command does not exist', async () => {
    const client = new McpClient({
      transport: 'stdio',
      command: 'this-command-does-not-exist-a2net-test',
      args: [],
    });
    await expect(client.connect()).rejects.toThrow();
    await client.close();
  });
});
