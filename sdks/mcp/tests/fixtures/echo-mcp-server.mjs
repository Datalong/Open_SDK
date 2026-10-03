#!/usr/bin/env node
/**
 * echo-mcp-server.mjs — 测试用最小 MCP Server（stdio，换行分隔 JSON-RPC 2.0）
 *
 * 暴露工具：
 *   echo  { text: string }            → 回显 "echo: <text>"
 *   add   { a: number, b: number }    → 返回两数之和
 *   boom  {}                          → 故意抛错（验证 isError 通道）
 */
import readline from 'node:readline';

const TOOLS = [
  {
    name: 'echo',
    description: 'Echo back the provided text',
    inputSchema: {
      type: 'object',
      properties: { text: { type: 'string', description: 'Text to echo' } },
      required: ['text'],
    },
  },
  {
    name: 'add',
    description: 'Add two numbers',
    inputSchema: {
      type: 'object',
      properties: { a: { type: 'number' }, b: { type: 'number' } },
      required: ['a', 'b'],
    },
  },
  {
    name: 'boom',
    description: 'Always fails, for error-path testing',
    inputSchema: { type: 'object', properties: {}, required: [] },
  },
];

const write = (msg) => process.stdout.write(JSON.stringify(msg) + '\n');

const rl = readline.createInterface({ input: process.stdin, terminal: false });

rl.on('line', (line) => {
  const raw = line.trim();
  if (!raw) return;
  let req;
  try {
    req = JSON.parse(raw);
  } catch {
    write({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
    return;
  }
  // 通知无需响应
  if (req.id === undefined) return;

  switch (req.method) {
    case 'initialize':
      write({
        jsonrpc: '2.0',
        id: req.id,
        result: {
          protocolVersion: req.params?.protocolVersion ?? '2025-06-18',
          capabilities: { tools: { listChanged: false } },
          serverInfo: { name: 'echo-mcp', version: '0.0.1' },
          instructions: 'Test MCP server for A2Net bridge.',
        },
      });
      return;

    case 'ping':
      write({ jsonrpc: '2.0', id: req.id, result: {} });
      return;

    case 'tools/list':
      write({ jsonrpc: '2.0', id: req.id, result: { tools: TOOLS } });
      return;

    case 'tools/call': {
      const { name, arguments: args = {} } = req.params ?? {};
      if (name === 'echo') {
        write({
          jsonrpc: '2.0',
          id: req.id,
          result: { content: [{ type: 'text', text: `echo: ${args.text ?? ''}` }] },
        });
        return;
      }
      if (name === 'add') {
        const sum = Number(args.a) + Number(args.b);
        write({
          jsonrpc: '2.0',
          id: req.id,
          result: { content: [{ type: 'text', text: String(sum) }] },
        });
        return;
      }
      if (name === 'boom') {
        write({
          jsonrpc: '2.0',
          id: req.id,
          result: { content: [{ type: 'text', text: 'intentional failure' }], isError: true },
        });
        return;
      }
      write({
        jsonrpc: '2.0',
        id: req.id,
        result: {
          content: [{ type: 'text', text: `Unknown tool: ${name}` }],
          isError: true,
        },
      });
      return;
    }

    default:
      write({
        jsonrpc: '2.0',
        id: req.id,
        error: { code: -32601, message: `Method not found: ${req.method}` },
      });
  }
});
