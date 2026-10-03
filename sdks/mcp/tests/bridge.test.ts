import { describe, expect, it } from 'vitest';
import {
  mcpResultToText,
  parseQueryIntent,
  slugifyToolName,
  toolToCapability,
  toolsToCapabilities,
  toolsToInformation,
  toolsToText,
} from '../src/bridge.js';
import type { McpTool } from '../src/types.js';

const echoTool: McpTool = {
  name: 'read_file',
  description: 'Read a file from disk',
  inputSchema: {
    type: 'object',
    properties: { path: { type: 'string' } },
    required: ['path'],
  },
};

const addTool: McpTool = {
  name: 'add',
  description: 'Add two numbers',
  inputSchema: {
    type: 'object',
    properties: { a: { type: 'number' }, b: { type: 'number' } },
    required: ['a', 'b'],
  },
};

describe('MCP ↔ A2Net bridge helpers', () => {
  it('slugifies tool names into capability-safe identifiers', () => {
    expect(slugifyToolName('Read_File')).toBe('read_file');
    expect(slugifyToolName('filesystem/read file')).toBe('filesystem-read-file');
    expect(toolToCapability('read_file')).toBe('mcp.read_file');
    expect(toolToCapability('get-weather', 'weather')).toBe('weather.get-weather');
  });

  it('derives capability tags and information entries from a tool list', () => {
    const caps = toolsToCapabilities([echoTool, addTool]);
    expect(caps).toContain('mcp.read_file');
    expect(caps).toContain('mcp.add');
    expect(caps).toContain('mcp.tools.v1');

    const info = toolsToInformation([echoTool]);
    expect(info).toHaveLength(1);
    expect(info[0]!.type).toBe('Information');
    expect(info[0]!.description).toContain('read_file');
  });

  it('parses JSON tool-call intents', () => {
    const intent = parseQueryIntent('{"tool":"read_file","arguments":{"path":"/etc/hosts"}}', [echoTool]);
    expect(intent).toEqual({ kind: 'call', tool: 'read_file', arguments: { path: '/etc/hosts' } });
  });

  it('parses command-style intents (tool + JSON)', () => {
    const intent = parseQueryIntent('add {"a":2,"b":3}', [echoTool, addTool]);
    expect(intent).toEqual({ kind: 'call', tool: 'add', arguments: { a: 2, b: 3 } });
  });

  it('parses command-style intents (tool + plain arg into primary field)', () => {
    const intent = parseQueryIntent('read_file /etc/hosts', [echoTool]);
    expect(intent).toEqual({ kind: 'call', tool: 'read_file', arguments: { path: '/etc/hosts' } });
  });

  it('routes natural language to the sole tool via its primary field', () => {
    const intent = parseQueryIntent('帮我看看 /etc/hosts', [echoTool]);
    expect(intent).toEqual({ kind: 'call', tool: 'read_file', arguments: { path: '帮我看看 /etc/hosts' } });
  });

  it('returns a list intent for the __tools__ alias', () => {
    expect(parseQueryIntent('__tools__', [echoTool]).kind).toBe('list');
    expect(parseQueryIntent('list tools', [echoTool]).kind).toBe('list');
  });

  it('errors with guidance when multiple tools and no explicit target', () => {
    const intent = parseQueryIntent('随便说点什么', [echoTool, addTool]);
    expect(intent.kind).toBe('error');
    if (intent.kind === 'error') {
      expect(intent.message).toContain('read_file');
      expect(intent.message).toContain('add');
    }
  });

  it('flattens MCP content parts into text and flags errors', () => {
    const text = mcpResultToText({
      content: [
        { type: 'text', text: 'hello' },
        { type: 'resource', resource: { uri: 'file:///a', text: 'body' } },
      ],
    });
    expect(text).toBe('hello\nbody');

    const err = mcpResultToText({ content: [{ type: 'text', text: 'nope' }], isError: true });
    expect(err).toContain('[MCP tool error]');
  });

  it('renders a human-readable tool catalogue', () => {
    const rendered = toolsToText([echoTool, addTool]);
    expect(rendered).toContain('可用 MCP 工具 (2)');
    expect(rendered).toContain('read_file(path*)');
    expect(rendered).toContain('add(a*, b*)');
  });
});
