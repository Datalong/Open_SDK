/**
 * bridge.ts — MCP ↔ A2Net 语义映射工具
 *
 * 职责：
 *   1. 把 MCP 工具清单映射为 A2Net 能力标签与能力说明书；
 *   2. 把 A2Net 自然语言 / 结构化查询解析为 MCP tools/call 参数；
 *   3. 把 MCP 工具返回内容（text/image/resource）规整为 A2Net 文本响应。
 */
import type { McpContent, McpTool, McpToolCallResult } from './types.js';

/** 把工具名规范化为能力标签片段（小写、点分保留、其余转连字符） */
export function slugifyToolName(name: string): string {
  return name
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 64);
}

/** MCP 工具 → A2Net 能力标签，例如 filesystem.read_file → mcp.filesystem.read-file */
export function toolToCapability(toolName: string, prefix = 'mcp'): string {
  return `${prefix}.${slugifyToolName(toolName)}`;
}

/** 汇总 MCP 工具清单为 A2Net 能力标签数组（含通用标记） */
export function toolsToCapabilities(tools: McpTool[], prefix = 'mcp'): string[] {
  const caps = new Set<string>();
  for (const t of tools) caps.add(toolToCapability(t.name, prefix));
  caps.add(`${prefix}.tools.v1`);
  caps.add('nlp.v1');
  return [...caps];
}

/** 生成供调用方阅读的工具说明书（A2Net Agent Card 的 information 字段） */
export function toolsToInformation(
  tools: McpTool[]
): { type: string; description: string }[] {
  return tools.map((t) => ({
    type: 'Information',
    description: `[MCP tool] ${t.name} — ${t.description ?? t.title ?? 'MCP tool'}`,
  }));
}

export interface ToolCallIntent {
  kind: 'call';
  tool: string;
  arguments: Record<string, unknown>;
}

export interface ToolListIntent {
  kind: 'list';
}

export interface ToolCallError {
  kind: 'error';
  message: string;
}

export type ParsedIntent = ToolCallIntent | ToolListIntent | ToolCallError;

const LIST_ALIASES = new Set([
  '__tools__',
  'tools',
  'list',
  'list tools',
  'list_tools',
  '帮助',
  'help',
  '/tools',
]);

/** 从 JSON Schema 中挑选一个“看起来像主输入”的字符串字段 */
function pickPrimaryStringField(tool: McpTool): string | null {
  const props = tool.inputSchema?.properties ?? {};
  const preferred = ['input', 'query', 'prompt', 'text', 'message', 'content', 'q'];
  for (const key of preferred) {
    const schema = props[key] as { type?: string } | undefined;
    if (schema && (schema.type === 'string' || schema.type === undefined)) return key;
  }
  for (const [key, raw] of Object.entries(props)) {
    const schema = raw as { type?: string };
    if (schema?.type === 'string') return key;
  }
  const required = tool.inputSchema?.required ?? [];
  return required[0] ?? null;
}

/**
 * 解析 A2Net 入站查询为 MCP 工具调用意图。支持三种形式：
 *   1. JSON： {"tool":"read_file","arguments":{"path":"/tmp/a"}}
 *   2. 指令： read_file {"path":"/tmp/a"}   或   read_file /tmp/a
 *   3. 自然语言：仅有单一工具时按主字段传入，否则返回可用工具清单
 */
export function parseQueryIntent(query: string, tools: McpTool[]): ParsedIntent {
  const raw = (query ?? '').trim();
  if (!raw) return { kind: 'error', message: 'Empty query' };

  if (LIST_ALIASES.has(raw.toLowerCase())) return { kind: 'list' };

  // 1. JSON 结构
  if (raw.startsWith('{')) {
    try {
      const obj = JSON.parse(raw) as Record<string, unknown>;
      const tool = (obj.tool ?? obj.name ?? obj.method) as string | undefined;
      if (typeof tool === 'string') {
        const args =
          (obj.arguments as Record<string, unknown> | undefined) ??
          (obj.args as Record<string, unknown> | undefined) ??
          {};
        return { kind: 'call', tool, arguments: args };
      }
      // 未指定工具：若只有一个工具则整体作为参数
      if (tools.length === 1) {
        return { kind: 'call', tool: tools[0]!.name, arguments: obj };
      }
      return {
        kind: 'error',
        message: `Query JSON must include a "tool" field. Available: ${tools.map((t) => t.name).join(', ')}`,
      };
    } catch {
      // 落到文本解析
    }
  }

  // 2. 指令形式： <tool> <json|text>
  const match = /^([A-Za-z0-9._/-]+)\s+([\s\S]+)$/.exec(raw);
  if (match) {
    const head = match[1]!;
    const rest = match[2] ?? '';
    const tool = tools.find((t) => t.name === head);
    if (tool) {
      const trimmed = rest.trim();
      if (trimmed.startsWith('{')) {
        try {
          return { kind: 'call', tool: tool.name, arguments: JSON.parse(trimmed) as Record<string, unknown> };
        } catch {
          /* 回落到主字段 */
        }
      }
      const field = pickPrimaryStringField(tool);
      if (field) return { kind: 'call', tool: tool.name, arguments: { [field]: trimmed } };
    }
  }

  // 3. 自然语言
  if (tools.length === 1) {
    const field = pickPrimaryStringField(tools[0]!);
    if (field) return { kind: 'call', tool: tools[0]!.name, arguments: { [field]: raw } };
    return { kind: 'call', tool: tools[0]!.name, arguments: {} };
  }

  return {
    kind: 'error',
    message:
      `无法从自然语言中确定要调用的工具。请使用以下任一形式：\n` +
      `  • {"tool":"<name>","arguments":{...}}\n` +
      `  • <name> {"arg":...}\n` +
      `  • __tools__  查看全部可用工具\n` +
      `可用工具: ${tools.map((t) => t.name).join(', ')}`,
  };
}

function contentToText(part: McpContent): string {
  switch (part.type) {
    case 'text':
      return part.text;
    case 'image':
      return `[image ${part.mimeType}, ${Math.round((part.data.length * 3) / 4 / 1024)}KB base64]`;
    case 'audio':
      return `[audio ${part.mimeType}, ${Math.round((part.data.length * 3) / 4 / 1024)}KB base64]`;
    case 'resource': {
      if (part.resource.text) return part.resource.text;
      if (part.resource.blob) return `[resource blob ${part.resource.uri}]`;
      return `[resource ${part.resource.uri}]`;
    }
    case 'resource_link':
      return `[resource link ${part.uri}]`;
    default:
      return JSON.stringify(part);
  }
}

/** 把 MCP tools/call 结果规整为可读文本 */
export function mcpResultToText(result: McpToolCallResult): string {
  const parts = (result.content ?? []).map(contentToText).filter((s) => s.length > 0);
  if (result.structuredContent) {
    parts.push(JSON.stringify(result.structuredContent, null, 2));
  }
  const body = parts.join('\n') || '(empty result)';
  return result.isError ? `[MCP tool error] ${body}` : body;
}

/** 生成工具清单的可读文本 */
export function toolsToText(tools: McpTool[]): string {
  if (tools.length === 0) return '(该 MCP 服务未暴露任何工具)';
  const lines = tools.map((t) => {
    const required = t.inputSchema?.required ?? [];
    const props = Object.keys(t.inputSchema?.properties ?? {});
    const params = props
      .map((p) => (required.includes(p) ? `${p}*` : p))
      .join(', ');
    const desc = t.description ? ` — ${t.description.split('\n')[0]}` : '';
    return `• ${t.name}(${params})${desc}`;
  });
  return `可用 MCP 工具 (${tools.length}):\n${lines.join('\n')}`;
}
