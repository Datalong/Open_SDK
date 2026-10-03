/**
 * types.ts — MCP (Model Context Protocol) 协议类型定义
 *
 * 对应规范版本：2024-11-05 / 2025-03-26 / 2025-06-18（取交集以最大化兼容）。
 * 传输层统一使用 JSON-RPC 2.0。
 */

// ---------------------------------------------------------------------------
// JSON-RPC 2.0
// ---------------------------------------------------------------------------
export interface JsonRpcRequest {
  jsonrpc: '2.0';
  id: string | number;
  method: string;
  params?: unknown;
}

export interface JsonRpcNotification {
  jsonrpc: '2.0';
  method: string;
  params?: unknown;
}

export interface JsonRpcError {
  code: number;
  message: string;
  data?: unknown;
}

export interface JsonRpcResponse {
  jsonrpc: '2.0';
  id: string | number | null;
  result?: unknown;
  error?: JsonRpcError;
}

export type JsonRpcMessage = JsonRpcRequest | JsonRpcNotification | JsonRpcResponse;

export function isJsonRpcResponse(msg: unknown): msg is JsonRpcResponse {
  return (
    typeof msg === 'object' &&
    msg !== null &&
    (msg as JsonRpcResponse).jsonrpc === '2.0' &&
    'id' in msg &&
    ('result' in msg || 'error' in msg)
  );
}

/** 标准 JSON-RPC 错误码 */
export const JSON_RPC_ERRORS = {
  PARSE_ERROR: -32700,
  INVALID_REQUEST: -32600,
  METHOD_NOT_FOUND: -32601,
  INVALID_PARAMS: -32602,
  INTERNAL_ERROR: -32603,
} as const;

// ---------------------------------------------------------------------------
// MCP 初始化
// ---------------------------------------------------------------------------
export const LATEST_PROTOCOL_VERSION = '2025-06-18';
export const SUPPORTED_PROTOCOL_VERSIONS = ['2025-06-18', '2025-03-26', '2024-11-05'];

export interface McpClientInfo {
  name: string;
  version: string;
}

export interface McpServerInfo {
  name: string;
  version: string;
  title?: string;
}

export interface McpServerCapabilities {
  tools?: { listChanged?: boolean };
  resources?: { subscribe?: boolean; listChanged?: boolean };
  prompts?: { listChanged?: boolean };
  logging?: Record<string, unknown>;
  completions?: Record<string, unknown>;
}

export interface McpInitializeResult {
  protocolVersion: string;
  capabilities: McpServerCapabilities;
  serverInfo: McpServerInfo;
  instructions?: string;
}

// ---------------------------------------------------------------------------
// Tools
// ---------------------------------------------------------------------------
export interface McpJsonSchema {
  type: 'object';
  properties?: Record<string, unknown>;
  required?: string[];
  additionalProperties?: boolean;
  [key: string]: unknown;
}

export interface McpTool {
  name: string;
  title?: string;
  description?: string;
  inputSchema: McpJsonSchema;
  outputSchema?: McpJsonSchema;
  annotations?: Record<string, unknown>;
}

export interface McpListToolsResult {
  tools: McpTool[];
  nextCursor?: string;
}

export type McpContent =
  | { type: 'text'; text: string }
  | { type: 'image'; data: string; mimeType: string }
  | { type: 'audio'; data: string; mimeType: string }
  | {
      type: 'resource';
      resource: { uri: string; mimeType?: string; text?: string; blob?: string };
    }
  | { type: 'resource_link'; uri: string; name?: string; mimeType?: string };

export interface McpToolCallResult {
  content: McpContent[];
  isError?: boolean;
  structuredContent?: unknown;
}

// ---------------------------------------------------------------------------
// Resources / Prompts（只读能力，用于能力映射）
// ---------------------------------------------------------------------------
export interface McpResource {
  uri: string;
  name: string;
  description?: string;
  mimeType?: string;
}

export interface McpListResourcesResult {
  resources: McpResource[];
  nextCursor?: string;
}

export interface McpPrompt {
  name: string;
  description?: string;
  arguments?: { name: string; description?: string; required?: boolean }[];
}

export interface McpListPromptsResult {
  prompts: McpPrompt[];
  nextCursor?: string;
}

// ---------------------------------------------------------------------------
// 传输配置
// ---------------------------------------------------------------------------
export interface McpStdioServerConfig {
  transport: 'stdio';
  command: string;
  args?: string[];
  env?: Record<string, string>;
  cwd?: string;
}

export interface McpHttpServerConfig {
  transport: 'http';
  /** Streamable HTTP 端点，例如 https://example.com/mcp */
  url: string;
  headers?: Record<string, string>;
}

export type McpServerConfig = McpStdioServerConfig | McpHttpServerConfig;
