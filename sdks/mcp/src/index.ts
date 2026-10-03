/**
 * @a2net/mcp — A2Net ↔ MCP 双向互操作网关
 *
 * * 入口（Ingress）：任意 MCP Server → A2Net Agent（McpIngressAdapter）
 * * 出口（Egress） ：A2Net 全网 → 标准 MCP Server（A2NetMcpServer）
 */
export * from './types.js';
export { McpClient, type McpClientOptions } from './client.js';
export {
  StdioTransport,
  HttpTransport,
  type McpTransport,
  type McpTransportHandlers,
  type StdioTransportOptions,
  type HttpTransportOptions,
} from './transport.js';
export {
  McpIngressAdapter,
  type McpIngressConfig,
  type McpIngressState,
} from './ingress.js';
export {
  A2NetMcpServer,
  serveA2NetMcpStdio,
  A2NET_MCP_TOOLS,
  mcpText,
  mcpErrorText,
  type A2NetMcpServerConfig,
} from './egress.js';
export {
  slugifyToolName,
  toolToCapability,
  toolsToCapabilities,
  toolsToInformation,
  toolsToText,
  parseQueryIntent,
  mcpResultToText,
  type ParsedIntent,
} from './bridge.js';
export { MCP_SERVER_PRESETS, type McpServerPreset } from './presets.js';
