/**
 * presets.ts — 常用 MCP Server 预设（一条命令即可挂载入网）
 *
 * 这些是社区广泛使用的官方/参考 MCP Server。命令与参数遵循各自仓库文档，
 * 通过 `npx -y` 按需拉取，无需预先安装。
 */
import type { McpServerConfig } from './types.js';

export interface McpServerPreset {
  /** 预设键名 */
  key: string;
  /** 展示名 */
  label: string;
  /** 说明 */
  description: string;
  /** 生成 MCP Server 配置 */
  build: (options: { target?: string; args?: string[]; env?: Record<string, string> }) => McpServerConfig;
  /** 是否需要 --target 参数（如目录路径 / 数据库连接串） */
  requiresTarget?: boolean;
  /** target 参数说明 */
  targetHint?: string;
}

export const MCP_SERVER_PRESETS: Record<string, McpServerPreset> = {
  filesystem: {
    key: 'filesystem',
    label: 'Filesystem（本地文件系统）',
    description: '让 A2Net 全网通过 E2EE 查询受控目录下的文件内容',
    requiresTarget: true,
    targetHint: '允许访问的绝对目录，例如 /tmp 或 /Users/me/notes',
    build: ({ target, args }) => ({
      transport: 'stdio',
      command: 'npx',
      args: ['-y', '@modelcontextprotocol/server-filesystem', target ?? '.', ...(args ?? [])],
    }),
  },
  fetch: {
    key: 'fetch',
    label: 'Fetch（网页抓取）',
    description: '把网页抓取与正文提取能力挂载为 A2Net Agent',
    build: ({ args }) => ({
      transport: 'stdio',
      command: 'npx',
      args: ['-y', '@modelcontextprotocol/server-fetch', ...(args ?? [])],
    }),
  },
  memory: {
    key: 'memory',
    label: 'Memory（知识图谱记忆）',
    description: '基于知识图谱的持久化记忆服务',
    build: ({ args }) => ({
      transport: 'stdio',
      command: 'npx',
      args: ['-y', '@modelcontextprotocol/server-memory', ...(args ?? [])],
    }),
  },
  'sequential-thinking': {
    key: 'sequential-thinking',
    label: 'Sequential Thinking（分步推理）',
    description: '结构化多步推理与反思工具',
    build: ({ args }) => ({
      transport: 'stdio',
      command: 'npx',
      args: ['-y', '@modelcontextprotocol/server-sequential-thinking', ...(args ?? [])],
    }),
  },
  github: {
    key: 'github',
    label: 'GitHub（仓库与 PR 操作）',
    description: '代码仓库、Issue 与 PR 操作（需 GITHUB_PERSONAL_ACCESS_TOKEN）',
    build: ({ args, env }) => ({
      transport: 'stdio',
      command: 'npx',
      args: ['-y', '@modelcontextprotocol/server-github', ...(args ?? [])],
      env: { ...env },
    }),
  },
  sqlite: {
    key: 'sqlite',
    label: 'SQLite（只读数据库查询）',
    description: '对本地 SQLite 数据库执行查询',
    requiresTarget: true,
    targetHint: 'SQLite 数据库文件绝对路径',
    build: ({ target, args }) => ({
      transport: 'stdio',
      command: 'npx',
      args: ['-y', '@modelcontextprotocol/server-sqlite', target ?? 'db.sqlite', ...(args ?? [])],
    }),
  },
  custom: {
    key: 'custom',
    label: 'Custom（自定义命令）',
    description: '任意 MCP Server 启动命令（stdio）',
    requiresTarget: true,
    targetHint: '可执行命令，例如 python3 /opt/my-mcp/server.py',
    build: ({ target, args, env }) => {
      const parts = (target ?? '').split(/\s+/).filter(Boolean);
      const [command, ...inlineArgs] = parts;
      return {
        transport: 'stdio',
        command: command ?? 'node',
        args: [...inlineArgs, ...(args ?? [])],
        env: { ...env },
      };
    },
  },
};

export const MCP_PRESET_KEYS = Object.keys(MCP_SERVER_PRESETS);
