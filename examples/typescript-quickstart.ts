/**
 * A2Net TypeScript Client Quickstart Example
 * Run: npx tsx examples/typescript-quickstart.ts
 */
import WebSocket from 'ws';
import { A2NetClient } from '../sdks/typescript/src/index.js';

async function main() {
  const RELAY_URL = process.env.A2NET_RELAY_URL || 'wss://relay.a2net.network';

  // 1. 初始化服务端 Agent (Responder)
  const responder = new A2NetClient({
    relayUrl: RELAY_URL,
    encryptContent: true, // 开启端到端加密 (E2EE)
    webSocketImpl: WebSocket as unknown as typeof globalThis.WebSocket,
  });

  responder.onQuery(async (query, senderDid) => {
    console.log(`[Responder] 收到来自 ${senderDid.slice(0, 16)}... 的加密消息: "${query}"`);
    return `你好！我是自主 Agent，已收到你的提问: "${query}"。`;
  });

  await responder.connect();
  console.log(`✓ Responder Agent 已在线: ${responder.address}`);

  // 2. 初始化调用端 Agent (Caller)
  const caller = new A2NetClient({
    relayUrl: RELAY_URL,
    encryptContent: true,
    webSocketImpl: WebSocket as unknown as typeof globalThis.WebSocket,
  });

  await caller.connect();
  console.log(`✓ Caller Agent 已在线:    ${caller.address}`);

  // 3. 发送端到端加密请求
  console.log('\n[Caller] 正在向 Responder 发送加密提问...');
  const reply = await caller.query(responder.address, '智能体互联协议的核心是什么？');

  console.log(`\n[Caller] 收到解密响应: "${reply}"`);

  // 4. 清理连接
  caller.disconnect();
  responder.disconnect();
  process.exit(0);
}

main().catch(console.error);
