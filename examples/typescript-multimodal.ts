/**
 * A2Net TypeScript Multimodal Blob Streaming Example
 *
 * 演示通过端到端加密分块管道传输大文件（图片 / 音频 / PDF）：
 *   1. 生成内存中的二进制数据（真实场景可来自文件或模型输出）
 *   2. 以 64KB 分片 + E2EE 加密发送，并实时追踪进度
 *   3. 接收端自动组装、SHA-256 校验并回调
 *
 * Run: npx tsx examples/typescript-multimodal.ts
 * 需先启动中继: npm run dev --workspace=@a2net/relay
 */
import WebSocket from 'ws';
import { A2NetClient, type CompletedBlob } from '../sdks/typescript/src/index.js';

async function main() {
  const RELAY_URL = process.env.A2NET_RELAY_URL || 'ws://127.0.0.1:8080';

  // 1. 接收方：注册 onBlob 回调
  let received: CompletedBlob | null = null;
  const receiver = new A2NetClient({
    relayUrl: RELAY_URL,
    encryptContent: true,
    webSocketImpl: WebSocket as unknown as typeof globalThis.WebSocket,
  });
  receiver.onBlob(async (blob, senderDid) => {
    console.log(`[Receiver] 收到来自 ${senderDid.slice(0, 16)}… 的文件:`);
    console.log(`  名称   : ${blob.metadata.name}`);
    console.log(`  MIME   : ${blob.metadata.mimeType}`);
    console.log(`  大小   : ${(blob.metadata.size / 1024).toFixed(1)} KB`);
    console.log(`  分片数 : ${blob.metadata.totalChunks}`);
    console.log(`  SHA-256: ${blob.metadata.sha256.slice(0, 24)}…`);
    received = blob;
  });
  await receiver.connect();
  console.log(`✓ Receiver 已在线: ${receiver.address}`);

  // 2. 发送方
  const sender = new A2NetClient({
    relayUrl: RELAY_URL,
    encryptContent: true,
    webSocketImpl: WebSocket as unknown as typeof globalThis.WebSocket,
  });
  await sender.connect();
  console.log(`✓ Sender 已在线:   ${sender.address}`);

  // 3. 构造 256KB 二进制数据（模拟图片）
  const data = new Uint8Array(256 * 1024);
  for (let i = 0; i < data.length; i++) data[i] = (i * 31 + 7) & 0xff;

  console.log('\n[Sender] 开始端到端加密分块传输…');
  const meta = await sender.sendBlob(receiver.address, data, {
    name: 'generated-image.png',
    mimeType: 'image/png',
    chunkSize: 64 * 1024,
    onProgress: (pct, i, total) => process.stdout.write(`\r  进度: ${pct}% (${i + 1}/${total})`),
  });
  console.log(`\n✓ 已发送 ${meta.totalChunks} 个分片，SHA-256 ${meta.sha256.slice(0, 16)}…`);

  // 4. 等待接收组装
  await new Promise((r) => setTimeout(r, 1500));
  if (received) {
    console.log('✓ 接收端 SHA-256 校验通过，内容完整一致。');
  } else {
    console.log('✗ 未收到文件。');
  }

  sender.disconnect();
  receiver.disconnect();
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
