/**
 * live.mjs — 为 Python 客户端起一个真实中继（保持运行直到被杀）
 * 运行：cd a2net-sdk && npx tsx ../a2net-py/tests/live.mjs
 */
import { A2NetRelayServer } from '../../a2net-relay/src/server.js';

const relay = new A2NetRelayServer({
  port: Number(process.env.PORT ?? 8090),
  host: '127.0.0.1',
  onLog: () => {},
});
await relay.start();
console.log('RELAY_READY');

process.on('SIGTERM', async () => {
  await relay.stop();
  process.exit(0);
});
