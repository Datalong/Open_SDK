/**
 * check_and_emit.mjs — 跨语言互操作测试（JS 侧）
 *
 * 1) 读入 Python 生成的向量（tests/fixtures/py-fixtures.json），在 JS 端校验
 * 2) 用固定种子生成向量写入 tests/fixtures/js-fixtures.json，供 Python 校验
 *
 * 运行：npx tsx a2net-py/tests/check_and_emit.mjs
 */
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  canonicalJson,
  getSignString,
  keyPairFromPrivateKey,
  verifySignature,
} from '../../a2net-sdk/src/crypto.js';
import { buildMessage, validateMessage } from '../../a2net-sdk/src/protocol.js';
import { createAgentCard, signAgentCard, verifyAgentCard } from '../../a2net-sdk/src/agent-card.js';
import { decryptFrom, encryptFor } from '../../a2net-sdk/src/e2ee.js';

const here = dirname(fileURLToPath(import.meta.url));
const fixturesDir = join(here, 'fixtures');
mkdirSync(fixturesDir, { recursive: true });

// 固定种子，保证两侧可复现
const seedA = Uint8Array.from({ length: 32 }, (_, i) => i + 1);
const seedB = Uint8Array.from({ length: 32 }, (_, i) => 0xa0 + i);
const kpA = keyPairFromPrivateKey(seedA);
const kpB = keyPairFromPrivateKey(seedB);

let failures = 0;
const assert = (cond, what) => {
  console.log(`  ${cond ? '\x1b[32m✓\x1b[0m' : '\x1b[31m✗\x1b[0m'} ${what}`);
  if (!cond) failures++;
};

// ---------------------------------------------------------------------------
// 方向一：校验 Python 生成的向量
// ---------------------------------------------------------------------------
const pyPath = join(fixturesDir, 'py-fixtures.json');
if (existsSync(pyPath)) {
  console.log('\n[JS] 校验 Python 生成的向量:');
  const py = JSON.parse(readFileSync(pyPath, 'utf8'));

  assert(py.address === kpA.address, `did:key 地址一致 (${py.address.slice(0, 24)}…)`);
  assert(
    py.canonicalJsonSample === canonicalJson(py.canonicalJsonInput),
    'canonical JSON 输出一致'
  );
  assert(py.message.signature === '' ? false : true, 'Python 消息带签名');
  const vcode = validateMessage(py.message, { now: py.message.timestamp });
  assert(vcode === null, `Python 签名的消息在 JS 端验签通过${vcode !== null ? ' (code ' + vcode + ')' : ''}`);
  assert(
    py.message.signature ===
      (await import('../../a2net-sdk/src/crypto.js')).signMessage(
        getSignString(py.message),
        seedA
      ),
    '同一消息两侧签名逐字节相同'
  );
  assert(verifyAgentCard(py.agentCard), 'Python 签名的 Agent Card 在 JS 端验签通过');
  const pt = await decryptFrom(kpA.address, py.envelope, kpB.privateKey);
  assert(pt === '来自 Python 的密文', `JS 能解开 Python 的密文: "${pt}"`);
} else {
  console.log('\n[JS] 未找到 py-fixtures.json，跳过方向一（先跑 Python 生成）');
}

// ---------------------------------------------------------------------------
// 方向二：生成向量给 Python
// ---------------------------------------------------------------------------
const message = buildMessage(
  {
    from: kpA.address,
    to: kpB.address,
    type: 'query',
    content: { query: '你好，Python', scope: { type: 'task', max_tokens: 128 } },
    timestamp: 1730000000000,
  },
  kpA.privateKey
);

const agentCard = signAgentCard(
  createAgentCard({
    did: kpA.address,
    name: 'JS 端助手',
    description: '由 JS SDK 生成',
    url: 'https://js.example.com/.well-known/agent-description.json',
    relay: 'wss://relay.a2net.io',
    pricing: { unit: 'sat', amount: 100 },
    capabilities: ['poetry'],
    interfaces: [{ type: 'NaturalLanguageInterface', protocol: 'A2Net' }],
  }),
  kpA,
  '2025-01-01T00:00:00.000Z'
);

// 固定临时种子 → 密文可复现
const envelope = await encryptFor(kpB.address, '来自 JS 的密文', seedB);

writeFileSync(
  join(fixturesDir, 'js-fixtures.json'),
  JSON.stringify(
    {
      seedA: Buffer.from(seedA).toString('hex'),
      addressA: kpA.address,
      addressB: kpB.address,
      canonicalJsonInput: {
        b: [1, 2, { z: null, a: '中文' }],
        a: { y: true, x: 1730000000000 },
      },
      canonicalJsonSample: canonicalJson({
        b: [1, 2, { z: null, a: '中文' }],
        a: { y: true, x: 1730000000000 },
      }),
      message,
      agentCard,
      envelope,
      plaintext: '来自 JS 的密文',
    },
    null,
    2
  )
);
console.log(`\n[JS] 已写出 ${join(fixturesDir, 'js-fixtures.json')}`);

if (failures > 0) {
  console.error(`\n\x1b[31m✗ JS 侧互操作校验失败 ${failures} 项\x1b[0m`);
  process.exit(1);
}
console.log('\n\x1b[32m✓ JS 侧互操作校验通过\x1b[0m');
