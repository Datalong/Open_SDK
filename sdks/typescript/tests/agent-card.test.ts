import { describe, it, expect, afterAll } from 'vitest';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import {
  AGENT_DESCRIPTION_PATH,
  agentDescriptionUrl,
  createAgentCard,
  resolveAgentCard,
  signAgentCard,
  verifyAgentCard,
} from '../src/agent-card.js';
import { generateKeyPair } from '../src/crypto.js';

function makeCard(keyPair = generateKeyPair()) {
  return createAgentCard({
    did: keyPair.address,
    name: '诗歌助手',
    description: '按主题写诗',
    url: 'https://poet.example.com/.well-known/agent-description.json',
    relay: 'wss://relay.a2net.io',
    pricing: { unit: 'sat', amount: 100 },
    capabilities: ['poetry', 'translation'],
    interfaces: [
      { type: 'StructuredInterface', protocol: 'A2Net', version: '1.0', url: 'https://poet.example.com/api' },
      { type: 'NaturalLanguageInterface', protocol: 'A2Net' },
    ],
  });
}

describe('agent card', () => {
  it('creates an ANP-07 shaped description', () => {
    const card = makeCard();
    expect(card.type).toBe('AgentDescription');
    expect(card.protocolType).toBe('A2Net');
    expect(card.interfaces).toHaveLength(2);
    expect(card.pricing?.amount).toBe(100);
    expect(card.security).toBe('a2net_message');
    expect(card.proof).toBeUndefined();
  });

  it('signs and verifies', () => {
    const kp = generateKeyPair();
    const signed = signAgentCard(makeCard(kp), kp);
    expect(signed.proof?.verificationMethod).toBe(kp.address);
    expect(verifyAgentCard(signed)).toBe(true);
  });

  it('rejects a tampered card', () => {
    const kp = generateKeyPair();
    const signed = signAgentCard(makeCard(kp), kp);
    const tampered = { ...signed, name: '恶意助手' };
    expect(verifyAgentCard(tampered)).toBe(false);
  });

  it('rejects when did does not match verificationMethod', () => {
    const kp = generateKeyPair();
    const other = generateKeyPair();
    const signed = signAgentCard(makeCard(kp), kp);
    expect(verifyAgentCard({ ...signed, did: other.address })).toBe(false);
  });

  it('rejects an unsigned card', () => {
    expect(verifyAgentCard(makeCard())).toBe(false);
  });

  it('derives the well-known discovery URL', () => {
    expect(agentDescriptionUrl('https://a.example.com/')).toBe(
      'https://a.example.com' + AGENT_DESCRIPTION_PATH
    );
  });

  it('resolves and verifies a card over .well-known (ANP-08)', async () => {
    const kp = generateKeyPair();
    const card = signAgentCard(makeCard(kp), kp);
    let served: string | undefined;

    const server = createServer((req, res) => {
      if (req.url === AGENT_DESCRIPTION_PATH) {
        served = req.url;
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(card));
      } else {
        res.writeHead(404);
        res.end();
      }
    });
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    const { port } = server.address() as AddressInfo;

    try {
      const url = agentDescriptionUrl(`http://127.0.0.1:${port}`);
      const resolved = await resolveAgentCard(url);
      expect(served).toBe(AGENT_DESCRIPTION_PATH);
      expect(resolved.name).toBe('诗歌助手');
      expect(resolved.proof?.signatureValue).toBe(card.proof?.signatureValue);
    } finally {
      await new Promise<void>((r) => server.close(() => r()));
    }
  });

  it('rejects a card with a broken signature when resolving', async () => {
    const kp = generateKeyPair();
    const card = signAgentCard(makeCard(kp), kp);
    const broken = { ...card, name: '被篡改' };
    const server = createServer((_req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(broken));
    });
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    const { port } = server.address() as AddressInfo;
    try {
      await expect(resolveAgentCard(`http://127.0.0.1:${port}/x`)).rejects.toThrow(/签名无效/);
    } finally {
      await new Promise<void>((r) => server.close(() => r()));
    }
  });
});
