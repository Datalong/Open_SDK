import { describe, it, expect } from 'vitest';
import { buildMessage, buildQuery, buildError, validateMessage, ErrorCode } from '../src/protocol.js';
import { generateKeyPair } from '../src/crypto.js';

describe('protocol', () => {
  const a = generateKeyPair();
  const b = generateKeyPair();

  it('builds and validates a signed message', () => {
    const msg = buildMessage(
      { from: a.address, to: b.address, type: 'ping', content: { nonce: 'n' } },
      a.privateKey
    );
    expect(validateMessage(msg)).toBeNull();
  });

  it('rejects tampered content', () => {
    const msg = buildQuery(a.address, b.address, 'hello', a.privateKey);
    msg.content.query = 'tampered';
    expect(validateMessage(msg)).toBe(ErrorCode.SIGNATURE);
  });

  it('rejects stale timestamp', () => {
    const msg = buildMessage(
      { from: a.address, to: b.address, type: 'ping', content: {}, timestamp: Date.now() - 10 * 60 * 1000 },
      a.privateKey
    );
    expect(validateMessage(msg)).toBe(ErrorCode.SIGNATURE);
  });

  it('rejects missing fields', () => {
    expect(validateMessage({ id: '1' })).toBe(ErrorCode.FORMAT);
  });

  it('rejects wrong type', () => {
    const msg = buildMessage({ from: a.address, to: b.address, type: 'ping', content: {} }, a.privateKey);
    (msg as { type: string }).type = 'hack';
    expect(validateMessage(msg)).toBe(ErrorCode.FORMAT);
  });

  it('detects replay via seenIds', () => {
    const msg = buildQuery(a.address, b.address, 'x', a.privateKey);
    const seen = new Set<string>();
    expect(validateMessage(msg, { seenIds: seen })).toBeNull();
    seen.add(msg.id);
    expect(validateMessage(msg, { seenIds: seen })).toBe(ErrorCode.SIGNATURE);
  });

  it('builds error with code', () => {
    const q = buildQuery(a.address, b.address, 'x', a.privateKey);
    const e = buildError(q, ErrorCode.PERMISSION, 'denied', b.privateKey);
    expect(e.content.code).toBe(ErrorCode.PERMISSION);
    expect(e.from).toBe(b.address);
    expect(e.to).toBe(a.address);
  });
});
