import { describe, it, expect } from 'vitest';
import {
  splitBlobIntoChunks,
  BlobTransferManager,
} from '../src/index.js';

describe('Multimodal Chunking & Assembly (Open SDK)', () => {
  it('splits binary buffer into chunks and verifies SHA-256 digests', async () => {
    const rawData = new Uint8Array(128 * 1024);
    for (let i = 0; i < rawData.length; i++) {
      rawData[i] = (i * 23 + 5) & 0xff;
    }

    const CHUNK_SIZE = 64 * 1024;
    const { metadata, chunks } = await splitBlobIntoChunks(
      rawData,
      'test-data.bin',
      'application/octet-stream',
      CHUNK_SIZE
    );

    expect(metadata.name).toBe('test-data.bin');
    expect(metadata.mimeType).toBe('application/octet-stream');
    expect(metadata.size).toBe(rawData.length);
    expect(metadata.totalChunks).toBe(2);
    expect(chunks.length).toBe(2);

    const mgr = new BlobTransferManager();
    mgr.initSession('did:key:sender', metadata);

    const res1 = await mgr.handleChunk('did:key:sender', chunks[0]!);
    expect(res1.completedBlob).toBeNull();

    const res2 = await mgr.handleChunk('did:key:sender', chunks[1]!);
    expect(res2.completedBlob).not.toBeNull();
    expect(res2.completedBlob?.data.length).toBe(rawData.length);
    expect(res2.completedBlob?.data).toEqual(rawData);
  });

  it('rejects corrupted chunks with SHA-256 mismatch', async () => {
    const rawData = new Uint8Array(16 * 1024);
    const { metadata, chunks } = await splitBlobIntoChunks(rawData, 'sample.txt', 'text/plain');

    const mgr = new BlobTransferManager();
    mgr.initSession('did:key:sender', metadata);

    const corruptedChunk = { ...chunks[0]!, chunkSha256: 'deadbeef00000000000000000000000000000000000000000000000000000000' };
    await expect(mgr.handleChunk('did:key:sender', corruptedChunk)).rejects.toThrow(/Corrupted chunk/);
  });
});
