import { defineConfig } from 'vitest/config';
import { fileURLToPath } from 'node:url';

export default defineConfig({
  resolve: {
    alias: {
      '@a2net/client': fileURLToPath(new URL('../typescript/src/index.ts', import.meta.url)),
    },
  },
  test: {
    testTimeout: 20000,
  },
});
