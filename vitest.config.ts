import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    globals: true,
    include: ['__tests__/**/*.e2e-spec.ts'],
    testTimeout: 120000,
    hookTimeout: 120000,
    teardownTimeout: 30000,
    isolate: false,
    setupFiles: ['reflect-metadata'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'html', 'lcov'],
    },
  },

  esbuild: {
    tsconfigRaw: require('./tsconfig.test.json'),
  },

});