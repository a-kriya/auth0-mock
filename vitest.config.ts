import { defineConfig } from 'vitest/config';

export default defineConfig({
    test: {
        include: ['test/**/*.test.ts'],
        // The suites start real HTTP servers on random ports; keep them in one worker pool but allow
        // files to run in parallel since each file owns its own server instance.
        testTimeout: 20_000,
        hookTimeout: 20_000,
    },
});
