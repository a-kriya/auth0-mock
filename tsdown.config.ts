import { defineConfig } from 'tsdown';

// Unbundled ESM build mirroring the source tree into dist/ (dist/src/index.js, dist/bin/auth0-mock.js)
// so the npm package exposes the same module layout the source has.
export default defineConfig({
    entry: ['src/index.ts', 'bin/auth0-mock.ts'],
    outDir: 'dist',
    format: 'esm',
    platform: 'node',
    target: 'node24',
    unbundle: true,
    outExtensions: () => ({ js: '.js' }),
    sourcemap: true,
    dts: true,
    clean: true,
});
