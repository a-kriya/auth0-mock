// `reflect-metadata` must be loaded before @peculiar/x509; importing src/tls.ts first guarantees the order.
import { TLS_FILES, ensureTls } from '../src/tls.ts';
import { SubjectAlternativeNameExtension, X509Certificate } from '@peculiar/x509';
import { copyFileSync, existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { resolveConfig, type ConfigInput } from '../src/config.ts';

const SANS = ['localhost', '127.0.0.1', 'auth.test.local'];

function sanValues(cert: X509Certificate): Array<{ type: string; value: string }> {
    const extension = cert.getExtension(SubjectAlternativeNameExtension);
    return (extension?.names.items ?? []).map((n) => ({ type: n.type, value: n.value }));
}

function pemBlocks(chain: string): number {
    return chain.split('-----BEGIN CERTIFICATE-----').length - 1;
}

describe('ensureTls (auto)', () => {
    let dir: string;
    beforeAll(() => {
        dir = mkdtempSync(join(tmpdir(), 'auth0-mock-tls-'));
    });
    afterAll(() => rmSync(dir, { recursive: true, force: true }));

    const config = (overrides: Partial<ConfigInput> = {}) =>
        resolveConfig({ tls: 'auto', tlsDir: dir, tlsSans: SANS, ...overrides });

    it('creates a CA and a leaf certificate covering the configured SANs', async () => {
        const material = await ensureTls(config());
        expect(material).toBeDefined();
        for (const file of Object.values(TLS_FILES)) {
            expect(existsSync(join(dir, file)), file).toBe(true);
        }
        expect(TLS_FILES).toEqual({
            caCert: 'rootCA.pem',
            caKey: 'rootCA-key.pem',
            cert: 'cert.pem',
            key: 'key.pem',
        });

        const leafPem = readFileSync(join(dir, TLS_FILES.cert), 'utf8');
        const caPem = readFileSync(join(dir, TLS_FILES.caCert), 'utf8');
        const keyPem = readFileSync(join(dir, TLS_FILES.key), 'utf8');
        const caKeyPem = readFileSync(join(dir, TLS_FILES.caKey), 'utf8');
        expect(leafPem).toMatch(/^-----BEGIN CERTIFICATE-----/);
        expect(keyPem).toMatch(/^-----BEGIN PRIVATE KEY-----/);
        expect(caKeyPem).toMatch(/^-----BEGIN PRIVATE KEY-----/);

        const leaf = new X509Certificate(leafPem);
        const ca = new X509Certificate(caPem);

        const names = sanValues(leaf);
        expect(names.map((n) => n.value)).toEqual(expect.arrayContaining(SANS));
        expect(names).toContainEqual({ type: 'dns', value: 'localhost' });
        expect(names).toContainEqual({ type: 'dns', value: 'auth.test.local' });
        expect(names).toContainEqual({ type: 'ip', value: '127.0.0.1' });

        expect(leaf.issuer).toBe(ca.subject);
        expect(ca.issuer).toBe(ca.subject);
        expect(ca.subject).toContain('CN=auth0-mock local CA');
        expect(leaf.subject).toContain('CN=localhost');
        expect(leaf.notAfter.getTime()).toBeGreaterThan(Date.now() + 30 * 24 * 60 * 60 * 1000);
        expect(leaf.notBefore.getTime()).toBeLessThan(Date.now());

        // Returned material: leaf chain (leaf + CA), the leaf key, the CA and the directory.
        expect(material!.cert).toBe(`${leafPem}\n${caPem}`);
        expect(pemBlocks(material!.cert)).toBe(2);
        expect(material!.cert.startsWith(leafPem)).toBe(true);
        expect(material!.cert.endsWith(caPem)).toBe(true);
        expect(material!.ca).toBe(caPem);
        expect(material!.key).toBe(keyPem);
        expect(material!.dir).toBe(dir);
    });

    it('reuses the same leaf and CA on a second call', async () => {
        const first = await ensureTls(config());
        const second = await ensureTls(config());
        expect(second).toEqual(first);
        expect(second!.cert).toBe(first!.cert);
        expect(second!.key).toBe(first!.key);
        expect(second!.ca).toBe(first!.ca);
        // A subset of the covered SANs is also satisfied by the existing leaf.
        const subset = await ensureTls(config({ tlsSans: ['localhost'] }));
        expect(subset!.cert).toBe(first!.cert);
        expect(subset!.key).toBe(first!.key);
    });

    it('regenerates the leaf but keeps the CA when a new SAN is added', async () => {
        const before = await ensureTls(config());
        const caFileBefore = readFileSync(join(dir, TLS_FILES.caCert), 'utf8');
        const caKeyBefore = readFileSync(join(dir, TLS_FILES.caKey), 'utf8');

        const grown = await ensureTls(config({ tlsSans: [...SANS, 'extra.test.local'] }));
        expect(grown!.ca).toBe(before!.ca);
        expect(readFileSync(join(dir, TLS_FILES.caCert), 'utf8')).toBe(caFileBefore);
        expect(readFileSync(join(dir, TLS_FILES.caKey), 'utf8')).toBe(caKeyBefore);
        expect(grown!.cert).not.toBe(before!.cert);
        expect(grown!.key).not.toBe(before!.key);
        expect(pemBlocks(grown!.cert)).toBe(2);
        expect(grown!.cert.endsWith(before!.ca!)).toBe(true);

        const leafPem = readFileSync(join(dir, TLS_FILES.cert), 'utf8');
        expect(grown!.cert.startsWith(leafPem)).toBe(true);
        const leaf = new X509Certificate(leafPem);
        expect(sanValues(leaf).map((n) => n.value)).toEqual(expect.arrayContaining([...SANS, 'extra.test.local']));
        expect(leaf.issuer).toBe(new X509Certificate(before!.ca!).subject);

        // The grown leaf is now the one that gets reused.
        const again = await ensureTls(config({ tlsSans: [...SANS, 'extra.test.local'] }));
        expect(again!.cert).toBe(grown!.cert);
    });

    it('de-duplicates SANs', async () => {
        const dupDir = mkdtempSync(join(tmpdir(), 'auth0-mock-tls-dup-'));
        try {
            const material = await ensureTls(
                resolveConfig({ tls: 'auto', tlsDir: dupDir, tlsSans: ['localhost', 'localhost', '127.0.0.1'] })
            );
            const leaf = new X509Certificate(readFileSync(join(dupDir, TLS_FILES.cert), 'utf8'));
            expect(sanValues(leaf).map((n) => n.value)).toEqual(['localhost', '127.0.0.1']);
            expect(material!.dir).toBe(dupDir);
        } finally {
            rmSync(dupDir, { recursive: true, force: true });
        }
    });

    it('creates the directory when it does not exist', async () => {
        const nested = join(dir, 'nested', 'deeper');
        expect(existsSync(nested)).toBe(false);
        const material = await ensureTls(config({ tlsDir: nested }));
        expect(existsSync(join(nested, TLS_FILES.cert))).toBe(true);
        expect(material!.dir).toBe(nested);
        // A fresh directory means a fresh CA.
        expect(material!.ca).not.toBe((await ensureTls(config()))!.ca);
    });
});

describe('ensureTls (off / provided)', () => {
    let dir: string;
    beforeAll(() => {
        dir = mkdtempSync(join(tmpdir(), 'auth0-mock-tls-provided-'));
    });
    afterAll(() => rmSync(dir, { recursive: true, force: true }));

    it('returns undefined when tls is off', async () => {
        await expect(ensureTls(resolveConfig({ tls: 'off', tlsDir: dir }))).resolves.toBeUndefined();
        expect(existsSync(join(dir, TLS_FILES.cert))).toBe(false);
    });

    it('reads the given files in provided mode without a CA or directory', async () => {
        const generated = join(dir, 'generated');
        await ensureTls(resolveConfig({ tls: 'auto', tlsDir: generated, tlsSans: ['localhost'] }));
        const certPath = join(dir, 'server.crt');
        const keyPath = join(dir, 'server.key');
        copyFileSync(join(generated, TLS_FILES.cert), certPath);
        copyFileSync(join(generated, TLS_FILES.key), keyPath);

        const material = await ensureTls(resolveConfig({ tls: 'provided', tlsCert: certPath, tlsKey: keyPath }));
        expect(material).toEqual({
            cert: readFileSync(certPath, 'utf8'),
            key: readFileSync(keyPath, 'utf8'),
        });
        expect(material!.ca).toBeUndefined();
        expect(material!.dir).toBeUndefined();
    });

    it('throws when provided mode lacks tlsCert or tlsKey', async () => {
        await expect(ensureTls(resolveConfig({ tls: 'provided' }))).rejects.toThrow(
            /tls=provided requires 'tlsCert' and 'tlsKey'/
        );
        await expect(ensureTls(resolveConfig({ tls: 'provided', tlsCert: join(dir, 'x.crt') }))).rejects.toThrow(
            /AUTH0_MOCK_TLS_CERT \/ AUTH0_MOCK_TLS_KEY/
        );
        await expect(ensureTls(resolveConfig({ tls: 'provided', tlsKey: join(dir, 'x.key') }))).rejects.toThrow(
            /tls=provided requires/
        );
    });

    it('throws when the provided paths do not exist', async () => {
        await expect(
            ensureTls(
                resolveConfig({ tls: 'provided', tlsCert: join(dir, 'missing.crt'), tlsKey: join(dir, 'missing.key') })
            )
        ).rejects.toThrow(/ENOENT/);
    });
});
