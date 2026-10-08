import 'reflect-metadata';
import type { webcrypto } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { isIP } from 'node:net';
import { join } from 'node:path';
import * as x509 from '@peculiar/x509';
import type { Config } from './config.ts';
import { randomHex } from './store/ids.ts';

type CryptoKey = webcrypto.CryptoKey;
type CryptoKeyPair = webcrypto.CryptoKeyPair;

x509.cryptoProvider.set(globalThis.crypto);

export interface TlsMaterial {
    /** Server private key (PKCS#8 PEM). */
    key: string;
    /** Server certificate chain (leaf followed by CA, PEM). */
    cert: string;
    /** CA certificate (PEM) clients must trust; undefined when the material was provided externally. */
    ca?: string;
    /** Directory holding the generated files (auto mode). */
    dir?: string;
}

const RSA = {
    name: 'RSASSA-PKCS1-v1_5',
    hash: 'SHA-256',
    publicExponent: new Uint8Array([1, 0, 1]),
    modulusLength: 2048,
};
const DAY = 24 * 60 * 60 * 1000;

export const TLS_FILES = {
    caCert: 'rootCA.pem',
    caKey: 'rootCA-key.pem',
    cert: 'cert.pem',
    key: 'key.pem',
} as const;

async function generateKeys(): Promise<CryptoKeyPair> {
    return crypto.subtle.generateKey(RSA, true, ['sign', 'verify']);
}

async function exportPrivateKeyPem(key: CryptoKey): Promise<string> {
    return x509.PemConverter.encode(await crypto.subtle.exportKey('pkcs8', key), 'PRIVATE KEY');
}

async function importPrivateKeyPem(pem: string): Promise<CryptoKey> {
    const [der] = x509.PemConverter.decode(pem);
    if (!der) throw new Error('PEM file does not contain a private key');
    return crypto.subtle.importKey('pkcs8', der, RSA, true, ['sign']);
}

async function createCa(): Promise<{ cert: x509.X509Certificate; keys: CryptoKeyPair }> {
    const keys = await generateKeys();
    const now = Date.now();
    const cert = await x509.X509CertificateGenerator.createSelfSigned({
        serialNumber: randomHex(16),
        name: 'CN=auth0-mock local CA, O=auth0-mock',
        notBefore: new Date(now - DAY),
        notAfter: new Date(now + 10 * 365 * DAY),
        signingAlgorithm: RSA,
        keys,
        extensions: [
            new x509.BasicConstraintsExtension(true, undefined, true),
            new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
            await x509.SubjectKeyIdentifierExtension.create(keys.publicKey),
        ],
    });
    return { cert, keys };
}

async function createLeaf(
    ca: { cert: x509.X509Certificate; key: CryptoKey },
    sans: string[]
): Promise<{ cert: x509.X509Certificate; keys: CryptoKeyPair }> {
    const keys = await generateKeys();
    const now = Date.now();
    const cert = await x509.X509CertificateGenerator.create({
        serialNumber: randomHex(16),
        subject: `CN=${sans[0] ?? 'auth0-mock'}, O=auth0-mock`,
        issuer: ca.cert.subject,
        notBefore: new Date(now - DAY),
        notAfter: new Date(now + 825 * DAY),
        signingAlgorithm: RSA,
        publicKey: keys.publicKey,
        signingKey: ca.key,
        extensions: [
            new x509.BasicConstraintsExtension(false, undefined, true),
            new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature | x509.KeyUsageFlags.keyEncipherment, true),
            new x509.ExtendedKeyUsageExtension([x509.ExtendedKeyUsage.serverAuth]),
            new x509.SubjectAlternativeNameExtension(
                sans.map((value) => (isIP(value) ? { type: 'ip' as const, value } : { type: 'dns' as const, value }))
            ),
            await x509.SubjectKeyIdentifierExtension.create(keys.publicKey),
            await x509.AuthorityKeyIdentifierExtension.create(ca.cert),
        ],
    });
    return { cert, keys };
}

function leafCovers(cert: x509.X509Certificate, sans: string[]): boolean {
    if (cert.notAfter.getTime() < Date.now() + 7 * DAY) return false;
    const ext = cert.getExtension(x509.SubjectAlternativeNameExtension);
    const present = new Set((ext?.names.items ?? []).map((n) => n.value));
    return sans.every((s) => present.has(s));
}

/**
 * Resolve TLS material for the configured mode. In `auto` mode a local CA and a server certificate
 * covering `tlsSans` are created under `tlsDir` on first use and reused afterwards; the leaf is
 * regenerated when the SAN list grows or the certificate nears expiry.
 */
export async function ensureTls(config: Config): Promise<TlsMaterial | undefined> {
    if (config.tls === 'off') return undefined;

    if (config.tls === 'provided') {
        if (!config.tlsCert || !config.tlsKey) {
            throw new Error("tls=provided requires 'tlsCert' and 'tlsKey' (AUTH0_MOCK_TLS_CERT / AUTH0_MOCK_TLS_KEY)");
        }
        return { cert: readFileSync(config.tlsCert, 'utf8'), key: readFileSync(config.tlsKey, 'utf8') };
    }

    const dir = config.tlsDir;
    mkdirSync(dir, { recursive: true });
    const paths = Object.fromEntries(Object.entries(TLS_FILES).map(([k, f]) => [k, join(dir, f)])) as Record<
        keyof typeof TLS_FILES,
        string
    >;

    let caCert: x509.X509Certificate;
    let caKey: CryptoKey;
    if (existsSync(paths.caCert) && existsSync(paths.caKey)) {
        caCert = new x509.X509Certificate(readFileSync(paths.caCert, 'utf8'));
        caKey = await importPrivateKeyPem(readFileSync(paths.caKey, 'utf8'));
    } else {
        const ca = await createCa();
        caCert = ca.cert;
        caKey = ca.keys.privateKey;
        writeFileSync(paths.caCert, caCert.toString('pem'));
        writeFileSync(paths.caKey, await exportPrivateKeyPem(caKey), { mode: 0o600 });
    }

    const sans = [...new Set(config.tlsSans)];
    let leafPem: string | undefined;
    let leafKeyPem: string | undefined;
    if (existsSync(paths.cert) && existsSync(paths.key)) {
        const existing = new x509.X509Certificate(readFileSync(paths.cert, 'utf8'));
        if (existing.issuer === caCert.subject && leafCovers(existing, sans)) {
            leafPem = existing.toString('pem');
            leafKeyPem = readFileSync(paths.key, 'utf8');
        }
    }
    if (!leafPem || !leafKeyPem) {
        const leaf = await createLeaf({ cert: caCert, key: caKey }, sans);
        leafPem = leaf.cert.toString('pem');
        leafKeyPem = await exportPrivateKeyPem(leaf.keys.privateKey);
        writeFileSync(paths.cert, leafPem);
        writeFileSync(paths.key, leafKeyPem, { mode: 0o600 });
    }

    const caPem = caCert.toString('pem');
    return { key: leafKeyPem, cert: `${leafPem}\n${caPem}`, ca: caPem, dir };
}
