import { createPrivateKey, createPublicKey, generateKeyPairSync, type KeyObject } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { calculateJwkThumbprint, exportJWK, type JWK } from 'jose';

export interface SigningKey {
    kid: string;
    alg: 'RS256';
    privateKey: KeyObject;
    publicKey: KeyObject;
    /** Public JWK as served by `/.well-known/jwks.json`. */
    jwk: JWK;
}

/**
 * Load the RS256 signing key from a PKCS#8 PEM file, generating (and persisting, when a path is given)
 * a fresh 2048-bit RSA key when none exists. The `kid` is the RFC 7638 thumbprint, so it is stable
 * for a given key across restarts.
 */
export async function loadSigningKey(pemPath?: string): Promise<SigningKey> {
    let pem: string;
    if (pemPath && existsSync(pemPath)) {
        pem = readFileSync(pemPath, 'utf8');
    } else {
        const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
        pem = privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
        if (pemPath) {
            mkdirSync(dirname(pemPath), { recursive: true });
            writeFileSync(pemPath, pem, { mode: 0o600 });
        }
    }
    const privateKey = createPrivateKey(pem);
    const publicKey = createPublicKey(privateKey);
    const publicJwk = await exportJWK(publicKey);
    const kid = await calculateJwkThumbprint(publicJwk);
    return {
        kid,
        alg: 'RS256',
        privateKey,
        publicKey,
        jwk: { ...publicJwk, kid, use: 'sig', alg: 'RS256' },
    };
}

export function jwksDocument(key: SigningKey): { keys: JWK[] } {
    return { keys: [key.jwk] };
}
