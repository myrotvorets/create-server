import { readFile } from 'node:fs/promises';
import { type Server as HttpServer, type RequestListener, createServer as createHttpServer } from 'node:http';
import { type Server as HttpsServer, type ServerOptions, createServer as createHttpsServer } from 'node:https';
import type { SecureVersion } from 'node:tls';
import process from 'node:process';
import { bool, cleanEnv, str } from 'envalid';

export interface ServerEnvironment {
    HTTPS: boolean;
    TLS_CERT: string;
    TLS_KEY: string;
    TLS_KEY_PASSPHRASE: string;
    DHPARAM_FILE: string;
    TLS_CA: string;
    TLS_CRL: string;
    TLS_CIPHERS: string;
    TLS_ECDH_CURVE: string;
    TLS_REQUEST_CLIENT_CERT: boolean;
    TLS_MIN_VERSION: SecureVersion;
    TLS_MAX_VERSION: SecureVersion;
}

function makeEnv(): ServerEnvironment {
    return cleanEnv(process.env, {
        HTTPS: bool({ default: false }),
        TLS_CERT: str({ default: '' }),
        TLS_KEY: str({ default: '' }),
        TLS_KEY_PASSPHRASE: str({ default: '' }),
        DHPARAM_FILE: str({ default: '' }),
        TLS_CA: str({ default: '' }),
        TLS_CRL: str({ default: '' }),
        TLS_CIPHERS: str({
            default: 'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256',
        }),
        TLS_ECDH_CURVE: str({ default: 'secp384r1:prime256v1' }),
        TLS_REQUEST_CLIENT_CERT: bool({ default: false }),
        TLS_MIN_VERSION: str({
            default: 'TLSv1.3',
            choices: ['TLSv1.2', 'TLSv1.3'],
        }),
        TLS_MAX_VERSION: str({
            default: 'TLSv1.3',
            choices: ['TLSv1.2', 'TLSv1.3'],
        }),
    });
}

export async function createServer(requestListener?: RequestListener): Promise<HttpServer | HttpsServer> {
    const env = makeEnv();
    const isHttps = env.HTTPS;
    let server: HttpServer | HttpsServer;

    if (isHttps) {
        const options: ServerOptions = {
            honorCipherOrder: true,
        };

        [options.cert, options.key] = await Promise.all([readFile(env.TLS_CERT), readFile(env.TLS_KEY)]);

        options.passphrase = env.TLS_KEY_PASSPHRASE || undefined;
        if (env.DHPARAM_FILE) {
            options.dhparam = await readFile(env.DHPARAM_FILE);
        }

        if (env.TLS_CA) {
            options.ca = await readFile(env.TLS_CA);
        }

        if (env.TLS_CRL) {
            options.crl = await readFile(env.TLS_CRL);
        }

        if (env.TLS_CIPHERS) {
            options.ciphers = env.TLS_CIPHERS;
        }

        if (env.TLS_ECDH_CURVE) {
            options.ecdhCurve = env.TLS_ECDH_CURVE;
        }

        options.requestCert = env.TLS_REQUEST_CLIENT_CERT;
        options.rejectUnauthorized = env.TLS_REQUEST_CLIENT_CERT;

        options.minVersion = env.TLS_MIN_VERSION;
        options.maxVersion = env.TLS_MAX_VERSION;

        server = createHttpsServer(options, requestListener);
    } else {
        server = createHttpServer(requestListener);
    }

    const finish = (): unknown => server.close(() => process.exit(0));
    process.on('SIGTERM', finish);
    process.on('SIGINT', finish);
    process.on('SIGQUIT', finish);
    process.on('SIGUSR2', finish);

    return server;
}
