import http, { RequestListener } from 'http';
import https from 'https';
import fs from 'fs';
import { promisify } from 'util';
import { bool, cleanEnv, str } from 'envalid';

const readFile = promisify(fs.readFile);

// eslint-disable-next-line @typescript-eslint/explicit-function-return-type
function makeEnv() {
    return cleanEnv(
        process.env,
        {
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
                choices: ['', 'TLSv1.2', 'TLSv1.3'],
            }),
            TLS_MAX_VERSION: str({
                default: '',
                choices: ['', 'TLSv1.2', 'TLSv1.3'],
            }),
        },
        {
            strict: true,
            dotEnvPath: null,
        },
    );
}

export async function createServer(requestListener?: RequestListener): Promise<http.Server | https.Server> {
    const env = makeEnv();
    const isHttps = env.HTTPS;

    if (isHttps) {
        const options: https.ServerOptions = {
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

        options.ciphers = env.TLS_CIPHERS || undefined;
        options.ecdhCurve = env.TLS_ECDH_CURVE || undefined;
        options.requestCert = env.TLS_REQUEST_CLIENT_CERT;
        options.rejectUnauthorized = env.TLS_REQUEST_CLIENT_CERT;

        options.minVersion = env.TLS_MIN_VERSION || undefined;
        options.maxVersion = env.TLS_MAX_VERSION || undefined;

        return https.createServer(options, requestListener);
    }

    return http.createServer(requestListener);
}
