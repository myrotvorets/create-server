import { once } from 'node:events';
import { readFile } from 'node:fs/promises';
import { type Server as HttpServer, type RequestListener, createServer as createHttpServer } from 'node:http';
import { type Server as HttpsServer, type ServerOptions, createServer as createHttpsServer } from 'node:https';
import process from 'node:process';
import { type SecureContextOptions, type SecureVersion } from 'node:tls';
import { bool, cleanEnv, port, str } from 'envalid';
import { FSWatcher, watch } from 'node:fs';

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
    PORT: number;
}

export interface CreateServerOptions {
    listen: boolean;
    setSignalHandlers: boolean;
    watchCert: boolean;
    reloadDelay: number;
    reloadAttempts: number;
    errorHandler: undefined | ((error: Error, where: 'renew' | 'watch') => void);
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
        PORT: port({ default: 3000 }),
    });
}

async function makeSecureContext(env: ServerEnvironment): Promise<SecureContextOptions> {
    const options: SecureContextOptions = {
        honorCipherOrder: true,
        passphrase: env.TLS_KEY_PASSPHRASE || undefined,
        ciphers: env.TLS_CIPHERS || undefined,
        ecdhCurve: env.TLS_ECDH_CURVE || undefined,
        minVersion: env.TLS_MIN_VERSION,
        maxVersion: env.TLS_MAX_VERSION,
    };

    const undef = Promise.resolve(undefined);
    const promises: Promise<Buffer | undefined>[] = [];

    promises.push(
        readFile(env.TLS_CERT),
        readFile(env.TLS_KEY),
        env.TLS_CA ? readFile(env.TLS_CA) : undef,
        env.TLS_CRL ? readFile(env.TLS_CRL) : undef,
        env.DHPARAM_FILE ? readFile(env.DHPARAM_FILE) : undef,
    );

    [options.cert, options.key, options.ca, options.crl, options.dhparam] = await Promise.all(promises);

    return options;
}

async function createSecureServer(
    env: ServerEnvironment,
    requestListener: RequestListener | undefined,
    opts: CreateServerOptions,
): Promise<HttpsServer> {
    const serverOption: ServerOptions = {
        ...(await makeSecureContext(env)),
        requestCert: env.TLS_REQUEST_CLIENT_CERT,
        rejectUnauthorized: env.TLS_REQUEST_CLIENT_CERT,
    };

    const server = createHttpsServer(serverOption, requestListener);

    if (opts.watchCert) {
        let timeout: NodeJS.Timeout | undefined;
        const watchHandler = (): void => {
            clearTimeout(timeout);
            let attempts = opts.reloadAttempts;
            const reloader = (): unknown =>
                makeSecureContext(env)
                    .then((options) => server.setSecureContext(options))
                    .catch((error: Error) => {
                        opts.errorHandler?.(error, 'renew');
                        if (attempts > 0) {
                            --attempts;
                            setTimeout(reloader, opts.reloadDelay);
                        }
                    });

            timeout = setTimeout(reloader, opts.reloadDelay);
        };

        const watchers: FSWatcher[] = [
            watch(env.TLS_CERT, { persistent: false }, watchHandler),
            watch(env.TLS_KEY, { persistent: false }, watchHandler),
        ];

        if (env.TLS_CA) {
            watchers.push(watch(env.TLS_CA, { persistent: false }, watchHandler));
        }

        if (env.TLS_CERT) {
            watchers.push(watch(env.TLS_CRL, { persistent: false }, watchHandler));
        }

        if (opts.errorHandler) {
            watchers.forEach((watcher) => {
                watcher.on('error', (err) => opts.errorHandler!(err, 'watch'));
            });
        }
    }

    return server;
}

function setSignalHandlers(server: HttpServer): void {
    const gracefulShutdown = (): void => {
        if (server.listening) {
            server.close();
        } else {
            server.closeAllConnections();
        }
    };

    const finish = (): void => {
        server.closeAllConnections();
    };

    process.on('SIGTERM', gracefulShutdown);
    process.on('SIGINT', gracefulShutdown);
    process.on('SIGQUIT', finish);
    process.on('SIGUSR2', finish);
}

export async function createServer(
    requestListener: RequestListener | undefined,
    options?: Partial<CreateServerOptions> | boolean,
): Promise<HttpServer | HttpsServer> {
    const defaults: CreateServerOptions = {
        listen: true,
        setSignalHandlers: true,
        watchCert: true,
        reloadDelay: 1000,
        reloadAttempts: 5,
        errorHandler: undefined,
    };

    if (typeof options === 'boolean') {
        options = { listen: options };
    }

    const opts = { ...defaults, ...options };

    const env = makeEnv();
    const server = env.HTTPS ? await createSecureServer(env, requestListener, opts) : createHttpServer(requestListener);

    if (opts.setSignalHandlers) {
        setSignalHandlers(server);
    }

    if (opts.listen) {
        server.listen(env.PORT);
        await once(server, 'listening');
    }

    return server;
}
