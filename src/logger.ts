export type LogLevel = 'silent' | 'error' | 'warn' | 'info' | 'debug';

const ORDER: Record<LogLevel, number> = { silent: 0, error: 1, warn: 2, info: 3, debug: 4 };

export interface Logger {
    level: LogLevel;
    error(message: string, ...args: unknown[]): void;
    warn(message: string, ...args: unknown[]): void;
    info(message: string, ...args: unknown[]): void;
    debug(message: string, ...args: unknown[]): void;
}

export function createLogger(level: LogLevel = 'info', sink: Pick<Console, 'log' | 'error'> = console): Logger {
    const enabled = (l: LogLevel) => ORDER[l] <= ORDER[level];
    const line = (l: LogLevel, message: string, args: unknown[]) => {
        if (!enabled(l)) return;
        const out = l === 'error' || l === 'warn' ? sink.error : sink.log;
        out(`[auth0-mock] ${l.padEnd(5)} ${message}`, ...args);
    };
    return {
        level,
        error: (m, ...a) => line('error', m, a),
        warn: (m, ...a) => line('warn', m, a),
        info: (m, ...a) => line('info', m, a),
        debug: (m, ...a) => line('debug', m, a),
    };
}
