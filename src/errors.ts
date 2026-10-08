/**
 * Error types mirroring the two envelopes Auth0 returns:
 *  - Management API v2: `{ statusCode, error, message, errorCode? }`
 *  - Authentication API (OAuth): `{ error, error_description }`
 */
export class HttpError extends Error {
    readonly status: number;
    readonly body: Record<string, unknown>;

    constructor(status: number, body: Record<string, unknown>) {
        const message =
            typeof body.message === 'string'
                ? body.message
                : typeof body.error_description === 'string'
                  ? body.error_description
                  : `HTTP ${status}`;
        super(message);
        this.name = 'HttpError';
        this.status = status;
        this.body = body;
    }
}

const REASONS: Record<number, string> = {
    400: 'Bad Request',
    401: 'Unauthorized',
    403: 'Forbidden',
    404: 'Not Found',
    409: 'Conflict',
    422: 'Unprocessable Entity',
    429: 'Too Many Requests',
    500: 'Internal Server Error',
};

/** Management API error envelope. */
export function mgmtError(status: number, message: string, errorCode?: string): HttpError {
    const body: Record<string, unknown> = { statusCode: status, error: REASONS[status] ?? 'Error', message };
    if (errorCode) body.errorCode = errorCode;
    return new HttpError(status, body);
}

export const badRequest = (message: string, errorCode = 'invalid_body'): HttpError =>
    mgmtError(400, message, errorCode);
export const unauthorized = (message = 'Missing authentication'): HttpError => mgmtError(401, message);
export const forbidden = (message = 'Insufficient scope'): HttpError => mgmtError(403, message, 'insufficient_scope');
export const notFound = (message = 'The resource does not exist', errorCode = 'inexistent_resource'): HttpError =>
    mgmtError(404, message, errorCode);
export const conflict = (message: string, errorCode = 'conflict'): HttpError => mgmtError(409, message, errorCode);

/** Authentication API (OAuth 2.0) error envelope. */
export function oauthError(status: number, error: string, description: string): HttpError {
    return new HttpError(status, { error, error_description: description });
}
