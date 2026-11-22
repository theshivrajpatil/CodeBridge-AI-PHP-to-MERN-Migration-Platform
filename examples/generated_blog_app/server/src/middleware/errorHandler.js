import { HttpError } from '../lib/httpError.js';
import { env } from '../config/env.js';
import { logger } from '../lib/logger.js';

export const notFound = (_req, _res, next) => next(new HttpError(404, 'Not Found'));

export function errorHandler(err, req, res, _next) {
  if (err instanceof HttpError) {
    const body = { message: err.message };
    if (err.errors) body.errors = err.errors;
    return res.status(err.status).json(body);
  }
  if (err?.type === 'entity.parse.failed') return res.status(400).json({ message: 'Malformed JSON.' });
  if (err?.type === 'entity.too.large') return res.status(413).json({ message: 'Payload too large.' });
  logger.error({ err, path: req.path }, 'unhandled error');
  return res.status(500).json({ message: env.NODE_ENV === 'production' ? 'Server Error' : String(err?.message || err) });
}
